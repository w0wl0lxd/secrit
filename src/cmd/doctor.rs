//! `secrit doctor` (PLAN section 4.7). Read-only: it creates, changes and
//! decrypts nothing, and prints no value, key material or hash of a value.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::agent;
use crate::backend::BackendError;
use crate::backend::sops::{MIN_SOPS, SopsBackend, TEMP_IGNORE};
use crate::config::{Config, ConfigSource, ENV_CONFIG, StoreConfig, config_path, home};
use crate::display::escape;
use crate::error::Error;
use crate::git::Repo;
use crate::harden::HardenReport;
use crate::tools::{self, ResolvedTool, ToolSource};

/// A temp copy younger than this may belong to a write that still runs.
const STALE_TEMP: Duration = Duration::from_secs(3600);
/// The marker in the name of a backup that secrit before 0.1 kept next to
/// the store file (SEC-2).
const OLD_BACKUP_MARK: &str = ".secrit-bak.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Info => "info",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    pub check: String,
    pub status: Status,
    pub detail: String,
}

#[derive(Debug, Default)]
struct Report(Vec<Row>);

impl Report {
    fn add(&mut self, check: impl Into<String>, status: Status, detail: impl Into<String>) {
        self.0.push(Row {
            check: check.into(),
            status,
            detail: detail.into(),
        });
    }
}

pub fn run(
    config_flag: Option<&Path>,
    store_flag: Option<&str>,
    json: bool,
    quiet: bool,
    hardened: HardenReport,
) -> Result<(), Error> {
    let env = |k: &str| std::env::var_os(k);
    let report = collect(config_flag, store_flag, quiet, hardened, &env);
    // A signal during a sops or git child made that row a false failure.
    super::interrupted()?;
    let mut out = std::io::stdout().lock();
    let written = if json {
        serde_json::to_writer_pretty(&mut out, &report.0)
            .map_err(std::io::Error::other)
            .and_then(|()| writeln!(out))
    } else {
        report.0.iter().try_for_each(|c| {
            writeln!(
                out,
                "{:<4}  {}: {}",
                c.status.label(),
                escape(&c.check),
                escape(&c.detail)
            )
        })
    };
    written.map_err(|e| Error::Failed(format!("could not write to stdout: {e}")))?;
    match report.0.iter().filter(|c| c.status == Status::Fail).count() {
        0 => Ok(()),
        n => Err(Error::Failed(format!("{n} check(s) failed"))),
    }
}

fn collect(
    config_flag: Option<&Path>,
    store_flag: Option<&str>,
    quiet: bool,
    hardened: HardenReport,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Report {
    let mut r = Report::default();
    process_checks(&mut r, hardened, env);
    let config =
        match config_path(config_flag, env)
            .map_err(Error::from)
            .and_then(|(path, source)| {
                super::note_config_source(&path, source, quiet);
                let config = Config::load(&path, &home(env)?)?;
                Ok((config, source))
            }) {
            Ok((config, source)) => {
                let from = if source == ConfigSource::Env {
                    format!(" (from {ENV_CONFIG})")
                } else {
                    String::new()
                };
                r.add(
                    "config",
                    Status::Ok,
                    format!("{}{from}", config.path.display()),
                );
                config
            }
            Err(e) => {
                r.add("config", Status::Fail, format!("{e}; run 'secrit init'"));
                return r;
            }
        };
    let sops = tool_check(&mut r, tools::SOPS, &config.tools.sops, env, true);
    tool_check(
        &mut r,
        tools::AGE_KEYGEN,
        &config.tools.age_keygen,
        env,
        false,
    );
    let stores: Vec<&StoreConfig> = match store_flag {
        Some(name) => match config.store(Some(name)) {
            Ok(s) => vec![s],
            Err(e) => {
                r.add("stores", Status::Fail, e.to_string());
                return r;
            }
        },
        None => config.stores.values().collect(),
    };
    if stores.is_empty() {
        r.add("stores", Status::Fail, "the config names no store");
    }
    let mut version_checked = false;
    for store in stores {
        let sops_path = sops
            .as_ref()
            .map_or_else(|| PathBuf::from("sops"), |t| t.path.clone());
        let backend = match SopsBackend::new(store, sops_path, config.lock_timeout, env) {
            Ok(b) => b,
            Err(e) => {
                r.add(format!("store {}", store.name), Status::Fail, e.to_string());
                continue;
            }
        };
        if sops.is_some() && !version_checked {
            version_checked = true;
            version_check(&mut r, &backend);
        }
        store_checks(&mut r, &store.name, &backend, sops.is_some(), env);
    }
    r
}

fn process_checks(r: &mut Report, hardened: HardenReport, env: &dyn Fn(&str) -> Option<OsString>) {
    let warnings = hardened.warnings();
    if warnings.is_empty() {
        r.add("hardening", Status::Ok, "no core dumps, not dumpable");
    }
    for w in warnings {
        r.add("hardening", Status::Warn, w);
    }
    match agent::detect() {
        Some(a) => r.add(
            "agent",
            Status::Info,
            format!("agent detected ({a}): 'get' is off"),
        ),
        None => r.add("agent", Status::Ok, "no agent detected"),
    }
    let exposed: Vec<&str> = ["SOPS_AGE_KEY", "SOPS_AGE_KEY_CMD"]
        .into_iter()
        .filter(|k| env(k).is_some_and(|v| !v.is_empty()))
        .collect();
    if exposed.is_empty() {
        r.add(
            "age key exposure",
            Status::Ok,
            "no age key in the environment",
        );
    } else {
        r.add(
            "age key exposure",
            Status::Warn,
            format!(
                "{} set in this environment; every program started here can read it (secrit does not pass it to sops)",
                exposed.join(" and ")
            ),
        );
    }
}

fn tool_check(
    r: &mut Report,
    program: tools::Program,
    setting: &crate::config::ToolSetting,
    env: &dyn Fn(&str) -> Option<OsString>,
    required: bool,
) -> Option<ResolvedTool> {
    match tools::resolve(program, setting, env("PATH").as_deref()) {
        Ok(t) => {
            let shown = t.path.display().to_string();
            if shown.contains("/mise/shims/") {
                r.add(
                    program.name,
                    Status::Warn,
                    format!(
                        "{shown} is a mise shim; set tools.{} to a Nix store path",
                        program.config_key
                    ),
                );
            } else if t.source == ToolSource::Path {
                r.add(
                    program.name,
                    Status::Warn,
                    format!(
                        "{shown} from PATH; install secrit with Nix to pin it, or set tools.{}",
                        program.config_key
                    ),
                );
            } else {
                r.add(program.name, Status::Ok, shown);
            }
            Some(t)
        }
        Err(e) => {
            let status = if required { Status::Fail } else { Status::Warn };
            let note = if required {
                ""
            } else {
                " (only 'secrit init' needs it)"
            };
            r.add(program.name, status, format!("{e}{note}"));
            None
        }
    }
}

fn version_check(r: &mut Report, backend: &SopsBackend) {
    match backend.sops_version() {
        Ok((a, b, c)) if (a, b) >= MIN_SOPS => {
            r.add("sops version", Status::Ok, format!("{a}.{b}.{c}"));
        }
        Ok((a, b, c)) => r.add(
            "sops version",
            Status::Fail,
            format!(
                "{a}.{b}.{c}; secrit needs {}.{} or newer",
                MIN_SOPS.0, MIN_SOPS.1
            ),
        ),
        Err(e) => r.add("sops version", Status::Fail, e.to_string()),
    }
}

fn store_checks(
    r: &mut Report,
    store: &str,
    backend: &SopsBackend,
    have_sops: bool,
    env: &dyn Fn(&str) -> Option<OsString>,
) {
    let name = |what: &str| format!("store {store}: {what}");
    let (status, detail) = age_key(backend.age_key_file());
    r.add(name("age key"), status, detail);

    match backend.check_store_dir() {
        Ok(()) => r.add(
            name("directory"),
            Status::Ok,
            backend.dir().display().to_string(),
        ),
        Err(e) => r.add(name("directory"), Status::Fail, e.to_string()),
    }

    match backend.inspect() {
        Ok(facts) => {
            r.add(
                name("file"),
                Status::Ok,
                format!("{} ({} names)", backend.file().display(), facts.names),
            );
            if !facts.rules.is_empty() {
                r.add(
                    name("cleartext rules"),
                    Status::Warn,
                    format!(
                        "the file sets {}; secrit v0.1 refuses to write it",
                        facts.rules.join(", ")
                    ),
                );
            }
            if facts.plaintext.is_empty() {
                r.add(name("plaintext"), Status::Ok, "every value is encrypted");
            } else {
                r.add(
                    name("plaintext"),
                    Status::Fail,
                    format!(
                        "not encrypted: {}",
                        facts
                            .plaintext
                            .iter()
                            .map(|n| escape(n).into_owned())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                );
            }
        }
        Err(BackendError::NoStoreFile(p)) => r.add(
            name("file"),
            Status::Fail,
            format!("{} does not exist; run 'secrit init'", p.display()),
        ),
        Err(e) => r.add(name("file"), Status::Fail, e.to_string()),
    }

    sops_config_check(r, &name(".sops.yaml"), backend, have_sops);
    temp_files_check(r, &name("temp files"), backend);
    backups_check(r, &name("backups"), backend);
    git_checks(r, store, backend, env);
}

fn age_key(path: Option<&Path>) -> (Status, String) {
    let Some(p) = path else {
        return (
            Status::Fail,
            "no age key file: set age_key_file, or HOME or XDG_CONFIG_HOME".into(),
        );
    };
    let shown = p.display();
    // Like init, which refuses a symlinked key (PLAN 4.7, age identity).
    match std::fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
            Status::Fail,
            format!("{shown} does not exist; run 'secrit init'"),
        ),
        Err(e) => (Status::Fail, format!("{shown}: {e}")),
        Ok(m) if m.is_symlink() => (
            Status::Fail,
            format!("{shown} is a symlink; point age_key_file at the key file itself"),
        ),
        Ok(m) if !m.is_file() => (Status::Fail, format!("{shown} is not a regular file")),
        Ok(m) if m.uid() != rustix::process::getuid().as_raw() => {
            (Status::Fail, format!("{shown} is owned by another user"))
        }
        Ok(m) if m.mode() & 0o077 != 0 => (
            Status::Fail,
            format!(
                "{shown} has mode {:04o}; run 'chmod 600 {}'",
                m.mode() & 0o7777,
                super::shell_path(p)
            ),
        ),
        Ok(m) if m.len() == 0 => (
            Status::Fail,
            format!("{shown} is empty; remove it and run 'secrit init'"),
        ),
        Ok(_) => (Status::Ok, shown.to_string()),
    }
}

fn sops_config_check(r: &mut Report, check: &str, backend: &SopsBackend, have_sops: bool) {
    let Some(p) = backend.sops_config() else {
        r.add(
            check,
            Status::Warn,
            format!(
                "none found upward from {}; writes use the file's own recipients, but 'secrit init' needs one to create a store file",
                backend.dir().display()
            ),
        );
        return;
    };
    if let Err(e) = backend.check_sops_config() {
        r.add(check, Status::Fail, e.to_string());
        return;
    }
    if !have_sops {
        r.add(
            check,
            Status::Info,
            format!("{} (rules not checked: no sops)", p.display()),
        );
        return;
    }
    match backend.rule_matches() {
        Ok(true) => r.add(
            check,
            Status::Ok,
            format!("{} (a creation rule covers the store file)", p.display()),
        ),
        Ok(false) => r.add(
            check,
            Status::Warn,
            format!(
                "{} has no creation rule for {}",
                p.display(),
                backend.file().display()
            ),
        ),
        Err(e) => r.add(check, Status::Warn, format!("{}: {e}", p.display())),
    }
}

/// Names in the store directory, with their modification times.
fn dir_entries(dir: &Path) -> Vec<(String, Option<SystemTime>)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<(String, Option<SystemTime>)> = entries
        .filter_map(Result::ok)
        .map(|e| {
            let mtime = e.metadata().ok().and_then(|m| m.modified().ok());
            (e.file_name().to_string_lossy().into_owned(), mtime)
        })
        .collect();
    v.sort();
    v
}

fn temp_files_check(r: &mut Report, check: &str, backend: &SopsBackend) {
    let prefix = format!(".{}.secrit-", backend.base().to_string_lossy());
    let now = SystemTime::now();
    let (mut stale, mut fresh) = (Vec::new(), Vec::new());
    for (n, mtime) in dir_entries(backend.dir()) {
        if !(n.starts_with(&prefix) && Path::new(&n).extension().is_some_and(|e| e == "yaml")) {
            continue;
        }
        let age = mtime.and_then(|m| now.duration_since(m).ok());
        if age.is_some_and(|a| a >= STALE_TEMP) {
            stale.push(escape(&n).into_owned());
        } else {
            fresh.push(escape(&n).into_owned());
        }
    }
    if !stale.is_empty() {
        r.add(
            check,
            Status::Warn,
            format!(
                "left by a crash or SIGKILL (ciphertext only); remove them when no secrit runs: {}",
                stale.join(", ")
            ),
        );
    }
    if !fresh.is_empty() {
        r.add(
            check,
            Status::Info,
            format!("a write may be running: {}", fresh.join(", ")),
        );
    }
    if stale.is_empty() && fresh.is_empty() {
        r.add(check, Status::Ok, "none");
    }
    let old: Vec<String> = dir_entries(backend.dir())
        .into_iter()
        .map(|(n, _)| n)
        .filter(|n| n.contains(OLD_BACKUP_MARK))
        .map(|n| escape(&n).into_owned())
        .collect();
    if !old.is_empty() {
        r.add(
            check,
            Status::Warn,
            format!(
                "backups from an earlier secrit sit next to the store file, one 'git add' from history; move them out: {}",
                old.join(", ")
            ),
        );
    }
}

fn backups_check(r: &mut Report, check: &str, backend: &SopsBackend) {
    let Some(dir) = backend.backup_dir() else {
        r.add(
            check,
            Status::Warn,
            "neither XDG_STATE_HOME nor HOME is absolute; writes that need a backup fail",
        );
        return;
    };
    let shown = dir.display();
    let me = rustix::process::getuid().as_raw();
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            r.add(check, Status::Ok, format!("none yet ({shown})"));
        }
        Err(e) => r.add(check, Status::Fail, format!("{shown}: {e}")),
        Ok(m) if !m.is_dir() => r.add(
            check,
            Status::Fail,
            format!("{shown} is a symlink or not a directory"),
        ),
        Ok(m) if m.uid() != me || m.mode() & 0o077 != 0 => r.add(
            check,
            Status::Fail,
            format!("{shown} must be owned by you with mode 0700"),
        ),
        Ok(_) => {
            let entries: Vec<(String, u32)> = std::fs::read_dir(dir)
                .map(|rd| {
                    rd.filter_map(Result::ok)
                        .filter_map(|e| {
                            let m = e.metadata().ok()?;
                            Some((e.file_name().to_string_lossy().into_owned(), m.uid()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            if entries.iter().any(|(_, uid)| *uid != me) {
                r.add(
                    check,
                    Status::Fail,
                    format!("{shown} holds files that another user owns"),
                );
                return;
            }
            let mut names: Vec<String> = entries.into_iter().map(|(n, _)| n).collect();
            names.sort();
            match names.first() {
                None => r.add(check, Status::Ok, format!("none yet ({shown})")),
                Some(oldest) => r.add(
                    check,
                    Status::Ok,
                    format!("{} in {shown}, oldest {}", names.len(), escape(oldest)),
                ),
            }
        }
    }
}

fn git_checks(
    r: &mut Report,
    store: &str,
    backend: &SopsBackend,
    env: &dyn Fn(&str) -> Option<OsString>,
) {
    let check = format!("store {store}: git");
    let repo = match Repo::open(backend.dir(), env) {
        Ok(Some(repo)) => repo,
        Ok(None) => {
            r.add(
                check,
                Status::Info,
                "the store directory is not in a git repository",
            );
            return;
        }
        Err(e) => {
            r.add(
                check,
                Status::Info,
                format!("{e}; repository checks skipped"),
            );
            return;
        }
    };
    let root = repo.root.display();
    match repo.is_ignored(&super::temp_sample(backend.file())) {
        Ok(true) => r.add(
            format!("store {store}: git ignore"),
            Status::Ok,
            format!("{root} ignores secrit temp copies"),
        ),
        Ok(false) => r.add(
            format!("store {store}: git ignore"),
            Status::Warn,
            format!("{root} does not ignore temp copies; add '{TEMP_IGNORE}' to its .gitignore"),
        ),
        Err(e) => r.add(
            format!("store {store}: git ignore"),
            Status::Info,
            e.to_string(),
        ),
    }
    if !backend.file().exists() {
        return;
    }
    match (repo.is_tracked(backend.file()), repo.is_flake()) {
        (Ok(true), _) => r.add(
            check,
            Status::Ok,
            format!("the store file is tracked in {root}"),
        ),
        (Ok(false), true) => r.add(
            check,
            Status::Warn,
            format!(
                "the store file is untracked, so the flake does not see it: {}",
                git_add_hint(&repo, backend.file())
            ),
        ),
        (Ok(false), false) => r.add(
            check,
            Status::Info,
            format!("the store file is untracked in {root}"),
        ),
        (Err(e), _) => r.add(check, Status::Info, e.to_string()),
    }
}

/// The `git add` line for `file` in `repo`.
pub fn git_add_hint(repo: &Repo, file: &Path) -> String {
    format!(
        "git -C {} add {}",
        super::shell_path(&repo.root),
        super::shell_path(repo.relative(file))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn age_key_rules() {
        let d = tempfile::tempdir().unwrap();
        let k = d.path().join("keys.txt");
        assert_eq!(age_key(Some(&k)).0, Status::Fail);
        std::fs::write(&k, "x").unwrap();
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (s, detail) = age_key(Some(&k));
        assert_eq!(s, Status::Fail);
        assert!(detail.contains("0644"), "{detail}");
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(age_key(Some(&k)).0, Status::Ok);
        assert_eq!(age_key(Some(d.path())).0, Status::Fail);
        assert_eq!(age_key(None).0, Status::Fail);

        // A symlink to a good key is reported, as init refuses it.
        let link = d.path().join("link.txt");
        std::os::unix::fs::symlink(&k, &link).unwrap();
        let (s, detail) = age_key(Some(&link));
        assert_eq!(s, Status::Fail);
        assert!(detail.contains("is a symlink"), "{detail}");

        let empty = d.path().join("empty.txt");
        std::fs::write(&empty, "").unwrap();
        std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (s, detail) = age_key(Some(&empty));
        assert_eq!(s, Status::Fail);
        assert!(detail.contains("is empty"), "{detail}");
    }

    /// T18: a tool found on PATH, or a mise shim, is a warning; a configured
    /// path is not. The Nix check bakes the sops path into the binary, so
    /// only a unit test with no baked path reaches the PATH branch.
    #[test]
    fn tool_rows_warn_on_path_fallback_and_shims() {
        let d = tempfile::tempdir().unwrap();
        let tool = |dir: &Path| {
            std::fs::create_dir_all(dir).unwrap();
            let p = dir.join("secrit-fake-tool");
            std::fs::write(&p, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let program = tools::Program {
            name: "secrit-fake-tool",
            config_key: "sops",
            baked: None,
        };
        let row = |setting: &crate::config::ToolSetting, path_dir: &Path| {
            let mut r = Report::default();
            let path_env = path_dir.as_os_str().to_owned();
            let env = move |k: &str| (k == "PATH").then(|| path_env.clone());
            assert!(tool_check(&mut r, program, setting, &env, true).is_some());
            assert_eq!(r.0.len(), 1, "{:?}", r.0);
            r.0.remove(0)
        };
        let auto = crate::config::ToolSetting::Auto;

        let bin = d.path().join("bin");
        tool(&bin);
        let r = row(&auto, &bin);
        assert_eq!(r.check, "secrit-fake-tool");
        assert_eq!(r.status, Status::Warn);
        assert!(r.detail.contains("from PATH"), "{}", r.detail);

        let shims = d.path().join("mise").join("shims");
        tool(&shims);
        let r = row(&auto, &shims);
        assert_eq!(r.status, Status::Warn);
        assert!(r.detail.contains("is a mise shim"), "{}", r.detail);

        let pinned = d.path().join("pinned");
        std::fs::create_dir_all(&pinned).unwrap();
        std::fs::set_permissions(&pinned, std::fs::Permissions::from_mode(0o755)).unwrap();
        let configured = crate::config::ToolSetting::Path(tool(&pinned));
        let r = row(&configured, &bin);
        assert_eq!(r.status, Status::Ok, "{}", r.detail);
    }

    /// The chmod hint is one shell word, as in init.
    #[test]
    fn the_chmod_hint_is_quoted() {
        let d = tempfile::tempdir().unwrap();
        let k = d.path().join("my keys; rm -rf x.txt");
        std::fs::write(&k, "x").unwrap();
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o640)).unwrap();
        let (_, detail) = age_key(Some(&k));
        assert!(
            detail.ends_with(&format!("run 'chmod 600 '{}''", k.display())),
            "{detail}"
        );
    }
}
