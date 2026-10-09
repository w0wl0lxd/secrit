//! The `doctor` rows of a sops store (PLAN section 4.7). Read-only: they
//! create, change and decrypt nothing, and show no value, key material or
//! hash of a value.

use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

use super::keys::{self, Shebang, SshKeyHeader};
use super::{MIN_SOPS, SopsBackend, SopsFormat};
use crate::backend::{BackendError, DoctorCtx};
use crate::cmd::doctor::git_add_hint;
use crate::cmd::shell_path;
use crate::display::escape;
use crate::git::Repo;
use crate::report::{Report, Status};

/// A temp copy younger than this may belong to a write that still runs.
const STALE_TEMP: Duration = Duration::from_secs(3600);
/// The marker in the name of a backup that secrit before 0.1 kept next to
/// the store file (SEC-2).
const OLD_BACKUP_MARK: &str = ".secrit-bak.";

/// The rows of one sops store, and the sops version row when `ctx` asks
/// for it.
pub(super) fn rows(r: &mut Report, backend: &SopsBackend, ctx: &DoctorCtx<'_>) {
    if ctx.tool_found && ctx.tool_version {
        version_check(r, backend);
    }
    store_checks(r, ctx.store, backend, ctx.tool_found, ctx.env);
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
    // v0.2 S8: one row per key source.
    key_source_rows(r, &name, backend);

    match backend.store.check_dir() {
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

/// The rows of the key sources (v0.2 plan 6.2). The age key row stays
/// when the store uses an age key file, or names no key source at all.
fn key_source_rows(r: &mut Report, name: &dyn Fn(&str) -> String, backend: &SopsBackend) {
    let keys = backend.runner.keys();
    let other = keys.ssh_key().is_some() || keys.key_cmd().is_some() || keys.plugin().is_some();
    if keys.age_key_file().is_some() || !other {
        let (status, detail) = age_key(keys.age_key_file());
        r.add(name("age key"), status, detail);
    }
    if let Some(p) = keys.ssh_key() {
        let (status, detail) = ssh_key(p);
        r.add(name("ssh key"), status, detail);
    }
    if let Some(c) = keys.key_cmd() {
        match keys::check_key_cmd(c) {
            Ok(()) => r.add(
                name("key command"),
                Status::Ok,
                format!(
                    "{}; it runs once per sops run that decrypts (a store runs it twice)",
                    c.display()
                ),
            ),
            Err(e) => r.add(name("key command"), Status::Fail, e.to_string()),
        }
        let (status, detail) = key_cmd_shebang(c);
        r.add(name("key command shebang"), status, detail);
    }
    if let Some(d) = keys.plugin_dir() {
        match keys::check_plugin_dir(d) {
            Ok(()) => r.add(
                name("age plugin directory"),
                Status::Ok,
                d.display().to_string(),
            ),
            Err(e) => r.add(name("age plugin directory"), Status::Fail, e.to_string()),
        }
    }
    if let Some(p) = keys.plugin() {
        let (status, detail) = plugin_identity(p);
        r.add(name("identity"), status, detail);
    }
}

fn ssh_key(p: &Path) -> (Status, String) {
    let shown = p.display();
    if let Err(reason) = keys::check_private_key(p) {
        return (Status::Fail, format!("{shown}: {reason}"));
    }
    match keys::ssh_key_header(p) {
        Ok(SshKeyHeader::Unencrypted) => (Status::Ok, format!("{shown} (no passphrase)")),
        Ok(SshKeyHeader::Encrypted) => (
            Status::Fail,
            format!(
                "{shown} has a passphrase; sops cannot ask for it, because secrit never gives sops the terminal (ruling Q24)"
            ),
        ),
        Ok(SshKeyHeader::NotOpenSsh) => (
            Status::Warn,
            format!("{shown} is not an OpenSSH private key; secrit cannot check its passphrase"),
        ),
        Err(e) => (Status::Fail, format!("{shown}: {e}")),
    }
}

/// T47a: the key command runs with no `PATH`, so a script needs an
/// absolute interpreter.
fn key_cmd_shebang(c: &Path) -> (Status, String) {
    let rule = "it runs with no PATH and HOME=/nonexistent, so use an absolute interpreter path, as in the README wrapper ('Keys')";
    match keys::shebang(c) {
        Ok(Shebang::Absolute) => (Status::Ok, "absolute interpreter or binary".into()),
        Ok(Shebang::Env) => (
            Status::Warn,
            format!(
                "{} uses '#!/usr/bin/env', which searches PATH; {rule}",
                c.display()
            ),
        ),
        Ok(Shebang::Missing) => (
            Status::Warn,
            format!(
                "{} has no absolute '#!' line and is not a binary; {rule}",
                c.display()
            ),
        ),
        Err(e) => (Status::Fail, format!("{}: {e}", c.display())),
    }
}

/// The stub and the level of a plugin identity. Only age-plugin-yubikey
/// reports a slot policy (6.7.8 rule 4).
fn plugin_identity(p: &keys::Plugin) -> (Status, String) {
    let stub = match p.read_stub() {
        Ok(s) => s,
        Err(e) => return (Status::Fail, e.to_string()),
    };
    let level = p.level().as_str();
    let shown = p.stub_path().display();
    match p.check_level() {
        Err(e) => (Status::Fail, e.to_string()),
        Ok(()) if stub.plugin == "yubikey" => (
            Status::Ok,
            format!("{shown} (plugin yubikey, level {level}; the slot policy allows it)"),
        ),
        Ok(()) => (
            Status::Warn,
            format!(
                "{shown} (plugin {}, level {level} not checked: secrit reads the slot policy of age-plugin-yubikey only)",
                stub.plugin
            ),
        ),
    }
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
                shell_path(p)
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
    let prefix = backend.store.temp_prefix().to_string_lossy().into_owned();
    let now = SystemTime::now();
    let (mut stale, mut fresh) = (Vec::new(), Vec::new());
    for (n, mtime) in dir_entries(backend.dir()) {
        if !(n.starts_with(&prefix)
            && Path::new(&n)
                .extension()
                .is_some_and(SopsFormat::is_temp_ext))
        {
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
    let Some(dir) = backend.store.backup_dir() else {
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
    let temp = backend.temp_ignore();
    match repo.is_ignored(&temp.sample) {
        Ok(true) => r.add(
            format!("store {store}: git ignore"),
            Status::Ok,
            format!("{root} ignores secrit temp copies"),
        ),
        Ok(false) => r.add(
            format!("store {store}: git ignore"),
            Status::Warn,
            format!(
                "{root} does not ignore temp copies; add '{}' to its .gitignore",
                temp.pattern
            ),
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
