//! `secrit doctor` (PLAN section 4.7). Read-only: it creates, changes and
//! decrypts nothing, and prints no value, key material or hash of a value.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::agent;
use crate::backend::{self, DoctorCtx};
use crate::config::{
    BackendKind, Config, ConfigSource, ENV_CONFIG, Env, StoreConfig, config_path, home,
};
use crate::display::escape;
use crate::error::Error;
use crate::git::Repo;
use crate::harden::HardenReport;
use crate::report::{Report, Status};
use crate::tools::{self, ResolvedTool, ToolSource};

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
        serde_json::to_writer_pretty(&mut out, report.rows())
            .map_err(std::io::Error::other)
            .and_then(|()| writeln!(out))
    } else {
        report.rows().iter().try_for_each(|c| {
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
    match report
        .rows()
        .iter()
        .filter(|c| c.status == Status::Fail)
        .count()
    {
        0 => Ok(()),
        n => Err(Error::Failed(format!("{n} check(s) failed"))),
    }
}

fn collect(
    config_flag: Option<&Path>,
    store_flag: Option<&str>,
    quiet: bool,
    hardened: HardenReport,
    env: &Env,
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
    // The tool rows above report a missing sops, so the store rows go on
    // with a bare name that no check runs. The sops backend asks for sops
    // only.
    let sops_path = sops
        .as_ref()
        .map_or_else(|| PathBuf::from("sops"), |t| t.path.clone());
    let tool = |_: tools::Program, _: &crate::config::ToolSetting| Ok(sops_path.clone());
    // The backend kinds whose tool version has a row already.
    let mut versioned: Vec<BackendKind> = Vec::new();
    for store in stores {
        let backend = match backend::open_with(store, &config, env, &tool) {
            Ok(b) => b,
            Err(e) => {
                r.add(format!("store {}", store.name), Status::Fail, e.to_string());
                continue;
            }
        };
        let kind = backend.kind();
        let ctx = DoctorCtx {
            store: &store.name,
            tool_found: sops.is_some(),
            tool_version: !versioned.contains(&kind),
            env,
        };
        if ctx.tool_version {
            versioned.push(kind);
        }
        backend.doctor(&mut r, &ctx);
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
            assert_eq!(r.rows().len(), 1, "{:?}", r.rows());
            r.rows()[0].clone()
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
}
