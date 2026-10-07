//! External tool resolution (PLAN section 10.2).
//!
//! Order for `"auto"`: the absolute path baked in at build time (the Nix
//! package sets `SECRIT_SOPS_BIN` and `SECRIT_AGE_KEYGEN_BIN`), else the first
//! match on the absolute entries of `PATH`. A configured path must be absolute.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::config::ToolSetting;

pub const BAKED_SOPS: Option<&str> = option_env!("SECRIT_SOPS_BIN");
#[allow(dead_code, reason = "used by init (milestone M4)")]
pub const BAKED_AGE_KEYGEN: Option<&str> = option_env!("SECRIT_AGE_KEYGEN_BIN");

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error(
        "{program} not found; install it (for example 'nix profile add nixpkgs#sops nixpkgs#age') or set tools.{key} in the config"
    )]
    NotFound {
        program: &'static str,
        key: &'static str,
    },
    #[error("configured {program} at {} does not exist or is not a file", path.display())]
    Missing {
        program: &'static str,
        path: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolSource {
    Configured,
    Baked,
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTool {
    pub path: PathBuf,
    pub source: ToolSource,
}

#[derive(Debug, Clone, Copy)]
pub struct Program {
    pub name: &'static str,
    pub config_key: &'static str,
    pub baked: Option<&'static str>,
}

pub const SOPS: Program = Program {
    name: "sops",
    config_key: "sops",
    baked: BAKED_SOPS,
};

#[allow(dead_code, reason = "used by init (milestone M4)")]
pub const AGE_KEYGEN: Program = Program {
    name: "age-keygen",
    config_key: "age_keygen",
    baked: BAKED_AGE_KEYGEN,
};

/// Resolve `program` by the rules above. `path_env` is the value of `PATH`.
pub fn resolve(
    program: Program,
    setting: &ToolSetting,
    path_env: Option<&OsStr>,
) -> Result<ResolvedTool, ToolError> {
    if let ToolSetting::Path(p) = setting {
        return if p.is_file() {
            Ok(ResolvedTool {
                path: p.clone(),
                source: ToolSource::Configured,
            })
        } else {
            Err(ToolError::Missing {
                program: program.name,
                path: p.clone(),
            })
        };
    }
    if let Some(b) = program.baked.map(Path::new).filter(|p| p.is_file()) {
        return Ok(ResolvedTool {
            path: b.to_path_buf(),
            source: ToolSource::Baked,
        });
    }
    let not_found = || ToolError::NotFound {
        program: program.name,
        key: program.config_key,
    };
    // Relative PATH entries would resolve against the working directory.
    let absolute: Vec<PathBuf> = path_env
        .map(|p| {
            std::env::split_paths(p)
                .filter(|d| d.is_absolute())
                .collect()
        })
        .unwrap_or_default();
    let joined: OsString = std::env::join_paths(absolute).map_err(|_| not_found())?;
    // Do not canonicalize: a mise shim is a symlink whose target needs argv[0].
    let found = which::which_in(program.name, Some(joined), "/").map_err(|_| not_found())?;
    Ok(ResolvedTool {
        path: found,
        source: ToolSource::Path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake_bin(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn program(baked: Option<&'static str>) -> Program {
        Program {
            name: "secrit-fake-tool",
            config_key: "sops",
            baked,
        }
    }

    /// T18: configured path, then baked path, then PATH.
    #[test]
    fn resolution_order() {
        let d = tempfile::tempdir().unwrap();
        let on_path = fake_bin(d.path(), "secrit-fake-tool");
        let path_env = d.path().as_os_str();

        let configured = fake_bin(d.path(), "configured");
        let r = resolve(
            program(None),
            &ToolSetting::Path(configured.clone()),
            Some(path_env),
        )
        .unwrap();
        assert_eq!(
            r,
            ResolvedTool {
                path: configured,
                source: ToolSource::Configured
            }
        );

        // A leaked path is fine for a test; it must be 'static like option_env!.
        let baked: &'static str = Box::leak(
            fake_bin(d.path(), "baked")
                .to_str()
                .unwrap()
                .to_owned()
                .into_boxed_str(),
        );
        let r = resolve(program(Some(baked)), &ToolSetting::Auto, Some(path_env)).unwrap();
        assert_eq!(r.source, ToolSource::Baked);

        let r = resolve(
            program(Some("/nonexistent/x")),
            &ToolSetting::Auto,
            Some(path_env),
        )
        .unwrap();
        assert_eq!(
            r,
            ResolvedTool {
                path: on_path,
                source: ToolSource::Path
            }
        );
    }

    #[test]
    fn missing_tools_are_errors() {
        let d = tempfile::tempdir().unwrap();
        assert!(matches!(
            resolve(
                program(None),
                &ToolSetting::Path(d.path().join("nope")),
                None
            ),
            Err(ToolError::Missing { .. })
        ));
        assert!(matches!(
            resolve(
                program(None),
                &ToolSetting::Auto,
                Some(d.path().as_os_str())
            ),
            Err(ToolError::NotFound { .. })
        ));
    }

    #[test]
    fn relative_path_entries_are_ignored() {
        let d = tempfile::tempdir().unwrap();
        fake_bin(d.path(), "secrit-fake-tool");
        let rel = OsStr::new("relative/dir:.");
        assert!(resolve(program(None), &ToolSetting::Auto, Some(rel)).is_err());
    }
}
