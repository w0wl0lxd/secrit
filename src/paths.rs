//! Default paths that follow the platform (v0.2 plan 8.1). `init`, `doctor`
//! and the sops backend take them from here, so the macOS port (S17)
//! changes this file and not its callers.

use std::path::PathBuf;

use crate::config::Env;

/// The value of `var` when it is an absolute path.
fn abs_var(env: &Env, var: &str) -> Option<PathBuf> {
    env(var).map(PathBuf::from).filter(|p| p.is_absolute())
}

/// sops's own default age key file: `$XDG_CONFIG_HOME/sops/age/keys.txt`,
/// else `~/.config/sops/age/keys.txt`. secrit makes it explicit, because
/// sops gets no real HOME (R2).
pub fn default_age_key_file(env: &Env) -> Option<PathBuf> {
    abs_var(env, "XDG_CONFIG_HOME")
        .or_else(|| abs_var(env, "HOME").map(|h| h.join(".config")))
        .map(|c| c.join("sops").join("age").join("keys.txt"))
}

/// The directory of the lock files: `$XDG_RUNTIME_DIR`.
pub fn runtime_dir(env: &Env) -> Option<PathBuf> {
    abs_var(env, "XDG_RUNTIME_DIR")
}

/// The backup directory: `$XDG_STATE_HOME/secrit/backups`, else
/// `~/.local/state/secrit/backups`.
pub fn backup_dir(env: &Env) -> Option<PathBuf> {
    abs_var(env, "XDG_STATE_HOME")
        .or_else(|| abs_var(env, "HOME").map(|h| h.join(".local").join("state")))
        .map(|s| s.join("secrit").join("backups"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::Path;

    fn env_of(vars: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        move |k| {
            vars.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[test]
    fn the_age_key_follows_xdg_then_home() {
        let both = env_of(&[("XDG_CONFIG_HOME", "/x/cfg"), ("HOME", "/h")]);
        assert_eq!(
            default_age_key_file(&both).as_deref(),
            Some(Path::new("/x/cfg/sops/age/keys.txt"))
        );
        let relative = env_of(&[("XDG_CONFIG_HOME", "cfg"), ("HOME", "/h")]);
        assert_eq!(
            default_age_key_file(&relative).as_deref(),
            Some(Path::new("/h/.config/sops/age/keys.txt"))
        );
        assert_eq!(default_age_key_file(&env_of(&[("HOME", "h")])), None);
        assert_eq!(default_age_key_file(&env_of(&[])), None);
    }

    #[test]
    fn the_backup_dir_follows_xdg_then_home() {
        let both = env_of(&[("XDG_STATE_HOME", "/x/state"), ("HOME", "/h")]);
        assert_eq!(
            backup_dir(&both).as_deref(),
            Some(Path::new("/x/state/secrit/backups"))
        );
        let relative = env_of(&[("XDG_STATE_HOME", "state"), ("HOME", "/h")]);
        assert_eq!(
            backup_dir(&relative).as_deref(),
            Some(Path::new("/h/.local/state/secrit/backups"))
        );
        assert_eq!(backup_dir(&env_of(&[("HOME", "h")])), None);
        assert_eq!(
            runtime_dir(&env_of(&[("XDG_RUNTIME_DIR", "/run/u")])).as_deref(),
            Some(Path::new("/run/u"))
        );
        assert_eq!(runtime_dir(&env_of(&[("XDG_RUNTIME_DIR", "run")])), None);
    }
}
