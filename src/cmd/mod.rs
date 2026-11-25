//! Subcommand handlers. Status goes to stderr, data to stdout (PLAN 8.4).

pub mod doctor;
pub mod get;
pub mod init;
pub mod ls;
pub mod rm;
pub mod store;
pub mod wire;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::backend::Backend;
use crate::backend::sops::{SopsBackend, TEMP_IGNORE};
use crate::config::{
    BackendKind, Config, ConfigSource, ENV_CONFIG, NixConfig, StoreConfig, config_path, home,
};
use crate::display::escape;
use crate::error::Error;
use crate::git::Repo;
use crate::name::Name;
use crate::tools::{self, ResolvedTool, ToolSource};

/// What every store-backed command needs.
pub struct Ctx {
    pub quiet: bool,
    pub store: StoreConfig,
    pub nix: Option<NixConfig>,
    pub backend: Box<dyn Backend>,
}

impl Ctx {
    /// Load the config, pick the store, and build its backend.
    pub fn load(
        config_flag: Option<&std::path::Path>,
        store_flag: Option<&str>,
        quiet: bool,
    ) -> Result<Self, Error> {
        let env = |k: &str| std::env::var_os(k);
        let (path, source) = config_path(config_flag, &env)?;
        note_config_source(&path, source, quiet);
        let config = Config::load(&path, &home(&env)?)?;
        let store = config.store(store_flag)?.clone();
        let backend: Box<dyn Backend> = match store.backend {
            BackendKind::Sops => {
                let sops = tools::resolve(
                    tools::SOPS,
                    &config.tools.sops,
                    std::env::var_os("PATH").as_deref(),
                )?;
                warn_on_path_fallback(&sops, quiet);
                Box::new(SopsBackend::new(
                    &store,
                    sops.path,
                    config.lock_timeout,
                    &env,
                )?)
            }
        };
        Ok(Self {
            quiet,
            store,
            nix: config.nix,
            backend,
        })
    }

    pub fn status(&self, msg: &str) {
        if !self.quiet {
            eprintln!("{msg}");
        }
    }
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("store", &self.store.name)
            .finish_non_exhaustive()
    }
}

/// A variable is not visible on the command line, so name the file it
/// picked (SEC-10). Every command that reads the config calls this.
pub fn note_config_source(path: &Path, source: ConfigSource, quiet: bool) {
    if source == ConfigSource::Env && !quiet {
        eprintln!(
            "secrit: using config {} from {ENV_CONFIG}",
            escape(&path.display().to_string())
        );
    }
}

/// A temp copy name for `file` (PLAN 8.1, step 6), to ask git whether it
/// ignores temp copies.
#[must_use]
pub fn temp_sample(file: &Path) -> PathBuf {
    file.with_file_name(format!(
        ".{}.secrit-0000000000000000.yaml",
        file.file_name().unwrap_or_default().to_string_lossy()
    ))
}

/// The command that makes `repo` ignore the temp copies of `file`, or `None`
/// when it ignores them already or git cannot tell.
pub fn ignore_hint(repo: &Repo, file: &Path) -> Result<Option<String>, Error> {
    let ignored = repo.is_ignored(&temp_sample(file));
    git_interrupted(&ignored)?;
    Ok(ignored.is_ok_and(|i| !i).then(|| {
        format!(
            "echo {} >> {}",
            shell_word(TEMP_IGNORE),
            shell_path(&repo.root.join(".gitignore"))
        )
    }))
}

/// The reminder that goes with the `git add` hint (PLAN 20, Q1).
#[must_use]
pub fn spell_hint(repo: &Repo, file: &Path) -> String {
    format!(
        "if a pre-commit spell checker (such as typos) runs in {}, exclude {} from it; ciphertext can fail it",
        shell_path(&repo.root),
        shell_path(repo.relative(file))
    )
}

fn warn_on_path_fallback(tool: &ResolvedTool, quiet: bool) {
    if tool.source == ToolSource::Path && !quiet {
        eprintln!(
            "secrit: warning: using {} from PATH; set tools.sops to an absolute path, or install secrit with Nix to pin it",
            tool.path.display()
        );
    }
}

/// `s` as one shell word, for a command that secrit prints for the user to
/// run. Control characters are escaped first, so the line cannot drive the
/// terminal.
#[must_use]
pub fn shell_word(s: &str) -> String {
    let s = escape(s);
    // '#' starts a comment only at the start of a word.
    let plain = !s.is_empty()
        && !s.starts_with('#')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._+-=:@%,#".contains(c));
    if plain {
        s.into_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// [`shell_word`] for a path.
#[must_use]
pub fn shell_path(p: &Path) -> String {
    shell_word(&p.to_string_lossy())
}

/// `Err(Error::Interrupted)` when a deferred signal arrived. A step that
/// turns a child's errors into rows or hints checks this after it, so a
/// signal during that child still exits 130 and prints no false result.
pub fn interrupted() -> Result<(), Error> {
    if crate::signals::pending() {
        Err(Error::Interrupted)
    } else {
        Ok(())
    }
}

/// Whether `r` is a git query that a signal stopped.
fn git_interrupted<T>(r: &Result<T, crate::git::GitError>) -> Result<(), Error> {
    match r {
        Err(crate::git::GitError::Interrupted(_)) => Err(Error::Interrupted),
        _ => Ok(()),
    }
}

pub fn parse_name(s: &str) -> Result<Name, Error> {
    Ok(Name::parse(s)?)
}

/// The arguments to `store`, after clap.
#[derive(Debug)]
pub struct StoreArgs {
    pub name: String,
    pub replace: bool,
    pub multiline: bool,
    pub raw: bool,
    pub extra: Vec<OsString>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_words_are_quoted_when_needed() {
        assert_eq!(shell_word("/etc/nixos"), "/etc/nixos");
        assert_eq!(shell_word("a b"), "'a b'");
        assert_eq!(shell_word("it's"), "'it'\\''s'");
        assert_eq!(shell_word(""), "''");
        assert_eq!(shell_word("$(x)"), "'$(x)'");
        assert_eq!(shell_word("/etc/nixos#myhost"), "/etc/nixos#myhost");
        assert_eq!(shell_word("#x"), "'#x'");
        assert_eq!(shell_word("a\u{1b}b"), "'a\\x1bb'");
    }
}
