//! Subcommand handlers. Status goes to stderr, data to stdout (PLAN 8.4).

pub mod doctor;
pub mod get;
pub mod init;
pub mod ls;
pub mod rm;
pub mod store;
pub mod wire;

use std::ffi::OsString;
use std::path::Path;

use crate::backend::sops::TempIgnore;
use crate::backend::{self, Backend};
use crate::config::{
    Config, ConfigSource, ENV_CONFIG, NixConfig, SopsStore, StoreConfig, config_path, home,
};
use crate::display::escape;
use crate::error::Error;
use crate::git::Repo;
use crate::name::Name;

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
        let backend = backend::open(&store, &config, &env, quiet)?;
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

    /// After a write to a store in a git repository, the git commands that
    /// record it. secrit never commits and never runs them (Q25).
    pub fn commit_hint(&self, name: &Name, what: &str) {
        let Some(file) = self.backend.commit_hint(name) else {
            return;
        };
        let Some(root) = file.parent().and_then(crate::git::find_root) else {
            return;
        };
        let rel = file.strip_prefix(&root).unwrap_or(&file);
        let git = format!("git -C {}", shell_path(&root));
        self.status(&format!(
            "secrit never commits; to record the change, run: {git} add -A -- {} && {git} commit -m {}",
            shell_path(rel),
            shell_word(&format!("{what} {name}"))
        ));
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

/// The command that makes `repo` ignore the temp copies of `store`, or
/// `None` when it ignores them already or git cannot tell. The sops backend
/// names a sample temp copy for git to check.
pub fn ignore_hint(repo: &Repo, store: &SopsStore) -> Result<Option<String>, Error> {
    let temp = TempIgnore::of(store);
    let ignored = repo.is_ignored(&temp.sample);
    git_interrupted(&ignored)?;
    Ok(ignored.is_ok_and(|i| !i).then(|| {
        format!(
            "echo {} >> {}",
            shell_word(&temp.pattern),
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
