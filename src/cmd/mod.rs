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

use crate::agent;
use crate::backend::sops::TEMP_IGNORE;
use crate::backend::{self, Backend};
use crate::config::{Config, ConfigSource, ENV_CONFIG, NixConfig, StoreConfig, config_path, home};
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

/// How the write gate let a command through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gated {
    /// No agent and a terminal: the command runs as in v0.1.
    Open,
    /// The person typed the name on the terminal.
    Confirmed,
}

/// The write gate of `store`, `rm` and `init` (PLAN-v0.2 4.1, 4.2).
/// `question` gets the agent and returns the text to ask; the answer must
/// equal `expected`. A wrong answer exits 3 with `not confirmed`; no
/// terminal exits 3 with the Q19 text.
pub fn write_gate(
    question: impl FnOnce(&agent::Agent) -> String,
    expected: &str,
) -> Result<Gated, Error> {
    if crate::testhook::gate_open() {
        return Ok(Gated::Open);
    }
    let tty_opens = agent::tty_opens();
    match agent::write_gate(agent::detect_tty(tty_opens), tty_opens) {
        agent::WriteGate::Allow => Ok(Gated::Open),
        agent::WriteGate::Refuse => Err(Error::Refused(agent::NO_TTY_REFUSAL.into())),
        agent::WriteGate::ConfirmOnTty(a) => {
            if crate::tty::confirm_typed(&question(&a), expected)? {
                Ok(Gated::Confirmed)
            } else {
                Err(Error::Refused("not confirmed".into()))
            }
        }
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
