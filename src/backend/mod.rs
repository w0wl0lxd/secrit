//! The backend trait (PLAN section 6.1).

pub mod sops;

use std::fmt;
use std::path::PathBuf;

use crate::config::BackendKind;
use crate::display::escape;
use crate::error::Exit;
use crate::lock::LockError;
use crate::name::{Name, NameError};
use crate::secret::SecretValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutMode {
    CreateOnly,
    Replace,
}

/// What a write did besides the write itself.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WriteReport {
    /// The ciphertext backup of the old file, when one was made.
    pub backup: Option<PathBuf>,
}

pub trait Backend {
    #[expect(dead_code, reason = "read by doctor and init (milestones M1 and M4)")]
    fn kind(&self) -> BackendKind;
    /// Top-level names, sorted, as the file holds them. Must not decrypt.
    fn list(&self) -> Result<Vec<String>, BackendError>;
    /// Must not decrypt.
    fn exists(&self, name: &Name) -> Result<bool, BackendError>;
    /// The checks of a put that need no value: NAME is not in the file yet
    /// (for `CreateOnly`), and the file's own rules would encrypt it.
    /// `store` runs them before it reads the value, so nobody types a value
    /// that will be refused (PLAN 4.1, step 1). Must not decrypt.
    fn check_put(&self, name: &Name, mode: PutMode) -> Result<(), BackendError>;
    /// The checks of a remove that `rm` runs before it asks: NAME is in the
    /// file, and no other entry is cleartext. Must not decrypt.
    fn check_remove(&self, name: &Name) -> Result<(), BackendError>;
    /// The string values of `names`, from one checked snapshot of the file.
    /// The sops backend runs one `--extract` decrypt per name, so each value
    /// lands in its own fixed buffer (SEC-8).
    fn get_many(&self, names: &[Name]) -> Result<Vec<(Name, SecretValue)>, BackendError>;
    fn put(
        &self,
        name: &Name,
        value: &SecretValue,
        mode: PutMode,
    ) -> Result<WriteReport, BackendError>;
    fn remove(&self, name: &Name) -> Result<WriteReport, BackendError>;
}

/// How often the write protocol starts over when the store file changed
/// under it, before it gives up with exit 4 (PLAN 8.1, step 11).
pub const MAX_RETRIES: usize = 3;

/// What an error is about: the store file, and the name when there is one
/// (PLAN 14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub path: PathBuf,
    pub name: Option<Name>,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(n) => write!(f, "'{n}' in {}", escape(&self.path.display().to_string())),
            None => write!(f, "{}", escape(&self.path.display().to_string())),
        }
    }
}

/// Backend errors. No variant holds a value; child stderr is redacted first.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error(
        "'{name}' already exists in {}; use --replace to overwrite it (a ciphertext backup is kept)",
        escape(&path.display().to_string())
    )]
    Exists { name: Name, path: PathBuf },
    #[error("'{name}' does not exist in {}", escape(&path.display().to_string()))]
    Missing { name: Name, path: PathBuf },
    #[error("refusing {}: {reason}", path.display())]
    Unsafe { path: PathBuf, reason: String },
    #[error(transparent)]
    Name(#[from] NameError),
    #[error("refusing to write {}: {reason}", path.display())]
    CleartextRule { path: PathBuf, reason: String },
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error(
        "{} changed while secrit was writing it, on the first try and on {MAX_RETRIES} retries; nothing was written",
        .0.display()
    )]
    Changed(PathBuf),
    #[error("{step} {}: {source}", path.display())]
    Io {
        step: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not parse {} as a sops YAML file: {what}", path.display())]
    Parse { path: PathBuf, what: String },
    #[error("sops {step} failed for {target} ({status}){stderr}")]
    Sops {
        step: &'static str,
        target: Target,
        status: String,
        stderr: String,
    },
    #[error("check of the new copy of {target} failed, the original is untouched: {reason}")]
    Validation { target: Target, reason: String },
    #[error("'{name}' holds a {kind}, not a string; secrit handles string values only")]
    NotString { name: String, kind: &'static str },
    #[error("interrupted by a signal; the original file is untouched")]
    Interrupted,
    #[error(
        "the store file {} does not exist; create it first (see the README, section 'Set up a store')",
        .0.display()
    )]
    NoStoreFile(PathBuf),
    #[error(
        "neither XDG_STATE_HOME nor HOME is an absolute path; secrit needs one for the backup directory"
    )]
    NoBackupDir,
    #[error(
        "sops {step} for {target} stopped to ask for input on the terminal (a passphrase-protected key?) and was ended. secrit v0.1 supports only an age key file without a passphrase: set age_key_file in the config"
    )]
    SopsPrompt { step: &'static str, target: Target },
    #[error(
        "sops {step} for {target} did not finish within {} ms and was ended; the original file is untouched",
        after.as_millis()
    )]
    SopsTimeout {
        step: &'static str,
        target: Target,
        after: std::time::Duration,
    },
    #[error(
        "no .sops.yaml for {}; sops needs a creation rule for it to create the file (pass --sops-config, or --write-sops-config to 'secrit init')",
        .0.display()
    )]
    NoSopsConfig(PathBuf),
    #[error("sops {step} for {target} printed more than secrit accepts; values are at most 64 KiB")]
    SopsOutputTooLarge { step: &'static str, target: Target },
    #[error(
        "{} is sops {found}; secrit needs sops 3.11 or newer (for 'set --value-stdin' and 'unset')",
        path.display()
    )]
    SopsTooOld { found: String, path: PathBuf },
}

impl BackendError {
    #[must_use]
    pub fn exit(&self) -> Exit {
        match self {
            BackendError::Exists { .. }
            | BackendError::Unsafe { .. }
            | BackendError::Name(_)
            | BackendError::CleartextRule { .. }
            | BackendError::Lock(LockError::UnsafeDir { .. }) => Exit::Refused,
            BackendError::Lock(LockError::Timeout { .. }) | BackendError::Changed(_) => Exit::Busy,
            BackendError::Interrupted | BackendError::Lock(LockError::Interrupted) => {
                Exit::Interrupted
            }
            _ => Exit::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PLAN 14: the sops errors name the step, the store file and the name.
    #[test]
    fn sops_errors_name_the_step_file_and_name() {
        let target = Target {
            path: PathBuf::from("/s/main.yaml"),
            name: Some(Name::parse("tok").unwrap()),
        };
        let e = BackendError::SopsTimeout {
            step: "set",
            target: target.clone(),
            after: std::time::Duration::from_millis(500),
        };
        let text = e.to_string();
        assert!(
            text.starts_with("sops set for 'tok' in /s/main.yaml did not finish within 500 ms"),
            "{text}"
        );
        let e = BackendError::Validation {
            target: Target {
                path: target.path.clone(),
                name: None,
            },
            reason: "the recipients or the sops settings changed".into(),
        };
        assert!(e.to_string().contains("copy of /s/main.yaml failed"), "{e}");
    }
}
