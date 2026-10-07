//! The backend trait (PLAN section 6.1).

pub mod sops;

use std::path::PathBuf;

use crate::config::BackendKind;
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
    #[allow(dead_code, reason = "read by doctor and init (milestones M1 and M4)")]
    fn kind(&self) -> BackendKind;
    /// Top-level names, sorted, as the file holds them. Must not decrypt.
    fn list(&self) -> Result<Vec<String>, BackendError>;
    /// Must not decrypt.
    fn exists(&self, name: &Name) -> Result<bool, BackendError>;
    /// One decrypt for all names.
    fn get_many(&self, names: &[Name]) -> Result<Vec<(Name, SecretValue)>, BackendError>;
    fn put(
        &self,
        name: &Name,
        value: &SecretValue,
        mode: PutMode,
    ) -> Result<WriteReport, BackendError>;
    fn remove(&self, name: &Name) -> Result<WriteReport, BackendError>;
}

/// Backend errors. No variant holds a value; child stderr is redacted first.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("'{0}' already exists; use --replace to overwrite it (a ciphertext backup is kept)")]
    Exists(Name),
    #[error("'{0}' does not exist")]
    Missing(Name),
    #[error("refusing {}: {reason}", path.display())]
    Unsafe { path: PathBuf, reason: String },
    #[error(transparent)]
    Name(#[from] NameError),
    #[error("refusing to write {}: {reason}", path.display())]
    CleartextRule { path: PathBuf, reason: String },
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error("{} changed while secrit was writing it, 3 times; nothing was written", .0.display())]
    Changed(PathBuf),
    #[error("{step} {}: {source}", path.display())]
    Io {
        step: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not parse {} as a sops YAML file: {what}", path.display())]
    Parse { path: PathBuf, what: String },
    #[error("sops {step} failed ({status}){stderr}")]
    Sops {
        step: &'static str,
        status: String,
        stderr: String,
    },
    #[error("check of the new file failed, the original is untouched: {0}")]
    Validation(String),
    #[error("'{name}' holds a {kind}, not a string; secrit handles string values only")]
    NotString { name: String, kind: &'static str },
    #[error("interrupted by a signal; the original file is untouched")]
    Interrupted,
}

impl BackendError {
    #[must_use]
    pub fn exit(&self) -> Exit {
        match self {
            BackendError::Exists(_)
            | BackendError::Unsafe { .. }
            | BackendError::Name(_)
            | BackendError::CleartextRule { .. }
            | BackendError::Lock(LockError::UnsafeDir { .. }) => Exit::Refused,
            BackendError::Lock(LockError::Timeout { .. }) | BackendError::Changed(_) => Exit::Busy,
            BackendError::Interrupted => Exit::Interrupted,
            _ => Exit::Failed,
        }
    }
}
