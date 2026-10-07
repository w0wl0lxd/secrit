//! The top-level error type and the exit-code contract (PLAN section 4).
//!
//! No variant holds a secret value. Messages name the file, the name and the
//! step, never the value, its length or a hash of it.

use crate::backend::BackendError;
use crate::config::ConfigError;
use crate::name::NameError;
use crate::secret::InputError;
use crate::tools::ToolError;

/// Process exit codes. `0` is success and is not listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The operation failed.
    Failed = 1,
    /// The command line was wrong.
    Usage = 2,
    /// A safety rule refused the operation (agent, TTY, overwrite, name rule).
    Refused = 3,
    /// Lock timeout, or a concurrent change after 3 retries.
    Busy = 4,
    /// A signal (INT, TERM, HUP) cancelled a write before it took effect.
    Interrupted = 130,
}

impl Exit {
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Failed(String),
    #[error(
        "'secrit {command}' is not implemented yet (planned for milestone {milestone}; see docs/PLAN.md)"
    )]
    NotImplemented {
        command: &'static str,
        milestone: &'static str,
    },
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Name(#[from] NameError),
    #[error(transparent)]
    Input(#[from] InputError),
    #[error(transparent)]
    Backend(#[from] BackendError),
    #[error(transparent)]
    Tool(#[from] ToolError),
}

impl Error {
    #[must_use]
    pub fn exit(&self) -> Exit {
        match self {
            Error::Usage(_) => Exit::Usage,
            Error::Refused(_) | Error::Name(_) => Exit::Refused,
            Error::Failed(_)
            | Error::NotImplemented { .. }
            | Error::Config(_)
            | Error::Input(_)
            | Error::Tool(_) => Exit::Failed,
            Error::Backend(e) => e.exit(),
        }
    }
}
