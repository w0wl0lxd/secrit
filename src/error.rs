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
    /// A safety rule refused the operation (agent, TTY, overwrite, name rule,
    /// an unsafe store file, store directory, config file, tool or lock
    /// directory).
    Refused = 3,
    /// Lock timeout, or a concurrent change after 3 retries.
    Busy = 4,
    /// A signal (INT, TERM, HUP, QUIT) stopped secrit before a write took
    /// effect, or while it waited at a prompt, the reveal screen or sops.
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
    #[error("interrupted by a signal; nothing was changed")]
    Interrupted,
    /// `init` makes several files, so an earlier step may have made one.
    #[error(
        "interrupted by a signal; files that init made before the signal are kept; run 'secrit init' again to finish"
    )]
    InitInterrupted,
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
            Error::Refused(_)
            | Error::Name(_)
            | Error::Config(ConfigError::Unsafe { .. })
            | Error::Tool(ToolError::Unsafe { .. }) => Exit::Refused,
            Error::Interrupted | Error::InitInterrupted | Error::Input(InputError::Interrupted) => {
                Exit::Interrupted
            }
            Error::Failed(_) | Error::Config(_) | Error::Input(_) | Error::Tool(_) => Exit::Failed,
            Error::Backend(e) => e.exit(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::LockError;
    use std::path::PathBuf;

    /// R3: every "unsafe file" refusal exits 3, as the README says.
    #[test]
    fn unsafe_files_exit_3() {
        let p = PathBuf::from("/x");
        let cases = [
            Error::Config(ConfigError::Unsafe {
                path: p.clone(),
                reason: "writable by group or others",
            }),
            Error::Tool(ToolError::Unsafe {
                program: "sops",
                path: p.clone(),
                reason: "writable by group or others".into(),
            }),
            Error::Backend(BackendError::Lock(LockError::UnsafeDir {
                path: p.clone(),
                reason: "owned by another user",
            })),
            Error::Backend(BackendError::Unsafe {
                path: p,
                reason: "it is a symlink".into(),
            }),
        ];
        for e in &cases {
            assert_eq!(e.exit(), Exit::Refused, "{e}");
        }
        assert_eq!(
            Error::Input(InputError::Interrupted).exit(),
            Exit::Interrupted
        );
        assert_eq!(Error::InitInterrupted.exit(), Exit::Interrupted);
        assert!(
            !Error::InitInterrupted
                .to_string()
                .contains("nothing was changed")
        );
    }
}
