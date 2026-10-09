//! The backend trait (PLAN section 6.1; v0.2 plan section 5.1) and the
//! factory that builds a store's backend from the config.

pub mod atomic;
pub mod sops;

use std::fmt;
use std::path::PathBuf;

use crate::config::{BackendConfig, BackendKind, Config, Env, StoreConfig, ToolSetting};
use crate::display::escape_path;
use crate::error::{Error, Exit};
use crate::lock::LockError;
use crate::name::{Name, NameError};
use crate::report::Report;
use crate::secret::SecretValue;
use crate::tools::{self, Program, ResolvedTool, ToolSource};

use self::sops::{SopsBackend, SopsFormat};

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

/// What a backend can do, for the commands that adapt to it (v0.2 plan
/// 5.2). A field joins in the slice that first reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Names with more than one segment (`a/b`) address nested keys.
    pub nested_names: bool,
}

impl Capabilities {
    /// Refuse `name` when the store cannot hold it (v0.2 plan 5.2): a
    /// nested name needs `nested_names`. Exit 3, before any input.
    pub fn check_name(self, name: &Name, location: &Location) -> Result<(), BackendError> {
        if name.is_nested() && !self.nested_names {
            return Err(BackendError::Capability {
                location: location.clone(),
                what: "nested names (a name with '/')",
            });
        }
        Ok(())
    }
}

pub trait Backend {
    fn kind(&self) -> BackendKind;
    fn capabilities(&self) -> Capabilities;
    /// Where the store lives, for messages and errors.
    fn location(&self) -> &Location;
    /// Names as the store holds them, sorted: key paths joined by `/`.
    /// Raw strings: another tool can write a key that is not a valid
    /// `Name`; `ls` escapes it. Must not decrypt.
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
    /// The backend's own `doctor` rows (store file, keys, rules, git).
    /// Read-only: it creates, changes and decrypts nothing.
    fn doctor(&self, report: &mut Report, ctx: &DoctorCtx<'_>);
    /// What `wire` can tell a consumer about NAME, if anything (v0.2 plan
    /// 5.7). Must not decrypt.
    fn wire_source(&self, name: &Name) -> Option<WireSource>;
}

/// Where a consumer such as sops-nix reads a secret (v0.2 plan 5.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireSource {
    /// A sops file, with the format that sops-nix must read it as, and
    /// the key path when it is not the plain name (a nested name).
    SopsFile {
        file: PathBuf,
        format: SopsFormat,
        key: Option<Name>,
    },
    /// A sops file that sops-nix gives to a consumer only as one whole
    /// file (dotenv, INI), so `wire` cannot expose one name of it.
    WholeSopsFile { file: PathBuf, format: SopsFormat },
}

/// What `doctor` gives a backend for its own rows.
pub struct DoctorCtx<'a> {
    /// The store name, for the row labels.
    pub store: &'a str,
    /// Whether the tool that the backend runs was found. When it was not,
    /// the backend skips the rows that need it.
    pub tool_found: bool,
    /// Whether this store also checks the tool's version. `doctor` sets it
    /// for the first store of each backend kind, so the row shows once.
    pub tool_version: bool,
    pub env: &'a Env,
}

impl fmt::Debug for DoctorCtx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DoctorCtx")
            .field("store", &self.store)
            .field("tool_found", &self.tool_found)
            .field("tool_version", &self.tool_version)
            .finish_non_exhaustive()
    }
}

/// Build the backend of `store`: resolve the tool that it runs, warn when
/// the tool came from `PATH`, and check the store's own settings.
pub fn open(
    store: &StoreConfig,
    config: &Config,
    env: &Env,
    quiet: bool,
) -> Result<Box<dyn Backend>, Error> {
    open_with(store, config, env, &|program, setting| {
        let tool = tools::resolve(program, setting, env("PATH").as_deref())?;
        warn_on_path_fallback(program, &tool, quiet);
        Ok(tool.path)
    })
}

/// [`open`] with the caller's tool lookup. `doctor` resolves each tool once
/// and reports a missing one as a row, so its lookup does not fail.
pub fn open_with(
    store: &StoreConfig,
    config: &Config,
    env: &Env,
    tool: &dyn Fn(Program, &ToolSetting) -> Result<PathBuf, Error>,
) -> Result<Box<dyn Backend>, Error> {
    match &store.backend {
        BackendConfig::Sops(sops) => {
            let path = tool(tools::SOPS, &config.tools.sops)?;
            Ok(Box::new(SopsBackend::new(
                sops,
                path,
                config.lock_timeout,
                env,
            )?))
        }
    }
}

fn warn_on_path_fallback(program: Program, tool: &ResolvedTool, quiet: bool) {
    if tool.source == ToolSource::Path && !quiet {
        eprintln!(
            "secrit: warning: using {} from PATH; set tools.{} to an absolute path, or install secrit with Nix to pin it",
            tool.path.display(),
            program.config_key
        );
    }
}

/// How often the write protocol starts over when the store file changed
/// under it, before it gives up with exit 4 (PLAN 8.1, step 11).
pub const MAX_RETRIES: usize = 3;

/// Where a store lives (v0.2 plan 5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// One file that holds every name.
    File(PathBuf),
}

/// Control characters are escaped, so a path cannot drive the terminal.
impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Location::File(p) => f.write_str(&escape_path(p)),
        }
    }
}

/// What an error is about: the store, and the name when there is one
/// (PLAN 14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub location: Location,
    pub name: Option<Name>,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(n) => write!(f, "'{n}' in {}", self.location),
            None => write!(f, "{}", self.location),
        }
    }
}

/// How a tool run ended: its exit code, or `None` when a signal ended it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolStatus(pub Option<i32>);

impl fmt::Display for ToolStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(c) => write!(f, "exit {c}"),
            None => f.write_str("killed by a signal"),
        }
    }
}

/// Backend errors. No variant holds a value; child stderr is redacted first.
///
/// The `Tool*` variants name the tool that ran, so a backend that runs
/// another tool than sops reuses them. With `tool = "sops"` each one prints
/// the v0.1 text.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error(
        "'{name}' already exists in {location}; use --replace to overwrite it (a ciphertext backup is kept)"
    )]
    Exists { name: Name, location: Location },
    #[error("'{name}' does not exist in {location}")]
    Missing { name: Name, location: Location },
    /// The key path of the name conflicts with the store's tree (T49).
    #[error("refusing '{name}' in {location}: {reason}")]
    KeyPath {
        name: Name,
        location: Location,
        reason: String,
    },
    /// The store's backend cannot do what the command asks (v0.2 plan 5.2).
    #[error("the store {location} does not support {what}")]
    Capability {
        location: Location,
        what: &'static str,
    },
    #[error("refusing {}: {reason}", escape_path(path))]
    Unsafe { path: PathBuf, reason: String },
    #[error(transparent)]
    Name(#[from] NameError),
    #[error("refusing to write {}: {reason}", escape_path(path))]
    CleartextRule { path: PathBuf, reason: String },
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error(
        "{} changed while secrit was writing it, on the first try and on {MAX_RETRIES} retries; nothing was written",
        escape_path(.0)
    )]
    Changed(PathBuf),
    #[error("{step} {}: {source}", escape_path(path))]
    Io {
        step: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    /// `format` names what the store should be, such as "sops YAML file".
    #[error("could not parse {location} as a {format}: {what}")]
    Parse {
        location: Location,
        format: &'static str,
        what: String,
    },
    #[error("{tool} {step} failed for {target} ({status}){stderr}")]
    Tool {
        tool: &'static str,
        step: &'static str,
        target: Target,
        status: ToolStatus,
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
        escape_path(.0)
    )]
    NoStoreFile(PathBuf),
    #[error(
        "neither XDG_STATE_HOME nor HOME is an absolute path; secrit needs one for the backup directory"
    )]
    NoBackupDir,
    /// The tool read the terminal from a background process group and was
    /// stopped. `hint` is the backend's advice on the key to configure.
    #[error(
        "{tool} {step} for {target} stopped to ask for input on the terminal (a passphrase-protected key?) and was ended. {hint}"
    )]
    ToolPrompt {
        tool: &'static str,
        step: &'static str,
        target: Target,
        hint: String,
    },
    #[error(
        "{tool} {step} for {target} did not finish within {} ms and was ended; the original file is untouched",
        after.as_millis()
    )]
    ToolTimeout {
        tool: &'static str,
        step: &'static str,
        target: Target,
        after: std::time::Duration,
    },
    #[error(
        "no .sops.yaml for {}; sops needs a creation rule for it to create the file (pass --sops-config, or --write-sops-config to 'secrit init')",
        escape_path(.0)
    )]
    NoSopsConfig(PathBuf),
    #[error(
        "{tool} {step} for {target} printed more than secrit accepts; values are at most 64 KiB"
    )]
    ToolOutputTooLarge {
        tool: &'static str,
        step: &'static str,
        target: Target,
    },
    /// `need` is the oldest version secrit accepts and why.
    #[error("{} is {tool} {found}; secrit needs {tool} {need}", escape_path(path))]
    ToolTooOld {
        tool: &'static str,
        found: String,
        path: PathBuf,
        need: &'static str,
    },
}

impl BackendError {
    #[must_use]
    pub fn exit(&self) -> Exit {
        match self {
            BackendError::Exists { .. }
            | BackendError::KeyPath { .. }
            | BackendError::Capability { .. }
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
    use std::time::Duration;

    /// PLAN 14: the sops errors name the step, the store file and the name.
    #[test]
    fn sops_errors_name_the_step_file_and_name() {
        let target = Target {
            location: Location::File(PathBuf::from("/s/main.yaml")),
            name: Some(Name::parse("tok").unwrap()),
        };
        let e = BackendError::ToolTimeout {
            tool: "sops",
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
                location: target.location.clone(),
                name: None,
            },
            reason: "the recipients or the sops settings changed".into(),
        };
        assert!(e.to_string().contains("copy of /s/main.yaml failed"), "{e}");
    }

    fn p() -> PathBuf {
        PathBuf::from("/s/main.yaml")
    }

    fn file() -> Location {
        Location::File(p())
    }

    fn tok() -> Name {
        Name::parse("tok").unwrap()
    }

    fn named() -> Target {
        Target {
            location: file(),
            name: Some(tok()),
        }
    }

    fn assert_texts(cases: &[(BackendError, &str)]) {
        for (e, want) in cases {
            assert_eq!(e.to_string(), *want);
        }
    }

    /// Golden test: every error that is not about a tool run renders the
    /// v0.1 text (v0.2 plan S1a changes no message).
    #[test]
    fn store_error_messages_are_unchanged() {
        let io = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_texts(&[
            (
                BackendError::Exists {
                    name: tok(),
                    location: file(),
                },
                "'tok' already exists in /s/main.yaml; use --replace to overwrite it (a ciphertext backup is kept)",
            ),
            (
                BackendError::Missing {
                    name: tok(),
                    location: file(),
                },
                "'tok' does not exist in /s/main.yaml",
            ),
            (
                BackendError::Unsafe {
                    path: p(),
                    reason: "it is a symlink".into(),
                },
                "refusing /s/main.yaml: it is a symlink",
            ),
            (
                BackendError::CleartextRule {
                    path: p(),
                    reason: "entry 'x' is not encrypted".into(),
                },
                "refusing to write /s/main.yaml: entry 'x' is not encrypted",
            ),
            (
                BackendError::Changed(p()),
                "/s/main.yaml changed while secrit was writing it, on the first try and on 3 retries; nothing was written",
            ),
            (
                BackendError::Io {
                    step: "open",
                    path: p(),
                    source: io,
                },
                "open /s/main.yaml: permission denied",
            ),
            (
                BackendError::Parse {
                    location: file(),
                    format: "sops YAML file",
                    what: "invalid YAML".into(),
                },
                "could not parse /s/main.yaml as a sops YAML file: invalid YAML",
            ),
            (
                BackendError::Validation {
                    target: named(),
                    reason: "'tok' is still present".into(),
                },
                "check of the new copy of 'tok' in /s/main.yaml failed, the original is untouched: 'tok' is still present",
            ),
            (
                BackendError::NotString {
                    name: "tok".into(),
                    kind: "number",
                },
                "'tok' holds a number, not a string; secrit handles string values only",
            ),
            (
                BackendError::Interrupted,
                "interrupted by a signal; the original file is untouched",
            ),
            (
                BackendError::NoStoreFile(p()),
                "the store file /s/main.yaml does not exist; create it first (see the README, section 'Set up a store')",
            ),
            (
                BackendError::NoBackupDir,
                "neither XDG_STATE_HOME nor HOME is an absolute path; secrit needs one for the backup directory",
            ),
            (
                BackendError::NoSopsConfig(p()),
                "no .sops.yaml for /s/main.yaml; sops needs a creation rule for it to create the file (pass --sops-config, or --write-sops-config to 'secrit init')",
            ),
        ]);
    }

    /// Golden test: the generic tool errors render the v0.1 sops text with
    /// `tool = "sops"`.
    #[test]
    fn tool_error_messages_are_unchanged() {
        assert_texts(&[
            (
                BackendError::Tool {
                    tool: "sops",
                    step: "set",
                    target: named(),
                    status: ToolStatus(Some(1)),
                    stderr: ":\n  bad".into(),
                },
                "sops set failed for 'tok' in /s/main.yaml (exit 1):\n  bad",
            ),
            (
                BackendError::Tool {
                    tool: "sops",
                    step: "encrypt",
                    target: Target {
                        location: file(),
                        name: None,
                    },
                    status: ToolStatus(None),
                    stderr: String::new(),
                },
                "sops encrypt failed for /s/main.yaml (killed by a signal)",
            ),
            (
                BackendError::ToolPrompt {
                    tool: "sops",
                    step: "decrypt",
                    target: named(),
                    hint: sops::PROMPT_HINT.into(),
                },
                "sops decrypt for 'tok' in /s/main.yaml stopped to ask for input on the terminal (a passphrase-protected key?) and was ended. secrit v0.1 supports only an age key file without a passphrase: set age_key_file in the config",
            ),
            (
                BackendError::ToolTimeout {
                    tool: "sops",
                    step: "set",
                    target: named(),
                    after: Duration::from_millis(1500),
                },
                "sops set for 'tok' in /s/main.yaml did not finish within 1500 ms and was ended; the original file is untouched",
            ),
            (
                BackendError::ToolOutputTooLarge {
                    tool: "sops",
                    step: "decrypt",
                    target: named(),
                },
                "sops decrypt for 'tok' in /s/main.yaml printed more than secrit accepts; values are at most 64 KiB",
            ),
            (
                BackendError::ToolTooOld {
                    tool: "sops",
                    found: "3.10.0".into(),
                    path: PathBuf::from("/bin/sops"),
                    need: sops::NEED_SOPS,
                },
                "/bin/sops is sops 3.10.0; secrit needs sops 3.11 or newer (for 'set --value-stdin' and 'unset')",
            ),
        ]);
    }

    /// v0.2 plan 5.2: a nested name on a store without nested keys exits
    /// 3 and names the store; a one-segment name always passes.
    #[test]
    fn a_nested_name_needs_the_capability() {
        let flat = Capabilities {
            nested_names: false,
        };
        let nested = Capabilities { nested_names: true };
        let ab = Name::parse("a/b").unwrap();
        let e = flat.check_name(&ab, &file()).unwrap_err();
        assert_eq!(e.exit(), Exit::Refused);
        assert_eq!(
            e.to_string(),
            "the store /s/main.yaml does not support nested names (a name with '/')"
        );
        assert!(flat.check_name(&tok(), &file()).is_ok());
        assert!(nested.check_name(&ab, &file()).is_ok());
        let e = BackendError::KeyPath {
            name: ab,
            location: file(),
            reason: "'a' holds a string, not a map".into(),
        };
        assert_eq!(e.exit(), Exit::Refused);
        assert_eq!(
            e.to_string(),
            "refusing 'a/b' in /s/main.yaml: 'a' holds a string, not a map"
        );
    }

    /// A store path with a control character is escaped in every error,
    /// so the path cannot drive the terminal.
    #[test]
    fn every_error_escapes_the_path() {
        let odd = PathBuf::from("/s/a\u{1b}b.yaml");
        let location = Location::File(odd.clone());
        assert_eq!(location.to_string(), "/s/a\\x1bb.yaml");
        let target = Target {
            location: location.clone(),
            name: Some(tok()),
        };
        assert_eq!(target.to_string(), "'tok' in /s/a\\x1bb.yaml");
        let reason = String::new;
        let errors = [
            BackendError::Exists {
                name: tok(),
                location: location.clone(),
            },
            BackendError::Missing {
                name: tok(),
                location: location.clone(),
            },
            BackendError::Unsafe {
                path: odd.clone(),
                reason: reason(),
            },
            BackendError::CleartextRule {
                path: odd.clone(),
                reason: reason(),
            },
            BackendError::Changed(odd.clone()),
            BackendError::Io {
                step: "open",
                path: odd.clone(),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            },
            BackendError::Parse {
                location,
                format: "sops YAML file",
                what: reason(),
            },
            BackendError::Validation {
                target,
                reason: reason(),
            },
            BackendError::NoStoreFile(odd.clone()),
            BackendError::NoSopsConfig(odd.clone()),
            BackendError::ToolTooOld {
                tool: "sops",
                found: "3.10.0".into(),
                path: odd,
                need: sops::NEED_SOPS,
            },
        ];
        for e in errors {
            let text = e.to_string();
            assert!(!text.contains('\u{1b}'), "{text:?}");
            assert!(text.contains("/s/a\\x1bb.yaml"), "{text}");
        }
    }
}
