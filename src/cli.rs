//! The command line (PLAN section 4). Parse errors are sanitised: clap echoes
//! the offending argument, and that argument may be a secret (T2).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

use crate::error::Exit;

/// The fixed message for a value on the command line. It never repeats the
/// argument text.
pub const ARGV_VALUE_MESSAGE: &str = "a value on the command line is already in shell history and /proc; rotate it, then pipe or type the value";

#[allow(clippy::doc_markdown, reason = "doc comments are clap help text")]
#[derive(Debug, Parser)]
#[command(
    name = "secrit",
    version,
    long_version = long_version(),
    about = "Store secrets in a sops + age file, with no value on the command line",
    propagate_version = true
)]
pub struct Cli {
    /// Config file [default: $SECRIT_CONFIG, then $XDG_CONFIG_HOME/secrit/config.toml, then ~/.config/secrit/config.toml]
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// A store from the config [default: default_store]
    #[arg(long, global = true, value_name = "NAME")]
    pub store: Option<String>,

    /// Print errors only
    #[arg(short, long, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[allow(clippy::doc_markdown, reason = "doc comments are clap help text")]
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Store a secret read from a no-echo prompt or from stdin
    Store {
        /// The secret name: A-Z, a-z, 0-9, '.', '_' and '-', at most 128 bytes
        name: String,
        /// Overwrite an existing secret (a sops store keeps a ciphertext backup; a Secret Service store keeps none and asks first)
        #[arg(long)]
        replace: bool,
        /// With --replace on a store that keeps no backup: do not ask for confirmation
        #[arg(long, requires = "replace")]
        yes: bool,
        /// Allow newlines; a terminal reads until a line that holds only '.'
        #[arg(long)]
        multiline: bool,
        /// Keep piped bytes exactly, including a trailing newline (implies --multiline)
        #[arg(long)]
        raw: bool,
        /// Caught only to refuse it: values never go on the command line.
        #[arg(hide = true, num_args = 0.., trailing_var_arg = true)]
        extra: Vec<OsString>,
    },
    /// Show a secret on the alternate screen, or write it to a pipe with --stdout
    Get {
        /// The secret name
        name: String,
        /// Write the exact value to stdout; refused when stdout is a terminal, or a file that group or others can read
        #[arg(long)]
        stdout: bool,
    },
    /// List secret names without decrypting anything
    Ls {
        /// Print a JSON array
        #[arg(long)]
        json: bool,
    },
    /// Remove a secret (a sops store keeps a ciphertext backup; a Secret Service store keeps none)
    Rm {
        /// The secret name
        name: String,
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Set up a machine: age key, sops file, config (never overwrites)
    Init {
        /// The backend of the store [default: the configured store's, else sops]
        #[arg(long, value_enum, value_name = "BACKEND")]
        backend: Option<InitBackend>,
        /// The sops file to create [default: the store file from the config]
        #[arg(long, value_name = "PATH")]
        sops_file: Option<PathBuf>,
        /// The .sops.yaml to use [default: the nearest one upward from the sops file]
        #[arg(long, value_name = "PATH")]
        sops_config: Option<PathBuf>,
        /// The age key file [default: the config, else $XDG_CONFIG_HOME/sops/age/keys.txt]
        #[arg(long, value_name = "PATH")]
        age_key: Option<PathBuf>,
        /// Create a .sops.yaml when none exists (never edits one)
        #[arg(long)]
        write_sops_config: bool,
        /// Print the plan and change nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Check the setup; read-only, decrypts nothing
    Doctor {
        /// Print the result as JSON
        #[arg(long)]
        json: bool,
    },
    /// Print the sops-nix stanza for a secret; changes nothing
    Wire {
        /// The secret name
        name: String,
        /// The owner of /run/secrets/NAME [default: the current user]
        #[arg(long, value_name = "USER")]
        owner: Option<String>,
        /// The output form
        #[arg(long, value_enum, default_value_t = WireFormat::Nix)]
        format: WireFormat,
    },
    /// Print shell completions
    #[command(hide = true)]
    Completions {
        /// The shell
        shell: CompletionShell,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WireFormat {
    /// A sops-nix `sops.secrets` stanza
    Nix,
    /// A shell assignment: `NAME_FILE=/run/secrets/NAME`
    Env,
}

#[allow(clippy::doc_markdown, reason = "doc comments are clap help text")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InitBackend {
    /// A sops + age file
    Sops,
    /// A Secret Service collection on the session bus (gnome-keyring, KWallet, KeePassXC)
    SecretService,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Fish,
    Zsh,
}

/// `--version` text, built once (clap needs a `'static` string).
fn long_version() -> &'static str {
    static TEXT: OnceLock<String> = OnceLock::new();
    TEXT.get_or_init(crate::tools::long_version).as_str()
}

impl From<CompletionShell> for clap_complete::Shell {
    fn from(s: CompletionShell) -> Self {
        match s {
            CompletionShell::Bash => clap_complete::Shell::Bash,
            CompletionShell::Fish => clap_complete::Shell::Fish,
            CompletionShell::Zsh => clap_complete::Shell::Zsh,
        }
    }
}

/// What `parse` returns when it does not return a [`Cli`].
#[derive(Debug)]
pub enum ParseOutcome {
    /// Help or version was printed; exit 0.
    Printed,
    /// A usage error was reported without its argument text.
    Usage,
}

/// Parse `args`. Help and version print as usual. Any other error prints its
/// kind and the usage line only (T2).
pub fn parse<I, T>(args: I) -> Result<Cli, ParseOutcome>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match Cli::try_parse_from(args) {
        Ok(cli) => Ok(cli),
        Err(e) => match e.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                let _ = e.print();
                Err(ParseOutcome::Printed)
            }
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
                let _ = e.print();
                Err(ParseOutcome::Usage)
            }
            kind => {
                eprintln!("{}", sanitized_message(kind));
                Err(ParseOutcome::Usage)
            }
        },
    }
}

/// The message for a parse error. It holds no argument text.
#[must_use]
pub fn sanitized_message(kind: ErrorKind) -> String {
    let usage = Cli::command().render_usage().to_string();
    format!(
        "secrit: invalid command line ({kind:?}). The argument text is not shown, because it may hold a secret.\n{usage}\nRun 'secrit --help' or 'secrit <COMMAND> --help'."
    )
}

impl ParseOutcome {
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            ParseOutcome::Printed => 0,
            ParseOutcome::Usage => Exit::Usage.code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn store_catches_extra_positionals() {
        let cli = Cli::try_parse_from(["secrit", "store", "N", "hunter2"]).unwrap();
        match cli.command {
            Command::Store { extra, .. } => assert_eq!(extra.len(), 1),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn sanitized_message_has_no_argument_text() {
        let err = Cli::try_parse_from(["secrit", "store", "N", "--value=hunter2"]).unwrap_err();
        // clap itself would echo the argument:
        let msg = sanitized_message(err.kind());
        assert!(!msg.contains("hunter2"));
        assert!(!msg.contains("--value"));
    }

    #[test]
    fn global_flags_work_after_the_subcommand() {
        let cli = Cli::try_parse_from(["secrit", "ls", "--store", "x", "-q"]).unwrap();
        assert_eq!(cli.store.as_deref(), Some("x"));
        assert!(cli.quiet);
    }
}
