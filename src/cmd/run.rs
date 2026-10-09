//! `secrit run [--file VAR=NAME]... [--env VAR=NAME]... [--pristine]
//! [--no-mask] -- CMD [ARGS...]` (v0.2 plan 7.1; slice S13).
//!
//! | Condition                              | Result                       |
//! |----------------------------------------|------------------------------|
//! | agent detected, `--env`                | refuse (Q27)                 |
//! | agent detected, `--no-mask`            | refuse (Q5)                  |
//! | `--no-mask`                            | replace secrit with CMD      |
//! | agent detected                         | mask                         |
//! | stdout or stderr not a terminal        | mask                         |
//! | otherwise                              | replace secrit with CMD      |
//!
//! The checks that need no value run before the config is read and before
//! any decrypt. Then every value is read with one `get_many`, before CMD
//! starts. With masking, secrit stays the parent ([`child::supervise`]) and
//! exits as CMD exits; otherwise it calls `exec`, and the memfds stay open
//! in the new image.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, ExitStatus};

use super::Ctx;
use crate::agent::{self, Agent};
use crate::child;
use crate::display::escape;
use crate::error::Error;
use crate::mask::Masker;
use crate::name::Name;
use crate::secret::SecretValue;

/// How a binding hands its value to CMD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// A sealed memfd; `VAR=/dev/fd/N`.
    File,
    /// The value itself in `VAR`.
    Env,
}

/// One `--file VAR=NAME` or `--env VAR=NAME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub var: String,
    pub name: Name,
    pub via: Via,
}

/// What `run` does once it has the values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Replace secrit with CMD (`exec`).
    Exec,
    /// Stay the parent and mask CMD's stdout and stderr.
    Mask,
}

/// Why `run` refuses before any decrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `--env` under agent detection (Q27).
    Env(Agent),
    /// `--no-mask` under agent detection (Q5).
    NoMask(Agent),
}

/// How `run` ended, for the exit status of secrit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// Exit with this code.
    Code(u8),
    /// End by this signal, as CMD did (T45).
    Signal(i32),
}

impl Ended {
    /// The end of CMD as secrit's own.
    #[must_use]
    pub fn of(status: ExitStatus) -> Self {
        match (status.code(), status.signal()) {
            (Some(code), _) => Ended::Code(u8::try_from(code).unwrap_or(1)),
            (None, Some(sig)) => Ended::Signal(sig),
            (None, None) => Ended::Code(1),
        }
    }
}

/// The checked command line of `run`.
#[derive(Debug)]
pub struct Plan {
    pub bindings: Vec<Binding>,
    pub mode: Mode,
    pub pristine: bool,
    pub program: PathBuf,
    pub args: Vec<OsString>,
}

/// The `run` arguments, after clap.
#[derive(Debug)]
pub struct RunArgs {
    pub file: Vec<String>,
    pub env: Vec<String>,
    pub pristine: bool,
    pub no_mask: bool,
    pub command: Vec<OsString>,
}

/// The decision for `run`, from the inputs only. Kept pure for tests.
/// `terminals`: stdout and stderr are both terminals.
pub fn decide(
    agent: Option<Agent>,
    no_mask: bool,
    has_env: bool,
    terminals: bool,
) -> Result<Mode, Refusal> {
    match agent {
        Some(a) if has_env => Err(Refusal::Env(a)),
        Some(a) if no_mask => Err(Refusal::NoMask(a)),
        None if no_mask || terminals => Ok(Mode::Exec),
        _ => Ok(Mode::Mask),
    }
}

/// Whether `var` is a shell variable name: `^[A-Za-z_][A-Za-z0-9_]*$`.
#[must_use]
pub fn is_var(var: &str) -> bool {
    let mut chars = var.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse the `--file` and `--env` arguments. A VAR is set once.
pub fn parse_bindings(file: &[String], env: &[String]) -> Result<Vec<Binding>, Error> {
    let mut bindings = Vec::new();
    let mut seen = HashSet::new();
    let all = file
        .iter()
        .map(|a| (a, Via::File))
        .chain(env.iter().map(|a| (a, Via::Env)));
    for (arg, via) in all {
        let flag = match via {
            Via::File => "--file",
            Via::Env => "--env",
        };
        let Some((var, name)) = arg.split_once('=') else {
            return Err(Error::Usage(format!("{flag} takes VAR=NAME")));
        };
        if !is_var(var) {
            return Err(Error::Usage(format!(
                "{flag}: VAR must match ^[A-Za-z_][A-Za-z0-9_]*$"
            )));
        }
        if !seen.insert(var.to_owned()) {
            return Err(Error::Usage(format!("{} is set twice", escape(var))));
        }
        bindings.push(Binding {
            var: var.to_owned(),
            name: Name::parse(name)?,
            via,
        });
    }
    if bindings.is_empty() {
        return Err(Error::Usage(
            "run needs at least one --file VAR=NAME or --env VAR=NAME".into(),
        ));
    }
    Ok(bindings)
}

/// The checks that need no config and no value: the command line, the
/// agent rules and the program. They run before any decrypt.
pub fn check(args: RunArgs) -> Result<Plan, Error> {
    use std::io::IsTerminal;
    let bindings = parse_bindings(&args.file, &args.env)?;
    let has_env = bindings.iter().any(|b| b.via == Via::Env);
    let mode = decide(
        agent::detect(),
        args.no_mask,
        has_env,
        std::io::stdout().is_terminal() && std::io::stderr().is_terminal(),
    )
    .map_err(refusal)?;
    #[cfg(not(target_os = "linux"))]
    if bindings.iter().any(|b| b.via == Via::File) {
        return Err(Error::Failed("run --file needs memfd (Linux)".into()));
    }
    let mut command = args.command.into_iter();
    let program = command
        .next()
        .ok_or_else(|| Error::Usage("run needs a command after '--'".into()))?;
    Ok(Plan {
        bindings,
        mode,
        pristine: args.pristine,
        program: resolve(&program)?,
        args: command.collect(),
    })
}

fn refusal(r: Refusal) -> Error {
    // No `match` on `Agent`: a new way to detect an agent needs no change
    // here, and its `Display` text gives the reason.
    let why = |a: Agent| {
        if a == Agent::NoTty {
            "there is no terminal (/dev/tty cannot be opened)".to_owned()
        } else {
            format!("an agent was detected ({a})")
        }
    };
    Error::Refused(match r {
        Refusal::Env(a) => format!(
            "{}, so 'run --env' is off: any process of your user can read a command's environment (/proc/PID/environ, ps eww). Use --file VAR=NAME",
            why(a)
        ),
        Refusal::NoMask(a) => format!(
            "{}, so 'run --no-mask' is off: the output of the command is always masked",
            why(a)
        ),
    })
}

/// CMD as a path: as given when it holds a `/`, else the first match on
/// secrit's `PATH`. `--pristine` does not change the search.
fn resolve(program: &OsStr) -> Result<PathBuf, Error> {
    if program.as_bytes().contains(&b'/') {
        return Ok(PathBuf::from(program));
    }
    which::which(program).map_err(|_| {
        Error::Failed(format!(
            "{} was not found on PATH",
            escape(&program.to_string_lossy())
        ))
    })
}

/// Read the values, hand them to CMD and run it.
pub fn run(ctx: &Ctx, plan: &Plan) -> Result<Ended, Error> {
    let mut names: Vec<Name> = Vec::new();
    for b in &plan.bindings {
        if !names.contains(&b.name) {
            names.push(b.name.clone());
        }
    }
    let values = ctx.backend.get_many(&names)?;
    let value_of = |name: &Name| -> Result<&SecretValue, Error> {
        values
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
            .ok_or_else(|| Error::Failed(format!("'{name}' was not returned by the backend")))
    };
    for b in plan.bindings.iter().filter(|b| b.via == Via::Env) {
        if value_of(&b.name)?.expose().contains(&0) {
            return Err(Error::Refused(format!(
                "'{}' holds a NUL byte, which an environment variable cannot hold; use --file {}={}",
                b.name, b.var, b.name
            )));
        }
    }
    let shown = escape(&plan.program.to_string_lossy()).into_owned();
    let mut cmd = Command::new(&plan.program);
    cmd.args(&plan.args);
    if plan.pristine {
        cmd.env_clear();
    }
    #[cfg(target_os = "linux")]
    let mut handoff = Vec::new();
    for b in &plan.bindings {
        let value = value_of(&b.name)?.expose();
        match b.via {
            #[cfg(target_os = "linux")]
            Via::File => {
                let sealed = crate::handoff::Sealed::new(value).map_err(|e| {
                    Error::Failed(format!("could not make the memfd for {}: {e}", b.var))
                })?;
                cmd.env(&b.var, sealed.path());
                handoff.push(sealed);
            }
            #[cfg(not(target_os = "linux"))]
            Via::File => {
                return Err(Error::Failed("run --file needs memfd (Linux)".into()));
            }
            Via::Env => {
                cmd.env(&b.var, OsStr::from_bytes(value));
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let handoff = ();
    crate::harden::restore_umask();
    match plan.mode {
        Mode::Exec => {
            drop(values);
            // Returns only on failure; the memfds stay open in the new image.
            let e = cmd.exec();
            // On other systems `handoff` is `()`, and a drop of it is a lint error.
            #[cfg(target_os = "linux")]
            drop(handoff);
            Err(Error::Failed(format!("could not run {shown}: {e}")))
        }
        Mode::Mask => {
            let maskers = [Masker::new(&values), Masker::new(&values)];
            drop(values);
            if !ctx.quiet {
                for warning in maskers[0].warnings() {
                    eprintln!("secrit: warning: {warning}");
                }
            }
            let status = child::supervise(cmd, maskers, handoff)
                .map_err(|e| Error::Failed(format!("could not run {shown}: {e}")))?;
            Ok(Ended::of(status))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_matrix() {
        let agent = Agent::Variable("CLAUDECODE");
        for a in [agent, Agent::NoTty] {
            for (no_mask, terminals) in [(false, true), (true, false)] {
                assert_eq!(
                    decide(Some(a), no_mask, true, terminals),
                    Err(Refusal::Env(a))
                );
            }
            assert_eq!(decide(Some(a), true, false, true), Err(Refusal::NoMask(a)));
            assert_eq!(decide(Some(a), false, false, true), Ok(Mode::Mask));
        }
        assert_eq!(decide(None, true, true, false), Ok(Mode::Exec));
        assert_eq!(decide(None, false, true, true), Ok(Mode::Exec));
        assert_eq!(decide(None, false, false, false), Ok(Mode::Mask));
    }

    #[test]
    fn var_names() {
        for good in ["V", "_", "_x1", "DATABASE_URL", "a9"] {
            assert!(is_var(good), "{good}");
        }
        for bad in ["", "1V", "V-X", "V X", "V=", "é"] {
            assert!(!is_var(bad), "{bad}");
        }
    }

    #[test]
    fn bindings_parse_and_refuse() {
        let b = parse_bindings(&["A=x".into()], &["B=y".into()]).unwrap();
        assert_eq!(b.len(), 2);
        assert_eq!((b[0].var.as_str(), b[0].via), ("A", Via::File));
        assert_eq!((b[1].var.as_str(), b[1].via), ("B", Via::Env));
        assert_eq!(b[1].name.as_str(), "y");
        let usage = |file: &[&str], env: &[&str]| {
            let f: Vec<String> = file.iter().map(|s| (*s).to_owned()).collect();
            let e: Vec<String> = env.iter().map(|s| (*s).to_owned()).collect();
            matches!(parse_bindings(&f, &e), Err(Error::Usage(_)))
        };
        assert!(usage(&[], &[]));
        assert!(usage(&["A"], &[]));
        assert!(usage(&["1A=x"], &[]));
        assert!(usage(&["A=x"], &["A=y"]));
        assert!(matches!(
            parse_bindings(&["A=bad/name".into()], &[]),
            Err(Error::Name(_))
        ));
    }

    #[test]
    fn a_signal_death_is_kept() {
        assert_eq!(Ended::of(ExitStatus::from_raw(7 << 8)), Ended::Code(7));
        assert_eq!(Ended::of(ExitStatus::from_raw(15)), Ended::Signal(15));
    }

    /// Q27: the refusal names `--file`.
    #[test]
    fn the_env_refusal_points_to_file() {
        let e = refusal(Refusal::Env(Agent::Variable("CLAUDECODE")));
        assert!(e.to_string().contains("--file"), "{e}");
        assert!(e.to_string().contains("CLAUDECODE is set"), "{e}");
        assert!(matches!(e, Error::Refused(_)));
    }

    /// With no terminal the refusal says so. Every other reason is an
    /// agent, named by its `Display` text.
    #[test]
    fn the_refusal_names_the_reason() {
        for r in [Refusal::Env(Agent::NoTty), Refusal::NoMask(Agent::NoTty)] {
            let text = refusal(r).to_string();
            assert!(text.contains("there is no terminal"), "{text}");
            assert!(!text.contains("an agent was detected"), "{text}");
        }
        let agent = Agent::Variable("CODEX_THREAD_ID");
        let text = refusal(Refusal::NoMask(agent)).to_string();
        assert!(
            text.contains(&format!("an agent was detected ({agent})")),
            "{text}"
        );
        assert!(text.contains("--no-mask"), "{text}");
    }
}
