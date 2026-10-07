//! `secrit get NAME` (PLAN section 4.2).
//!
//! | Condition                         | Result                         |
//! |-----------------------------------|--------------------------------|
//! | agent detected                    | refuse (no override)           |
//! | no flag, stdout a TTY             | reveal on the alternate screen |
//! | no flag, stdout not a TTY         | refuse                         |
//! | `--stdout`, stdout not a TTY      | exact bytes, no newline        |
//! | `--stdout`, stdout a TTY          | refuse                         |
//!
//! `--stdout` also refuses a regular file that group or others can read, and
//! a block device (SEC-3).

use std::fs::File;
use std::io::{IsTerminal, Write};

use rustix::fs::{FileType, fstat};

use super::Ctx;
use crate::agent::{self, Agent};
use crate::display;
use crate::error::Error;
use crate::name::Name;
use crate::secret::SecretValue;
use crate::tty::{self, ModeGuard, ReadError};

const ALT_SCREEN_ON: &[u8] = b"\x1b[?1049h\x1b[2J\x1b[H";
const ALT_SCREEN_OFF: &[u8] = b"\x1b[2J\x1b[?1049l";

/// The decision for `get`, from the inputs only. Kept pure for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetAction {
    Reveal,
    Stdout,
    RefuseAgent(Agent),
    RefuseNotTty,
    RefuseStdoutTty,
}

#[must_use]
pub fn decide(agent: Option<Agent>, stdout_flag: bool, stdout_is_tty: bool) -> GetAction {
    match (agent, stdout_flag, stdout_is_tty) {
        (Some(a), _, _) => GetAction::RefuseAgent(a),
        (None, false, true) => GetAction::Reveal,
        (None, false, false) => GetAction::RefuseNotTty,
        (None, true, false) => GetAction::Stdout,
        (None, true, true) => GetAction::RefuseStdoutTty,
    }
}

/// What `--stdout` writes to, from `fstat` of fd 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdoutKind {
    /// A pipe, a socket or a character device such as `/dev/null`.
    Stream,
    /// A regular file of this user that group and others cannot read.
    PrivateFile,
    /// A regular file that another user owns, or that group or others can read.
    SharedFile,
    /// A block device, or anything else.
    Other,
}

#[must_use]
pub fn classify_stdout(file_type: FileType, mode: u32, owner_is_me: bool) -> StdoutKind {
    match file_type {
        FileType::Fifo | FileType::Socket | FileType::CharacterDevice => StdoutKind::Stream,
        FileType::RegularFile if owner_is_me && mode & 0o077 == 0 => StdoutKind::PrivateFile,
        FileType::RegularFile => StdoutKind::SharedFile,
        _ => StdoutKind::Other,
    }
}

pub fn run(ctx: &Ctx, name: &Name, stdout_flag: bool) -> Result<(), Error> {
    let action = decide(
        agent::detect(),
        stdout_flag,
        std::io::stdout().is_terminal(),
    );
    match action {
        GetAction::RefuseAgent(Agent::NoTty) => {
            return Err(Error::Refused(
                "there is no terminal (/dev/tty cannot be opened), so 'get' is off; run it in your own terminal".into(),
            ));
        }
        GetAction::RefuseAgent(a) => {
            return Err(Error::Refused(format!(
                "an agent was detected ({a}); 'get' is off so the value cannot reach a transcript. Run it in your own terminal"
            )));
        }
        GetAction::RefuseNotTty => {
            return Err(Error::Refused(
                "stdout is not a terminal; use --stdout to write the value to a pipe".into(),
            ));
        }
        GetAction::RefuseStdoutTty => {
            return Err(Error::Refused(format!(
                "--stdout would leave the value in scrollback; run 'secrit get {name}' without --stdout"
            )));
        }
        GetAction::Reveal => {}
        GetAction::Stdout => check_stdout_target()?,
    }
    let mut values = ctx.backend.get_many(std::slice::from_ref(name))?;
    let (_, value) = values
        .pop()
        .ok_or_else(|| Error::Failed(format!("'{name}' was not returned by the backend")))?;
    if action == GetAction::Stdout {
        let mut out = std::io::stdout().lock();
        out.write_all(value.expose())
            .and_then(|()| out.flush())
            .map_err(|e| Error::Failed(format!("could not write to stdout: {e}")))
    } else {
        reveal(name, &value)
    }
}

/// Refuse a `--stdout` target that would keep a readable plaintext copy.
fn check_stdout_target() -> Result<(), Error> {
    let st = fstat(std::io::stdout())
        .map_err(|e| Error::Failed(format!("could not stat stdout: {e}")))?;
    let mine = st.st_uid == rustix::process::getuid().as_raw();
    match classify_stdout(FileType::from_raw_mode(st.st_mode), st.st_mode, mine) {
        StdoutKind::Stream | StdoutKind::PrivateFile => Ok(()),
        StdoutKind::SharedFile => Err(Error::Refused(
            "stdout is a file that another user owns, or that group or others can read; write to a pipe, or to a file with mode 0600 (for example after 'umask 077')".into(),
        )),
        StdoutKind::Other => Err(Error::Refused(
            "stdout is not a pipe, a socket, a character device or a regular file".into(),
        )),
    }
}

/// Show the value on the alternate screen, wait for one key, then clear it.
/// Nothing reaches the scrollback. A deferred signal (INT, TERM, HUP, QUIT)
/// also clears the screen and restores the terminal, then exits 130.
fn reveal(name: &Name, value: &SecretValue) -> Result<(), Error> {
    let io = |e: std::io::Error| Error::Failed(format!("terminal error: {e}"));
    let (shown_value, escaped) = display::render_secret(value.expose());
    let tty = tty::open().map_err(io)?;
    let mut w = &tty;
    w.write_all(ALT_SCREEN_ON).map_err(io)?;
    let shown = write_screen(&tty, name, &shown_value, escaped)
        .map_err(ReadError::Io)
        .and_then(|()| {
            let _raw = ModeGuard::raw(&tty)?;
            tty::wait_key(&tty)
        });
    drop(shown_value);
    let cleared = w.write_all(ALT_SCREEN_OFF).and_then(|()| w.flush());
    match shown {
        Ok(()) => cleared.map_err(io),
        Err(ReadError::Interrupted) => Err(Error::Interrupted),
        Err(ReadError::Io(e)) => Err(io(e)),
        Err(ReadError::BufferFull | ReadError::LineTooLong) => {
            Err(Error::Failed("terminal read failed".into()))
        }
    }
}

fn write_screen(mut tty: &File, name: &Name, shown: &[u8], escaped: bool) -> std::io::Result<()> {
    write!(tty, "{}:\r\n\r\n", display::escape(name.as_str()))?;
    tty.write_all(shown)?;
    if escaped {
        tty.write_all(
            b"\r\n\r\n(control characters in the value are shown as \\xNN in reverse video)",
        )?;
    }
    tty.write_all(b"\r\n\r\n(press any key to clear the screen)")?;
    tty.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_matrix() {
        let agent = Agent::Variable("CLAUDECODE");
        for (flag, tty) in [(false, false), (false, true), (true, false), (true, true)] {
            assert_eq!(
                decide(Some(agent), flag, tty),
                GetAction::RefuseAgent(agent)
            );
        }
        assert_eq!(
            decide(Some(Agent::NoTty), true, false),
            GetAction::RefuseAgent(Agent::NoTty)
        );
        assert_eq!(decide(None, false, true), GetAction::Reveal);
        assert_eq!(decide(None, false, false), GetAction::RefuseNotTty);
        assert_eq!(decide(None, true, false), GetAction::Stdout);
        assert_eq!(decide(None, true, true), GetAction::RefuseStdoutTty);
    }

    /// SEC-3: pipes pass; a regular file must be private.
    #[test]
    fn stdout_targets() {
        use FileType as T;
        assert_eq!(classify_stdout(T::Fifo, 0o600, true), StdoutKind::Stream);
        assert_eq!(classify_stdout(T::Socket, 0o777, false), StdoutKind::Stream);
        assert_eq!(
            classify_stdout(T::CharacterDevice, 0o666, false),
            StdoutKind::Stream
        );
        assert_eq!(
            classify_stdout(T::RegularFile, 0o600, true),
            StdoutKind::PrivateFile
        );
        assert_eq!(
            classify_stdout(T::RegularFile, 0o644, true),
            StdoutKind::SharedFile
        );
        assert_eq!(
            classify_stdout(T::RegularFile, 0o600, false),
            StdoutKind::SharedFile
        );
        assert_eq!(
            classify_stdout(T::BlockDevice, 0o600, true),
            StdoutKind::Other
        );
    }
}
