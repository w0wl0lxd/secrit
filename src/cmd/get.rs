//! `secrit get NAME` (PLAN section 4.2).
//!
//! | Condition                         | Result                         |
//! |-----------------------------------|--------------------------------|
//! | agent detected                    | refuse (no override)           |
//! | no flag, stdout a TTY             | reveal on the alternate screen |
//! | no flag, stdout not a TTY         | refuse                         |
//! | `--stdout`, stdout not a TTY      | exact bytes, no newline        |
//! | `--stdout`, stdout a TTY          | refuse                         |

use std::fs::File;
use std::io::{IsTerminal, Read, Write};

use rustix::termios::{OptionalActions, tcgetattr, tcsetattr};

use super::{Ctx, parse_name};
use crate::agent::{self, Agent};
use crate::error::Error;
use crate::name::Name;
use crate::secret::SecretValue;

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

pub fn run(ctx: &Ctx, name: &str, stdout_flag: bool) -> Result<(), Error> {
    let name = parse_name(name)?;
    let action = decide(
        agent::detect(),
        stdout_flag,
        std::io::stdout().is_terminal(),
    );
    match action {
        GetAction::RefuseAgent(a) => {
            return Err(Error::Refused(format!(
                "an agent was detected ({a}); 'get' is off so the value cannot reach a transcript. Run it in your own terminal"
            )));
        }
        GetAction::RefuseNotTty => {
            return Err(Error::Refused(
                "stdout is not a terminal; use --stdout, or better 'secrit run'".into(),
            ));
        }
        GetAction::RefuseStdoutTty => {
            return Err(Error::Refused(format!(
                "--stdout would leave the value in scrollback; run 'secrit get {name}' without --stdout"
            )));
        }
        GetAction::Reveal | GetAction::Stdout => {}
    }
    let mut values = ctx.backend.get_many(std::slice::from_ref(&name))?;
    let (_, value) = values
        .pop()
        .ok_or_else(|| Error::Failed(format!("'{name}' was not returned by the backend")))?;
    if action == GetAction::Stdout {
        let mut out = std::io::stdout().lock();
        out.write_all(value.expose())
            .and_then(|()| out.flush())
            .map_err(|e| Error::Failed(format!("could not write to stdout: {e}")))
    } else {
        reveal(&name, &value)
    }
}

/// Show the value on the alternate screen, wait for one key, then clear it.
/// Nothing reaches the scrollback.
fn reveal(name: &Name, value: &SecretValue) -> Result<(), Error> {
    let io = |e: std::io::Error| Error::Failed(format!("terminal error: {e}"));
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(io)?;
    tty.write_all(ALT_SCREEN_ON).map_err(io)?;
    let shown = write_screen(&mut tty, name, value).and_then(|()| wait_for_key(&tty));
    let cleared = tty.write_all(ALT_SCREEN_OFF).and_then(|()| tty.flush());
    shown.map_err(io)?;
    cleared.map_err(io)
}

fn write_screen(tty: &mut File, name: &Name, value: &SecretValue) -> std::io::Result<()> {
    write!(tty, "{name}:\r\n\r\n")?;
    tty.write_all(value.expose())?;
    write!(tty, "\r\n\r\n(press any key to clear the screen)")?;
    tty.flush()
}

/// Read one byte in raw mode, so Ctrl-C is a key press and cannot leave the
/// value on the alternate screen.
fn wait_for_key(tty: &File) -> std::io::Result<()> {
    let orig = tcgetattr(tty)?;
    let mut raw = orig.clone();
    raw.make_raw();
    tcsetattr(tty, OptionalActions::Now, &raw)?;
    let mut byte = [0u8; 1];
    let read = (&*tty).read(&mut byte);
    tcsetattr(tty, OptionalActions::Now, &orig)?;
    read.map(|_| ())
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
}
