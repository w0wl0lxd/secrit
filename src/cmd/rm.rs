//! `secrit rm NAME` (PLAN section 4.4).

use super::Ctx;
use crate::display::escape_path;
use crate::error::Error;
use crate::name::Name;
use crate::tty::{self, LineEnd, ReadError};

/// What `store --replace` and `rm` print when the backend keeps no backup
/// (v0.2 plan 5.2, T55).
pub const NO_BACKUP: &str = "no backup; the old value is gone";

pub fn run(ctx: &Ctx, name: &Name, yes: bool) -> Result<(), Error> {
    ctx.backend.check_remove(name)?;
    let backups = ctx.backend.capabilities().backups;
    let note = if backups {
        String::new()
    } else {
        format!(" {NO_BACKUP}.")
    };
    if yes {
        if !backups {
            ctx.status(NO_BACKUP);
        }
    } else {
        let question = format!(
            "remove {name} from {}?{note} [y/N] ",
            ctx.backend.location()
        );
        if !confirm(&question, "remove")? {
            return Err(Error::Failed("not removed".into()));
        }
    }
    let report = ctx.backend.remove(name)?;
    if let Some(b) = &report.backup {
        ctx.status(&format!("backup of the old file: {}", escape_path(b)));
    }
    if backups {
        ctx.status(&format!(
            "removed {name}. git history, backups and any rendered /run/secrets copy still hold the old value; rotate it at its source if it leaked."
        ));
    } else {
        ctx.status(&format!(
            "removed {name}. secrit kept no backup, but the daemon may keep the old value in its own files; rotate it at its source if it leaked."
        ));
    }
    Ok(())
}

/// Ask on `/dev/tty`. With no terminal, refuse: `--yes` is the only way.
/// `verb` names the action in that refusal. The read polls the signal flag,
/// so INT or TERM exits 130 (R13).
pub fn confirm(question: &str, verb: &str) -> Result<bool, Error> {
    let Ok(tty) = tty::open() else {
        return Err(Error::Refused(format!(
            "no terminal to confirm on; pass --yes to {verb} without asking"
        )));
    };
    let io = |e: std::io::Error| Error::Failed(format!("could not ask on the terminal: {e}"));
    tty::say(&tty, question).map_err(io)?;
    let mut buf = [0u8; 64];
    let mut len = 0;
    match tty::read_line(&tty, &mut buf, &mut len) {
        Ok(LineEnd::Newline | LineEnd::Eof) => Ok(is_yes(&buf[..len])),
        // A long answer is not "y" or "yes".
        Err(ReadError::BufferFull | ReadError::LineTooLong) => Ok(false),
        Err(ReadError::Interrupted) => Err(Error::Interrupted),
        Err(ReadError::Io(e)) => Err(io(e)),
    }
}

fn is_yes(answer: &[u8]) -> bool {
    let a = answer.trim_ascii();
    a.eq_ignore_ascii_case(b"y") || a.eq_ignore_ascii_case(b"yes")
}

#[cfg(test)]
mod tests {
    use super::is_yes;

    #[test]
    fn only_y_and_yes_confirm() {
        for a in [&b"y"[..], b"Y", b"yes", b" YES ", b"yes\r"] {
            assert!(is_yes(a), "{a:?}");
        }
        for a in [&b""[..], b"n", b"no", b"yess", b"y y"] {
            assert!(!is_yes(a), "{a:?}");
        }
    }
}
