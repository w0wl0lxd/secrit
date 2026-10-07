//! `secrit rm NAME` (PLAN section 4.4).

use std::io::{BufRead, BufReader, Write};

use super::{Ctx, parse_name};
use crate::backend::BackendError;
use crate::error::Error;

pub fn run(ctx: &Ctx, name: &str, yes: bool) -> Result<(), Error> {
    let name = parse_name(name)?;
    if !ctx.backend.exists(&name)? {
        return Err(BackendError::Missing(name).into());
    }
    if !yes
        && !confirm(&format!(
            "remove {name} from {}? [y/N] ",
            ctx.store.file.display()
        ))?
    {
        return Err(Error::Failed("not removed".into()));
    }
    let report = ctx.backend.remove(&name)?;
    if let Some(b) = &report.backup {
        ctx.status(&format!("backup of the old file: {}", b.display()));
    }
    ctx.status(&format!(
        "removed {name}. git history, backups and any rendered /run/secrets copy still hold the old value; rotate it at its source if it leaked."
    ));
    Ok(())
}

/// Ask on `/dev/tty`. With no terminal, refuse: `--yes` is the only way.
fn confirm(question: &str) -> Result<bool, Error> {
    let Ok(tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    else {
        return Err(Error::Refused(
            "no terminal to confirm on; pass --yes to remove without asking".into(),
        ));
    };
    let io = |e: std::io::Error| Error::Failed(format!("could not ask on the terminal: {e}"));
    let mut writer = &tty;
    writer.write_all(question.as_bytes()).map_err(io)?;
    writer.flush().map_err(io)?;
    let mut answer = String::new();
    BufReader::new(&tty).read_line(&mut answer).map_err(io)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
