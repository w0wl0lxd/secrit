//! `secrit ls` (PLAN section 4.3). Reads cleartext key names; decrypts nothing.
//!
//! A key that another tool wrote can hold any character. Plain output escapes
//! control and bidi characters, so a name cannot drive the terminal (R5).
//! `--json` output is for programs: JSON escapes the C0 controls (ESC, BEL),
//! and other characters pass as data.

use std::io::Write;

use super::Ctx;
use crate::display::escape;
use crate::error::Error;

pub fn run(ctx: &Ctx, json: bool) -> Result<(), Error> {
    let names = ctx.backend.list()?;
    let mut out = std::io::stdout().lock();
    let written = if json {
        serde_json::to_writer(&mut out, &names)
            .map_err(std::io::Error::other)
            .and_then(|()| writeln!(out))
    } else {
        names
            .iter()
            .try_for_each(|n| writeln!(out, "{}", escape(n)))
    };
    written.map_err(|e| Error::Failed(format!("could not write to stdout: {e}")))
}
