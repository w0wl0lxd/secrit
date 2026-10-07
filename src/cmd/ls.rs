//! `secrit ls` (PLAN section 4.3). Reads cleartext key names; decrypts nothing.

use std::io::Write;

use super::Ctx;
use crate::error::Error;

pub fn run(ctx: &Ctx, json: bool) -> Result<(), Error> {
    let names = ctx.backend.list()?;
    let mut out = std::io::stdout().lock();
    let written = if json {
        serde_json::to_writer(&mut out, &names)
            .map_err(std::io::Error::other)
            .and_then(|()| writeln!(out))
    } else {
        names.iter().try_for_each(|n| writeln!(out, "{n}"))
    };
    written.map_err(|e| Error::Failed(format!("could not write to stdout: {e}")))
}
