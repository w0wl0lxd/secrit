//! `secrit rm NAME` (PLAN section 4.4, PLAN-v0.2 section 4).

use super::{Ctx, Gated};
use crate::display::escape_path;
use crate::error::Error;
use crate::name::Name;
use crate::tty;

pub fn run(ctx: &Ctx, name: &Name, yes: bool) -> Result<(), Error> {
    ctx.backend.check_remove(name)?;
    // Under an agent the typed name replaces the y/N question, and `--yes`
    // does not skip it (PLAN-v0.2 4.2, step 6).
    let gated = super::write_gate(
        |agent| {
            let skip = if yes {
                "--yes does not skip this question when an agent runs secrit.\n"
            } else {
                ""
            };
            format!(
                "{skip}an agent runs secrit ({agent}). To remove '{name}' from {}, type the name: ",
                ctx.backend.location()
            )
        },
        name.as_str(),
    )?;
    if gated == Gated::Open && !yes {
        let question = format!("remove {name} from {}? [y/N] ", ctx.backend.location());
        if !tty::confirm_yes(&question)? {
            return Err(Error::Failed("not removed".into()));
        }
    }
    let report = ctx.backend.remove(name)?;
    if let Some(b) = &report.backup {
        ctx.status(&format!("backup of the old file: {}", escape_path(b)));
    }
    ctx.status(&format!(
        "removed {name}. git history, backups and any rendered /run/secrets copy still hold the old value; rotate it at its source if it leaked."
    ));
    Ok(())
}
