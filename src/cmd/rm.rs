//! `secrit rm NAME` (PLAN section 4.4, PLAN-v0.2 section 4).

use super::{Ctx, Gated};
use crate::display::escape_path;
use crate::error::Error;
use crate::name::Name;
use crate::tty;

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
    // Under an agent the typed name replaces the y/N question, and `--yes`
    // does not skip it (PLAN-v0.2 4.2, step 6). The typed name also
    // confirms the loss of the value on a backend with no backup (T55).
    let gated = super::write_gate(
        |agent| {
            let skip = if yes {
                "--yes does not skip this question when an agent runs secrit.\n"
            } else {
                ""
            };
            format!(
                "{skip}an agent runs secrit ({agent}).{note} To remove '{name}' from {}, type the name: ",
                ctx.backend.location()
            )
        },
        name.as_str(),
    )?;
    if gated == Gated::Open && !yes {
        let question = format!(
            "remove {name} from {}?{note} [y/N] ",
            ctx.backend.location()
        );
        if !tty::confirm_yes(&question)? {
            return Err(Error::Failed("not removed".into()));
        }
    }
    let report = ctx.backend.remove(name)?;
    // After the delete: a refused delete leaves the item in place.
    if !backups {
        ctx.status(NO_BACKUP);
    }
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
    ctx.commit_hint(name, "Remove");
    Ok(())
}
