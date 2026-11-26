//! `secrit store NAME` (PLAN section 4.1).

use super::rm::NO_BACKUP;
use super::{Ctx, Gated, StoreArgs};
use crate::backend::{BackendError, PutMode, WireSource};
use crate::cli::ARGV_VALUE_MESSAGE;
use crate::display::escape_path;
use crate::error::Error;
use crate::name::Name;
use crate::secret::{InputMode, read_value};

/// Refuse a value on argv before anything else; the message never repeats it.
pub fn check_argv(args: &StoreArgs) -> Result<(), Error> {
    if args.extra.is_empty() {
        Ok(())
    } else {
        Err(Error::Usage(ARGV_VALUE_MESSAGE.into()))
    }
}

pub fn run(ctx: &Ctx, name: &Name, args: &StoreArgs) -> Result<(), Error> {
    let put_mode = if args.replace {
        PutMode::Replace
    } else {
        PutMode::CreateOnly
    };
    // Check before the prompt (the name is free, and the file's rules would
    // encrypt it), so nobody types a value that will be refused. The write
    // protocol checks again under the lock.
    ctx.backend.check_put(name, put_mode)?;
    // On a backend with no backup, a replace of a name that exists needs a
    // confirmation (T55, Q37). The check runs before the gate, so the gate
    // question can say that the old value is lost.
    let no_backup_replace = put_mode == PutMode::Replace
        && !ctx.backend.capabilities().backups
        && ctx.backend.exists(name)?;
    // The write gate comes after the checks and before the value (PLAN-v0.2
    // 4.2, step 1), so nobody types a value that the gate then refuses.
    // Under an agent the typed name replaces the y/N question of T55, and
    // `--yes` does not skip it (4.2, step 6).
    let gated = super::write_gate(
        |agent| {
            let skip = if args.yes {
                "--yes does not skip this question when an agent runs secrit.\n"
            } else {
                ""
            };
            let note = if no_backup_replace {
                format!(" {NO_BACKUP}.")
            } else {
                String::new()
            };
            format!(
                "{skip}an agent runs secrit ({agent}).{note} To store '{name}' in {}, type the name: ",
                ctx.backend.location()
            )
        },
        name.as_str(),
    )?;
    let mut write_mode = put_mode;
    let mut no_backup = false;
    if put_mode == PutMode::Replace && !ctx.backend.capabilities().backups {
        if no_backup_replace {
            if gated == Gated::Open {
                confirm_replace(ctx, name, args.yes)?;
            }
            no_backup = true;
        } else if !args.yes || gated == Gated::Confirmed {
            // Nothing confirmed the loss of a value, so the write must not
            // replace an item that another process makes before it (T55, Q37).
            // Under an agent the typed name confirmed a new item only, and
            // `--yes` does not count (4.2, step 6). The backend checks again
            // under its lock.
            write_mode = PutMode::CreateOnly;
        }
    }
    let mode = InputMode {
        multiline: args.multiline || args.raw,
        raw: args.raw,
    };
    let value = read_value(name, mode)?;
    let written = ctx.backend.put(name, &value, write_mode);
    drop(value);
    let report = match written {
        Err(BackendError::Exists { .. }) if write_mode != put_mode => {
            // Under an agent `--yes` does not confirm, so only a new run that
            // shows the no-backup note in the gate question can.
            let yes = if gated == Gated::Confirmed {
                ""
            } else {
                ", or pass --yes"
            };
            return Err(Error::Refused(format!(
                "'{name}' appeared while secrit waited; nothing was replaced. {} keeps no backup, so run the command again to confirm the replace{yes}",
                ctx.backend.location()
            )));
        }
        r => r?,
    };
    if let Some(b) = &report.backup {
        ctx.status(&format!("backup of the old file: {}", escape_path(b)));
    }
    ctx.status(&format!(
        "stored {name} in {} ({})",
        ctx.store.name,
        ctx.backend.location()
    ));
    if no_backup {
        ctx.status(NO_BACKUP);
    } else if write_mode == PutMode::Replace && !ctx.backend.capabilities().backups {
        // The name was free at the check, and another process may have made
        // it before the write: say that a replaced value has no backup, and
        // do not claim that there was one.
        ctx.status("secrit keeps no backup of a value that a replace overwrites");
    }
    ctx.commit_hint(name, "Store");
    // The hint is for a name that `wire` can expose.
    let wired = matches!(
        ctx.backend.wire_source(name),
        Some(WireSource::SopsFile { .. })
    );
    if ctx.store.wire_hint && wired {
        ctx.status(&format!(
            "run 'secrit wire {name}' to expose it at /run/secrets/{name}"
        ));
    }
    Ok(())
}

/// The backend keeps no backup, so `--replace` asks first: `y` on
/// `/dev/tty`, or `--yes`, even for the owner (v0.2 plan 5.2, Q37, T55).
/// It asks before the value is read, so nobody types a value for nothing.
fn confirm_replace(ctx: &Ctx, name: &Name, yes: bool) -> Result<(), Error> {
    if yes {
        return Ok(());
    }
    let question = format!(
        "replace {name} in {}? {NO_BACKUP}. [y/N] ",
        ctx.backend.location()
    );
    if crate::tty::confirm_yes(&question)? {
        Ok(())
    } else {
        Err(Error::Failed("not replaced".into()))
    }
}
