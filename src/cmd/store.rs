//! `secrit store NAME` (PLAN section 4.1).

use super::rm::{NO_BACKUP, confirm};
use super::{Ctx, StoreArgs};
use crate::backend::PutMode;
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
    let no_backup = put_mode == PutMode::Replace
        && !ctx.backend.capabilities().backups
        && ctx.backend.exists(name)?;
    if no_backup {
        confirm_replace(ctx, name, args.yes)?;
    }
    let mode = InputMode {
        multiline: args.multiline || args.raw,
        raw: args.raw,
    };
    let value = read_value(name, mode)?;
    let report = ctx.backend.put(name, &value, put_mode)?;
    drop(value);
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
    }
    // Only a sops store has a sops-nix stanza to print.
    if ctx.store.wire_hint && ctx.store.sops().is_some() {
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
    if confirm(&question, "replace")? {
        Ok(())
    } else {
        Err(Error::Failed("not replaced".into()))
    }
}
