//! `secrit store NAME` (PLAN section 4.1).

use super::rm::{NO_BACKUP, confirm};
use super::{Ctx, StoreArgs};
use crate::backend::{BackendError, PutMode};
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
    let mut write_mode = put_mode;
    let mut no_backup = false;
    if put_mode == PutMode::Replace && !ctx.backend.capabilities().backups {
        if ctx.backend.exists(name)? {
            confirm_replace(ctx, name, args.yes)?;
            no_backup = true;
        } else if !args.yes {
            // Nothing was confirmed, so the write must not replace an item
            // that another process makes before it (T55, Q37). The backend
            // checks again under its lock.
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
            return Err(Error::Refused(format!(
                "'{name}' appeared while secrit waited; nothing was replaced. {} keeps no backup, so run the command again to confirm the replace, or pass --yes",
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
