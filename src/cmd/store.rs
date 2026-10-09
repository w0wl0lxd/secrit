//! `secrit store NAME` (PLAN section 4.1).

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
    if ctx.store.wire_hint {
        ctx.status(&format!(
            "run 'secrit wire {name}' to expose it at /run/secrets/{name}"
        ));
    }
    Ok(())
}
