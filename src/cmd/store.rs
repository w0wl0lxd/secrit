//! `secrit store NAME` (PLAN section 4.1).

use super::{Ctx, StoreArgs};
use crate::backend::{BackendError, PutMode};
use crate::cli::ARGV_VALUE_MESSAGE;
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
    // Check before the prompt, so nobody types a value that will be refused.
    // The write protocol checks again under the lock.
    if !args.replace && ctx.backend.exists(name)? {
        return Err(BackendError::Exists(name.clone()).into());
    }
    let mode = InputMode {
        multiline: args.multiline || args.raw,
        raw: args.raw,
    };
    let value = read_value(name, mode)?;
    let put_mode = if args.replace {
        PutMode::Replace
    } else {
        PutMode::CreateOnly
    };
    let report = ctx.backend.put(name, &value, put_mode)?;
    drop(value);
    if let Some(b) = &report.backup {
        ctx.status(&format!("backup of the old file: {}", b.display()));
    }
    ctx.status(&format!(
        "stored {name} in {} ({})",
        ctx.store.name,
        ctx.store.file.display()
    ));
    if ctx.store.wire_hint {
        ctx.status(&format!(
            "run 'secrit wire {name}' to expose it at /run/secrets/{name}"
        ));
    }
    Ok(())
}
