//! Deferred INT, TERM, HUP and QUIT (PLAN section 8.1, step 8).
//!
//! Once [`defer`] runs, these signals only set a flag. Every blocking wait in
//! secrit (the no-echo prompt, the reveal screen, a sops child, the write
//! protocol before its rename) polls the flag and stops cleanly: it restores
//! the terminal, kills the sops process group, and removes the temp copy.
//! The handlers stay for the rest of the (short-lived) process.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};

/// The signals that [`defer`] turns into a flag. SIGQUIT is here because its
/// default action ends the process with no cleanup (SEC-14).
pub const DEFERRED: [i32; 4] = [SIGINT, SIGTERM, SIGHUP, SIGQUIT];

static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Install the flag handlers. Idempotent.
pub fn defer() -> std::io::Result<()> {
    if FLAG.get().is_some() {
        return Ok(());
    }
    let flag = Arc::new(AtomicBool::new(false));
    for sig in DEFERRED {
        signal_hook::flag::register(sig, Arc::clone(&flag))?;
    }
    let _ = FLAG.set(flag);
    Ok(())
}

/// Whether a deferred signal arrived.
#[must_use]
pub fn pending() -> bool {
    FLAG.get().is_some_and(|f| f.load(Ordering::SeqCst))
}
