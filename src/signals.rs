//! Deferred INT, TERM and HUP during a write (PLAN section 8.1, step 8).
//!
//! Once [`defer`] runs, these signals only set a flag. The write protocol
//! checks the flag before its rename and cancels cleanly. The handlers stay
//! for the rest of the (short-lived) process.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};

static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Install the flag handlers. Idempotent.
pub fn defer() -> std::io::Result<()> {
    if FLAG.get().is_some() {
        return Ok(());
    }
    let flag = Arc::new(AtomicBool::new(false));
    for sig in [SIGINT, SIGTERM, SIGHUP] {
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
