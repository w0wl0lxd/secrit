//! INT, TERM, HUP and QUIT (PLAN section 8.1, step 8).
//!
//! [`defer`] installs two handlers for each signal. Inside a [`Critical`]
//! section (a prompt or the reveal screen, a sops child, the write protocol
//! before its rename) a signal only sets a flag; the wait polls it, restores
//! the terminal, kills the sops group, removes the temp copy and exits 130.
//! Outside every critical section a signal has its default action, so a
//! blocking write to a stalled pipe cannot hold secrit (REG-1).

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};

/// The signals that [`defer`] handles. SIGQUIT is here because its default
/// action ends the process with no cleanup (SEC-14).
pub const DEFERRED: [i32; 4] = [SIGINT, SIGTERM, SIGHUP, SIGQUIT];

static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
static DEFAULT_ACTION: OnceLock<Arc<AtomicBool>> = OnceLock::new();
static DEPTH: AtomicUsize = AtomicUsize::new(0);

fn default_action() -> &'static Arc<AtomicBool> {
    DEFAULT_ACTION.get_or_init(|| Arc::new(AtomicBool::new(DEPTH.load(Ordering::SeqCst) == 0)))
}

/// Install the handlers. Idempotent.
pub fn defer() -> std::io::Result<()> {
    if FLAG.get().is_some() {
        return Ok(());
    }
    let flag = Arc::new(AtomicBool::new(false));
    for sig in DEFERRED {
        signal_hook::flag::register(sig, Arc::clone(&flag))?;
        signal_hook::flag::register_conditional_default(sig, Arc::clone(default_action()))?;
    }
    let _ = FLAG.set(flag);
    Ok(())
}

/// Whether a signal arrived while it was deferred.
#[must_use]
pub fn pending() -> bool {
    FLAG.get().is_some_and(|f| f.load(Ordering::SeqCst))
}

/// While a `Critical` lives, the signals in [`DEFERRED`] only set the flag.
/// Sections nest. Only the main thread opens them.
#[derive(Debug)]
#[must_use = "the section ends when the guard drops"]
pub struct Critical(());

impl Critical {
    pub fn enter() -> Self {
        DEPTH.fetch_add(1, Ordering::SeqCst);
        default_action().store(false, Ordering::SeqCst);
        Critical(())
    }
}

impl Drop for Critical {
    fn drop(&mut self) {
        if DEPTH.fetch_sub(1, Ordering::SeqCst) == 1 {
            default_action().store(true, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_action_on() -> bool {
        default_action().load(Ordering::SeqCst)
    }

    #[test]
    fn sections_nest() {
        assert!(default_action_on());
        let outer = Critical::enter();
        assert!(!default_action_on());
        let inner = Critical::enter();
        drop(inner);
        assert!(!default_action_on(), "the outer section is still open");
        drop(outer);
        assert!(default_action_on());
    }
}
