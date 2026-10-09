//! INT, TERM, HUP and QUIT (PLAN section 8.1, step 8).
//!
//! [`defer`] installs two handlers for each signal. Inside a [`Critical`]
//! section (a prompt or the reveal screen, a sops child, the write protocol
//! before its rename) a signal only sets a flag; the wait polls it, restores
//! the terminal, kills the sops group, removes the temp copy and exits 130.
//! Outside every critical section a signal has its default action, so a
//! blocking write to a stalled pipe cannot hold secrit (REG-1).
//!
//! `secrit run` also records each signal by its number ([`record`], v0.2
//! plan 7.1 step 5), so it can forward TERM and HUP to the command it
//! supervises, and ends by the signal that ended that command ([`die_by`]).

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGTSTP};

/// The signals that [`defer`] handles. SIGQUIT is here because its default
/// action ends the process with no cleanup (SEC-14).
pub const DEFERRED: [i32; 4] = [SIGINT, SIGTERM, SIGHUP, SIGQUIT];

/// The signals that [`record`] records. TSTP is here so that secrit does
/// not stop before the command it supervises does.
pub const RECORDED: [i32; 5] = [SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP];

static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
static RECORDS: OnceLock<Vec<Arc<AtomicUsize>>> = OnceLock::new();
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

/// Forget a signal that arrived while it was deferred. `run` calls this
/// when the command it supervised has ended: a Ctrl-C that the command
/// handled does not turn its exit into 130.
pub fn clear_pending() {
    if let Some(f) = FLAG.get() {
        f.store(false, Ordering::SeqCst);
    }
}

/// Record each signal in [`RECORDED`] by its number, with
/// `register_usize` (v0.2 plan V18). From then on TSTP does not stop
/// secrit: `run` stops itself when the command it supervises stops. The
/// other signals keep the handlers of [`defer`]. Idempotent.
pub fn record() -> std::io::Result<()> {
    if RECORDS.get().is_some() {
        return Ok(());
    }
    let mut slots = Vec::with_capacity(RECORDED.len());
    for sig in RECORDED {
        let slot = Arc::new(AtomicUsize::new(0));
        let number = usize::try_from(sig).map_err(std::io::Error::other)?;
        signal_hook::flag::register_usize(sig, Arc::clone(&slot), number)?;
        slots.push(slot);
    }
    let _ = RECORDS.set(slots);
    Ok(())
}

/// The signals that arrived since the last call, in [`RECORDED`] order.
/// Two arrivals of one signal between calls count once.
#[must_use]
pub fn take() -> Vec<i32> {
    RECORDS.get().map_or_else(Vec::new, |slots| {
        slots
            .iter()
            .filter_map(|slot| i32::try_from(slot.swap(0, Ordering::SeqCst)).ok())
            .filter(|&sig| sig != 0)
            .collect()
    })
}

/// End secrit by `sig`, as the command that `run` supervised ended. The
/// pending flag is cleared, the default action is restored and the signal
/// is raised (`emulate_default_handler`). It returns only when `sig` does
/// not end a process; the caller then exits 128 + `sig`. Call it outside
/// every [`Critical`] section, with every value already wiped.
pub fn die_by(sig: i32) {
    clear_pending();
    let _ = signal_hook::low_level::emulate_default_handler(sig);
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

    /// V18: a recorded signal is read back by its number, once.
    #[test]
    fn a_recorded_signal_is_taken_once() {
        record().unwrap();
        let _ = take();
        signal_hook::low_level::raise(SIGTSTP).unwrap();
        assert_eq!(take(), vec![SIGTSTP]);
        assert!(take().is_empty());
    }
}
