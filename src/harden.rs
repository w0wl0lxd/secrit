//! Process hardening (PLAN section 8.5). Linux only; every platform call of
//! secrit's own process lives here.

use rustix::fs::Mode;
#[cfg(target_os = "linux")]
use rustix::process::{DumpableBehavior, set_dumpable_behavior};
use rustix::process::{Resource, Rlimit, setrlimit, umask};
use std::sync::OnceLock;

/// The umask before [`harden`] set 077, for the command of `secrit run`.
static UMASK_BEFORE: OnceLock<Mode> = OnceLock::new();

/// What [`harden`] managed to do. `main` prints a warning for each failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardenReport {
    /// `RLIMIT_CORE` is 0.
    pub no_core_dumps: bool,
    /// `PR_SET_DUMPABLE` is 0.
    pub not_dumpable: bool,
}

impl HardenReport {
    /// One message for each step that failed.
    #[must_use]
    pub fn warnings(self) -> Vec<&'static str> {
        let mut w = Vec::new();
        if !self.no_core_dumps {
            w.push("could not set RLIMIT_CORE to 0; a crash could write a core dump");
        }
        if !self.not_dumpable {
            w.push("could not clear PR_SET_DUMPABLE; same-user processes can read secrit's memory");
        }
        w
    }
}

/// Harden the process before any input is read:
/// no core dumps, not dumpable (no same-user ptrace or `/proc/<pid>/mem`),
/// umask 077.
///
/// PLAN 8.5 step 5 (`mlock` and `MADV_DONTDUMP` on value buffers) is not
/// done: rustix exposes both only as `unsafe fn`, and the crate forbids
/// `unsafe`. With no core dumps and values of at most 64 KiB, the open risk
/// is swap (T7); see PLAN section 20.
pub fn harden() -> HardenReport {
    let no_core_dumps = setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .is_ok();
    // macOS has no `PR_SET_DUMPABLE`; the report then carries its warning
    // (v0.2 plan 8.2).
    #[cfg(target_os = "linux")]
    let not_dumpable = set_dumpable_behavior(DumpableBehavior::NotDumpable).is_ok();
    #[cfg(not(target_os = "linux"))]
    let not_dumpable = false;
    let before = umask(Mode::from_raw_mode(0o077));
    let _ = UMASK_BEFORE.set(before);
    HardenReport {
        no_core_dumps,
        not_dumpable,
    }
}

/// Set the umask back to its value before [`harden`]. `secrit run` calls
/// this after it made the memfds and before it starts the command, so the
/// command creates files as the user expects. secrit creates no file after
/// it. The core-dump limit stays 0 in the command: it holds the values too.
pub fn restore_umask() {
    if let Some(&mode) = UMASK_BEFORE.get() {
        umask(mode);
    }
}

/// Replace the default panic hook. The default hook prints the panic payload,
/// which could hold a value; this one prints a fixed message.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!(
            "secrit: internal error (panic). The details are not shown, because they could hold a secret."
        );
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use rustix::process::dumpable_behavior;
    use rustix::process::getrlimit;

    /// T6: the hardening calls take effect. This runs in the test process,
    /// which is fine: the settings only restrict it.
    #[test]
    fn harden_sets_limits() {
        let report = harden();
        assert!(report.no_core_dumps);
        assert_eq!(getrlimit(Resource::Core).current, Some(0));
        #[cfg(target_os = "linux")]
        {
            assert!(report.not_dumpable);
            assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
            assert!(report.warnings().is_empty());
        }
        let failed = HardenReport {
            no_core_dumps: false,
            not_dumpable: false,
        };
        assert_eq!(failed.warnings().len(), 2);
    }
}
