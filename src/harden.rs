//! Process hardening (PLAN section 8.5). Linux only; every platform call of
//! secrit's own process lives here.

use rustix::fs::Mode;
use rustix::process::{
    DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit, umask,
};

/// What [`harden`] managed to do. `doctor` reports the failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardenReport {
    /// `RLIMIT_CORE` is 0.
    pub no_core_dumps: bool,
    /// `PR_SET_DUMPABLE` is 0.
    pub not_dumpable: bool,
}

/// Harden the process before any input is read:
/// no core dumps, not dumpable (no same-user ptrace or `/proc/<pid>/mem`),
/// umask 077.
pub fn harden() -> HardenReport {
    let no_core_dumps = setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .is_ok();
    let not_dumpable = set_dumpable_behavior(DumpableBehavior::NotDumpable).is_ok();
    umask(Mode::from_raw_mode(0o077));
    HardenReport {
        no_core_dumps,
        not_dumpable,
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
    use rustix::process::{dumpable_behavior, getrlimit};

    /// T6: the hardening calls take effect. This runs in the test process,
    /// which is fine: the settings only restrict it.
    #[test]
    fn harden_sets_limits() {
        let report = harden();
        assert!(report.no_core_dumps);
        assert!(report.not_dumpable);
        assert_eq!(getrlimit(Resource::Core).current, Some(0));
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
    }
}
