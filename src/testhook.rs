//! Fault injection for the integration tests. The `test-hooks` feature
//! compiles it in; no release or Nix package build enables that feature, and
//! without it every function here does nothing.
//!
//! - `SECRIT_TEST_HOOK=step=action[,step=action]`: see [`hook`].
//! - `SECRIT_TEST_CHILD_TIMEOUT_MS`: a shorter child timeout, see
//!   [`child_timeout`].

use std::time::Duration;

/// Run the actions that `SECRIT_TEST_HOOK` names for `step`. Actions:
/// `abort`, `sigint`, `sigterm`, `sigquit`, `sleep-<ms>`, and `pause`. A
/// pause appends the step to `$SECRIT_TEST_HOOK_DIR/log`, then waits (at
/// most 60 s, or until a signal) for the file `$SECRIT_TEST_HOOK_DIR/go`.
#[cfg(feature = "test-hooks")]
pub fn hook(step: &str) {
    use rustix::process::{Signal, getpid, kill_process};
    let Ok(spec) = std::env::var("SECRIT_TEST_HOOK") else {
        return;
    };
    let actions = spec
        .split(',')
        .filter_map(|item| item.split_once('='))
        .filter(|(at, _)| *at == step)
        .map(|(_, a)| a);
    for action in actions {
        match action {
            "abort" => std::process::abort(),
            "sigint" => drop(kill_process(getpid(), Signal::INT)),
            "sigterm" => drop(kill_process(getpid(), Signal::TERM)),
            "sigquit" => drop(kill_process(getpid(), Signal::QUIT)),
            "pause" => pause(step),
            a => {
                if let Some(ms) = a.strip_prefix("sleep-").and_then(|m| m.parse().ok()) {
                    std::thread::sleep(Duration::from_millis(ms));
                }
            }
        }
    }
}

#[cfg(feature = "test-hooks")]
fn pause(step: &str) {
    use std::io::Write;
    use std::path::PathBuf;
    let Some(dir) = std::env::var_os("SECRIT_TEST_HOOK_DIR").map(PathBuf::from) else {
        return;
    };
    if let Ok(mut log) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("log"))
    {
        let _ = writeln!(log, "{step}");
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while !dir.join("go").exists()
        && !crate::signals::pending()
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(not(feature = "test-hooks"))]
pub fn hook(_: &str) {}

/// The child timeout that `SECRIT_TEST_CHILD_TIMEOUT_MS` sets, if any.
#[cfg(feature = "test-hooks")]
#[must_use]
pub fn child_timeout() -> Option<Duration> {
    std::env::var("SECRIT_TEST_CHILD_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_millis)
}

#[cfg(not(feature = "test-hooks"))]
#[must_use]
pub fn child_timeout() -> Option<Duration> {
    None
}
