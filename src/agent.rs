//! Agent detection (PLAN section 8.3).
//!
//! An agent is detected when a known agent variable is set and not empty, or
//! when `/dev/tty` cannot be opened. There is no override variable: an agent
//! can set any variable. This prevents accidents; it is not a security
//! boundary (PLAN N1).

use std::ffi::OsString;
use std::fmt;

/// Variables that coding agents set in the shells they run.
pub const AGENT_VARS: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "AI_AGENT",
    "AGENT",
    "CODEX_SANDBOX",
    "CODEX_THREAD_ID",
    "CURSOR_AGENT",
    "GEMINI_CLI",
    "CLINE_ACTIVE",
    "OPENCODE_CLIENT",
];

/// Why secrit thinks an agent runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Variable(&'static str),
    NoTty,
}

impl fmt::Display for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Agent::Variable(v) => write!(f, "{v} is set"),
            Agent::NoTty => f.write_str("/dev/tty cannot be opened"),
        }
    }
}

/// Detect an agent from an environment lookup and the `/dev/tty` result.
pub fn detect_with(env: &dyn Fn(&str) -> Option<OsString>, tty_opens: bool) -> Option<Agent> {
    for var in AGENT_VARS {
        if env(var).is_some_and(|v| !v.is_empty()) {
            return Some(Agent::Variable(var));
        }
    }
    if tty_opens { None } else { Some(Agent::NoTty) }
}

/// Detect an agent in the current process.
#[must_use]
pub fn detect() -> Option<Agent> {
    detect_with(&|k| std::env::var_os(k), tty_opens())
}

/// Whether this process has a controlling terminal it can open.
#[must_use]
pub fn tty_opens() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn no_agent_with_tty_and_clean_env() {
        assert_eq!(detect_with(&env_of(&[]), true), None);
    }

    #[test]
    fn every_listed_variable_is_detected() {
        for var in AGENT_VARS {
            let env = env_of(&[(var, "1")]);
            assert_eq!(detect_with(&env, true), Some(Agent::Variable(var)));
        }
    }

    #[test]
    fn empty_variable_is_ignored() {
        assert_eq!(detect_with(&env_of(&[("CLAUDECODE", "")]), true), None);
    }

    #[test]
    fn no_tty_is_detected() {
        assert_eq!(detect_with(&env_of(&[]), false), Some(Agent::NoTty));
    }

    #[test]
    fn variable_wins_over_tty() {
        let env = env_of(&[("CODEX_SANDBOX", "seatbelt")]);
        assert_eq!(
            detect_with(&env, false),
            Some(Agent::Variable("CODEX_SANDBOX"))
        );
    }

    /// PLAN 8.3: the README lists every variable, so it cannot drift.
    #[test]
    fn the_readme_lists_every_variable() {
        let readme = include_str!("../README.md");
        for v in AGENT_VARS {
            assert!(readme.contains(&format!("`{v}`")), "README misses {v}");
        }
    }
}
