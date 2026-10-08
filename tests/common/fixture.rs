//! Backend fixtures for the conformance suite (v0.2 plan 10.1). A fixture
//! makes an empty store in a temp environment and reads it back with the
//! backend's own tool, never with secrit.

use std::path::Path;

use serde_json::Value;

use super::env::{Dirs, TestEnv};

/// What a backend can do, as the conformance cases need to know it. The
/// first two fields follow `Capabilities` (v0.2 plan 5.2); a field joins
/// when a case reads it.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    /// `ls` lists the names when no value can be decrypted.
    pub names_without_decrypt: bool,
    /// `store --replace` and `rm` keep a backup of the old ciphertext.
    pub backups: bool,
    /// Each operation runs a child program (sops, gpg) that gets the value
    /// on stdin. A daemon backend runs none.
    pub child_tool: bool,
}

pub trait Fixture: Sized {
    const CAPS: Caps;

    /// A temp environment with an empty store and a config whose
    /// `[stores.main]` table is [`Self::config_section`].
    fn new() -> Self;

    fn dirs(&self) -> &Dirs;

    /// The body of the `[stores.main]` table.
    fn config_section(&self) -> String;

    /// The value of `name`, read with the backend's own tool; `None` when
    /// the store has no such name. Never printed.
    fn read_back(&self, name: &str) -> Option<Vec<u8>>;

    /// The names in the store, read with the backend's own tool, sorted.
    fn names(&self) -> Vec<String>;

    /// Take away what decrypts the values, and keep what lists the names.
    fn lock_values(&self);

    /// Run the child tool through a wrapper that appends each of its
    /// arguments to `log`, one per line. Only when `CAPS.child_tool`.
    fn log_tool_argv(&self, log: &Path);

    /// Replace the child tool with one that copies its stdin to stderr and
    /// exits 1. Only when `CAPS.child_tool`.
    fn fail_tool_echoing_stdin(&self);
}

/// A sops YAML store, encrypted to two temp age keys.
pub struct SopsFixture {
    env: TestEnv,
}

impl Fixture for SopsFixture {
    const CAPS: Caps = Caps {
        names_without_decrypt: true,
        backups: true,
        child_tool: true,
    };

    fn new() -> Self {
        let env = TestEnv::new();
        let fixture = Self { env };
        fixture.env.write_store_config(
            &fixture.config_section(),
            &format!("sops = \"{}\"", fixture.env.sops.display()),
            120,
        );
        fixture
    }

    fn dirs(&self) -> &Dirs {
        &self.env
    }

    fn config_section(&self) -> String {
        self.env.sops_section()
    }

    fn read_back(&self, name: &str) -> Option<Vec<u8>> {
        match self.env.decrypt().remove(name) {
            Some(Value::String(s)) => Some(s.into_bytes()),
            Some(_) => panic!("{name} is not stored as a string"),
            None => None,
        }
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.env.decrypt().keys().cloned().collect();
        names.sort();
        names
    }

    /// sops reads names from the cleartext keys and needs the age key only
    /// for values.
    fn lock_values(&self) {
        std::fs::remove_file(&self.env.key_file).unwrap();
    }

    fn log_tool_argv(&self, log: &Path) {
        let wrapper = self.env.script(
            "sops-argv",
            &format!(
                "for a in \"$@\"; do printf '%s\\n' \"$a\" >> '{}'; done\nexec '{}' \"$@\"",
                log.display(),
                self.env.sops.display()
            ),
        );
        self.env.write_config_with(&wrapper, "");
    }

    fn fail_tool_echoing_stdin(&self) {
        let fake = self.env.fake_sops(
            "sops-echo",
            "while IFS= read -r l || [ -n \"$l\" ]; do printf 'sops says: %s\\n' \"$l\" >&2; done\nexit 1",
        );
        self.env.write_config_with(&fake, "");
    }
}
