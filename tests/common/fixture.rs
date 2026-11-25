//! Backend fixtures for the conformance suite (v0.2 plan 10.1). A fixture
//! makes an empty store in a temp environment and reads it back with the
//! backend's own tool, never with secrit.

use std::marker::PhantomData;
use std::path::Path;

use serde_json::Value;

use super::env::{Dirs, TestEnv, sh_quote};

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

/// The text before each stdin line that the tool of
/// [`Fixture::fail_tool_echoing_stdin`] writes to stderr.
pub const ECHO_PREFIX: &str = "tool echo: ";

pub trait Fixture: Sized {
    const CAPS: Caps;

    /// The note in a secrit error that says it left out child stderr lines
    /// because they may hold the value.
    const REDACTION_NOTE: &'static str;

    /// Two names that the store can hold, in sorted order, for the round
    /// trip case. A store with a narrower name grammar gives its own.
    const NAMES: [&'static str; 2] = ["a-key_1", "b.key"];

    /// What comes before the short name of a case (`n`, `m`, `nope`) to
    /// make a name that the store can hold. An INI store takes
    /// `section/key` names only, so it gives a section here.
    const NAME_PREFIX: &'static str = "";

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

    /// Replace the child tool with one that copies each line of its stdin
    /// to stderr after [`ECHO_PREFIX`] and exits 1. Only when
    /// `CAPS.child_tool`.
    fn fail_tool_echoing_stdin(&self);
}

/// The sops format of a [`SopsFixtureStore`] fixture.
pub trait FixtureFormat {
    /// The sops `--input-type` of the store file.
    const NAME: &'static str;

    /// [`Fixture::NAMES`] for a store in this format.
    const NAMES: [&'static str; 2] = ["a-key_1", "b.key"];

    /// [`Fixture::NAME_PREFIX`] for a store in this format.
    const NAME_PREFIX: &'static str = "";
}

/// A sops YAML store (`main.yaml`).
pub struct Yaml;

impl FixtureFormat for Yaml {
    const NAME: &'static str = "yaml";
}

/// A sops JSON store (`main.json`).
pub struct Json;

impl FixtureFormat for Json {
    const NAME: &'static str = "json";
}

/// A sops dotenv store (`main.env`). Its names are variable names (v0.2
/// plan 5.4).
pub struct Dotenv;

impl FixtureFormat for Dotenv {
    const NAME: &'static str = "dotenv";
    const NAMES: [&'static str; 2] = ["A_KEY_1", "b_key"];
}

/// A sops INI store (`main.ini`). Its names are `section/key`, each a
/// variable name (v0.2 plan 5.4).
pub struct Ini;

impl FixtureFormat for Ini {
    const NAME: &'static str = "ini";
    const NAMES: [&'static str; 2] = ["s/A_KEY_1", "s/b_key"];
    const NAME_PREFIX: &'static str = "s/";
}

/// A sops store in the format `F`, encrypted to two temp age keys.
pub struct SopsFixtureStore<F: FixtureFormat> {
    env: TestEnv,
    format: PhantomData<F>,
}

/// A sops YAML store, the v0.1 store.
pub type SopsFixture = SopsFixtureStore<Yaml>;
/// A sops JSON store (v0.2 plan S4).
pub type SopsJsonFixture = SopsFixtureStore<Json>;
/// A sops dotenv store (v0.2 plan S6).
pub type SopsDotenvFixture = SopsFixtureStore<Dotenv>;
/// A sops INI store (v0.2 plan S6b).
pub type SopsIniFixture = SopsFixtureStore<Ini>;

impl<F: FixtureFormat> SopsFixtureStore<F> {
    /// The [`TestEnv`] of the store, for the checks that only sops has.
    pub fn env(&self) -> &TestEnv {
        &self.env
    }
}

impl<F: FixtureFormat> Fixture for SopsFixtureStore<F> {
    const CAPS: Caps = Caps {
        names_without_decrypt: true,
        backups: true,
        child_tool: true,
    };
    const REDACTION_NOTE: &'static str = "line(s) not shown, because they may hold the value";
    const NAMES: [&'static str; 2] = F::NAMES;
    const NAME_PREFIX: &'static str = F::NAME_PREFIX;

    fn new() -> Self {
        Self {
            env: TestEnv::with_format(F::NAME),
            format: PhantomData,
        }
    }

    fn dirs(&self) -> &Dirs {
        &self.env
    }

    fn config_section(&self) -> String {
        self.env.sops_section()
    }

    fn read_back(&self, name: &str) -> Option<Vec<u8>> {
        // A name of the suite has a `/` only as a key path. `b.key` of a
        // YAML store has none.
        match self.env.decrypt_at(name) {
            Some(Value::String(s)) => Some(s.into_bytes()),
            Some(_) => panic!("{name} is not stored as a string"),
            None => None,
        }
    }

    fn names(&self) -> Vec<String> {
        self.env.decrypt_names()
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
                "for a in \"$@\"; do printf '%s\\n' \"$a\" >> {}; done\nexec {} \"$@\"",
                sh_quote(log),
                sh_quote(&self.env.sops)
            ),
        );
        self.env.write_config_with(&wrapper, "");
    }

    fn fail_tool_echoing_stdin(&self) {
        let fake = self.env.fake_sops(
            "sops-echo",
            &format!(
                "while IFS= read -r l || [ -n \"$l\" ]; do printf '{ECHO_PREFIX}%s\\n' \"$l\" >&2; done\nexit 1"
            ),
        );
        self.env.write_config_with(&fake, "");
    }
}
