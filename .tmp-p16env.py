import subprocess, os

os.chdir("/home/w0w/dev/.land-0c813e16/leftovers/secrit-16")
p = "tests/common/env.rs"
s = open(p).read()
pr = subprocess.check_output(["git", "show", "fix/pr16:tests/common/mod.rs"]).decode()
m1 = "    /// Run `inner` under `script` with the environment of"
a = pr.index(m1)
b = pr.index(
    "    /// Run `inner` through `/bin/sh` under util-linux `script`, which gives"
)
block = pr[a:b].replace(
    "self.script_cmd(base, inner)", "self.script_cmd_for(base, inner)"
)

old = """            .env("PATH", &self.path)
            .current_dir(self.root.path())
            .stdin(Stdio::null());
        c
    }
"""
new = """            .env("PATH", &self.path)
            // The write gate (PLAN-v0.2 4.3): most tests run `store` and `rm`
            // with no terminal, which the gate refuses. The `test-hooks`
            // build opens the gate for them; the gate tests use `gate_cmd`.
            .env("SECRIT_TEST_GATE", "allow")
            // The ancestor walk stops at this test process, so an agent
            // variable in the environment of the test runner does not count.
            .env("SECRIT_TEST_ANCESTOR_STOP", std::process::id().to_string())
            .current_dir(self.root.path())
            .stdin(Stdio::null());
        c
    }

    /// [`Self::cmd`] with the write gate in force.
    pub fn gate_cmd(&self) -> Command {
        let mut c = self.cmd();
        c.env_remove("SECRIT_TEST_GATE");
        c
    }
"""
assert old in s
s = s.replace(old, new, 1)

hs = s.index("    /// [`Self::under_script`], with `script`'s stdin held open until it")
he = s.index(
    '        let mut child = s.spawn().expect("spawn script");\n        let held'
)
s = (
    s[:hs]
    + """    /// [`Self::under_script`], with `script`'s stdin held open until it
    /// exits, so no end-of-input reaches the terminal.
    pub fn under_script_held(&self, inner: &str) -> Output {
        self.under_script_held_with(&self.cmd(), inner)
    }

    /// [`Self::under_script_held`] with the environment of `base`.
    pub fn under_script_held_with(&self, base: &Command, inner: &str) -> Output {
        let mut s = self.script_cmd_for(base, inner);
        s.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
"""
    + s[he:]
)

i = s.index(
    "    /// util-linux `script` with the secrit environment and `/bin/sh` as its"
)
j = s.index("        s\n    }\n}\n", i) + len("        s\n    }\n")
tail = """
    /// util-linux `script` with the secrit environment and `/bin/sh` as its
    /// shell, in the temp root.
    fn script_cmd(&self) -> Command {
        self.script_base(&self.cmd())
    }

    /// `script` running `inner` through `/bin/sh`, with the environment of
    /// `base`.
    pub fn script_cmd_for(&self, base: &Command, inner: &str) -> Command {
        let mut s = self.script_base(base);
        s.args(["-q", "-e", "-c", inner, "/dev/null"]);
        s
    }

    fn script_base(&self, base: &Command) -> Command {
        let script = which::which("script")
            .expect("util-linux 'script' is needed for the pty tests; run in 'nix develop'");
        let mut s = Command::new(script);
        s.env_clear();
        for (k, v) in base.get_envs() {
            if let Some(v) = v {
                s.env(k, v);
            }
        }
        s.env("SHELL", "/bin/sh").current_dir(self.root.path());
        s
    }

"""
s = s[:i].rstrip("\n") + "\n" + tail + block.rstrip("\n") + "\n" + s[j:]
open(p, "w").write(s)
