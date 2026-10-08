# secrit: plan for v0.2

Status: revision 3, 2026-10-08: owner answers in section 14. Draft for review. Author: design agent of the v0.2 expansion workflow.
Owner: w0wl0lxd. Branch
`feat/expand`, stacked on PR #2 (`feat/mvp-gaps`, HEAD `a8ec45c` on 2026-10-08; the branch
is rewritten from time to time, so check `gh pr view 2` before a rebase).
Revision 2, 2026-10-08: applies the critique of section 16.

This plan extends [`PLAN.md`](PLAN.md) (v0.1). It does not repeat v0.1 rules. Where this
plan and v0.1 disagree, this plan wins for v0.2 code. Section numbers such as "PLAN 8.1"
point to v0.1; section numbers with no prefix point to this file.

## 1. Summary

v0.1 is a sops + age tool for one NixOS machine. v0.2 removes that specificity in four
directions, and applies one owner ruling:

| Dir. | Goal | Main result this round |
|---|---|---|
| A | More backends | A real `Backend` trait with capabilities. Secret Service, a password-store (pass layout, tested against gopass stores) backend and macOS Keychain ship. KeePassXC and others wait. |
| B | Wider sops support | JSON, dotenv, INI and binary store formats, nested keys, SSH-derived age keys, `SOPS_AGE_KEY_CMD` and age plugins (touch or cached PIN only). |
| C | Beyond NixOS | A trust check for a `sops` found on `PATH`, new install text, release builds, wire targets for systemd-creds, Docker Compose, Kubernetes, home-manager and dotenv (print only), and a macOS port (compile-checked; run-tested only if Q34 gives a Mac or a runner). |
| D | v0.2 commands | `run` (sealed memfd, output masking), `generate`, and binary values through the binary store format. |
| Q13 | Owner ruling (b) | Under agent detection, `store`, `rm`, `generate` and the write steps of `init` need the name typed on `/dev/tty`. With no `/dev/tty` they are refused. The gate stops accidents, not an agent that works around it (4.4). |

The security posture of v0.1 stays: no value on argv, `unsafe_code = "forbid"`, zeroized
buffers, bounded child processes with a cleared environment, crash-safe lock-protected
writes, and agent refusal of `get`.

The work is 20 slices plus one hotfix (S0): S1 splits into S1a and S1b, S6b (INI) is new,
and S7 (canary probe) is deferred. Each slice is one stacked pull request that compiles
and passes every gate on its own (section 12).

## 2. Scope of this round

"Ship" means a slice in section 12 delivers it. "Defer" gives the reason.

### 2.1 Direction A: backends

| Item | Decision | Slice | Reason |
|---|---|---|---|
| `Backend` trait with capabilities, config enum, backend factory | Ship | S1a, S3 | Every other item needs it. |
| Secret Service (`secret-service` 5.2.0, blocking, DH) | Ship | S10 | Planned in v0.1 (PLAN 6.3, M6). Licences pass. It also reaches KWallet and the KeePassXC FdoSecrets server. |
| pass (password-store layout) | Ship, secrit-native | S11 | secrit writes the pass layout itself through `gpg`, with temp file and rename. It never runs `pass` and never commits (N7). See 6.4 and Q25. |
| gopass (store compatibility) | Ship as "gopass-compatible, no auto-sync" through the pass backend | S11 | S11 tests the pass backend against a gopass store with the `gpgcli` crypto backend and `fs` storage. secrit never runs `gopass`, so it never pushes. Native gopass (age crypto, `gitfs` sync) waits on Q35. |
| macOS Keychain (`security-framework` 3.7.0) | Ship | S18 | It is the macOS-native store. Its item ACL trusts the secrit binary, so it stops other programs, not an agent that runs secrit (6.5). It needs the macOS port (S17) and waits on Q34 for a runtime test. |
| KeePassXC through `keepassxc-cli` | Defer to v0.3 (M7) | — | Q3 (stopping `keepassxc.service`) is open. Secret Service through FdoSecrets reaches a running KeePassXC first. |
| Linux kernel keyring | Defer | — | Values do not survive a reboot. It is a cache for `run`, not a store. |
| 1Password, Bitwarden | Defer | — | Both need a network account and hand the whole item JSON, value included, to secrit's parser. |
| `--also BACKEND` mirroring (Q2) | Defer | — | A partial multi-store write needs its own design. |

### 2.2 Direction B: sops

| Item | Decision | Slice | Reason |
|---|---|---|---|
| Fix: v0.1 rewrites a JSON store as YAML | Ship as hotfix S0, then S4 | S0, S4 | Confirmed bug (3.9). sops-nix with `format = "json"` then cannot read the file. |
| JSON store format | Ship | S4 | Same tree model as YAML. |
| Nested keys in YAML and JSON (`a/b/c`) | Ship | S5 | The sops-nix `key` option uses `/` paths. |
| dotenv store format (flat) | Ship | S6 | Serves non-Nix consumers with `sops exec-env`. |
| Canary probe for `encrypted_regex` and `unencrypted_regex` files | Defer (S7 deferred) | — | While the every-leaf-encrypted rule stays (Q23), the probe helps only a regex file whose every leaf already matches the rule. It costs one more sops run, and one more plugin touch, per `store`. Revisit with Q23. |
| SSH-derived age key file (`SOPS_AGE_SSH_PRIVATE_KEY_FILE`, Q18) | Ship, unencrypted keys only | S8 | Explicit config key, so T19 holds. A passphrase key needs a terminal prompt (Q24). |
| `SOPS_AGE_KEY_CMD` | Ship | S8 | Absolute, trust-checked path from config. |
| age plugins (`age-plugin-*`) | Ship, touch-only or cached PIN | S8 | sops needs `PATH` to find the plugin. A PIN prompt from a background process group is stopped (Q24). |
| Binary store format (one sops binary file per name) | Ship | S9 | Carrier for `--binary` (Q22). sops-nix reads it with `format = "binary"`. |
| INI store format | Ship | S6b | Names of exactly two segments (`section/key`, from S5) and a `[sops]` metadata section. The line parser of S6 is the base. Q36 lets the owner drop it. |
| Other recipient types (pgp, KMS, Vault, plugins) in existing files | Ship for writes and reads by an age identity | S3, S4 | `sops set` reuses the data key, so validation compares opaque metadata and stays recipient-agnostic (3.8). |
| pgp, KMS and Vault identities | Defer | — | They need `GNUPGHOME`, cloud credentials or `VAULT_*` in the sops environment, which conflicts with T19 and PLAN 8.2. |
| `init` with non-age recipients | Defer | — | `init` prints "age recipients only; create other files with sops". |

### 2.3 Direction C: beyond NixOS

| Item | Decision | Slice | Reason |
|---|---|---|---|
| Trust check for a `sops` found on `PATH`; tool source in `doctor` | Ship | S16 | Without Nix, the `PATH` fallback is the normal path, and v0.1 does not trust-check it (3.13). |
| Install text without Nix; non-Nix `NotFound` hint | Ship | S16 | The v0.1 hint names `nix profile add` only. |
| Release builds (cargo-dist 0.33, `x86_64` and `aarch64` musl, macOS) | Ship the build in CI; publish nothing | S16 | The repository is private, and Q17 (machine-specific text) blocks a public release (Q29). |
| crates.io, Homebrew tap, AUR | Defer | — | Q17 and Q29. |
| Wire targets `hm`, `systemd`, `systemd-creds`, `compose`, `k8s` | Ship | S15 | Each prints text and runs nothing (N7). |
| Wire target `dotenv` | Ship, print only | S15 | It writes no file and prints no value. For a dotenv store it prints `sops exec-env FILE 'CMD'`; for any other store it prints a `secrit run --env VAR=NAME -- CMD` line (5.7). |
| macOS port (N8) | Ship, compile-checked; run-tested only after Q34 | S17 | Lock directory, hardening, `F_FULLFSYNC`, terminal limits. A Linux-side `clippy --target aarch64-apple-darwin` gate from S1a catches cfg errors. A macOS job needs a Mac or paid runner minutes (Q28, Q34). |
| `run --file` on macOS | Defer | — | No memfd. A pipe fallback can be read only once and needs its own tests. `run --env` works on macOS. |
| Windows | Defer | — | Not asked. |

### 2.4 Direction D: commands

| Item | Decision | Slice | Reason |
|---|---|---|---|
| Masking library (`mask.rs`) | Ship | S12 | Pure code with unit tests. `run` needs it from its first commit. |
| `run --file`, `--env`, `--pristine`, `--no-mask` (Linux) | Ship | S13 | PLAN 4.5, M6. |
| `{}` placeholder in the `run` command line | Defer | — | `-- sh -c '... "$F"'` covers it. A placeholder grammar is a new parser. |
| `generate` with character sets | Ship | S14 | It prints no value. It writes the store, so the write gate applies to it like `store` (4.1). |
| `generate --words` (EFF list) | Defer | — | 60 KB of data and a word-list licence check. |
| `--binary` for `store` and `get` | Ship, binary stores only | S9 | sops cannot encrypt bytes into a YAML or JSON leaf (3.8). Base64 inside YAML waits on Q22. |
| `--clip` (Q4) | Defer | — | Q4 is open. |

### 2.5 Owner ruling Q13

Ship in S1b. Section 4 holds the rule.

## 3. Facts this plan depends on

Facts come from four research reports of this workflow and from checks in this design
session. The "Tool" column names what established each fact. context7 could not run in
the research sessions (monthly quota), so docs.rs and upstream source stood in for it.
**[unverified]** marks a claim that no tool established; a slice that depends on one
checks it first (section 12, "Risks").

| # | Fact | Tool |
|---|---|---|
| V1 | sops v3.13.3 (2026-07-23) is the newest release. The locked nixpkgs ships sops 3.13.3 and age 1.3.2. | `gh release list -R getsops/sops`, re-run in this session; `nix eval` (research) |
| V2 | `secret-service` 5.2.0 (2026-08-29) is the newest release. Its features include `rt-async-io-crypto-rust`. | crates.io API (`curl`), re-run in this session |
| V3 | `security-framework` 3.7.0 (2026-02-20), `linux-keyutils` 0.2.5, rustix 1.1.5 and signal-hook 0.4.5 are the newest releases. | crates.io API, re-run in this session |
| V4 | cargo-dist v0.33.0 (2026-09-11) is on GitHub. crates.io stops at 0.32.0. | `gh release list -R axodotdev/cargo-dist`, re-run in this session; crates.io (research) |
| V5 | `secret-service` 5.2 with `default-features = false, features = ["rt-async-io-crypto-rust"]` passes `cargo deny check licenses bans` with this repository's `deny.toml`. It does not depend on `zeroize`. It adds about 96 crates on Linux. | `cargo-deny` on a scratch crate; crates.io dependency API (research) |
| V6 | `oo7` 0.6.0 is async only and uses tokio by default. `dbus-secret-service` binds libdbus, whose vendored C code is outside the licence allow list. | docs.rs, crates.io (research) |
| V7 | `SOPS_AGE_SSH_PRIVATE_KEY_FILE` arrived in sops 3.10.0 (PR #1692). `SOPS_AGE_KEY_CMD` arrived in 3.10 (PR #1811). age plugin identities arrived in 3.10 (PR #1641). `SOPS_AGE_SSH_PRIVATE_KEY_CMD` and post-quantum identities arrived in 3.12. | `gh api` on getsops/sops source and CHANGELOG at v3.13.3 (research) |
| V8 | An unencrypted ed25519 key decrypts under `env -i HOME=/nonexistent` with `SOPS_AGE_SSH_PRIVATE_KEY_FILE`. A passphrase key makes sops read `/dev/tty`. | Lab, sops 3.13.3, throwaway keys (research) |
| V9 | sops splits `SOPS_AGE_KEY_CMD` with shlex and runs it with no shell. A bare command name fails with no `PATH`. The command runs once per age recipient that sops tries, in every sops run. | sops source `age/keysource.go`; lab (research) |
| V10 | An `AGE-PLUGIN-*` identity runs `age-plugin-<name>` through `PATH`. The plugin inherits the environment. | age v1.3.2 `plugin/client.go` lines 426-433 (research) |
| V11 | Per format, `sops set` and `unset` behave as the table in 6.1.1 shows. After a `set`, every other `ENC[...]` string stays byte-identical in YAML, JSON, dotenv and ini. | Lab, sops 3.13.3 (research) |
| V12 | With no `--input-type`, sops reads `/dev/stdin` as the binary store's JSON. | Lab (research) |
| V13 | `sops set` reuses the data key. Only `create` encrypts to recipients. | Lab; existing `stable_meta` check (research) |
| V14 | v0.1 `secrit store` on a JSON sops store succeeds and rewrites the file as YAML. | Lab with the built binary, `/tmp/sopsr/lab5.sh` (research) |
| V15 | `sops` can encrypt str, int, float, bool and time values only. `bytes` exists on the decrypt side only. | `gh api` on sops `aes/cipher.go` (research) |
| V16 | rustix 1.1.5 has safe `memfd_create`, `fcntl_add_seals`, `fcntl_get_seals` and `termios::tcsetpgrp`. `MemfdFlags::NOEXEC_SEAL` exists. `renameat_with` is gated to `apple`, `linux_kernel` and `redox`. `fcntl_fullfsync` is gated to Apple. | rustix source in `~/.cargo/registry` (research) |
| V17 | std has no stable way to place an fd in a child. `CommandExt::fd` (rust-lang/rust#144989) is unimplemented. `command-fds` needs `pre_exec`, which is `unsafe`. std keeps an fd without `CLOEXEC` open across exec. | `gh api`; exa (research) |
| V18 | `signal_hook::flag::register_usize` and `low_level::emulate_default_handler` exist in 0.4.5 and are safe. | signal-hook source (research) |
| V19 | `systemd-creds encrypt` reads stdin when the input is `-`. `--user` and `--uid` arrived in systemd 256. | Local man pages, systemd 261.3 (research) |
| V20 | Docker Compose secrets accept an `environment:` source (Compose only, not `docker stack deploy`) and mount at `/run/secrets/<name>`. | exa, docs.docker.com (research) |
| V21 | `keepassxc-cli` 2.7.12 `rm` moves an entry to the Recycle Bin. | Local `keepassxc-cli --help` (research) |
| V22 | 76 integration tests exist (`cli.rs` 26, `safety.rs` 21, `setup.rs` 20, `tty.rs` 9). 54 run `store` or `rm` with no pty. | `grep -c '#[test]'` in this session; a script over `tests/*.rs` (research) |
| V23 | The macOS keychain CI recipe needs `security set-key-partition-list -S apple-tool:,apple: -s -k ""`; without it a read opens a dialog and hangs. | exa, a public workflow (research) **[unverified on this repository]** |
| V24 | The keyring-rs headless recipe is `dbus-run-session -- sh -c 'printf pw \| gnome-keyring-daemon --daemonize --login --components=secrets; …'`. | exa, three projects cite it (research) **[unverified in the Nix sandbox]** |
| V25 | `gpg --batch --pinentry-mode error --list-packets` on a file for a passphrase key tries to decrypt and fails with `No pinentry`. With `--list-only` it prints the `:pubkey enc packet:` lines (the key ID is the encryption subkey) and does not decrypt. | Lab, gpg 2.4.9, temp `GNUPGHOME`, revision 2 |
| V26 | sops runs `SOPS_AGE_KEY_CMD` with `exec.Command` and `cmd.Env = append(os.Environ(), …)`, so the command gets sops's own environment, which secrit has cleared. sops also passes `SOPS_AGE_RECIPIENT`. | `gh api` on `age/keysource.go` at v3.13.3, lines 307-309 and 39, revision 2 |
| V27 | cargo-dist inherits `publish` from `Cargo.toml` when `dist` is not set, so `publish = false` makes a package not distable. `dist = true` overrides it. | exa: cargo-dist book, "Which Packages Are Distable", revision 2 |
| V28 | secrit is a bin-only crate (no `[lib]`). The sops child stdout cap is `MAX_VALUE_BYTES` (64 KiB) per run. `tests/cli.rs` (3 sites) and `tests/safety.rs` (2 sites) set `SECRIT_TEST_HOOK` themselves. `tests/setup.rs` asserts that `doctor` exits 0 with no `fail` row. The toolchain is the nixpkgs rustc 1.98.1 with no cross `std`. The `env` wire already maps every non-alphanumeric character to `_`. | Reading `Cargo.toml`, `src/backend/sops.rs:787`, `rg` over `tests/`, `rust-toolchain.toml`, `src/cmd/wire.rs:191`, revision 2 |

## 4. Owner ruling Q13(b): the write gate

OWNER RULING 2026-10-08 on Q13: option (b). Under agent detection, `store` and `rm` need a
confirmation typed on `/dev/tty`. With no `/dev/tty` they are refused.

### 4.1 Rule

`agent::write_gate(agent: Option<Agent>, tty_opens: bool) -> WriteGate` is a pure function:

| Agent detection (PLAN 8.3) | `/dev/tty` opens | Result |
|---|---|---|
| None | yes | `Allow` |
| `Variable(v)` | yes | `ConfirmOnTty(v)` |
| `Variable(v)` | no | `Refuse` |
| `NoTty` | no | `Refuse` |

`store` (also `--replace`), `rm` (also `--yes`), `generate` and `init` call the gate.
`init` calls it once, before its first write step (store file, `.sops.yaml`, age key,
config). `ls`, `get`, `run`, `doctor` and `wire` do not (Q21).

With no `/dev/tty`, the message is: `refused: an agent or a session with no terminal
cannot change the store (Q13); run it from your own terminal`. The v0.1 `rm` hint "pass
--yes to remove without asking" goes, because `--yes` no longer helps there.

`NoTty` counts as an agent in v0.1 (PLAN 8.3), and the ruling refuses writes with no
`/dev/tty`. So `printf v | secrit store n` from cron, a systemd unit or CI is refused
(exit 3). Q19 asks the owner to confirm this result.

### 4.2 The confirmation

1. The gate runs after the name check and the backend `check_put` or `check_remove`, and
   before secrit reads a value. Nobody types a value that the gate then refuses.
2. secrit opens `/dev/tty` and discards pending input (`tcflush(TCIFLUSH)`, safe in rustix).
   So input typed ahead cannot answer the question.
3. It prints, on `/dev/tty`:
   `an agent runs secrit (CLAUDECODE is set). To store 'NAME' in <location>, type the name:`
   For `rm`: `To remove 'NAME' from <location>, type the name:`. For a create in a
   binary store (6.1.4) and for `init`, the prompt also lists the recipients that the
   new file will have, because `.sops.yaml` decides them.
4. It reads one line in canonical mode with echo on (a name is not secret), at most 255
   bytes, through the signal-polling `tty::read_line`.
5. The line must equal NAME byte for byte. Anything else exits 3 with `not confirmed`.
   A signal restores the terminal and exits 130.
6. For `rm` under `ConfirmOnTty`, `--yes` does not skip the question. secrit prints one
   line that says so.

The typed name replaces `y` on purpose: a reflexive `y` is too easy (Q20). This is not a
security boundary (4.4).

### 4.3 Code and tests

The gate ships in S1b. S1a moves the hook code first, with no behaviour change.

- `agent.rs`: `WriteGate` and `write_gate`, with a unit test for every row of 4.1.
- `tty.rs`: `confirm_typed(question, expected) -> Result<bool, Error>`. `rm::confirm` and
  `is_yes` move here, so `store`, `rm`, `generate` and `init` share one path.
- `cmd/store.rs`: the gate between `check_put` and `read_value`.
- `cmd/rm.rs`: the gate replaces the `--yes` shortcut under `ConfirmOnTty`.
- `cmd/init.rs`: the gate before the first write step.
- **Test bypass.** 54 integration tests run `store` or `rm` with no pty (V22). Under the
  ruling, all of them would exit 3. The `test-hooks` feature, which no release or Nix
  package build enables, reads a separate variable, `SECRIT_TEST_GATE=allow`. It is not
  part of `SECRIT_TEST_HOOK`, so the five tests that set their own `SECRIT_TEST_HOOK`
  (`tests/cli.rs` lines 501, 519, 535; `tests/safety.rs` lines 255, 283; V28) keep the
  bypass without an edit. `TestEnv::cmd()` sets `SECRIT_TEST_GATE=allow` by default. The
  gate tests remove it.
  - `secrit --version` prints `test-hooks` when the feature is on.
  - `doctor` shows a `warn` row `build: test hooks are compiled in` when the feature is
    on. It is a warning, not a failure, so `doctor_passes_on_a_good_setup` (exit 0, no
    `fail` row) still passes under `--all-features`.
  - A new flake check `release-features` runs `${secrit}/bin/secrit --version` on the
    package derivation (the artifact that ships) and fails when the output contains
    `test-hooks`. That check guards T54.
  - The hook code moves from `backend/sops.rs` to a new `testhook.rs` (S1a).
- New integration tests (pty through util-linux `script`):
  - `CLAUDECODE=1`, piped value, the name typed on the tty: stored.
  - `CLAUDECODE=1`, `y` typed: exit 3, the store is byte-identical.
  - typed-ahead input before the prompt is discarded.
  - `rm --yes` under `CLAUDECODE=1` still asks.
  - `no_tty()` with and without `CLAUDECODE`: `store`, `rm --yes`, `generate` and `init`
    exit 3 with the new message.
  - T27a (documented bypass): `script -qc 'env -u CLAUDECODE secrit store n' /dev/null`
    with a piped value stores with no question. The test asserts this result, so the
    docs stay honest about it.
- Docs: PLAN 8.3, the Q11 and Q13 rows, README lines 201 and 243, the README list "does
  not protect against" (4.4), and the `doctor` agent row (`get` off; `store`, `rm`,
  `generate` and `init` need a typed name, or are off with no tty).

### 4.4 What the gate does not stop

The gate stops accidents. It does not stop an agent that works around it:

- An agent can allocate a pty and unset its variable (`script -qc 'env -u CLAUDECODE …'`).
  Detection then finds no agent, and the gate allows the write (T27a).
- An agent that runs commands in a pty (PTY exec modes, `tmux send-keys`, terminal
  remote control) sees the prompt and can type the name.
- A writer can feed the answer after the `tcflush`, for example
  `{ sleep 1; echo n; } | script -qc 'secrit store n'`.
- The gate does not cover direct `sops set`, `sops edit` or `git` changes to the store
  file. Only file permissions and review cover those.

Claude Code itself gets `Refuse` today: it sets `CLAUDECODE=1` and has no `/dev/tty` (lab
in this session). Q33 asks the owner whether an accident gate meets the ruling's intent.

## 5. Architecture

### 5.1 The `Backend` trait

```rust
pub trait Backend {
    fn kind(&self) -> BackendKind;
    fn capabilities(&self) -> Capabilities;
    /// Where the store lives, for messages and errors.
    fn location(&self) -> &Location;
    /// Names as the store holds them, sorted. Raw strings: another tool can
    /// write a key that is not a valid `Name`; `ls` escapes it. Never decrypts
    /// when `capabilities().names_without_decrypt` is true.
    fn list(&self) -> Result<Vec<String>, BackendError>;
    fn exists(&self, name: &Name) -> Result<bool, BackendError>;
    fn check_put(&self, name: &Name, mode: PutMode, kind: ValueKind) -> Result<(), BackendError>;
    fn check_remove(&self, name: &Name) -> Result<(), BackendError>;
    /// A file backend reads one checked snapshot. A daemon backend gives a
    /// consistent value per name, not across names.
    fn get_many(&self, names: &[Name]) -> Result<Vec<(Name, SecretValue)>, BackendError>;
    fn put(&self, name: &Name, value: &SecretValue, mode: PutMode) -> Result<WriteReport, BackendError>;
    fn remove(&self, name: &Name) -> Result<WriteReport, BackendError>;
    /// The backend's own doctor rows (store file, keys, daemon, rules).
    fn doctor(&self, report: &mut Report);
    /// What `wire` can tell a consumer about NAME, if anything.
    fn wire_source(&self, name: &Name) -> Option<WireSource>;
}
```

This is the trait at the end of v0.2. secrit is a bin-only crate (V28), so `pub` does not
suppress `dead_code`, and both clippy gates run with `-D warnings`. Each slice therefore
adds only the items that it reads. No item carries `#[expect(dead_code)]` across slices.

| Item | Added in |
|---|---|
| `kind`, `location`, `list`, `exists`, `check_put` (no `ValueKind`), `check_remove`, `get_many`, `put`, `remove`, `doctor`; `Location::File` | S1a |
| `capabilities()` with the fields that a command reads in the same slice; `Location::Dir` | S5 (`nested_names`), then each field with its first reader |
| `wire_source`, `WireSource::SopsFile` | S4 (wire reads `format`) |
| `ValueKind` and the `binary_values` field | S9 |
| `WireSource::Opaque`, `Location::Collection`, `BackendError::{Daemon, Locked}` | S10 |
| `BackendError::Capability` | the first slice that refuses on a capability (S5) |
| `Location::Keychain` | S18, under `cfg(target_os = "macos")` |

Changes from v0.1:

- `kind()` loses `#[expect(dead_code)]`. `doctor` and `init` read it.
- `list` keeps raw strings. PLAN 6.1 said `Vec<Name>`; the code is right, and this plan
  corrects the text.
- `check_put` gains a `ValueKind { Text, Binary }` parameter in S9, not before.
- `location`, `capabilities`, `doctor` and `wire_source` are new.
- `PutMode` and `WriteReport` stay. `WriteReport.backup` is `None` for daemon backends.
- `backend::open(&StoreConfig, &Config, &Env, quiet) -> Result<Box<dyn Backend>, Error>`
  replaces the match in `Ctx::load`. `doctor` uses it too, not `SopsBackend::new`.
- `init` does not go through the trait. Each backend module has a free function
  `init(&InitArgs, &mut Steps)`, and `cmd/init.rs` picks it with `--backend`.

### 5.2 Capabilities

```rust
pub struct Capabilities {
    pub names_without_decrypt: bool,
    pub write: WriteAtomicity,     // Rename | DaemonCall
    pub backups: bool,             // ciphertext backup before replace and rm
    pub binary_values: bool,
    pub nested_names: bool,
    pub snapshot_reads: bool,
    pub other_app_acl: bool,       // other programs need the owner's approval to read
}
```

| Capability | sops yaml/json | sops dotenv | sops ini | sops binary dir | Secret Service | pass layout | Keychain |
|---|---|---|---|---|---|---|---|
| names without decrypt | yes | yes | yes | yes (file names) | yes (attributes) | yes (file names) | yes (attributes, no data) |
| write | Rename | Rename | Rename | Rename | DaemonCall | Rename | DaemonCall |
| backups | yes | yes | yes | yes | no | yes | no |
| binary values | no | no | no | yes | yes | no (6.4) | yes |
| nested names | yes | no | exactly two segments | no | yes (flat string) | yes (directories) | yes (flat string) |
| snapshot reads | yes | yes | yes | per name | per name | per name | per name |
| other-app ACL | no | no | no | no | no | no | yes; secrit itself is trusted |

How commands use them:

- `ls`: when `names_without_decrypt` is false, `ls` prints `listing unlocks <location>` on
  stderr first. No backend of this round has false; KeePassXC will.
- `store --binary`: refused (exit 3) when `binary_values` is false, with a pointer to a
  binary store.
- A nested name (`a/b`): refused (exit 3) when `nested_names` is false.
- `store --replace` and `rm`: the backup line appears only when `backups` is true. When
  `backups` is false, `store --replace` and `rm` print `no backup; the old value is gone`
  and need a confirmation: `y` on `/dev/tty`, or `--yes`. The owner gets that question too
  (Q37). `rm` also says that the daemon may keep the old value in its own files. PLAN T12
  and the README bullet "Old values" are true only for backends with `backups` (T55).
- `get` under agent detection stays refused on every backend (Q26). On every backend this
  refusal is an accident guard only: an agent that passes the env and tty check runs
  secrit, and secrit is trusted by every store. When `other_app_acl` is true, the doctor
  row says `other programs need your approval to read; secrit itself is trusted`.

### 5.3 Location, Target and errors

- `Location` is an enum: `File(PathBuf)`, `Dir(PathBuf)`, `Collection { collection,
  store }`, `Keychain { service, keychain: Option<PathBuf> }`. Its `Display` escapes
  control characters, as v0.1 does.
- `Target { location: Location, name: Option<Name> }` replaces `Target { path }`. For
  `File`, the text stays the same as v0.1.
- The sops-shaped errors become generic: `Tool { tool, step, target, status, stderr }`,
  `ToolPrompt`, `ToolTimeout`, `ToolOutputTooLarge`, `ToolTooOld`, and
  `Parse { location, format, what }`. With `tool = "sops"`, each message renders the same
  text as v0.1. So S1a changes no test expectation. `ToolPrompt` carries a `hint: String`
  that the backend supplies, so S8 changes the prompt text in `sops/runner.rs` only, not
  in `backend/mod.rs`.
- New variants, each in the slice that first returns it (5.1): `NotConfirmed` and
  `AgentNoTty` (S1b, exit 3), `Capability { what }` (S5, exit 3), `Daemon { daemon, step,
  what }` and `Locked(Location)` (S10).
- The lock key (PLAN 8.1 step 4) stays `<dir dev>-<dir ino>-<name hash>` for file
  locations. For other locations it is a hash of the backend kind and the location text.
  The lock serialises secrit writers only. It does not lock out other programs.

### 5.4 Names and key paths

`Name` becomes a key path. Each segment matches the v0.1 grammar
`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. Segments are joined by `/`. A name has at most 8
segments and 255 bytes. The type keeps its name, so the trait signatures do not change.

- `Name::segments()` gives the parts. `Name::sops_path()` gives `["a"]["b"]`.
- A one-segment name is exactly a v0.1 name.
- `parse_name` still runs before the config loads (R6). The nesting check runs after, from
  the capability.
- The sops rules move from `name.rs` into the sops `check_put`. The suffix rules
  (`_unencrypted` and the file's own suffix rules) apply to every segment (6.1.3). The
  reserved key `sops` applies to the first segment only: only the top-level `sops` key is
  metadata, so `app/sops` is a valid name.
- The dotenv rule is narrower: one segment matching `^[A-Za-z_][A-Za-z0-9_]{0,127}$`, and
  no name that starts with `sops_` (case-sensitive, as sops matches it). sops reads every
  `sops_*` line of a dotenv file as metadata (6.1.1).
- The INI rule (S6b): exactly two segments, `section/key`. The section must not be `sops`.
  Each segment matches the dotenv grammar.

### 5.5 Store formats (sops only)

```rust
pub enum SopsFormat { Yaml, Json, Dotenv, Ini, Binary }
```

Each format gives: `input_type()` (passed as both `--input-type` and `--output-type` on
every sops run), `parse(bytes) -> SopsDoc`, `empty_doc()`, `temp_ext()`, `nested_ok()`,
and `validate(orig, copy, op)`. `SopsDoc` holds the metadata (minus `mac`,
`lastmodified`, `version`) and a tree of leaves keyed by path.

The write protocol (PLAN 8.1) moves into `backend/atomic.rs` as `FileStore::write(name,
&dyn FileEdit)`. A `FileEdit` has `parse`, `precheck`, `apply(tmp_path)`, `validate`, and
`readback`. sops YAML, JSON, dotenv and INI implement it. The pass backend reuses
`FileStore` with its own `FileEdit` (6.4). S3 puts every `FileStore` operation that a later
slice needs into `atomic.rs` at once: `write` (replace in place), `create_new` (temp file,
validate, `renameat_with(NOREPLACE)`) and `backup` (0600 copy). A file-per-name remove is
`backup`, then one `unlinkat` in the backend module. So S9 and S11 use `atomic.rs` and do
not change it. Only S17 changes it again (`F_FULLFSYNC`).

### 5.6 Key sources (sops identities)

```rust
pub enum KeySource {
    AgeKeyFile(PathBuf),     // v0.1, SOPS_AGE_KEY_FILE
    AgeSshKeyFile(PathBuf),  // SOPS_AGE_SSH_PRIVATE_KEY_FILE
    AgeKeyCmd(PathBuf),      // SOPS_AGE_KEY_CMD
}
```

A store has one or more key sources, plus an optional `age_plugin_dir`. `runner::child_env`
builds the sops environment from them (6.2). No key source puts key material in an
environment variable: each passes a path.

### 5.7 Wire targets

```rust
pub enum WireSource {
    SopsFile { file: PathBuf, format: SopsFormat, key: Option<Name> },
    Opaque,   // any backend: consumers go through `secrit get --stdout` or `secrit run`
}
pub enum WireFormat { Nix, Hm, Env, Systemd, SystemdCreds, Compose, K8s, Dotenv }
```

| Format | Needs | Prints |
|---|---|---|
| `nix` | `SopsFile` | the NixOS sops-nix stanza (v0.1), with `format` from the store and `key` for a nested name |
| `hm` | `SopsFile` | the sops-nix home-manager stanza; the unit hint `After=sops-nix.service` |
| `env` | `SopsFile` | `NAME_FILE=/run/secrets/NAME` (v0.1) |
| `systemd` | `SopsFile` | the `nix` stanza plus `LoadCredential=NAME:/run/secrets/NAME` |
| `systemd-creds` | any | `secrit get --stdout NAME \| sudo systemd-creds encrypt --name=NAME - /etc/credstore.encrypted/NAME` and `LoadCredentialEncrypted=NAME`; with `--user`, the per-user form (V19) |
| `compose` | any | a `secrets:` block with `environment:` as the source, and `secrit run --env VAR=NAME -- docker compose up -d` |
| `k8s` | any | `secrit run --file F=NAME -- sh -c 'kubectl create secret generic SECRET --from-file=KEY="$F"'` |
| `dotenv` | any | for a dotenv store: `sops exec-env FILE 'CMD'`; for any other store: `secrit run --env VAR=NAME -- CMD`. It writes no file and prints no value. |

Nested names (5.4) in names that a consumer sees:

- `env`, `compose`, `dotenv` (variable names): the v0.1 `env_line` mapping already turns
  every character that is not ASCII alphanumeric, `/` included, into `_` and upper-cases
  the rest (V28). So `a/b` gives `A_B_FILE=/run/secrets/a/b`.
- `systemd` and `systemd-creds` (credential IDs, which must not contain `/`): segments
  joined with `_`, so `a/b` gives `LoadCredential=a_b:/run/secrets/a/b`.
- Two names of one store that map to the same variable or ID (`a/b`, `a_b`, `a.b`) exit 3
  and name both. The check runs over every name of the store, not only the one wired.

A format that needs `SopsFile` on a backend that gives `Opaque` exits 3 and names the
formats that work. `wire` runs nothing (N7). It prints `sudo` lines as text, as v0.1 does.

### 5.8 Configuration

The v0.1 file parses unchanged. `backend` becomes the tag of an enum:

```toml
default_store = "main"

[stores.main]                     # a v0.1 store: parses with no change
backend = "sops"
file = "/etc/nixos/secrets/secrit.yaml"
format = "yaml"                   # new, optional: yaml | json | dotenv | ini | binary
sops_config = "/etc/nixos/.sops.yaml"
age_key_file = "~/.config/sops/age/keys.txt"
age_ssh_key_file = "~/.ssh/sops_ed25519"   # new, optional (S8)
age_key_cmd = "/home/you/bin/age-key"      # new, optional, absolute (S8)
age_key_cmd_timeout_secs = 20              # new, optional (S8, 6.2)
age_plugin_dir = "/nix/store/…-age-plugin-yubikey-0.5.1/bin"  # new, optional (S8)
wire_hint = true

[stores.blobs]                    # binary store: one sops file per name (S9)
backend = "sops"
format = "binary"
dir = "/etc/nixos/secrets/blobs"
sops_config = "/etc/nixos/.sops.yaml"

[stores.desk]                     # S10
backend = "secret-service"
collection = "default"            # optional; an alias or an object path; default "default"
unlock = "refuse"                 # optional; "refuse" (default) or "prompt" (Q30)

[stores.pw]                       # S11
backend = "pass"
dir = "~/.password-store"
prefix = "secrit"                 # optional subdirectory; default: the store root
gnupg_home = "~/.gnupg"           # optional; default: $GNUPGHOME, else ~/.gnupg
value = "whole"                   # optional; "whole" (default) or "first-line" (6.4)
pinentry = "error"                # optional; "error" (default) or "agent" (6.4)

[stores.mac]                      # S18, macOS only
backend = "keychain"
service = "secrit.mac"            # optional; default "secrit.<store name>"
keychain = "~/Library/Keychains/test.keychain-db"   # optional; default: the login keychain

[nix]
flake = "/etc/nixos"
host = "myhost"

[tools]
sops = "auto"
age_keygen = "auto"
gpg = "auto"                      # new (S11)

[lock]
timeout_secs = 30
```

Rules:

- `RawStore` becomes `#[serde(tag = "backend", rename_all = "kebab-case")]` with one
  struct per variant, each with `deny_unknown_fields`. A unit test proves that an unknown
  key in each variant is still an error, because serde has known gaps with
  `deny_unknown_fields` on tagged enums.
- `StoreConfig` becomes `{ name, wire_hint, backend: BackendConfig }`.
- sops `format` is optional. With no `format`, `.json` means JSON, `.env` means dotenv
  and `.ini` means INI. Any other extension, `.yaml` and `.yml` included, means YAML, as
  in v0.1. Until S6b merges, `.ini` without a `format` is refused (exit 3).
- `format = "binary"` needs `dir` and forbids `file`. Every other format needs `file` and
  forbids `dir`.
- A backend that this build lacks (`keychain` on Linux) is an error that names the
  platform. It is not an unknown variant.
- The home-manager module (`nix/hm-module.nix`) renders any TOML, so it needs no change.
  Its flake check gets one new store of each kind.
- There is no config version key. A v0.2 file that a v0.1 binary reads fails on the
  unknown key, which is the safe result.

### 5.9 How each command adapts

| Command | Change |
|---|---|
| `store` | Gate (4); `--binary` (S9); messages from `location()` and `capabilities()`. `/run/secrets/NAME` appears only for a `SopsFile` wire source. |
| `rm` | Gate (4); messages from `location()` and `capabilities()`. |
| `get` | `--stdout` writes binary values raw. The reveal screen shows a binary value as base64 plus its byte count. |
| `ls` | Nested names print as `a/b`. Capability note (5.2). |
| `doctor` | Common rows: config, tools, agent, hardening, build. Then each store's `backend.doctor()`. The sops rows move from `cmd/doctor.rs` into `backend/sops/doctor.rs` (S3). |
| `init` | Gate (4) before the first write step. `--backend sops\|secret-service\|pass\|keychain`, default `sops`. sops keeps v0.1 steps and gains `--format`. Other backends check reachability and write the config section only. |
| `wire` | `--format` gains `hm`, `systemd`, `systemd-creds`, `compose`, `k8s`, `dotenv` (5.7). |
| `run`, `generate` | New (7.1, 7.2). |

## 6. Backends

### 6.1 sops

#### 6.1.1 Format behaviour (V11, lab on sops 3.13.3)

| | yaml / json | dotenv | ini | binary |
|---|---|---|---|---|
| top-level `set ["K"]` | ok | ok | refused by secrit (5.4) | `["data"]` replaces the whole content |
| nested `set ["a"]["b"]` | ok; creates missing parent maps | rc 4, refused | `["section"]["key"]` (V11 covers ini; S6b labs the nested form first) | n/a |
| `unset` | ok; leaves an empty parent map | ok | ok | n/a |
| `decrypt --extract` of a string | raw bytes, no trailing newline | same | same | raw file bytes, NUL included |
| metadata | `sops:` map | flat `sops_*` lines; lists as `__list_N__map_` | a `[sops]` section | JSON `{"data": ENC, "sops": {}}` |

Lab traps that the validation must catch:

- `set ["a"]["sub"]` on a string leaf `a` replaces it with a map, silently.
- An out-of-range list index appends. secrit never addresses lists.
- dotenv accepts `["bad key"]` and returns a number set with `set` as `5.0`.

#### 6.1.2 Validation per format

All formats keep PLAN 8.1 step 9, generalised:

- Parse with the store's own format. A JSON store must parse with `serde_json` strictly;
  a YAML result fails. This closes the V14 bug.
- Metadata minus `mac`, `lastmodified` and `version` is equal. At least one master key is
  present. Recipient types are opaque (V13).
- Every leaf except the target path is byte-equal, comparing the raw `ENC[...]` strings.
- No leaf appears except the target. The target is `ENC[AES256_GCM,…,type:str]`.
- YAML and JSON: every ancestor of the target is a map before and after. Only missing
  ancestors may be created. `rm` prunes an ancestor map that it left empty, with a second
  `unset` on the same copy.
- dotenv: a line parser for `KEY=VALUE` and `#` comments. It splits the `sops_` prefix and
  unflattens `__map_` and `__list_N__`. Names follow 5.4; `check_put` refuses a name with
  the `sops_` prefix before any input.
- INI (S6b): the same line parser with `[section]` headers. The `[sops]` section is the
  metadata. Every other section holds only the target and byte-equal leaves.
- binary: exactly `{data, sops}`, and `data` is an encrypted string.
- The readback runs `decrypt --extract` with the same `--input-type`.

#### 6.1.3 Cleartext rules

- Suffix rules (`unencrypted_suffix`, `encrypted_suffix`) apply to every segment of a
  nested name: sops tests each key on the path. The reserved `sops` key applies to the
  first segment only (5.4).
- Regex rules (`encrypted_regex`, `unencrypted_regex`): v0.1 refuses the whole file, and
  v0.2 keeps that refusal. The canary probe (S7) is deferred: while the every-leaf rule
  stays, it helps only a regex file whose every leaf already matches, at the cost of one
  more sops run per `store`. It returns if the owner relaxes Q23.
- The every-leaf-encrypted rule stays. A Kubernetes manifest with plaintext `kind` and
  `apiVersion` is still refused (Q23).

#### 6.1.4 Binary store layout

A binary store is a directory. Each name is one sops binary file: `<dir>/<NAME>.bin`.
Nested names are refused.

- `list`: the regular files `*.bin` in `<dir>`, without decrypting. Names come from file
  names.
- `put`, create: `sops --config C encrypt --input-type binary --output-type binary
  --filename-override <dir>/<NAME>.bin /dev/stdin` with the raw bytes on stdin, into a
  temp file. secrit validates it (shape, recipients present), reads it back with
  `decrypt`, compares in constant time, fsyncs it and renames it with `NOREPLACE`.
  The child stdout cap is per step: `decrypt` keeps 64 KiB, and a binary `encrypt` allows
  `ceil(65536 * 4 / 3)` bytes plus a 16 KiB metadata margin. A 64 KiB value encrypts to
  about 88 KiB, which the v0.1 cap of 64 KiB (V28) would refuse with `ToolOutputTooLarge`.
- `put`, replace: the same, but the new file's recipients must equal the old file's.
  A changed `.sops.yaml` rule therefore refuses the replace; the message tells the user to
  run `sops updatekeys` first.
- `remove`: back up, then `unlinkat`.
- `init --format binary` creates the directory (0700) and prints the rule
  `path_regex: <dir>/[^/]+\.bin$`.
- `wire` prints one stanza per name with `format = "binary"`.

A create needs a `.sops.yaml` creation rule, unlike `set` (F3). `doctor` checks the rule.
Because the rule decides the recipients, the write-gate prompt of a create lists them
(4.2).

#### 6.1.5 Other sops changes

- `TEMP_IGNORE` becomes `.*.secrit-*`. Temp copies end in the format's extension. The
  `.gitignore` hint and the check-ignore probe use one sample name per format.
- `MIN_SOPS` stays 3.11. Each key source checks its own floor (V7).
- `init` refuses to create a file for non-age recipients and says so (2.2).

### 6.2 sops identities (S8)

`runner::child_env` keeps `HOME=/nonexistent`, `SOPS_DISABLE_VERSION_CHECK=1` and the
cleared environment. It adds, only from config:

| Config key | Child variable | Rules |
|---|---|---|
| `age_key_file` | `SOPS_AGE_KEY_FILE` | v0.1. |
| `age_ssh_key_file` | `SOPS_AGE_SSH_PRIVATE_KEY_FILE` | Owner and mode as the age key file (0600, no symlink). An encrypted key needs `<key>.pub` beside it and a terminal prompt, which the stop detection ends at once; the message names Q24. `doctor` reads the key header (`openssh-key-v1`, cipher `none`) without the private part. |
| `age_key_cmd` | `SOPS_AGE_KEY_CMD` | An absolute path to an executable that passes the trust rule (PLAN 5). No arguments: sops splits the string with shlex (V9), so secrit refuses whitespace and quotes in the path. `doctor` warns that it runs once per sops run. secrit never reads its output. Environment and deadline: see below. |
| `age_plugin_dir` | `PATH=<dir>` | The directory passes the trust rule and holds only `age-plugin-*` files. `PATH` holds this one directory. A PIN prompt stops sops (SIGTTIN) and secrit ends it. Each `store` costs two to three plugin operations (set, readback, probe). |

**The key command's environment.** sops runs the command with sops's own environment
(V26). That is secrit's cleared child environment: `HOME=/nonexistent`, no `PATH` (or only
`age_plugin_dir`), no `DBUS_SESSION_BUS_ADDRESS`, no `GNUPGHOME`, plus the sops key
variables and `SOPS_AGE_RECIPIENT`. So `pass show`, `op read`, `rbw get` or `security
find-generic-password` fail unless the command sets its own `PATH` and `HOME`. secrit
does not widen the environment for it (T19). The rules:

- `doctor` reads the command's first bytes. A script must have an absolute shebang
  (`#!/nix/store/…/bash`, not `#!/usr/bin/env bash`); an ELF binary passes. Otherwise
  `doctor` warns and names the rule.
- The README shows a wrapper that sets `PATH` and `HOME` explicitly.
- `SOPS_AGE_RECIPIENT` reaches the command only on sops 3.12 or newer (V7). The command
  must not depend on it below that.

**The key command's deadline.** A key command that reads `/dev/tty` is a grandchild in
the sops process group, which is not the foreground group. It stops on SIGTTIN, but
secrit watches only the sops child, which does not stop: it waits. With `age_key_cmd` or
`age_plugin_dir` set, the sops deadline drops from 120 s to `age_key_cmd_timeout_secs`
(default 20). The timeout message names the key command and says that it may wait for
a terminal.

`SOPS_AGE_KEY` stays forbidden: it puts key material in an environment. `doctor` keeps the
warning row for `SOPS_AGE_KEY` and `SOPS_AGE_KEY_CMD` in secrit's own environment.

The v0.1 prompt error ("v0.1 supports only an age key file") changes to name the key
source that prompted.

### 6.3 Secret Service (S10)

- Crate: `secret-service` 5.2.0, `default-features = false`,
  `features = ["rt-async-io-crypto-rust"]` (V2, V5). Encryption `EncryptionType::Dh` only.
  PLAN 6.3 said "needs no async runtime". That is wrong: the blocking API wraps zbus,
  which runs an internal async-io executor thread. There is still no tokio.
- Item: label `secrit: NAME`; attributes `application=secrit`, `secrit-store=<store>`,
  `secrit-name=NAME`. `secret-tool lookup secrit-name NAME` still works.
  Content type `application/octet-stream`, so binary values work.
- `list`: `search_items` on `application` and `secrit-store`; secrit reads attributes only.
- `get_many`: one `get_secret` per name. secrit copies the returned `Vec<u8>` into a
  `SecretValue` and zeroizes the source at once: the crate does not use `zeroize`.
  Other copies stay unwiped: the zbus message buffers and the crate's AES-CBC buffers
  (V5: no `zeroize` dependency). The "zeroized buffers" posture covers secrit's own
  buffers only (T56).
- `put`:
  - `Replace`: one `create_item(…, replace = true)`, atomic in the daemon.
  - `CreateOnly`: under the secrit lock, search, then `create_item(…, replace = false)`,
    then search again. More than one match refuses and deletes the item that secrit
    created. The daemon does not refuse a duplicate by itself **[unverified per daemon]**.
- `remove`: `Item::delete`.
- Locked collection: refused with `Locked` (Q30). With `unlock = "prompt"` and no agent,
  secrit calls `unlock()`, which may open a GUI prompt.
- Bus address: secrit reads `DBUS_SESSION_BUS_ADDRESS` from its own environment. When it
  is unset, secrit uses `unix:path=$XDG_RUNTIME_DIR/bus`. Either way it must be
  `unix:path=<absolute>`, and the socket must be owned by the uid, in a directory that
  group and others cannot write (no sticky `/tmp`). Anything else is refused (exit 3).
  secrit builds the connection from the checked address with
  `zbus::connection::Builder::address(…)` and passes it to
  `SecretService::connect_with_existing` **[verify in S10: the blocking API signature
  and the zbus version that `secret-service` 5.2.0 pins]**. So zbus never reads the
  environment again. This adds a direct `zbus` dependency at the version that
  `secret-service` uses.
- Deadline and signals: D-Bus calls run in a spawned (not scoped) thread, which sends its
  result on a channel. The main thread waits with `recv_timeout` in 100 ms steps and
  checks `signals::pending()` at each step. On a signal it exits 130 (R13); at 120 s it
  exits 1. Both exits go through the normal error path, so `Drop` runs: the lock is
  released, buffers are zeroized and the terminal mode is restored. The abandoned thread
  ends with the process.
- `doctor` rows: bus address, daemon reachable, collection exists and is unlocked, DH
  session works, count of secrit items.
- `wire_source`: `Opaque`.
- `init --backend secret-service`: connects, checks the collection, writes the config.

### 6.4 pass layout (S11)

secrit reads and writes the password-store layout itself. It runs `gpg`, never `pass`.

- Layout: `<dir>/<prefix>/<name>.gpg`. A nested name maps to subdirectories.
- Recipients: the nearest `.gpg-id`, from the entry's directory up to `<dir>`. Each line
  is one `-r` argument. A `.gpg-id.sig` file (pass signing) refuses every write in v0.2:
  secrit does not verify signatures yet.
- `list`: walk `<dir>/<prefix>` for `*.gpg` with `openat` and `O_NOFOLLOW`. Nothing is
  decrypted.
- **Value.** By pass convention the first line is the password and later lines are
  metadata (`login:`, `url:`). `pass insert` writes the password plus a newline. secrit's
  rule:
  - `put` writes the value, then one `\n`. A value that already ends in `\n` gets one
    more, so the round trip is exact.
  - `get` returns the whole decrypted file minus exactly one trailing `\n`.
  - With the store option `value = "first-line"`, `get` returns the bytes before the
    first `\n` (the pass password), and `put` refuses a value that holds `\n`.
  - Binary values are off on this backend (`binary_values = false`): a trailing-newline
    rule cannot round-trip arbitrary bytes.
- `get`: `gpg --batch --quiet --pinentry-mode error --decrypt` with the file bytes on
  stdin. gpg-agent, not gpg, starts the pinentry, so pinentry is outside secrit's process
  group and secrit cannot see it stop. With a cleared environment, gpg-agent uses its own
  startup display or tty: it can open a GUI prompt on the owner's desktop or block. So
  secrit always passes `--pinentry-mode error`: a cached passphrase still works, and a
  needed prompt fails at once with a message that says how to cache the passphrase. The
  store option `pinentry = "agent"` drops the flag, and secrit honours it only when no
  agent is detected and `/dev/tty` opens. The README says that a GUI pinentry can appear
  in that mode.
- `put`: `FileStore` with a pass `FileEdit`. `gpg --batch --no-tty --quiet --yes
  --compress-algo=none --no-encrypt-to --trust-model always --encrypt -r … -o -` with the
  value on stdin writes the temp file. `--no-encrypt-to` stops `encrypt-to` and
  `hidden-encrypt-to` in the user's `gpg.conf` from adding recipients (pass uses the same
  flag **[unverified in this session: pass 1.7.4 `GPG_OPTS`]**). secrit validates the copy
  with `gpg --batch --list-only --list-packets`, which does not decrypt (V25). The packets
  name encryption-subkey IDs, while `.gpg-id` holds e-mail addresses or primary-key
  fingerprints. So secrit resolves each `.gpg-id` entry with `gpg --with-colons
  --list-keys` to the key IDs of its usable encryption subkeys, and requires the packet
  set to equal the union. A write asks for no passphrase. Then fsync and rename.
- `remove`: `FileStore::backup`, then `unlinkat`. Empty subdirectories stay.
- git: secrit never commits (N7). When `<dir>` is a git repository, `store` and `rm` print
  `git -C <dir> add … && git -C <dir> commit` as text (Q25).
- Child environment: cleared, then `GNUPGHOME` (absolute) only. No `HOME`, no `GPG_TTY`.
- Tools: `tools.gpg`, resolved like `tools.sops`. S11 adds it to the `[tools]` table
  with the baked and config sources only. S16 then applies the `PATH` trust rule to every
  tool, `gpg` included.
- gopass: a gopass store with the `gpgcli` crypto backend and `fs` storage has the same
  layout. S11 tests both directions against such a store. secrit never runs `gopass`,
  so it never pushes; the docs call the support "gopass-compatible, no auto-sync".
- `doctor` rows: `gpg` binary, `GNUPGHOME` mode, `.gpg-id` present, each recipient key in
  the keyring and not expired, `.gpg-id.sig` present (warn), git state.
- `wire_source`: `Opaque`.

### 6.5 macOS Keychain (S18)

- Crate: `security-framework` 3.7.0 as a `cfg(target_os = "macos")` dependency (V3). The
  `unsafe` code is inside the crate, so `forbid` holds for secrit.
- Item: generic password, service `secrit.<store>` (or `service`), account NAME.
- `list`: `ItemSearchOptions` with the class, the service, `load_attributes(true)`, no
  `load_data`, limit all.
- `get`: `generic_password`. The value arrives as `CFData`, which secrit cannot wipe; it
  copies it into a `SecretValue` at once.
- `put`: `CreateOnly` uses `SecItemAdd`, which returns `errSecDuplicateItem`, atomic per
  item. `Replace` uses `set_generic_password`.
- `remove`: `delete_generic_password`.
- secrit never runs `security add-generic-password -w`: that puts the value on argv.
- ACL: the item trusts the creating binary. A rebuilt binary or a new Nix store path loses
  that identity, and the next read opens a dialog. The README says so.
- The ACL stops other programs (`security find-generic-password -w` opens a dialog that
  the owner may approve). It does not stop an agent that runs secrit: once secrit's own
  env and tty check passes, secrit reads with no dialog. The `doctor` row says `other
  programs need your approval to read; secrit itself is trusted` (5.2, T29).
- The value also stays in `CFData` buffers that secrit cannot wipe (T56).
- `wire_source`: `Opaque`.

### 6.6 Deferred backends

| Backend | Waits on |
|---|---|
| KeePassXC (`keepassxc-cli`) | Q3; v0.3 (M7). `rm` must empty the Recycle Bin too (V21). Binary values need `attachment-import`. |
| gopass (native: age crypto, `gitfs` sync) | Q35; auto-push and locking decisions. A `gpgcli` + `fs` store already works through the pass backend (S11). |
| Kernel keyring | A `run` cache design. |
| 1Password, Bitwarden | Network accounts; JSON item parsing of values. |

## 7. Commands

### 7.1 `secrit run` (S12, S13; Linux)

```text
secrit run [--file VAR=NAME]... [--env VAR=NAME]... [--pristine] [--no-mask] -- CMD [ARGS...]
```

PLAN 4.5 holds, with these changes:

1. **Values.** `get_many` on the store, before any child starts. For `--env`, a value
   with NUL is refused (exit 3). Under agent detection, `--env` is refused (exit 3) and
   only `--file` runs (Q27). An env value is readable without masking through `ps eww`,
   `/proc/<pid>/environ` and `docker inspect`, which are common agent debugging steps. A
   `--file` value is readable too, through `/proc/<pid>/fd/N`, but only by a deliberate
   read (T42, T57).
2. **`--file`.** For each VAR: `memfd_create("secrit", NOEXEC_SEAL)`, with no `CLOEXEC`.
   On `EINVAL` (kernel before 6.3), retry with `ALLOW_SEALING`. Write the value, add
   `WRITE | GROW | SHRINK | SEAL`, check with `fcntl_get_seals`, seek to 0. Set
   `VAR=/dev/fd/N`. The fixed name `secrit` does not leak secret names in
   `/proc/<pid>/fd`. A reader that opens `/dev/fd/N` gets a new file description at
   offset 0, so the path can be read more than once.
3. **`--pristine`.** The child starts with an empty environment plus the `--env` and
   `--file` variables. Without it, the child inherits secrit's environment.
4. **Masking** (S12, `mask.rs`). On when stdout or stderr is not a TTY, or when an agent
   is detected. Patterns per value: the raw bytes; standard and URL-safe base64, each with
   and without padding, at all three byte offsets with the unstable edge characters
   dropped; percent-encoding; the JSON-escaped form; lowercase hex. The replacement is
   `[secrit:NAME]`.
   - Streaming: hold back only the longest buffer suffix that is a proper prefix of some
     pattern. Flush the rest at once. Flush everything at EOF. Match leftmost-longest.
     This replaces the "longest − 1 bytes" tail of PLAN 4.5, which held prompts with no
     newline.
   - The matcher is hand-written over `Zeroizing<Vec<u8>>`. `aho-corasick` keeps buffers
     that secrit cannot wipe.
   - A value shorter than 4 bytes is not masked, with one warning.
5. **Process model.** A new `child::supervise` is its own state machine. It reuses only
   the scoped pipe pump and kill-then-reap from `child.rs`. It does not reuse the v0.1
   poll loop, because that loop treats a stop as fatal and a deferred signal as a reason
   to kill the child (PLAN 8.1 step 8). It has no deadline and no output cap.
   - CMD stays in secrit's process group, the foreground group. Terminal signals (INT,
     QUIT, TSTP) reach CMD and secrit together.
   - Wait: `waitid(EXITED | STOPPED | NOWAIT)` with a 25 ms poll. A stopped CMD is not an
     error and is never killed.
   - INT and QUIT: secrit records them and does not act. CMD decides what they mean.
   - TSTP (Ctrl-Z): CMD stops by itself. secrit ignores TSTP while it supervises. When the
     poll reports that CMD stopped, secrit stops itself with `raise(SIGSTOP)`, so the
     shell sees the whole job stop. After `fg`, secrit runs again, sends SIGCONT to CMD
     and resumes the poll.
   - TERM and HUP: forwarded to CMD; secrit keeps waiting.
   - `signals.rs` records the signal number with `register_usize` (V18).
   - Exit: CMD's exit code. When a signal ended CMD, secrit clears its pending-signal flag,
     restores that signal's default action and raises it with
     `emulate_default_handler`. The fallback is 128 + N. A pending INT does not turn
     CMD's normal exit into 130.
6. **`--no-mask`.** Refused under agent detection (Q5). Otherwise secrit calls
   `CommandExt::exec`, which is safe. The memfds stay open in the new image.
7. **Not Linux.** `run --file` exits 1 with `run --file needs memfd (Linux)`. `--env`
   works. `handoff.rs` (memfd) is `#[cfg(target_os = "linux")]`, because rustix builds
   `memfd_create` on Linux only.

Documented limits, also in the README list "does not protect against" (S13): `sudo` and
other programs that close every fd above 2 lose `--file` values. The open fd and `VAR`
pass to grandchildren. memfd pages can reach swap (T7). Masking covers stdout and stderr
only, and the child sees pipes, not a TTY. A same-uid process reads `--env` values from
`/proc/<pid>/environ` and `--file` values from `/proc/<pid>/fd/N`; masking does not cover
either (T42, T57).

### 7.2 `secrit generate` (S14)

```text
secrit generate NAME [--length N] [--charset alnum|alnum-symbols|hex|base64url] [--strict] [--bytes N] [--replace] [--allow-weak]
```

- Draws: rejection sampling from `getrandom::fill` into a `Zeroizing` buffer. The
  `passwords` crate is not used: it returns a plain `String`. The sampler is generic over
  a byte source (`FnMut(&mut [u8])`), so tests can feed fixed bytes.
- `--strict` classes: draw the whole value again until each class appears. Forced
  positions bias the result.
- Default: 32 `alnum` characters, about 190 bits.
- Under 128 bits is refused unless `--allow-weak`.
- `--bytes N` writes N random bytes. It needs a store with `binary_values` (S9).
- Output: `stored NAME (32 chars, ~190 bits)` on stderr. Never the value.
- `generate` goes through the write gate (4) and then `put`, like `store`.

### 7.3 Binary values (S9)

- `store --binary`: the piped bytes are kept exactly, up to 64 KiB. The UTF-8 and
  control-character rules (PLAN 7.2) do not apply. TTY input is refused: a binary value
  comes from a pipe or a file.
- `get --stdout` writes the raw bytes. The PLAN 4.2 rules for the output type stay.
- The reveal screen shows `NAME (N bytes, binary)` and the base64 text.
- `run --file` writes the raw bytes into the memfd. `run --env` refuses NUL.
- A store without `binary_values` refuses `--binary` with exit 3 and a pointer to a
  binary store (Q22).

## 8. Beyond NixOS

### 8.1 Install without Nix (S16)

- A `sops` (or `gpg`) found on `PATH` passes the same trust rule as a configured one.
  A failure exits 3. `doctor` shows the source of each tool: `baked`, `config` or `PATH`.
- Version-manager shims are refused, with a hint. A resolved path under `/mise/shims/`,
  `/.asdf/shims/` or `/aquaproj-aqua/bin/` passes the trust rule (the shim canonicalizes
  to a user-owned 0755 binary) but needs the real `HOME`, which secrit's child does not
  get. The message: `<path> is a version-manager shim; point tools.sops at the real
  binary (for example the output of 'mise which sops')`. The v0.1 test harness already
  refuses mise shims for the same reason (`tests/common/mod.rs` line 32).
- The `NotFound` hint names the Nix command and the package manager forms
  (`brew install sops age`, the distribution package, the release binary).
- The default age key path follows sops: the config value, then
  `$XDG_CONFIG_HOME/sops/age/keys.txt`, then the platform default
  (`~/.config/sops/age/keys.txt` on Linux, `~/Library/Application Support/sops/age/keys.txt`
  on macOS). `init` and `doctor` use one function for it.
- Release builds: cargo-dist 0.33 config for `x86_64-unknown-linux-musl`,
  `aarch64-unknown-linux-musl` and `aarch64-apple-darwin`. CI builds them on each pull
  request (`dist build --artifacts=local`). No workflow publishes anything until Q29.
  Runners: `ubuntu-latest` with `cargo-zigbuild` for both musl targets (no separate
  cross linker); `macos-latest` for `aarch64-apple-darwin`. The darwin artifact is
  optional until Q28 and Q34 are answered.
- `publish = false` stays in `Cargo.toml` for crates.io (Q17, Q29).
  `dist-workspace.toml` sets `dist = true` for the package, because cargo-dist otherwise
  inherits `publish = false` and builds nothing (V27).

### 8.2 macOS port (S17)

| File | Change |
|---|---|
| `lock.rs` | Linux (S16, non-Nix hosts often lack `XDG_RUNTIME_DIR`: `su -`, cron, containers): with no `XDG_RUNTIME_DIR`, fall back to `/run/user/<uid>` when it exists, is owned by the uid and has mode 0700. Otherwise keep the refusal, with a hint. macOS (S17): with no `XDG_RUNTIME_DIR`, use `$TMPDIR/secrit` only when `$TMPDIR` resolves under `/private/var/folders/` and is owned by the uid; it must pass `ensure_private_dir`. A lock path from an environment variable lets two processes with different values take different locks and lose an update (T9). That weakness exists with `XDG_RUNTIME_DIR` already; the README states it for both. |
| `harden.rs` | `set_dumpable_behavior` only on Linux. On macOS the step prints the existing warning; `PT_DENY_ATTACH` needs `unsafe` (Q14). |
| `backend/atomic.rs` | `fcntl_fullfsync` after `fsync` on Apple (V16). `renameat_with(NOREPLACE)` maps to `renameatx_np`. |
| `tty.rs` | The canonical line limit is a per-OS constant (Linux 4095; macOS `MAX_CANON` **[unverified: 1024]**). |
| `trust.rs` | No change: `/proc/sys/kernel/overflowuid` already falls back to 65534. |
| `child.rs` | No change: `waitid` with `NOWAIT` exists on Apple (V16, research). |
| tests | pty tests use BSD `script -q /dev/null …` on macOS. No-tty tests need `setsid`, which macOS lacks. Tests that read `/proc` (`tests/safety.rs` lines 143, 507-565; `tests/setup.rs` line 55) and the Secret Service tests are Linux-only too. Each such test or file carries `#[cfg(target_os = "linux")]`. |
| CI, flake | `testTools` becomes platform-conditional: util-linux, `dbus` and `gnome-keyring` on Linux only. Then `flake.nix` adds `aarch64-darwin` to the package and devShell systems. `checks` stay Linux-only. A `macos-latest` job runs fmt, clippy and nextest through `nix develop` only after Q28 and Q34 say a runner or a Mac exists. Without one, S17 and S18 are "compile-checked only" (10.2). |

## 9. Threat model changes

v0.1 rows T1 to T26 stay. New assets: the Secret Service collection, the GnuPG keyring,
the Keychain. New adversary: A6, a process that has the D-Bus session or the gpg-agent
socket of the user. It is a form of A2.

The README list "does not protect against" gains, each in the slice named: the write gate
bypasses of 4.4 (S1b); any same-uid process on the D-Bus session reads Secret Service
values, and replace or remove keeps no backup (S10); any process that can use the user's
gpg-agent reads pass entries (S11); `run` masking and `/proc` exposure (S13); the Keychain
trusts secrit itself (S18).

| # | Threat | Rule | Test |
|---|---|---|---|
| T27 | An agent changes the store with no owner action (Q13) | Write gate: typed name on `/dev/tty`; no tty refuses (4) | pty tests in 4.3; `no_tty()` refusals |
| T27a | An agent allocates a pty and unsets its variable, drives a pty and types the name, or edits the store with `sops` or `git` directly | Documented bypass (4.4, PLAN N1); README "does not protect against". Q33 asks whether more is needed. | `script -qc 'env -u CLAUDECODE secrit store n'` stores with no question (the test asserts the bypass) |
| T28 | Typed-ahead input answers the gate | `tcflush(TCIFLUSH)` before the prompt (4.2) | pty test writes the name before the prompt; refused |
| T29 | A same-uid process reads a Secret Service, pass or Keychain value (A6), or an agent runs `secrit get` after it passes the env and tty check | None; documented. `get` refusal is an accident guard on every backend; the Keychain ACL stops other programs only (5.2, 6.5, Q26) | `doctor` agent row text per backend; Keychain row says `secrit itself is trusted` |
| T30 | Secret Service value crosses the bus in cleartext | `EncryptionType::Dh` only; no `Plain` path in the code | Unit: the connect call uses `Dh`; a grep test finds no `Plain` |
| T31 | A forged `DBUS_SESSION_BUS_ADDRESS` sends values to a fake daemon | Address must be `unix:path=`, socket owned by the uid in a private directory; the connection uses the checked address only (6.3) | Address `tcp:`, a socket of another owner and a socket in sticky `/tmp` refused; the fixture daemon listens on `unix:path=<tempdir>/bus` |
| T32 | Duplicate items under `CreateOnly` | Search, create, search again under the lock (6.3) | 20 parallel `store` of one name: one item, 19 exit 3 |
| T33 | A locked collection opens a GUI prompt or hangs | `unlock = "refuse"` default; 120 s deadline (6.3) | Locked collection refused with `Locked` |
| T34 | pass entry written in place and torn by a crash | `FileStore` temp file, validate, rename (6.4) | SIGKILL at the hook before rename: original byte-identical |
| T35 | pass entry encrypted to the wrong keys | `--no-encrypt-to`; `--list-only --list-packets` subkey IDs compared with the resolved `.gpg-id` keys (6.4) | A changed `.gpg-id` in a subdirectory: the new entry uses it; a forged `-r` in a fake gpg is caught; `encrypt-to` in `gpg.conf` adds no recipient; a write with a passphrase key and `--pinentry-mode error` needs no pinentry |
| T36 | pass writes leak into git history by auto-commit | secrit never commits; prints the commands (N7, Q25) | `git status` shows the change uncommitted |
| T37 | gpg-agent opens a pinentry (GUI or terminal) that an agent-started `secrit` caused | `--pinentry-mode error` by default; `pinentry = "agent"` only with no agent and a tty (6.4) | Real gpg, passphrase key, nothing cached: `get` fails in under 5 s with the caching hint; `gpg-agent.conf` names a `pinentry-program` script that writes a marker file, and the marker is absent |
| T38 | Keychain ACL identity changes on each rebuild | Documented; `doctor` notes a non-signed binary (6.5) | Manual, macOS |
| T39 | macOS hardening is weaker (no `PR_SET_DUMPABLE`) | Warning row in `doctor`; documented (8.2) | macOS CI: the warning appears |
| T40 | `run` child leaks a value to output | Masking with encodings and offsets (7.1) | Child prints raw, base64 at 3 offsets, URL-safe, percent, JSON, hex: all masked; split across reads |
| T41 | `run` masking holds an interactive prompt | Prefix-hold algorithm (7.1) | Under `script` with `CLAUDECODE=1` (so masking is on), a prompt with no newline appears before the child reads; the test asserts that masking is active |
| T42 | `run --env` value read from `/proc/<pid>/environ`, `ps eww` or `docker inspect` | `--env` refused under agent detection (Q27); `--file` preferred; documented (PLAN T5) | `CLAUDECODE=1 secrit run --env V=n -- true` exits 3; `/proc/<child>/environ` holds only `/dev/fd/N` with `--file` |
| T43 | `run --file` value reaches a grandchild or swap | Documented (7.1) | None |
| T44 | `run` masking bypassed by an encoding secrit does not know | Documented: masking prevents accidents (PLAN 4.5) | None |
| T45 | `run` exit status hides a signal death | Re-raise the child's signal (7.1) | Child killed by SIGTERM: secrit ends by SIGTERM |
| T46 | `generate` produces a biased or weak value | Rejection sampling; 128-bit floor (7.2) | Deterministic: the rejection step over every input byte value 0-255 per charset gives each symbol equally often; one statistical test with a fixed-seed test-only RNG |
| T47 | `age_key_cmd` runs a hijacked program | Absolute path, trust rule, no shell (6.2) | Command in a group-writable directory refused |
| T47a | `age_key_cmd` hangs on a terminal prompt or fails in the cleared environment | Shorter deadline; `doctor` shebang check; documented environment (6.2) | A key command that reads `/dev/tty` ends within `age_key_cmd_timeout_secs`; a key command that needs `PATH` fails with the documented message |
| T48 | An age plugin found through a wide `PATH` | `PATH` is the one trusted plugin directory (6.2) | `age_plugin_dir` with a group-writable entry refused |
| T49 | A nested write silently turns a leaf into a map | Ancestors must be maps; tree diff (6.1.2) | `store a/b` when `a` is a string: exit 3, file unchanged |
| T50 | JSON or dotenv store rewritten in another format (V14) | Explicit types; strict reparse (6.1.2) | JSON store stays JSON; sops with `--input-type json` decrypts it |
| T51 | Cleartext through a regex rule | v0.1 refusal of regex-rule files stays (6.1.3; S7 deferred) | Existing v0.1 test |
| T52 | A sops on `PATH` that is not trusted gets plaintext on stdin | Trust rule for `PATH` tools (8.1) | `sops` in a group-writable `PATH` directory refused |
| T53 | A binary store replace changes recipients | Recipient compare with the old file (6.1.4) | Changed `.sops.yaml` rule: replace refused |
| T54 | A `test-hooks` build reaches a user | `--version` shows it and `doctor` warns (4.3); release profile has no features | Flake check `release-features`: the package derivation's `--version` has no `test-hooks`; `doctor` shows a `warn` `build` row under `--all-features` |
| T55 | `store --replace` or `rm` on a daemon backend destroys the old value with no backup (PLAN T12 and README "Old values" do not hold there) | `no backup; the old value is gone`, plus a `y` on `/dev/tty` or `--yes`, even for the owner (5.2, Q37) | Secret Service: `store --replace` with no tty and no `--yes` exits 3, value unchanged |
| T56 | Copies of a value stay unwiped outside secrit's buffers: zbus messages, `secret-service` AES-CBC buffers, macOS `CFData`, gpg's memory | Documented; secrit wipes its own copies at once (6.3, 6.5) | None |
| T57 | `run` exposes values outside masking: `/proc/<pid>/environ` (`--env`), `/proc/<pid>/fd/N` (`--file`), unknown encodings | Documented in the README list (7.1); `--env` refused under agents (Q27) | T42 tests |
| T58 | A dotenv name with the `sops_` prefix is read back as metadata | `check_put` refuses the prefix (5.4) | `store sops_x` on a dotenv store exits 3 before input |

## 10. Tests and gates

### 10.1 Harness

- `tests/common/` splits into `env.rs` (dirs, `cmd()`, pty helpers), `fixture.rs` (trait
  `Fixture { new; config_section; read_back; names }`) and `conformance.rs`.
- The conformance suite runs on every backend: round trip; create-only, replace and
  backups (when the capability says so); `rm`; `ls` that never decrypts; the argv canary
  (PLAN T1); the stderr canary (T8); agent refusal of `get`; the write gate (T27).
- One file per backend: `tests/backend_sops.rs`, `backend_secret_service.rs` (with
  `#![cfg(target_os = "linux")]`), `backend_pass.rs`, `backend_keychain.rs` (with
  `#![cfg(target_os = "macos")]`).
- A test whose tool is missing fails loudly, as `script` does in v0.1. It never skips.
  A test that cannot exist on a platform is compiled out with `cfg`, not skipped.
- `flake.nix` `testTools` gains `dbus`, `gnome-keyring` (S10, Linux only), `gnupg`, `pass`
  and `gopass` (S11).

### 10.2 Gates for every slice

```sh
nix develop -c cargo fmt --all --check
nix develop -c cargo clippy --all-targets --all-features --locked -- -D warnings
nix develop -c cargo clippy --all-targets --locked -- -D warnings
nix develop -c cargo nextest run --all-features --locked
nix develop -c cargo deny check
nix flake check -L
```

From S1a, one more gate catches macOS cfg errors without a Mac:

```sh
cargo clippy --all-targets --all-features --locked --target aarch64-apple-darwin -- -D warnings
```

`clippy` does not link, so it needs no Apple SDK. It does need the `std` of that target.
The devShell's nixpkgs rustc has none (V28), so this gate runs as a separate CI job with
`rustup target add aarch64-apple-darwin` at the pinned 1.98.1 **[unverified until S1a:
that no dependency's build script needs the Apple SDK]**. If a build script needs it, the
job uses `cargo check` on the crate only and S1a records the gap.

`checks.nextest` in `flake.nix` excludes the Secret Service tests with a nextest filter
(`-E 'not binary(backend_secret_service)'`) if lab V24 fails in the Nix sandbox (S10).
The CI `cargo` job always runs them.

A new `include_str!` of a non-cargo file goes into the `fileset` of `flake.nix`. The macOS
CI job becomes a gate only when Q28 and Q34 provide a runner. Until then, macOS work is
"compile-checked only".

## 11. Changes to v0.1 text

| PLAN section | Change |
|---|---|
| 6.1 | `list` returns raw strings; the trait in 5.1 replaces it. |
| 6.3 | "needs no async runtime" is wrong (6.3). |
| 7.3 | Names become key paths (5.4). |
| 8.3 | The write gate (4) replaces "`store`, `rm --yes` … work". |
| 4.5 | The tail-buffer rule changes to the prefix-hold rule (7.1). |
| 8.2 | Key sources (6.2). |
| 10.2 | `PATH` tools are trust-checked (8.1). |
| 13 (T12) | Backups exist only on backends with `backups` (T55). |
| 8.1 step 8 | The stop and deferred-signal rules apply to sops runs, not to `run` (7.1 step 5). |
| 20 | Q13 answered: (b). |

Each slice updates the v0.1 text that it changes.

## 12. Slices

Each slice is one stacked pull request on top of the slice before it in this list,
unless section 13 lets it start earlier. Each passes every gate of 10.2, adds a
`CHANGELOG.md` entry under `[Unreleased]`, and updates the README section that it
changes.

### S0. Hotfix on PR #2: refuse a non-YAML store

- **Goal:** stop the V14 corruption before v0.2 starts. Land on `feat/mvp-gaps` (Q31).
- **Files:** `src/backend/sops.rs` (`parse_doc`: refuse a file that `serde_json` parses
  as an object; refuse a `.json`, `.env` or `.ini` extension), `tests/safety.rs`,
  `CHANGELOG.md`.
- **Tests:** a JSON sops store: `store` exits 3 and the file is byte-identical; `ls` works.
- **Acceptance:** the lab5 case from V14 fails safely.
- **Risks:** a YAML file in flow style (`{...}`) also parses as JSON. sops never writes
  YAML in flow style, so the risk is a hand-made file only.

### S1a. Trait, config and error refactor (no behaviour change)

- **Goal:** the trait items of S1a in 5.1, the config enum, the factory, generic errors
  and `Target` (5.3), and the hook code in `testhook.rs`. No behaviour change.
- **Files:** `src/config.rs`, `src/backend/mod.rs`, `src/backend/sops.rs` (errors,
  `Target`, hooks moved), `src/testhook.rs` (new), `src/cmd/mod.rs`, `src/cmd/doctor.rs`
  (factory), `src/cmd/init.rs` and `src/cmd/wire.rs` (config enum), `src/main.rs`
  (`mod testhook`), `.github/workflows/ci.yml` (darwin clippy job, 10.2), `CHANGELOG.md`.
- **Tests:** config: every v0.1 config of the test suite parses to the same
  `StoreConfig`; unknown key per variant; `.ini` refused. A golden test on every error
  `Display` string. All 76 existing tests pass with no edit.
- **Acceptance:** all gates of 10.2, the darwin clippy job included; `git diff` of
  `tests/` is empty except the golden test.
- **Risks:** serde `deny_unknown_fields` with a tagged enum (unit test per variant). A
  dependency build script that needs the Apple SDK breaks the darwin job (10.2).

### S1b. Write gate (Q13)

- **Goal:** Q13(b) in force (section 4).
- **Files:** `src/agent.rs`, `src/tty.rs`, `src/testhook.rs` (`SECRIT_TEST_GATE`),
  `src/cmd/store.rs`, `src/cmd/rm.rs` (new no-tty message), `src/cmd/init.rs` (gate),
  `src/cmd/doctor.rs` (agent row, `build` warn row), `src/tools.rs` (`--version` feature
  line), `flake.nix` (check `release-features`), `tests/common/mod.rs`
  (`SECRIT_TEST_GATE=allow` in `cmd()`), `tests/tty.rs`, `tests/setup.rs` (the `rm` twin),
  `README.md` (4.4 list), `docs/PLAN.md` (8.3, Q11), `CHANGELOG.md`. The five tests that set
  `SECRIT_TEST_HOOK` (V28) need no edit, because the gate bypass is a separate variable.
- **Tests:** unit: `write_gate` matrix; `confirm_typed` comparison. Integration: the pty
  and no-tty cases of 4.3, T27a. All 76 existing tests pass with `SECRIT_TEST_GATE=allow`,
  and their expected output is unchanged. `doctor_passes_on_a_good_setup` passes under
  `--all-features` (the `build` row is `warn`).
  `rm_of_a_missing_name_fails_and_needs_yes_without_tty` gets a twin without the bypass
  that expects exit 3 and the new message.
- **Acceptance:** `printf v | CLAUDECODE=1 secrit store n` with no tty exits 3. Under
  `script`, typing `n` stores it. `nix flake check` runs `release-features`.
- **Risks:** waits for the owner to confirm the ruling, Q19 and Q33 (section 15). No
  other slice waits for S1b except S14 (`generate` calls the gate).

### S2. Backend conformance harness

- **Goal:** the shared test suite of 10.1, run against sops.
- **Files:** `tests/common/{mod.rs, env.rs, fixture.rs, conformance.rs}`,
  `tests/backend_sops.rs` (new). No `src/` change.
- **Tests:** the conformance cases, on sops. The write-gate case (T27) joins the suite in
  whichever of S1b and S2 merges second.
- **Acceptance:** the suite passes on sops; one case per capability that sops reads.
- **Risks:** duplicate coverage with `tests/cli.rs`. Move a case only when the
  conformance version asserts the same thing.

### S3. Split the sops module

- **Goal:** `backend/atomic.rs` (`FileStore`, `FileEdit`) and `backend/sops/{mod.rs,
  runner.rs, format.rs (Yaml only), edit.rs, doctor.rs}`. `FileEdit::temp_ext` sets the
  temp suffix, so later formats do not touch `atomic.rs`. `create_new_noreplace` and the
  fsync helpers move into `atomic.rs`, and the default age key path moves into a new
  `paths.rs`, so the macOS port (S17) changes only those two files. `atomic.rs` also
  gains `FileStore::create_new` and `FileStore::backup` (5.5) now, so S9 and S11 do not
  change it. Each has a reader in S3, so neither is dead code: `init` creates the store
  file through `create_new`, and sops `store --replace` and `rm` make their v0.1 backup
  through `backup` (same behaviour). `sops/runner.rs` takes a per-call stdout cap,
  which S9 uses (6.1.4). No behaviour change.
- **Files:** `src/backend/sops.rs` (removed), the new files, `src/paths.rs` (new),
  `src/backend/mod.rs`, `src/cmd/doctor.rs` (sops rows move out), `src/cmd/mod.rs`
  (`temp_sample` asks the backend), `src/cmd/init.rs` (calls `atomic.rs` and `paths.rs`).
- **Tests:** existing tests unchanged; a golden test that `doctor --json` gives the same
  rows in the same order as before the split.
- **Acceptance:** `git diff --stat` shows moves; all gates pass with no test edit.
- **Risks:** a 1720-line move hides a change. Review with `git diff -M --color-moved`.

### S4. sops JSON format and format selection

- **Goal:** 5.5 with `Yaml` and `Json`; the `format` key; strict JSON validation. Replaces
  the S0 refusal for JSON.
- **Files:** `src/backend/sops/{format.rs, edit.rs, runner.rs, doctor.rs}`,
  `src/config.rs` (sops `format`), `src/cmd/init.rs` (`--format`), `src/cmd/wire.rs`
  (`format` literal), `tests/backend_sops.rs`.
- **Tests:** JSON round trip; the result parses with `serde_json`; sops with
  `--input-type json` decrypts; `init --format json` creates a JSON store; wire prints
  `format = "json"`; YAML stores unchanged.
- **Acceptance:** T50 passes for JSON.
- **Risks:** `TEMP_IGNORE` and the `.gitignore` hint change for users who added the v0.1
  pattern; `doctor` warns when the new pattern is not ignored.

### S5. Nested keys (YAML, JSON)

- **Goal:** 5.4 and the tree validation of 6.1.2.
- **Files:** `src/name.rs`, `src/backend/sops/{edit.rs, format.rs, mod.rs}`,
  `src/cmd/ls.rs`, `src/cmd/wire.rs` (`key`, path), `tests/backend_sops.rs`.
- **Tests:** unit: segment grammar, 8 segments, 255 bytes, `sops` reserved as the first
  segment only (`app/sops` is valid), suffix rules on each segment. Integration: `store a/b/c`; `ls` prints
  `a/b/c`; `store a/b` over a string `a` refused (T49); `rm a/b/c` prunes empty maps;
  wire prints `key = "a/b/c"`.
- **Acceptance:** sops-nix reads a nested key from a secrit-written file (flake check
  with a NixOS VM test is out of scope; `sops decrypt --extract '["a"]["b"]["c"]'` stands
  in).
- **Risks:** a v0.1 file with a nested map now lists its leaves, not the parent name.
  This changes `ls` output for such files; the CHANGELOG says so.

### S6. dotenv format

- **Goal:** `SopsFormat::Dotenv` with the env-name grammar.
- **Files:** `src/backend/sops/{format.rs, edit.rs}`, `src/name.rs` (dotenv check),
  `src/cmd/init.rs`, `tests/backend_sops.rs`.
- **Tests:** round trip of the 14 tricky strings of V11; `store a.b` refused; `store
  sops_x` exits 3 before input (unit and integration, T58); the metadata unflattening on a
  file with two recipients and `sops_unencrypted_suffix`.
- **Acceptance:** `sops exec-env` on the written file exports the value.
- **Risks:** `init` creating an empty dotenv file through `encrypt` of `{}`
  **[unverified]**: lab it first.

### S6b. INI format

- **Goal:** `SopsFormat::Ini` (6.1.1, 6.1.2), names `section/key` (5.4).
- **Files:** `src/backend/sops/{format.rs, edit.rs}`, `src/name.rs` (INI check),
  `src/cmd/init.rs` (`--format ini`), `tests/backend_sops.rs`.
- **Tests:** round trip in two sections; `store k` (one segment) and `store a/b/c`
  refused; `store sops/k` refused; the `[sops]` section unchanged except `mac` and
  `lastmodified`; every other line byte-equal.
- **Acceptance:** `sops decrypt --input-type ini --extract '["s"]["k"]'` gives the value.
- **Risks:** `sops set` on an INI file with a nested path **[unverified]**: lab it first
  (V11 covers top-level `set` only). If sops refuses it, S6b stops and Q36 goes back to
  the owner.

### S7. Canary probe for regex rules: deferred

Deferred with Q23 (2.2, 6.1.3). The v0.1 refusal stays. No pull request this round.

### S8. sops key sources

- **Goal:** 6.2: `age_ssh_key_file`, `age_key_cmd`, `age_plugin_dir`.
- **Files:** `src/backend/sops/runner.rs` (environment, deadline, `ToolPrompt` hint),
  `src/backend/sops/doctor.rs`, `src/config.rs` (sops keys), `src/trust.rs` (executable and directory
  checks), `tests/backend_sops.rs`, `README.md` ("Keys", key-command wrapper). Not
  `src/backend/mod.rs`: the prompt text is the `ToolPrompt` hint (5.3).
- **Tests:** an unencrypted ed25519 key from `ssh-keygen` as the only recipient: round
  trip. The v0.1 decoy passphrase key as `age_ssh_key_file`: fails fast (T19 style).
  `age_key_cmd` script with an absolute shebang that prints the test age key: round trip;
  a counter file shows the run count. A key command with `#!/usr/bin/env sh` that calls a
  bare `cat`: fails with the documented environment message, and `doctor` warns (T47a).
  A key command that reads `/dev/tty`: ends within `age_key_cmd_timeout_secs = 3` (T47a).
  Group-writable command refused (T47). Plugin dir: unit test of the environment; a
  group-writable entry refused (T48).
- **Acceptance:** Q18 default is implemented; T47 and T48 pass.
- **Risks:** no real plugin in CI. A YubiKey check is manual and listed in the PR body.

### S9. Binary values and the binary store

- **Goal:** 6.1.4 and 7.3.
- **Files:** `src/backend/sops/{dir.rs (new), format.rs, mod.rs, runner.rs (encrypt
  cap)}`, `src/backend/mod.rs` (`ValueKind`, `binary_values`), `src/secret.rs` (binary
  read path), `src/cmd/store.rs`, `src/cmd/get.rs`, `src/display.rs` (binary reveal),
  `src/cli.rs` (`--binary`), `src/config.rs` (`dir`), `src/cmd/init.rs`,
  `src/cmd/wire.rs`, `tests/backend_sops.rs`, `tests/tty.rs`. It uses
  `FileStore::create_new` and `backup` from S3 and does not change `atomic.rs`.
- **Tests:** exactly 65 536 random bytes with NUL: round trip byte-exact, and the
  encrypt step passes the per-step cap (6.1.4); `get --stdout` to a pipe; reveal shows
  base64 under `script`; `--binary` on a YAML store exits 3; replace with changed
  recipients refused (T53); create needs a rule; the gate prompt lists the recipients.
- **Acceptance:** `sops decrypt --input-type binary --output-type binary` on the file
  gives the bytes.
- **Risks:** `encrypt --input-type binary /dev/stdin` behaviour **[unverified]**: lab it
  first (V12 covers the no-type case only).

### S10. Secret Service backend

- **Goal:** 6.3.
- **Before code:** lab V24 in the Nix sandbox (a throwaway `runCommand` that starts the
  fixture daemons). Its result picks the acceptance text below.
- **Files:** `Cargo.toml` (`secret-service`, `zbus`), `Cargo.lock`,
  `src/backend/secret_service.rs` (new), `src/backend/mod.rs` (factory arm, `Daemon` and
  `Locked` variants, `WireSource::Opaque`, `Location::Collection`), `src/config.rs`
  (variant), `src/cmd/init.rs` (arm), `tests/common/fixture_secret_service.rs` (new),
  `tests/backend_secret_service.rs` (new, Linux only), `flake.nix` (`testTools`; nextest
  filter if the lab fails), `README.md` (backend section; "does not protect against":
  same-uid D-Bus readers, no backup on replace and rm).
- **Tests:** unit: attribute set, bus address rule (T31), `Dh` only (T30). Integration
  under a per-test `dbus-daemon --session --address=unix:path=<tempdir>/bus` and
  `gnome-keyring-daemon --login` with a temp `XDG_DATA_HOME`: conformance suite; T32 with
  20 writers; locked collection (T33); T55 (no backup, confirmation); a signal during a
  blocked D-Bus call exits 130 and releases the lock; `secret-tool lookup secrit-name n`
  reads a secrit-written value.
- **Acceptance:** if the lab passes, conformance passes in `nix flake check` and in CI.
  If it fails, conformance passes in the CI `cargo` job, and `checks.nextest` excludes the
  binary with `-E 'not binary(backend_secret_service)'` (10.2). The PR body says which.
- **Risks:** the blocking `connect_with_existing` signature and zbus version (6.3).
  Dependency count (+96 crates): `cargo deny` must pass.

### S11. pass layout backend

- **Goal:** 6.4.
- **Files:** `src/backend/pass.rs` (new), `src/backend/mod.rs` (arm), `src/config.rs`
  (variant, `tools.gpg`), `src/tools.rs` (gpg, baked and config sources only),
  `src/cmd/init.rs` (arm), `tests/common/fixture_pass.rs` (new), `tests/backend_pass.rs`
  (new), `flake.nix` (`gnupg`, `pass`, `gopass` for interop), `README.md` (backend
  section; "does not protect against": any process that can use the gpg-agent reads
  entries). It uses `FileStore::create_new` and `backup` from S3 and does not change
  `atomic.rs`.
- **Tests:** temp `GNUPGHOME` with `--quick-gen-key`. Conformance suite; T34 (SIGKILL
  hook); T35 (`.gpg-id` in a subdirectory, `encrypt-to` in `gpg.conf`, a passphrase key
  with `--pinentry-mode error`: the write needs no pinentry); T36 (no commit); T37 (real
  gpg, passphrase key, fast failure, no pinentry marker). Exact bytes both ways with pass
  1.7.4: `pass insert` of `pw` reads back as `pw`; `pass insert -m` of `pw\nlogin: a\n`
  reads back as `pw\nlogin: a` (whole) and `pw` (`first-line`); a secrit-written `pw`
  shows as `pw` in `pass show` and copies as `pw` with the first-line rule. The same
  cases against a gopass store (`gpgcli`, `fs`). `.gpg-id.sig` refuses writes.
- **Acceptance:** interop both ways with pass 1.7.4 and gopass, exact bytes as above.
- **Risks:** gpg-agent socket location with a cleared environment **[unverified]**; the
  fixture starts its own agent with `gpgconf --launch`. gopass setup without a network
  or a git remote **[unverified]**: lab it first.

### S12. Masking library

- **Goal:** `src/mask.rs` of 7.1 step 4, not yet used by a command.
- **Files:** `src/mask.rs` (new), `src/main.rs` (`mod mask`), `Cargo.toml` (`base64`, if
  used; check the version on crates.io first).
- **Tests:** unit: every encoding; matches split at every byte boundary; leftmost-longest
  with overlapping values; prefix-hold flushes a non-matching prompt at once; EOF flush;
  buffers are `Zeroizing`; under-4-byte warning.
- **Acceptance:** a property test over random splits gives the same output as a one-shot
  replace.
- **Risks:** `#[expect(dead_code)]` on the module's public items until S13, which removes
  it. This is the one cross-slice `expect` in the plan. Its items all gain a reader in
  S13 at once, so `unfulfilled_lint_expectations` cannot fire on a partial use.

### S13. `run`

- **Goal:** 7.1 steps 1 to 7.
- **Files:** `src/cmd/run.rs` (new), `src/handoff.rs` (new, memfd), `src/child.rs`
  (`supervise`, shared parts), `src/signals.rs` (signal number), `src/cli.rs`,
  `src/main.rs`, `src/cmd/mod.rs`, `tests/run.rs` (new), `README.md` (`run` section;
  "does not protect against": masking limits and `/proc` exposure, T57).
  `handoff.rs` is `#[cfg(target_os = "linux")]`.
- **Tests:** `run --file V=n -- cat` path read twice; `/proc/<child>/environ` holds the
  path only (T42); seals present; `--env`; `CLAUDECODE=1` with `--env` exits 3 and with
  `--file` runs (Q27); `--pristine`; masking of a child that prints the value (T40);
  interactive prompt under `script` with `CLAUDECODE=1`, masking asserted active (T41);
  exit code and signal re-raise (T45); under `script`: Ctrl-C to a child that traps INT
  and exits 0 gives exit 0, not 130; Ctrl-Z stops the job and `fg` resumes CMD, which
  then completes (7.1 step 5); `--no-mask` refused under `CLAUDECODE`; `--no-mask`
  replaces the process (the pid of CMD equals secrit's pid).
- **Acceptance:** T4 (run part), T5, T40 to T45 and T57 pass.
- **Risks:** pty tests of Ctrl-C and Ctrl-Z are timing-sensitive; the child writes a ready
  marker before the test sends the key.

### S14. `generate`

- **Goal:** 7.2.
- **Files:** `src/cmd/generate.rs` (new), `src/gen.rs` (new), `src/cli.rs`, `src/main.rs`,
  `src/cmd/mod.rs`, `tests/generate.rs` (new), `README.md`.
- **Tests:** unit: the deterministic bias test over every byte value (T46), one
  fixed-seed statistical test, entropy arithmetic, `--strict`; integration: value never in
  stdout or stderr; gate applies; `--bytes` on a binary store; weak refused.
- **Acceptance:** `generate n` then `get --stdout n | wc -c` gives 32.
- **Risks:** none known.

### S15. Wire targets

- **Goal:** 5.7.
- **Files:** `src/cmd/wire.rs` becomes `src/wire/{mod.rs, nix.rs, hm.rs, env.rs,
  systemd.rs, compose.rs, k8s.rs, dotenv.rs}`, `src/cli.rs` (`WireFormat`),
  `src/cmd/mod.rs`, `tests/wire.rs` (new; wire cases move from `tests/setup.rs`),
  `README.md`.
- **Tests:** exact stdout per format; `Opaque` backend with `nix` exits 3; shell quoting
  of every printed name and path; nested name and binary store stanzas; `a/b` gives
  `A_B_FILE=/run/secrets/a/b` and `LoadCredential=a_b:/run/secrets/a/b`; a store with
  `a/b` and `a_b` exits 3 for `env` and `systemd` and names both; `dotenv` on a dotenv
  store prints `sops exec-env`, on any other store a `secrit run --env` line.
- **Acceptance:** each printed command runs as printed in a lab (manual for `kubectl`
  and `docker compose`, listed in the PR body).
- **Risks:** `systemd-creds --user` paths depend on the systemd version (V19).

### S16. Install without Nix and release builds

- **Goal:** 8.1.
- **Files:** `src/tools.rs` (`PATH` trust for every tool, `gpg` included; shim refusal;
  the `NotFound` hint that `init` prints), `src/trust.rs`, `src/lock.rs` (Linux
  `/run/user/<uid>` fallback, 8.2), `src/cmd/doctor.rs` (tool source rows),
  `dist-workspace.toml` (new, `dist = true`), `.github/workflows/ci.yml` (dist build job:
  `cargo-zigbuild` for musl; darwin optional), `tests/tools.rs` (new), `README.md`.
- **Tests:** a `sops` in a group-writable `PATH` directory refused (T52); a `gpg` the
  same; a `sops` under a `mise/shims` directory refused with the hint; `doctor` shows
  `PATH`; hint text; lock fallback to `/run/user/<uid>` and its refusal when the mode is
  not 0700 (unit, with an injected directory).
- **Acceptance:** `dist build` produces both musl artifacts in CI, and the x86_64 one runs
  `secrit --version` on a non-Nix container image.
- **Risks:** the musl build with `secret-service` (pure-Rust crypto) **[unverified]**.

### S17. macOS port

- **Goal:** 8.2.
- **Before code:** ask Q34 (does a Mac or a macOS runner exist?).
- **Files:** `src/lock.rs` (macOS fallback), `src/harden.rs`, `src/tty.rs`,
  `src/backend/atomic.rs` (`F_FULLFSYNC`), `src/paths.rs` (macOS default key path),
  `tests/common/env.rs` (BSD `script`), `tests/safety.rs` and `tests/setup.rs` (`cfg` on
  the `/proc` and `setsid` tests), `flake.nix` (platform-conditional `testTools`, then
  systems), `.github/workflows/ci.yml` (macOS job, only with Q34 yes), `README.md`.
- **Tests:** lock fallback unit test; `F_FULLFSYNC` call under `cfg`; with a runner, the
  existing suite on macOS minus the Linux-only tests.
- **Acceptance:** with a runner or a Mac: the macOS job passes. Without one: the darwin
  clippy gate passes and `nix flake show` evaluates `aarch64-darwin`; the slice and the
  README say "compile-checked only".
- **Risks:** macOS runner cost on a private repository (Q28); `MAX_CANON` value.

### S18. macOS Keychain backend

- **Goal:** 6.5.
- **Files:** `Cargo.toml` (target dependency), `src/backend/keychain.rs` (new),
  `src/backend/mod.rs` (arm), `src/config.rs` (variant), `src/cmd/init.rs` (arm),
  `tests/common/fixture_keychain.rs` (new), `tests/backend_keychain.rs` (new, macOS
  only), `.github/workflows/ci.yml` (temp keychain steps), `README.md` (backend section;
  "does not protect against": the Keychain trusts secrit itself, T29). `Location::Keychain`
  is `cfg(target_os = "macos")`.
- **Tests:** conformance on a temp keychain (V23 recipe); `CreateOnly` duplicate refused;
  T55 (no backup, confirmation); the doctor row text.
- **Acceptance:** with a runner or a Mac: conformance passes there. Without one: the
  darwin clippy gate passes, and the backend ships marked "compile-checked only, not
  tested", or waits, as the owner rules on Q34.
- **Risks:** a dialog hangs the runner (V23); every Keychain test has a 60 s limit.

### S19. v0.2.0

- **Goal:** release state.
- **Files:** `Cargo.toml` (`version = "0.2.0"`), `Cargo.lock`, `CHANGELOG.md` (release
  section), `README.md` ("What works"), `docs/PLAN.md` (M6 row), `docs/PLAN-v0.2.md`
  (status), `SECURITY.md` (new backends).
- **Tests:** a check that every threat row T27 to T58 with a test names an existing test.
- **Acceptance:** all gates on Linux, the darwin clippy gate, and the macOS job if Q34
  provides one; the owner trial of `run` and Secret Service on the owner's machine.
- **Risks:** none known.

## 13. Order and parallel work

**Registration points.** Some files gain one line or one block per slice: `Cargo.toml`,
`Cargo.lock`, `CHANGELOG.md`, `README.md` (each slice its own section), `src/main.rs` and
`src/cmd/mod.rs` (`mod` lines), `src/cli.rs` (one subcommand or flag), `src/config.rs`
(one enum variant or field), `src/backend/mod.rs` (one factory arm, plus the enum
variants that the slice first returns, 5.1), `src/cmd/init.rs` (one `--backend` arm),
`flake.nix` (`testTools` entries, one check), `.github/workflows/ci.yml` (one job) and
`tests/backend_sops.rs` (new test functions only). Two parallel slices may both add lines
there. The second one to merge restacks and keeps both lines.

Any other edit to those files is not a registration: the `init.rs` gate (S1b) and
`--format` (S4, S6, S6b, S9), the `testTools` restructure (S17), and the `tests/common`
split (S2). "Parallel-safe" below means: no shared file outside registration lines, and
no dependency either way.

| Slice | Starts after | Parallel-safe with |
|---|---|---|
| S0 | PR #2 | — (lands on PR #2) |
| S1a | S0 | — |
| S1b | S1a; merges only after the owner confirms (section 15) | S5, S8, S10, S11, S12, S13 |
| S2 | S1a | S3, S12, S13 |
| S3 | S1a | S2, S12, S13 |
| S4 | S2, S3 | S10, S11, S12, S13 |
| S5 | S4 | S1b, S8, S10, S11, S12, S13 |
| S6 | S5 | S8, S10, S11, S13 |
| S6b | S6 | S8, S10, S11, S13 |
| S8 | S4 | S1b, S5, S6, S6b, S10, S11, S12, S13 |
| S9 | S6b, S8 | S10, S11, S13, S16 |
| S10 | S2, S3 | S1b, S4 to S9, S11, S12, S13, S14, S16 |
| S11 | S2, S3 | S1b, S4 to S9, S10, S12, S13, S14 |
| S12 | S1a | every slice except S0, S1a, S13 (which needs it) and S19 |
| S13 | S12 | S1b, S2 to S11, S14, S16, S17 |
| S14 | S1b, S9 | S10, S11, S13, S15, S16, S17 |
| S15 | S6, S9, S13 | S10, S11, S14, S16, S18 |
| S16 | S3, S8, S11 | S9, S10, S13, S14, S15 |
| S17 | S2, S3, S16 | S13, S14 (not S1b: `tty.rs`, `tests/setup.rs`; not S10: `testTools`; not S15: `tests/setup.rs`) |
| S18 | S17 | S15 |
| S19 | all | — |

Suggested waves for implementer agents (one slice per agent, each in its own worktree):

1. S0, then S1a.
2. S1b (opened; it waits for the owner), S2, S3, S12.
3. S4, S10, S11, S13.
4. S5 and S8, then S6, then S6b.
5. S9, S16.
6. S14 (when S1b has merged), S17.
7. S15, S18.
8. S19.

Slices that share `src/backend/sops/edit.rs`, `format.rs` or `runner.rs` (S4, S5, S6,
S6b, S9) stay in sequence; S8 shares only `runner.rs` and `doctor.rs` with S4 and S9, so
it runs beside S5 to S6b. The stack order for review is S0, S1a, S2, S3, S4, S5, S6, S6b,
S8, S9, S10 to S19. S1b sits beside the stack on S1a. When the owner confirms the ruling,
S1b rebases onto the current tip and merges; S14 waits for it. A slice that started early
rebases onto its predecessor in the review order before review.

## 14. Open questions for the owner

Owner answers of 2026-10-08 [ruled-by: w0wl0lxd; recorded-by: lead session dc2a06ae;
source: answers to questions in that session]:

- Q13: (b) is confirmed in the owner's own answer.
- Q19 and Q33: not decided. The owner asked for research on a secure gate with good UX,
  including a secrit store with its own sops identity, kept apart from the main sops
  setup, with the gate on that identity. S1b waits for that research and a new ruling.
- Q29: build only. CI builds release artifacts; nothing is published until the owner
  says so at v0.2.0.
- Q17: done. The repository was recreated public on 2026-10-08 from a history with the
  machine-specific text replaced. Q28 and Q34: GitHub-hosted macOS runners are free on a
  public repository, so S17 and S18 get a macOS CI job once GitHub Actions runs again.

Q1 to Q12 and Q14 to Q17 of PLAN 20 stay open as written. Q13 is answered (b). Q18: this
plan implements its stated default (an explicit `age_ssh_key_file`), so no new ruling is
needed unless the owner objects.

| # | Question | Assumed default | Why |
|---|---|---|---|
| Q19 | The Q13(b) ruling refuses `store` and `rm` with no `/dev/tty`. That also stops cron, systemd units and CI, which are not agents. Is that intended? | Yes, as ruled. No exception: secrit cannot tell cron from an agent with no terminal, and any exception variable can be set by an agent. | The ruling names the no-tty case. |
| Q20 | What must the user type at the gate: the name, or `y`? | The name. | A reflexive `y` is too easy. |
| Q21 | Which commands does the gate cover? | `store`, `rm`, `generate` and the write steps of `init`. | The ruling names `store` and `rm`; `generate` is a `store`. `init` never overwrites a file, but under the Q1 default it creates files under `/etc/nixos`: the store file, the age key and, with `--write-sops-config`, `.sops.yaml`, which decides the recipients of later creates. |
| Q22 | Binary values: (a) base64 inside a YAML store with a marker, or (b) one sops binary file per name? | (b) only, this round. (a) waits. | sops-nix `format = "binary"` gives the raw bytes. (a) gives base64 text to every consumer and needs a marker key in cleartext. |
| Q23 | May secrit write a file that holds plaintext by design (a Kubernetes manifest with `encrypted_regex: ^(data\|stringData)$`)? | No. The every-leaf-encrypted rule of PLAN 8.1 step 9 stays. | Relaxing it lets a rule mistake store a value in cleartext. |
| Q24 | May sops get the foreground terminal (`tcsetpgrp`) for a passphrase key or a plugin PIN prompt? | No. Only unencrypted SSH keys, touch-only or cached-PIN plugins. | A foreground child receives Ctrl-C and terminal signals directly, which the v0.1 signal design avoids. |
| Q25 | Is the pass backend acceptable as "secrit writes the pass layout through gpg, never runs `pass`, never commits"? | Yes. secrit prints the git commands. | `pass` writes in place with no lock and auto-commits, which conflicts with crash safety and N7. |
| Q26 | On Secret Service and pass, any same-uid process can read values. Does `get` stay refused under agent detection there? | Yes, for one rule on every backend. The docs say it is an accident guard only. | Consistency; the agent transcript risk is the same. |
| Q27 | May `run --env` run under agent detection? | No. Under agent detection `--env` exits 3; `--file` runs, with masking forced. | An env value is readable without masking through `ps eww`, `/proc/<pid>/environ` and `docker inspect`, common agent debugging steps. That weakens T4 (get refused for agents). A `--file` value needs a deliberate `/proc/<pid>/fd/N` read (T57). |
| Q28 | macOS CI runs cost more on a private repository. Run the macOS job on every pull request? | Yes, from S17 on, if Q34 says a runner is available. | A port without a gate decays. |
| Q29 | When may release artifacts and a crates.io package be published? | Not until Q17 is done. CI builds artifacts and keeps them as workflow artifacts. | Q17: the plan text holds machine-specific facts. |
| Q30 | A locked Secret Service collection: refuse, or ask the daemon to unlock (a GUI prompt)? | Refuse by default. `unlock = "prompt"` in config opts in. | A GUI prompt from a CLI is a surprise, and it can hang a headless session. |
| Q31 | Land the S0 guard on PR #2 before it merges? | Yes. | v0.1 corrupts a JSON store today (V14). |
| Q32 | KeePassXC stays at v0.3 (M7), reached through Secret Service FdoSecrets meanwhile. Agreed? | Yes. | Q3 is open; FdoSecrets lets the running KeePassXC do the write. |
| Q33 | The write gate stops accidents, not an agent that works around it (4.4: pty plus `env -u`, pty-driving agents, direct `sops`/`git` edits). Is an accident gate enough for the ruling's intent, which is to keep every `/etc/nixos` change in the owner's hands? | Yes for v0.2, documented as T27a. | An out-of-band channel is a larger design: a GUI pinentry or polkit prompt, or a check that the controlling-terminal session does not descend from a process with an agent variable. None stops a direct `sops set`. |
| Q34 | Does the owner have a Mac, or will the owner pay for macOS runner minutes on this private repository? | No until answered. S17 and S18 are "compile-checked only" through the Linux darwin clippy gate. | Without either, no macOS claim can be tested. |
| Q35 | gopass: is "gopass-compatible, no auto-sync" through the pass backend enough, or is a native gopass backend (age crypto, `gitfs` sync) wanted? | Compatible only, this round. | Native gopass pushes to a remote by default and documents no locking. |
| Q36 | INI store format: ship it (S6b) although no consumer here uses it? | Yes, as scoped by the request. | Small: two-segment names on the S6 parser. Drop S6b if the owner says no. |
| Q37 | Daemon backends (Secret Service, Keychain) keep no backup. Must `store --replace` and `rm` ask for confirmation there even for the owner, or should secrit keep the old item under a `secrit-backup=<UTC>` attribute? | Ask (`y` on `/dev/tty` or `--yes`); keep no old item. | A kept item leaves the old value in the daemon, which a rotation wants gone. |

## 15. Record of the Q13 ruling

The ruling reached this design session through the workflow task text of 2026-10-08,
not in the owner's own words. PLAN 20 records it with that source. The owner should
confirm it, together with Q19, Q21 and Q33, before S1b merges. No other slice waits for
that answer except S14.

## 16. Critique log

An independent critic reviewed revision 1 on 2026-10-08 (31 findings). Revision 2 fixes
30 and fixes one in part with a partial refutation (F20). "Checked" names the tool that
confirmed the finding's premise in this session.

| ID | Severity | Verdict | Note |
|---|---|---|---|
| F01 | blocker | fixed | `build` row is `warn`; new flake check `release-features` on the package derivation guards T54 (4.3). Checked: `tests/setup.rs` 282-317, `ci.yml`, `flake.nix` 202 read. |
| F02 | major | fixed | Gate bypass reads its own variable `SECRIT_TEST_GATE=allow`; the five `SECRIT_TEST_HOOK` call sites need no edit (4.3, V28). Checked: `rg` over `tests/`. |
| F03 | major | fixed | Each trait item, variant and field lands in the slice that first reads it (5.1 table, 5.3); `Location::Keychain` is macOS-only. Checked: `Cargo.toml` has no `[lib]`. |
| F04 | major | fixed | New 4.4, T27a with a test that asserts the bypass, README list entry, Q33. Checked: `/dev/tty` does not open here and `CLAUDECODE=1` (bash). |
| F05 | major | fixed | `--list-only --list-packets`, `.gpg-id` resolved to subkey IDs, `--no-encrypt-to`, `--trust-model always`, pinentry-free write test (6.4, T35). Checked: lab, gpg 2.4.9 (V25). |
| F06 | major | fixed | `--pinentry-mode error` by default; `pinentry = "agent"` only with no agent and a tty; T37 rewritten with real gpg and a marker pinentry (6.4). |
| F07 | major | fixed | Key-command environment documented, shebang check in `doctor`, wrapper in README, shorter `age_key_cmd_timeout_secs`, two new tests (6.2, T47a). Checked: `gh api` on sops `age/keysource.go` v3.13.3 (V26). |
| F08 | major | fixed | `supervise` is a separate state machine: stops are not fatal, Ctrl-Z stops the job, INT/QUIT do not kill CMD, TERM/HUP forwarded, pending flag cleared (7.1 step 5); pty tests in S13. |
| F09 | major | fixed | Q27 default changed: `--env` refused under agent detection, `--file` allowed; T42 test added; `/proc/<pid>/fd` limit documented (T57). |
| F10 | major | fixed | Capability renamed `other_app_acl`; 2.1 rationale and doctor row reworded; T29 covers every backend (5.2, 6.5). |
| F11 | major | fixed | T55 (no backup, confirmation, Q37), T56 (unwiped zbus, AES-CBC, CFData copies), T57 (run limits); README list entries named per slice (section 9). Checked: README list read. |
| F12 | major | fixed | S16 starts after S11 and S8; gpg resolution in S11 has no `PATH` source; S7 deferred removes the S7/S8 overlap; `atomic.rs` operations all land in S3; S8 no longer edits `backend/mod.rs`; waves corrected (section 13). |
| F13 | major | fixed | Linux darwin clippy gate from S1a (needs a rustup target; nixpkgs rustc has no cross std, V28); platform-conditional `testTools`; `cfg` on `/proc`, `setsid` and Secret Service tests; Q34; S17/S18 "compile-checked only" without a Mac. Checked: `rg /proc tests/`, `rust-toolchain.toml`. |
| F14 | major | fixed | `dist = true` in `dist-workspace.toml`; runners named; `cargo-zigbuild` for musl; darwin artifact optional (8.1). Checked: exa, cargo-dist book (V27). |
| F15 | major | fixed | gopass compatibility tested in S11 (Q35 for native); INI ships as S6b (Q36); `wire --format dotenv` print-only in S15. |
| F16 | major | fixed | S1 split into S1a (no behaviour change) and S1b (gate, waits for the owner); only S14 depends on S1b. |
| F17 | major | fixed | Value rule: write value plus `\n`, read strips one `\n`; `value = "first-line"` option; pass binary values off; exact-byte interop tests (6.4, S11). |
| F18 | minor | fixed | Spawned thread with `recv_timeout` and signal polling; connection built from the checked address with `Builder::address`; unset variable maps to `$XDG_RUNTIME_DIR/bus`; fixture daemon on a tempdir socket (6.3). `connect_with_existing` signature stays a check in S10. |
| F19 | minor | fixed | dotenv names refuse the `sops_` prefix; T58 and S6 tests (5.4). |
| F20 | minor | fixed (env part refuted) | The `env` wire already maps `/` to `_` (`src/cmd/wire.rs` 191-210), so `A_B_FILE` is valid today. Credential IDs now map `/` to `_`; a collision check across the store added (5.7). |
| F21 | minor | fixed | Per-step stdout cap for binary `encrypt`; test with exactly 65 536 bytes (6.1.4, S9). Checked: `MAX_VALUE_BYTES` passed as the cap at `src/backend/sops.rs` 787. |
| F22 | minor | fixed | `init` write steps go behind the gate; Q21 reworded with the true facts; gate prompt lists recipients for binary creates and `init` (4.1, 4.2). |
| F23 | minor | fixed | Lab V24 before S10 code; acceptance text covers both outcomes with a nextest filter for `checks.nextest` (10.2, S10). |
| F24 | minor | fixed | Linux falls back to `/run/user/<uid>` with owner and mode checks (S16); macOS uses `$TMPDIR` only under `/private/var/folders` owned by the uid; env-derived lock weakness documented (8.2). |
| F25 | minor | fixed | S7 deferred until Q23 is revisited; v0.1 refusal stays (2.2, 6.1.3, T51). |
| F26 | minor | fixed | Shim directories refused with a `mise which` hint; test in S16 (8.1). Checked: `tests/common/mod.rs` 32. |
| F27 | minor | fixed | Sampler generic over a byte source; deterministic test over every byte value; one fixed-seed statistical test (7.2, T46). |
| F28 | nit | fixed | Header names `a8ec45c`. |
| F29 | nit | fixed | `sops` reserved in the first segment only; suffix rules on every segment (5.4, 6.1.3, S5 test). |
| F30 | nit | fixed | 2.4 `generate` reason reworded; new no-tty message replaces the `--yes` hint (4.1). |
| F31 | nit | fixed | T41 runs with `CLAUDECODE=1` under `script` and asserts masking is active. |
