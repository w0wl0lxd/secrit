# secrit: plan for v0.2

Status: revision 4, 2026-10-08: owner rulings on the gated store and the security levels
(section 14, design in 6.7, slices S8b and S8c). Draft for review. Author: design agent of
the v0.2 expansion workflow.
Owner: w0wl0lxd. Branch
`feat/expand`, stacked on PR #2 (`feat/mvp-gaps`, merged in at `9a7a97c` on 2026-10-08).
The branches are published: bring a parent's changes in with a merge commit, not a rebase.
Revision 3, 2026-10-08: owner answers in section 14.
Revision 2, 2026-10-08: applies the critique of section 16.1.

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
| Gate | Owner rulings of 2026-10-08 (Q19, Q33, Q43, Q47 to Q51) | A gated store with its own hardware-token identity, one sops YAML file per name and a signed manifest (6.7). Security levels with the default "strictest that runs". `secrit seal` for CI and remote producers. Every same-uid gate is an accident gate until coding agents run under their own uid (issue #3). |

The security posture of v0.1 stays: no value on argv, `unsafe_code = "forbid"`, zeroized
buffers, bounded child processes with a cleared environment, crash-safe lock-protected
writes, and agent refusal of `get`.

The work is 22 slices plus one hotfix (S0): S1 splits into S1a and S1b, S6b (INI) is new,
S8b (gated store) and S8c (`seal`) are new, and S7 (canary probe) is deferred. Each slice
is one stacked pull request that compiles and passes every gate on its own (section 12).
Section 12 also lists the work that waits for v0.3.

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
| age plugins (`age-plugin-*`) | Ship, touch-only, or a PIN that secrit verifies on its own tty (`session`, 6.7.5) | S8, S8b | sops needs `PATH` to find the plugin. A PIN prompt from a background process group is stopped (Q24). |
| Binary store format (one sops binary file per name) | Ship | S9 | Carrier for `--binary` (Q22). sops-nix reads it with `format = "binary"`. |
| Per-name YAML store format (`yaml-dir`: one sops YAML file per name) | Ship | S9 | The layout of a gated store (Q48, 6.7.7). Each file has its own data key, so one decrypt exposes one value, and a write needs only public keys. |
| Gated store: own token identity, signed manifest, root-owned pin | Ship (YubiKey 5 PIV only, Q51) | S8b | Owner rulings Q33, Q43, Q47 and Q48 (6.7). |
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
| `secrit seal` (encrypt-only, no tty, no identity) | Ship | S8c | Owner ruling Q19: CI and remote producers write through `seal`, not through a no-tty `store` (6.7.10). |
| `secrit sign` (sign the manifest of a gated store) | Ship | S8b | A file that `seal` made, or a batch of writes, becomes readable only after the owner signs the manifest (6.7.7). |
| `secrit request` and `secrit apply` (request by intent) | Defer to v0.3; design in 6.7.12 | — | Owner ruling Q49: built after agents run under their own uid. |

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

With no `/dev/tty`, the message is:

```text
refused: no terminal to confirm on. CI or a remote job: use 'secrit seal'. A scheduled job: run it as its own system service. Over ssh: use ssh -t.
```

The v0.1 `rm` hint "pass --yes to remove without asking" goes, because `--yes` no longer
helps there.

`NoTty` counts as an agent in v0.1 (PLAN 8.3), and the ruling refuses writes with no
`/dev/tty`. So `printf v | secrit store n` from cron, a systemd unit or CI is refused
(exit 3). The owner confirmed this result (Q19, section 14): no variable, config key or
flag opens an exception, because an agent can set all three. Legitimate automated
writers use the paths of 6.7.10.

**Detection changes in S1b** (accident signals only):

- Add `OPENCODE` and `COPILOT_CLI` (the latter from secondary sources only;
  **[unverified]**). Keep `AGENT`, `CODEX_THREAD_ID` and `OPENCODE_CLIENT`. Document that
  `CODEX_SANDBOX` is set on macOS only.
- Walk the process ancestors (`/proc/<pid>/stat` ppid, then `/proc/<pid>/environ`). An
  ancestor with a detection variable counts as an agent, and the prompt names that
  process. This catches `script -qc 'env -u CLAUDECODE …'` under an agent. T27a then
  asserts the bypass with `systemd-run --user --pty`, which reparents the command to the
  user service manager.
- For a gated store, `get`, `run` and every other decrypt are refused under agent
  detection, with no typed-name path (6.7.2 rule 5). Writes keep the typed name.

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
- An agent that runs under the owner's uid can start a process outside its own process
  tree (a user service, a terminal that it controls), so the ancestor walk does not see
  it.
- Some agents set no detection variable at all.

Claude Code itself gets `Refuse` today: it sets `CLAUDECODE=1` and has no `/dev/tty` (lab
in this session).

Q33 is ruled (section 14). The typed name stays an accident gate. The real boundary is
coding agents under their own uid, which is deferred and tracked in issue #3. Until then
every same-uid gate, the gated store of 6.7 included, is an accident gate, and `doctor`
reports the host conditions that make it so (6.7.1). The gated store adds what a typed
name cannot: a decrypt needs the owner's token, and a read refuses a file that the signed
manifest does not cover.

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

A store can instead name one identity in a `[stores.X.identity]` table (S1a parses it, S8
uses it, 6.7.8):

```rust
pub enum Identity {
    File(PathBuf),           // the key sources above, as one kind each
    SshFile(PathBuf),
    KeyCmd(PathBuf),
    Plugin { stub: PathBuf, dir: PathBuf, level: Option<Level>, touch_timeout_secs: u64 },
}
pub enum Level { Strict, Session, Touch, Unlock, Open }
```

A `Plugin` identity never falls back to the age key file. Only a `Plugin` identity can
serve a gated store.

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
format = "yaml"                   # new, optional: yaml | json | dotenv | ini | binary | yaml-dir
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

[stores.vault]                    # gated store (S8b, 6.7): one sops YAML file per name (S9)
backend = "sops"
format = "yaml-dir"
dir = "/etc/nixos/secrets/vault"

[stores.vault.identity]           # new in S1a, used in S8 and S8b
kind = "plugin"                   # file | ssh-file | key-cmd | plugin
stub = "~/.config/secrit/vault.identity"
plugin_dir = "/nix/store/…-age-plugin-yubikey-0.5.1/bin"
level = "session"                 # optional: strict | session | touch | unlock | open
touch_timeout_secs = 30           # optional

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
- `format = "binary"` and `format = "yaml-dir"` need `dir` and forbid `file`. Every other
  format needs `file` and forbids `dir`.
- The `identity` table is optional. No table means the v0.1 key sources, so v0.1 configs
  parse unchanged. The table has `deny_unknown_fields`, with a unit test per `kind`. No
  `level` key parses as "the strictest level that this build supports" (6.7.8). A store
  with an `identity` table must not also set `age_key_file`, `age_ssh_key_file` or
  `age_key_cmd`.
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
| `seal`, `sign` | New (6.7.7, 6.7.10). |
| every command on a gated store | The pin and manifest checks of 6.7.7 and 6.7.8 run before any sops run. Decrypts are refused under agent detection and with no `/dev/tty`. |

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

The binary format has no name binding: a file renamed to another name decrypts as that
name, because sops binary files have no key path. So a gated store refuses
`format = "binary"` in v0.2, and binary values are refused in a gated store.

#### 6.1.6 Per-name YAML store (`yaml-dir`, S9)

A `yaml-dir` store is a directory (mode 0700). Each name is one sops YAML file
`<dir>/<NAME>.yaml` that holds one key, `NAME`. Nested names are refused.

- **Name binding.** sops uses the key path as additional data of the value's AEAD
  (sops v3.13.3 `sops.go` lines 549-550, checked in the gated-store review). A file whose
  YAML key is changed does not decrypt, and secrit refuses a file whose YAML key differs
  from its file name before any sops run.
- `list`: the regular files that match `^NAME\.yaml$` with a name that passes `name.rs`.
  `doctor` lists every other file in the directory as stray.
- `put`, create and replace: a new sops file each time, encrypted to explicit `--age`
  recipients with an empty `--config`, never through `.sops.yaml` rules. Each write makes
  a new data key. It uses `create_new` and `backup` from S3, a lock per name, and
  `renameat` for a replace.
- **Readback without the token.** The write adds a one-time X25519 recipient that lives
  in secrit's memory only. secrit builds the file in a private `O_TMPFILE`, decrypts it
  with the one-time key, compares in constant time, removes the one-time stanza, checks
  that the recipient set equals the expected set, and then `linkat`s the file into place.
  The readback proves that the value round-trips. It does not prove that the token, host
  or backup stanza works: a wrong recipient shows only at boot or in a recovery drill.
- `remove`: back up, then `unlinkat`. A gated store keeps its backups outside the store
  directory and outside git, owner-only, with a time limit. So a backup cannot be
  renamed back into place as an older valid value.
- **No in-place edit.** secrit never runs `sops set` or `sops edit` on a `yaml-dir`
  file. The README tells the owner not to do so either, and to use `store --replace`
  instead: an in-place edit keeps the old data key, which a forged file can make known
  to its forger.
- `wire` prints `sopsFile = ./<dir>/NAME.yaml;` and the `git add` line.

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
| `age_plugin_dir` | `PATH=<dir>` | The directory passes the trust rule and holds only `age-plugin-*` files. `PATH` holds this one directory. A PIN prompt stops sops (SIGTTIN) and secrit ends it. Each `store` on a single-file store costs two to three plugin operations (set, readback, probe). A `yaml-dir` store costs none on a write (6.1.6). |

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

### 6.7 Gated store and security levels (S8b, S8c)

The owner rulings of 2026-10-08 (section 14) decide this section. It applies to a sops
store with `format = "yaml-dir"` and a `plugin` identity. The main sops setup and every
other store keep v0.1 behaviour plus the write gate of section 4.

Evidence marks: **checked** means read in the source at the tagged release or in the
vendor document. **Inferred** means it follows from checked facts but is not tested.
**[unverified]** means no primary source was read. **Lab** means a test with a real token
must pass before the design depends on it (6.7.11).

#### 6.7.1 Boundary

- **Same-uid agent**: a coding agent that runs under the owner's uid. Every gate is an
  accident gate against it. Depending on the host, it can become root (for example
  through sudo with no password or a cached sudo ticket), read keystrokes and inject
  input (for example through access to input devices), or drive the owner's terminal
  (for example through a terminal or multiplexer control socket).
- **Separate-uid agent**: an agent under its own uid that cannot read the owner's files,
  drive the owner's terminal or input devices, or become root.

The real boundary is the second one: coding agents under their own uid. The owner
deferred that migration, and issue #3 tracks it. Until it lands:

- every same-uid gate in this plan is an accident gate, the token gate included;
- `doctor` reports the host conditions that weaken the gate: privilege escalation with no
  password, access to input devices, terminal remote control, a NixOS configuration
  source that the uid can write, and the polkit result for card access through `pcscd`.

#### 6.7.2 Rules for every level

1. **The card enforces the level.** A YubiKey PIV slot gets its PIN and touch policy at
   key generation, and the policy cannot change after that. The config only selects the
   level that secrit expects. To lower the level, an agent must use another key. The
   recipient then changes, and the pin (6.7.8) refuses the file. A process that can use
   the card while the PIN is verified can replace keys; the attestation digest in the
   pin detects that.
2. **A write decrypts nothing.** In the per-name layout, a write encrypts a new file to
   public recipients, so sops needs no identity. The plugin binary must be on `PATH` in
   recipient mode, but it asks for no touch. The write still costs one signing touch for
   the manifest (6.7.7).
3. **One decrypt is one file.** Each per-name file has its own data key.
   age-plugin-yubikey does one PIV decrypt per stanza (`src/key.rs` `unwrap_file_key`,
   checked). So one touch exposes one value, not the whole store.
4. **Refused at every level** for a gated store:
   - PIV touch `cached`: for 15 s after a touch, any process decrypts with no touch
     (`key.rs` `FIFTEEN_SECONDS`, checked; Yubico PIV policy page).
   - fido2-hmac v2 (the native X25519 recipient, or the v2 plugin stanza with a fixed
     salt): the hmac output is a static X25519 private key (`docs/spec-v2.md`, checked).
     One theft decrypts all past and future values and survives `sops rotate`.
   - A plain identity that the owner uid can read: the plain age key file of the main
     sops setup, or the user's default SSH keys. Q33 rules that the plain age key file is
     never a recipient of a gated store.
   - A non-age key type (pgp, KMS, Vault).
5. **Under agent detection, a gated decrypt is refused**, with no typed-name path. A
   typed-name path would train the owner to touch for commands that an agent started.
   Writes keep the typed-name gate of S1b.
6. **With no `/dev/tty`, a gated decrypt is refused** before sops runs. Otherwise the card
   blinks for nobody.
7. **One factor in one key group.** The token, host and backup recipients sit in one sops
   key group (OR). A Shamir split (token AND host) blocks sops-nix at boot, so a gated
   store never uses one.
8. **A backup recipient is required.** Three wrong PINs and three wrong PUKs block both.
   The PIV reset command then deletes every slot key with no PIN, touch or management
   key (Yubico `yubico-piv-tool` reset action and YubiKey SDK `ResetPivCommand`, checked).
   Any process that reaches the card can do that. The backup recipient keeps the store
   readable after such an erase.

#### 6.7.3 The ladder

| Level | Config | Factor rule | YubiKey 5 PIV slot | Same-uid agent today can | Separate-uid agent later can | Ships |
|---|---|---|---|---|---|---|
| L4 | `strict` | Knowledge and presence on every decrypt | PIN `always`, touch `always` | Keylog the PIN, then win the touch race. Drive the owner's terminal. | The touch race, if it reaches `pcscd`, until the secrit-owned unwrap sends `VERIFY` and the decrypt in one PC/SC transaction (K11). Then nothing without the owner, the card and the PIN. | v0.3: it needs the secrit-owned unwrap. The plugin asks for an `always` PIN through sops `/dev/tty`, which Q24 forbids. |
| L3 | `session` (default) | Knowledge once per secrit command; presence on every decrypt | PIN `once`, touch `always` | While an owner's command holds the PIN state, the card accepts a decrypt from any process with only a touch. So: the touch race, as at L2. | Nothing, if it cannot reach `pcscd`. With `pcscd` access: the touch race during an owner's command. | v0.2, when lab test LT1 passes. Until then v0.2 ships L2 as the default. |
| L2 | `touch` | Presence on every decrypt | PIN `never`, touch `always` | The touch race: stop the owner's plugin with `SIGSTOP` and send its own request first. Steal the value from a descendant that it started and the owner touched. | With `pcscd` access: the touch race. Without it: nothing. A stolen token plus a copy of the file decrypts. | v0.2 |
| L1 | `unlock` | Knowledge only; no presence | (not a PIV level) | Keylog the PIN or passphrase, then decrypt with no signal to the owner. Root also needs the PIN of a TPM key, but can keylog it. | Nothing without the device or the file. | v0.3. `doctor` warns: "no presence check". |
| L0 | `open` | None | (not a PIV level) | Everything. | Nothing, if the file is 0600 and owned by another uid. | v0.1 behaviour. Main store and host recipient only. Never the only person factor of a gated store. |

Other tokens map to the levels as follows, but v0.2 builds the YubiKey 5 PIV path only
(Q51): Secure Enclave `current-biometry` and YubiKey Bio `matchalways` (L4), YubiKey Bio
`matchonce` (L3), fido2-hmac "symmetric" v1 with no PIN (L2), age-plugin-tpm `--pin` and an
scrypt passphrase identity (L1).

What each level adds over the one below it:

- L1 over L0: a copy of the file and the key file is not enough; the thief also needs a
  secret. It does not stop a same-uid agent.
- L2 over L1: a person must be present for every decrypt. A same-uid agent can still win
  the touch race, but the owner sees an extra blink and can cancel.
- L3 over L2: a stolen token plus a copy of the file does not decrypt. It costs one PIN
  per secrit command.
- L4 over L3: no PIN state that other processes can share. Against a same-uid agent with
  input-device access it adds nothing.

#### 6.7.4 Facts behind the levels

- **The PIN state lives on the card, for every process.** The plugin skips the PIN when
  the policy is `once` and `verify_pin(&[])` succeeds (`src/key.rs`, checked). It
  disconnects with `pcsc::Disposition::LeaveCard` "to preserve the YubiKey's PIN and
  touch caches" (`key.rs` `disconnect_without_reset`, checked). The state ends on unplug,
  on a card reset, and on a switch to another applet such as FIDO2 (plugin README "Agent
  support").
- **An idle card forgets the PIN.** pcsc-lite powers off a card that no client uses
  after a grace period (`PCSCLITE_POWER_OFF_GRACE_PERIOD`, 5 s in `src/pcscd.h.in`, and
  the power-down in `src/eventhandler.c`; checked). The power-off clears the PIV PIN
  state. age-plugin-yubikey issue #198 reports a PIN cache of about 5 s for this reason.
  Some pcscd setups also exit when the last client leaves. So a PIN state that lasts
  across commands needs a keep-alive process that holds a PC/SC connection. Such a
  process is a cache that every PC/SC client of the host can use, and Q50 rules it out.
- **A YubiKey 4 resets between runs.** For "ephemeral applications" a PIN `once` acts
  like `always` (plugin i18n `cli-setup-yk4-pin-policy`, checked). L3 needs a YubiKey 5.
- **The plugin reads the policy from the slot certificate** that it wrote at generation
  (`src/util.rs` `Metadata::extract`, checked). An agent with the management key can
  rewrite that certificate. Only a Yubico-signed PIV attestation proves the real policy,
  and the card enforces the real policy in every case.
- **L4 cannot run under sops in v0.2.** For PIN `always` the plugin always calls
  `request_secret` (`key.rs`, checked). sops answers it from `/dev/tty`. Under secrit the
  sops child is not in the foreground group, so the prompt stops it (Q24). L4 needs
  secrit to act as the age client, answer the PIN request itself, and give sops the data
  key through a one-shot keyservice (v0.3).
- **YubiKey Bio.** Firmware 5.7 and later accept the PIN policies `matchonce` and
  `matchalways` (Yubico PIV tool manual, checked). age-plugin-yubikey maps only the policy
  bytes 1 to 3 (`util.rs`, checked), so it asks for a PIN on a Bio slot (inferred). The Bio
  path is lab work (LT5), not v0.2.
- **fido2-hmac symmetric (v1)** uses a new salt for each file, so every encrypt also needs
  the token and a touch (`pkg/plugin/identity.go`, checked). At that level `store`, `seal`
  and `init` each cost a touch, and CI cannot seal. Not in v0.2 (Q51).

#### 6.7.5 Default level (Q47)

The default is the strictest level that runs.

- **v0.2: `session`.** For each command that decrypts, secrit opens one shared PC/SC
  connection and selects the PIV applet. It sends `VERIFY` with no data to read the PIN
  state, asks for the PIN on its own `/dev/tty` with echo off, and sends `VERIFY`. It
  holds that connection until the command ends. So the card stays powered and keeps the
  PIN state while sops and the plugin run. The plugin finds the PIN verified and asks
  only for a touch per value. At the end, secrit disconnects with a card reset, so the
  PIN state does not outlive the command (LT4). No process holds the connection between
  commands (Q50). Cost: one PIN per secrit command, plus one touch per value read.
- sops never prompts for the PIN, so `session` does not conflict with Q24. It needs the
  `pcsc` crate and `libpcsclite` at run time.
- `session` depends on lab test LT1 with idle gaps of 0, 10 and 90 s (6.7.11). Until LT1
  passes, the default is `touch`.
- **v0.3: `strict`**, when secrit owns the unwrap (6.7.12). It removes the PIN state that
  other processes can share.
- `session` stops "a stolen token plus a copy of the repository". It does not stop a
  same-uid agent on a host with privilege escalation with no password, input-device
  access or terminal remote control. `doctor` says so.

#### 6.7.6 Cost per command

Gated store on the per-name layout. "Touch" means one PIV operation on one file, or one
signature of the manifest.

| Command | `strict` (v0.3) | `session` | `touch` |
|---|---|---|---|
| `store`, `store --replace`, `generate`, `rm` | 1 signing touch | 1 signing touch | 1 signing touch |
| `seal` | 0 (the file is unreadable until `sign`) | 0 | 0 |
| `sign` (one batch) | 1 signing touch | 1 signing touch | 1 signing touch |
| `ls`, `wire`, `doctor` | 0 | 0 | 0 |
| `get NAME` | PIN + touch | PIN + touch | touch |
| `run` with N names | N × (PIN + touch) | 1 PIN + N touches | N touches |
| Move an existing value in | one rotation at its source, then 1 signing touch per batch | same | same |
| Add a second token as recipient | one decrypt per file, or one run with the backup identity | same | same |
| No `/dev/tty`, or an agent detected | decrypts refused | refused | refused |

- Writes decrypt nothing because of the layout, not because of the level. The signing
  touch uses the manifest key (6.7.7), not the decrypt slot.
- The real cost of a migration is one rotation at the source per value that moves (Q43),
  not a touch count. Only values that must be gated move.
- The layout turns `run` with N names into N touches. Read bundles (one touch per bundle)
  wait for v0.3 (6.7.12). S13 prints the count first.

#### 6.7.7 Layout and signed manifest (Q48)

- **Layout:** `yaml-dir` (6.1.6). One sops YAML file per name.
- **Manifest:** `<dir>/MANIFEST` holds the store name, a counter and, per name, the
  SHA-256 of the file bytes. `<dir>/MANIFEST.sig` holds an SSH signature
  (`ssh-keygen -Y sign -n secrit-manifest`). The verify key (an allowed-signers line)
  sits in the root-owned pin (6.7.8), never in the store or the user config.
- **Manifest key.** Plan default: an `sk-ssh-ed25519` key with touch and no PIN, so the
  check is a plain `ssh-keygen -Y verify`, and a later build-time check can reuse it. The
  alternative is a PIV slot `9c` with touch `always` through PKCS#11 **[unverified]**. LT2
  checks whether a FIDO2 signature ends the PIV PIN state inside one command. The S8b
  review confirms the choice.
- **Write.** After the new file is in place, secrit writes a new manifest with the
  counter plus one and signs it, under the store lock: one touch. If the signature fails
  or times out, the command exits non-zero. The value is then stored but unreadable, and
  `doctor` and `ls` show it as not covered until `secrit sign`.
- **`secrit sign --store X`.** It lists each file that differs from the manifest (new,
  changed or missing): name, size, SHA-256 prefix and the recipient check. It removes
  control characters, escapes and bidirectional marks from every printed field. It asks
  for the typed store name under agent detection and refuses with no `/dev/tty`. On
  confirmation it hashes the files again, refuses when anything changed since it printed
  the list, and signs with one touch.
- **Read.** Before any sops run, secrit checks the signature with the pinned key, then
  checks that the SHA-256 of the file equals its manifest entry. A file that the manifest
  does not cover is refused (exit 3) and costs no touch.
- **What it stops.** Anyone with the public recipients can make a valid sops file, for
  example with `seal` and `mv`. Such a file has the right name binding, recipients and
  YAML key. The manifest makes secrit refuse it.
- **What it does not stop.** sops-nix does not read the manifest, so a forged file can
  reach `/run/secrets` at activation. The owner's review of the diff before a rebuild
  stays the gate there; a build-time check waits for the uid split (K3). A rollback to an
  older signed pair of manifest and files is not detected: the counter has no trusted
  store until the uid split (K3). A same-uid agent can win the race for the signing
  touch, or change the pin through privilege escalation. So the manifest is an accident
  gate until the uid split.

#### 6.7.8 Pin and store selection

The pin is root-owned `/etc/secrit/pins.toml`, a compile-time path. A new secrit NixOS
module renders it from `programs.secrit.pins`. On another host, the administrator writes
it. A home-manager file does not work, because a home-manager switch needs no root.
secrit checks that every component of the path, and of a `/nix/store` target, is
root-owned and not group- or other-writable (new `trust::check_root_file`). The
`test-hooks` feature reads the pin from a test path.

Per store name, the pin holds: the directory path, the recipient set (token, host and
backup), the plugin path, `min_level`, the attestation digest of the token slot, and the
manifest verify key.

**Keyed by store name and directory inode.** At run time, secrit compares the
`(st_dev, st_ino)` of the configured directory with that of the pinned path. A pinned
store name with another directory is refused. An unpinned store name whose directory
matches a pinned directory is refused. User config cannot redefine a pinned store name.
So an edit of the user config to another path, or a bind-mount alias of the same
directory, does not step around the pin. A gated store with no pin is refused.

Level rules:

1. No `level` key means the strictest level that this build supports for the identity
   kind: `session` for a PIV plugin once LT1 passes, else `touch`. A `file` identity is
   `open` and cannot serve a gated store.
2. The level in use is the stricter of the config level and `min_level`. User config can
   raise it and never lower it.
3. `init --gated` reads the slot policy through a PIV attestation. It checks the chain to
   the Yubico PIV root CA, checks that the attested public key equals the stub's
   recipient, and refuses a slot weaker than the level. It prints the digest for the pin
   (LT6).
4. At run time, secrit checks that the slot policy in `age-plugin-yubikey --list` is at
   least the level. That output comes from a certificate that an agent with the
   management key could rewrite, so the attestation at `init` is the real proof.
5. A config level that is stricter than the slot is an error, not a silent downgrade:
   `level 'strict' needs PIN policy always; slot 82 on serial N has once`.
6. The pin holds only while root-owned config is reviewed before each rebuild. If the
   agent's uid can write the NixOS configuration source, it can change the pin at the
   next rebuild. `doctor` reports that condition.

#### 6.7.9 Creation and card requirements

`secrit init --gated --identity-file STUB --host-recipient R --backup-recipient R --dir
PATH`:

1. Run the write gate. Refuse with no `/dev/tty`: setup needs the person.
2. secrit does not generate the token key: generation is interactive, and Q24 forbids
   handing the terminal to a child. With no `--identity-file`, `init` prints the
   `age-plugin-yubikey --generate` command with `--touch-policy always` and the PIN
   policy of the level, and exits 1.
3. Read the token recipient from the stub's `# Recipient:` line.
4. Require `--host-recipient`: a root-only host identity that sops-nix uses at boot, never
   the plain age key file.
5. Require `--backup-recipient` (6.7.2 rule 8). There is no `--no-backup`.
6. Refuse a recipient that equals the public key of the configured or default age key
   file, or of the user's default SSH keys.
7. Use explicit `--age` recipients with an empty `--config`. `doctor` warns when a
   `.sops.yaml` rule for the directory lists a plain key, because a later
   `sops updatekeys` would add it back.
8. Check the attestation (6.7.8 rule 3).
9. Create the directory, sign an empty manifest (one touch), write the store config, and
   print the pin snippet, the sops-nix stanza and the `git add` line.

**Card hardening** (documented requirement, applied by the owner later). age-plugin-yubikey
stores the management key on the card, protected by the PIN, and sets the PUK equal to
the PIN at setup (`src/key.rs` lines 350-388, i18n line 137; checked). While the PIN is
verified, any PC/SC client can then read the management key and act as admin. It can
generate a new key in the gated slot, rewrite the slot certificates, or change the PIN.
A keylogged PIN also gives the PUK. So `init --gated` documents two requirements: a
management key that is not PIN-protected, and a PUK that differs from the PIN
(`ykman piv access change-management-key` without `--protect`, and
`ykman piv access change-puk`). Until the owner applies them, `init --gated` and `doctor`
warn. LT8 tests the attack.

`doctor` reads the PIN and PUK retry counters, which needs no PIN, and fails when either
is below its maximum. It cannot read whether the PUK equals the PIN, so it prints the
requirement.

**Migration (Q33, Q43).** The gated store is new. Values that the plain age key file
could read, in the file or in git history, count as known to an agent. Rotate each value
at its source when it moves into the gated store. Only values that must be gated move.

#### 6.7.10 Automated writers (Q19)

| Writer | Path | Why it is safe |
|---|---|---|
| CI, a remote producer | `secrit seal NAME --store X [--recipients FILE] [--out PATH]` (S8c). It reads the value from stdin and writes the per-name YAML form `{NAME: value}`, encrypted to the recipients of `--recipients FILE` (CI pins its hash) or of the root pin, never of the store metadata. It writes to stdout or to a new path with `O_EXCL`, never into the store and never over a file. It needs no identity, no tty and no gate. The file reaches the host through a reviewed commit. Reads refuse it until the owner runs `secrit sign`. | Encryption needs public keys only. Review and the signed manifest are the gate. |
| A scheduled job on the host | A system service with its own uid and its own credentials (for example `LoadCredentialEncrypted=`, or its own secrit store and identity). It never writes the owner's gated store. | The uid is the boundary. The owner declares the unit through a reviewed rebuild. |
| User crontab | Refused. Move the job to a system timer as above. | A user crontab has the trust of an agent. |
| ssh | `ssh -t`, so the gate reaches the person. An unattended remote job uses `seal`. | The gate needs a person. |

#### 6.7.11 Lab tests with a real YubiKey

The lab runs on a spare retired PIV slot (82 to 95), with the owner present. It changes
no management key and no PUK: the card hardening of 6.7.9 comes later.

| Id | Test | Decides |
|---|---|---|
| LT1 | Generate a slot with PIN `once` and touch `always`. secrit opens a shared PC/SC connection, verifies the PIN on its tty, and holds the connection. After an idle gap of 0 s, 10 s and 90 s, run `sops decrypt` through the plugin under secrit's cleared environment. Pass: no PIN prompt and one touch at every gap. Control: with no held connection, a 10 s gap asks for the PIN again. | `session` in v0.2 |
| LT2 | Inside one command after LT1, make a FIDO2 signature (`ssh-keygen -Y sign` with an `sk` key). Then decrypt. Record whether the PIN is asked again. | The manifest key; whether a FIDO2 signature ends the PIV PIN state |
| LT3 | Measure the card's touch timeout on a decrypt. | The `touch_timeout_secs` default |
| LT4 | At the end of a command, secrit disconnects with a card reset. A second process then decrypts. Expect a PIN request. | That the PIN state does not outlive the command |
| LT5 | YubiKey Bio only: a `matchonce` slot, `yubico-piv-tool -a verify-bio`, then a plugin decrypt. | The Bio path for L3 and L4 (v0.3) |
| LT6 | Attestation of the slot: the chain to the Yubico root, the policy bytes, and that the public key equals the recipient. | 6.7.8 rule 3 |
| LT7 | A second uid opens `pcscd` through four launch paths: `sudo -u`, `run0 --user`, `systemd-run --uid` and a system service. pcsc-lite with polkit grants card access to active sessions only, so a process started from the owner's session can keep that session (inferred). | The separate-uid column of L2 and L3; the polkit rule for the agent uid |
| LT8 | With the PIN verified by secrit, a second process reads the PIN-protected management key. | The card hardening requirement (6.7.9) |

#### 6.7.12 Gap fillers and the v0.3 design

Rank = interruptions removed per unit of risk, with the uid split still deferred.

| Rank | Filler | Removes | Security effect | Ships |
|---|---|---|---|---|
| 1 | Write/read asymmetry: one file per name, encrypt-only writes, readback through a one-time recipient | Every decrypt touch on `store`, `rm`, `generate`, `seal` and a migration | One touch exposes one value; every write makes a new data key | v0.2 |
| 2 | PIN once per secrit command | Every PIN after the first in a command | The PIN state ends with the command | v0.2 (LT1) |
| 3 | Signed manifest | Nothing; it makes forgery visible to secrit reads | Accident gate until the uid split; sops-nix does not check it | v0.2 |
| 4 | Request by intent (Q49) | Every synchronous interrupt for agent writes | The requester never sees a value that the trusted side makes | Designed now; built in v0.3 after the uid split |
| 5 | Read bundles: one file holds the names that one consumer reads together | N-1 touches per `run` | One touch exposes the bundle. A bundle is the only home of its names, and the pin lists them | v0.3 |
| 6 | Scoped leases through a broker under its own uid | Repeated approvals inside one task | Real only across a uid boundary. A lease binds the uid and a pidfd of the requester, not a cgroup that the requester can join | v0.3, after the uid split |
| 7 | Trusted-path request binding | Nothing; each approval then means something | The approval shows the broker's copy of the request on a channel that the agent cannot draw | v0.3 or later |
| 8 | Detection | Nothing | secrit prints the touch count before a multi-name read and names each file in its touch line. A notification or audit line sees only secrit's own runs, so it detects nothing against a same-uid agent | Touch counts in v0.2; a polkit card-access log in v0.3 |
| 9 | A check that cannot be keylogged (YubiKey Bio, Touch ID) | Typing the PIN | Stops keylogging of the knowledge factor | Lab LT5; v0.3 |

**Request by intent (Q49).** Agents rarely need to see a secret. They need to cause a
write, or to make a value usable by a service. An approval of a value that the agent
made proves where the value came from, but it does not keep the value secret. So:

- `secrit request generate NAME [--len N]`, `secrit request rotate NAME --recipe R` and
  `secrit request store NAME`.
- For `generate` and `rotate`, the trusted side (`secrit apply` by the owner, later the
  broker) makes the value at apply time. The requester never sees it.
- A `store` request carries a value that the requester knows. The manifest marks it
  "known to the requester", and `wire` and `doctor` warn when such a value guards
  something that the agent must not reach.
- Requests arrive only through a broker socket under its own uid. The requester identity
  comes from `SO_PEERCRED` and a pidfd, never from the request text.
- `apply` copies the hashed bytes into a new owner-owned file (`O_TMPFILE`, then
  `linkat`). It never renames an inode that the requester owns.
- `apply` prints each reason on one line, capped in length, with control characters,
  escapes and bidirectional marks removed. It shows a count, and refuses when the count
  or a hash differs at commit time.
- Before the uid split, a same-uid inbox is a write with no tty, which Q19 refuses. So it
  is built only after the split.

**v0.3 work** (after the uid split, or designed for it):

- `strict` and the secrit-owned unwrap: secrit acts as the age client, sends `VERIFY`
  and the decrypt in one PC/SC transaction, and gives sops the data key through a
  one-shot keyservice. Default level `strict` from then on (Q47).
- The request inbox, `secrit request` and `secrit apply` (request by intent).
- A broker under its own uid: requests over its socket, leases, trusted-path rendering.
- A build-time check of the manifest where sops-nix consumes the files, and a trusted
  rollback counter (K3).
- Read bundles.
- Other token kinds: FIDO2 v1, TPM PIN (`unlock`), Secure Enclave and YubiKey Bio.
- A polkit rule that refuses card access to the agent uid, and a polkit card-access log.

#### 6.7.13 Residuals

The README list "does not protect against" gains, in S8b:

- A same-uid agent that becomes root, reads keystrokes or drives the owner's terminal
  passes every gate. `doctor` reports these host conditions.
- The touch race: an agent starts a decrypt at the moment the owner touches for another
  request. The touch line names the file and the count (`touch your key to read 'NAME'
  from vault (2 of 5)`), and an extra blink is the only other signal.
- An agent can steal the data key of a command that it started and the owner touched.
  Rule for the owner: touch only for a command that you typed in your own terminal.
- sops-nix does not check the manifest, and a rollback to an older signed pair is not
  detected (6.7.7).
- Any process that reaches the card can block the PIN and PUK and erase the token key.
  The backup recipient recovers the store.
- During a write, a same-uid process can read the one-time readback key and so learn the
  data key of that file.
- An agent can change the owner's shell configuration or `PATH`, so that the owner's own
  `secrit` runs a wrapper.

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
   dropped; percent-encoding in the RFC 3986, form (`+` for space), URI-component and
   path variants with upper and lower hex digits; the JSON-escaped forms of serde_json,
   Go and Python (`ensure_ascii`), with and without an escaped solidus; upper and lower
   hex; and each of these for the value without one final newline. The replacement is
   `[secrit:NAME]`; a region that overlapping values cover is masked whole as
   `[secrit:A+B]`.
   - Streaming: hold back only the longest buffer suffix that is a proper prefix of some
     pattern. Flush the rest at once. Flush everything at EOF. Match leftmost-longest,
   and grow a match while another match starts inside it and ends after it. After an
   idle period (100 ms by default) S13 calls `flush_held`, so a prompt with no newline
   is shown; at most a proper prefix of one pattern goes out unmasked.
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
trusts secrit itself (S18); the gated-store residuals of 6.7.13 (S8b).

New assets of the gated store: the token slot, the manifest key, the pin. New adversary:
A7, a same-uid agent with the abilities of 6.7.1. Until agents run under their own uid
(issue #3), every rule below against A7 is an accident gate.

| # | Threat | Rule | Test |
|---|---|---|---|
| T27 | An agent changes the store with no owner action (Q13) | Write gate: typed name on `/dev/tty`; no tty refuses (4) | pty tests in 4.3; `no_tty()` refusals |
| T27a | An agent allocates a pty and unsets its variable, drives a pty and types the name, or edits the store with `sops` or `git` directly | Documented bypass (4.4, PLAN N1); README "does not protect against". Q33 is ruled: the gated store (6.7) adds a token and a signed manifest; the real boundary waits for the uid split. | Under an agent, the ancestor walk refuses `script -qc 'env -u CLAUDECODE secrit store n'`; `systemd-run --user --pty` stores with no question (the test asserts the bypass) |
| T27b | A forged gated file with the same public recipients (for example `seal` plus `mv`) | Signed manifest; reads refuse an uncovered file before any touch (6.7.7) | T72 |
| T27c | Rollback to an older signed pair, the touch race, data-key theft from an agent-started command, a forged file read by sops-nix | Documented residuals (6.7.13) | None |
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
| T59 | A plain identity that the owner uid can read is a recipient of a gated store | `init --gated` refuses; `doctor` fails; every command refuses (6.7.2 rule 4) | The test age key as a recipient: `init` exits 3, `doctor` has a `fail` row |
| T60 | A relay plugin through an edited `plugin_dir` | The pin holds the plugin path (6.7.8) | A changed `plugin_dir` is refused before sops runs |
| T61 | A same-uid agent becomes root, reads keystrokes or drives the owner's terminal | None in v0.2; `doctor` reports the host conditions (6.7.1) | `doctor` rows with injected host facts |
| T62 | `seal` overwrites a file | `O_EXCL` on `--out`; stdout otherwise (6.7.10) | `seal --out` to an existing path exits 3, file unchanged |
| T63 | A config edit steps around the pin (another path, a bind-mount alias, a redefined store name) | Pin keyed by store name and directory inode (6.7.8) | A pinned name with another directory, and an unpinned name on a pinned directory, both exit 3 before sops runs |
| T64 | Any process that reaches the card blocks the PIN and PUK and erases the token key | Backup recipient required; `doctor` reads the retry counters (6.7.2 rule 8, 6.7.9) | `init --gated` without `--backup-recipient` exits 3; a fake card with low retry counters gives a `doctor` `fail` row |
| T65 | One touch exposes more than one value | One data key per file (6.7.2 rule 3) | The fake plugin's counter: `get` of one name runs one unwrap |
| T66 | A gated write needs the token, or reads back nothing | Encrypt-only write with a one-time readback recipient (6.1.6) | `store` on a gated store succeeds and reads back, and the fake plugin counts no unwrap |
| T67 | A file renamed to another name is read as that name | YAML key equals the file name; sops key-path AEAD (6.1.6) | A renamed file is refused before any touch |
| T68 | A config level stricter than the slot runs at the slot's level | Error, not a downgrade (6.7.8 rule 5) | `level = "strict"` on a `once` slot exits 3 |
| T69 | A touch `cached` slot lets any process decrypt for 15 s | Refused (6.7.2 rule 4) | A fake `--list` with touch `cached` is refused |
| T70 | A fido2-hmac v2 recipient makes one theft final | Refused (6.7.2 rule 4) | A v2 recipient in the recipient set is refused |
| T71 | A no-tty or agent-started gated `get` blinks the card for nobody | Refused before sops runs (6.7.2 rules 5 and 6) | No-tty gated `get` and `CLAUDECODE=1` gated `get` exit 3; the fake plugin counter is 0 |
| T72 | A read uses a file that the signed manifest does not cover | Signature and hash check before any sops run (6.7.7) | A forged file with the same recipients, a changed file, and a file with a bad `MANIFEST.sig` exit 3 with a counter of 0 |
| T73 | The manifest verify key comes from a place the agent can write | The verify key sits in the root pin only (6.7.8) | A verify key in the user config is an unknown-key error; a user-owned pin is refused |
| T74 | A failed signature leaves a readable unsigned file | The file stays uncovered and unreadable until `sign` (6.7.7) | A fake signer that fails: `store` exits non-zero, `get` exits 3, `sign` covers it |
| T75 | `sign` signs bytes that changed after it printed them | Hash again at commit time and refuse a change (6.7.7) | A test hook changes a file between the list and the commit: `sign` exits 3 |
| T76 | An in-place sops edit keeps a data key that a forger knows | secrit never edits a `yaml-dir` file in place; README rule (6.1.6) | `store --replace` makes new key stanzas (the `enc` values differ) |
| T77 | A backup renamed back into place restores an older value | Gated backups outside the store directory; the reader accepts only `^NAME\.yaml$` (6.1.6) | No backup file appears in the directory; a stray file is listed by `doctor` and never read |

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
| 20 | Q13 answered: (b). Q19 and Q33 ruled (section 14). |
| 8.3 | The no-tty refusal names `seal`, system services and `ssh -t` (4.1). Gated decrypts are refused under agent detection (6.7.2). |

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
- **Config additions (parse only):** the `[stores.X.identity]` table with `kind` (`file`,
  `ssh-file`, `key-cmd`, `plugin`) and `level` (enum `strict`, `session`, `touch`,
  `unlock`, `open`), and `format = "yaml-dir"` (5.8). No `level` key parses as "strictest
  supported". No code reads them yet: S8, S8b and S9 do. Under the F03 rule, a field
  with no reader lands with its first reader instead. So if S1a is already in review,
  the identity table moves to S8 and `yaml-dir` to S9.
- **Tests:** config: every v0.1 config of the test suite parses to the same
  `StoreConfig`; unknown key per variant and per identity `kind` (`deny_unknown_fields`);
  an unknown `level` refused; `.ini` refused. A golden test on every error `Display`
  string. All 76 existing tests pass with no edit.
- **Acceptance:** all gates of 10.2, the darwin clippy job included; `git diff` of
  `tests/` is empty except the golden test.
- **Risks:** serde `deny_unknown_fields` with a tagged enum (unit test per variant). A
  dependency build script that needs the Apple SDK breaks the darwin job (10.2).

### S1b. Write gate (Q13)

- **Goal:** Q13(b) in force (section 4), with the Q19 ruling: the refusal text of 4.1,
  the detection changes of 4.1 (more variables, the ancestor walk), and T27a with
  `systemd-run --user --pty`. The `doctor` agent row says: `get` and `run --env` off;
  every decrypt of a gated store off, with no typed-name path; `store`, `rm`, `generate` and `init`
  need the typed name, or are off with no tty; `seal` works.
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
- **Risks:** the owner ruled Q19 and Q33 on 2026-10-08 (section 14), so S1b no longer
  waits. The gated-decrypt refusal of 6.7.2 rule 5 lands in S8b, which has the gated
  store. `COPILOT_CLI` is **[unverified]**. No other slice waits for S1b except S14
  (`generate` calls the gate) and S8b.

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
- **Identity:** `KeySource` gains the `Identity` enum of 5.6 with
  `Plugin { stub, dir, level, touch_timeout_secs }`. The plugin kind never falls back to
  the age key file. secrit refuses a decrypt with no tty before sops runs. Before each
  sops run that decrypts, secrit writes one touch line to `/dev/tty`, which names the
  file and the count: `touch your key to read 'NAME' from vault (2 of 5)`. The plugin
  gives no touch cue of its own on decrypt. `touch_timeout_secs` (default 30, LT3)
  replaces the sops deadline for a plugin identity. New checks: the `level` against the
  policy in `age-plugin-yubikey --list`; refusal of touch `cached`, fido2-hmac v2
  recipients and plain keys (6.7.2 rule 4).
- **Plugin tests:** the rage `age-plugin-unencrypted` example stands in for a plugin,
  with a counter wrapper that counts unwraps ("touches"). T65, T68, T69, T70.
- **Acceptance:** Q18 default is implemented; T47 and T48 pass.
- **Risks:** no real plugin in CI. A YubiKey check is manual and listed in the PR body.
  It runs on a spare retired slot (6.7.11).

### S8b. Gated store on the per-name layout, with the signed manifest

- **Goal:** 6.7, except `seal` (S8c) and the v0.3 items. Starts after S8, S3, S9 and
  S1b.
- **Scope:**
  - The pin (6.7.8): `trust::check_root_file`, keyed by store name and directory inode,
    with the recipient set, plugin path, `min_level`, attestation digest and manifest
    verify key; `BackendError::PinMismatch`; a new `nixosModules.default` with
    `programs.secrit.pins`.
  - Pre-touch checks: the keys of each file are exactly `{NAME, sops}`, the YAML key
    equals the file name, only age stanzas, and the recipient set equals the pin.
  - The signed manifest (6.7.7): check before every read, sign after every write, and
    `secrit sign`.
  - The `session` level (6.7.5): the PIN check over PC/SC on secrit's tty, one shared
    connection held for the command, a card reset at the end (new crate `pcsc`, behind
    LT1; until LT1 passes, the default is `touch`).
  - `init --gated` (6.7.9) with the attestation check, the required backup recipient,
    and the documented card-hardening requirement.
  - Under agent detection, every gated decrypt is refused (6.7.2 rule 5).
  - Gated backups outside the store directory (6.1.6).
  - `doctor` rows: identity kind, recipients (a plain key is `fail`), `.sops.yaml` rule
    for the directory, pin, plugin, manifest (uncovered and stray files), level against
    the slot, PIN and PUK retry counters, card hardening, file domain (your uid owns the
    directory), and the host conditions of 6.7.1. Still no decrypt.
  - README: "Keys" gains the gated store, `seal` and `sign`; "does not protect against"
    gains 6.7.13.
- **Files:** `src/backend/sops/{dir.rs, doctor.rs, runner.rs}`, `src/pin.rs` (new),
  `src/manifest.rs` (new), `src/card.rs` (new, PC/SC), `src/trust.rs`, `src/agent.rs`,
  `src/config.rs`, `src/cli.rs` (`sign`, `init --gated`), `src/cmd/{init.rs, sign.rs
  (new), get.rs, doctor.rs}`, `src/testhook.rs` (test pin path, fake card), `flake.nix`
  (`nixosModules.default`, `pcsclite`, a check for the module), `Cargo.toml` (`pcsc`),
  `tests/gated.rs` (new), `README.md`, `CHANGELOG.md`.
- **Tests:** T27b, T59 to T61, T63, T64, T66, T67, T71 to T77. A plain key as recipient
  makes `init` refuse and `doctor` fail. A user-owned pin is refused. `ls` lists names
  with no unwrap. A real YubiKey check is manual and listed in the PR body.
- **Acceptance:** with the fake plugin and a fake signer, a gated `store`, `get`, `rm`,
  `sign` and `run` give the touch counts of 6.7.6; every pre-touch refusal has a counter
  of 0. `nix flake check` evaluates the NixOS module.
- **Risks:** LT1 fails: ship `touch` as the default and keep the PC/SC code out. LT2
  shows that a FIDO2 signature ends the PIV PIN state: sign before the first decrypt of
  a command, or use a PIV `9c` key. The `pcsc` crate adds `libpcsclite` at run time;
  `cargo deny` must pass. The management-key protection flag may not be readable without
  the PIN **[unverified]**; then `doctor` prints the requirement only.

### S8c. `secrit seal`

- **Goal:** 6.7.10. Starts after S8b.
- **Scope:** `seal NAME --store X [--recipients FILE] [--out PATH]` reads the value from
  stdin and writes the per-name YAML form `{NAME: value}`, not a binary file, so the name
  binding holds. Recipients come from `--recipients FILE` (CI pins its hash) or the root
  pin, never from the store metadata. It shares the encrypt path of S9 `yaml-dir`. It
  writes to stdout, or to a new path with `O_EXCL`. No identity, no tty, no gate, no
  touch. Binary values are refused for a gated store. On the host, `store` into a gated
  store also decrypts nothing, so `seal` is mainly for CI and remote producers.
- **Files:** `src/cmd/seal.rs` (new), `src/cli.rs`, `src/main.rs`, `src/cmd/mod.rs`,
  `src/backend/sops/dir.rs` (shared encrypt path), `tests/seal.rs` (new), `README.md`,
  `CHANGELOG.md`.
- **Tests:** works with `no_tty()` and with `CLAUDECODE=1`; T62; the output decrypts with
  the test key and has the YAML key `NAME`; the recipients equal the pin or the file;
  a sealed file in the store directory is refused on read until `sign` covers it.
- **Acceptance:** a file from `seal` passes the S8b pre-touch checks, and `get` reads it
  after `sign`.
- **Risks:** none known.

### S9. Binary values and the binary store

- **Goal:** 6.1.4, 6.1.6 and 7.3. `format = "yaml-dir"` sits beside `binary` in
  `dir.rs`: `<dir>/<NAME>.yaml`, mode 0700, `create_new` and `backup` from S3, a lock per
  name, `renameat` for a replace, and `unlinkat` after the backup for `rm`. Both dir
  formats read back through the one-time recipient. A gated store takes its recipients
  from explicit `--age` with an empty `--config`, never from `.sops.yaml`. The binary
  format has no name binding, so a gated store refuses it in v0.2. `wire` prints
  `sopsFile = ./vault/NAME.yaml;` and the `git add` line.
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
  `yaml-dir`: round trip; the one-time stanza is gone from the final file; a file whose
  YAML key differs from its name is refused before sops runs (T67); `store --replace`
  makes new key stanzas (T76); no file other than `^NAME\.yaml$` is read.
- **Acceptance:** `sops decrypt --input-type binary --output-type binary` on the file
  gives the bytes.
- **Risks:** `encrypt --input-type binary /dev/stdin` behaviour **[unverified]**: lab it
  first (V12 covers the no-type case only). The removal of the one-time stanza edits
  sops metadata that the MAC does not cover **[inferred]**: the readback test proves that
  the final file still decrypts. Without privilege, `linkat` of an `O_TMPFILE` goes
  through `/proc/self/fd/N` with `AT_SYMLINK_FOLLOW` **[inferred]**; a filesystem with no
  `O_TMPFILE` support falls back to a named temp file in a private directory.

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
- **Gated store** (in whichever of S13 and S8b merges second): `get_many` prints the
  touch count first (`5 names in vault: 5 touches`), then decrypts each file in order,
  each with its own touch line. At `session`, the PIN is asked once for the whole command
  (6.7.5). No decrypt runs under agent detection (6.7.2 rule 5), so `run --file` on a
  gated store is refused for agents too. Values go to `--file` memfds as planned. The
  README says that one touch per name is the price of "one touch exposes one value".
- **Acceptance:** T4 (run part), T5, T40 to T45 and T57 pass.
- **Risks:** pty tests of Ctrl-C and Ctrl-Z are timing-sensitive; the child writes a ready
  marker before the test sends the key.

### S14. `generate`

- **Goal:** 7.2.
- **Files:** `src/cmd/generate.rs` (new), `src/gen.rs` (new), `src/cli.rs`, `src/main.rs`,
  `src/cmd/mod.rs`, `tests/generate.rs` (new), `README.md`.
- **Tests:** unit: the deterministic bias test over every byte value (T46), one
  fixed-seed statistical test, entropy arithmetic, `--strict`; integration: value never in
  stdout or stderr; gate applies; `--bytes` on a binary store; weak refused. On a gated
  store, `generate` decrypts nothing (encrypt-only write plus the one-time readback) and
  costs only the manifest signing touch of S8b: the fake plugin counts no unwrap.
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
  (status), `SECURITY.md` (new backends; the gated store and its accident-gate status).
- **Tests:** a check that every threat row T27 to T77 with a test names an existing test.
- **Acceptance:** all gates on Linux, the darwin clippy gate, and the macOS job if Q34
  provides one; the owner trial of `run`, Secret Service and the gated store (lab tests
  LT1 to LT8, 6.7.11) on the owner's machine.
- **Risks:** none known.

### Waits for v0.3

Not slices of this round. 6.7.12 has the design.

- `strict` and the secrit-owned unwrap: `VERIFY` and the decrypt in one PC/SC
  transaction, and a one-shot keyservice for sops. The default level becomes `strict`.
- Request by intent: the request inbox, `secrit request generate|rotate|store` and
  `secrit apply`.
- A broker under its own uid, after the uid split (issue #3): requests over its socket,
  scoped leases, trusted-path rendering of each approval.
- A build-time check of the manifest where sops-nix consumes the files, and a trusted
  rollback counter (K3).
- Read bundles.
- Other token kinds: FIDO2 v1, TPM PIN (`unlock`), Secure Enclave, YubiKey Bio.
- A polkit rule that refuses card access to the agent uid, and a polkit card-access log.

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
| S1b | S1a (Q19 and Q33 ruled, section 14) | S5, S8, S10, S11, S12, S13 |
| S2 | S1a | S3, S12, S13 |
| S3 | S1a | S2, S12, S13 |
| S4 | S2, S3 | S10, S11, S12, S13 |
| S5 | S4 | S1b, S8, S10, S11, S12, S13 |
| S6 | S5 | S8, S10, S11, S13 |
| S6b | S6 | S8, S10, S11, S13 |
| S8 | S4 | S1b, S5, S6, S6b, S10, S11, S12, S13 |
| S8b | S1b, S3, S8, S9 | S10, S11, S12, S13 (gated `run` goes into the second to merge), S16 |
| S8c | S8b | S10, S11, S13, S15, S16 |
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
| S19 | all, S8b and S8c included | — |

Suggested waves for implementer agents (one slice per agent, each in its own worktree):

1. S0, then S1a.
2. S1b, S2, S3, S12.
3. S4, S10, S11, S13.
4. S5 and S8, then S6, then S6b.
5. S9, S16.
6. S8b (after S9 and S1b), S14 (after S1b and S9), S17.
7. S8c, S15, S18.
8. S19.

The lab tests LT1 to LT8 (6.7.11) run beside wave 5 or 6, with the owner present. LT1
decides whether S8b ships `session` as the default.

Slices that share `src/backend/sops/edit.rs`, `format.rs` or `runner.rs` (S4, S5, S6,
S6b, S9) stay in sequence; S8 shares only `runner.rs` and `doctor.rs` with S4 and S9, so
it runs beside S5 to S6b. The stack order for review is S0, S1a, S2, S3, S4, S5, S6, S6b,
S8, S9, S8b, S8c, S10 to S19. S1b sits beside the stack on S1a. The owner ruled Q19 and
Q33, so S1b merges the current tip in and merges; S8b and S14 wait for it. A slice that
started early merges its predecessor in the review order before review. Published
branches are never rebased.

## 14. Open questions for the owner

Owner answers of 2026-10-08 [ruled-by: w0wl0lxd; recorded-by: lead session dc2a06ae;
source: answers to questions in that session]:

- Q13: (b) is confirmed in the owner's own answer.
- Q29: build only. CI builds release artifacts; nothing is published until the owner
  says so at v0.2.0.
- Q17: done. The repository was recreated public on 2026-10-08 from a history with the
  machine-specific text replaced. Q28 and Q34: GitHub-hosted macOS runners are free on a
  public repository, so S17 and S18 get a macOS CI job once GitHub Actions runs again.

Owner rulings of 2026-10-08 on the gate, the gated store and the security levels
[ruled-by: w0wl0lxd; recorded-by: lead session dc2a06ae; source: answers to questions in
that session]. Section 6.7 holds the design that applies them.

- **Q19:** with no `/dev/tty`, `store` and `rm` are refused, with no exception. CI and
  remote producers use a new encrypt-only `secrit seal`. Scheduled jobs become system
  services with their own credentials. Over ssh, use `ssh -t` (4.1, 6.7.10).
- **Q33 and Q43:** a separate gated store with its own identity. Its recipients never
  include the plain age key file. Values that move there are rotated at their source
  (6.7.9).
- **Boundary:** the real boundary is coding agents under their own uid. It is deferred
  and tracked in issue #3. Until then every same-uid gate is an accident gate, and
  `doctor` reports the host conditions (6.7.1).
- **Q47, default level:** the strictest level that runs. In v0.2 that is `session`: one
  PIN per secrit command (one shared PC/SC connection held for the command, no
  keep-alive) plus one touch per value read. The default is `touch` until lab test LT1,
  with idle gaps of 0, 10 and 90 s, passes. In v0.3 the default becomes `strict`, when
  secrit owns the unwrap (6.7.5).
- **Q48, layout:** one sops YAML file per name, plus a signed manifest in v0.2. One
  signing touch per write or batch. secrit reads refuse files that the signed manifest
  does not cover. It is an accident gate until the uid split. sops-nix itself does not
  check the manifest, which is a residual (6.7.7).
- **Q49, gap filler:** request by intent (`secrit request generate|rotate|store NAME`).
  The trusted side makes `generate` and `rotate` values at apply time, so the requester
  never sees them. Designed in v0.2, built in v0.3 after the uid split (6.7.12).
- **Q50:** no keep-alive cache. Only the card's own PIN state inside one secrit command.
- **Q51 (assumed, not asked):** YubiKey 5 PIV only in v0.2.
- **YubiKey lab:** on a spare retired PIV slot, with the owner present. Card hardening (a
  management key that is not PIN-protected, a PUK that differs from the PIN) is a
  documented `init --gated` requirement that the owner applies later (6.7.9, 6.7.11).
- **Design fixes taken with no question:** a backup recipient is required for a gated
  store; `doctor` reads the PIN and PUK retry counters; the pin is keyed by store name and
  directory inode, not by path; no in-place sops edit of a gated file; gated backups sit
  outside the store directory; readback goes through a one-time recipient in a private
  `O_TMPFILE`, then `linkat` (6.1.6, 6.7.8, 6.7.9).

Q1 to Q12 and Q14 to Q17 of PLAN 20 stay open as written. Q13 is answered (b). Q18: this
plan implements its stated default (an explicit `age_ssh_key_file`), so no new ruling is
needed unless the owner objects.

| # | Question | Assumed default | Why |
|---|---|---|---|
| Q19 | The Q13(b) ruling refuses `store` and `rm` with no `/dev/tty`. That also stops cron, systemd units and CI, which are not agents. Is that intended? | Ruled 2026-10-08: yes, no exception. CI and remote producers use `seal`; scheduled jobs become system services; ssh uses `ssh -t`. | secrit cannot tell cron from an agent with no terminal, and an agent can set any exception variable. |
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
| Q33 | The write gate stops accidents, not an agent that works around it (4.4: pty plus `env -u`, pty-driving agents, direct `sops`/`git` edits). Is an accident gate enough for the ruling's intent, which is to keep every `/etc/nixos` change in the owner's hands? | Ruled 2026-10-08: a separate gated store with its own token identity and a signed manifest (6.7). The real boundary, agents under their own uid, is deferred (issue #3). | No same-uid gate stops a direct `sops` or `git` change. Only a uid boundary does. |
| Q34 | Does the owner have a Mac, or will the owner pay for macOS runner minutes on this private repository? | No until answered. S17 and S18 are "compile-checked only" through the Linux darwin clippy gate. | Without either, no macOS claim can be tested. |
| Q35 | gopass: is "gopass-compatible, no auto-sync" through the pass backend enough, or is a native gopass backend (age crypto, `gitfs` sync) wanted? | Compatible only, this round. | Native gopass pushes to a remote by default and documents no locking. |
| Q36 | INI store format: ship it (S6b) although no consumer here uses it? | Yes, as scoped by the request. | Small: two-segment names on the S6 parser. Drop S6b if the owner says no. |
| Q37 | Daemon backends (Secret Service, Keychain) keep no backup. Must `store --replace` and `rm` ask for confirmation there even for the owner, or should secrit keep the old item under a `secrit-backup=<UTC>` attribute? | Ask (`y` on `/dev/tty` or `--yes`); keep no old item. | A kept item leaves the old value in the daemon, which a rotation wants gone. |
| Q43 | What happens to the current secrit store, which the plain age key file can read? | Ruled 2026-10-08: a new gated store; each value that moves is rotated at its source. | A value that the plain key could read, in the file or in git history, counts as known to an agent. |
| Q47 | Which level is the default for a gated store? | Ruled 2026-10-08: the strictest that runs. v0.2 `session` (`touch` until LT1 passes); v0.3 `strict`. | 6.7.5. |
| Q48 | What layout does the gated store use? | Ruled 2026-10-08: one sops YAML file per name, plus a signed manifest in v0.2. | One touch reads one value; writes decrypt nothing; the manifest makes forgery visible to secrit reads (6.7.7). |
| Q49 | What fills the gap between "touch per command" and automation? | Ruled 2026-10-08: request by intent, designed now, built in v0.3 after the uid split. | The requester never sees a value that the trusted side makes (6.7.12). |
| Q50 | May a convenience cache exist before agents run under their own uid? | Ruled 2026-10-08 (through Q47): no keep-alive cache. | A cache on the same uid is open to every process of that uid. |
| Q51 | Which token kinds get a level in v0.2? | Assumed, not asked: YubiKey 5 PIV only. | Other kinds wait for v0.3 (6.7.3). |

Q38 to Q42 and Q44 to Q46 were questions of an earlier draft of the gate design. The
rulings above and the design of 6.7 answer or replace them.

## 15. Record of the Q13 ruling

The ruling reached this design session through the workflow task text of 2026-10-08,
not in the owner's own words. PLAN 20 records it with that source. The owner confirmed
Q13 (b) in the owner's own answer, and ruled Q19 and Q33 on 2026-10-08 (section 14). Q21
keeps its assumed default.

## 16. Critique log

### 16.1 Revision 1 critique (F01 to F31)

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

### 16.2 Gated-store design critique (K1 to K20)

An independent skeptic reviewed the security-levels design on 2026-10-08 (20 findings).
Revision 4 applies the owner rulings to them. "Fixed" means this plan now holds the fix.
"Deferred" names where the fix waits.

| ID | Severity | Verdict | Note |
|---|---|---|---|
| K1 | blocker | fixed | pcsc-lite powers off an idle card after a grace period, which clears the PIN state. So `session` costs one PIN per secrit command (one shared PC/SC connection held for the command), not per working session. No keep-alive (Q50). LT1 now has idle gaps of 0, 10 and 90 s and a control (6.7.4, 6.7.5, 6.7.11). |
| K2 | major | fixed | The per-name layout lost forgery detection, and `seal` plus `mv` made a drop-in forgery. v0.2 ships the signed manifest; reads refuse an uncovered file before any touch (Q48, 6.7.7, T27b, T72). |
| K3 | major | deferred (uid split) | sops-nix does not read the manifest, and the rollback counter has no trusted store on the same uid. Both are documented residuals; a build-time check and a trusted counter wait for v0.3 (6.7.7, 6.7.13). |
| K4 | major | fixed in design; built in v0.3 | Request identity comes from `SO_PEERCRED` and a pidfd through a broker socket, never from the request; `apply` copies hashed bytes through `O_TMPFILE`; reasons are cleaned and capped; a same-uid inbox is not built, because Q19 refuses writes with no tty (6.7.12). |
| K5 | major | fixed in design; built in v0.3 | Request by intent: the trusted side makes `generate` and `rotate` values at apply time; agent-made values are marked "known to the requester" (Q49, 6.7.12). |
| K6 | major | fixed (documented requirement) | While the PIN is verified, any PC/SC client can read a PIN-protected management key. `init --gated` documents a management key that is not PIN-protected and a PUK that differs from the PIN; the owner applies them later; LT8 tests the attack (6.7.9). |
| K7 | major | fixed | Blocked PIN and PUK plus the PIV reset erase the token key. The backup recipient is required, `doctor` reads the retry counters, and the erase is a listed residual (6.7.2 rule 8, T64). |
| K8 | major | fixed | Default = strictest that runs: `session` in v0.2 (`touch` until LT1), `strict` in v0.3 (Q47, 6.7.5). |
| K9 | major | deferred (uid split, issue #3) | Whether a separate-uid agent reaches `pcscd` depends on how it starts. LT7 tests four launch paths; a polkit rule for the agent uid waits for v0.3 (6.7.11, 6.7.12). |
| K10 | major | fixed | The pin is keyed by store name and directory inode, so a config edit or a bind-mount alias does not step around it (6.7.8, T63). |
| K11 | minor | deferred (v0.3) | The PIN state is not bound to a PC/SC client. The secrit-owned unwrap sends `VERIFY` and the decrypt in one transaction; until then the L4 separate-uid cell says "touch race" (6.7.3). |
| K12 | minor | fixed | The text now says detection sees only secrit's own runs and detects nothing against a same-uid agent. Touch lines name the file and the count. The polkit card-access log stays v0.3 (6.7.12). |
| K13 | minor | fixed | A TPM key with a PIN needs the PIN even for root; root can keylog it. The L1 row says so (6.7.3). |
| K14 | minor | fixed | Gated backups sit outside the store directory; the reader accepts only `^NAME\.yaml$`; `doctor` lists stray files (6.1.6, T77). |
| K15 | minor | fixed | No in-place sops edit of a gated file; README rule; a test that `store --replace` makes new stanzas (6.1.6, T76). |
| K16 | minor | fixed | Readback builds the file in a private `O_TMPFILE`, removes the one-time stanza, checks the recipient set, then `linkat`s it. The text states what the readback does not prove (6.1.6). |
| K17 | minor | fixed | The real migration cost is one rotation per moved value; `run` with N names costs N touches; bundles wait for v0.3 (6.7.6). |
| K18 | minor | fixed in design; v0.3 | A lease binds the uid and a pidfd of the requester, not a cgroup that the requester can join (6.7.12). |
| K19 | minor | fixed in design; v0.3 | A bundle is the only home of its names, and the pin lists them (6.7.12). |
| K20 | minor | fixed | An earlier draft gave one host's conditions as typical. The text now gives them as examples that depend on the host, and no host fact appears in this plan (6.7.1). |
