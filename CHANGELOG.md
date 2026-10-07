# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `secrit store NAME`: read a value from a no-echo prompt or stdin and write it to a sops
  file through a locked, validated copy-and-rename protocol. `--replace` keeps a 0600
  ciphertext backup. `--multiline` and `--raw` control newlines.
- `secrit ls [--json]`: list names from the cleartext keys; decrypts nothing.
- `secrit rm NAME [--yes]`: remove a name through the same protocol, with a backup.
- `secrit get NAME [--stdout]`: reveal on the alternate screen, or write the exact bytes to
  a pipe. Refused when an agent is detected, and `--stdout` is refused on a terminal.
- Hidden `secrit completions bash|fish|zsh`.
- `run`, `init`, `doctor` and `wire` parse their flags, say "not implemented yet" in
  `--help`, and exit 1.
- Config loader with a fixed search order, `~` expansion, unknown-key errors and
  ownership and mode checks.
- Process hardening: no core dumps, not dumpable, umask 077, a payload-free panic hook. A
  step that fails prints a warning.
- `secrit --version` prints the baked-in `sops` and `age-keygen` paths.
- Nix flake: package with baked-in `sops` and `age-keygen` paths, devShell, overlay,
  home-manager module (`homeManagerModules.default`, `programs.secrit`), and checks (fmt,
  clippy, nextest, cargo-deny, the package, the home-manager module).
- GitHub Actions CI: one cargo job (fmt, clippy, nextest, cargo-deny) and `nix flake check`.
- README section "Set up a store": age key, `.sops.yaml` rule, the empty sops file, the
  `.gitignore` line, and a sops-nix stanza.

### Security

- A sops run can no longer hang secrit. A sops that waits for a terminal (a
  passphrase-protected key) is stopped at once with a clear message. A run that takes more
  than 120 s, or a SIGINT, SIGTERM, SIGHUP or SIGQUIT, kills the sops process group. Every
  path reaps the child.
- sops gets `HOME=/nonexistent` and an explicit `SOPS_AGE_KEY_FILE`, so it never uses an
  SSH key from `~/.ssh`.
- Reveal mode shows control characters in a value as `\xNN` in reverse video, so a value
  cannot leave the alternate screen or send terminal commands. `ls` escapes names too.
- A signal during reveal clears the screen and restores the terminal (exit 130).
- `get --stdout` refuses a regular file that group or others can read, or that another
  user owns, and a block device.
- The terminal prompt keeps tab characters and holds echo off for the whole multiline
  read.
- A group-writable store directory is refused unless it is sticky.
- The `.sops.yaml` and a configured `tools.sops` must pass an owner and mode check. A
  `SECRIT_CONFIG` in use is announced on stderr.
- `get` decrypts each name from the checked snapshot bytes on stdin, not from the file by
  path, and no longer leaves value copies in JSON parser buffers.
- sops stderr lines that may hold the value are dropped, not redacted inline.
- SIGQUIT is deferred like SIGINT, so it cannot leave a temp copy behind.
- Piped input is read with `read(2)` straight into the fixed value buffer. std's stdin
  buffer kept up to 8 KiB of a value between 56 and 64 KiB, and never wiped it (REG-2).

### Changed from docs/PLAN.md

`docs/PLAN.md` now describes these choices; this list records where the code moved away
from the first draft.

- The write lock is keyed by the store directory and a hash of the file name, not by the
  store file's inode. Each write renames a new inode over the file, so an inode key let
  two writers hold "the" lock at once.
- The lock is taken before the store-file checks, not after them.
- The cleartext-name rules come from the store file's own sops metadata (which
  `sops set` applies), not from `.sops.yaml`. A file with `unencrypted_regex` or
  `encrypted_regex` is not written in v0.1.
- `Backend::list` returns the names as the file holds them (`Vec<String>`), so a key that
  another tool wrote with a name secrit would reject still shows in `ls`.
- `Backend::remove` returns the backup path like `put`.
- Signals: SIGINT, SIGTERM, SIGHUP and SIGQUIT are deferred while secrit waits for the
  lock, writes, prompts or reveals. A signal before the rename cancels the write with exit
  130 and kills a running sops. sops runs in its own process group, not its own session
  (`setsid` needs unstable or `unsafe` code); stop detection gives the same fail-fast
  result. The first draft of this entry said a signal always cancelled the write; that was
  not true while sops waited for a terminal.
- Backups go to `$XDG_STATE_HOME/secrit/backups/<id>-<basename>/` (mode 0700), not next to
  the store file, and only the newest 10 per store are kept. A failed rename removes the
  new backup.
- `get` runs one `sops decrypt --extract` per name instead of one whole-file decrypt.
- Reveal mode clears on any key, not only Enter.
- The terminal prompt is secrit's own `/dev/tty` reader; `rpassword` was dropped. A line
  is limited to 4095 bytes (the terminal's canonical-mode limit). `--multiline` at the
  prompt is asked once.
- Exit codes: an unsafe config file, lock directory, `.sops.yaml` or `sops` binary exits 3,
  like an unsafe store file. A bad name exits 3 even with no config.
- A sops older than 3.11 is refused before the first run.
- `mlock` and `MADV_DONTDUMP` on value buffers are deferred: rustix offers them only as
  `unsafe fn`, and the crate forbids `unsafe` code (PLAN open question Q14).
- Crates: `signal-hook` added; `rpassword` and `anyhow` dropped; `base64`, `insta` and the
  rustix `mm` feature wait for the commands that need them; the tests use
  `std::process::Command` instead of `assert_cmd`, `assert_fs` and `predicates`.
- The flake builds `x86_64-linux` only, and `rust-toolchain.toml` pins 1.98.1.
- The licence texts are in `LICENSE-MIT` and `LICENSE-APACHE`.
- The `wire_hint` config key is accepted, but the hint prints only once `wire` lands.
