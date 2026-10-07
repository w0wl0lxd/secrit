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
- `run`, `init`, `doctor` and `wire` parse their flags and exit 1 with "not implemented
  yet".
- Config loader with a fixed search order, `~` expansion, unknown-key errors and
  ownership and mode checks.
- Process hardening: no core dumps, not dumpable, umask 077, a payload-free panic hook.
- Nix flake: package with baked-in `sops` and `age-keygen` paths, devShell, overlay, and
  checks (fmt, clippy, nextest, cargo-deny, package).
- GitHub Actions CI: fmt, clippy, nextest, cargo-deny, `nix flake check`.

### Changed from docs/PLAN.md

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
- A signal (INT, TERM, HUP) during a write cancels it before the rename (exit 130)
  instead of being blocked; sops runs in its own process group.
- The `wire_hint` config key is accepted, but the hint prints only once `wire` lands.
