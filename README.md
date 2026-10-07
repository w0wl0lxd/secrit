# secrit

secrit is a small Rust command-line tool that stores secrets in a sops + age file that
sops-nix can read. You type `secrit store NAME`, and secrit reads the value from a no-echo
prompt or from stdin. The value never goes on the command line, never reaches the terminal
scrollback, and the write is crash-safe and lock-protected. The design is in
[`docs/PLAN.md`](docs/PLAN.md).

Status: v0.1 scaffold. `store`, `ls`, `rm` and `get` work. `run`, `init`, `doctor` and
`wire` print "not implemented yet" (see [What works](#what-works)).

## What secrit does not protect against

Read this first.

- **A hostile process of your own user.** Such a process can run `sops decrypt` with your
  key, read `/run/secrets/*`, or read your terminal. secrit's agent and terminal rules
  prevent accidents. They are not a security boundary.
- **Secret names are not secret.** sops keeps key names in cleartext, in the file and in
  git history. `secrit ls` prints them without a key.
- **Copies outside secrit.** sops (a Go program) holds the value in memory that secrit
  cannot wipe. A value that a program prints, logs or sends is out of secrit's control.
- **Old values.** `rm` and `store --replace` keep a ciphertext backup next to the file.
  Git history, backups and rendered `/run/secrets` copies keep old values. Rotate a leaked
  value at its source.

## Install

With Nix (recommended). The package bakes in the absolute store paths of `sops` and
`age-keygen`, so installing secrit also installs the exact tools it runs:

```sh
nix profile add github:w0wl0lxd/secrit     # or: nix run github:w0wl0lxd/secrit -- ls
```

In a flake, use `inputs.secrit.packages.${system}.default`, or the overlay
`inputs.secrit.overlays.default` (it adds `pkgs.secrit`).

With Cargo (Rust 1.98 or newer):

```sh
cargo install --locked --path .
```

A Cargo build has no baked-in tool paths. secrit then uses the first `sops` on `PATH` and
prints a warning. Set `tools.sops` in the config to an absolute path to remove the
warning. secrit runs sops with a cleared environment, so a version-manager shim (mise,
asdf) that needs `PATH` or `HOME` can fail; point `tools.sops` at the real binary.

## Configure

secrit reads `$SECRIT_CONFIG`, else `$XDG_CONFIG_HOME/secrit/config.toml`, else
`~/.config/secrit/config.toml`. `--config PATH` overrides all three. The file must be
yours and not writable by group or others. Unknown keys are an error.

```toml
default_store = "main"

[stores.main]
backend = "sops"                              # v0.1: only "sops"
file = "/etc/nixos/secrets/secrit.yaml"       # an existing sops file
sops_config = "/etc/nixos/.sops.yaml"         # optional; default: nearest .sops.yaml upward from `file`
age_key_file = "~/.config/sops/age/keys.txt"  # optional; passed to sops as SOPS_AGE_KEY_FILE

[tools]
sops = "auto"        # "auto" = baked-in path, else PATH; or an absolute path

[lock]
timeout_secs = 30
```

Paths must be absolute or start with `~/`. Until `secrit init` lands, create the sops file
once by hand, for example:

```sh
printf '{}\n' | sops --config /etc/nixos/.sops.yaml encrypt --input-type yaml \
  --output-type yaml --filename-override /etc/nixos/secrets/secrit.yaml /dev/stdin \
  > /etc/nixos/secrets/secrit.yaml
```

In a flake repository, `git add` the new file, or the flake (and sops-nix) cannot see it.

## Use

```sh
secrit store github-token              # no-echo prompt, asked twice
gh auth token | secrit store gh-token  # piped; one trailing newline is stripped
secrit store tls-key --multiline < key.pem
secrit store blob --raw < file         # keep the exact bytes
secrit store github-token --replace    # overwrite; keeps a ciphertext backup

secrit ls                              # names only; decrypts nothing
secrit ls --json

secrit get github-token                # shows it on the alternate screen; any key clears it
secrit get github-token --stdout | some-cmd   # exact bytes to a pipe; refused on a terminal

secrit rm github-token                 # asks on the terminal; --yes to skip
```

`--store NAME` picks another store from the config. `-q` prints errors only.

Exit codes: `0` success, `1` failed, `2` usage error, `3` refused by a safety rule (agent,
terminal, overwrite, name rule, unsafe file), `4` lock timeout or a concurrent change,
`130` a signal cancelled a write before it took effect.

### Rules secrit enforces

- **No value on the command line.** `secrit store NAME VALUE` fails with exit 2 and a
  fixed message that does not repeat the value. Parse errors never echo argument text.
- **Names** match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. `sops` is reserved. A name that
  sops would store in cleartext (the `_unencrypted` suffix, the file's
  `unencrypted_suffix` or `encrypted_suffix`) is refused. secrit v0.1 does not write a
  file whose sops metadata has `unencrypted_regex` or `encrypted_regex`.
- **Values** are UTF-8 text up to 64 KiB, with no control characters except tab (and
  newline with `--multiline` or `--raw`). They are always stored as strings.
- **Agents.** When a coding-agent variable is set (`CLAUDECODE`, `CODEX_SANDBOX`, and
  others in `src/agent.rs`) or `/dev/tty` cannot be opened, `get` is refused. There is
  no override: an agent can set any variable. `store`, `ls` and `rm --yes` work.
- **The write protocol.** secrit takes a lock in `$XDG_RUNTIME_DIR/secrit/`, copies the
  ciphertext to a temp file in the same directory, runs `sops set` on the copy, checks
  the copy (recipients and sops settings unchanged, every other entry byte-identical, the
  new entry an encrypted string, the value decrypts back equal), and renames the copy over
  the file. A crash leaves the original intact. A symlinked or hard-linked store file, or
  one writable by group or others, is refused.
- **Process hardening.** No core dumps, not dumpable (`PR_SET_DUMPABLE=0`), umask 077, a
  panic hook that prints no payload, and `panic = "abort"` in release builds.

Known limit: a raw `sops set` or `sops edit` on the same file does not take secrit's lock.
secrit detects a change that lands before its rename and retries (at most 3 times), but
not one that lands after it.

## What works

| Command | v0.1 scaffold | Planned |
|---|---|---|
| `store`, `ls`, `rm` | Works | |
| `get` (reveal, `--stdout`) | Works | |
| `completions bash\|fish\|zsh` | Works (hidden) | |
| `doctor` | Not implemented | M1 |
| `run` (memfd, masking) | Not implemented | M3 |
| `init`, `wire` | Not implemented | M4 |

## Develop

```sh
nix develop                       # Rust, sops, age, cargo-nextest, cargo-deny
cargo nextest run --all-features  # unit and integration tests
nix flake check                   # fmt, clippy, nextest, cargo-deny, the package
```

The integration tests run the real `sops` and `age-keygen` against a temp directory with
a temp HOME and new age keys. They find the tools through `SECRIT_TEST_SOPS` and
`SECRIT_TEST_AGE_KEYGEN` (the devShell sets both), else `PATH`. The `test-hooks` feature
adds fault injection (`SECRIT_TEST_HOOK`) for the crash and signal tests; it is never on
in a release build.

## Licence

Dual-licensed under MIT or Apache-2.0, at your option. See [`LICENSE`](LICENSE).
