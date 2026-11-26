# secrit

secrit is a small Rust command-line tool that stores secrets in a sops + age file that
sops-nix can read. You type `secrit store NAME`, and secrit reads the value from a no-echo
prompt or from stdin. The value never goes on the command line, never reaches the terminal
scrollback, and the write is crash-safe and lock-protected. The design is in
[`docs/PLAN.md`](docs/PLAN.md).

Status: v0.1. Every v0.1 command works: `store`, `get`, `ls`, `rm`, `init`, `doctor` and
`wire`. `run` moved to v0.2 (see [What works](#what-works)).

## What secrit does not protect against

Read this first.

- **A hostile process of your own user.** Such a process can run `sops decrypt` with your
  key, read `/run/secrets/*`, or read your terminal. secrit's agent and terminal rules
  prevent accidents. They are not a security boundary.
- **An agent that works around the write gate.** The typed-name question stops accidents,
  not an agent that wants to write. An agent can allocate a terminal, unset its variable
  and start secrit outside its own process tree (for example with
  `systemd-run --user --pty`), so detection finds no agent. An agent that drives a
  terminal (a pty mode, `tmux send-keys`, terminal remote control) sees the question and
  can type the name. A writer can type the answer after secrit discards the input typed
  ahead. A direct `sops set`, `sops edit` or `git` change to the store file never meets
  the gate. Some agents set no variable at all.
- **Secret names are not secret.** sops keeps key names in cleartext, in the file and in
  git history. `secrit ls` prints them without a key.
- **Copies outside secrit.** sops (a Go program) holds the value in memory that secrit
  cannot wipe. sops runs as a separate program: after exec it is dumpable again, so
  `PR_SET_DUMPABLE=0` covers secrit, not sops, and a process of your user can read the
  memory of sops while it runs. A value that a program prints, logs or sends is out of
  secrit's control. secrit does not lock its own buffers into memory (`mlock`) in v0.1, so
  a value can reach swap; it keeps values small and wipes its buffers.
- **The screen.** While `secrit get` shows a value, any program that can read the screen
  can read it too: for example Kitty remote control, a screen recorder or a screen share.
- **No clipboard in v0.1.** secrit has no clipboard support: clipboard history daemons
  keep values on disk. Use `get --stdout` into a pipe instead.
- **gpg-agent (pass stores).** Any process that can use your gpg-agent can decrypt the
  entries of a pass store while the agent caches the passphrase, or at any time when the
  key has no passphrase. secrit's agent rules do not change that.
- **Old values.** `rm` and `store --replace` keep a ciphertext backup in
  `$XDG_STATE_HOME/secrit/backups/` (default `~/.local/state/secrit/backups/`), the newest
  10 per store. Git history, backups and rendered `/run/secrets` copies keep old values.
  Rotate a leaked value at its source.

## Install

With Nix (recommended). The package bakes in the absolute store paths of `sops` and
`age-keygen`, so installing secrit also installs the exact tools it runs. `secrit --version`
shows both paths. The repository has no public remote yet, so install from a checkout:

```sh
nix profile add path:.            # from the checkout; or: nix run path:. -- ls
```

In a flake, add the checkout as an input (for example `inputs.secrit.url =
"path:/home/you/dev/secrit"` or a `git+ssh://` URL), then use
`inputs.secrit.packages.${system}.default`, or the overlay `inputs.secrit.overlays.default`
(it adds `pkgs.secrit`, built from your nixpkgs).

With home-manager, import `inputs.secrit.homeManagerModules.default`. It installs the
package and writes `~/.config/secrit/config.toml` from `settings`:

```nix
programs.secrit = {
  enable = true;
  settings = {
    default_store = "main";
    stores.main = {
      backend = "sops";
      file = "/etc/nixos/secrets/secrit.yaml";
      sops_config = "/etc/nixos/.sops.yaml";
    };
  };
};
```

With Cargo (Rust 1.98 or newer):

```sh
cargo install --locked --path .
```

A Cargo build has no baked-in tool paths. secrit then uses the first `sops` on `PATH` and
prints a warning. Set `tools.sops` in the config to an absolute path to remove the
warning. secrit runs sops with a cleared environment, so a version-manager shim (mise,
asdf) that needs `PATH` or `HOME` can fail; point `tools.sops` at the real binary. secrit
needs sops 3.11 or newer.

## Configure

secrit reads `$SECRIT_CONFIG`, else `$XDG_CONFIG_HOME/secrit/config.toml`, else
`~/.config/secrit/config.toml`. `--config PATH` overrides all three. When
`$SECRIT_CONFIG` picks the file, secrit says so on stderr each time (not with `-q`). The
file must be yours (or a read-only `/nix/store` file from home-manager) and not writable by
group or others. Unknown keys are an error.

```toml
default_store = "main"

[stores.main]
backend = "sops"                              # "sops" or "pass"
file = "/etc/nixos/secrets/secrit.yaml"       # an existing sops file
format = "yaml"                               # optional: "yaml", "json", "dotenv" or "ini"; default: from the file name
sops_config = "/etc/nixos/.sops.yaml"         # optional; default: nearest .sops.yaml upward from `file`
age_key_file = "~/.config/sops/age/keys.txt"  # optional; default: $XDG_CONFIG_HOME/sops/age/keys.txt

[tools]
sops = "auto"        # "auto" = baked-in path, else PATH; or an absolute path
gpg = "auto"         # pass stores: "auto" = baked-in path only (no PATH); or an absolute path

[lock]
timeout_secs = 30
```

**Format.** A sops store is YAML, JSON, dotenv or INI. With no `format`, a file name that
ends in `.json` means JSON, a name that ends in `.env` means dotenv, a name that ends in
`.ini` means INI, and any other name means YAML. Every sops run names the store's format,
and `store` and `rm` refuse (exit 3) a file whose content or name does not match it, so a
write never rewrites a store in another format.

**Dotenv stores.** A dotenv store holds one `NAME=value` line for each name. A name is a
variable name: a letter, then letters, digits and `_`. It has no `/`, `.` or `-`, and it
cannot start with `sops_`, because sops keeps its own data in those lines. secrit
refuses any other name with exit 3 before it reads a value. A value keeps its exact
bytes, and a newline in it is stored as `\n` on one line. `sops exec-env FILE 'COMMAND'`
runs a command with the values as environment variables. sops-nix gives a dotenv file to
a consumer only as one whole file, so `secrit wire` refuses a dotenv store.

**INI stores.** An INI store holds `[section]` headers and one `KEY = value` line for each
name. A name is `section/key`: exactly two segments, and each one is a variable name as in
a dotenv store. The section cannot be `sops`, because sops keeps its own data in that
section. secrit refuses any other name with exit 3 before it reads a value. The keys
before the first header are in the section `DEFAULT`. `rm` of the last key of a section
removes the section. sops aligns the `=` signs of a section again when a longer key
arrives, so those lines change; their encrypted values do not. `store` and `rm` refuse a
file with a line that the INI reader of sops reads in a special way: a quoted value, a
`:` separator, an inline comment, a line that ends in `\`, an indented line, a `[DEFAULT]`
header, a section twice or a key twice. `sops decrypt --extract '["section"]["key"]' FILE`
prints one value. sops-nix gives an INI file to a consumer only as one whole file, so
`secrit wire` refuses an INI store.

Paths must be absolute or start with `~/`. A configured `tools.sops` and the `.sops.yaml`
must be owned by you, root or the Nix store, and neither the file nor its directory may be
writable by group or others.

**Keys.** secrit gives sops only an age key file (`SOPS_AGE_KEY_FILE`). sops runs with no
usable `HOME`, so it never tries `~/.ssh/id_ed25519` or `~/.ssh/id_rsa`. Age keys from SSH
keys, `SOPS_AGE_KEY` and `SOPS_AGE_KEY_CMD` are not used. A passphrase-protected key fails
at once with a clear message; sops cannot prompt.

## Set up a store

`secrit init` sets up what is missing and never replaces a file that exists:

```sh
secrit init --sops-file /etc/nixos/secrets/secrit.yaml --dry-run   # print the plan only
secrit init --sops-file /etc/nixos/secrets/secrit.yaml
secrit init --sops-file /etc/nixos/secrets/secrit.json                # a JSON store
secrit doctor                                                     # check the result
```

It makes an age key if there is none (back it up: without it the secrets are lost), checks
that a `.sops.yaml` creation rule covers the file, creates the empty sops file, writes the
config, and prints the `.gitignore` and `git add` steps. It never edits an existing
`.sops.yaml`: when no rule covers the file, it prints one and exits 1. With
`--write-sops-config` it creates a `.sops.yaml` when there is none. The example uses
`/etc/nixos/secrets/secrit.yaml`; any directory that you own and that group and others
cannot write works. `--format yaml|json|dotenv|ini` sets the store format and writes it to the config
as `format`; without it, the file name picks the format. `--format` that does not match
the file name (`--format json` for a `.yaml` file) exits 3 before init makes a file.

To set up the same store by hand:

1. Make an age key, if you have none. `age-keygen` refuses to overwrite a file. Back the
   key up: without it the secrets are lost.

   ```sh
   mkdir -p -m 700 ~/.config/sops/age
   age-keygen -o ~/.config/sops/age/keys.txt    # prints the public key: age1...
   ```

2. Add a creation rule for the file to `.sops.yaml` at the repository root, with your
   public key (and any other recipient, such as the host key that sops-nix uses):

   ```yaml
   creation_rules:
     - path_regex: secrets/secrit\.yaml$
       age: age1yourpublickey...
   ```

3. Create the empty sops file:

   ```sh
   printf '{}\n' | sops --config /etc/nixos/.sops.yaml encrypt --input-type yaml \
     --output-type yaml --filename-override /etc/nixos/secrets/secrit.yaml /dev/stdin \
     > /etc/nixos/secrets/secrit.yaml
   ```

4. In a git repository, ignore secrit's temp copies, which a crash or a SIGKILL can leave
   behind (ciphertext only), then `git add` the new file. A temp copy ends in the format's
   extension; the pattern matches both formats. The v0.1 pattern `.*.secrit-*.yaml` still
   covers a YAML store, and `doctor` warns when a JSON store's temp copies are not ignored. A flake (and sops-nix) cannot see
   an untracked file.

   ```sh
   echo '.*.secrit-*' >> /etc/nixos/.gitignore
   git -C /etc/nixos add .gitignore secrets/secrit.yaml
   ```

   If the repository runs a spell checker such as `typos` in a pre-commit hook, exclude the
   file from it; ciphertext can fail the check.

5. Store a value, then expose it through sops-nix in your NixOS config.
   `secrit wire github-token` prints the stanza, the `git add` line when the file is
   untracked, and the rebuild command (with `[nix]` in the config). secrit runs none of
   them. The stanza looks like this:

   ```nix
   sops.secrets."github-token" = {
     sopsFile = ./secrets/secrit.yaml;
     format = "yaml";
     owner = "you";
   };
   ```

   The value then appears at `/run/secrets/github-token`. For a JSON store, `wire` prints
   `format = "json";`. For a nested name such as `app/db/pass`, the stanza also has
   `key = "app/db/pass";`, which sops-nix reads as the nested key, and the value appears
   at `/run/secrets/app/db/pass`.

## pass layout store

A store with `backend = "pass"` uses the password-store layout: one gpg-encrypted file
per name, `<dir>/<prefix>/<name>.gpg`. `pass` and `gopass` read the entries that secrit
writes, and secrit reads theirs. secrit runs `gpg` itself and never runs `pass` or
`gopass`. The support is gopass-compatible, with no auto-sync: secrit never pulls, pushes
or commits.

```toml
[stores.pw]
backend = "pass"
dir = "~/.password-store"   # the store directory; it must hold a .gpg-id (run 'pass init KEY')
prefix = "secrit"           # optional; entries go in <dir>/secrit/
gnupg_home = "~/.gnupg"     # optional; default: $GNUPGHOME when absolute, else ~/.gnupg
value = "whole"             # or "first-line"
pinentry = "error"          # or "agent"
```

`secrit init --backend pass --pass-dir DIR` checks the directory, the `.gpg-id` and each
recipient key, then writes the config or, when a config exists, prints the
`[stores.NAME]` section to add. It never creates the store: `pass init KEY` does that.
`wire_hint` does not apply to a pass store, and `wire` works with sops stores only.

- **Recipients.** secrit encrypts to the keys in the nearest `.gpg-id`, from the entry's
  directory up to `dir`. Each line must name exactly one key in the keyring with a usable
  encryption subkey. Recipients and settings from `gpg.conf` (`encrypt-to`,
  `hidden-encrypt-to`) are not added. After the encryption, secrit lists the packets of
  the new file (no decryption) and checks that only those keys can decrypt it, before the
  rename.
- **Signed `.gpg-id`.** A `.gpg-id.sig` beside the nearest `.gpg-id` refuses `store` and
  `rm` with exit 3: secrit does not verify the signature yet.
- **Value.** `store` writes the value and one newline, as `pass insert` does. With
  `value = "whole"`, `get` returns the file minus one trailing newline, so every value
  round-trips exactly. With `value = "first-line"`, `get` returns the first line (the pass
  password, without the `login:` and `url:` lines), and `store` refuses a value with a
  newline.
- **Passphrase.** A write needs no passphrase. `get` passes `--pinentry-mode error` to
  gpg: a passphrase that gpg-agent has cached works, and a needed passphrase fails at once
  with a hint. With `pinentry = "agent"`, and only when no coding agent is detected and
  `/dev/tty` opens, gpg-agent may ask with its own pinentry. That pinentry can be a GUI
  window on your desktop.
- **gpg runs** with a cleared environment that holds only `GNUPGHOME`, and with
  `--batch --no-tty`. secrit takes `gpg` from `tools.gpg` or from the path baked into the
  Nix package, never from `PATH`.
- **git.** secrit never commits. When `dir` is in a git repository, `store` and `rm` print
  the `git add` and `git commit` commands; run them yourself.
- `ls` walks `<dir>/<prefix>` (8 levels at most) for `*.gpg` files. It decrypts nothing,
  and it skips hidden names and symlinks. `rm` keeps a ciphertext backup, as for sops
  stores; empty subdirectories stay.
- `doctor` checks the `gpg` binary and version, the store directory, the `GNUPGHOME` mode,
  the `.gpg-id`, each recipient key, a `.gpg-id.sig` (warn) and the git state.

## Use

```sh
secrit store github-token              # no-echo prompt, asked twice
gh auth token | secrit store gh-token  # piped; one trailing newline is stripped
secrit store tls-key --multiline < key.pem
secrit store blob --raw < file         # keep the exact bytes
secrit store github-token --replace    # overwrite; keeps a ciphertext backup
secrit store app/db/pass               # a nested key: app -> db -> pass

secrit ls                              # names only; decrypts nothing
secrit ls --json

secrit get github-token                # shows it on the alternate screen; any key clears it
                                       # (a screen reader or recorder can see it too)
secrit get github-token --stdout | some-cmd   # exact bytes to a pipe; refused on a terminal

secrit rm github-token                 # asks on the terminal; --yes to skip (not under an agent)

secrit doctor                          # read-only checks; exit 1 when one fails
secrit doctor --json
secrit wire github-token               # sops-nix stanza on stdout; git and rebuild steps on stderr
secrit wire github-token --owner svc --format env   # GITHUB_TOKEN_FILE=/run/secrets/github-token
```

`doctor` checks the tools, the age key and its mode, the store file and directory, the
`.sops.yaml` rule, cleartext entries, leftover temp copies and old backups, the backup
directory, and the git state of the store file. It decrypts nothing and prints no value.
It says what the write gate does when it detects an agent, and it warns when the binary
was built with the `test-hooks` feature, which only the test suite uses.

`--store NAME` picks another store from the config. `-q` prints errors only.

At the terminal prompt, a tab is kept. The terminal limits one line to 4095 bytes; pipe a
longer value. `--multiline` at the prompt reads lines until a line that holds only `.`, and
asks once, not twice.

`get --stdout` writes to a pipe, a socket or a character device. It writes to a regular
file only when the file is yours and group and others cannot read it (for example after
`umask 077`).

Exit codes: `0` success, `1` failed, `2` usage error, `3` refused by a safety rule (agent,
terminal, overwrite, name rule, an unsafe store file, store directory, config file, lock
directory, `.sops.yaml` or `sops`), `4` lock timeout or a
concurrent change, `130` a signal cancelled the command before a write took effect. `init`
keeps the files of the steps it finished; run it again to finish the setup.

### Rules secrit enforces

- **No value on the command line.** `secrit store NAME VALUE` fails with exit 2 and a
  fixed message that does not repeat the value. Parse errors never echo argument text.
- **Names** are key paths: one or more segments joined by `/`, at most 8 segments and
  255 bytes. Each segment matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, so a one-segment
  name is a v0.1 name. `sops` is reserved as the first segment only (`app/sops` is a
  name). A name that sops would store in cleartext is refused: a segment that ends with
  `_unencrypted` or with the file's `unencrypted_suffix`, or, when the file sets
  `encrypted_suffix`, a name with no segment that ends with it. sops tests each key on
  the path, and secrit does the same. secrit does not write a file whose sops metadata
  has `unencrypted_regex` or `encrypted_regex`.
- **Nested names** (YAML and JSON stores; a dotenv store refuses them, and an INI store
  takes `section/key` only). `secrit store
  a/b/c` writes the key `c` in the
  map `b` in the map `a`, and creates the maps that are missing. `store` refuses (exit 3,
  before it reads a value) a path through a value that is not a map, such as `a/b` when
  `a` holds a string: sops would replace that value with a map. `store` and `rm` refuse a
  name that holds other names, such as `a` when `a/b` exists, because the write would
  replace or drop them all. `rm a/b/c` also removes each map that it leaves empty. `ls`
  lists every leaf by its path (`a/b/c`), and an empty map by its own name.
- **Values** are UTF-8 text up to 64 KiB, with no control characters except tab (and
  newline with `--multiline` or `--raw`). They are always stored as strings.
- **Agents.** secrit detects an agent when a coding-agent variable is set and not empty
  (`CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `AI_AGENT`, `AGENT`, `CODEX_SANDBOX` (macOS
  only), `CODEX_THREAD_ID`, `CURSOR_AGENT`, `GEMINI_CLI`, `CLINE_ACTIVE`, `OPENCODE`,
  `OPENCODE_CLIENT` or `COPILOT_CLI`), in its own environment or in the environment of a
  parent process (at most 64 levels up), or when there is no terminal at all (`/dev/tty`
  cannot be opened, as in cron or `ssh -T`). There is no override: an agent can set any
  variable. Under an agent, `get` is refused. The walk reads the environment that each
  parent process had when it started. So a long-lived process that started in an agent
  session (for example a terminal multiplexer server) makes every shell under it an agent.
  The question and the `doctor` agent row name the pid and the name of that process. Start
  that process again outside the agent session.
- **The write gate.** Under an agent, `store`, `rm` and `init` ask on the terminal for the
  secret name (the store name for `init`) and go on only when it is typed exactly. A `y`
  does not confirm, and `rm --yes` still asks. secrit discards input that was typed before
  the question. With no terminal they are refused with exit 3: CI or a remote job uses
  `secrit seal`, a scheduled job runs as its own system service that reads an existing
  secret (a service has no terminal either, so it cannot write the store: unattended
  writes are not supported), and ssh uses `ssh -t`.
  No variable, config key or flag turns the gate off. It stops accidents, not an agent
  that works around it (see [What secrit does not protect
  against](#what-secrit-does-not-protect-against)). `ls`, `doctor` and `wire` work.
- **Terminal output.** `get` never writes a control character from the value to the
  terminal: it shows `\xNN` in reverse video instead. `ls` escapes names the same way.
- **The write protocol.** secrit takes a lock in `$XDG_RUNTIME_DIR/secrit/`, copies the
  ciphertext to a temp file in the same directory, runs `sops set` on the copy, checks
  the copy (recipients and sops settings unchanged, every other entry unchanged (same
  parsed value), every entry encrypted, the new entry an encrypted string, the value
  decrypts back equal), and
  renames the copy over the file. A crash leaves the original intact. A symlinked or
  hard-linked store file, a store file writable by group or others, and a store directory
  writable by group or others (unless sticky) are refused.
- **sops runs are bounded.** sops runs in its own process group with a cleared
  environment. secrit stops it when it waits for a terminal, after 120 seconds, or on
  SIGINT, SIGTERM, SIGHUP or SIGQUIT, and never leaves it running.
- **Process hardening.** No core dumps, secrit itself is not dumpable
  (`PR_SET_DUMPABLE=0`), umask 077, a panic hook that prints no payload, and
  `panic = "abort"` in release builds. This covers secrit only, not the sops child.

Known limit: a raw `sops set` or `sops edit` on the same file does not take secrit's lock.
secrit detects a change that lands before its rename and retries (at most 3 times), but
not one that lands after it.

## What works

| Command | v0.1 | Planned |
|---|---|---|
| `store`, `ls`, `rm` | Works | |
| `get` (reveal, `--stdout`) | Works | |
| `init`, `doctor`, `wire` | Works | |
| `completions bash\|fish\|zsh` | Works (hidden) | |
| home-manager module | Works | |
| pass layout store (`backend = "pass"`) | Not in v0.1 | Works on this branch (v0.2, S11) |
| `run` (memfd, masking) | Not in v0.1 | v0.2 (M6) |
| `--clip` (clipboard) | Not in v0.1 | v0.2, optional (Q4) |

## Develop

```sh
nix develop                       # Rust, sops, age, ssh-keygen, gnupg, pass, gopass, util-linux, cargo-nextest, cargo-deny
cargo nextest run --all-features  # unit, integration and terminal tests
nix flake check                   # fmt, clippy, nextest, cargo-deny, the package, the HM module
```

The integration tests run the real `sops` and `age-keygen` against a temp directory with
a temp HOME and new age keys. They find the tools through `SECRIT_TEST_SOPS`,
`SECRIT_TEST_AGE_KEYGEN` and `SECRIT_TEST_SSH_KEYGEN` (the devShell sets them), else
`PATH`. The pass tests run the real `gpg`, `pass` and `gopass` (`SECRIT_TEST_GPG`,
`SECRIT_TEST_PASS`, `SECRIT_TEST_GOPASS`) with a new `GNUPGHOME` and keys in the temp
directory. Run the integration tests inside `nix develop`, or set those variables to Nix
store paths yourself. The flake defines a devShell only for x86_64-linux, so on macOS
set the variables. Outside the devShell, `tests/common/env.rs` panics when a test tool
resolves to a mise shim. The terminal tests need util-linux `script` and `setsid`; they
fail, not skip, when those are missing. The `test-hooks` feature adds fault injection
(`SECRIT_TEST_HOOK`) for the crash and signal tests; it is never on in a release build.

## Licence

Dual-licensed under MIT ([`LICENSE-MIT`](LICENSE-MIT)) or Apache-2.0
([`LICENSE-APACHE`](LICENSE-APACHE)), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 licence, shall be dual licensed
as above, without any additional terms or conditions.
