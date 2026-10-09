# secrit

secrit is a small Rust command-line tool that stores secrets in a sops + age file that
sops-nix can read. You type `secrit store NAME`, and secrit reads the value from a no-echo
prompt or from stdin. The value never goes on the command line, never reaches the terminal
scrollback, and the write is crash-safe and lock-protected. The design is in
[`docs/PLAN.md`](docs/PLAN.md).

Status: v0.1. Every v0.1 command works: `store`, `get`, `ls`, `rm`, `init`, `doctor` and
`wire`. `run` moved to v0.2 (see [What works](#what-works)). v0.2 adds a second backend:
a [Secret Service store](#secret-service-store) keeps each value as an item of
gnome-keyring, KWallet or the KeePassXC Secret Service server.

## What secrit does not protect against

Read this first.

- **A hostile process of your own user.** Such a process can run `sops decrypt` with your
  key, read `/run/secrets/*`, or read your terminal. secrit's agent and terminal rules
  prevent accidents. They are not a security boundary.
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
- **Old values.** On a sops store, `rm` and `store --replace` keep a ciphertext backup in
  `$XDG_STATE_HOME/secrit/backups/` (default `~/.local/state/secrit/backups/`), the newest
  10 per store. Git history, backups and rendered `/run/secrets` copies keep old values.
  Rotate a leaked value at its source.
- **Secret Service stores.** Any process of your user that can reach the D-Bus session
  bus can read every value in an unlocked collection; it does not need secrit. A
  Secret Service store keeps no backup: `store --replace` and `rm` destroy the old value
  (secrit says so and asks first), and the daemon can keep old data in its own files.
  The value crosses the bus encrypted (a DH session), but the `secret-service` and `zbus`
  crates keep more copies in memory that secrit cannot wipe. secrit wipes its own copies.

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
backend = "sops"                              # v0.1: only "sops"
file = "/etc/nixos/secrets/secrit.yaml"       # an existing sops file
sops_config = "/etc/nixos/.sops.yaml"         # optional; default: nearest .sops.yaml upward from `file`
age_key_file = "~/.config/sops/age/keys.txt"  # optional; default: $XDG_CONFIG_HOME/sops/age/keys.txt

[tools]
sops = "auto"        # "auto" = baked-in path, else PATH; or an absolute path

[lock]
timeout_secs = 30
```

Paths must be absolute or start with `~/`. A configured `tools.sops` and the `.sops.yaml`
must be owned by you, root or the Nix store, and neither the file nor its directory may be
writable by group or others.

A Secret Service store names a collection instead of a file:

```toml
[stores.desk]
backend = "secret-service"
collection = "default"   # optional; an alias, or an object path that starts with '/'
unlock = "refuse"        # optional; "refuse" (default) or "prompt"
```

A sops key (`file`, `sops_config`, `age_key_file`) in a Secret Service store is an error,
and so is `collection` or `unlock` in a sops store.

**Keys.** secrit gives sops only an age key file (`SOPS_AGE_KEY_FILE`). sops runs with no
usable `HOME`, so it never tries `~/.ssh/id_ed25519` or `~/.ssh/id_rsa`. Age keys from SSH
keys, `SOPS_AGE_KEY` and `SOPS_AGE_KEY_CMD` are not used. A passphrase-protected key fails
at once with a clear message; sops cannot prompt.

## Set up a store

`secrit init` sets up what is missing and never replaces a file that exists:

```sh
secrit init --sops-file /etc/nixos/secrets/secrit.yaml --dry-run   # print the plan only
secrit init --sops-file /etc/nixos/secrets/secrit.yaml
secrit doctor                                                     # check the result
```

It makes an age key if there is none (back it up: without it the secrets are lost), checks
that a `.sops.yaml` creation rule covers the file, creates the empty sops file, writes the
config, and prints the `.gitignore` and `git add` steps. It never edits an existing
`.sops.yaml`: when no rule covers the file, it prints one and exits 1. With
`--write-sops-config` it creates a `.sops.yaml` when there is none. The example uses
`/etc/nixos/secrets/secrit.yaml`; any directory that you own and that group and others
cannot write works.

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
   behind (ciphertext only), then `git add` the new file. A flake (and sops-nix) cannot see
   an untracked file.

   ```sh
   echo '.*.secrit-*.yaml' >> /etc/nixos/.gitignore
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

   The value then appears at `/run/secrets/github-token`.

## Secret Service store

A Secret Service store keeps each name as one item of a collection on the D-Bus session
bus: gnome-keyring, KWallet, or KeePassXC with its Secret Service integration. secrit
needs no sops and no age key for it.

```sh
secrit init --backend secret-service --store desk   # checks the daemon, writes the config
secrit --store desk store github-token
secret-tool lookup secrit-name github-token          # libsecret reads the same item
```

`init --backend secret-service` checks that the daemon answers and that the collection
exists and is unlocked. Then it writes the config section. It creates nothing in the daemon.

- **Items.** Each item has the label `secrit: NAME` and the attributes
  `application=secrit`, `secrit-store=<store>` and `secrit-name=NAME`. Two stores in one
  collection do not see each other's items. `ls` reads the attributes only.
- **The bus.** secrit reads `DBUS_SESSION_BUS_ADDRESS`, or uses `$XDG_RUNTIME_DIR/bus`
  when it is not set. It accepts only a `unix:path=<absolute path>` address. The socket
  must be yours, in a directory that group and others cannot write (so not `/tmp`), and
  the bus daemon must run as you. Anything else exits 3. secrit connects to the checked
  socket itself.
- **Encryption.** secrit always opens a DH session, so the daemon sends values encrypted.
  It has no code path for a plain session.
- **A locked collection** exits 3. secrit does not open the daemon's unlock prompt unless
  the store sets `unlock = "prompt"`, and never when an agent is detected or there is no
  terminal. A gnome-keyring that started with the keyring locked shows no names, so `ls`
  exits 3 too.
- **No backup.** `store --replace` and `rm` print `no backup; the old value is gone` and
  ask for `y` on the terminal, even for you. `--yes` skips the question; with no terminal
  it is the only way.
- **Create only.** Without `--replace`, secrit searches, creates and searches again under
  its lock, so parallel `store` runs make one item. Another program can still add an item
  with the same attributes; then `get` exits 1 and names the count.
- **Deadline.** Each daemon call has 120 seconds. SIGINT or SIGTERM during a call exits
  130 and releases the lock; the daemon can still finish that call.
- `wire` exits 3 on a Secret Service store: sops-nix cannot read it. A program reads the
  value with `secrit get --stdout NAME`.

## Use

```sh
secrit store github-token              # no-echo prompt, asked twice
gh auth token | secrit store gh-token  # piped; one trailing newline is stripped
secrit store tls-key --multiline < key.pem
secrit store blob --raw < file         # keep the exact bytes
secrit store github-token --replace    # overwrite; keeps a ciphertext backup
secrit --store desk store tok --replace --yes   # no backup on a Secret Service store: --yes confirms

secrit ls                              # names only; decrypts nothing
secrit ls --json

secrit get github-token                # shows it on the alternate screen; any key clears it
                                       # (a screen reader or recorder can see it too)
secrit get github-token --stdout | some-cmd   # exact bytes to a pipe; refused on a terminal

secrit rm github-token                 # asks on the terminal; --yes to skip

secrit doctor                          # read-only checks; exit 1 when one fails
secrit doctor --json
secrit wire github-token               # sops-nix stanza on stdout; git and rebuild steps on stderr
secrit wire github-token --owner svc --format env   # GITHUB_TOKEN_FILE=/run/secrets/github-token
```

`doctor` checks the tools, the age key and its mode, the store file and directory, the
`.sops.yaml` rule, cleartext entries, leftover temp copies and old backups, the backup
directory, and the git state of the store file. It decrypts nothing and prints no value.

`--store NAME` picks another store from the config. `-q` prints errors only.

At the terminal prompt, a tab is kept. The terminal limits one line to 4095 bytes; pipe a
longer value. `--multiline` at the prompt reads lines until a line that holds only `.`, and
asks once, not twice.

`get --stdout` writes to a pipe, a socket or a character device. It writes to a regular
file only when the file is yours and group and others cannot read it (for example after
`umask 077`).

Exit codes: `0` success, `1` failed, `2` usage error, `3` refused by a safety rule (agent,
terminal, overwrite, name rule, an unsafe store file, store directory, config file, lock
directory, `.sops.yaml` or `sops`, a locked collection or an unsafe session bus), `4` lock
timeout or a
concurrent change, `130` a signal cancelled the command before a write took effect. `init`
keeps the files of the steps it finished; run it again to finish the setup.

### Rules secrit enforces

- **No value on the command line.** `secrit store NAME VALUE` fails with exit 2 and a
  fixed message that does not repeat the value. Parse errors never echo argument text.
- **Names** match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. `sops` is reserved. A name that
  sops would store in cleartext (the `_unencrypted` suffix, the file's
  `unencrypted_suffix` or `encrypted_suffix`) is refused. secrit v0.1 does not write a
  file whose sops metadata has `unencrypted_regex` or `encrypted_regex`.
- **Values** are UTF-8 text up to 64 KiB, with no control characters except tab (and
  newline with `--multiline` or `--raw`). They are always stored as strings.
- **Agents.** When a coding-agent variable is set and not empty (`CLAUDECODE`,
  `CLAUDE_CODE_ENTRYPOINT`, `AI_AGENT`, `AGENT`, `CODEX_SANDBOX`, `CODEX_THREAD_ID`,
  `CURSOR_AGENT`, `GEMINI_CLI`, `CLINE_ACTIVE` or `OPENCODE_CLIENT`), `get` is refused. There is no override: an agent can set any
  variable. With no terminal at all (`/dev/tty` cannot be opened, as in cron or
  `ssh -T`), `get` is also refused. `store`, `ls` and `rm --yes` work.
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
| Secret Service store (`backend = "secret-service"`) | Not in v0.1 | v0.2: works (Linux) |
| `completions bash\|fish\|zsh` | Works (hidden) | |
| home-manager module | Works | |
| `run` (memfd, masking) | Not in v0.1 | v0.2 (M6) |
| `--clip` (clipboard) | Not in v0.1 | v0.2, optional (Q4) |

## Develop

```sh
nix develop                       # Rust, sops, age, ssh-keygen, util-linux, dbus, gnome-keyring, cargo-nextest, cargo-deny
cargo nextest run --all-features  # unit, integration and terminal tests
nix flake check                   # fmt, clippy, nextest, cargo-deny, the package, the HM module
```

The integration tests run the real `sops` and `age-keygen` against a temp directory with
a temp HOME and new age keys. They find the tools through `SECRIT_TEST_SOPS`,
`SECRIT_TEST_AGE_KEYGEN` and `SECRIT_TEST_SSH_KEYGEN` (the devShell sets them), else
`PATH`. The terminal tests need util-linux `script` and `setsid`; they fail, not skip,
when those are missing. The Secret Service tests start a private `dbus-daemon` and
`gnome-keyring-daemon` per test, with a temp keyring, and read values back with
`secret-tool`. They find the tools through `SECRIT_TEST_DBUS_DAEMON`,
`SECRIT_TEST_DBUS_SEND`, `SECRIT_TEST_DBUS_CONFIG`, `SECRIT_TEST_GNOME_KEYRING` and
`SECRIT_TEST_SECRET_TOOL`, else `PATH`. They never touch your own session bus or keyring,
and they run in `nix flake check` too. The `test-hooks` feature adds fault injection
(`SECRIT_TEST_HOOK`) for the crash and signal tests; it is never on in a release build.

## Licence

Dual-licensed under MIT ([`LICENSE-MIT`](LICENSE-MIT)) or Apache-2.0
([`LICENSE-APACHE`](LICENSE-APACHE)), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 licence, shall be dual licensed
as above, without any additional terms or conditions.
