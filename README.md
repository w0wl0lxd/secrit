# secrit

secrit is a small Rust command-line tool that stores secrets in a sops + age file that
sops-nix can read. You type `secrit store NAME`, and secrit reads the value from a no-echo
prompt or from stdin. The value never goes on the command line, never reaches the terminal
scrollback, and the write is crash-safe and lock-protected. The design is in
[`docs/PLAN.md`](docs/PLAN.md).

Status: v0.1, with v0.2 work in progress. Every v0.1 command works: `store`, `get`, `ls`,
`rm`, `init`, `doctor` and `wire`. `run` (v0.2) works on Linux (see
[What works](#what-works)). v0.2 adds a second backend: a
[Secret Service store](#secret-service-store) keeps each value as an item of
gnome-keyring, KWallet or the KeePassXC Secret Service server.

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
- **`secrit run` hands values to another program.** Masking of its output prevents
  accidents only. A program can print a value in a form that secrit does not know (T44),
  and base64 that is wrapped into lines is not matched. Masking covers stdout and stderr
  only, and the command sees pipes, not a terminal. After 100 ms of idle output secrit
  shows the bytes that it holds, so a prefix of a value can show. When the rest of the
  value follows later, the rest is masked; the prefix stays shown. While secrit masks,
  it stops the copy of the output when CMD has exited and the output stays idle for
  100 ms. A background process that CMD leaves running and that writes later gets `EPIPE`
  or `SIGPIPE`, and its output is lost. Any process of your user can read an `--env`
  value in `/proc/PID/environ` (also `ps eww` and `docker inspect`), and a `--file` value
  through `/proc/PID/fd/N` (T42, T57); masking covers neither. The memfd and `VAR` pass
  to grandchildren; `sudo` and other programs that close every fd above 2 lose `--file`
  values; memfd pages can reach swap.
- **gpg-agent (pass stores).** Any process that can use your gpg-agent can decrypt the
  entries of a pass store while the agent caches the passphrase, or at any time when the
  key has no passphrase. secrit's agent rules do not change that.
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

A Secret Service store names a collection instead of a file:

```toml
[stores.desk]
backend = "secret-service"
collection = "default"   # optional; an alias, or an object path that starts with '/'
unlock = "refuse"        # optional; "refuse" (default) or "prompt"
```

A sops key (`file`, `sops_config`, `age_key_file`, a key source of the table below, or an
`identity` table) or `wire_hint` in a Secret Service store is an error, and so is
`collection` or `unlock` in a sops store.

**Keys.** secrit runs sops with a cleared environment and `HOME=/nonexistent`, so sops
never tries `~/.ssh/id_ed25519`, `~/.ssh/id_rsa` or a key in an environment variable.
sops gets only the key sources that the store names, each one as a path:

| Store key | sops variable | Rules |
|---|---|---|
| `age_key_file` | `SOPS_AGE_KEY_FILE` | The default: `$XDG_CONFIG_HOME/sops/age/keys.txt`, when the store names no other key source. |
| `age_ssh_key_file` | `SOPS_AGE_SSH_PRIVATE_KEY_FILE` | An OpenSSH ed25519 or RSA key with no passphrase, mode 0600, not a symlink. |
| `age_key_cmd` | `SOPS_AGE_KEY_CMD` | An absolute path to an executable that prints age identities. No arguments, and no space, tab, quote, backslash or `#` in the path, because sops splits the string. The file and its directory must be yours, root's or the Nix store's, and not writable by group or others (exit 3). |
| `age_plugin_dir` | `PATH` | A directory that holds only `age-plugin-*` programs, under the same ownership rule. sops gets this directory as its only `PATH`. |

```toml
[stores.main]
backend = "sops"
file = "/etc/nixos/secrets/secrit.yaml"
age_ssh_key_file = "~/.ssh/sops_ed25519"     # optional
age_key_cmd = "~/.local/bin/sops-age-key"    # optional
age_key_cmd_timeout_secs = 20                # the default
age_plugin_dir = "~/.local/lib/age-plugins"  # optional
```

sops never gets the terminal, so a key that asks for a passphrase or a PIN fails at once,
and the message names the key source. A key command or a plugin that waits for another
reason ends after `age_key_cmd_timeout_secs` (default 20 s), not after the usual 120 s.

sops runs the key command each time it loads identities, so the command can run more than
once for one sops run (for example, a second recipient is another try), and `store`
runs sops twice (the write and the read-back check). Do not rely on a count of runs.
It runs with the environment of sops: no terminal, `HOME=/nonexistent`, and no `PATH`
(or only `age_plugin_dir` as `PATH`). So `pass`, `rbw`, `op` or `secret-tool` fail unless the command sets
its own `PATH` and `HOME`. secrit does not widen the environment for it. Use an absolute
interpreter, as in this wrapper; `doctor` warns about a `#!/usr/bin/env` line:

```sh
#!/run/current-system/sw/bin/bash
# sops-age-key: prints one age identity for sops. Mode 0700.
export PATH=/run/current-system/sw/bin HOME=/home/alice
exec secret-tool lookup service sops-age
```

**Plugin identity.** A store can name one identity in its own table instead. Then the
store must not set `age_key_file`, `age_ssh_key_file`, `age_key_cmd` or `age_plugin_dir`,
and sops gets no other key:

```toml
[stores.vault.identity]
kind = "plugin"                             # or "file", "ssh-file", "key-cmd" with `path`
stub = "~/.config/secrit/yubikey.identity"  # the identity file that the plugin wrote
plugin_dir = "~/.local/lib/age-plugins"     # holds age-plugin-yubikey
level = "touch"                             # optional; default: the strictest this build supports
touch_timeout_secs = 30                     # the default
```

For a plugin identity, secrit:

- refuses each command that decrypts when there is no `/dev/tty` (exit 3);
- refuses (exit 3) a stub file that holds a plain age key or that is larger than 16 KiB;
- writes one line to `/dev/tty` before each sops run that decrypts, for example
  `secrit: touch your key to read 'db_password' from vault (1 of 1)`;
- ends a sops run that waits longer than `touch_timeout_secs`;
- refuses (exit 3) a file with a fido2-hmac recipient of format version 2, a plain key
  that you can read as a recipient (the default age key file, `~/.ssh/id_ed25519.pub` or
  `~/.ssh/id_rsa.pub`), or a key type other than age;
- for age-plugin-yubikey, reads the slot policy from `age-plugin-yubikey --list`. A slot
  with touch policy `cached` is refused at every level. A level stricter than the slot is
  an error, not a downgrade, for example
  `level 'strict' needs PIN policy always; slot 1 on serial N has once`.

This build serves the levels up to `touch`: touch policy `always` and PIN policy `never`.
`session` and `strict` are refused after the slot check. secrit checks the slot policy of
age-plugin-yubikey only; `doctor` says when it cannot check another plugin. A fido2-hmac
key in its native X25519 form (`age1...`) looks like any other age key, so secrit cannot
refuse it.

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
  socket itself. `doctor` uses the same checks and shows a refused bus as a failed row.
- **Encryption.** secrit always opens a DH session, so the daemon sends values encrypted.
  It has no code path for a plain session.
- **A locked collection** exits 3. secrit does not open the daemon's unlock prompt unless
  the store sets `unlock = "prompt"`, and never when an agent is detected or there is no
  terminal. A gnome-keyring that started with the keyring locked shows no names, so `ls`
  exits 3 too.
- **No backup.** `store --replace` and `rm` print `no backup; the old value is gone` and
  ask for `y` on the terminal, even for you. `--yes` skips the question. Under an agent
  the typed name of [the write gate](#rules-secrit-enforces) replaces the `y`, and with no
  terminal the write gate refuses them. When the name is free, `store --replace` asks
  nothing more. If another process makes the name before secrit writes, secrit keeps that
  item and exits 3; run the command again to confirm the replace. Only `--yes` with no
  agent replaces that item; under an agent, `--yes` does not.
- **Create only.** Without `--replace`, secrit searches, creates and searches again under
  its lock, so parallel `store` runs make one item. Another program can still add an item
  with the same attributes; then `get` exits 1 and names the count.
- **Deadline.** Each daemon call has 120 seconds. SIGINT or SIGTERM during a call exits
  130 and releases the lock; the daemon can still finish that call.
- `wire` exits 3 on a Secret Service store: sops-nix cannot read it. A program reads the
  value with `secrit get --stdout NAME`.

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
secrit --store desk store tok --replace --yes   # no backup on a Secret Service store: --yes confirms

secrit ls                              # names only; decrypts nothing
secrit ls --json

secrit get github-token                # shows it on the alternate screen; any key clears it
                                       # (a screen reader or recorder can see it too)
secrit get github-token --stdout | some-cmd   # exact bytes to a pipe; refused on a terminal

secrit rm github-token                 # asks on the terminal; --yes to skip (not under an agent)

secrit run --file TOKEN_FILE=github-token -- some-cmd   # TOKEN_FILE=/dev/fd/N, a sealed memfd
secrit run --env TOKEN=github-token -- some-cmd         # the value in the environment
secrit run --pristine --file KEY=db-pass -- server      # only the --file and --env variables

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

`run` (Linux) reads every value first, then starts CMD. `--file VAR=NAME` puts the value
in a sealed memfd named `secrit` and sets `VAR=/dev/fd/N`; the command can open that path
more than once. `--env VAR=NAME` puts the value itself in `VAR` and refuses a value with a
NUL byte. `--pristine` starts CMD with only those variables. When stdout or stderr is not
a terminal, or an agent is detected, secrit stays the parent and masks the output: each
value, and its base64, URL-safe base64, hex, percent and JSON forms, becomes
`[secrit:NAME]`. A value shorter than 4 bytes is not masked, with a warning. Otherwise,
and with `--no-mask`, secrit replaces itself with CMD. Ctrl-C and Ctrl-Z reach CMD as
usual; TERM and HUP are forwarded to it. A signal that the caller ignores (`nohup`,
`trap '' HUP`) stays ignored in secrit and in CMD, and secrit does not forward it (Linux;
on other systems CMD starts with the default action). `run` exits with CMD's exit code,
or ends by the signal that ended CMD. CMD runs with the umask that secrit started with.
CMD keeps `RLIMIT_CORE=0` on purpose: it holds the values too, so it writes no core dump.
The hard limit is 0 too, so an unprivileged CMD cannot raise it.

`get --stdout` writes to a pipe, a socket or a character device. It writes to a regular
file only when the file is yours and group and others cannot read it (for example after
`umask 077`).

Exit codes: `0` success, `1` failed, `2` usage error, `3` refused by a safety rule (agent,
terminal, overwrite, name rule, an unsafe store file, store directory, config file, lock
directory, `.sops.yaml` or `sops`, a locked collection or an unsafe session bus), `4` lock
timeout or a
concurrent change, `130` a signal cancelled the command before a write took effect. `init`
keeps the files of the steps it finished; run it again to finish the setup. `run` exits
with the exit code of CMD once CMD has started.

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
  variable. Under an agent, `get`, `run --env` and `run --no-mask` are refused; `run --file`
  works and its output is always masked. The walk reads the environment that each
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
| Secret Service store (`backend = "secret-service"`) | Not in v0.1 | v0.2: works (Linux) |
| `completions bash\|fish\|zsh` | Works (hidden) | |
| home-manager module | Works | |
| pass layout store (`backend = "pass"`) | Not in v0.1 | Works on this branch (v0.2, S11) |
| `run` (memfd, masking) | Works on Linux (v0.2, S13) | `--file` needs Linux |
| `--clip` (clipboard) | Not in v0.1 | v0.2, optional (Q4) |

## Develop

```sh
nix develop                       # Rust, sops, age, ssh-keygen, gnupg, pass, gopass, util-linux, dbus, gnome-keyring, cargo-nextest, cargo-deny
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
fail, not skip, when those are missing. The Secret Service tests start a private `dbus-daemon` and
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
