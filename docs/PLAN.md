# secrit: plan for v0.1

Status: draft for review, 2026-10-06. Author: planning agent (workflow `00000000`).
Owner: w0wl0lxd. Repository: `~/dev/secrit` (private GitHub repository later; the lead creates it).

Revised 2026-10-06 after the scaffold review (findings SEC-1 to SEC-16, R1 to R15, PF-1 to
PF-5, UX-1 to UX-4, OQ-1 to OQ-3, NIX-1, NIX-2, TEST-1, CI-1, FOSS-1). Where the code and an
earlier draft disagreed, this text now follows the code. `CHANGELOG.md`, section "Changed
from docs/PLAN.md", lists each change.

## 1. Summary

`secrit` is a small Rust command-line tool. `secrit store NAME` reads a value from a no-echo
prompt or from stdin and writes it into a sops + age file that sops-nix can read. The value
never goes on argv, never reaches the terminal scrollback, and never reaches an agent
transcript by default.

The design rests on five decisions:

1. **sops is the only v0.1 backend.** secrit runs the `sops` binary by an absolute path.
   No Rust crate writes sops files safely today (section 9).
2. **secrit never edits the live file in place.** `sops set` truncates and rewrites the file
   with no lock (verified in the lab, section 17). secrit edits a ciphertext copy under a lock,
   validates it, and renames it over the original.
3. **The Nix package bakes in the absolute store paths of `sops` and `age-keygen`.** Installing
   secrit through Nix therefore installs its tools. This is the main "set it up with Nix" step.
4. **No path of this machine is in the code.** Paths come from `config.toml`. The home-manager
   module of this repository writes that file. myhost's values live in the owner's own Nix
   config, not in secrit.
5. **secrit never runs sudo, systemctl or nixos-rebuild and never edits `.nix` files.**
   `secrit wire NAME` prints the sops-nix stanza and the commands. The owner runs them.

## 2. Goals and non-goals

### Goals (v0.1)

- G1. Store a secret in one command with no value on argv: `secrit store NAME`.
- G2. Write only through a crash-safe, lock-protected protocol. No lost updates under 40
  parallel writers.
- G3. Moved to v0.2 (Q12): hand secrets to programs without printing them:
  `secrit run --file VAR=NAME -- cmd`.
- G4. List names without decrypting anything: `secrit ls`.
- G5. Set up a fresh machine: make an age key if none exists, make the sops file, write the
  config. Never overwrite an existing key or file.
- G6. Print the sops-nix wiring for a name: `secrit wire NAME`.
- G7. Stay portable: every path comes from config, so the tool can go open source later.

### Non-goals (v0.1)

- N1. **No defence against a hostile process of the same user.** Such a process can run
  `sops -d` with the user's key, read `/run/secrets/*`, or query the Secret Service.
  secrit's agent and terminal rules prevent accidents. They are not a security boundary. The
  README says this in its first section.
- N2. No `edit` command. sops issues #624, #1903 and #2104 show plaintext temp-file leaks.
- N3. No clipboard support (section 8.4 and open question Q4).
- N4. No Secret Service or KeePassXC backend in v0.1. Both are planned for v0.2 behind the
  same trait (section 6).
- N5. No binary (non-UTF-8) values in v0.1. `--binary` is planned for v0.2.
- N6. No `generate` command in v0.1. Planned for v0.2.
- N7. secrit never commits to git, never edits `.sops.yaml` that already exists, never
  edits `.nix` files, and never runs `sudo`, `systemctl` or `nixos-rebuild`.
- N8. No Windows or macOS support in v0.1. The code keeps platform calls in one module
  (`harden.rs`) so a port stays possible.

## 3. Facts this plan depends on

Every row was checked in this planning session. "Lab" means a throwaway directory under
`/home/alice/.claude/jobs/00000000/tmp/` with a temp HOME, a temp `XDG_CONFIG_HOME`, and new
age keys from `age-keygen`. No real secret was read or decrypted.

| # | Fact | How checked |
|---|---|---|
| F1 | `sops` on PATH is the mise shim `~/.local/share/mise/shims/sops`. The Nix copy is `/nix/store/ga1j9059…-sops-3.13.3/bin/sops`. | `command -v sops`, `ls /nix/store/*-sops-3.13.3` |
| F2 | sops 3.13.3 is the newest release (2026-07-23). `set --value-stdin` exists. | `gh api repos/getsops/sops/releases/latest`, `sops --version --disable-version-check` |
| F3 | `sops set` on a renamed copy (`.t.secrit-abcd.yaml`) keeps the copy's recipients and needs no `.sops.yaml`. | Lab: 2 recipients before and after |
| F4 | `sops set` on a file whose suffix is not `.yaml` fails ("Could not unmarshal input data") unless `--input-type yaml --output-type yaml` is given. | Lab |
| F5 | `sops set` with JSON `123` stores an int, not a string. secrit must always send a JSON string. | Lab |
| F6 | `sops set` overwrites an existing key with exit 0 and no warning. `sops unset` removes a key. | Lab |
| F7 | Key names with `.`, `-` and `_` work as top-level keys (`["a.b-c_d"]`). | Lab |
| F8 | `sops set` needs a key that can decrypt the data key; with a non-recipient key it fails. | Lab |
| F9 | `sops encrypt --filename-override PATH /dev/stdin` with input `{}` makes a valid empty file; `set` then works. | Lab |
| F10 | sops searches for `.sops.yaml` upward from the current directory. `--config PATH` turns the search off. secrit must always pass `--config`. | `sops --help` line 132; lab run from a subdirectory |
| F11 | `age-keygen -o PATH` refuses an existing file ("file exists") and creates mode 0600. | Lab |
| F12 | `/etc/nixos/secrets/` is `alice:users 0755`; `secrets.yaml` is `0644`, link count 1. So the user can create a temp file and rename in that directory. | `stat` (no content read) |
| F13 | `/etc/nixos/.sops.yaml` rule `secrets/.*\.yaml$` encrypts to myhost + recovery. A new `secrets/secrit.yaml` matches it and does not match the otherhost rules. | Read `.sops.yaml` (recipients redacted) |
| F14 | `/etc/nixos` is a flake. A flake does not see untracked files, so a new `secrets/secrit.yaml` needs `git add` before sops-nix can use it. | Flake semantics; `.gitignore` has no rule for `secrets/` |
| F15 | sops-nix decrypts on myhost with the key at `/persist/home/alice/.config/sops/age/keys.txt`. | `modules/nixos/base/sops.nix` |
| F16 | `set-example-key.sh` is the reference write pattern: stdin only, JSON-escape, backup, `sops set --value-stdin`, readback, restore on failure, then print the sops-nix stanza and the rebuild command. | Read the script |
| F17 | `kp-get.sh` takes `flock -w 120` on `${XDG_RUNTIME_DIR:-/tmp}/kp-get-$UID.lock`. | Read the script |
| F18 | Crate versions in section 12 are the `max_stable_version` from the crates.io API on 2026-10-06. | `curl https://crates.io/api/v1/crates/<name>` |
| F19 | `secret_service::blocking::SecretService::connect(encryption: EncryptionType)` exists in 5.2.0. | docs.rs page for 5.2.0 |
| F20 | rustix 1.1.5 has `fs::memfd_create`, `fs::renameat_with`, `process::set_dumpable_behavior`, and `mm::Advice::LinuxDontDump`. | docs.rs pages for 1.1.5 |
| F21 | crane v0.24.0 (2026-08-21) is the newest release. cargo-deny 0.20.2 is installed. | `gh api`, `command -v` |
| F22 | Local `rustc` resolves to a nightly. Stable 1.98.1 and 1.99.0 (2026-09-28) are installed under `/srv/build/rustup`. The locked nixpkgs has rustc 1.98.1, so `rust-toolchain.toml` pins `1.98.1` (R15). | `rustc --version`, `ls /srv/build/rustup/toolchains`, `nix eval --inputs-from . nixpkgs#rustc.version` |
| F23 | sops 3.13.3 runs `decrypt --extract '["NAME"]' /dev/stdin` with `HOME=/nonexistent` and prints the raw string. A passphrase-protected key (age or SSH) makes sops read `/dev/tty`, which stops a background process group with SIGTTIN. | Lab, temp keys only |

Facts taken from the research reports and not re-checked here: the 27-of-40 lost-update lab
result, the clipd and cliphist clipboard behaviour, Kitty remote control, and the
`/proc/<pid>/environ` access rule. They inform rules but no rule depends on their exact numbers.

## 4. Command set (v0.1)

Global flags, valid on every subcommand:

| Flag | Meaning |
|---|---|
| `--config PATH` | Config file. Default: `$SECRIT_CONFIG`, then `$XDG_CONFIG_HOME/secrit/config.toml`, then `~/.config/secrit/config.toml`. |
| `--store NAME` | A store from config. Default: `default_store` in config. |
| `-q`, `--quiet` | Print errors only. |

Exit codes: `0` success; `1` operation failed; `2` usage error; `3` refused by a safety rule
(agent, TTY, overwrite, name rule, an unsafe store file, store directory, config file, lock
directory, `.sops.yaml` or `sops` binary); `1` also covers a `sops` older than 3.11; `4` lock timeout or
concurrent change after 3 retries; `130` a signal cancelled the command before a write took
effect (`init` keeps the files of the steps it finished, 4.6). A name is checked before the config loads, so a bad name exits 3 even with no config
(R6).

The v0.1 command set is `store`, `get`, `ls`, `rm`, `init`, `doctor`, `wire` and the hidden
`completions`. `run` (4.5) moved to v0.2 (open question Q12), so v0.1 does not parse it.

### 4.1 `secrit store NAME`

```text
secrit store NAME [--replace] [--multiline] [--raw]
```

| Flag | Behaviour |
|---|---|
| (none) | Fail with exit 3 if NAME exists. Existence is checked by parsing the cleartext key names; nothing is decrypted. |
| `--replace` | Allow overwrite. Before the rename, copy the old ciphertext file to the backup directory (section 8.1, step 11a) and print its path. |
| `--multiline` | Allow `\n` inside the value. TTY input then reads until a line that holds only `.` (pass convention). It is asked once, not twice. |
| `--raw` | Piped input: keep the bytes exactly, including a trailing newline. Implies `--multiline`. |

Behaviour:

1. Validate NAME (section 7.3). On failure, exit 3.
2. Read the value (section 7). A TTY gets a no-echo prompt on `/dev/tty`, asked twice.
3. Run the write protocol (section 8.1).
4. Print to stderr: `stored NAME in <store> (<file>)`. Never print the value, its length, or a
   hash of it.
5. If the store has `wire_hint = true`, print one line: `run 'secrit wire NAME' to expose it at /run/secrets/NAME`.

There is no value argument and no `--value` flag. Extra positional arguments after NAME fail
with exit 2 and this fixed message, which never repeats the argument text:
`a value on the command line is already in shell history and /proc; rotate it, then pipe or type the value`.

### 4.2 `secrit get NAME`

```text
secrit get NAME [--stdout]
```

| Condition | Result |
|---|---|
| Agent detected (section 8.3) | Refuse, exit 3. No flag overrides this (open question Q5). |
| No flag, stdout is a TTY, `/dev/tty` opens | Reveal mode: switch to the alternate screen, show NAME and the value, wait for any key on `/dev/tty` (raw mode), clear the alternate screen, switch back. Nothing reaches scrollback. |
| No flag, stdout is not a TTY | Refuse, exit 3: `stdout is not a terminal; use --stdout to write the value to a pipe`. |
| `--stdout`, stdout is a pipe, a socket or a character device | Write the exact value bytes to stdout, no trailing newline. |
| `--stdout`, stdout is a regular file | Allowed only when the file is the user's own and group and others cannot read it (mode 0600); else refuse, exit 3 (SEC-3). A block device is refused. |
| `--stdout`, stdout is a TTY | Refuse, exit 3: `--stdout would leave the value in scrollback; run 'secrit get NAME' without --stdout`. |
| No `/dev/tty` (cron, `ssh -T`) | Refuse, exit 3: `there is no terminal (/dev/tty cannot be opened)`. |

The reveal-mode escape sequences are written by hand (`ESC[?1049h`, `ESC[2J`, `ESC[?1049l`).
No terminal crate is needed. The value never reaches the terminal raw: `\n` becomes `\r\n`,
tab stays, and every other control character, bidirectional override or invalid byte shows
as `\xNN` in reverse video (SEC-1). SIGINT, SIGTERM, SIGHUP and SIGQUIT during the wait clear
the screen, restore the terminal and exit 130 (SEC-13). The docs warn that Kitty remote
control and screen recorders can read the screen while the value shows.

The writes to the terminal stay blocking inside the critical section. A stopped terminal
(Ctrl-S) or a slow link can hold such a write, and a deferred signal then waits for it. That
is the safe order: nothing new shows while output is stopped, and when it resumes the wait
sees the flag within 100 ms and clears the screen. A write that gave up on the signal would
exit with value bytes already queued in the terminal or the ssh channel, and the clear
sequence must pass the same stalled channel, so the value would show later and stay. A
hang-up makes the write fail at once (EIO), and SIGKILL still ends secrit.

### 4.3 `secrit ls`

```text
secrit ls [--json]
```

Parse the encrypted YAML and print the top-level key names, sorted, one per line. Skip the
`sops` key. Decrypt nothing. `--json` prints a JSON array of strings. Names are not secret
(they are cleartext in the file and in git history); the docs say so. The plain output
escapes control characters and bidirectional overrides in a name that another tool wrote
(R5).

### 4.4 `secrit rm NAME`

```text
secrit rm NAME [--yes]
```

1. Fail with exit 1 if NAME does not exist.
2. Without `--yes`, ask `remove NAME from <file>? [y/N]` on `/dev/tty`. With no TTY and no
   `--yes`, exit 3.
3. Run the write protocol with `sops unset`. It copies the old file to the backup directory
   (section 8.1, step 11a).
4. Print: `removed NAME. git history, backups and any rendered /run/secrets copy still hold the old value; rotate it at its source if it leaked.`

### 4.5 `secrit run` (v0.2)

Built in v0.2 (slice S13). The v0.2 plan, section 7.1, replaces this section where they
differ: `--env` is refused under agent detection (Q27), `--pristine` is added, the tail
buffer gives way to the prefix-hold rule with an idle flush, and the process model of 7.1
step 5 applies.

Moved to v0.2 (milestone M6, open question Q12). The memfd sealing and the output masking need
their own design and tests. This section is the starting point for that design.

```text
secrit run [--file VAR=NAME]... [--env VAR=NAME]... [--no-mask] -- CMD [ARGS...]
```

| Flag | Behaviour |
|---|---|
| `--file VAR=NAME` | Preferred. Put the value in a sealed memfd (`memfd_create` without `MFD_CLOEXEC`, then `F_SEAL_WRITE`, `F_SEAL_GROW`, `F_SEAL_SHRINK`, `F_SEAL_SEAL`). Set `VAR=/dev/fd/N` in the child environment. The value enters no environment. |
| `--env VAR=NAME` | Set `VAR` to the value in the child environment. The docs say that any process of the same user can read `/proc/<pid>/environ` of a dumpable child. |
| `--no-mask` | Turn output masking off. Refused (exit 3) when an agent is detected. |

Behaviour:

1. At least one `--file` or `--env` is required. `VAR` must match `^[A-Za-z_][A-Za-z0-9_]*$`.
2. Decrypt each name as `get` does (section 6.2): one `sops decrypt --extract` per name, on
   the checked snapshot bytes, into a capped buffer. The earlier rule "one decrypt of the
   whole file per store" is withdrawn: parsing the whole-file JSON left unwiped copies of
   every value in `serde_json` scratch buffers (SEC-8).
3. Run CMD directly with `execvp` semantics. Never through a shell.
4. **Masking.** Masking is on when stdout or stderr is not a TTY, or when an agent is detected.
   With masking on, secrit stays as the parent. It pipes the child's stdout and stderr and
   replaces each value, its standard base64 form, its URL-safe base64 form, and its
   percent-encoded form with `[secrit:NAME]`. A tail buffer of (longest pattern - 1) bytes
   handles a match that spans two reads. Values shorter than 4 bytes are not masked, and secrit
   prints one warning for each. Signals (INT, TERM, HUP) are forwarded to the child. secrit
   exits with the child's exit code.
5. With masking off, secrit calls `execve`. The process image is replaced, so secrit keeps no
   copy of the values.

Masking prevents accidents. A child can still encode a value in a form secrit does not know.
The docs say this.

### 4.6 `secrit init`

```text
secrit init [--sops-file PATH] [--sops-config PATH] [--age-key PATH] [--write-sops-config] [--dry-run]
```

`init` is idempotent. It changes only what is missing, and it prints each step it takes.

1. **Tools.** Resolve `sops` and `age-keygen` (section 10.2). Check `sops` is 3.11 or newer
   (every command that runs sops already does this once, PF-4).
   If a tool is missing, print `nix profile add nixpkgs#sops nixpkgs#age` or the flake
   instructions, then exit 1. `init` does not install packages itself (open question Q6).
2. **Age key.** Path: `--age-key`, else config, else `$XDG_CONFIG_HOME/sops/age/keys.txt`.
   If the file exists, secrit does not touch it; it runs `age-keygen -y PATH` once to get the
   public recipient (the output is a public key). An empty key file is refused (exit 3) with
   the hint to remove it. If the file is missing, secrit creates the parent directory with
   mode 0700, runs `age-keygen -o` (mode 0600; F11) into a new mode-0700 directory next to
   PATH, fsyncs the key and renames it to PATH with `RENAME_NOREPLACE`. age-keygen creates
   its output before it writes the key, so a run stopped by a signal must not leave an empty
   file at PATH; the temp directory is removed on every path but SIGKILL. secrit prints a
   warning: back up this key; without it the secrets are lost.
3. **sops config.** Only a new sops file needs one: writes to an existing file keep its own
   recipients (F3). Path: `--sops-config`, else config, else the nearest `.sops.yaml` upward
   from the sops file's directory (not from the current directory; F10). If one exists, it
   must pass the trust rule (section 5), and sops must find a creation rule for the sops file
   (secrit asks sops to encrypt `{}` and drops the output). If no rule matches, print a rule
   snippet with the recipient on stdout and exit 1; secrit never edits an existing
   `.sops.yaml`. If none exists, print the snippet and exit 1; with `--write-sops-config`,
   create it with `O_EXCL` at the root of the git repository that holds the sops file, else
   in the sops file's directory. The snippet's `path_regex` is
   `(^|/)<sops file path relative to the .sops.yaml directory>$`, with regex characters
   escaped.
4. **sops file.** Path: `--sops-file`, else config. If the file exists, run the store-file
   checks of the write path and parse it (no decrypt). If it is missing, create its directory
   (mode 0700) when needed, then: `sops --config <cfg> encrypt --input-type json --output-type
   yaml --filename-override <path> /dev/stdin` with input `{}\n` (F9). secrit checks that the
   output has recipients, writes it to a temp file in the same directory, fsyncs it, and
   renames it with `RENAME_NOREPLACE`.
5. **Config.** If the config file is missing, write it (mode 0600, `O_EXCL`): `default_store`,
   and `backend` and `file` for the store, plus `sops_config` and `age_key_file` only when a
   flag gave them. If it exists, do not change it. When it names the store and
   `--sops-file`, `--sops-config` or `--age-key` differs from it, `init` refuses before
   step 1 (exit 2) and names the flags that differ: it would otherwise set up files that the
   config does not use. When it does not name the store, print the store's section for the
   user to add.
6. **Next steps.** On stderr: the `.gitignore` line when the repository does not ignore temp
   copies, `git -C <repo> add <file>` when the file is untracked (F14) followed by the
   reminder to exclude the file from a pre-commit spell checker (Q1), the home-manager hint
   (section 10.3), and `secrit store` then `secrit wire`.

`--dry-run` prints each step as `would: ...` and changes nothing. A signal between steps, or
during a sops, age-keygen or git child, ends `init` with exit 130; each write step is a
critical section (8.1, step 8). The message says that the files from earlier steps are kept
and that a rerun finishes the setup, because `init` is idempotent.

A `--sops-config` outside the store file's tree gets a rule with the absolute path
(`(^|/)/abs/path$`): sops 3.13.3 matches `path_regex` against the absolute path when the
file is not under the `.sops.yaml` directory (lab, 2026-10-07).

### 4.7 `secrit doctor`

```text
secrit doctor [--json]
```

Read-only: it creates, changes and decrypts nothing. One line per check,
`<status>  <check>: <detail>`, with the status `ok`, `info`, `warn` or `fail`; control
characters in paths and names are escaped. `--json` prints an array of
`{check, status, detail}`. Exit 1 if any check fails. A signal while a sops or git child
runs exits 130 and prints no rows, since the stopped child would read as a failed check.
`doctor` works without a config (the
config row fails with a pointer to `init`). It checks the store from `--store`, else every
store in the config. v0.1 has no `doctor --fix`.

| Check | Fail or warn when |
|---|---|
| sops binary | missing, or a configured path fails the trust rule (fail); older than 3.11 (fail); resolved through a mise shim or PATH (warn) |
| age-keygen | missing (warn: only `init` needs it); resolved through a mise shim or PATH (warn) |
| age identity | no key file in the configured path or the sops default path (fail); a symlink (not followed) or not a regular file, another owner, any group or other mode bit, or an empty file (fail); the `chmod` hint is shell-quoted |
| age key exposure | `SOPS_AGE_KEY` or `SOPS_AGE_KEY_CMD` is set in secrit's environment (warn) |
| `.sops.yaml` | it fails the trust rule (fail); none found (warn: writes need none, F3, but `init` needs one to create a file); no creation rule covers the store file (warn) |
| store file | missing, not a regular file, a symlink, link count > 1, owned by another uid, or writable by group or others; not a sops YAML file (fail) |
| store directory | not owned by the uid, or writable by group or others and not sticky (fail) |
| plaintext risk | the store file's sops metadata has `unencrypted_regex` or `encrypted_regex` (warn: secrit v0.1 does not write such a file); any top-level entry outside `sops` with a leaf that is not `ENC[...]` (fail; the row names the entry, never its value). The suffix rules are not a warning: sops writes `unencrypted_suffix` into every file, and the name check enforces both suffixes. |
| leftover temp files | `.*.secrit-*.yaml` older than 1 hour in the store directory (warn); younger (info: a write may be running). A SIGKILL or a crash leaves one; SIGINT, SIGTERM, SIGHUP and SIGQUIT do not. Remove them by hand when no secrit runs. |
| old backups | `*.secrit-bak.*` files in the store directory, left by a secrit before the SEC-2 fix (warn: one `git add` from history) |
| backups | the backup directory (section 8.1, step 11a) is a symlink, not mode 0700 or not owned by the uid, or holds files another user owns (fail); otherwise the count and the oldest file name (ok) |
| git ignore | the store repository does not ignore `.*.secrit-*.yaml` (warn) |
| git | the store file is untracked in a flake repository (warn, F14); untracked elsewhere, no repository, or no git (info) |
| agent | agent variables set or no `/dev/tty` (info: `get` is off) |
| hardening | `RLIMIT_CORE` could not be set to 0, or `PR_SET_DUMPABLE` could not be cleared (warn) |

`doctor` never prints secret values, key material, or hashes of values. git runs with a
cleared environment (only `HOME`), `GIT_OPTIONAL_LOCKS=0` and `core.fsmonitor=false`, through
the same bounded child runner as sops, and only for `check-ignore` and `ls-files`.

### 4.8 `secrit wire NAME`

```text
secrit wire NAME [--owner USER] [--format nix|env]
```

Print, and change nothing:

```nix
sops.secrets."NAME" = {
  sopsFile = <path relative to the configured flake root, or absolute>;
  format = "yaml";
  owner = "<USER>";   # default: the current user
};
```

`sopsFile` is `./<path>` relative to `[nix] flake` when the file is inside it, else
relative to the nearest git repository that has a `flake.nix`; a comment says the path
assumes the stanza sits at that root. Otherwise it is absolute, with a comment that pure
flake evaluation needs a path inside the flake. A path that is not a valid Nix path literal
becomes a quoted, escaped string. Nix has no `\xNN` escape, so a control character or
bidirectional control in that string is written as `${builtins.fromJSON ''"\uNNNN"''}`: it
never reaches the terminal raw, and Nix still evaluates the string to the same path. The owner must be a plain user name (`a-z`, `0-9`, `_`,
`-`, at most 32 bytes); the default is `$USER`, then `$LOGNAME`.

The stanza goes to stdout. On stderr, secrit then prints the `.gitignore` line (`echo
'.*.secrit-*.yaml' >> <repo>/.gitignore`) when the repository does not ignore temp copies,
`git -C <repo> add <file>` when the file is untracked followed by the spell-checker reminder
(Q1), and `sudo nixos-rebuild switch --flake <flake>#<host>` with `<flake>` and `<host>`
from config, each shell-quoted. secrit does not run either command. A name that is
not in the store yet gives a warning, not an error. A signal during the git query exits 130.

`--format env` prints `NAME_FILE=/run/secrets/NAME` instead, with `NAME` upper-cased and
every character outside `A-Z0-9` turned into `_`.

### 4.9 `secrit completions SHELL`

Hidden. Prints completions for `bash`, `fish` or `zsh` (clap_complete). The Nix package runs it
at build time.

## 5. Configuration

File: `$XDG_CONFIG_HOME/secrit/config.toml` (section 4 lists the search order). secrit refuses
a config file that is a symlink to a file not owned by the uid, or that is writable by group or
others. A home-manager symlink into `/nix/store` is accepted: store paths are root-owned and
read-only.

```toml
# secrit config. Every path is explicit; secrit has no built-in machine paths.
default_store = "main"

[stores.main]
backend = "sops"                      # v0.1: only "sops"
file = "/etc/nixos/secrets/secrit.yaml"
sops_config = "/etc/nixos/.sops.yaml" # optional; default: nearest .sops.yaml upward from `file`
age_key_file = "~/.config/sops/age/keys.txt" # optional; passed to sops as SOPS_AGE_KEY_FILE
wire_hint = true

[nix]                                  # used only by `secrit wire`
flake = "/etc/nixos"
host = "myhost"

[tools]
sops = "auto"        # "auto" = path baked in at build time, else PATH; or an absolute path
age_keygen = "auto"

[lock]
timeout_secs = 30
```

Rules:

- The compiled-in defaults contain only XDG-relative paths. The example above is what the
  owner's home-manager config would set on myhost; it is not in the code.
- `~` expands to `$HOME`. No other expansion. Relative paths are an error.
- Unknown keys are an error (`#[serde(deny_unknown_fields)]`), so a typo cannot silently fall
  back to a default.
- Environment overrides: `SECRIT_CONFIG` only. No `SECRIT_FILE` or similar. `SECRIT_CONFIG`
  can still point at a config that names another store file and another `sops` binary, so
  it is not hidden (SEC-10): each run that uses it prints
  `secrit: using config PATH from SECRIT_CONFIG` on stderr (not with `-q`), and a configured
  `tools.sops` and the `.sops.yaml` must pass the trust rule: owned by the uid, root or the
  Nix store, and neither the file nor its directory writable by group or others (a sticky
  directory passes). A failed trust check exits 3.

## 6. Backends

### 6.1 The trait

```rust
pub trait Backend {
    fn kind(&self) -> BackendKind;
    /// Names only. Must not decrypt.
    fn list(&self) -> Result<Vec<Name>, BackendError>;
    fn exists(&self, name: &Name) -> Result<bool, BackendError>;
    /// One locked snapshot; each name is decrypted from it.
    fn get_many(&self, names: &[Name]) -> Result<Vec<(Name, SecretValue)>, BackendError>;
    fn put(&self, name: &Name, value: &SecretValue, mode: PutMode) -> Result<PutReport, BackendError>;
    /// Returns the backup path, like `put`.
    fn remove(&self, name: &Name) -> Result<PutReport, BackendError>;
}

pub enum PutMode { CreateOnly, Replace }
```

`SecretValue` wraps `secrecy::SecretBox<Vec<u8>>`. It has no `Display`, no `Serialize`, and a
`Debug` that prints `[REDACTED]`. `Name` is a validated newtype (section 7.3).

### 6.2 sops (v0.1, default)

- Runs `sops` by absolute path with a clean environment (section 8.2).
- `list` and `exists` parse the ciphertext YAML with `serde-saphyr` and read top-level keys.
- `get_many` reads one snapshot of the file through the directory fd. It checks the
  ciphertext type tag of each wanted entry first: a non-string value (int, bool, map) is an
  error that names the key and the type, never the value. Then, for each name, it runs
  `sops --config C decrypt --input-type yaml --output-type yaml --extract '["NAME"]' /dev/stdin`
  with the snapshot bytes on stdin, and reads the raw value into a capped, zeroized buffer.
  sops never reopens the store file by path, so it decrypts the bytes that secrit checked
  (SEC-8, SEC-11). This costs one sops run per name.
- `put` and `remove` use the write protocol in section 8.1.

### 6.3 Secret Service (v0.2)

- Crate: `secret-service` 5.2 `blocking` API with `EncryptionType::Dh` (F19). The two research
  reports disagree (one names oo7). This plan picks `secret-service`: it needs no async
  runtime, and the encryption type is an explicit argument. oo7 0.6 is async only and its API
  changes before 0.7. Re-check both at v0.2.
- Attributes: `application=secrit`, `secrit-name=NAME`, so `secret-tool lookup secrit-name NAME`
  still works.
- `create_item(..., replace = false)` unless `--replace`.
- Needs a session D-Bus. Over SSH or in a headless shell, it fails with a clear message.

### 6.4 KeePassXC (v0.2 or later, opt-in)

- Shell out to `keepassxc-cli` by absolute path, following `set-example-key.sh` (F16): DB
  password and entry password on stdin; `setsid`; stop `keepassxc.service` before a write and
  restart after; timestamped backup; read back; restore on mismatch; at most 3 tries.
- Take the same lock as `kp-get` (F17), with the path from config, so secrit queues
  behind Argon2 unlocks.
- An "HMAC mismatch" error is wrong key material. Retry at most once.
- Stopping `keepassxc.service` drops the SSH agent keys for a moment (open question Q3).
- The `keepass` crate is not used: it calls its KDBX 4.1 writing experimental.

## 7. Input rules

### 7.1 Source

| stdin | Source | Rules |
|---|---|---|
| A TTY | `/dev/tty`, read by secrit with echo off | Ask twice; a mismatch fails with exit 1. One line; the newline is not stored. With `--multiline`, read lines until a line that holds only `.`, in one no-echo session, asked once. |
| Not a TTY | stdin to EOF | Strip exactly one trailing `\n` or `\r\n`, unless `--raw`. |

- No value from argv, ever. No value from an environment variable in v0.1.
- secrit reads `/dev/tty` itself in canonical mode with `ECHO` off, through `poll`, into a
  pre-sized zeroized buffer. `rpassword` is not used: it dropped tab and other control
  characters, and it restored echo between multiline lines (SEC-5, SEC-7). A tab is kept.
  The terminal limits one line to 4095 bytes; a longer line is refused. A signal during the
  prompt restores the terminal and exits 130.
- Piped input is read into a pre-allocated `Vec<u8>` with a hard cap of 64 KiB. Input past the
  cap fails with exit 1; the buffer is zeroized.

### 7.2 Content

- Empty input: refuse.
- Must be valid UTF-8 (sops `set` takes a JSON string). Non-UTF-8 fails with "binary values
  need --binary (v0.2)".
- Reject NUL and every control character except tab, and except `\n` with `--multiline` or
  `--raw` (and `\r` only as part of `\r\n` with `--raw`).
- The value is JSON-encoded as a string with `serde_json` into a `Zeroizing<Vec<u8>>` and sent
  to `sops set --value-stdin`. It is always a JSON string (F5).

### 7.3 Names

- Regex: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. This keeps quotes and brackets out of the sops
  path expression `["NAME"]`, so a name cannot address a nested key.
- Refuse `sops` (reserved by the file format).
- Refuse names that end with `_unencrypted`. The file rules come from the store file's own
  sops metadata, which `sops set` applies, not from `.sops.yaml`: refuse a name that ends
  with its `unencrypted_suffix`, or that does not end with its `encrypted_suffix` when one is
  set. sops would store such a value in cleartext. secrit v0.1 does not write a file whose
  metadata sets `unencrypted_regex` or `encrypted_regex`. `store` checks these rules before
  it reads the value, and the write protocol checks them again under the lock.

## 8. Write, read and output rules

### 8.1 The sops write protocol

Used by `store` and `rm`. secrit's own file operations are relative to one directory fd
(rustix `openat`, `renameat_with`). The sops child opens the temp copy by path (step 8);
the readback and `get` give sops the bytes on stdin instead (SEC-11).

0. Defer SIGINT, SIGTERM, SIGHUP and SIGQUIT (step 8), so a signal while secrit waits for
   the lock also exits 130 (R1).
1. Resolve the store file path once. Open its parent with `O_DIRECTORY | O_NOFOLLOW`.
2. Check the parent: owned by the uid, and not writable by group or others unless the
   sticky bit is set (SEC-4).
3. `fstatat(AT_SYMLINK_NOFOLLOW)` on the file: a regular file, owned by the uid, not writable
   by group or others, link count 1. A symlink fails (exit 3). A missing file fails with
   "create it first" and a pointer to the README.
4. Take an exclusive `flock` on `$XDG_RUNTIME_DIR/secrit/<dir dev>-<dir ino>-<name hash>.lock`
   (directory mode 0700), with the configured timeout. The key is the directory and a hash of
   the file name, not the file's inode: each write renames a new inode over the file, so an
   inode key let two writers hold "the" lock at once. The lock is taken before steps 2 and 3
   repeat on the locked file. If `XDG_RUNTIME_DIR` is unset, fail; do not fall back to `/tmp`.
   A signal stops the wait (exit 130).
5. Snapshot the original: dev, inode, size, mtime, and a SHA-256 of the ciphertext.
6. Parse the original names. For `store` without `--replace`, fail if NAME exists. For `rm`,
   fail if it does not.
7. Create `.<basename>.secrit-<random>.yaml` in the same directory with `O_EXCL | O_NOFOLLOW`,
   mode 0600, and copy the ciphertext into it. The copy holds ciphertext only.
8. SIGINT, SIGTERM, SIGHUP and SIGQUIT are deferred in secrit (the stuck-process reaper
   signals a whole process group). The stop and deferred-signal rules of this step apply
   to sops runs; the command of `run` follows v0.2 plan 7.1, step 5. Run sops in its own process group, so a group signal does
   not reach it:
   `sops --config C set --input-type yaml --output-type yaml --value-stdin COPY '["NAME"]'`
   (or `unset COPY '["NAME"]'`). The JSON-encoded value goes on stdin. Every sops run is
   bounded (R1, SEC-6):
   - secrit polls the child every 20 ms with `waitid(WEXITED | WSTOPPED | WNOHANG | WNOWAIT)`.
     A stopped child (SIGTTIN from a sops passphrase prompt on `/dev/tty`) is killed at once,
     and secrit says that passphrase-protected identities are not supported.
   - A deferred signal kills the sops process group; the command exits 130.
   - A wall-clock limit of 120 s kills the group; the command exits 1.
   - stdout is read into a capped buffer; output past the cap kills the group.
   - On every path, secrit kills the group and reaps the child before it returns (R10).
   `setsid` is not used: `CommandExt::setsid` is unstable, and a `pre_exec` hook needs
   `unsafe`, which the crate forbids. The stop detection gives the same fail-fast result.
9. Validate the copy:
   - it parses, and the `sops` block with `mac` and at least one recipient is present;
   - the recipient list equals the original's;
   - every top-level leaf outside `sops` is encrypted: each non-empty string starts with
     `ENC[`, and no number or boolean is left (sops leaves `null` and an empty string as
     they are); NAME itself must be an
     `ENC[AES256_GCM,...,type:str]` string. `store` and `rm` check the other entries before
     they read a value or ask (exit 3);
   - the set of names equals the old set plus NAME (`store`) or minus NAME (`rm`);
   - every other entry has the same parsed value as before (not a byte compare);
   - for `store`, decrypt only NAME from the copy's bytes (`decrypt --extract '["NAME"]'
     /dev/stdin`) and compare it to the input with `subtle::ConstantTimeEq`.
10. `fsync` the copy, then `fchmod` it to the original mode.
11. Snapshot the original again (dev, inode, size, mtime, mode and hash). If it changed
    since step 5, unlink the copy and retry from step 5, at most 3 times; then exit 4.
    a. Back up the original ciphertext (`store --replace` and `rm`) to
       `$XDG_STATE_HOME/secrit/backups/<id>-<basename>/<basename>.<UTC>` (directory mode
       0700, file mode 0600, fsynced), where `<id>` is a short hash of the store path. The
       backups stay out of the store repository (SEC-2, UX-1).
12. `renameat` the copy over the original. `fsync` the directory. If the rename fails,
    unlink the backup of step 11a.
13. Keep the newest 10 backups of this store and remove the rest. Release the lock.
    secrit checks for a deferred signal last just before step 11a. A signal that arrives
    after that check does not stop the write, and the command completes.

On any failure before step 12, unlink the copy and leave the original untouched. A crash or
a SIGKILL between steps 7 and 12 can leave a ciphertext-only temp file; `doctor` reports it.
The README tells the user to add `.*.secrit-*.yaml` to the store repository's `.gitignore`,
and `init` and `wire` will print that line too.

Known limit, in the docs: a raw `sops set` or `sops edit` that runs against the old file at the
same time does not take secrit's lock. secrit's step 11 detects a change that lands before the
rename, but not one that lands after it.

### 8.2 Child processes

- Run children by absolute path only (section 10.2). Never through a shell.
- Clear the child environment, then set only: `HOME=/nonexistent`,
  `SOPS_DISABLE_VERSION_CHECK=1`, and `SOPS_AGE_KEY_FILE`. The key file comes from config,
  else `$XDG_CONFIG_HOME/sops/age/keys.txt`, else `~/.config/sops/age/keys.txt` (the sops
  default, made explicit). With no usable HOME, sops cannot find `~/.ssh/id_ed25519` or
  `~/.ssh/id_rsa`, so only age key files work (R2, T19; open question Q18).
  `SOPS_AGE_KEY`, `SOPS_AGE_KEY_CMD` and the SSH key variables are never passed. secrit never
  puts key material into any environment.
- Always pass `--config` to sops (F10). With no `.sops.yaml`, pass `--config /dev/null`.
- Before the first sops run, check the `.sops.yaml` trust (section 5) and run
  `sops --version --disable-version-check` once. A sops older than 3.11 is refused (PF-4).
- Capture child stderr. Before showing it, drop every line that holds the value, its JSON
  form, or any line of the value with 4 or more bytes; escape control characters in the
  rest; show at most 20 lines, and say how many lines were dropped (SEC-15). Never echo
  child stdout of a decrypt.
- No value on any child argv. A test reads `/proc/<pid>/cmdline` of the children (section 15).

### 8.3 Agent detection

An agent is detected when any of these is true:

- one of these variables is set and not empty: `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`,
  `AI_AGENT`, `AGENT`, `CODEX_SANDBOX`, `CODEX_THREAD_ID`, `CURSOR_AGENT`, `GEMINI_CLI`,
  `CLINE_ACTIVE`, `OPENCODE_CLIENT`;
- `/dev/tty` cannot be opened.

When an agent is detected: `get` is refused (in v0.2, `run --no-mask` and `run --env` are refused and `run`
masks); `store`, `ls`, `rm --yes`, `doctor`, `wire` and `init` work. There is no override variable, because an
agent can set any variable (open question Q5). The list lives in one constant and the docs.
Whether an agent may write the store file at all is open question Q13: with the Q1 default,
`store` and `rm --yes` rewrite a file under `/etc/nixos`.

### 8.4 Output

- secrit prints status to stderr and data (`ls`, `doctor --json`) to stdout.
- No value, value length, value hash or fingerprint in any message, log, error or panic.
- `get` follows section 4.2. `run` (v0.2) follows section 4.5.
- Clipboard: none in v0.1. On myhost, clipd keeps clipboard history on disk with no
  sensitive-data handling, and the X11 bridge drops the sensitive hint (research report). A
  timed clear does not help. v0.2 may add `--clip` with `wl-copy --sensitive --paste-once` only
  if `doctor` finds no history daemon that ignores the hint (open question Q4).

### 8.5 Process hardening

At start, before reading any input:

1. `setrlimit(RLIMIT_CORE, 0)`.
2. `prctl(PR_SET_DUMPABLE, 0)` (rustix `set_dumpable_behavior`). This also stops a process of
   the same user from reading secrit's `/proc/<pid>/mem` and `environ`.
3. Set the umask to `0o077`.
4. `panic = "abort"` in the release profile; the panic hook prints a fixed message with no
   payload.
5. Deferred (open question Q14): `mlock` and `madvise(MADV_DONTDUMP)` on value buffers.
   rustix 1.1.5 exposes both as `unsafe fn`, and the crate has `unsafe_code = "forbid"`.
   v0.1 relies on small values (64 KiB cap), zeroized buffers and `RLIMIT_CORE=0`.
6. A step of 1 to 3 that fails prints one warning line (not with `-q`).
7. SIGINT, SIGTERM, SIGHUP and SIGQUIT are deferred only inside a critical section: the
   write protocol from the lock wait to the rename (section 8.1, step 0), every child run,
   every wait on the terminal or on piped stdin, a changed terminal mode, and the reveal
   screen. SIGQUIT is in the set because its default action would end secrit before the
   temp copy is removed (SEC-14). Outside these sections each signal keeps its default
   action, so a write to a stalled pipe (`get --stdout`, `ls`) or a status line cannot hold
   secrit (REG-1). No cleanup is due there: no temp copy, no child and no changed terminal
   mode exists.

Limits the docs state: a child (sops, CMD) is dumpable again after `execve`, and secrit cannot
zeroize copies inside sops (Go).

## 9. Why secrit shells out to sops

- sops-nix must decrypt the file. It pins the sops Go library (3.12.2 at the locked
  revision, research report). The files are written by sops 3.13.3.
- A native writer must match the value AAD paths, the `ENC[...]` encoding, the MAC, and the
  comment handling. `rops` 0.1.7 does not keep comments, uses deprecated `serde_yaml`, and
  reads keys from its own paths. `suminuri` is too new.
- `sops set --value-stdin` keeps the value off argv. Only the file path and `["NAME"]` appear
  on argv, and names are cleartext in the file anyway.

The `age` crate is not needed in v0.1: `age-keygen` makes the key (F11).

## 10. Nix

### 10.1 Flake layout

```text
flake.nix
  inputs:  nixpkgs (nixos-unstable), crane (v0.24)
  outputs:
    packages.<system>.default    secrit, built with crane
    apps.<system>.default        nix run path:. -- ls
    checks.<system>.*            fmt, clippy (-D warnings), nextest, cargo-deny, the package,
                                 hm-module (evaluates the module, runs secrit on its config)
    devShells.<system>.default   crane devShell + sops, age, cargo-nextest, cargo-deny,
                                 util-linux, openssh, coreutils, diffutils (test tools)
    homeManagerModules.default   programs.secrit (nix/hm-module.nix)
    overlays.default             pkgs.secrit, built from the consumer's nixpkgs
```

Systems: `x86_64-linux` only. CI builds no other system, so `aarch64-linux` comes back with an
arm runner job (CI-1). No flake-utils; a small `forAllSystems` helper.

### 10.2 Pinned tools

The crane build sets `SECRIT_SOPS_BIN = "${pkgs.sops}/bin/sops"` and
`SECRIT_AGE_KEYGEN_BIN = "${pkgs.age}/bin/age-keygen"` on the package, clippy and nextest
derivations, not on `buildDepsOnly`, so a sops or age bump does not rebuild the
dependencies (NIX-2). The code reads them with `option_env!` at compile time.
`secrit --version` prints both paths, which keeps both store paths in the binary, so the
package closure carries `age` too (NIX-1). Tool resolution for `tools.sops = "auto"`:

1. the compile-time path, if set and the file exists;
2. else the first `sops` on PATH, resolved to an absolute path with `which`, with a `doctor`
   warning.

A build-time constant cannot be changed by a variable at run time, and it avoids the mise shim
(F1). No `makeWrapper` is needed. Users outside Nix get step 2.

### 10.3 home-manager module

```nix
programs.secrit = {
  enable = true;
  package = pkgs.secrit;          # default: this flake's package, built from the consumer's nixpkgs
  settings = { ... };             # rendered with pkgs.formats.toml to xdg.configFile."secrit/config.toml"
};
```

The module installs the package and the config. The package ships the bash, fish and zsh
completions in `share/`, so no `enable*Integration` option is needed. An empty `settings`
writes no file. The config is a symlink into `/nix/store`, which the config trust rule
accepts (section 5). The module does not import the sops-nix home-manager module:
`/etc/nixos` removed user-level sops-nix because of a login race. The `hm-module` flake
check evaluates the module with stub `home.packages` and `xdg.configFile` options, and runs
the installed secrit on the generated file (PF-2).

### 10.4 What "sets it up for you" means

| Layer | What it does | Who runs it |
|---|---|---|
| Flake package | Brings pinned `sops` and `age-keygen` with secrit. | `nix profile add`, home-manager, or `nix run` |
| home-manager module | Writes `config.toml` and completions. | Owner's home-manager config |
| `secrit init` | Makes a missing age key, sops file, config; prints `.sops.yaml` snippet. | User, once per machine |
| `secrit wire NAME` | Prints the sops-nix stanza, `git add`, and the rebuild command. | User; the owner runs the printed commands |

A NixOS module that generates `sops.secrets.*` from a manifest is a later option (milestone
M6), not v0.1.

## 11. Repository layout

```text
Cargo.toml  Cargo.lock  rust-toolchain.toml (channel = "1.98.1")
deny.toml
flake.nix  flake.lock  nix/hm-module.nix
src/
  main.rs        parse, harden, dispatch, map errors to exit codes
  cli.rs         clap derive; sanitised parse errors
  config.rs      TOML, search order, path checks
  name.rs        Name newtype and rules
  secret.rs      SecretValue, input reading, JSON encoding
  agent.rs       agent detection
  harden.rs      rlimit, dumpable, umask (Linux only)
  lock.rs        flock under XDG_RUNTIME_DIR
  tools.rs       binary resolution, the --version text
  trust.rs       owner and mode checks for .sops.yaml and a configured sops
  signals.rs     INT, TERM, HUP and QUIT: deferred inside critical sections only
  tty.rs         /dev/tty prompt and key reads through poll, termios guard
  display.rs     escaping of names and revealed values
  error.rs       error type and exit codes
  child.rs       bounded child runs (process group, deadline, capped stdout, reaping)
  git.rs         read-only git queries (check-ignore, ls-files)
  backend/mod.rs     Backend trait
  backend/sops.rs    sops backend, write protocol, store-file creation, sops version check
  cmd/{mod,store,get,ls,rm,init,doctor,wire}.rs
tests/
  common/mod.rs  TestEnv harness
  cli.rs  safety.rs  setup.rs  tty.rs   integration and pty tests (std::process::Command)
docs/PLAN.md  README.md  SECURITY.md  CHANGELOG.md  LICENSE-MIT  LICENSE-APACHE
```

Planned for v0.2 and not present: `cmd/run.rs` and `mask.rs` (the streaming redactor for
`run`). `rustfmt.toml` and `clippy.toml` are not needed: the defaults and the
`[lints]` table in `Cargo.toml` hold every setting.

`clap` errors echo the offending argument text. `cli.rs` uses `try_parse` and, on an error,
prints the error kind and usage only. A test feeds `store NAME --value=hunter2` and checks
that `hunter2` is in neither stdout nor stderr.

## 12. Crates

Versions are the newest stable releases on crates.io on 2026-10-06 (F18). `Cargo.toml` uses
caret requirements at these versions; `Cargo.lock` is committed.

| Crate | Version | Use |
|---|---|---|
| clap (derive) | 4.6.7 | CLI |
| clap_complete | 4.6.11 | completions |
| serde (derive) | 1.0.229 | config |
| toml | 1.1.6 | config |
| serde_json | 1.0.151 | JSON-encode values for `sops set` |
| serde-saphyr | 1.3.0 | read ciphertext YAML key names and type tags |
| secrecy | 0.10.3 | `SecretBox<Vec<u8>>` |
| zeroize | 1.9.1 | wipe buffers |
| subtle | 2.6.1 | constant-time readback compare |
| rustix (event, fs, process, termios) | 1.1.5 | openat, renameat, flock, prctl, rlimit, waitid, kill, poll, termios |
| signal-hook | 0.4.5 | deferred INT, TERM, HUP and QUIT |
| getrandom | 0.4.3 | temp-file suffix |
| which | 8.0.6 | PATH fallback |
| sha2 | 0.11.0 | file snapshot hash, lock and backup directory names |
| thiserror | 2.0.21 | error types |

Later, with the command that needs it: `base64` (masking patterns for `run`), the rustix `mm`
feature (memfd for `run`; `mlock` waits on Q14). `insta` is not used: the `wire` and
`doctor` tests assert exact lines and `--json` rows instead (section 15.3).

Dev: tempfile 3.27.0. The integration tests drive the binary with `std::process::Command`,
so `assert_cmd`, `assert_fs` and `predicates` are not used.

Dropped during the scaffold: `rpassword` (it dropped tab and restored echo between lines;
secrit reads `/dev/tty` itself, SEC-5, SEC-7) and `anyhow` (`main` maps the typed errors to
exit codes directly).

Rejected: `rops`, `keepass`, `keyring`, `oo7` (v0.1), `arboard`, `dialoguer`, `serde_yaml`
(deprecated), `serde_yml` (RUSTSEC-2025-0068), `memsecurity`, `age` (not needed in v0.1),
`tokio` (no async in v0.1), `fs4` (rustix has `flock`).

MSRV: 1.98 (`rust-version`). `rust-toolchain.toml` pins 1.98.1, the rustc in the locked
nixpkgs (F22, R15). Edition 2024.

## 13. Threat model

Assets: secret values; integrity of the store file; the age identity; secret names (metadata,
cleartext). Adversaries: A1 another local user; A2 a process of the same user that the user
did not mean to give the value to (agent transcript, clipboard manager, terminal remote
control); A3 later readers of persistent data (history, scrollback, logs, git, backups, swap);
A4 concurrent writers; A5 the stuck-process reaper and the OOM killer.

| # | Threat | Rule | Test |
|---|---|---|---|
| T1 | Value on argv, read from `/proc/<pid>/cmdline` (A1, A3) | No value argument or flag; values reach children on stdin only (7.1, 8.2) | Spawn `store` with a sops wrapper that records its own `/proc/self/cmdline`; assert the value is absent. Extra positional fails with the fixed message. |
| T2 | clap error echoes a mistyped value (A2, A3) | Sanitised parse errors (11) | `store N --value=hunter2` and `store N hunter2`: `hunter2` absent from stdout and stderr |
| T3 | Value in terminal scrollback (A3) | `get` uses the alternate screen; `--stdout` refused on a TTY (4.2) | PTY test under `script -q` (util-linux): outside the `ESC[?1049h`..`ESC[?1049l` span, the typescript holds no value |
| T4 | Value in an agent transcript (A2) | Agent detection refuses `get`; in v0.2 it refuses `--no-mask`, and `run` masks (8.3, 4.5) | `CLAUDECODE=1 secrit get N --stdout` exits 3; `run` with a child that prints the value shows `[secrit:N]` |
| T5 | Value in a child environment (A2), v0.2 | `--file` memfd preferred; `--env` documented (4.5) | `run --file V=N -- cat $V` reads the value; `/proc/<child>/environ` has only `/dev/fd/N` |
| T6 | Core dump or ptrace read (A2, A3) | `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, `panic=abort` (8.5) | Read `/proc/<secrit pid>/status` during a blocked prompt; `prctl` read-back in a unit test |
| T7 | Value in swap (A3) | Small values and zeroized buffers (7.1). `mlock` and `MADV_DONTDUMP` are deferred (8.5, Q14) | Unit: buffer over 64 KiB refused |
| T8 | Value in logs or errors (A3) | `SecretValue` has redacted `Debug`; child stderr redacted (6.1, 8.2) | Fake sops that echoes stdin to stderr and exits 1: value absent from output |
| T9 | Lost update from concurrent writers (A4) | flock + snapshot compare + rename (8.1) | 40 parallel `store` calls, 40 names present |
| T10 | Torn file after a kill mid-write (A5) | Edit a copy; defer signals; sops in its own process group; bounded child runs; rename (8.1) | SIGKILL secrit at a test hook between steps 8 and 12: original byte-identical |
| T11 | Symlink or hard-link swap of the target (A1, A2) | `O_NOFOLLOW`, owner and mode checks, link count 1, dir-fd relative ops (8.1) | Symlinked target refused; hard-linked target refused |
| T12 | Accidental overwrite | `--replace` required; ciphertext backup (4.1) | Second `store` of a name exits 3; `--replace` makes a 0600 backup |
| T13 | Value stored in cleartext by `.sops.yaml` rules | Name rules (7.3); validation that every leaf is `ENC[` (8.1) | Name `x_unencrypted` refused; a store file whose metadata sets `unencrypted_regex` refuses every store; a cleartext entry already in the file fails validation |
| T14 | Wrong recipients (for example the otherhost key in a myhost file) | Always `--config`; recipient list compared before rename (8.1, F10) | Copy run from a directory with a different `.sops.yaml`: recipients unchanged |
| T15 | Name injection into the sops path expression | Name regex excludes quotes and brackets (7.3) | `a"]["b` refused |
| T16 | Value stored as a non-string type | Always a JSON string (7.2, F5) | Store `123`, decrypt in the test: type is string |
| T17 | Trailing newline stored by mistake | Strip one `\n` or `\r\n` on piped input unless `--raw` (7.1) | Piped `v\n` decrypts to `v`; `--raw` keeps it |
| T18 | Hijacked `sops` on PATH (mise shim, `PATH` edit) | Compile-time absolute path; warning on fallback (10.2) | Unit: resolution order; `doctor` warns on PATH fallback |
| T19 | sops picks up a different key (`SOPS_AGE_KEY`, `~/.ssh/id_ed25519`) | Clean child environment; sops gets `HOME=/nonexistent` and an explicit `SOPS_AGE_KEY_FILE` (8.2) | Tests run with a temp HOME holding a passphrase-protected decoy `~/.ssh/id_ed25519` that is not a recipient; `store` under a pty never prompts. A store encrypted only to an SSH key in HOME cannot be read through secrit, while a direct sops run with that HOME can (control) |
| T25 | sops blocks on a terminal prompt or hangs (A5) | Stop detection, a 120 s limit and signal kill on every sops run (8.1, step 8) | A fake sops that reads `/dev/tty` fails fast; a hung sops times out; a signal ends a running sops with exit 130 |
| T26 | A stored value moves the terminal off the alternate screen (A3) | Reveal escapes control characters (4.2) | PTY test with `ESC[?1049l` and an OSC 52 sequence in the value |
| T20 | Leftover ciphertext temp file in a git repository | Unlink on failure; `doctor` reports old ones (4.7) | Fault-injected sops exit: no `.secrit-*` file left |
| T21 | Clipboard history keeps the value (A2, A3) | No clipboard in v0.1 (8.4) | None in v0.1 |
| T22 | Plaintext temp files from an editor | No `edit` command (N2) | None |
| T23 | Lost age key on a fresh machine | `init` never overwrites; prints a backup warning (4.6) | `init` with an existing key leaves its bytes and mode unchanged |
| T24 | A hostile process of the same user | Out of scope (N1); docs say so | None |

## 14. Error handling

- `thiserror` enums per module; `main` maps the typed errors to exit codes (no `anyhow`,
  section 12).
- Every error message names the file, the name and the step. None holds a value.
- Exit codes as in section 4.

## 15. Test plan

All tests run under `cargo nextest run`. No test touches the real key, `/etc/nixos`, or a real
store.

### 15.1 Harness

A `TestEnv` helper (in `tests/common/mod.rs`) builds, per test:

- a temp directory (`tempfile`) holding `home/`, `config/`, `runtime/` (mode 0700),
  `store/secrets/`, a new age key from `age-keygen`, a second recipient key, `.sops.yaml`, and
  a `config.toml` that names these paths;
- a passphrase-protected decoy `home/.ssh/id_ed25519` that is not a recipient (T19);
- test tools found through `SECRIT_TEST_SOPS`, `SECRIT_TEST_AGE_KEYGEN` and
  `SECRIT_TEST_SSH_KEYGEN` (the devShell and the Nix check set them), else `PATH`;
- pty tests through util-linux `script`, and no-terminal tests through `setsid -w`. A
  missing `script` or `setsid` fails the test; it never skips silently (TEST-1, R9);
- an environment for the secrit child that is cleared, then set: `HOME`, `XDG_CONFIG_HOME`,
  `XDG_RUNTIME_DIR`, `SECRIT_CONFIG`, `PATH` (Nix store paths of sops and age only),
  `SOPS_AGE_KEY_FILE` (the temp key). `SOPS_AGE_KEY*`, `SOPS_AGE_SSH_*`,
  `DBUS_SESSION_BUS_ADDRESS` and all agent variables are removed, except where a test sets
  one on purpose.

Tests read decrypted values only from the temp store, and compare them in the test process.
No test prints a value; assertions use `assert!(a == b)` with a custom message, never
`assert_eq!` on values.

### 15.2 Unit tests

- Name rules, including `.sops.yaml` suffix and regex rules.
- Input normalisation: newline stripping, `--raw`, control characters, UTF-8, the 64 KiB cap.
- JSON encoding of values (quotes, backslashes, Unicode).
- Config parsing: unknown keys, relative paths, `~` expansion, search order.
- Agent detection matrix.
- Masking: split across reads, base64 and URL forms, short-value warning.
- Tool resolution order.
- `SecretValue` `Debug` prints `[REDACTED]`.

### 15.3 Integration tests (real sops and age in the temp env)

Each row of the threat table with a test, plus:

- `init` on an empty temp HOME creates key (0600), `.sops.yaml` (with `--write-sops-config`),
  store file, config; a second `init` changes nothing.
- `store`, `ls`, `rm` round trip; `ls` works with no key present (proves no decryption).
- `run --file` and `run --env`, exit-code passthrough, signal forwarding.
- `get --stdout` to a pipe returns the exact bytes; `get` with no TTY is refused.
- `wire` output: an exact compare of stdout with no Nix setup, and an assertion on each
  stderr hint line.
- `doctor` on a broken setup reports each failure: one sub-case per failing check, across
  the doctor tests, with assertions
  on the `--json` rows (status and check name) instead of an `insta` snapshot.

### 15.4 Fault injection

A `SECRIT_TEST_HOOK` is compiled in only under `#[cfg(feature = "test-hooks")]` (never in the
release build). It pauses or aborts at named protocol steps, so the tests for T9, T10 and T20
are deterministic.

### 15.5 Local run on this machine

```sh
mkdir -p /home/alice/.claude/jobs/<job>/tmp/secrit-cargo
ln -s /srv/build/cargo-home/registry /srv/build/cargo-home/git <that dir>/
env -u CARGO_UNSTABLE_GIT CARGO_HOME=<that dir> cargo +stable nextest run > nextest.log 2>&1; echo $?
```

`nix flake check` runs the same suite in the sandbox.

## 16. CI (GitHub Actions)

One workflow, `ci.yml`, on pull requests and pushes to `main`:

| Job | Steps |
|---|---|
| cargo | `cargo fmt --all --check`; `cargo clippy --all-targets --all-features -- -D warnings`; the same clippy without features; `cargo nextest run --all-features`; `cargo deny check` (advisories, bans, licences, sources). All through `nix develop -c` after `cachix/install-nix-action`. |
| nix | `nix flake check -L` |

The cargo gates share one job, so the devShell and the dependencies build once per run
(CI-1). A Nix store cache (cachix or magic-nix-cache) is a later step.

`deny.toml` allows MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-3-Clause and
Unicode-3.0, the licences the current dependency tree uses. Add a licence only when a new
dependency needs it. Workflow actions are pinned to commit SHAs.
`permissions: contents: read`.

## 17. Licence

`MIT OR Apache-2.0`. It matches nearly every dependency and the Rust ecosystem default, and it
allows a later open-source release with no relicensing. The repository carries both licence
files, `LICENSE-MIT` and `LICENSE-APACHE` (open question Q7). Before a public release, see
Q17 for the machine-specific text in this plan.

## 18. Milestones

| # | Content | Done when |
|---|---|---|
| M0 | Scaffold: Cargo, flake (package, devShell, checks), CI, deny, licence, README stub, SECURITY.md | `nix flake check` and CI pass on an empty `main` |
| M1 | Config, names, input, hardening, agent detection, sops backend read path, `ls`, `doctor` | `ls` and `doctor` pass integration tests |
| M2 | Write protocol, `store`, `rm`, fault-injection tests, 40-writer test | T1, T2, T8-T17, T19, T20 tests pass |
| M3 | `get` (reveal, `--stdout`) | T3, T6 and the `get` part of T4 pass |
| M4 | `init`, `wire`, home-manager module, completions | `init` round trip on an empty HOME; HM module evaluates in a `nix flake check` test |
| M5 | Owner trial on myhost with a dedicated file; README with the limits from N1 and 8.x | Owner confirms `secrit store`, `wire`, rebuild, `/run/secrets/NAME` |
| M6 (v0.2) | `run` (`--file`, `--env`, masking; section 4.5, moved from M3 by Q12), Secret Service backend, `generate`, `--binary`, optional `--clip`, optional NixOS manifest module | Separate plan; T5 and the `run` part of T4 pass |
| M7 (v0.3) | KeePassXC backend (opt-in) | Separate plan |

State on 2026-10-06: M0 to M4 are done. `store`, `ls`, `rm`, `get`, `init`, `doctor`,
`wire`, completions, the home-manager module and its check pass their tests (`tests/cli.rs`,
`tests/setup.rs`, `tests/safety.rs`, `tests/tty.rs`, and the flake checks). M5 waits on the
owner.

## 19. Settled conflicts between the research reports

| Topic | Report A | Report B | Decision |
|---|---|---|---|
| Secret Service crate | `secret-service` 5.2, blocking | `oo7` `Service::encrypted` | `secret-service` 5.2 at v0.2; no async runtime, explicit encryption (6.3) |
| Memory locking crate | rustix | `memsec` or `region` | rustix only (F20) |
| Temp copy suffix | keep `.yaml` | `.<name>.secrit-XXXX.yaml` | Both: keep `.yaml` and also pass explicit input and output types (F4) |
| Lock crate | `fs4` | flock | rustix `flock`; one crate fewer |
| Default store file | (open) | dedicated `secrets/secrit.yaml` | Dedicated file as the assumed default (Q1) |

## 20. Open questions for the owner

Each question has the default this plan assumes and the reason. The v0.2 plan,
[`PLAN-v0.2.md`](PLAN-v0.2.md), answers Q13, implements the Q18 default, and adds Q19 to
Q32 (its section 14).

| # | Question | Assumed default | Why |
|---|---|---|---|
| Q1 | Which sops file does `secrit store` write by default? | A new dedicated `/etc/nixos/secrets/secrit.yaml`, set in config, not in code. | It matches the existing myhost + recovery rule (F13), so sops-nix can wire it. It avoids `secrets.yaml`, which has other writers and an uncommitted change now. It needs one `git add` (F14). It also needs an owner change in `/etc/nixos` (OQ-1): the typos pre-commit hook (`flake-modules/checks/pre-commit.nix`) excludes only `secrets/secrets.yaml` and `secrets/otherhost-gcp.yaml`, and a lab run of typos on a 200-value sops file exited 2. Add `secrets/secrit.yaml` to that exclude list. `init` and `wire` will print this reminder next to the `git add` line. |
| Q2 | Should `store` also mirror to KeePassXC or the Secret Service, as `set-example-key` does? | No. v0.1 writes sops only. Mirroring comes with the v0.2 backends as an explicit `--also BACKEND` flag that reports each store's result. | One write path keeps the crash-safety story simple. A partial multi-store write needs its own design. |
| Q3 | When the KeePassXC backend arrives, may secrit stop and restart `keepassxc.service` (it feeds the SSH agent)? | Yes, only for a KDBX write, as `set-example-key` does, and only after a printed notice. | KeePassXC overwrites CLI changes from its stale memory copy otherwise. |
| Q4 | Clipboard support? | None in v0.1. In v0.2, `--clip` only if clipd is reconfigured or removed, or `doctor` finds no unsafe history daemon. | clipd writes history to disk and restores it after a clear. |
| Q5 | Is a hard refusal of `get` and `run --no-mask` under agent detection, with no override, acceptable? | Yes. | Any override variable is one an agent can set. The owner can run `get` in a normal terminal. |
| Q6 | Should `secrit init` install `sops` and `age` itself (for example `nix profile add`)? | No. The flake package brings them; `init` prints the command when they are missing. | Imperative profile installs conflict with home-manager on this machine and are hard to undo. |
| Q7 | Licence for the later open-source release? | `MIT OR Apache-2.0` from the first commit. | Matches the dependencies and the Rust default; no relicensing later. |
| Q8 | Repository name and place: `~/dev/secrit`, private `w0wl0lxd/secrit` on GitHub? | Yes, as the request says. | Stated in the request. |
| Q9 | Should a later version be allowed to write `.nix` files (a `hosts/<host>/secrit.nix`) behind a flag? | No in v0.1; `wire` prints only. Revisit for v0.2. | `/etc/nixos` changes are owner-gated, and printed snippets keep the owner in review. |
| Q10 | Should `secrit-egress-guard.sh` learn the patterns `secrit get` and `--stdout`? | Suggested only. It is an `/etc/nixos` change for the owner. | secrit cannot edit that file. |
| Q11 | Agents may run `secrit rm NAME --yes`. Should `rm` be refused under agent detection? | No: agents act for the owner, and `rm` keeps a ciphertext backup. | A backup makes `rm` reversible. Refusing would block the owner's own automation. Q13 asks the wider question. |
| Q12 | Does v0.1 ship `run` (PF-1)? | No: `run` moves to v0.2 (M6), and v0.1 does not parse it. `init`, `doctor` and `wire` are built (G5 and G6 met); G3 moves to v0.2. The owner can still ask for `run` in v0.1. | `run` hands values to other programs through sealed memfds and masks their output; that needs its own design and tests (T4, T5). The owner trial (M5) needs `store`, `wire` and a rebuild, not `run`. Stubs that exit 1 were an open promise in `--help`. |
| Q13 | Q9 calls `/etc/nixos` changes owner-gated, but 8.3 and Q11 let an agent run `store` and `rm --yes`, which rewrite `/etc/nixos/secrets/secrit.yaml` under the Q1 default (OQ-2). Which rule wins? | OWNER RULING 2026-10-08: (b) [ruled-by: w0wl0lxd; recorded-by: v0.2 design agent; source: the v0.2 workflow task text of 2026-10-08, not the owner's own words; the owner confirms it with PLAN-v0.2 Q19]. Under agent detection, `store` and `rm` need a confirmation typed on `/dev/tty`. With no `/dev/tty` they are refused. PLAN-v0.2 section 4 holds the rule; slice S1 builds it. The rejected choice was (a): an agent may write the store file, and Q9 narrows to `.nix` files. | (a) keeps agent automation; (b) keeps every `/etc/nixos` change in the owner's hands. A variable cannot be a gate, because an agent can set it. |
| Q14 | May secrit have one audited `unsafe` block for `mlock` and `madvise(MADV_DONTDUMP)` on value buffers (PF-3, SEC-9, R7)? | No for v0.1. The crate keeps `unsafe_code = "forbid"`; values are small, zeroized, and core dumps are off. | rustix 1.1.5 has both calls only as `unsafe fn`. A `forbid` lint is easier to audit than one exception. |
| Q15 | Where do backups go, and how many stay (UX-1, SEC-2)? | `$XDG_STATE_HOME/secrit/backups/<id>-<basename>/` (mode 0700), newest 10 per store. | Backups in the store directory sat one `git add` away from git history in `/etc/nixos`. A count cap bounds old values on disk. A config key for the place and the count can come later. |
| Q16 | How does myhost consume the private flake (OQ-3)? `github:w0wl0lxd/secrit` does not exist yet, and a private `github:` input needs a token, which root fetches during `nixos-rebuild`. | `path:/home/alice/dev/secrit` for personal use, or a `git+ssh://` input once the repository exists; home-manager over `nix profile`. The README installs with `nix profile add path:.` until then. | A `path:` or `git+ssh://` input needs no GitHub token in the Nix config. |
| Q17 | This plan holds machine-specific facts: key paths, host and recipient names, private script names, local paths, repository state (F12-F17, F22, Q1-Q4, 15.5) (FOSS-1). How do they stay out of a public release? | Before the first push to a public remote, move those facts to an uncommitted myhost note and rewrite the history, or publish a new repository from a clean first commit. | A later delete leaves the text in git history. |
| Q18 | sops gets `HOME=/nonexistent`, so it cannot use `~/.ssh/id_ed25519` or `id_rsa`, and only age key files work (R2). Should SSH identities be supported? | No in v0.1. A later version may pass `SOPS_AGE_SSH_PRIVATE_KEY_FILE` from an explicit config key. | An implicit key in HOME is the T19 threat. A passphrase-protected key also needs a terminal, which sops cannot have in a background process group. |
