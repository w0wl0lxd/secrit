//! Every gpg run of the pass backend (v0.2 plan 6.4).
//!
//! gpg runs by absolute path with a cleared environment: `GNUPGHOME` only,
//! no `HOME` and no `GPG_TTY`. A value reaches gpg on stdin only. Writes
//! use public keys only, so they never need a passphrase.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

use crate::backend::sops::redact;
use crate::backend::{BackendError, Target, ToolStatus};
use crate::child::{self, ChildError, ChildOutput};
use crate::secret::MAX_VALUE_BYTES;

const TOOL: &str = "gpg";
/// gpg output that is not a value: key listings, packet listings, the
/// version, and an encrypted entry.
const MAX_LISTING_BYTES: usize = 1024 * 1024;
/// What to do when gpg stops to read the terminal.
const PROMPT_HINT: &str =
    "secrit runs gpg with --batch, so this should not happen; check gpg.conf in GNUPGHOME";
/// The gpg error text when `--pinentry-mode error` stops a passphrase prompt.
const NO_PINENTRY: &str = "No pinentry";

/// One key that a `.gpg-id` line names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// The primary key fingerprint, which the encrypt run names.
    pub fpr: String,
    /// The long key IDs of the usable encryption keys (primary or subkeys).
    pub enc_ids: BTreeSet<String>,
}

/// Why a `.gpg-id` line names no usable key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unresolved {
    Missing,
    Ambiguous,
    Unusable,
}

impl Unresolved {
    pub fn reason(self) -> &'static str {
        match self {
            Unresolved::Missing => "is not in the keyring of GNUPGHOME",
            Unresolved::Ambiguous => {
                "matches more than one usable key; put the key fingerprint in .gpg-id"
            }
            Unresolved::Unusable => "has no usable encryption key (expired, revoked or disabled)",
        }
    }
}

/// How secrit runs gpg for one store.
#[derive(Debug)]
pub struct Gpg {
    path: PathBuf,
    gnupg_home: PathBuf,
}

impl Gpg {
    pub fn new(path: PathBuf, gnupg_home: PathBuf) -> Self {
        Self { path, gnupg_home }
    }

    pub fn gnupg_home(&self) -> &Path {
        &self.gnupg_home
    }

    fn command(&self) -> Command {
        let mut c = Command::new(&self.path);
        c.env_clear()
            .env("GNUPGHOME", &self.gnupg_home)
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .args(["--batch", "--no-tty"]);
        c
    }

    fn run(
        &self,
        cmd: Command,
        stdin: Option<&[u8]>,
        stdout_cap: usize,
        step: &'static str,
        target: &Target,
    ) -> Result<ChildOutput, BackendError> {
        let timeout = child::timeout();
        child::run(cmd, stdin, stdout_cap, timeout).map_err(|e| match e {
            ChildError::Io(source) => BackendError::Io {
                step: "run",
                path: self.path.clone(),
                source,
            },
            ChildError::Interrupted => BackendError::Interrupted,
            ChildError::Stopped => BackendError::ToolPrompt {
                tool: TOOL,
                step,
                target: target.clone(),
                hint: PROMPT_HINT.into(),
            },
            ChildError::Timeout => BackendError::ToolTimeout {
                tool: TOOL,
                step,
                target: target.clone(),
                after: timeout,
            },
            ChildError::Overflow => BackendError::ToolOutputTooLarge {
                tool: TOOL,
                step,
                target: target.clone(),
            },
        })
    }

    /// The version that `gpg --version` reports.
    pub fn version(&self, target: &Target) -> Result<(u64, u64, u64), BackendError> {
        let mut cmd = self.command();
        cmd.arg("--version");
        let out = self.run(cmd, None, MAX_LISTING_BYTES, "--version", target)?;
        if !out.status.success() {
            return Err(failed("--version", target, &out, &[]));
        }
        parse_version(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| {
            BackendError::ToolTooOld {
                tool: TOOL,
                found: "an unknown version".into(),
                path: self.path.clone(),
                need: "2.2 or newer",
            }
        })
    }

    /// The key that the `.gpg-id` line `entry` names. Decrypts nothing.
    pub fn resolve(
        &self,
        entry: &str,
        target: &Target,
    ) -> Result<Result<Recipient, Unresolved>, BackendError> {
        let mut cmd = self.command();
        cmd.args(["--with-colons", "--fixed-list-mode", "--list-keys", "--"])
            .arg(entry);
        let out = self.run(cmd, None, MAX_LISTING_BYTES, "--list-keys", target)?;
        let keys = parse_keys(&String::from_utf8_lossy(&out.stdout));
        if keys.is_empty() {
            return if out.status.success() || out.status.code() == Some(2) {
                Ok(Err(Unresolved::Missing))
            } else {
                Err(failed("--list-keys", target, &out, &[]))
            };
        }
        let usable: Vec<Recipient> = keys.into_iter().filter(|k| !k.enc_ids.is_empty()).collect();
        match usable.len() {
            0 => Ok(Err(Unresolved::Unusable)),
            1 => Ok(usable.into_iter().next().ok_or(Unresolved::Unusable)),
            _ => Ok(Err(Unresolved::Ambiguous)),
        }
    }

    /// The entry bytes for `plaintext`, encrypted to `recipients` only:
    /// `--no-encrypt-to` drops the `encrypt-to` recipients of `gpg.conf`.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        recipients: &[Recipient],
        value: &[u8],
        target: &Target,
    ) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        let mut cmd = self.command();
        cmd.args([
            "--quiet",
            "--yes",
            "--compress-algo=none",
            "--no-encrypt-to",
            "--no-throw-keyids",
            "--no-armor",
            "--trust-model",
            "always",
            "--encrypt",
        ]);
        for r in recipients {
            cmd.arg("--recipient").arg(&r.fpr);
        }
        cmd.args(["--output", "-"]);
        let cap = plaintext.len() + MAX_LISTING_BYTES;
        let out = self.run(cmd, Some(plaintext), cap, "encrypt", target)?;
        if !out.status.success() {
            return Err(failed("encrypt", target, &out, &[value, plaintext]));
        }
        Ok(out.stdout)
    }

    /// The key IDs of the public-key session packets of `entry`, and
    /// whether it also has a passphrase (symmetric) packet. Decrypts
    /// nothing (V25).
    pub fn packets(
        &self,
        entry: &[u8],
        target: &Target,
    ) -> Result<(BTreeSet<String>, bool), BackendError> {
        let mut cmd = self.command();
        cmd.args(["--list-only", "--list-packets"]);
        let out = self.run(
            cmd,
            Some(entry),
            MAX_LISTING_BYTES,
            "--list-packets",
            target,
        )?;
        if !out.status.success() {
            return Err(failed("--list-packets", target, &out, &[]));
        }
        Ok(parse_packets(&String::from_utf8_lossy(&out.stdout)))
    }

    /// The decrypted bytes of `entry`. With `pinentry` false, gpg runs with
    /// `--pinentry-mode error`, so a needed passphrase fails at once.
    pub fn decrypt(
        &self,
        entry: &[u8],
        pinentry: bool,
        target: &Target,
    ) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        let mut cmd = self.command();
        cmd.arg("--quiet");
        if !pinentry {
            cmd.args(["--pinentry-mode", "error"]);
        }
        cmd.args(["--decrypt", "--output", "-"]);
        // The value, its newline and the metadata lines of a pass entry.
        let out = self.run(cmd, Some(entry), MAX_VALUE_BYTES + 1, "decrypt", target)?;
        if !out.status.success() {
            if !pinentry && String::from_utf8_lossy(&out.stderr).contains(NO_PINENTRY) {
                return Err(BackendError::NeedsPassphrase {
                    target: target.clone(),
                });
            }
            return Err(failed("decrypt", target, &out, &[&out.stdout]));
        }
        Ok(out.stdout)
    }
}

/// The error of a gpg run that exited with a failure. Its stderr is
/// redacted against `secrets`.
fn failed(
    step: &'static str,
    target: &Target,
    out: &ChildOutput,
    secrets: &[&[u8]],
) -> BackendError {
    BackendError::Tool {
        tool: TOOL,
        step,
        target: target.clone(),
        status: ToolStatus(out.status.code()),
        stderr: redact(&out.stderr, secrets),
    }
}

/// `gpg (GnuPG) 2.4.9` on the first line.
fn parse_version(text: &str) -> Option<(u64, u64, u64)> {
    let word = text.lines().next()?.split_whitespace().last()?;
    let mut parts = word.splitn(3, '.');
    let mut next = || -> Option<u64> {
        let digits: String = parts
            .next()?
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    };
    Some((next()?, next()?, next()?))
}

/// A key that is not invalid, disabled, revoked or expired.
fn valid(validity: &str) -> bool {
    !matches!(validity, "i" | "d" | "r" | "e")
}

/// The keys of a `--with-colons` listing. Only the usable encryption keys
/// of a usable primary key count; field numbers follow gpg's
/// `doc/DETAILS`.
fn parse_keys(text: &str) -> Vec<Recipient> {
    let mut keys: Vec<Recipient> = Vec::new();
    // Whether the current primary key is usable, and whether the last
    // record was a primary key (its fpr record follows).
    let mut usable = false;
    let mut want_fpr = false;
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        let field = |i: usize| f.get(i).copied().unwrap_or("");
        match field(0) {
            "pub" => {
                usable = valid(field(1)) && field(11).contains('E');
                want_fpr = true;
                keys.push(Recipient {
                    fpr: String::new(),
                    enc_ids: BTreeSet::new(),
                });
                if usable
                    && field(11).contains('e')
                    && let Some(k) = keys.last_mut()
                {
                    k.enc_ids.insert(field(4).to_ascii_uppercase());
                }
            }
            "fpr" if want_fpr => {
                want_fpr = false;
                if let Some(k) = keys.last_mut() {
                    field(9).clone_into(&mut k.fpr);
                }
            }
            "sub" => {
                want_fpr = false;
                if usable
                    && valid(field(1))
                    && field(11).contains('e')
                    && let Some(k) = keys.last_mut()
                {
                    k.enc_ids.insert(field(4).to_ascii_uppercase());
                }
            }
            "fpr" | "grp" | "uid" | "uat" | "tru" | "rvk" | "rvs" | "sig" | "cfg" => {}
            _ => want_fpr = false,
        }
    }
    keys.retain(|k| !k.fpr.is_empty() && k.fpr.chars().all(|c| c.is_ascii_hexdigit()));
    keys
}

/// The key IDs of `:pubkey enc packet:` lines, and whether a
/// `:symkey enc packet:` line occurs.
fn parse_packets(text: &str) -> (BTreeSet<String>, bool) {
    let mut ids = BTreeSet::new();
    let mut symkey = false;
    for line in text.lines() {
        if line.starts_with(":symkey enc packet:") {
            symkey = true;
        } else if line.starts_with(":pubkey enc packet:")
            && let Some(id) = line.rsplit("keyid ").next()
        {
            ids.insert(id.trim().to_ascii_uppercase());
        }
    }
    (ids, symkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "\
tru::1:1700000000:0:3:1:5
pub:u:255:22:AF395AF27F1BFE02:1700000000:::u:::scESC:::::ed25519:::0:
fpr:::::::::D29688D1CE547AA5C8AEF7F3AF395AF27F1BFE02:
uid:u::::1700000000::HASH::secrit test <a@secrit.test>::::::::::0:
sub:u:255:18:1111111111111111:1700000000::::::e:::::cv25519::
fpr:::::::::AAAA1111111111111111:
sub:e:255:18:2222222222222222:1600000000:1650000000:::::e:::::cv25519::
fpr:::::::::BBBB2222222222222222:
sub:u:255:22:3333333333333333:1700000000::::::s:::::ed25519::
fpr:::::::::CCCC3333333333333333:
";

    #[test]
    fn a_listing_gives_the_fingerprint_and_the_usable_encryption_keys() {
        let keys = parse_keys(LISTING);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fpr, "D29688D1CE547AA5C8AEF7F3AF395AF27F1BFE02");
        assert_eq!(
            keys[0].enc_ids.iter().collect::<Vec<_>>(),
            ["1111111111111111"]
        );

        let revoked = LISTING.replace("pub:u:", "pub:r:");
        assert!(parse_keys(&revoked)[0].enc_ids.is_empty());
        let no_e = LISTING.replace("scESC", "scSC");
        assert!(parse_keys(&no_e)[0].enc_ids.is_empty());
        let two = format!("{LISTING}{}", LISTING.replace("D29688", "E29688"));
        assert_eq!(parse_keys(&two).len(), 2);
    }

    #[test]
    fn packets_give_key_ids_and_a_passphrase_packet() {
        let text = "\
# off=0 ctb=84 tag=1 hlen=2 plen=94
:pubkey enc packet: version 3, algo 18, keyid 1111111111111111
\tdata: [263 bits]
:pubkey enc packet: version 3, algo 18, keyid 2222222222222222
";
        let (ids, sym) = parse_packets(text);
        assert_eq!(
            ids.into_iter().collect::<Vec<_>>(),
            ["1111111111111111", "2222222222222222"]
        );
        assert!(!sym);
        let (_, sym) = parse_packets(":symkey enc packet: version 4, cipher 9\n");
        assert!(sym);
    }

    #[test]
    fn gpg_versions_parse() {
        assert_eq!(
            parse_version("gpg (GnuPG) 2.4.9\nlibgcrypt 1.11.2\n"),
            Some((2, 4, 9))
        );
        assert_eq!(parse_version("gpg (GnuPG) 2.2.41-beta\n"), Some((2, 2, 41)));
        assert_eq!(parse_version("nothing\n"), None);
    }
}
