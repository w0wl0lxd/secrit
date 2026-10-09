//! `secrit wire NAME` (PLAN section 4.8). Prints the sops-nix wiring and the
//! commands to apply it. It changes nothing and runs neither command (N7).

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{Ctx, shell_path, shell_word};
use crate::backend::sops::SopsFormat;
use crate::backend::{BackendError, WireSource};
use crate::cli::WireFormat;
use crate::display::escape_path;
use crate::error::Error;
use crate::git::{Repo, find_root};
use crate::name::Name;

pub fn run(ctx: &Ctx, name: &Name, owner: Option<&str>, format: WireFormat) -> Result<(), Error> {
    let env = |k: &str| std::env::var_os(k);
    // Both forms point at /run/secrets/NAME, which only sops-nix fills.
    let (file, sops_format) = sops_file(ctx, name)?;
    let text = match format {
        WireFormat::Nix => {
            let owner = owner_name(owner, &env)?;
            let flake = flake_root(ctx, &file);
            nix_stanza(name, &file, sops_format, flake.as_deref(), &owner)
        }
        WireFormat::Env => env_line(name),
    };
    std::io::stdout()
        .lock()
        .write_all(text.as_bytes())
        .map_err(|e| Error::Failed(format!("could not write to stdout: {e}")))?;

    match ctx.backend.exists(name) {
        Ok(true) => {}
        Ok(false) => warn(
            ctx,
            &format!("{name} is not in the store yet; run 'secrit store {name}'"),
        ),
        Err(BackendError::NoStoreFile(p)) => {
            warn(
                ctx,
                &format!("{} does not exist yet; run 'secrit init'", escape_path(&p)),
            );
        }
        Err(e) => return Err(e.into()),
    }
    if format == WireFormat::Nix {
        next_steps(ctx, &env)?;
    }
    Ok(())
}

/// The store file that sops-nix reads, and its format (v0.2 plan 5.7).
fn sops_file(ctx: &Ctx, name: &Name) -> Result<(PathBuf, SopsFormat), Error> {
    match ctx.backend.wire_source(name) {
        Some(WireSource::SopsFile { file, format }) => Ok((file, format)),
        None => Err(Error::Refused(format!(
            "store '{}' has no sops file for sops-nix to read, and every wire format needs one",
            ctx.store.name
        ))),
    }
}

fn warn(ctx: &Ctx, msg: &str) {
    ctx.status(&format!("secrit: warning: {msg}"));
}

fn next_steps(ctx: &Ctx, env: &dyn Fn(&str) -> Option<OsString>) -> Result<(), Error> {
    let store = ctx.store.require_sops()?;
    let file = &store.file;
    if let Some(repo) = file
        .parent()
        .and_then(|d| Repo::open(d, env).ok().flatten())
    {
        if let Some(hint) = super::ignore_hint(&repo, store)? {
            ctx.status(&format!("then run: {hint}"));
        }
        let tracked = if file.exists() {
            repo.is_tracked(file)
        } else {
            Ok(true)
        };
        super::git_interrupted(&tracked)?;
        if tracked.is_ok_and(|t| !t) {
            ctx.status(&format!(
                "then run: {}",
                super::doctor::git_add_hint(&repo, file)
            ));
            ctx.status(&format!("then: {}", super::spell_hint(&repo, file)));
        }
    }
    if let Some(nix) = &ctx.nix {
        ctx.status(&format!(
            "then run: sudo nixos-rebuild switch --flake {}",
            shell_word(&format!("{}#{}", nix.flake.to_string_lossy(), nix.host))
        ));
    }
    Ok(())
}

/// `--owner`, else `$USER`, else `$LOGNAME`. The value goes into Nix text, so
/// it must be a plain user name.
fn owner_name(flag: Option<&str>, env: &dyn Fn(&str) -> Option<OsString>) -> Result<String, Error> {
    let found = flag.map(str::to_owned).or_else(|| {
        ["USER", "LOGNAME"].into_iter().find_map(|k| {
            env(k)
                .and_then(|v| v.into_string().ok())
                .filter(|v| !v.is_empty())
        })
    });
    let Some(owner) = found else {
        return Err(Error::Usage(
            "neither USER nor LOGNAME is set; pass --owner".into(),
        ));
    };
    let ok = owner.len() <= 32
        && owner
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && owner
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if ok {
        Ok(owner)
    } else {
        Err(Error::Usage(
            "the owner must be a user name: a-z, 0-9, '_' and '-', at most 32 bytes".into(),
        ))
    }
}

/// The flake that holds `file`: `[nix] flake` when the file is inside it,
/// else the nearest git repository with a `flake.nix`.
fn flake_root(ctx: &Ctx, file: &Path) -> Option<PathBuf> {
    if let Some(nix) = &ctx.nix
        && file.starts_with(&nix.flake)
    {
        return Some(nix.flake.clone());
    }
    find_root(file.parent()?).filter(|r| r.join("flake.nix").is_file())
}

/// Whether `s` can be written as a Nix path literal.
fn nix_path_ok(s: &str) -> bool {
    !s.is_empty()
        && !s.ends_with('/')
        && !s.contains("//")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._+-".contains(c))
}

/// `s` as a Nix string literal. Nix has no `\xNN` escape, so a character
/// that must not reach the terminal raw (`display::is_unsafe`) is spliced in
/// from a JSON `\uNNNN` escape: the text stays printable and Nix still
/// evaluates it to the same path.
fn nix_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '$' => out.push_str("\\$"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if crate::display::is_unsafe(c) => {
                let _ = write!(
                    out,
                    "${{builtins.fromJSON ''\"\\u{:04x}\"''}}",
                    u32::from(c)
                );
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn nix_stanza(
    name: &Name,
    file: &Path,
    format: SopsFormat,
    flake: Option<&Path>,
    owner: &str,
) -> String {
    let abs = file.to_string_lossy();
    let rel = flake
        .and_then(|f| file.strip_prefix(f).ok())
        .map(|r| format!("./{}", r.to_string_lossy()));
    let source = match (rel, flake) {
        (Some(r), Some(f)) if nix_path_ok(&r) => format!(
            "{r}; # relative to {}; adjust it to the .nix file that holds this stanza",
            escape_path(f)
        ),
        _ if nix_path_ok(&abs) => {
            format!("{abs}; # absolute; pure flake evaluation needs a path inside the flake")
        }
        _ => format!(
            "{}; # absolute; pure flake evaluation needs a path inside the flake",
            nix_string(&abs)
        ),
    };
    format!(
        "sops.secrets.\"{name}\" = {{\n  sopsFile = {source}\n  format = \"{}\";\n  owner = \"{owner}\";\n}};\n",
        format.name()
    )
}

/// `NAME_FILE=/run/secrets/NAME`, with `NAME` made a shell variable name.
fn env_line(name: &Name) -> String {
    let mut var: String = name
        .as_str()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    if var.starts_with(|c: char| c.is_ascii_digit()) {
        var.insert(0, '_');
    }
    format!(
        "{var}_FILE={}\n",
        shell_path(&Path::new("/run/secrets").join(name.as_str()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: SopsFormat = SopsFormat::Yaml;

    fn name(s: &str) -> Name {
        Name::parse(s).unwrap()
    }

    #[test]
    fn the_stanza_uses_a_flake_relative_path() {
        let s = nix_stanza(
            &name("gh-token"),
            Path::new("/etc/nixos/secrets/secrit.yaml"),
            SopsFormat::Yaml,
            Some(Path::new("/etc/nixos")),
            "alice",
        );
        assert!(s.starts_with("sops.secrets.\"gh-token\" = {\n"), "{s}");
        assert!(
            s.contains("  sopsFile = ./secrets/secrit.yaml; # relative to /etc/nixos;"),
            "{s}"
        );
        assert!(
            s.contains("  format = \"yaml\";\n  owner = \"alice\";\n};\n"),
            "{s}"
        );
    }

    #[test]
    fn the_stanza_falls_back_to_an_absolute_path() {
        let s = nix_stanza(&name("a"), Path::new("/s/x.yaml"), YAML, None, "u");
        assert!(s.contains("sopsFile = /s/x.yaml; # absolute"), "{s}");
        let s = nix_stanza(&name("a"), Path::new("/s p/${x}.yaml"), YAML, None, "u");
        assert!(
            s.contains("sopsFile = \"/s p/\\${x}.yaml\"; # absolute"),
            "{s}"
        );
        let s = nix_stanza(
            &name("a"),
            Path::new("/f/s p.yaml"),
            YAML,
            Some(Path::new("/f")),
            "u",
        );
        assert!(s.contains("sopsFile = \"/f/s p.yaml\";"), "{s}");
    }

    /// A control character in the path never reaches stdout raw, and the
    /// Nix text still names the same path.
    #[test]
    fn the_stanza_escapes_control_characters() {
        let s = nix_stanza(
            &name("a"),
            Path::new("/s/a\u{1b}]0;x\u{7}\u{202e}b.yaml"),
            YAML,
            None,
            "u",
        );
        assert!(!s.chars().any(|c| c != '\n' && c.is_control()), "{s:?}");
        assert!(!s.contains('\u{202e}'), "{s:?}");
        assert!(
            s.contains(
                "sopsFile = \"/s/a${builtins.fromJSON ''\"\\u001b\"''}]0;x${builtins.fromJSON ''\"\\u0007\"''}${builtins.fromJSON ''\"\\u202e\"''}b.yaml\"; # absolute"
            ),
            "{s}"
        );
    }

    /// The stanza names the store's format (v0.2 plan 5.7).
    #[test]
    fn the_stanza_names_the_format() {
        for format in SopsFormat::ALL {
            let s = nix_stanza(&name("a"), Path::new("/s/x"), format, None, "u");
            let want = format!("  format = \"{}\";\n", format.name());
            assert!(s.contains(&want), "{s}");
        }
        let s = nix_stanza(
            &name("a"),
            Path::new("/s/x.json"),
            SopsFormat::Json,
            None,
            "u",
        );
        assert!(s.contains("  format = \"json\";\n"), "{s}");
    }

    #[test]
    fn owners_are_checked() {
        let none = |_: &str| None;
        assert_eq!(owner_name(Some("alice"), &none).unwrap(), "alice");
        assert!(owner_name(Some("a\"; x"), &none).is_err());
        assert!(owner_name(Some("Root"), &none).is_err());
        assert!(owner_name(None, &none).is_err());
        let user = |k: &str| (k == "LOGNAME").then(|| OsString::from("bob"));
        assert_eq!(owner_name(None, &user).unwrap(), "bob");
    }

    #[test]
    fn env_lines_use_a_shell_name() {
        assert_eq!(
            env_line(&name("gh-token.v2")),
            "GH_TOKEN_V2_FILE=/run/secrets/gh-token.v2\n"
        );
        assert_eq!(env_line(&name("9x")), "_9X_FILE=/run/secrets/9x\n");
    }
}
