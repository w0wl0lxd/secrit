//! Secret names (PLAN section 7.3; v0.2 plan 5.4).
//!
//! A name is a key path: one or more segments joined by `/`. Each segment
//! matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, the v0.1 name grammar. A
//! name has at most [`MAX_SEGMENTS`] segments and [`MAX_LEN`] bytes. The
//! grammar keeps quotes and brackets out of the sops path expression
//! `["a"]["b"]`, so a segment cannot address another key. Error messages
//! never repeat the rejected text: a value typed in the wrong place must not
//! be echoed back.
//!
//! The rules of a store format (the reserved `sops` key, the suffix rules)
//! are not here: each backend checks them in `check_put` (v0.2 plan 5.4).
//! The grammar of a format that is narrower than a key path is here, as
//! [`Name::check_dotenv`] and [`Name::check_ini`]; the backend still
//! decides when it applies.

use std::fmt;

/// The longest name secrit accepts, in bytes, separators included.
pub const MAX_LEN: usize = 255;

/// The longest segment secrit accepts, in bytes: a v0.1 name.
pub const MAX_SEGMENT_LEN: usize = 128;

/// The most segments in one name.
pub const MAX_SEGMENTS: usize = 8;

/// The separator of the segments of a name.
pub const SEPARATOR: char = '/';

/// The sops default suffix for keys that sops leaves in cleartext.
pub const DEFAULT_UNENCRYPTED_SUFFIX: &str = "_unencrypted";

/// The top-level key that the sops file format reserves for its metadata.
pub const RESERVED: &str = "sops";

/// The prefix of the lines that sops reads as the metadata of a dotenv
/// file. sops matches it with the case as written.
pub const DOTENV_METADATA_PREFIX: &str = "sops_";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("NAME is empty")]
    Empty,
    #[error("NAME is longer than {MAX_LEN} bytes")]
    TooLong,
    #[error("NAME has more than {MAX_SEGMENTS} segments separated by '/'")]
    TooManySegments,
    #[error("NAME has an empty segment; '/' separates segments and must not lead, trail or repeat")]
    EmptySegment,
    #[error("NAME has a segment longer than {MAX_SEGMENT_LEN} bytes")]
    SegmentTooLong,
    #[error("each segment of NAME must start with a letter or a digit")]
    BadStart,
    #[error(
        "NAME has a character that is not allowed at position {position}; use only A-Z, a-z, 0-9, '.', '_', '-' and '/' between segments"
    )]
    BadChar { position: usize },
    #[error("NAME 'sops' is reserved by the sops file format")]
    Reserved,
    #[error(
        "NAME '{name}' has a segment that ends with '{suffix}', so sops would store its value in cleartext"
    )]
    UnencryptedSuffix { name: String, suffix: String },
    #[error(
        "NAME '{name}' has no segment that ends with '{suffix}' (the file's encrypted_suffix), so sops would store its value in cleartext"
    )]
    MissingEncryptedSuffix { name: String, suffix: String },
    #[error(
        "NAME must be a variable name in a dotenv store: one segment that starts with a letter or '_' and has only A-Z, a-z, 0-9 and '_'"
    )]
    NotVariable,
    #[error(
        "NAME starts with '{DOTENV_METADATA_PREFIX}', and sops reads each '{DOTENV_METADATA_PREFIX}' line of a dotenv file as its own metadata"
    )]
    MetadataPrefix,
    #[error(
        "NAME must be 'section/key' in an INI store: two segments, and each one starts with a letter or '_' and has only A-Z, a-z, 0-9 and '_'"
    )]
    NotSectionKey,
    #[error(
        "NAME is in the section '{RESERVED}', and sops keeps its own metadata in that section of an INI file"
    )]
    ReservedSection,
}

/// Whether `s` is a variable name: `^[A-Za-z_][A-Za-z0-9_]{0,127}$`, the
/// name grammar of a dotenv store (v0.2 plan 5.4).
#[must_use]
pub fn is_variable(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes
        .first()
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        && bytes.len() <= MAX_SEGMENT_LEN
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// A validated secret name: a key path of one or more segments.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

impl Name {
    /// Validate `s` as a secret name.
    pub fn parse(s: &str) -> Result<Self, NameError> {
        if s.is_empty() {
            return Err(NameError::Empty);
        }
        if s.len() > MAX_LEN {
            return Err(NameError::TooLong);
        }
        if let Some(i) = s
            .bytes()
            .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/')))
        {
            return Err(NameError::BadChar { position: i + 1 });
        }
        let mut count = 0usize;
        for segment in s.split(SEPARATOR) {
            count += 1;
            if count > MAX_SEGMENTS {
                return Err(NameError::TooManySegments);
            }
            let Some(&first) = segment.as_bytes().first() else {
                return Err(NameError::EmptySegment);
            };
            if segment.len() > MAX_SEGMENT_LEN {
                return Err(NameError::SegmentTooLong);
            }
            if !first.is_ascii_alphanumeric() {
                return Err(NameError::BadStart);
            }
        }
        Ok(Self(s.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The segments of the key path. A v0.1 name has one.
    pub fn segments(&self) -> impl Iterator<Item = &str> + Clone {
        self.0.split(SEPARATOR)
    }

    /// Whether the name has more than one segment.
    #[must_use]
    pub fn is_nested(&self) -> bool {
        self.0.contains(SEPARATOR)
    }

    /// The first `n` segments as a name: an ancestor of this name.
    /// `None` when `n` is 0 or more than the segments there are.
    #[must_use]
    pub fn prefix(&self, n: usize) -> Option<Name> {
        if n == 0 {
            return None;
        }
        let mut end = 0usize;
        for (i, segment) in self.segments().enumerate() {
            end += segment.len() + usize::from(i > 0);
            if i + 1 == n {
                return Some(Name(self.0[..end].to_owned()));
            }
        }
        None
    }

    /// The dotenv rule (v0.2 plan 5.4): one segment that is a variable
    /// name, and no `sops_` prefix. sops reads a `sops_` line back as
    /// metadata, so a value under such a name would vanish from the
    /// entries (T58).
    pub fn check_dotenv(&self) -> Result<(), NameError> {
        if self.0.starts_with(DOTENV_METADATA_PREFIX) {
            return Err(NameError::MetadataPrefix);
        }
        if !is_variable(&self.0) {
            return Err(NameError::NotVariable);
        }
        Ok(())
    }

    /// The INI rule (v0.2 plan 5.4): exactly two segments, `section/key`,
    /// each one a variable name. The section is not `sops`: sops reads
    /// that section as its metadata. sops 3.13.3 refuses a `set` of one
    /// segment, and a `set` of three writes a value that it cannot read
    /// back (S6b lab).
    pub fn check_ini(&self) -> Result<(), NameError> {
        let mut segments = self.segments();
        let (Some(section), Some(key), None) = (segments.next(), segments.next(), segments.next())
        else {
            return Err(NameError::NotSectionKey);
        };
        if section == RESERVED {
            return Err(NameError::ReservedSection);
        }
        if !is_variable(section) || !is_variable(key) {
            return Err(NameError::NotSectionKey);
        }
        Ok(())
    }

    /// The sops path expression that addresses this key: `["a"]["b"]`.
    /// The grammar admits no quote, bracket or backslash, so no segment
    /// needs escaping.
    #[must_use]
    pub fn sops_path(&self) -> String {
        let mut out = String::with_capacity(self.0.len() + 4 * MAX_SEGMENTS);
        for segment in self.segments() {
            out.push_str("[\"");
            out.push_str(segment);
            out.push_str("\"]");
        }
        out
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_names() {
        for ok in [
            "a",
            "A1",
            "api.key",
            "a.b-c_d",
            "0lead",
            "sops",
            "x_unencrypted",
            &"x".repeat(MAX_SEGMENT_LEN),
        ] {
            let n = Name::parse(ok).unwrap_or_else(|e| panic!("{ok} should be valid: {e}"));
            assert!(!n.is_nested(), "{ok}");
            assert_eq!(n.segments().collect::<Vec<_>>(), [ok]);
        }
    }

    /// v0.2 plan 5.4: each segment follows the v0.1 grammar.
    #[test]
    fn accepts_key_paths() {
        for (ok, want) in [
            ("a/b", &["a", "b"][..]),
            ("a/b/c", &["a", "b", "c"]),
            ("app/sops", &["app", "sops"]),
            ("x.y/0-z/A_b", &["x.y", "0-z", "A_b"]),
            ("a/b/c/d/e/f/g/h", &["a", "b", "c", "d", "e", "f", "g", "h"]),
        ] {
            let n = Name::parse(ok).unwrap_or_else(|e| panic!("{ok} should be valid: {e}"));
            assert!(n.is_nested(), "{ok}");
            assert_eq!(n.segments().collect::<Vec<_>>(), want);
        }
    }

    #[test]
    fn rejects_bad_names() {
        assert_eq!(Name::parse(""), Err(NameError::Empty));
        assert_eq!(
            Name::parse(&"x".repeat(MAX_SEGMENT_LEN + 1)),
            Err(NameError::SegmentTooLong)
        );
        assert_eq!(Name::parse(".hidden"), Err(NameError::BadStart));
        assert_eq!(Name::parse("-flag"), Err(NameError::BadStart));
        assert_eq!(Name::parse("_x"), Err(NameError::BadStart));
        assert_eq!(Name::parse("a b"), Err(NameError::BadChar { position: 2 }));
    }

    /// The segment grammar applies to every segment.
    #[test]
    fn every_segment_follows_the_grammar() {
        for bad in ["a/.b", "a/-b", "a/_b", "a/b/.c"] {
            assert_eq!(Name::parse(bad), Err(NameError::BadStart), "{bad}");
        }
        for bad in ["/a", "a/", "a//b", "/", "a/b/"] {
            assert_eq!(Name::parse(bad), Err(NameError::EmptySegment), "{bad}");
        }
        assert_eq!(
            Name::parse("a/b c"),
            Err(NameError::BadChar { position: 4 })
        );
        let long = format!("a/{}", "x".repeat(MAX_SEGMENT_LEN + 1));
        assert_eq!(Name::parse(&long), Err(NameError::SegmentTooLong));
        let edge = format!("a/{}", "x".repeat(MAX_SEGMENT_LEN));
        assert!(Name::parse(&edge).is_ok());
    }

    /// At most 8 segments.
    #[test]
    fn at_most_eight_segments() {
        assert!(Name::parse(&["s"; MAX_SEGMENTS].join("/")).is_ok());
        assert_eq!(
            Name::parse(&["s"; MAX_SEGMENTS + 1].join("/")),
            Err(NameError::TooManySegments)
        );
    }

    /// At most 255 bytes, separators included.
    #[test]
    fn at_most_255_bytes() {
        // Two segments of 127 bytes and one separator: 255 bytes.
        let seg = "x".repeat(127);
        let max = format!("{seg}/{seg}");
        assert_eq!(max.len(), MAX_LEN);
        assert!(Name::parse(&max).is_ok());
        let over = format!("{seg}/{seg}y");
        assert_eq!(Name::parse(&over), Err(NameError::TooLong));
        let over = format!("{}/{}", "x".repeat(MAX_SEGMENT_LEN), "x".repeat(127));
        assert_eq!(over.len(), MAX_LEN + 1);
        assert_eq!(Name::parse(&over), Err(NameError::TooLong));
    }

    /// T15: quotes and brackets cannot reach the sops path expression.
    #[test]
    fn rejects_path_injection() {
        for bad in [
            "a\"][\"b", "a]", "a[0]", "a\\b", "a'b", "é", "a/b\"]", "a/[0]",
        ] {
            assert!(Name::parse(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn error_does_not_echo_rejected_text() {
        for bad in ["hunter2 is my password", "a/hunter2 x", "a//hunter2"] {
            let err = Name::parse(bad).unwrap_err();
            assert!(!err.to_string().contains("hunter2"), "{err}");
        }
    }

    #[test]
    fn sops_path_quotes_each_segment() {
        let n = Name::parse("a.b-c_d").unwrap();
        assert_eq!(n.sops_path(), r#"["a.b-c_d"]"#);
        let n = Name::parse("a/b/c").unwrap();
        assert_eq!(n.sops_path(), r#"["a"]["b"]["c"]"#);
    }

    /// v0.2 plan 5.4: the dotenv grammar is `^[A-Za-z_][A-Za-z0-9_]{0,127}$`.
    #[test]
    fn variable_names_follow_the_dotenv_grammar() {
        let longest = "x".repeat(MAX_SEGMENT_LEN);
        for ok in ["A", "a", "_", "_x", "API_KEY", "a1_B2", longest.as_str()] {
            assert!(is_variable(ok), "{ok}");
        }
        let too_long = "x".repeat(MAX_SEGMENT_LEN + 1);
        for bad in [
            "",
            "0a",
            "a.b",
            "a-b",
            "a/b",
            "a b",
            "a=b",
            "\u{e9}",
            too_long.as_str(),
        ] {
            assert!(!is_variable(bad), "{bad}");
        }
    }

    /// T58: a dotenv name must not start with `sops_`; the match keeps
    /// the case, as sops does. The error never repeats the name.
    #[test]
    fn the_dotenv_rule_refuses_the_metadata_prefix() {
        let check = |s: &str| Name::parse(s).unwrap().check_dotenv();
        for ok in ["TOKEN", "a1_B2", "sops", "SOPS_X", "Sops_x", "xsops_y"] {
            assert_eq!(check(ok), Ok(()), "{ok}");
        }
        for bad in ["sops_x", "sops_mac", "sops_", "sops_a.b", "sops_a/b"] {
            assert_eq!(check(bad), Err(NameError::MetadataPrefix), "{bad}");
        }
        for bad in ["a.b", "a-b", "0a", "a/b", "a/sops_x"] {
            let e = check(bad).unwrap_err();
            assert_eq!(e, NameError::NotVariable, "{bad}");
            assert!(!e.to_string().contains(bad), "{e}");
        }
    }

    /// v0.2 plan 5.4: an INI name is `section/key`, each one a variable
    /// name, and the section is not `sops`. The error never repeats the
    /// name.
    #[test]
    fn the_ini_rule_takes_a_section_and_a_key() {
        let check = |s: &str| Name::parse(s).unwrap().check_ini();
        for ok in [
            "s/k",
            "DEFAULT/k",
            "app/sops",
            "SOPS/k",
            "sops_x/k",
            "A1/b_2",
        ] {
            assert_eq!(check(ok), Ok(()), "{ok}");
        }
        for bad in ["Zq9", "a/b/c", "a.b/k", "s/a-b", "0s/k", "s/0k", "s/a.b"] {
            let e = check(bad).unwrap_err();
            assert_eq!(e, NameError::NotSectionKey, "{bad}");
            assert!(!e.to_string().contains(bad), "{e}");
        }
        assert_eq!(check("sops/k"), Err(NameError::ReservedSection));
        assert_eq!(check("sops/mac"), Err(NameError::ReservedSection));
        assert_eq!(check("sops"), Err(NameError::NotSectionKey));
    }

    #[test]
    fn prefixes_are_ancestors() {
        let n = Name::parse("ab/c/def").unwrap();
        let p = |k| n.prefix(k).map(|p| p.to_string());
        assert_eq!(p(0), None);
        assert_eq!(p(1).as_deref(), Some("ab"));
        assert_eq!(p(2).as_deref(), Some("ab/c"));
        assert_eq!(p(3).as_deref(), Some("ab/c/def"));
        assert_eq!(p(4), None);
    }
}
