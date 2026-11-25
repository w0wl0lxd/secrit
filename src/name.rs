//! Secret names (PLAN section 7.3).
//!
//! A name matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. The rule keeps quotes
//! and brackets out of the sops path expression `["NAME"]`, so a name cannot
//! address a nested key. Error messages never repeat the rejected text: a value
//! typed in the wrong place must not be echoed back.

use std::fmt;

/// The longest name secrit accepts, in bytes.
pub const MAX_LEN: usize = 128;

/// The sops default suffix for keys that sops leaves in cleartext.
pub const DEFAULT_UNENCRYPTED_SUFFIX: &str = "_unencrypted";

/// The top-level key that the sops file format reserves for its metadata.
pub const RESERVED: &str = "sops";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("NAME is empty")]
    Empty,
    #[error("NAME is longer than {MAX_LEN} bytes")]
    TooLong,
    #[error("NAME must start with a letter or a digit")]
    BadStart,
    #[error(
        "NAME has a character that is not allowed at position {position}; use only A-Z, a-z, 0-9, '.', '_' and '-'"
    )]
    BadChar { position: usize },
    #[error("NAME 'sops' is reserved by the sops file format")]
    Reserved,
    #[error("NAME '{name}' ends with '{suffix}', so sops would store its value in cleartext")]
    UnencryptedSuffix { name: String, suffix: String },
    #[error(
        "NAME '{name}' does not end with '{suffix}' (the file's encrypted_suffix), so sops would store its value in cleartext"
    )]
    MissingEncryptedSuffix { name: String, suffix: String },
}

/// A validated secret name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

impl Name {
    /// Validate `s` as a secret name.
    pub fn parse(s: &str) -> Result<Self, NameError> {
        let bytes = s.as_bytes();
        let Some(&first) = bytes.first() else {
            return Err(NameError::Empty);
        };
        if bytes.len() > MAX_LEN {
            return Err(NameError::TooLong);
        }
        if !first.is_ascii_alphanumeric() {
            return Err(NameError::BadStart);
        }
        if let Some(i) = bytes
            .iter()
            .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
        {
            return Err(NameError::BadChar { position: i + 1 });
        }
        if s == RESERVED {
            return Err(NameError::Reserved);
        }
        if s.ends_with(DEFAULT_UNENCRYPTED_SUFFIX) {
            return Err(NameError::UnencryptedSuffix {
                name: s.to_owned(),
                suffix: DEFAULT_UNENCRYPTED_SUFFIX.to_owned(),
            });
        }
        Ok(Self(s.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The sops path expression that addresses this top-level key.
    #[must_use]
    pub fn sops_path(&self) -> String {
        format!("[\"{}\"]", self.0)
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
            &"x".repeat(MAX_LEN),
        ] {
            assert!(Name::parse(ok).is_ok(), "{ok} should be valid");
        }
    }

    #[test]
    fn rejects_bad_names() {
        assert_eq!(Name::parse(""), Err(NameError::Empty));
        assert_eq!(
            Name::parse(&"x".repeat(MAX_LEN + 1)),
            Err(NameError::TooLong)
        );
        assert_eq!(Name::parse(".hidden"), Err(NameError::BadStart));
        assert_eq!(Name::parse("-flag"), Err(NameError::BadStart));
        assert_eq!(Name::parse("_x"), Err(NameError::BadStart));
        assert_eq!(Name::parse("a b"), Err(NameError::BadChar { position: 2 }));
        assert_eq!(Name::parse("sops"), Err(NameError::Reserved));
        assert!(matches!(
            Name::parse("token_unencrypted"),
            Err(NameError::UnencryptedSuffix { .. })
        ));
    }

    /// T15: quotes and brackets cannot reach the sops path expression.
    #[test]
    fn rejects_path_injection() {
        for bad in ["a\"][\"b", "a]", "a[0]", "a/b", "a\\b", "a'b", "é"] {
            assert!(Name::parse(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn error_does_not_echo_rejected_text() {
        let err = Name::parse("hunter2 is my password").unwrap_err();
        assert!(!err.to_string().contains("hunter2"));
    }

    #[test]
    fn sops_path_quotes_the_name() {
        let n = Name::parse("a.b-c_d").unwrap();
        assert_eq!(n.sops_path(), r#"["a.b-c_d"]"#);
    }
}
