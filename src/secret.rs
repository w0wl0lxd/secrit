//! Secret values and input reading (PLAN sections 6.1, 7.1 and 7.2).
//!
//! A [`SecretValue`] has no `Display` and no `Serialize`, and its `Debug`
//! prints `[REDACTED]`. Every buffer that holds a value is zeroized on drop.

use std::fmt;
use std::io::{self, IsTerminal, Read};

use secrecy::{ExposeSecret, SecretBox};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::name::Name;
use crate::tty;

/// The largest value secrit accepts, in bytes.
pub const MAX_VALUE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InputError {
    #[error("the value is empty; nothing was stored")]
    Empty,
    #[error("the value is larger than {MAX_VALUE_BYTES} bytes")]
    TooLarge,
    #[error("the value is not valid UTF-8; binary values need --binary (v0.2)")]
    NotUtf8,
    #[error("the value has a newline; use --multiline (or --raw for piped input)")]
    NewlineNeedsMultiline,
    #[error(
        "the value has a control character; only tab, and newline with --multiline or --raw, are allowed"
    )]
    ControlChar,
    #[error("the two entries do not match; nothing was stored")]
    Mismatch,
    #[error(
        "a line at the terminal prompt is too long ({} bytes or more), so the terminal may have cut it; pipe the value instead",
        tty::CANON_LINE_MAX
    )]
    TtyLineTooLong,
    #[error("interrupted by a signal; nothing was stored")]
    Interrupted,
    #[error("could not read the value: {0}")]
    Io(String),
}

impl From<tty::ReadError> for InputError {
    fn from(e: tty::ReadError) -> Self {
        match e {
            tty::ReadError::Interrupted => InputError::Interrupted,
            tty::ReadError::BufferFull => InputError::TooLarge,
            tty::ReadError::LineTooLong => InputError::TtyLineTooLong,
            tty::ReadError::Io(e) => e.into(),
        }
    }
}

impl From<io::Error> for InputError {
    fn from(e: io::Error) -> Self {
        // io::Error messages come from the OS, never from the value.
        InputError::Io(e.kind().to_string())
    }
}

/// A secret value. The bytes live in a [`SecretBox`] and are zeroized on drop.
pub struct SecretValue(SecretBox<Vec<u8>>);

impl SecretValue {
    /// Take ownership of `bytes` without copying them.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    /// The value bytes. Callers must not log, print or format them.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Compare with `other` in constant time (for equal lengths).
    #[must_use]
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        self.expose().ct_eq(other).into()
    }

    /// Encode the value as a JSON string, for `sops set --value-stdin`.
    ///
    /// The value is always a JSON string, never a number or a boolean (F5).
    pub fn to_json_string(&self) -> Result<Zeroizing<Vec<u8>>, InputError> {
        let s = std::str::from_utf8(self.expose()).map_err(|_| InputError::NotUtf8)?;
        // Escaping at most doubles the allowed characters (tab, newline, CR,
        // quote, backslash); reserve that much so the buffer never reallocates
        // and leaves an unzeroized copy behind.
        let mut out = Zeroizing::new(Vec::with_capacity(s.len() * 2 + 2));
        serde_json::to_writer(&mut *out, s)
            .map_err(|_| InputError::Io("JSON encoding failed".into()))?;
        Ok(out)
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

/// How `store` treats newlines in the input.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InputMode {
    /// Allow `\n` inside the value.
    pub multiline: bool,
    /// Keep piped bytes exactly, including a trailing newline. Implies `multiline`.
    pub raw: bool,
}

impl InputMode {
    fn allows_newline(self) -> bool {
        self.multiline || self.raw
    }
}

/// Read the value: a no-echo prompt on `/dev/tty` when stdin is a terminal,
/// else stdin to EOF. Both wait in `poll`, so a deferred signal stops them.
pub fn read_value(name: &Name, mode: InputMode) -> Result<SecretValue, InputError> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        read_from_tty(name, mode)
    } else {
        let mut wait = || tty::wait_readable(io::stdin()).map_err(InputError::from);
        read_piped(&mut stdin.lock(), mode, &mut wait)
    }
}

/// Read piped input: at most [`MAX_VALUE_BYTES`], one trailing `\n` or
/// `\r\n` stripped unless `mode.raw`.
#[cfg(test)]
pub fn read_from_reader(
    reader: &mut impl Read,
    mode: InputMode,
) -> Result<SecretValue, InputError> {
    read_piped(reader, mode, &mut || Ok(()))
}

/// [`read_from_reader`], with `wait` called before each read.
fn read_piped(
    reader: &mut impl Read,
    mode: InputMode,
    wait: &mut dyn FnMut() -> Result<(), InputError>,
) -> Result<SecretValue, InputError> {
    // A fixed, pre-sized buffer: reads never reallocate, so no unzeroized
    // copy of a partial value is left in freed memory.
    let mut buf = Zeroizing::new(vec![0u8; MAX_VALUE_BYTES + 1]);
    let mut len = 0;
    loop {
        wait()?;
        // While len <= MAX_VALUE_BYTES the slice has at least one byte, so
        // Ok(0) always means EOF.
        match reader.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => {
                len += n;
                if len > MAX_VALUE_BYTES {
                    return Err(InputError::TooLarge);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    if !mode.raw {
        if buf[..len].ends_with(b"\r\n") {
            len -= 2;
        } else if buf[..len].ends_with(b"\n") {
            len -= 1;
        }
    }
    validate(&buf[..len], mode)?;
    let mut bytes = std::mem::take(&mut *buf);
    bytes.truncate(len);
    // `truncate` keeps the capacity; the zeroize impl for Vec wipes the
    // whole capacity on drop, so the tail is wiped too.
    Ok(SecretValue::new(bytes))
}

/// A no-echo prompt on `/dev/tty`. Tab and every other byte reach
/// [`validate`] unchanged, so a control character fails instead of being
/// dropped (SEC-5).
fn read_from_tty(name: &Name, mode: InputMode) -> Result<SecretValue, InputError> {
    let tty = tty::open()?;
    let _mode = tty::ModeGuard::no_echo(&tty)?;
    if mode.allows_newline() {
        return read_multiline_from_tty(&tty, name);
    }
    tty::say(&tty, &format!("value for {name}: "))?;
    let first = read_tty_line(&tty)?;
    tty::say(&tty, "again: ")?;
    let second = read_tty_line(&tty)?;
    if !first.ct_eq(second.expose()) {
        return Err(InputError::Mismatch);
    }
    drop(second);
    validate(first.expose(), mode)?;
    Ok(first)
}

/// One line from the terminal into a fixed buffer.
fn read_tty_line(tty: &std::fs::File) -> Result<SecretValue, InputError> {
    let mut buf = Zeroizing::new(vec![0u8; MAX_VALUE_BYTES + 1]);
    let mut len = 0;
    tty::read_line(tty, &mut buf, &mut len)?;
    let mut bytes = std::mem::take(&mut *buf);
    bytes.truncate(len);
    // `truncate` keeps the capacity; the zeroize impl wipes all of it.
    Ok(SecretValue::new(bytes))
}

/// Lines until one that holds only `.` (or end of input), in one no-echo
/// session (SEC-7). Asked once: a pasted block is hard to paste twice, and
/// the readback after `sops set` still checks what was stored.
fn read_multiline_from_tty(tty: &std::fs::File, name: &Name) -> Result<SecretValue, InputError> {
    tty::say(
        tty,
        &format!("value for {name}; end with a line that holds only '.':\n"),
    )?;
    // One byte more than the cap, so an over-long value is detected.
    let mut buf = Zeroizing::new(vec![0u8; MAX_VALUE_BYTES + 1]);
    let mut len = 0;
    loop {
        let before = len;
        if len > 0 {
            if len == buf.len() {
                return Err(InputError::TooLarge);
            }
            buf[len] = b'\n';
            len += 1;
        }
        let line_start = len;
        let end = tty::read_line(tty, &mut buf, &mut len)?;
        let line = &buf[line_start..len];
        if line == b"." || (end == tty::LineEnd::Eof && line.is_empty()) {
            len = before;
            break;
        }
        if end == tty::LineEnd::Eof {
            break;
        }
    }
    if len > MAX_VALUE_BYTES {
        return Err(InputError::TooLarge);
    }
    validate(
        &buf[..len],
        InputMode {
            multiline: true,
            raw: false,
        },
    )?;
    let mut bytes = std::mem::take(&mut *buf);
    bytes.truncate(len);
    Ok(SecretValue::new(bytes))
}

/// Check the content rules of PLAN section 7.2.
pub fn validate(bytes: &[u8], mode: InputMode) -> Result<(), InputError> {
    if bytes.is_empty() {
        return Err(InputError::Empty);
    }
    let s = std::str::from_utf8(bytes).map_err(|_| InputError::NotUtf8)?;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\t' => {}
            '\n' if mode.allows_newline() => {}
            '\n' => return Err(InputError::NewlineNeedsMultiline),
            '\r' if mode.raw && chars.peek() == Some(&'\n') => {}
            c if c.is_control() => return Err(InputError::ControlChar),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: InputMode = InputMode {
        multiline: false,
        raw: false,
    };
    const MULTI: InputMode = InputMode {
        multiline: true,
        raw: false,
    };
    const RAW: InputMode = InputMode {
        multiline: true,
        raw: true,
    };

    fn read(input: &[u8], mode: InputMode) -> Result<SecretValue, InputError> {
        read_from_reader(&mut &input[..], mode)
    }

    #[test]
    fn strips_one_trailing_newline() {
        assert!(read(b"v\n", LINE).unwrap().ct_eq(b"v"));
        assert!(read(b"v\r\n", LINE).unwrap().ct_eq(b"v"));
        assert!(read(b"v", LINE).unwrap().ct_eq(b"v"));
        // Only one newline is stripped; the second makes it multiline.
        assert_eq!(
            read(b"v\n\n", LINE).unwrap_err(),
            InputError::NewlineNeedsMultiline
        );
        assert!(read(b"v\n\n", MULTI).unwrap().ct_eq(b"v\n"));
    }

    /// T17: `--raw` keeps the exact bytes.
    #[test]
    fn raw_keeps_trailing_newline() {
        assert!(read(b"v\n", RAW).unwrap().ct_eq(b"v\n"));
        assert!(read(b"a\r\nb\r\n", RAW).unwrap().ct_eq(b"a\r\nb\r\n"));
    }

    #[test]
    fn rejects_bad_content() {
        assert_eq!(read(b"", LINE).unwrap_err(), InputError::Empty);
        assert_eq!(read(b"\n", LINE).unwrap_err(), InputError::Empty);
        assert_eq!(read(b"\xff\xfe", LINE).unwrap_err(), InputError::NotUtf8);
        assert_eq!(read(b"a\0b", LINE).unwrap_err(), InputError::ControlChar);
        assert_eq!(read(b"a\x1bb", MULTI).unwrap_err(), InputError::ControlChar);
        assert_eq!(read(b"a\rb", RAW).unwrap_err(), InputError::ControlChar);
        assert_eq!(read(b"a\r\nb", MULTI).unwrap_err(), InputError::ControlChar);
        assert_eq!(
            read("a\u{85}b".as_bytes(), LINE).unwrap_err(),
            InputError::ControlChar
        );
        assert!(read(b"a\tb", LINE).unwrap().ct_eq(b"a\tb"));
    }

    /// T7: input past the cap is refused.
    #[test]
    fn enforces_the_size_cap() {
        let at_cap = vec![b'x'; MAX_VALUE_BYTES];
        assert!(read(&at_cap, LINE).is_ok());
        let over = vec![b'x'; MAX_VALUE_BYTES + 1];
        assert_eq!(read(&over, LINE).unwrap_err(), InputError::TooLarge);
        let far_over = vec![b'x'; MAX_VALUE_BYTES * 3];
        assert_eq!(read(&far_over, LINE).unwrap_err(), InputError::TooLarge);
    }

    /// T16: the value always goes to sops as a JSON string.
    #[test]
    fn json_encoding_is_always_a_string() {
        let cases: &[(&[u8], &str)] = &[
            (b"123", r#""123""#),
            (b"true", r#""true""#),
            (br#"a"b\c"#, r#""a\"b\\c""#),
            (b"line1\nline2\t", r#""line1\nline2\t""#),
            ("é✓".as_bytes(), "\"é✓\""),
        ];
        for (input, want) in cases {
            let json = SecretValue::new(input.to_vec()).to_json_string().unwrap();
            assert!(json.as_slice() == want.as_bytes(), "JSON encoding mismatch");
        }
    }

    #[test]
    fn debug_is_redacted() {
        let v = SecretValue::new(b"hunter2".to_vec());
        let shown = format!("{v:?}");
        assert_eq!(shown, "SecretValue([REDACTED])");
        assert!(!shown.contains("hunter2"));
    }

    #[test]
    fn input_errors_never_hold_the_value() {
        for input in [&b"hunter2\x07"[..], b"hunter2\nx", b"\xffhunter2"] {
            let err = read(input, LINE).unwrap_err();
            assert!(!err.to_string().contains("hunter2"));
        }
    }
}
