//! Safe terminal output of text that secrit did not write: key names from the
//! store file (R5) and values in reveal mode (SEC-1). Control characters and
//! bidirectional overrides never reach the terminal raw.

use std::borrow::Cow;
use std::fmt::Write as _;

use zeroize::Zeroizing;

const MARK_ON: &[u8] = b"\x1b[7m";
const MARK_OFF: &[u8] = b"\x1b[27m";

/// A character that must not reach a terminal raw: C0, DEL, C1, and the
/// Unicode bidirectional controls that reorder what is shown.
#[must_use]
pub fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}

/// `c` as `\xNN` (code points below 0x100) or `\u{NNNN}`.
fn escape_code(c: u32, out: &mut String) {
    if c < 0x100 {
        let _ = write!(out, "\\x{c:02x}");
    } else {
        let _ = write!(out, "\\u{{{c:04x}}}");
    }
}

/// A name with every unsafe character escaped. Borrowed when nothing changes.
#[must_use]
pub fn escape(s: &str) -> Cow<'_, str> {
    if !s.chars().any(is_unsafe) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        if is_unsafe(c) {
            escape_code(u32::from(c), &mut out);
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Feed the terminal form of `value` to `emit`, piece by piece. `\n` becomes
/// `\r\n` (the screen is in raw mode), tab stays, and every other unsafe
/// character or invalid byte is shown as an escape in reverse video.
/// Returns whether anything was escaped.
fn render_with(value: &[u8], emit: &mut dyn FnMut(&[u8])) -> bool {
    let mut escaped = false;
    let mut code = String::with_capacity(12);
    let mut mark = |c: u32, emit: &mut dyn FnMut(&[u8])| {
        code.clear();
        escape_code(c, &mut code);
        emit(MARK_ON);
        emit(code.as_bytes());
        emit(MARK_OFF);
    };
    for chunk in value.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '\n' => emit(b"\r\n"),
                '\t' => emit(b"\t"),
                c if is_unsafe(c) => {
                    escaped = true;
                    mark(u32::from(c), emit);
                }
                c => emit(c.encode_utf8(&mut [0u8; 4]).as_bytes()),
            }
        }
        for b in chunk.invalid() {
            escaped = true;
            mark(u32::from(*b), emit);
        }
    }
    escaped
}

/// The terminal form of a secret value, in a buffer sized exactly once (two
/// passes), so it never reallocates and leaves no unwiped copy behind.
#[must_use]
pub fn render_secret(value: &[u8]) -> (Zeroizing<Vec<u8>>, bool) {
    let mut size = 0;
    render_with(value, &mut |b| size += b.len());
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    let escaped = render_with(value, &mut |b| out.extend_from_slice(b));
    (out, escaped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_escaped_only_when_needed() {
        assert!(matches!(escape("a.b-c_d"), Cow::Borrowed("a.b-c_d")));
        assert_eq!(escape("\x1b]0;pwned\x07x"), "\\x1b]0;pwned\\x07x");
        assert_eq!(escape("a\u{202e}b"), "a\\u{202e}b");
        assert_eq!(escape("é✓"), "é✓");
    }

    #[test]
    fn rendered_secrets_hold_no_raw_control_bytes() {
        let value = b"canaryA\x1b[?1049lcanaryB\x1b]52;c;aGk=\x07\nline2\t\x9b\xff";
        let (out, escaped) = render_secret(value);
        assert!(escaped);
        let mut rest: &[u8] = &out;
        // The only ESC bytes left are the reverse-video marks secrit adds.
        while let Some(i) = rest.iter().position(|&b| b == 0x1b) {
            let tail = &rest[i..];
            assert!(
                tail.starts_with(MARK_ON) || tail.starts_with(MARK_OFF),
                "a raw escape sequence survived"
            );
            rest = &rest[i + 1..];
        }
        assert!(!out.windows(2).any(|w| w == b"\x1b]"));
        assert!(!out.contains(&0x07));
        assert!(!out.contains(&0x9b));
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("\\x1b") && text.contains("\\x07") && text.contains("\\xff"));
        assert!(text.contains("\r\nline2\t"));
        assert_eq!(out.capacity(), out.len());
    }

    #[test]
    fn plain_values_are_unchanged() {
        let (out, escaped) = render_secret("pässwörd 123".as_bytes());
        assert!(!escaped);
        assert!(out.as_slice() == "pässwörd 123".as_bytes());
    }
}
