//! Output masking for `secrit run` (v0.2 plan 7.1, step 4).
//!
//! A [`Masker`] replaces each value in a byte stream, and each known
//! encoding of it, with `[secrit:NAME]`. The stream arrives in chunks of any
//! size, and the output is the same as one replace over the whole stream.
//!
//! - Forms: the value, and the value without one final `\n` or `\r\n` (a
//!   value stored with `--raw` that a program prints without the newline).
//! - Encodings of each form:
//!   - the raw bytes;
//!   - standard and URL-safe base64, cut, ended and padded, at the three
//!     byte offsets in a 3-byte group;
//!   - lowercase and uppercase hex;
//!   - percent-encoding with lowercase or uppercase hex digits, for four
//!     sets of kept bytes: RFC 3986, form encoding with `+` for a space
//!     (Python `quote_plus`, Go `QueryEscape`), JavaScript
//!     `encodeURIComponent`, and Python `quote` (keeps `/`);
//!   - the JSON string escape as `serde_json` and JavaScript write it, as Go
//!     `json.Marshal` writes it (`\u003c`, `\u003e`, `\u0026`, `\u2028`,
//!     `\u2029`), and as Python `json.dumps` writes it (`\uXXXX` for each
//!     character that is not printable ASCII, a surrogate pair above
//!     U+FFFF). Each of the three also with `\/` for `/` and with uppercase
//!     hex digits.
//! - Identical forms are kept once.
//! - Matches are leftmost-longest. A match that starts inside a masked
//!   region and ends after it makes the region longer, so overlapping
//!   values are masked as their union. The label names each value that made
//!   the region, in the order of their matches: `[secrit:A+B]`. A name
//!   cannot contain `+`.
//! - A value shorter than [`MIN_MASK_BYTES`] is not masked, with a warning.
//!   The same applies to the form without the final newline.
//!
//! Hold-back: a byte is held only when it starts some pattern, as the
//! longest suffix that is a proper prefix of a pattern, or as a region that
//! a held match can still make longer. All other output goes out at once.
//! A prompt with no newline that starts like a pattern stays held until
//! [`Masker::flush_held`] or the end of the stream. So the time at which
//! output goes out shows that it starts some pattern.
//!
//! The matcher is hand-written over `Zeroizing` buffers: `aho-corasick` keeps
//! buffers that secrit cannot wipe. Each comparison of pattern bytes runs in
//! constant time for its length (`subtle`), so it does not show where the
//! first different byte is.
//!
//! Known gaps:
//!
//! - Masking prevents accidents (PLAN 4.5). It does not stop a child or a
//!   command author that wants to leak a value: a form that is not in this
//!   list goes through (T44).
//! - base64 that is wrapped into lines (64 or 76 columns, as PEM and MIME
//!   write it) is not matched.
//! - The worst-case cost is O(stream length x value length): each input
//!   byte that starts a pattern costs the length of the patterns that start
//!   with it.
//! - A prefix that [`Masker::flush_held`] releases is not masked when the
//!   rest of the value follows.

use std::cmp::Reverse;
use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::name::Name;
use crate::secret::SecretValue;

/// A value shorter than this is not masked: it would match by chance too
/// often.
pub const MIN_MASK_BYTES: usize = 4;

const B64_STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Replaces values and their encodings in a stream of output bytes.
pub struct Masker {
    patterns: Patterns,
    /// The names with a form that is too short to mask.
    short: Vec<(Name, Short)>,
    /// Input that is not decided yet: a proper prefix of some pattern, or a
    /// region that can still grow.
    pending: Zeroizing<Vec<u8>>,
    /// The output of the last call. Bytes past its length are always zero.
    out: Zeroizing<Vec<u8>>,
}

/// Which form of a value is too short to mask.
#[derive(Debug, Clone, Copy)]
enum Short {
    Value,
    /// The value without its final newline.
    Trimmed,
}

impl Masker {
    /// Build the patterns of every value. When two names give the same
    /// pattern, the first name is the replacement.
    #[must_use]
    pub fn new(values: &[(Name, SecretValue)]) -> Self {
        let mut list: Vec<Pattern> = Vec::new();
        let mut names = Vec::new();
        let mut short = Vec::new();
        for (name, value) in values {
            let value = value.expose();
            if value.len() < MIN_MASK_BYTES {
                short.push((name.clone(), Short::Value));
                continue;
            }
            if trim_newline(value).is_some_and(|t| t.len() < MIN_MASK_BYTES) {
                short.push((name.clone(), Short::Trimmed));
            }
            let label = names.len();
            names.push(name.to_string());
            for bytes in encodings(value) {
                if !list.iter().any(|p| same(&p.bytes, &bytes)) {
                    list.push(Pattern { bytes, label });
                }
            }
        }
        let mut by_first = vec![Vec::new(); 256];
        for (i, pattern) in list.iter().enumerate() {
            by_first[usize::from(pattern.bytes[0])].push(i);
        }
        for ids in &mut by_first {
            ids.sort_by_key(|&i| Reverse(list[i].bytes.len()));
        }
        Self {
            patterns: Patterns {
                list,
                by_first,
                names,
            },
            short,
            pending: Zeroizing::new(Vec::new()),
            out: Zeroizing::new(Vec::new()),
        }
    }

    /// One warning for each value, or form of a value, that is too short to
    /// mask.
    pub fn warnings(&self) -> impl Iterator<Item = String> + '_ {
        self.short.iter().map(|(name, short)| match short {
            Short::Value => format!(
                "{name} is shorter than {MIN_MASK_BYTES} bytes, so its value is not masked"
            ),
            Short::Trimmed => format!(
                "{name} without its final newline is shorter than {MIN_MASK_BYTES} bytes, so that form is not masked"
            ),
        })
    }

    /// Mask the next chunk of the stream. The result is the output that is
    /// decided now; a possible start of a match stays held back.
    pub fn feed(&mut self, chunk: &[u8]) -> &[u8] {
        wipe(&mut self.out);
        append(&mut self.pending, chunk);
        self.scan(false);
        &self.out
    }

    /// Release the held bytes as if the stream ended here, and stay open for
    /// more input. A complete match in the held bytes is still replaced; the
    /// rest goes out unmasked. So one call shows at most a proper prefix of
    /// a pattern, never a full match.
    ///
    /// `secrit run` (v0.2 plan S13) calls this when the child writes nothing
    /// for a short idle period, 100 ms by default, so that a prompt with no
    /// newline is shown even when it starts like a pattern. A released
    /// prefix is not masked later: when the rest of the value follows, only
    /// a form that matches by itself is masked.
    pub fn flush_held(&mut self) -> &[u8] {
        wipe(&mut self.out);
        self.scan(true);
        &self.out
    }

    /// End the stream: mask and return all held bytes.
    pub fn finish(&mut self) -> &[u8] {
        self.flush_held()
    }

    /// Move the decided part of `pending` to `out`. At the end of the stream
    /// nothing is held.
    fn scan(&mut self, eof: bool) {
        let mut i = 0;
        // The start of the bytes that pass through unchanged.
        let mut run = 0;
        while i < self.pending.len() {
            match self.patterns.step(&self.pending, i, eof) {
                Step::Hold => break,
                Step::Pass => i += 1,
                Step::Replace { end, labels } => {
                    append(&mut self.out, &self.pending[run..i]);
                    append(&mut self.out, self.patterns.label(&labels).as_bytes());
                    i = end;
                    run = i;
                }
            }
        }
        append(&mut self.out, &self.pending[run..i]);
        // Move the held bytes to the front and wipe the rest.
        let held = self.pending.len() - i;
        self.pending.copy_within(i.., 0);
        self.pending[held..].zeroize();
        self.pending.truncate(held);
    }
}

impl fmt::Debug for Masker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Masker")
            .field("patterns", &self.patterns.list.len())
            .field("short", &self.short)
            .finish_non_exhaustive()
    }
}

/// One byte string to replace.
struct Pattern {
    bytes: Zeroizing<Vec<u8>>,
    /// The index in [`Patterns::names`].
    label: usize,
}

struct Patterns {
    list: Vec<Pattern>,
    /// For each byte value, the patterns that start with it, longest first.
    by_first: Vec<Vec<usize>>,
    /// The name of each masked value.
    names: Vec<String>,
}

enum Step {
    /// The input that follows can change the decision: wait for more.
    Hold,
    /// A masked region up to `end`, made of the matches of `labels`.
    Replace { end: usize, labels: Vec<usize> },
    /// No pattern starts here: one byte passes through.
    Pass,
}

/// What starts at one position of the input.
enum At {
    /// The rest of the input is a proper prefix of a pattern.
    Hold,
    /// The longest pattern that starts here.
    Match {
        len: usize,
        label: usize,
    },
    Nothing,
}

impl Patterns {
    /// The decision at `start` of `input`. A match grows into a region while
    /// a match that starts inside the region ends after it.
    fn step(&self, input: &[u8], start: usize, eof: bool) -> Step {
        let (mut end, label) = match self.at(&input[start..], eof) {
            At::Hold => return Step::Hold,
            At::Nothing => return Step::Pass,
            At::Match { len, label } => (start + len, label),
        };
        let mut labels = vec![label];
        let mut j = start + 1;
        while j < end {
            match self.at(&input[j..], eof) {
                At::Hold => return Step::Hold,
                At::Match { len, label } if j + len > end => {
                    end = j + len;
                    if !labels.contains(&label) {
                        labels.push(label);
                    }
                }
                At::Match { .. } | At::Nothing => {}
            }
            j += 1;
        }
        Step::Replace { end, labels }
    }

    /// What starts at the start of `rest`, which is not empty. A pattern
    /// longer than `rest` that `rest` starts holds the input, so a match is
    /// taken only when no longer one can follow.
    fn at(&self, rest: &[u8], eof: bool) -> At {
        for &i in &self.by_first[usize::from(rest[0])] {
            let pattern = &self.list[i];
            let bytes: &[u8] = &pattern.bytes;
            if bytes.len() > rest.len() {
                if !eof && same(&bytes[..rest.len()], rest) {
                    return At::Hold;
                }
            } else if same(&rest[..bytes.len()], bytes) {
                // The list is longest first, so this is the longest match.
                return At::Match {
                    len: bytes.len(),
                    label: pattern.label,
                };
            }
        }
        At::Nothing
    }

    /// `[secrit:A+B]` for the names of `labels`.
    fn label(&self, labels: &[usize]) -> String {
        let names: Vec<&str> = labels.iter().map(|&l| self.names[l].as_str()).collect();
        format!("[secrit:{}]", names.join("+"))
    }
}

/// Equality of secret bytes in constant time for the length. Slices of
/// different lengths are not equal; a length is not secret here.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Append `data` to `buf`. `Vec` frees its old buffer unwiped when it grows,
/// so a larger buffer is made here and the old one is wiped as it drops.
fn append(buf: &mut Zeroizing<Vec<u8>>, data: &[u8]) {
    let need = buf.len() + data.len();
    if need > buf.capacity() {
        let mut bigger = Zeroizing::new(Vec::with_capacity(need.max(buf.capacity() * 2)));
        bigger.extend_from_slice(buf);
        *buf = bigger;
    }
    buf.extend_from_slice(data);
}

/// Wipe the bytes of `buf` and empty it. Only the bytes up to the length
/// are wiped: every shrink in this module wipes first and [`append`] grows
/// into a new buffer, so the spare capacity holds no plaintext.
fn wipe(buf: &mut Zeroizing<Vec<u8>>) {
    buf.as_mut_slice().zeroize();
    buf.clear();
}

/// `value` without one final `\r\n` or `\n`, when it ends in one.
fn trim_newline(value: &[u8]) -> Option<&[u8]> {
    [b"\r\n".as_slice(), b"\n"].into_iter().find_map(|ending| {
        let cut = value.len().checked_sub(ending.len())?;
        same(&value[cut..], ending).then(|| &value[..cut])
    })
}

/// Every masked form of `value` (v0.2 plan 7.1, step 4). It can hold
/// duplicates; [`Masker::new`] drops them.
fn encodings(value: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut forms = Vec::new();
    encode(value, &mut forms);
    if let Some(trimmed) = trim_newline(value).filter(|t| t.len() >= MIN_MASK_BYTES) {
        encode(trimmed, &mut forms);
    }
    forms.retain(|form| !form.is_empty());
    forms
}

/// Push the encodings of one form of a value.
fn encode(value: &[u8], forms: &mut Vec<Zeroizing<Vec<u8>>>) {
    forms.push(build(|put| put(value)));
    for alphabet in [B64_STANDARD, B64_URL_SAFE] {
        for offset in 0..3 {
            for tail in [Tail::Cut, Tail::End, Tail::Padded] {
                forms.push(base64(value, offset, alphabet, tail));
            }
        }
    }
    for digits in [HEX_LOWER, HEX_UPPER] {
        forms.push(build(|put| {
            for &b in value {
                put(&hex_pair(b, digits));
            }
        }));
        for set in [Kept::Rfc3986, Kept::Form, Kept::UriComponent, Kept::Path] {
            forms.push(percent(value, set, digits));
        }
    }
    if let Ok(text) = std::str::from_utf8(value) {
        for (go_html, ascii) in [(false, false), (true, false), (false, true)] {
            for solidus in [false, true] {
                for digits in [HEX_LOWER, HEX_UPPER] {
                    let style = JsonStyle {
                        go_html,
                        ascii,
                        solidus,
                        digits,
                    };
                    forms.push(json(text, style));
                }
            }
        }
    }
}

/// A buffer made from the pieces that `write` gives. A first pass counts
/// the bytes, so the buffer is made once at its exact size and never grows
/// and leaves an unwiped copy behind.
fn build(write: impl Fn(&mut dyn FnMut(&[u8]))) -> Zeroizing<Vec<u8>> {
    let mut len = 0;
    write(&mut |piece| len += piece.len());
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    write(&mut |piece| out.extend_from_slice(piece));
    debug_assert_eq!(out.len(), len, "the two passes differ");
    out
}

/// `b` as two hex digits.
fn hex_pair(b: u8, digits: &[u8; 16]) -> [u8; 2] {
    [digits[usize::from(b >> 4)], digits[usize::from(b & 0xf)]]
}

/// How a base64 pattern ends.
#[derive(Clone, Copy)]
enum Tail {
    /// Bytes follow the value: drop the last character when it also holds
    /// bits of the next byte.
    Cut,
    /// The value ends the stream, with no `=`.
    End,
    /// The value ends the stream, with `=` padding.
    Padded,
}

/// `value` in base64 when it starts `offset` bytes into a 3-byte group of a
/// longer stream. The characters that also hold bits of the bytes before the
/// value are dropped.
fn base64(value: &[u8], offset: usize, alphabet: &[u8; 64], tail: Tail) -> Zeroizing<Vec<u8>> {
    let start_bit = 8 * offset;
    let end_bit = start_bit + 8 * value.len();
    let first = start_bit.div_ceil(6);
    let last = match tail {
        Tail::Cut => end_bit / 6,
        Tail::End | Tail::Padded => end_bit.div_ceil(6),
    };
    let padding = match tail {
        Tail::Padded => (4 - last % 4) % 4,
        Tail::Cut | Tail::End => 0,
    };
    build(|put| {
        for i in first..last {
            put(&[alphabet[sextet(value, offset, i)]]);
        }
        for _ in 0..padding {
            put(b"=");
        }
    })
}

/// Sextet `i` of the stream of `offset` zero bytes, `value`, then zero bytes.
fn sextet(value: &[u8], offset: usize, i: usize) -> usize {
    let byte = |j: usize| {
        j.checked_sub(offset)
            .and_then(|j| value.get(j))
            .map_or(0, |&b| u16::from(b))
    };
    let bit = 6 * i;
    let window = (byte(bit / 8) << 8) | byte(bit / 8 + 1);
    usize::from((window >> (10 - bit % 8)) & 0x3f)
}

/// The bytes that a percent-encoder keeps besides ASCII letters, digits and
/// `-._~`.
#[derive(Clone, Copy)]
enum Kept {
    /// RFC 3986: none.
    Rfc3986,
    /// Form encoding: none, and a space becomes `+` (Python `quote_plus`,
    /// Go `QueryEscape`).
    Form,
    /// JavaScript `encodeURIComponent`: `!*'()`.
    UriComponent,
    /// Python `quote`: `/`.
    Path,
}

/// Percent-encoding: every byte that `set` does not keep becomes `%XX`.
fn percent(value: &[u8], set: Kept, digits: &[u8; 16]) -> Zeroizing<Vec<u8>> {
    let kept = |b: u8| {
        b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || match set {
                Kept::Rfc3986 | Kept::Form => false,
                Kept::UriComponent => matches!(b, b'!' | b'*' | b'\'' | b'(' | b')'),
                Kept::Path => b == b'/',
            }
    };
    build(|put| {
        for &b in value {
            if kept(b) {
                put(&[b]);
            } else if b == b' ' && matches!(set, Kept::Form) {
                put(b"+");
            } else {
                let [high, low] = hex_pair(b, digits);
                put(&[b'%', high, low]);
            }
        }
    })
}

/// How a JSON encoder escapes a string. All of them escape `"`, `\` and
/// the control characters, with the short forms `\b \f \n \r \t`.
#[derive(Clone, Copy)]
struct JsonStyle {
    /// Go `json.Marshal`: `<`, `>`, `&`, U+2028 and U+2029 as `\uXXXX`.
    go_html: bool,
    /// Python `json.dumps` (`ensure_ascii`): each character that is not
    /// printable ASCII as `\uXXXX`, a surrogate pair above U+FFFF.
    ascii: bool,
    /// `/` as `\/`.
    solidus: bool,
    /// The hex digits of `\uXXXX`.
    digits: &'static [u8; 16],
}

/// The body of a JSON string, escaped in `style`.
fn json(text: &str, style: JsonStyle) -> Zeroizing<Vec<u8>> {
    build(|put| {
        for c in text.chars() {
            let short: Option<&[u8; 2]> = match c {
                '"' => Some(b"\\\""),
                '\\' => Some(b"\\\\"),
                '\u{8}' => Some(b"\\b"),
                '\u{c}' => Some(b"\\f"),
                '\n' => Some(b"\\n"),
                '\r' => Some(b"\\r"),
                '\t' => Some(b"\\t"),
                '/' if style.solidus => Some(b"\\/"),
                _ => None,
            };
            let escape = c < ' '
                || (style.ascii && !(' '..='~').contains(&c))
                || (style.go_html && matches!(c, '<' | '>' | '&' | '\u{2028}' | '\u{2029}'));
            if let Some(short) = short {
                put(short);
            } else if escape {
                for &unit in c.encode_utf16(&mut [0; 2]).iter() {
                    let [a, b] = unit.to_be_bytes();
                    let ([a1, a2], [b1, b2]) =
                        (hex_pair(a, style.digits), hex_pair(b, style.digits));
                    put(&[b'\\', b'u', a1, a2, b1, b2]);
                }
            } else {
                put(c.encode_utf8(&mut [0; 4]).as_bytes());
            }
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    fn masker(values: &[(&str, &[u8])]) -> Masker {
        let values: Vec<(Name, SecretValue)> = values
            .iter()
            .map(|(name, value)| (Name::parse(name).unwrap(), SecretValue::new(value.to_vec())))
            .collect();
        Masker::new(&values)
    }

    /// The whole input in one chunk.
    fn one_shot(values: &[(&str, &[u8])], input: &[u8]) -> Vec<u8> {
        streamed(values, [input])
    }

    fn streamed<'a>(
        values: &[(&str, &[u8])],
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Vec<u8> {
        let mut m = masker(values);
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend_from_slice(m.feed(chunk));
        }
        out.extend_from_slice(m.finish());
        out
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn lower_hex(bytes: &[u8]) -> Vec<u8> {
        bytes.iter().flat_map(|&b| hex_pair(b, HEX_LOWER)).collect()
    }

    fn std_b64(bytes: &[u8]) -> Vec<u8> {
        base64(bytes, 0, B64_STANDARD, Tail::Padded).to_vec()
    }

    /// RFC 4648, section 10, and the two characters where the alphabets
    /// differ.
    #[test]
    fn base64_matches_the_rfc_vectors() {
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (input, expected) in vectors {
            assert_eq!(std_b64(input), expected.as_bytes());
            let end = base64(input, 0, B64_STANDARD, Tail::End);
            assert_eq!(*end, expected.trim_end_matches('=').as_bytes());
        }
        assert_eq!(*base64(b"foob", 0, B64_STANDARD, Tail::Cut), *b"Zm9vY");
        assert_eq!(
            *base64(&[0xfb, 0xff], 0, B64_STANDARD, Tail::Padded),
            *b"+/8="
        );
        assert_eq!(
            *base64(&[0xfb, 0xff], 0, B64_URL_SAFE, Tail::Padded),
            *b"-_8="
        );
    }

    /// T40: the value inside a longer base64 stream is masked at every
    /// offset, in both alphabets, padded or not. At most the edge characters
    /// that also hold other bytes stay.
    #[test]
    fn base64_is_masked_at_every_offset() {
        let value: &[u8] = b"s3cr\xfb\xff-t0ken";
        for alphabet in [B64_STANDARD, B64_URL_SAFE] {
            for before in 0..6 {
                for after in 0..4 {
                    let mut stream = vec![b'P'; before];
                    stream.extend_from_slice(value);
                    stream.extend(std::iter::repeat_n(b'S', after));
                    let padded = base64(&stream, 0, alphabet, Tail::Padded).to_vec();
                    let unpadded = base64(&stream, 0, alphabet, Tail::End).to_vec();
                    for encoded in [padded, unpadded] {
                        let out = one_shot(&[("tok", value)], &encoded);
                        let marker = b"[secrit:tok]";
                        let at = out
                            .windows(marker.len())
                            .position(|w| w == marker)
                            .unwrap_or_else(|| {
                                panic!("not masked: {}", String::from_utf8_lossy(&encoded))
                            });
                        let (left, right) = (&out[..at], &out[at + marker.len()..]);
                        assert!(encoded.starts_with(left) && encoded.ends_with(right));
                        assert!(left.len() <= (8 * before).div_ceil(6));
                        assert!(right.len() <= (8 * after).div_ceil(6) + 3);
                    }
                }
            }
        }
    }

    /// T40: the raw value, percent-encoding, the JSON escape and hex.
    #[test]
    fn every_other_encoding_is_masked() {
        let value = b"s3cr\"t/\\x y\n\x01";
        let forms: [&[u8]; 4] = [
            value,
            b"s3cr%22t%2F%5Cx%20y%0A%01",
            b"s3cr\\\"t/\\\\x y\\n\\u0001",
            &lower_hex(value),
        ];
        for form in forms {
            masks_in_text(&[("tok", value)], form, "[secrit:tok]");
        }
    }

    #[test]
    fn the_json_escape_matches_serde_json() {
        let text = "a\"b\\c/d\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f}é";
        let encoded = serde_json::to_string(text).unwrap();
        let style = JsonStyle {
            go_html: false,
            ascii: false,
            solidus: false,
            digits: HEX_LOWER,
        };
        assert_eq!(*json(text, style), encoded.as_bytes()[1..encoded.len() - 1]);
    }

    #[test]
    fn a_value_that_is_not_utf8_has_no_json_form() {
        let forms = encodings(b"ab\xffcd");
        assert!(forms.iter().all(|f| !f.starts_with(b"ab\\")));
    }

    /// Every split into two chunks, and one byte at a time, gives the
    /// one-shot output.
    #[test]
    fn a_match_split_at_every_byte_boundary_is_masked() {
        let value: &[u8] = b"hunter2-correct";
        let values = [("pw", value)];
        let mut input = b"a ".to_vec();
        input.extend_from_slice(value);
        input.extend_from_slice(b" b ");
        input.extend_from_slice(&std_b64(&[b"xy".as_slice(), value].concat()));
        input.extend_from_slice(b" c ");
        input.extend_from_slice(&lower_hex(value));
        let expected = one_shot(&values, &input);
        assert_eq!(
            expected.windows(9).filter(|w| *w == b"[secrit:p").count(),
            3,
            "{}",
            String::from_utf8_lossy(&expected)
        );
        for split in 0..=input.len() {
            let (a, b) = input.split_at(split);
            assert_eq!(streamed(&values, [a, b]), expected, "split at {split}");
        }
        assert_eq!(streamed(&values, input.chunks(1)), expected);
    }

    #[test]
    fn overlapping_values_match_leftmost_longest() {
        let values: [(&str, &[u8]); 3] = [("A", b"abcdef"), ("B", b"cdefgh"), ("C", b"abcd")];
        assert_eq!(one_shot(&values, b"xabcdefgh"), b"x[secrit:A+B]");
        assert_eq!(one_shot(&values, b"xcdefghab"), b"x[secrit:B]ab");
        assert_eq!(one_shot(&values, b"abcdxx"), b"[secrit:C]xx");
        // The shorter match waits until the longer one cannot follow.
        let mut m = masker(&values);
        assert_eq!(m.feed(b"abcd"), b"");
        assert_eq!(m.feed(b"x"), b"[secrit:C]x");
        assert_eq!(m.finish(), b"");
    }

    #[test]
    fn the_first_name_wins_for_a_shared_value() {
        let values: [(&str, &[u8]); 2] = [("one", b"same-value"), ("two", b"same-value")];
        assert_eq!(one_shot(&values, b"same-value"), b"[secrit:one]");
    }

    /// T41: a prompt with no newline goes out at once; only a possible start
    /// of a match is held.
    #[test]
    fn a_prompt_that_does_not_match_goes_out_at_once() {
        let mut m = masker(&[("pw", b"hunter22")]);
        assert_eq!(m.feed(b"Password: "), b"Password: ");
        assert_eq!(m.feed(b"ok hun"), b"ok ");
        assert_eq!(m.feed(b"ter22!"), b"[secrit:pw]!");
        assert_eq!(m.feed(b"hunt"), b"");
        assert_eq!(m.feed(b"x"), b"huntx");
        assert_eq!(m.finish(), b"");
    }

    #[test]
    fn the_end_of_the_stream_flushes_held_bytes() {
        let mut m = masker(&[("pw", b"hunter22")]);
        assert_eq!(m.feed(b"abc hunter2"), b"abc ");
        assert_eq!(m.finish(), b"hunter2");
        assert_eq!(m.finish(), b"");
    }

    /// Every buffer that holds a value, a part of one or an encoding of
    /// one is wiped on drop.
    #[test]
    fn buffers_are_zeroizing() {
        fn wiped(_: &Zeroizing<Vec<u8>>) {}
        let mut m = masker(&[("pw", b"hunter22")]);
        let _ = m.feed(b"x hunt");
        wiped(&m.pending);
        wiped(&m.out);
        for pattern in &m.patterns.list {
            wiped(&pattern.bytes);
        }
        assert_eq!(*m.pending, *b"hunt");
        // `append` keeps the content when it moves to a larger buffer.
        let mut buf = Zeroizing::new(Vec::with_capacity(2));
        append(&mut buf, b"ab");
        append(&mut buf, b"cdefgh");
        assert_eq!(*buf, *b"abcdefgh");
        assert!(buf.capacity() >= 8);
    }

    #[test]
    fn a_short_value_is_not_masked_and_warns_once() {
        let values: [(&str, &[u8]); 2] = [("pin", b"123"), ("tok", b"abcdef")];
        let m = masker(&values);
        assert_eq!(
            m.warnings().collect::<Vec<_>>(),
            ["pin is shorter than 4 bytes, so its value is not masked"]
        );
        assert_eq!(one_shot(&values, b"123 abcdef"), b"123 [secrit:tok]");
    }

    /// Wrap `form` in text and mask it with `values`.
    fn masks_in_text(values: &[(&str, &[u8])], form: &[u8], label: &str) {
        let mut input = b"pre ".to_vec();
        input.extend_from_slice(form);
        input.extend_from_slice(b" post");
        assert_eq!(
            String::from_utf8_lossy(&one_shot(values, &input)),
            format!("pre {label} post"),
            "{}",
            String::from_utf8_lossy(form)
        );
    }

    #[test]
    fn uppercase_hex_is_masked() {
        let value = b"s3cr\xfb\xff\x01";
        masks_in_text(&[("tok", value)], b"73336372FBFF01", "[secrit:tok]");
    }

    /// The reference forms come from Python 3 `urllib.parse.quote_plus`
    /// and `quote`, Go `url.QueryEscape` and JavaScript
    /// `encodeURIComponent`.
    #[test]
    fn every_percent_variant_is_masked() {
        let value = "s3cr\"t/\\x y!*'()~é\n\x01".as_bytes();
        let forms: [&[u8]; 5] = [
            b"s3cr%22t%2F%5Cx%20y%21%2A%27%28%29~%C3%A9%0A%01",
            b"s3cr%22t%2f%5cx%20y%21%2a%27%28%29~%c3%a9%0a%01",
            b"s3cr%22t%2F%5Cx+y%21%2A%27%28%29~%C3%A9%0A%01",
            b"s3cr%22t%2F%5Cx%20y!*'()~%C3%A9%0A%01",
            b"s3cr%22t/%5Cx%20y%21%2A%27%28%29~%C3%A9%0A%01",
        ];
        for form in forms {
            masks_in_text(&[("tok", value)], form, "[secrit:tok]");
        }
    }

    /// The reference forms come from Go `json.Marshal` and Python 3
    /// `json.dumps`; the last two are the escaped solidus and uppercase
    /// `\u00XX` hex.
    #[test]
    fn every_json_variant_is_masked() {
        let text = "a\"b\\c/d\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f}é<>&\u{2028}\u{2029}😀";
        let forms: [&str; 4] = [
            concat!(
                r#"a\"b\\c/d\b\f\n\r\t\u0001\u001f"#,
                "\u{7f}é",
                r"\u003c\u003e\u0026\u2028\u2029",
                "😀"
            ),
            r#"a\"b\\c/d\b\f\n\r\t\u0001\u001f\u007f\u00e9<>&\u2028\u2029\ud83d\ude00"#,
            concat!(
                r#"a\"b\\c\/d\b\f\n\r\t\u0001\u001f"#,
                "\u{7f}é<>&\u{2028}\u{2029}😀"
            ),
            concat!(
                r#"a\"b\\c/d\b\f\n\r\t\u0001\u001F"#,
                "\u{7f}é<>&\u{2028}\u{2029}😀"
            ),
        ];
        for form in forms {
            masks_in_text(&[("tok", text.as_bytes())], form.as_bytes(), "[secrit:tok]");
        }
    }

    #[test]
    fn identical_forms_are_kept_once() {
        let value: &[u8] = b"plain-token";
        let m = masker(&[("tok", value)]);
        let mut distinct: Vec<Vec<u8>> = encodings(value).iter().map(|f| f.to_vec()).collect();
        distinct.sort();
        distinct.dedup();
        assert_eq!(m.patterns.list.len(), distinct.len());
    }

    /// A match that starts inside a masked region and ends after it makes
    /// the region longer, in one chunk or one byte at a time.
    #[test]
    fn overlapping_values_mask_the_union() {
        let values: [(&str, &[u8]); 2] = [("A", b"abcdEFGH"), ("B", b"EFGHijklmnopqrst")];
        let input = b"abcdEFGHijklmnopqrst!";
        assert_eq!(one_shot(&values, input), b"[secrit:A+B]!");
        assert_eq!(streamed(&values, input.chunks(1)), b"[secrit:A+B]!");
        let values: [(&str, &[u8]); 4] = [
            ("A", b"abcdEF"),
            ("B", b"EFghij"),
            ("C", b"ijKLMN"),
            ("D", b"cdEF"),
        ];
        let input = b"xabcdEFghijKLMNy";
        assert_eq!(one_shot(&values, input), b"x[secrit:A+B+C]y");
        assert_eq!(streamed(&values, input.chunks(1)), b"x[secrit:A+B+C]y");
        // The region waits while a longer one can follow.
        let mut m = masker(&values);
        assert_eq!(m.feed(b"abcdEFgh"), b"");
        assert_eq!(m.finish(), b"[secrit:A]gh");
    }

    /// A value stored with `--raw` can end in a newline that the program
    /// does not print.
    #[test]
    fn a_value_with_a_final_newline_is_masked_without_it() {
        for value in [b"hunter22\n".as_slice(), b"hunter22\r\n"] {
            let values = [("pw", value)];
            masks_in_text(&values, value, "[secrit:pw]");
            masks_in_text(&values, b"hunter22", "[secrit:pw]");
            masks_in_text(&values, &std_b64(b"hunter22"), "[secrit:pw]");
        }
        let values: [(&str, &[u8]); 1] = [("pin", b"abc\n")];
        assert_eq!(one_shot(&values, b"abc abc\n"), b"abc [secrit:pin]");
        assert_eq!(
            masker(&values).warnings().collect::<Vec<_>>(),
            ["pin without its final newline is shorter than 4 bytes, so that form is not masked"]
        );
    }

    /// T41: a prompt that starts like a pattern goes out after an idle
    /// period. A complete match in the held bytes is still replaced.
    #[test]
    fn flush_held_releases_a_held_prompt() {
        let values: [(&str, &[u8]); 2] = [("A", b"abcdef"), ("C", b"abcd")];
        let mut m = masker(&values);
        assert_eq!(m.feed(b"Name: ab"), b"Name: ");
        assert_eq!(m.flush_held(), b"ab");
        assert_eq!(m.flush_held(), b"");
        assert_eq!(m.feed(b"cd x abcd"), b"cd x ");
        assert_eq!(m.flush_held(), b"[secrit:C]");
        assert_eq!(m.feed(b"ef"), b"ef");
        assert_eq!(m.finish(), b"");
    }

    /// The output buffer is wiped up to its length only, so a small write
    /// after a large one costs little.
    #[test]
    fn a_small_write_after_a_large_one_is_cheap() {
        let mut m = masker(&[("pw", b"hunter22")]);
        let big = vec![b'.'; 2 << 20];
        assert_eq!(m.feed(&big).len(), big.len());
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            assert_eq!(m.feed(b"."), b".");
        }
        let took = start.elapsed();
        assert!(took < std::time::Duration::from_millis(500), "{took:?}");
    }

    #[test]
    fn debug_shows_no_value() {
        let shown = format!("{:?}", masker(&[("pw", b"hunter22")]));
        assert!(!shown.contains("hunter"), "{shown}");
        assert!(shown.starts_with("Masker"), "{shown}");
    }

    /// `SplitMix64`: a fixed-seed generator, so a failure repeats.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
        }

        fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
            &items[self.below(items.len())]
        }
    }

    /// Acceptance of S12: random values, inputs and splits give the one-shot
    /// output, also one byte at a time, and no value is left in it. Some
    /// values start with the end of the value before them, so their matches
    /// overlap and are masked as a union. The value bytes are not in
    /// `[secrit:vN+vM]`, so a value in the output can only come from input
    /// that passed through.
    #[test]
    fn random_splits_give_the_one_shot_output() {
        const TOKENS: &[&[u8]] = &[
            b"\x00",
            b"\x01",
            b"\xfb",
            b"\xff",
            b"a",
            b"Z",
            b"%",
            b"\"",
            b"\\",
            b"/",
            b"\n",
            b"\r\n",
            b" ",
            b"+",
            b"<",
            b"!",
            "\u{e9}".as_bytes(),
            "\u{2028}".as_bytes(),
            "\u{1f600}".as_bytes(),
        ];
        let mut rng = Rng(0x5ec2_1700);
        let mut unions = 0;
        for case in 0..400 {
            // The name, the value, and how many bytes it shares with the
            // end of the value before it.
            let mut owned: Vec<(String, Vec<u8>, usize)> = Vec::new();
            for i in 0..=rng.below(3) {
                let mut value = Vec::new();
                if let Some((_, before, _)) = owned.last()
                    && rng.below(2) == 0
                {
                    let shared = 1 + rng.below(before.len() - 1);
                    value.extend_from_slice(&before[before.len() - shared..]);
                }
                let shared = value.len();
                let len = shared + MIN_MASK_BYTES + rng.below(8);
                while value.len() < len {
                    value.extend_from_slice(rng.pick(TOKENS));
                }
                if rng.below(4) == 0 {
                    value.push(b'\n');
                }
                owned.push((format!("v{i}"), value, shared));
            }
            let values: Vec<(&str, &[u8])> = owned
                .iter()
                .map(|(n, v, _)| (n.as_str(), v.as_slice()))
                .collect();
            let mut input = Vec::new();
            for _ in 0..rng.below(10) {
                let k = rng.below(owned.len());
                let (_, value, shared) = &owned[k];
                match rng.below(5) {
                    0 => {
                        for _ in 0..rng.below(6) {
                            input.extend_from_slice(rng.pick(TOKENS));
                        }
                    }
                    1 => input.extend_from_slice(value),
                    2 => input.extend_from_slice(rng.pick(&encodings(value))),
                    3 => {
                        let mut stream: Vec<u8> = (0..rng.below(4)).map(|_| b'p').collect();
                        stream.extend_from_slice(value);
                        stream.extend((0..rng.below(4)).map(|_| b's'));
                        input.extend_from_slice(&std_b64(&stream));
                    }
                    _ => {
                        // The value before, then the rest of this one.
                        if *shared > 0 {
                            input.extend_from_slice(&owned[k - 1].1);
                        }
                        input.extend_from_slice(&value[*shared..]);
                    }
                }
            }
            let expected = one_shot(&values, &input);
            if contains(&expected, b"+v") {
                unions += 1;
            }
            for (_, value, _) in &owned {
                let trimmed = trim_newline(value).filter(|t| t.len() >= MIN_MASK_BYTES);
                for form in std::iter::once(value.as_slice()).chain(trimmed) {
                    assert!(!contains(&expected, form), "case {case}: a value is left");
                }
            }
            let mut chunks = Vec::new();
            let mut rest = input.as_slice();
            while !rest.is_empty() {
                let (chunk, tail) = rest.split_at(1 + rng.below(rest.len().min(8)));
                chunks.push(chunk);
                rest = tail;
            }
            assert_eq!(streamed(&values, chunks), expected, "case {case}");
            assert_eq!(streamed(&values, input.chunks(1)), expected, "case {case}");
        }
        assert!(unions > 20, "only {unions} cases mask a union");
    }
}
