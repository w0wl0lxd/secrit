//! Output masking for `secrit run` (v0.2 plan 7.1, step 4).
//!
//! A [`Masker`] replaces each value in a byte stream, and each known
//! encoding of it, with `[secrit:NAME]`. The stream arrives in chunks of any
//! size, and the output is the same as one replace over the whole stream.
//!
//! - Encodings: the raw bytes; standard and URL-safe base64, cut, ended and
//!   padded, at the three byte offsets in a 3-byte group; percent-encoding;
//!   the JSON string escape; lowercase hex.
//! - Matches are leftmost-longest. Only the longest suffix that is a proper
//!   prefix of some pattern is held back, so a prompt with no newline goes
//!   out at once. Everything goes out at the end of the stream.
//! - A value shorter than [`MIN_MASK_BYTES`] is not masked, with a warning.
//!
//! The matcher is hand-written over `Zeroizing` buffers: `aho-corasick` keeps
//! buffers that secrit cannot wipe. Its comparisons stop at the first
//! different byte; the child that could time them already has the values.
//!
//! Masking prevents accidents (PLAN 4.5). A child that encodes a value in a
//! form that is not in this list gets it through (T44).

use std::cmp::Reverse;
use std::fmt;

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
    /// The names whose values are too short to mask.
    short: Vec<Name>,
    /// Input that is not decided yet: a proper prefix of some pattern.
    pending: Zeroizing<Vec<u8>>,
    /// The output of the last [`Masker::feed`] or [`Masker::finish`].
    out: Zeroizing<Vec<u8>>,
}

impl Masker {
    /// Build the patterns of every value. When two names give the same
    /// pattern, the first name is the replacement.
    #[must_use]
    pub fn new(values: &[(Name, SecretValue)]) -> Self {
        let mut list: Vec<Pattern> = Vec::new();
        let mut replacements = Vec::new();
        let mut short = Vec::new();
        for (name, value) in values {
            let value = value.expose();
            if value.len() < MIN_MASK_BYTES {
                short.push(name.clone());
                continue;
            }
            let replacement = replacements.len();
            replacements.push(format!("[secrit:{name}]").into_bytes());
            for bytes in encodings(value) {
                if !list.iter().any(|p| *p.bytes == *bytes) {
                    list.push(Pattern { bytes, replacement });
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
                replacements,
            },
            short,
            pending: Zeroizing::new(Vec::new()),
            out: Zeroizing::new(Vec::new()),
        }
    }

    /// One warning for each value that is too short to mask.
    pub fn warnings(&self) -> impl Iterator<Item = String> + '_ {
        self.short.iter().map(|name| {
            format!("{name} is shorter than {MIN_MASK_BYTES} bytes, so its value is not masked")
        })
    }

    /// Mask the next chunk of the stream. The result is the output that is
    /// decided now; a possible start of a match stays held back.
    pub fn feed(&mut self, chunk: &[u8]) -> &[u8] {
        self.out.zeroize();
        append(&mut self.pending, chunk);
        self.scan(false);
        &self.out
    }

    /// End the stream: mask and return all held bytes.
    pub fn finish(&mut self) -> &[u8] {
        self.out.zeroize();
        self.scan(true);
        &self.out
    }

    /// Move the decided part of `pending` to `out`. At the end of the stream
    /// nothing is held.
    fn scan(&mut self, eof: bool) {
        let mut i = 0;
        // The start of the bytes that pass through unchanged.
        let mut run = 0;
        while i < self.pending.len() {
            match self.patterns.step(&self.pending[i..], eof) {
                Step::Hold => break,
                Step::Pass => i += 1,
                Step::Replace { len, replacement } => {
                    append(&mut self.out, &self.pending[run..i]);
                    append(&mut self.out, &self.patterns.replacements[replacement]);
                    i += len;
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
    /// The index in [`Patterns::replacements`].
    replacement: usize,
}

struct Patterns {
    list: Vec<Pattern>,
    /// For each byte value, the patterns that start with it, longest first.
    by_first: Vec<Vec<usize>>,
    /// `[secrit:NAME]` for each masked name.
    replacements: Vec<Vec<u8>>,
}

enum Step {
    /// The rest of the input is a proper prefix of a pattern: wait for more.
    Hold,
    /// The longest pattern that starts here.
    Replace { len: usize, replacement: usize },
    /// No pattern starts here: one byte passes through.
    Pass,
}

impl Patterns {
    /// The decision at the start of `rest`, which is not empty. A pattern
    /// longer than `rest` that `rest` starts holds the input, so a match is
    /// taken only when no longer one can follow.
    fn step(&self, rest: &[u8], eof: bool) -> Step {
        for &i in &self.by_first[usize::from(rest[0])] {
            let pattern = &self.list[i];
            let bytes: &[u8] = &pattern.bytes;
            if bytes.len() > rest.len() {
                if !eof && bytes.starts_with(rest) {
                    return Step::Hold;
                }
            } else if rest.starts_with(bytes) {
                // The list is longest first, so this is the longest match.
                return Step::Replace {
                    len: bytes.len(),
                    replacement: pattern.replacement,
                };
            }
        }
        Step::Pass
    }
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

/// Every masked form of `value` (v0.2 plan 7.1, step 4). It can hold
/// duplicates; [`Masker::new`] drops them.
fn encodings(value: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut forms = vec![exact(value.len(), |out| out.extend_from_slice(value))];
    for alphabet in [B64_STANDARD, B64_URL_SAFE] {
        for offset in 0..3 {
            for tail in [Tail::Cut, Tail::End, Tail::Padded] {
                forms.push(base64(value, offset, alphabet, tail));
            }
        }
    }
    forms.push(percent(value));
    if let Ok(text) = std::str::from_utf8(value) {
        forms.push(json(text));
    }
    forms.push(hex(value));
    forms.retain(|form| !form.is_empty());
    forms
}

/// A buffer of exactly `len` bytes, filled by `fill`, so that it never
/// grows and leaves an unwiped copy behind.
fn exact(len: usize, fill: impl FnOnce(&mut Vec<u8>)) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    fill(&mut out);
    debug_assert_eq!(out.len(), len, "the length estimate is wrong");
    out
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
    exact(last - first + padding, |out| {
        for i in first..last {
            out.push(alphabet[sextet(value, offset, i)]);
        }
        out.extend(std::iter::repeat_n(b'=', padding));
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

/// Percent-encoding (RFC 3986): every byte except the unreserved ones
/// becomes `%XX`.
fn percent(value: &[u8]) -> Zeroizing<Vec<u8>> {
    let kept = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
    let len = value.iter().map(|&b| if kept(b) { 1 } else { 3 }).sum();
    exact(len, |out| {
        for &b in value {
            if kept(b) {
                out.push(b);
            } else {
                out.extend_from_slice(&[
                    b'%',
                    HEX_UPPER[usize::from(b >> 4)],
                    HEX_UPPER[usize::from(b & 0xf)],
                ]);
            }
        }
    })
}

/// The body of a JSON string, escaped as `serde_json` escapes it.
fn json(text: &str) -> Zeroizing<Vec<u8>> {
    let short = |b: u8| match b {
        b'"' => Some(*b"\\\""),
        b'\\' => Some(*b"\\\\"),
        0x08 => Some(*b"\\b"),
        0x0c => Some(*b"\\f"),
        b'\n' => Some(*b"\\n"),
        b'\r' => Some(*b"\\r"),
        b'\t' => Some(*b"\\t"),
        _ => None,
    };
    let bytes = text.as_bytes();
    let len = bytes
        .iter()
        .map(|&b| match short(b) {
            Some(_) => 2,
            None if b < 0x20 => 6,
            None => 1,
        })
        .sum();
    exact(len, |out| {
        for &b in bytes {
            match short(b) {
                Some(escape) => out.extend_from_slice(&escape),
                None if b < 0x20 => out.extend_from_slice(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX_LOWER[usize::from(b >> 4)],
                    HEX_LOWER[usize::from(b & 0xf)],
                ]),
                None => out.push(b),
            }
        }
    })
}

/// Lowercase hex.
fn hex(value: &[u8]) -> Zeroizing<Vec<u8>> {
    exact(2 * value.len(), |out| {
        for &b in value {
            out.extend_from_slice(&[
                HEX_LOWER[usize::from(b >> 4)],
                HEX_LOWER[usize::from(b & 0xf)],
            ]);
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
        let hex_form: String = value
            .iter()
            .flat_map(|b| [b >> 4, b & 0xf])
            .map(|d| char::from_digit(u32::from(d), 16).unwrap())
            .collect();
        let forms: [&[u8]; 4] = [
            value,
            b"s3cr%22t%2F%5Cx%20y%0A%01",
            b"s3cr\\\"t/\\\\x y\\n\\u0001",
            hex_form.as_bytes(),
        ];
        for form in forms {
            let mut input = b"pre ".to_vec();
            input.extend_from_slice(form);
            input.extend_from_slice(b" post");
            assert_eq!(
                one_shot(&[("tok", value)], &input),
                b"pre [secrit:tok] post",
                "{}",
                String::from_utf8_lossy(form)
            );
        }
    }

    #[test]
    fn the_json_escape_matches_serde_json() {
        let text = "a\"b\\c/d\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f}é";
        let encoded = serde_json::to_string(text).unwrap();
        assert_eq!(*json(text), encoded.as_bytes()[1..encoded.len() - 1]);
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
        input.extend_from_slice(&hex(value));
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
        assert_eq!(one_shot(&values, b"xabcdefgh"), b"x[secrit:A]gh");
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
    /// output, and no raw value is left in it. The value bytes are not in
    /// `[secrit:vN]`, so a value in the output can only come from input that
    /// passed through.
    #[test]
    fn random_splits_give_the_one_shot_output() {
        const BYTES: &[u8] = b"\x00\x01\x02\xfb\xffa%\"\\/\n";
        let mut rng = Rng(0x5ec2_1700);
        for case in 0..400 {
            let owned: Vec<(String, Vec<u8>)> = (0..=rng.below(3))
                .map(|i| {
                    let len = MIN_MASK_BYTES + rng.below(10);
                    (
                        format!("v{i}"),
                        (0..len).map(|_| *rng.pick(BYTES)).collect(),
                    )
                })
                .collect();
            let values: Vec<(&str, &[u8])> = owned
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_slice()))
                .collect();
            let mut input = Vec::new();
            for _ in 0..rng.below(10) {
                let value = &rng.pick(&owned).1;
                match rng.below(4) {
                    0 => input.extend((0..rng.below(6)).map(|_| *rng.pick(BYTES))),
                    1 => input.extend_from_slice(value),
                    2 => input.extend_from_slice(rng.pick(&encodings(value))),
                    _ => {
                        let mut stream: Vec<u8> = (0..rng.below(4)).map(|_| b'p').collect();
                        stream.extend_from_slice(value);
                        stream.extend((0..rng.below(4)).map(|_| b's'));
                        input.extend_from_slice(&std_b64(&stream));
                    }
                }
            }
            let expected = one_shot(&values, &input);
            for (_, value) in &owned {
                assert!(!contains(&expected, value), "case {case}: raw value left");
            }
            let mut chunks = Vec::new();
            let mut rest = input.as_slice();
            while !rest.is_empty() {
                let (chunk, tail) = rest.split_at(1 + rng.below(rest.len().min(8)));
                chunks.push(chunk);
                rest = tail;
            }
            assert_eq!(streamed(&values, chunks), expected, "case {case}");
        }
    }
}
