//! Decoding a gzip or deflate body (feature `ssrf-decompress`): the
//! classification, the caps, and a decode that runs in bounded steps.
//!
//! The wire body is read whole first, under its own cap ([`wire_cap`]), then
//! decoded with flate2's readers: gzip with `MultiGzDecoder` (every member,
//! back to back), deflate with `ZlibDecoder`, or with `DeflateDecoder` when
//! the body does not start with a zlib header (raw deflate labelled
//! `deflate`, which browsers accept too).
//!
//! **Bounded steps.** A synchronous decode cannot be preempted:
//! `tokio::time::timeout` around the fetch fires only at an `.await`, and
//! `spawn_blocking` would leave a timed-out decode running (dropping its
//! `JoinHandle` does not stop the work). So the decode is a loop of steps,
//! each one `read` of at most `STEP_OUTPUT` bytes out, fed at most
//! `STEP_INPUT` bytes in: the input reader answers `WouldBlock` once a step's
//! share is used, and flate2's readers pick up where they stopped. Between
//! steps the decode checks the fetch's deadline and yields to the runtime. A
//! body of thousands of tiny gzip members is many short steps, never one
//! long one.
//!
//! **The decoded cap.** A step never asks for more than one byte past what
//! the cap leaves, so passing `max_bytes` is `TooLarge` within the step that
//! does it, and nothing past the cap is stored. Once the deadline has
//! passed, the answer is `TimedOut`, whatever the decode came to.

use std::cmp;
use std::io::{self, BufRead, Read};

use bytes::Bytes;
use flate2::bufread::{DeflateDecoder, MultiGzDecoder, ZlibDecoder};
use http::header::CONTENT_ENCODING;
use http::HeaderMap;
use tokio::time::Instant;

use super::fetch::reserve_capped;

/// The most output one step produces.
const STEP_OUTPUT: usize = 32 * 1024;
/// The most input one step consumes.
const STEP_INPUT: usize = 16 * 1024;

/// A coding the decoder handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Coding {
    /// `gzip` or `x-gzip`: every member, back to back.
    Gzip,
    /// `deflate`: zlib-wrapped, or raw when the body has no zlib header.
    Deflate,
}

/// The coding of a response that is not identity-encoded: identity tokens
/// dropped across every `Content-Encoding` header, exactly one token left,
/// and that one `gzip`, `x-gzip` or `deflate` (case-insensitive). Anything
/// else (stacked codings, `br`, `zstd`, an empty token, an unreadable value)
/// is `None`, which refuses the response.
pub(super) fn classify(headers: &HeaderMap) -> Option<Coding> {
    let mut coding = None;
    for value in headers.get_all(CONTENT_ENCODING) {
        for token in value.to_str().ok()?.split(',') {
            let token = token.trim();
            if token.eq_ignore_ascii_case("identity") {
                continue;
            }
            if coding.is_some() {
                return None;
            }
            coding = Some(
                if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
                    Coding::Gzip
                } else if token.eq_ignore_ascii_case("deflate") {
                    Coding::Deflate
                } else {
                    return None;
                },
            );
        }
    }
    coding
}

/// The cap on a coded body's wire bytes: `max_bytes` plus an eighth, plus
/// 4 KiB, saturating. The slack covers stored blocks and flushes of
/// incompressible data; the cap itself is what stops a server streaming
/// empty members or blocks at CPU cost for the whole budget, and what bounds
/// memory.
pub(super) fn wire_cap(max_bytes: usize) -> usize {
    max_bytes.saturating_add(max_bytes / 8).saturating_add(4096)
}

/// Why a decode produced no body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DecodeError {
    /// The decoded body would pass `max_bytes`.
    TooLarge,
    /// Corrupt, truncated, or not the coding claimed.
    Corrupt,
    /// The fetch's deadline passed, before a step or by the time the decode
    /// came to any answer: it wins over every other outcome.
    TimedOut,
    /// A reservation for the decoded body's buffer was refused (it is only
    /// ever asked for output the cap keeps, so never past `max_bytes`).
    OutOfMemory,
}

/// Decode `wire` as `coding` into at most `max_bytes`, giving up once
/// `deadline` has passed. An empty `wire` is an empty body: there is
/// nothing to decode.
pub(super) async fn decode(
    coding: Coding,
    wire: &[u8],
    max_bytes: usize,
    deadline: Option<Instant>,
) -> Result<Bytes, DecodeError> {
    decode_paced(coding, wire, max_bytes, deadline, Steps::DEFAULT, || {}).await
}

/// What one step may do.
#[derive(Debug, Clone, Copy)]
struct Steps {
    /// The most input it consumes.
    input: usize,
    /// The most output it produces.
    output: usize,
}

impl Steps {
    const DEFAULT: Steps = Steps {
        input: STEP_INPUT,
        output: STEP_OUTPUT,
    };
}

/// [`decode`] with its step bounds, calling `pace` before each step: the
/// seams a test shrinks and slows the steps with.
async fn decode_paced(
    coding: Coding,
    wire: &[u8],
    max_bytes: usize,
    deadline: Option<Instant>,
    steps: Steps,
    mut pace: impl FnMut(),
) -> Result<Bytes, DecodeError> {
    let passed = || deadline.is_some_and(|deadline| Instant::now() >= deadline);
    let outcome = async {
        if wire.is_empty() {
            return Ok(Bytes::new());
        }
        let mut decode = Decode::new(coding, wire, max_bytes, steps);
        loop {
            if passed() {
                return Err(DecodeError::TimedOut);
            }
            pace();
            if decode.step()? {
                return Ok(Bytes::from(decode.body));
            }
            tokio::task::yield_now().await;
        }
    }
    .await;
    // Every answer, an empty body or a step's error included, is late once
    // the deadline has passed (the fetch's outer timeout would take a ready
    // answer before looking at its timer).
    if passed() {
        return Err(DecodeError::TimedOut);
    }
    outcome
}

/// A decode in progress: the reader, the body so far and one step's room.
struct Decode<'a> {
    reader: Reader<'a>,
    /// Never longer than `max_bytes`, and never given a larger capacity
    /// ([`reserve_capped`]).
    body: Vec<u8>,
    max_bytes: usize,
    steps: Steps,
    /// `steps.output` bytes, zeroed once and reused.
    room: Box<[u8]>,
}

impl<'a> Decode<'a> {
    fn new(coding: Coding, wire: &'a [u8], max_bytes: usize, steps: Steps) -> Self {
        Self {
            reader: Reader::new(coding, wire),
            body: Vec::new(),
            max_bytes,
            steps,
            room: vec![0; steps.output].into_boxed_slice(),
        }
    }

    /// One step: one read under a fresh input allowance. `true` once the
    /// body is decoded.
    fn step(&mut self) -> Result<bool, DecodeError> {
        self.reader.input().allowance = self.steps.input;
        // `body.len() <= max_bytes` always holds. One byte past what is
        // left is enough to know the cap was passed.
        let left = self.max_bytes - self.body.len();
        let room = &mut self.room[..cmp::min(self.steps.output, left.saturating_add(1))];
        match self.reader.read(room) {
            Ok(0) => Ok(true),
            Ok(read) if read > left => Err(DecodeError::TooLarge),
            Ok(read) => {
                reserve_capped(&mut self.body, read, self.max_bytes)
                    .map_err(|_| DecodeError::OutOfMemory)?;
                self.body.extend_from_slice(&room[..read]);
                Ok(false)
            }
            // The step's input is used up; the next step resumes.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(_) => Err(DecodeError::Corrupt),
        }
    }
}

/// flate2's reader for the coding, over the metered input.
enum Reader<'a> {
    Gzip(MultiGzDecoder<Metered<'a>>),
    Zlib(ZlibDecoder<Metered<'a>>),
    Raw(DeflateDecoder<Metered<'a>>),
}

impl<'a> Reader<'a> {
    fn new(coding: Coding, wire: &'a [u8]) -> Self {
        // No allowance until the first step: not even the gzip header, which
        // `MultiGzDecoder::new` starts reading, is read before it.
        let input = Metered {
            rest: wire,
            allowance: 0,
        };
        match coding {
            Coding::Gzip => Reader::Gzip(MultiGzDecoder::new(input)),
            Coding::Deflate if is_zlib_header(wire) => Reader::Zlib(ZlibDecoder::new(input)),
            Coding::Deflate => Reader::Raw(DeflateDecoder::new(input)),
        }
    }

    fn input(&mut self) -> &mut Metered<'a> {
        match self {
            Reader::Gzip(reader) => reader.get_mut(),
            Reader::Zlib(reader) => reader.get_mut(),
            Reader::Raw(reader) => reader.get_mut(),
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Reader::Gzip(reader) => reader.read(buf),
            Reader::Zlib(reader) => reader.read(buf),
            Reader::Raw(reader) => reader.read(buf),
        }
    }
}

/// Whether `wire` starts with a zlib header (RFC 1950 section 2.2):
/// compression method 8, a window of at most 32 KiB, and check bits that
/// make the first two bytes a multiple of 31.
fn is_zlib_header(wire: &[u8]) -> bool {
    match wire {
        [cmf, flg, ..] => {
            cmf & 0x0f == 8 && cmf >> 4 <= 7 && (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0
        }
        _ => false,
    }
}

/// The wire body, handed out at most `allowance` bytes at a time: once a
/// step's share is used, a read answers `WouldBlock` (never an empty read,
/// which a decoder takes for the end of its input) until the next step
/// refills it.
struct Metered<'a> {
    rest: &'a [u8],
    allowance: usize,
}

impl Read for Metered<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let read = cmp::min(available.len(), buf.len());
        buf[..read].copy_from_slice(&available[..read]);
        self.consume(read);
        Ok(read)
    }
}

impl BufRead for Metered<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.rest.is_empty() {
            return Ok(&[]);
        }
        if self.allowance == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(&self.rest[..cmp::min(self.rest.len(), self.allowance)])
    }

    fn consume(&mut self, amount: usize) {
        self.rest = &self.rest[amount..];
        self.allowance -= amount;
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use flate2::{Compression, GzBuilder};
    use http::HeaderValue;

    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn raw(data: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// `data` in each coding the decoder reads: gzip, zlib and raw deflate.
    fn every_coding(data: &[u8]) -> [(Coding, Vec<u8>); 3] {
        [
            (Coding::Gzip, gzip(data)),
            (Coding::Deflate, zlib(data)),
            (Coding::Deflate, raw(data)),
        ]
    }

    /// Drive a decode step by step, checking every step's bounds: at most
    /// `steps.input` consumed, at most `steps.output` produced, and a
    /// buffer whose capacity never passes the cap. The result and the
    /// steps taken.
    fn stepped(
        coding: Coding,
        wire: &[u8],
        max_bytes: usize,
        steps: Steps,
    ) -> (Result<Vec<u8>, DecodeError>, usize) {
        if wire.is_empty() {
            return (Ok(Vec::new()), 0);
        }
        let mut decode = Decode::new(coding, wire, max_bytes, steps);
        for count in 1.. {
            let (rest, len) = (decode.reader.input().rest.len(), decode.body.len());
            let step = decode.step();
            let consumed = rest - decode.reader.input().rest.len();
            assert!(consumed <= steps.input, "step {count} consumed {consumed}");
            let produced = decode.body.len() - len;
            assert!(produced <= steps.output, "step {count} produced {produced}");
            let capacity = decode.body.capacity();
            assert!(capacity <= max_bytes, "step {count}: capacity {capacity}");
            match step {
                Ok(true) => return (Ok(decode.body), count),
                Ok(false) => {}
                Err(e) => return (Err(e), count),
            }
        }
        unreachable!()
    }

    fn run(coding: Coding, wire: &[u8], max_bytes: usize) -> Result<Vec<u8>, DecodeError> {
        stepped(coding, wire, max_bytes, Steps::DEFAULT).0
    }

    fn encoded(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(CONTENT_ENCODING, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    /// Only called for a response `is_identity_encoded` refused, which is
    /// what the fetch does; identity-only sets are covered there.
    #[test]
    fn classification_drops_identity_and_needs_exactly_one_known_coding() {
        for (values, expected) in [
            (&["gzip"][..], Some(Coding::Gzip)),
            (&["GZIP"][..], Some(Coding::Gzip)),
            (&["x-gzip"][..], Some(Coding::Gzip)),
            (&["X-Gzip"][..], Some(Coding::Gzip)),
            (&[" gzip "][..], Some(Coding::Gzip)),
            (&["deflate"][..], Some(Coding::Deflate)),
            (&["Deflate"][..], Some(Coding::Deflate)),
            (&["identity, gzip"][..], Some(Coding::Gzip)),
            (&["gzip, identity"][..], Some(Coding::Gzip)),
            (&["identity", "gzip"][..], Some(Coding::Gzip)),
            (&["gzip", "identity"][..], Some(Coding::Gzip)),
            (
                &["identity, identity", "deflate"][..],
                Some(Coding::Deflate),
            ),
            (&["gzip, gzip"][..], None),
            (&["gzip", "gzip"][..], None),
            (&["deflate, gzip"][..], None),
            (&["br"][..], None),
            (&["zstd"][..], None),
            (&["compress"][..], None),
            (&["gzip, br"][..], None),
            (&["gzip,"][..], None),
            (&["identity,"][..], None),
            (&[""][..], None),
            (&["gzip;q=1"][..], None),
        ] {
            assert_eq!(classify(&encoded(values)), expected, "{values:?}");
        }
        let mut opaque = HeaderMap::new();
        opaque.insert(
            CONTENT_ENCODING,
            HeaderValue::from_bytes(b"gzip\xff").unwrap(),
        );
        assert_eq!(classify(&opaque), None, "an unreadable value");
    }

    #[test]
    fn the_wire_cap_is_an_eighth_more_plus_four_kib_and_saturates() {
        assert_eq!(wire_cap(0), 4096);
        assert_eq!(wire_cap(8), 8 + 1 + 4096);
        assert_eq!(
            wire_cap(10 * 1024 * 1024),
            10 * 1024 * 1024 + 1280 * 1024 + 4096
        );
        assert_eq!(wire_cap(usize::MAX), usize::MAX);
        assert_eq!(wire_cap(usize::MAX - 4096), usize::MAX);
    }

    // --- the codings ------------------------------------------------------

    #[test]
    fn gzip_zlib_and_raw_deflate_decode() {
        let data = b"<rss><channel><title>a feed</title></channel></rss>".repeat(200);
        for (coding, wire) in every_coding(&data) {
            assert_eq!(run(coding, &wire, 1 << 20).unwrap(), data, "{coding:?}");
        }
        assert!(is_zlib_header(&zlib(b"x")));
        assert!(!is_zlib_header(&raw(b"x")));
        assert!(!is_zlib_header(b"\x78"), "one byte is no header");
    }

    /// Every member, back to back, whatever its header carries (a name, a
    /// comment, an extra field), its size, or where a step boundary falls
    /// inside it.
    #[test]
    fn a_multi_member_gzip_body_decodes_every_member() {
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        for (i, size) in [0usize, 1, 31, STEP_OUTPUT - 1, STEP_OUTPUT + 1, 100_000]
            .into_iter()
            .enumerate()
        {
            let data: Vec<u8> = (0..size).map(|j| (i * 7 + j) as u8).collect();
            let mut encoder = GzBuilder::new()
                .filename(format!("part-{i}.xml"))
                .comment("a comment")
                .extra(vec![i as u8; 4])
                .write(Vec::new(), Compression::default());
            encoder.write_all(&data).unwrap();
            wire.extend(encoder.finish().unwrap());
            expected.extend(data);
        }

        assert_eq!(run(Coding::Gzip, &wire, expected.len()).unwrap(), expected);
        assert_eq!(
            run(Coding::Gzip, &wire, expected.len() - 1),
            Err(DecodeError::TooLarge)
        );
    }

    /// Steps of one byte in and one byte out: every coding resumes after a
    /// step's input runs out, at every byte boundary, header and trailer
    /// included.
    #[test]
    fn a_decode_resumes_wherever_a_step_ends() {
        let tiny = Steps {
            input: 1,
            output: 1,
        };
        let data = b"a feed, more or less".repeat(20);
        let mut members = gzip(&data[..100]);
        let mut named = GzBuilder::new()
            .filename("feed.xml")
            .comment("c")
            .extra(vec![1, 2, 3])
            .write(Vec::new(), Compression::default());
        named.write_all(&data[100..]).unwrap();
        members.extend(named.finish().unwrap());
        for (coding, wire) in every_coding(&data)
            .into_iter()
            .chain([(Coding::Gzip, members)])
        {
            let (result, steps) = stepped(coding, &wire, 1 << 20, tiny);
            assert_eq!(result.unwrap(), data, "{coding:?}");
            assert!(steps >= wire.len(), "{coding:?}: {steps} steps");
        }
    }

    /// A body without a zlib header is raw deflate. One with a zlib header
    /// that is not a zlib stream is corrupt: there is no second reading.
    #[test]
    fn deflate_without_a_zlib_header_is_raw_and_a_bad_zlib_stream_is_corrupt() {
        let data = b"raw deflate, labelled deflate".repeat(10);
        let raw = raw(&data);
        assert!(!is_zlib_header(&raw));
        assert_eq!(run(Coding::Deflate, &raw, 1 << 20).unwrap(), data);
        let mut bad = zlib(&data);
        let last = bad.len() - 1;
        bad[last] ^= 0xff; // the Adler-32
        assert_eq!(
            run(Coding::Deflate, &bad, 1 << 20),
            Err(DecodeError::Corrupt)
        );
    }

    #[test]
    fn corrupt_or_truncated_input_is_never_a_partial_body() {
        let data = b"a feed, more or less".repeat(500);
        let gz = gzip(&data);
        for cut in [1, 9, 10, 11, gz.len() / 2, gz.len() - 9, gz.len() - 1] {
            assert_eq!(
                run(Coding::Gzip, &gz[..cut], 1 << 20),
                Err(DecodeError::Corrupt),
                "gzip cut {cut}"
            );
        }
        let zl = zlib(&data);
        for cut in [2, 3, zl.len() / 2, zl.len() - 1] {
            assert_eq!(
                run(Coding::Deflate, &zl[..cut], 1 << 20),
                Err(DecodeError::Corrupt),
                "zlib cut {cut}"
            );
        }
        let rw = raw(&data);
        for cut in [1, rw.len() / 2, rw.len() - 1] {
            assert_eq!(
                run(Coding::Deflate, &rw[..cut], 1 << 20),
                Err(DecodeError::Corrupt),
                "raw cut {cut}"
            );
        }
        // A bad trailer, and whatever follows a member that is not one.
        let mut bad_crc = gz.clone();
        let crc = bad_crc.len() - 8;
        bad_crc[crc] ^= 0xff;
        let mut padded = gz.clone();
        padded.extend([0u8; 8]);
        let mut trailing = gz.clone();
        trailing.extend(b"<rss/>");
        for (name, wire) in [
            ("a bad CRC", bad_crc),
            ("zero padding", padded),
            ("trailing bytes", trailing),
            ("not gzip at all", b"not gzip at all".to_vec()),
        ] {
            assert_eq!(
                run(Coding::Gzip, &wire, 1 << 20),
                Err(DecodeError::Corrupt),
                "{name}"
            );
        }
        assert_eq!(
            run(Coding::Deflate, b"\xff\xff\xff\xff", 1 << 20),
            Err(DecodeError::Corrupt)
        );
    }

    // --- the caps ---------------------------------------------------------

    #[test]
    fn exactly_max_bytes_decodes_and_one_more_is_too_large() {
        for (coding, wire) in every_coding(&vec![b'x'; 100_000]) {
            assert_eq!(
                run(coding, &wire, 100_000).unwrap().len(),
                100_000,
                "{coding:?}"
            );
            assert_eq!(
                run(coding, &wire, 99_999),
                Err(DecodeError::TooLarge),
                "{coding:?}"
            );
        }
    }

    #[test]
    fn a_zero_allowance_accepts_only_an_empty_body() {
        for (coding, wire) in every_coding(b"") {
            assert_eq!(run(coding, &wire, 0).unwrap(), b"", "{coding:?}");
        }
        for (coding, wire) in every_coding(b"x") {
            assert_eq!(
                run(coding, &wire, 0),
                Err(DecodeError::TooLarge),
                "{coding:?}"
            );
        }
    }

    #[test]
    fn a_usize_max_cap_works() {
        let data = b"hello, world".repeat(1000);
        for (coding, wire) in every_coding(&data) {
            assert_eq!(run(coding, &wire, usize::MAX).unwrap(), data, "{coding:?}");
        }
    }

    /// One gzip member holding 1 GiB of zeros, in about 1 MiB: the encoder's
    /// output for a sync-flushed MiB of zeros is the same block every time
    /// once its window is all zeros, so that block is repeated rather than
    /// compressing a GiB (seconds, in a debug build). The trailer is exact.
    fn gzip_bomb() -> Vec<u8> {
        let mib = vec![0u8; 1 << 20];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        let mut marks = Vec::new();
        for _ in 0..3 {
            encoder.write_all(&mib).unwrap();
            encoder.flush().unwrap();
            marks.push(encoder.get_ref().len());
        }
        let written = encoder.get_ref().clone();
        let steady = &written[marks[0]..marks[1]];
        assert_eq!(steady, &written[marks[1]..marks[2]], "a steady block");
        let mut bomb = written[..marks[0]].to_vec();
        for _ in 1..1024 {
            bomb.extend_from_slice(steady);
        }
        // A final, empty fixed-Huffman block, then CRC32 and ISIZE.
        bomb.extend_from_slice(&[0x03, 0x00]);
        let mut one = flate2::Crc::new();
        one.update(&mib);
        let mut crc = flate2::Crc::new();
        for _ in 0..1024 {
            crc.combine(&one);
        }
        bomb.extend_from_slice(&crc.sum().to_le_bytes());
        bomb.extend_from_slice(&(1u32 << 30).to_le_bytes());
        bomb
    }

    /// About 1 GiB of zeros in about 1 MiB of gzip: the decode stops at the
    /// cap, never inflating the rest.
    #[test]
    fn a_decompression_bomb_stops_at_the_cap() {
        let bomb = gzip_bomb();
        assert!(bomb.len() < 2 << 20, "{} wire bytes", bomb.len());
        let max_bytes = 1 << 20;
        let (result, steps) = stepped(Coding::Gzip, &bomb, max_bytes, Steps::DEFAULT);
        assert_eq!(result, Err(DecodeError::TooLarge));
        // 32 KiB a step: the cap is reached in about 32 steps.
        assert!(steps <= max_bytes / STEP_OUTPUT + 2, "{steps} steps");
        // The bomb is a real one: all of the GiB inflates and the trailer
        // checks, streamed to a sink (in a release build only; a debug build
        // would take a minute).
        if !cfg!(debug_assertions) {
            let mut reader = flate2::read::GzDecoder::new(&bomb[..]);
            assert_eq!(io::copy(&mut reader, &mut io::sink()).unwrap(), 1 << 30);
        }
    }

    /// Capacity, not only length, is capped: a stored (level 0) gzip body of
    /// 8 MiB + 1 bytes grows the decoded buffer step by step, and at the cap
    /// and one byte over it the buffer's capacity never passes `max_bytes`
    /// (`stepped` checks every step). `Vec`'s own doubling would end at
    /// 16 MiB.
    #[test]
    fn the_decoded_buffer_never_holds_more_than_the_cap() {
        let size = (8 << 20) + 1;
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let wire = {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::none());
            encoder.write_all(&data).unwrap();
            encoder.finish().unwrap()
        };
        let (decoded, _) = stepped(Coding::Gzip, &wire, size, Steps::DEFAULT);
        let decoded = decoded.unwrap();
        assert_eq!(decoded, data);
        assert!(decoded.capacity() <= size, "{}", decoded.capacity());
        let (decoded, _) = stepped(Coding::Gzip, &wire, size + 1, Steps::DEFAULT);
        assert!(decoded.unwrap().capacity() <= size + 1);
        let (decoded, _) = stepped(Coding::Gzip, &wire, size - 1, Steps::DEFAULT);
        assert_eq!(decoded, Err(DecodeError::TooLarge));
    }

    // --- many small members, steps, yields, the deadline ------------------

    /// Thousands of tiny members: correct, and still bounded, every step
    /// within its input and output share (`stepped` checks each), so the
    /// work between two yields stays small however the members are cut.
    #[test]
    fn many_small_members_decode_in_bounded_steps() {
        let (empty, one) = (gzip(b""), gzip(b"x"));
        assert_eq!(empty.len(), 20);
        let mut wire = Vec::new();
        for i in 0..10_000 {
            wire.extend(if i % 2 == 0 { &empty } else { &one });
        }
        let (result, steps) = stepped(Coding::Gzip, &wire, 1 << 20, Steps::DEFAULT);
        assert_eq!(result.unwrap(), vec![b'x'; 5_000]);
        // One read per output byte at least, and input-bound steps for the
        // empty members between them.
        assert!(steps >= 5_000, "{steps} steps");
        let (result, steps) = stepped(Coding::Gzip, &empty.repeat(10_000), 10, Steps::DEFAULT);
        assert_eq!(result.unwrap(), b"");
        assert!(steps > 200_000 / STEP_INPUT, "{steps} steps");
    }

    /// Raw deflate made of empty stored blocks consumes input and produces
    /// nothing: input-only progress, paced like any other. 30,000 of them
    /// (5 bytes each) and a final empty one decode to nothing in steps of at
    /// most a step's input (`stepped` checks each), and slowed steps stop at
    /// the deadline long before the input ends.
    #[tokio::test(flavor = "current_thread")]
    async fn empty_stored_blocks_are_paced_by_their_input() {
        let mut stored = Vec::new();
        for _ in 0..30_000 {
            stored.extend_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xff]);
        }
        stored.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
        assert!(!is_zlib_header(&stored), "raw deflate");

        let (result, steps) = stepped(Coding::Deflate, &stored, 10, Steps::DEFAULT);
        assert_eq!(result.unwrap(), b"");
        assert!(steps > stored.len() / STEP_INPUT, "{steps} steps");

        let deadline = Instant::now() + Duration::from_millis(50);
        let mut count = 0;
        let result = decode_paced(
            Coding::Deflate,
            &stored,
            10,
            Some(deadline),
            Steps::DEFAULT,
            || {
                count += 1;
                std::thread::sleep(Duration::from_millis(20));
            },
        )
        .await;
        assert_eq!(result, Err(DecodeError::TimedOut));
        assert!(count < steps, "stopped after {count} of {steps} steps");
    }

    /// 100,000 empty members are 2,000,000 wire bytes: over the wire cap of
    /// any `max_bytes` up to about 1.77 MB, so the read refuses them before
    /// a decode (the integration tests cover that read). Under a larger cap
    /// the decode yields after every step: on one thread, the ticker below
    /// runs only while the decode yields.
    #[tokio::test(flavor = "current_thread")]
    async fn a_hundred_thousand_empty_members_are_wire_capped_and_yield_per_step() {
        let wire = gzip(b"").repeat(100_000);
        assert!(wire.len() > wire_cap(1 << 20));
        assert!(wire.len() <= wire_cap(2 << 20));
        let ticks = Arc::new(AtomicUsize::new(0));
        let ticker = {
            let ticks = Arc::clone(&ticks);
            tokio::spawn(async move {
                loop {
                    ticks.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            })
        };
        let mut count = 0;
        let result = decode_paced(Coding::Gzip, &wire, 2 << 20, None, Steps::DEFAULT, || {
            count += 1
        })
        .await;
        ticker.abort();
        assert_eq!(result, Ok(Bytes::new()));
        assert!(count > wire.len() / STEP_INPUT, "{count} steps");
        let ticks = ticks.load(Ordering::Relaxed);
        assert!(
            ticks + 1 >= count,
            "the ticker ran {ticks} times in {count} steps"
        );
    }

    /// The deadline is checked before every step: a decode slowed past it
    /// stops within a step or two, whatever is left of the body.
    #[tokio::test(flavor = "current_thread")]
    async fn a_decode_that_outlives_the_deadline_is_timed_out() {
        let slowed = |wire: Vec<u8>, coding, max_bytes| async move {
            let deadline = Instant::now() + Duration::from_millis(50);
            let mut count = 0;
            let started = std::time::Instant::now();
            let result = decode_paced(
                coding,
                &wire,
                max_bytes,
                Some(deadline),
                Steps::DEFAULT,
                || {
                    count += 1;
                    std::thread::sleep(Duration::from_millis(5));
                },
            )
            .await;
            assert!(count < 100, "stopped after {count} slowed steps");
            assert!(started.elapsed() < Duration::from_secs(2));
            result
        };
        // Many members, the input-heavy case.
        let members = gzip(b"").repeat(100_000);
        assert_eq!(
            slowed(members, Coding::Gzip, 2 << 20).await,
            Err(DecodeError::TimedOut)
        );
        // A deflate bomb, the output-heavy case.
        let bomb = zlib(&vec![0u8; 16 << 20]);
        assert_eq!(
            slowed(bomb, Coding::Deflate, usize::MAX).await,
            Err(DecodeError::TimedOut)
        );

        // A deadline already past refuses before the first step.
        let mut count = 0;
        let past = Instant::now();
        let result = decode_paced(
            Coding::Gzip,
            &gzip(b"x"),
            10,
            Some(past),
            Steps::DEFAULT,
            || count += 1,
        )
        .await;
        assert_eq!((result, count), (Err(DecodeError::TimedOut), 0));
    }

    /// A decode under a deadline 50 ms away whose step number `slow_at`
    /// (from 1), and no other, is slowed 100 ms past it: the answer and the
    /// steps taken.
    async fn slowed_at(
        coding: Coding,
        wire: &[u8],
        max_bytes: usize,
        slow_at: Option<usize>,
    ) -> (Result<Bytes, DecodeError>, usize) {
        let deadline = Instant::now() + Duration::from_millis(50);
        let mut count = 0;
        let result = decode_paced(
            coding,
            wire,
            max_bytes,
            Some(deadline),
            Steps::DEFAULT,
            || {
                count += 1;
                if Some(count) == slow_at {
                    std::thread::sleep(Duration::from_millis(100));
                }
            },
        )
        .await;
        (result, count)
    }

    /// An answer that comes after the deadline is late, whatever it is. Each
    /// case is first run unslowed, to learn its answer and how many steps it
    /// takes; then only its last step, the one that produces the answer, is
    /// slowed past the deadline. That step still runs to its end (the step
    /// count is the same), and its answer is `TimedOut`: a finished body
    /// (one step for an empty gzip stream, the EOF step after a byte for
    /// zlib), `Corrupt` or `TooLarge` alike.
    #[tokio::test(flavor = "current_thread")]
    async fn the_step_that_answers_past_the_deadline_answers_timed_out() {
        for (coding, wire, max_bytes, unslowed, steps) in [
            (Coding::Gzip, gzip(b""), 10, Ok(Bytes::new()), 1),
            (
                Coding::Deflate,
                zlib(b"x"),
                1,
                Ok(Bytes::from_static(b"x")),
                2,
            ),
            (
                Coding::Gzip,
                b"\x1f".to_vec(),
                10,
                Err(DecodeError::Corrupt),
                1,
            ),
            (Coding::Gzip, gzip(b"xx"), 1, Err(DecodeError::TooLarge), 1),
        ] {
            assert_eq!(
                slowed_at(coding, &wire, max_bytes, None).await,
                (unslowed.clone(), steps),
                "unslowed"
            );
            assert_eq!(
                slowed_at(coding, &wire, max_bytes, Some(steps)).await,
                (Err(DecodeError::TimedOut), steps),
                "{unslowed:?}: its last step slowed"
            );
        }
    }

    /// Even an empty body, which needs no decode, is late once the deadline
    /// has passed.
    #[tokio::test(flavor = "current_thread")]
    async fn an_empty_body_needs_no_steps_and_is_late_past_the_deadline() {
        let past = Instant::now();
        let future = Instant::now() + Duration::from_secs(5);
        for coding in [Coding::Gzip, Coding::Deflate] {
            let mut count = 0;
            let result =
                decode_paced(coding, b"", 0, Some(future), Steps::DEFAULT, || count += 1).await;
            assert_eq!((result, count), (Ok(Bytes::new()), 0), "{coding:?}");
            assert_eq!(
                decode(coding, b"", 0, Some(past)).await,
                Err(DecodeError::TimedOut),
                "{coding:?}"
            );
        }
    }

    #[test]
    fn the_decode_future_is_send() {
        fn send<T: Send>(_: &T) {}
        let wire = gzip(b"x");
        send(&decode(Coding::Gzip, &wire, 10, None));
    }
}
