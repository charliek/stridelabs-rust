//! Decoding a gzip or deflate body (feature `ssrf-decompress`): the
//! classification, the caps, and a decoder that works in bounded steps.
//!
//! The wire body is read whole first, under its own cap, as feedparser
//! reads it (`f.read()`), which is what makes "zlib, then raw" exact. It is
//! then decoded **cooperatively**: each step does a bounded amount of work,
//! and between steps the decoder checks the fetch's deadline and yields to
//! the runtime. Not `spawn_blocking`, whose `JoinHandle`, once dropped, does
//! not stop the work: a timed-out decode would keep a blocking thread busy up
//! to the caps. And not one synchronous decode, which `tokio::time::timeout`
//! cannot preempt.
//!
//! A step ends when it has made one inflate call (at most
//! `min(STEP_OUTPUT, remaining allowance + 1)` bytes out), consumed
//! `STEP_INPUT` bytes of input, or finished a gzip member — each member
//! resets the inflater, so a body of many tiny members is many steps, never
//! one long one.
//!
//! Every coding inflates through one [`flate2::Decompress`], and every byte
//! it writes is counted, including the bytes a call writes before it reports
//! corruption. gzip's member framing (header, trailer, padding) is read here,
//! as CPython's `gzip` module reads it, rather than by flate2's `GzDecoder`,
//! whose `read` drops the count of bytes written when it returns an error.
//!
//! Precedence: the deadline first, on every answer (past it, the answer is
//! `TimedOut` whatever the decode came to). Then `TooLarge`, the moment the
//! decoded allowance would be passed, decided before the output is stored and
//! before anything else is looked at. It never falls back to raw deflate,
//! and corruption after the cap is never reported.

use std::cmp;

use bytes::Bytes;
use flate2::{Crc, Decompress, DecompressError, FlushDecompress, Status};
use http::header::CONTENT_ENCODING;
use http::HeaderMap;
use tokio::time::Instant;

use super::fetch::reserve_capped;

/// The most output one step produces.
const STEP_OUTPUT: usize = 32 * 1024;
/// The most input one step consumes.
const STEP_INPUT: usize = 64 * 1024;

/// A coding the decoder handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Coding {
    /// `gzip` or `x-gzip`: every member, with zero padding between and after.
    Gzip,
    /// `deflate`: zlib-wrapped, or raw when the zlib reading fails.
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
/// `deadline` has passed.
///
/// Precedence: once `deadline` has passed, the answer is
/// [`DecodeError::TimedOut`], whatever the decode came to: a body, `TooLarge`
/// or `Corrupt` (the fetch's outer timeout would take a ready answer before
/// looking at its timer, so a late answer is checked here). Before it,
/// `TooLarge` wins over corruption, and a zlib reading that passed the cap is
/// never retried as raw.
pub(super) async fn decode(
    coding: Coding,
    wire: &[u8],
    max_bytes: usize,
    deadline: Option<Instant>,
) -> Result<Bytes, DecodeError> {
    decode_paced(coding, wire, max_bytes, deadline, || {}).await
}

/// [`decode`], calling `pace` before each step: the seam a test slows the
/// steps with.
async fn decode_paced(
    coding: Coding,
    wire: &[u8],
    max_bytes: usize,
    deadline: Option<Instant>,
    pace: impl FnMut(),
) -> Result<Bytes, DecodeError> {
    let passed = || deadline.is_some_and(|deadline| Instant::now() >= deadline);
    let outcome = decode_steps(coding, wire, max_bytes, &passed, pace).await;
    // Every answer, whichever way it came (an empty body, a step's error, a
    // finished body), is late once the deadline has passed.
    if passed() {
        return Err(DecodeError::TimedOut);
    }
    outcome
}

/// The steps themselves, stopping before a step once `passed` says so.
async fn decode_steps(
    coding: Coding,
    wire: &[u8],
    max_bytes: usize,
    passed: &impl Fn() -> bool,
    mut pace: impl FnMut(),
) -> Result<Bytes, DecodeError> {
    // feedparser decodes only a non-empty body (`if data and ...`).
    if wire.is_empty() {
        return Ok(Bytes::new());
    }
    let mut out = Output::new(max_bytes);
    let mut body = Body::new(coding, wire);
    loop {
        if passed() {
            return Err(DecodeError::TimedOut);
        }
        pace();
        if body.step(&mut out)? {
            return Ok(Bytes::from(out.body));
        }
        tokio::task::yield_now().await;
    }
}

/// The decoded bytes so far, the cap they may not pass, and one step's
/// room.
struct Output {
    /// Never longer than `max_bytes`, and never given a larger capacity
    /// ([`reserve_capped`]): output past the cap is refused before anything
    /// is reserved for it.
    body: Vec<u8>,
    max_bytes: usize,
    /// Test only: the length past which a reservation is refused, as an
    /// allocator would refuse it.
    #[cfg(test)]
    refuse_growth_past: usize,
    /// `STEP_OUTPUT` bytes, zeroed once and reused: a step decodes into it,
    /// and what it wrote is appended to `body`. Zero-filling `body`'s tail
    /// instead would cost a whole step's room on every step, even one that
    /// produces nothing (an empty gzip member).
    step: Box<[u8]>,
}

impl Output {
    fn new(max_bytes: usize) -> Self {
        Self {
            body: Vec::new(),
            max_bytes,
            #[cfg(test)]
            refuse_growth_past: usize::MAX,
            step: vec![0; STEP_OUTPUT].into_boxed_slice(),
        }
    }

    /// Hand `produce` room for at most `min(STEP_OUTPUT, remaining + 1)`
    /// bytes and keep the `written` it reports, whatever else it reports:
    /// the cap is judged first, before anything is reserved, so output past
    /// it is never stored and a refused reservation can only be for output
    /// the cap keeps. One byte past the allowance is enough to know it was
    /// passed, so no step overshoots by more.
    fn produce<T>(
        &mut self,
        produce: impl FnOnce(&mut [u8]) -> (T, usize),
    ) -> Result<T, DecodeError> {
        let remaining = self.max_bytes - self.body.len();
        let room = cmp::min(STEP_OUTPUT, remaining.saturating_add(1));
        let step = &mut self.step[..room];
        let (result, written) = produce(step);
        if written > remaining {
            return Err(DecodeError::TooLarge);
        }
        #[cfg(test)]
        if self.body.len() + written > self.refuse_growth_past {
            return Err(DecodeError::OutOfMemory);
        }
        reserve_capped(&mut self.body, written, self.max_bytes)
            .map_err(|_| DecodeError::OutOfMemory)?;
        self.body.extend_from_slice(&step[..written]);
        Ok(result)
    }
}

/// What one inflate call did.
struct Inflated {
    status: Result<Status, DecompressError>,
    consumed: usize,
    produced: usize,
}

/// One `decompress` call of `input` into `out`'s room. The bytes it wrote
/// reach `out` (and `on_output`) even when it reports corruption, so the cap
/// is judged on everything the stream produced.
fn inflate_into(
    inflate: &mut Decompress,
    input: &[u8],
    out: &mut Output,
    on_output: impl FnOnce(&[u8]),
) -> Result<Inflated, DecodeError> {
    let before_in = inflate.total_in();
    let (status, produced) = out.produce(|buf| {
        let before_out = inflate.total_out();
        let status = inflate.decompress(input, buf, FlushDecompress::None);
        // Bounded by `buf.len()`, so the cast is lossless.
        let produced = (inflate.total_out() - before_out) as usize;
        on_output(&buf[..produced]);
        ((status, produced), produced)
    })?;
    // Bounded by `input.len()`.
    let consumed = (inflate.total_in() - before_in) as usize;
    Ok(Inflated {
        status,
        consumed,
        produced,
    })
}

enum Body<'a> {
    Gzip(GzipBody<'a>),
    Deflate(DeflateBody<'a>),
}

impl<'a> Body<'a> {
    fn new(coding: Coding, wire: &'a [u8]) -> Self {
        match coding {
            Coding::Gzip => Body::Gzip(GzipBody::new(wire)),
            Coding::Deflate => Body::Deflate(DeflateBody::new(wire)),
        }
    }

    /// One bounded step. `true` when the whole body is decoded.
    fn step(&mut self, out: &mut Output) -> Result<bool, DecodeError> {
        match self {
            Body::Gzip(gzip) => gzip.step(out),
            Body::Deflate(deflate) => deflate.step(out),
        }
    }
}

const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;

/// Where a gzip body's reading stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Member {
    /// At a member's first byte: the fixed ten-byte header.
    Header,
    /// FEXTRA's two-byte length.
    ExtraLength { flags: u8 },
    /// FEXTRA's data, `left` bytes of it to skip.
    Extra { flags: u8, left: usize },
    /// FNAME, skipped to its NUL.
    Name { flags: u8 },
    /// FCOMMENT, skipped to its NUL.
    Comment { flags: u8 },
    /// FHCRC's two bytes.
    HeaderCrc,
    /// The member's raw deflate data.
    Data,
    /// CRC32 and ISIZE.
    Trailer,
    /// A member ended and its trailer checked: zeros may follow, then
    /// another member or the end.
    Padding,
}

/// gzip as CPython's `gzip` module reads it (Python 3.13, `gzip.py`
/// `_read_gzip_header`, `_GzipReader`), which is what feedparser decodes
/// with, member by member until the input ends:
///
/// - **The header:** the magic `1f 8b` and method 8, else refused; the flag
///   byte's reserved bits ignored, as CPython ignores them; FEXTRA skipped by
///   its length; FNAME and FCOMMENT skipped to their NUL, of any length; and
///   FHCRC's two bytes read but not checked (CPython discards them).
/// - **The data:** raw deflate, required to reach its end.
/// - **The trailer:** CRC32 and ISIZE (the size mod 2^32), both checked.
/// - **After a member:** a run of zeros is skipped; then the input must end
///   or another member start.
///
/// Truncation anywhere is refused, as CPython's `EOFError` is a bozo feed.
struct GzipBody<'a> {
    data: &'a [u8],
    pos: usize,
    state: Member,
    /// Raw deflate, reset for each member.
    inflate: Decompress,
    /// The member's CRC32 and size so far.
    crc: Crc,
}

impl<'a> GzipBody<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            state: Member::Header,
            inflate: Decompress::new(false),
            crc: Crc::new(),
        }
    }

    /// The next `n` bytes, consumed from `budget`: `Ok(None)` when the
    /// budget cannot cover them (the next step can), `Err` when the input
    /// ends first.
    fn take(&mut self, n: usize, budget: &mut usize) -> Result<Option<&'a [u8]>, DecodeError> {
        let data = self.data;
        let field = data
            .get(self.pos..self.pos + n)
            .ok_or(DecodeError::Corrupt)?;
        if *budget < n {
            return Ok(None);
        }
        self.pos += n;
        *budget -= n;
        Ok(Some(field))
    }

    /// Skip to just past the next NUL, as far as `budget` goes. `true` once
    /// it is passed; the input ending first is a truncated header.
    fn skip_to_nul(&mut self, budget: &mut usize) -> Result<bool, DecodeError> {
        let rest = &self.data[self.pos..];
        let window = &rest[..cmp::min(rest.len(), *budget)];
        let (skipped, found) = match window.iter().position(|&b| b == 0) {
            Some(nul) => (nul + 1, true),
            None => (window.len(), false),
        };
        self.pos += skipped;
        *budget -= skipped;
        if !found && self.pos == self.data.len() {
            return Err(DecodeError::Corrupt);
        }
        Ok(found)
    }

    fn start_data(&mut self) -> Member {
        self.inflate.reset(false);
        self.crc.reset();
        Member::Data
    }

    /// One step. `true` when the whole body is decoded.
    fn step(&mut self, out: &mut Output) -> Result<bool, DecodeError> {
        let mut budget = STEP_INPUT;
        loop {
            self.state = match self.state {
                Member::Header => {
                    let Some(header) = self.take(10, &mut budget)? else {
                        return Ok(false);
                    };
                    if header[..3] != [0x1f, 0x8b, 8] {
                        return Err(DecodeError::Corrupt);
                    }
                    let flags = header[3];
                    if flags & FEXTRA != 0 {
                        Member::ExtraLength { flags }
                    } else {
                        Member::Name { flags }
                    }
                }
                Member::ExtraLength { flags } => {
                    let Some(length) = self.take(2, &mut budget)? else {
                        return Ok(false);
                    };
                    let left = usize::from(u16::from_le_bytes([length[0], length[1]]));
                    Member::Extra { flags, left }
                }
                Member::Extra { flags, left } => {
                    // Within the budget by construction; only the input can
                    // end first.
                    let skip = cmp::min(left, budget);
                    self.take(skip, &mut budget)?;
                    if skip < left {
                        self.state = Member::Extra {
                            flags,
                            left: left - skip,
                        };
                        return Ok(false);
                    }
                    Member::Name { flags }
                }
                Member::Name { flags } if flags & FNAME != 0 => {
                    if !self.skip_to_nul(&mut budget)? {
                        return Ok(false);
                    }
                    Member::Comment { flags }
                }
                Member::Name { flags } => Member::Comment { flags },
                Member::Comment { flags } => {
                    if flags & FCOMMENT != 0 && !self.skip_to_nul(&mut budget)? {
                        return Ok(false);
                    }
                    if flags & FHCRC != 0 {
                        Member::HeaderCrc
                    } else {
                        self.start_data()
                    }
                }
                Member::HeaderCrc => {
                    if self.take(2, &mut budget)?.is_none() {
                        return Ok(false);
                    }
                    self.start_data()
                }
                Member::Data => {
                    let rest = &self.data[self.pos..];
                    let input = &rest[..cmp::min(rest.len(), budget)];
                    if input.is_empty() && !rest.is_empty() {
                        return Ok(false);
                    }
                    let crc = &mut self.crc;
                    let inflated =
                        inflate_into(&mut self.inflate, input, out, |bytes| crc.update(bytes))?;
                    self.pos += inflated.consumed;
                    budget -= inflated.consumed;
                    match inflated.status {
                        Ok(Status::StreamEnd) => Member::Trailer,
                        Ok(Status::Ok | Status::BufError)
                            if inflated.consumed > 0 || inflated.produced > 0 =>
                        {
                            return Ok(false)
                        }
                        // Corrupt data, or no progress: the input ended
                        // before the stream did.
                        Ok(_) | Err(_) => return Err(DecodeError::Corrupt),
                    }
                }
                Member::Trailer => {
                    let Some(trailer) = self.take(8, &mut budget)? else {
                        return Ok(false);
                    };
                    let crc32 =
                        u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
                    let isize =
                        u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
                    if crc32 != self.crc.sum() || isize != self.crc.amount() {
                        return Err(DecodeError::Corrupt);
                    }
                    // A member is complete: the next step looks past it.
                    self.state = Member::Padding;
                    return Ok(false);
                }
                Member::Padding => {
                    let rest = &self.data[self.pos..];
                    let zeros = rest.iter().take(budget).take_while(|&&b| b == 0).count();
                    self.pos += zeros;
                    budget -= zeros;
                    if self.pos == self.data.len() {
                        return Ok(true);
                    }
                    if budget == 0 {
                        return Ok(false);
                    }
                    // Something follows the padding, so it must be a member.
                    Member::Header
                }
            };
        }
    }
}

/// deflate as feedparser reads it (`zlib.decompress(data)`, then
/// `zlib.decompress(data, -15)`): zlib-wrapped over the whole buffer,
/// requiring the stream's end; on any failure of that reading (never on
/// `TooLarge`), its output is discarded and raw deflate runs over the whole
/// buffer, again requiring the end. Bytes after the end are ignored.
struct DeflateBody<'a> {
    data: &'a [u8],
    pos: usize,
    inflate: Decompress,
    zlib: bool,
}

impl<'a> DeflateBody<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            inflate: Decompress::new(true),
            zlib: true,
        }
    }

    /// One step. `true` when the stream has ended.
    fn step(&mut self, out: &mut Output) -> Result<bool, DecodeError> {
        let input = &self.data[self.pos..cmp::min(self.data.len(), self.pos + STEP_INPUT)];
        let inflated = inflate_into(&mut self.inflate, input, out, |_| {})?;
        self.pos += inflated.consumed;
        match inflated.status {
            Ok(Status::StreamEnd) => Ok(true),
            Ok(Status::Ok | Status::BufError) if inflated.consumed > 0 || inflated.produced > 0 => {
                Ok(false)
            }
            // No progress: the input ran out before the stream's end
            // (truncated), or the decoder is stuck. Either way, not a stream.
            Ok(_) | Err(_) => self.fail(out),
        }
    }

    fn fail(&mut self, out: &mut Output) -> Result<bool, DecodeError> {
        if !self.zlib {
            return Err(DecodeError::Corrupt);
        }
        // From scratch, with none of the zlib reading's output.
        out.body.clear();
        self.inflate = Decompress::new(false);
        self.zlib = false;
        self.pos = 0;
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use flate2::Compression;
    use http::HeaderValue;
    use serde_json::Value;

    use super::*;
    use crate::ssrf::fetch::{self, BodyCoding};
    use crate::ssrf::{Decompression, FetchPolicy};

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

    /// Run a decode on a fresh current-thread runtime, with no deadline.
    fn run(coding: Coding, wire: &[u8], max_bytes: usize) -> Result<Bytes, DecodeError> {
        steps(coding, wire, max_bytes).0
    }

    /// A decode on a fresh current-thread runtime, with no deadline, and
    /// the steps it took.
    fn steps(coding: Coding, wire: &[u8], max_bytes: usize) -> (Result<Bytes, DecodeError>, usize) {
        let mut count = 0;
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(decode_paced(coding, wire, max_bytes, None, || count += 1));
        (result, count)
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

    // --- feedparser parity -------------------------------------------------

    /// A fixture byte string: hex strings and `[byte, count]` runs.
    fn bytes_of(segments: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        for segment in segments.as_array().expect("a segment list") {
            match segment {
                Value::String(hex) => {
                    assert!(hex.len() % 2 == 0, "{hex}");
                    for i in (0..hex.len()).step_by(2) {
                        out.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
                    }
                }
                Value::Array(run) => {
                    let byte = u8::try_from(run[0].as_u64().unwrap()).unwrap();
                    let count = usize::try_from(run[1].as_u64().unwrap()).unwrap();
                    out.extend(std::iter::repeat_n(byte, count));
                }
                other => panic!("not a segment: {other}"),
            }
        }
        out
    }

    /// What the fetch does with a case's headers and bytes, at the decoder,
    /// through its own classification: identity passes through, a
    /// classified coding is decoded, anything else is refused. `None` for a
    /// refusal.
    fn rust_outcome(headers: &HeaderMap, wire: &[u8], max_bytes: usize) -> Option<Vec<u8>> {
        let policy =
            FetchPolicy::new("feed", max_bytes).with_decompression(Decompression::GzipDeflate);
        match fetch::classify(headers, &policy)? {
            BodyCoding::Identity => Some(wire.to_vec()),
            BodyCoding::Coded(coding) => {
                run(coding, wire, max_bytes).ok().map(|body| body.to_vec())
            }
        }
    }

    /// The decoder against feedparser 6.0.12 (`feedparser.http.get`), case
    /// by case: equal bytes wherever both decode, the same accept-or-refuse
    /// everywhere else on the supported subset, and each residue diverging
    /// exactly as recorded (plan 024 section 3.2).
    #[test]
    fn decoding_matches_feedparser_on_the_supported_subset() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/feedparser_decode.json"))
                .expect("the fixture parses");
        assert_eq!(fixture["provenance"]["feedparser"], "6.0.12");
        assert_eq!(fixture["provenance"]["python"], "3.13.15");
        let cases = fixture["cases"].as_array().expect("cases");
        assert!(cases.len() >= 66, "{} cases", cases.len());
        let mut residues = std::collections::BTreeMap::<&str, usize>::new();
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let mut headers = HeaderMap::new();
            for pair in case["headers"].as_array().unwrap() {
                headers.append(
                    http::HeaderName::from_bytes(pair[0].as_str().unwrap().as_bytes()).unwrap(),
                    HeaderValue::from_str(pair[1].as_str().unwrap()).unwrap(),
                );
            }
            let wire = bytes_of(&case["wire"]);
            let payload = (!case["payload"].is_null()).then(|| bytes_of(&case["payload"]));
            let python = &case["python"];
            let python_body = match &python["body"] {
                Value::String(name) if name == "payload" => payload.clone(),
                Value::String(name) if name == "wire" => Some(wire.clone()),
                Value::Null => None,
                segments => Some(bytes_of(segments)),
            };
            // A feed slaudio would keep: no bozo, nothing raised.
            let python_accepts = python["outcome"] == "ok";
            let rust = rust_outcome(&headers, &wire, 10 * 1024 * 1024);

            match case["residue"].as_str() {
                None => {
                    if python_accepts {
                        assert_eq!(rust, python_body, "{name}: both decode, to the same bytes");
                        assert_eq!(rust, payload, "{name}: and that is the payload");
                    } else {
                        assert_eq!(
                            rust, None,
                            "{name}: feedparser refuses ({python}), so does Rust"
                        );
                    }
                }
                Some(residue) => {
                    *residues.entry(residue).or_default() += 1;
                    assert!(
                        python_accepts,
                        "{name}: feedparser returns a body ({python})"
                    );
                    match residue {
                        // feedparser's case-sensitive `'gzip' in` (and the
                        // last header only) leaves the body coded; Rust
                        // decodes it.
                        "case" | "last-header" => {
                            assert_eq!(
                                python_body.as_deref(),
                                Some(&wire[..]),
                                "{name}: passed through"
                            );
                            assert_eq!(rust, payload, "{name}: Rust decodes");
                        }
                        // Both drop the feed: feedparser passes coded bytes
                        // on (its parser then fails), Rust refuses outright.
                        "stacked-or-unknown" => {
                            assert_ne!(python_body, payload, "{name}: not the feed");
                            assert_eq!(rust, None, "{name}: Rust refuses");
                        }
                        other => panic!("{name}: unknown residue {other}"),
                    }
                }
            }
        }
        // Every recorded residue is exercised.
        for residue in ["case", "last-header", "stacked-or-unknown"] {
            assert!(residues.contains_key(residue), "no {residue} case");
        }
    }

    // --- caps and precedence ------------------------------------------------

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
            assert_eq!(run(coding, &wire, 0).unwrap(), Bytes::new(), "{coding:?}");
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
    fn an_empty_wire_body_is_an_empty_body_without_a_decode() {
        assert_eq!(steps(Coding::Gzip, b"", 0), (Ok(Bytes::new()), 0));
        assert_eq!(steps(Coding::Deflate, b"", 0), (Ok(Bytes::new()), 0));
    }

    /// Even an empty body, which needs no decode, is late once the deadline
    /// has passed.
    #[tokio::test(flavor = "current_thread")]
    async fn an_empty_body_past_the_deadline_is_timed_out() {
        let past = Instant::now();
        let future = Instant::now() + Duration::from_secs(5);
        for coding in [Coding::Gzip, Coding::Deflate] {
            assert_eq!(
                decode(coding, b"", 0, Some(past)).await,
                Err(DecodeError::TimedOut),
                "{coding:?}"
            );
            assert_eq!(
                decode(coding, b"", 0, Some(future)).await,
                Ok(Bytes::new()),
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

    /// The cap is passed while decoding a member whose trailer is corrupt:
    /// the cap answers, and the corruption after it is never looked at.
    #[test]
    fn the_cap_exhausted_before_a_corrupt_trailer_is_too_large() {
        let data = vec![b'y'; 200_000];
        let mut wire = gzip(&data);
        let crc = wire.len() - 8;
        wire[crc] ^= 0xff;
        assert_eq!(
            run(Coding::Gzip, &wire, 100_000),
            Err(DecodeError::TooLarge)
        );
        // With room for the whole member, the trailer is checked.
        assert_eq!(run(Coding::Gzip, &wire, 200_000), Err(DecodeError::Corrupt));
    }

    /// A raw stream whose first bytes also read as a zlib header and a
    /// stored block: zlib decodes `n + 6` bytes of it, then runs out of
    /// input; raw decodes the whole stream to `0x01` and `n` `A`s. (The
    /// fixture's `deflate_zlib_fails_late_raw_succeeds`, at another size.)
    fn zlib_fails_late_raw_succeeds(n: u16) -> Vec<u8> {
        let mut out = vec![0x78, 0x01, 0x00, 0xfe, 0xff, 0x01, 0x00];
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&(!n).to_le_bytes());
        out.extend(std::iter::repeat_n(b'A', usize::from(n)));
        out.extend_from_slice(&[0x03, 0x00]);
        out
    }

    #[test]
    fn a_zlib_failure_after_substantial_output_retries_raw_from_scratch() {
        let wire = zlib_fails_late_raw_succeeds(40_000);
        let mut expected = vec![0x01];
        expected.extend(std::iter::repeat_n(b'A', 40_000));
        // The zlib reading produced 40,006 bytes before failing; none of
        // them survive into the raw reading's body.
        assert_eq!(run(Coding::Deflate, &wire, 1 << 20).unwrap(), expected);
    }

    #[test]
    fn too_large_never_retries_raw() {
        let wire = zlib_fails_late_raw_succeeds(40_000);
        // Raw would fit (40,001 bytes), but the zlib reading passes the cap
        // first, and that is final.
        assert_eq!(
            run(Coding::Deflate, &wire, 40_001),
            Err(DecodeError::TooLarge)
        );
    }

    /// A non-final stored block of `n` bytes, then a block of the reserved
    /// type 3: raw deflate that writes `n` bytes and then fails, in one
    /// inflate call.
    fn output_then_corrupt(n: u16) -> Vec<u8> {
        let mut out = vec![0x00];
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&(!n).to_le_bytes());
        out.extend(std::iter::repeat_n(b'x', usize::from(n)));
        out.push(0x07);
        out
    }

    /// `raw` inside a gzip member: a minimal header, the data, a trailer that
    /// is never reached.
    fn gzip_member_of(raw: &[u8]) -> Vec<u8> {
        let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
        out.extend_from_slice(raw);
        out.extend_from_slice(&[0; 8]);
        out
    }

    /// The bytes an inflate call writes before it reports corruption count
    /// against the cap: past it, `TooLarge` wins over the corruption, in
    /// every coding. (flate2's `GzDecoder::read` dropped that count on an
    /// error, which is why the gzip framing is read here.)
    #[test]
    fn output_before_corruption_counts_against_the_cap() {
        // The review's input: a stored block producing "xx", then an
        // invalid block type.
        let review = [
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x02, 0x00, 0xfd,
            0xff, 0x78, 0x78, 0x07,
        ];
        assert_eq!(run(Coding::Gzip, &review, 1), Err(DecodeError::TooLarge));
        assert_eq!(run(Coding::Gzip, &review, 2), Err(DecodeError::Corrupt));
        for n in [2u16, 40_000] {
            let raw = output_then_corrupt(n);
            let mut zlib = vec![0x78, 0x01];
            zlib.extend_from_slice(&raw);
            for (coding, wire) in [
                (Coding::Gzip, gzip_member_of(&raw)),
                (Coding::Deflate, zlib),
                (Coding::Deflate, raw),
            ] {
                let output = usize::from(n);
                assert_eq!(
                    run(coding, &wire, output - 1),
                    Err(DecodeError::TooLarge),
                    "{coding:?} {n}: below the output"
                );
                // With room for the output, the corruption answers (for zlib,
                // after the raw reading fails too).
                assert_eq!(
                    run(coding, &wire, output),
                    Err(DecodeError::Corrupt),
                    "{coding:?} {n}: at the output"
                );
            }
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
    /// cap, a step past it at most, never inflating the rest.
    #[test]
    fn a_decompression_bomb_stops_at_the_cap() {
        let bomb = gzip_bomb();
        assert!(bomb.len() < 2 << 20, "{} wire bytes", bomb.len());
        let max_bytes = 1 << 20;
        let (result, count) = steps(Coding::Gzip, &bomb, max_bytes);
        assert_eq!(result, Err(DecodeError::TooLarge));
        // 32 KiB a step: the cap is reached in about 32 steps.
        assert!(count <= max_bytes / STEP_OUTPUT + 2, "{count} steps");
        // The bomb is a real one: all of the GiB inflates and the trailer
        // checks, streamed to a sink (in a release build only; a debug build
        // would take a minute).
        if !cfg!(debug_assertions) {
            let mut reader = flate2::read::GzDecoder::new(&bomb[..]);
            assert_eq!(io::copy(&mut reader, &mut io::sink()).unwrap(), 1 << 30);
        }
    }

    // --- steps, yields, the deadline ---------------------------------------

    fn empty_members(count: usize) -> Vec<u8> {
        let member = gzip(b"");
        assert_eq!(member.len(), 20);
        member.repeat(count)
    }

    /// 100,000 empty members are 2,000,000 wire bytes: over the wire cap of
    /// any `max_bytes` up to about 1.77 MB, so the read refuses them before
    /// a decode (the integration tests cover that read). Under a larger cap,
    /// each member is a step of its own, and the decoder yields after every
    /// one: on one thread, the ticker below runs only while the decode
    /// yields.
    #[tokio::test(flavor = "current_thread")]
    async fn a_hundred_thousand_empty_members_are_wire_capped_and_yield_per_member() {
        let wire = empty_members(100_000);
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
        let result = decode_paced(Coding::Gzip, &wire, 2 << 20, None, || count += 1).await;
        ticker.abort();
        assert_eq!(result, Ok(Bytes::new()));
        assert!(count > 100_000, "{count} steps");
        let ticks = ticks.load(Ordering::Relaxed);
        assert!(
            ticks >= 100_000,
            "the ticker ran {ticks} times during the decode"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_decode_that_outlives_the_deadline_is_timed_out() {
        let wire = empty_members(100_000);
        let deadline = Instant::now() + Duration::from_millis(50);
        let mut count = 0;
        let started = std::time::Instant::now();
        let result = decode_paced(Coding::Gzip, &wire, 2 << 20, Some(deadline), || {
            count += 1;
            std::thread::sleep(Duration::from_millis(1));
        })
        .await;
        assert_eq!(result, Err(DecodeError::TimedOut));
        assert!(count < 1000, "stopped after {count} slowed steps");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );

        // And a deflate bomb, the output-heavy case.
        let bomb = zlib(&vec![0u8; 64 << 20]);
        let deadline = Instant::now() + Duration::from_millis(50);
        let result = decode_paced(Coding::Deflate, &bomb, usize::MAX, Some(deadline), || {
            std::thread::sleep(Duration::from_millis(1));
        })
        .await;
        assert_eq!(result, Err(DecodeError::TimedOut));

        // A deadline already past refuses before the first step.
        let mut count = 0;
        let past = Instant::now();
        let result = decode_paced(Coding::Gzip, &gzip(b"x"), 10, Some(past), || count += 1).await;
        assert_eq!((result, count), (Err(DecodeError::TimedOut), 0));
    }

    /// A decode whose last step ends past the deadline is late, not done:
    /// one step, slowed past the deadline, finishes the body, and the
    /// answer is still `TimedOut`. (The fetch's outer timeout would take
    /// the ready body.)
    #[tokio::test(flavor = "current_thread")]
    async fn a_decode_that_finishes_past_the_deadline_is_timed_out() {
        let wire = zlib(b"x");
        let deadline = Instant::now() + Duration::from_millis(50);
        let mut count = 0;
        let result = decode_paced(Coding::Deflate, &wire, 1, Some(deadline), || {
            count += 1;
            std::thread::sleep(Duration::from_millis(100));
        })
        .await;
        assert_eq!((result, count), (Err(DecodeError::TimedOut), 1));
        // The control: the same decode, unslowed, inside the deadline.
        let deadline = Instant::now() + Duration::from_secs(5);
        let result = decode_paced(Coding::Deflate, &wire, 1, Some(deadline), || {}).await;
        assert_eq!(result.as_deref(), Ok(&b"x"[..]));
    }

    /// One step, slowed `slow`, then the answer, under a deadline 50 ms
    /// away.
    async fn one_slow_step(
        coding: Coding,
        wire: &[u8],
        max_bytes: usize,
        slow: Duration,
    ) -> Result<Bytes, DecodeError> {
        let deadline = Instant::now() + Duration::from_millis(50);
        decode_paced(coding, wire, max_bytes, Some(deadline), || {
            std::thread::sleep(slow)
        })
        .await
    }

    /// A step's error is late too: one slowed step that finds a truncated
    /// header past the deadline answers `TimedOut`, not `Corrupt`.
    #[tokio::test(flavor = "current_thread")]
    async fn a_step_error_past_the_deadline_is_timed_out() {
        let slow = Duration::from_millis(100);
        assert_eq!(
            one_slow_step(Coding::Gzip, b"\x1f", 10, slow).await,
            Err(DecodeError::TimedOut)
        );
        assert_eq!(
            one_slow_step(Coding::Deflate, b"\xff\xff", 10, slow).await,
            Err(DecodeError::TimedOut)
        );
        // The controls, unslowed: the corruption answers.
        assert_eq!(
            one_slow_step(Coding::Gzip, b"\x1f", 10, Duration::ZERO).await,
            Err(DecodeError::Corrupt)
        );
    }

    /// The precedence, stated: once the deadline has passed, `TimedOut` wins
    /// over `TooLarge` as over every outcome. Inside it, `TooLarge`.
    #[tokio::test(flavor = "current_thread")]
    async fn the_deadline_wins_over_too_large() {
        let wire = gzip(b"xx");
        assert_eq!(
            one_slow_step(Coding::Gzip, &wire, 1, Duration::from_millis(100)).await,
            Err(DecodeError::TimedOut)
        );
        assert_eq!(
            one_slow_step(Coding::Gzip, &wire, 1, Duration::ZERO).await,
            Err(DecodeError::TooLarge)
        );
    }

    /// Drive a body step by step and check every step's bounds: at most
    /// `STEP_INPUT` consumed, at most `STEP_OUTPUT` produced, and never more
    /// than one byte past the allowance. Returns the result and the steps.
    fn bounded_steps(
        coding: Coding,
        wire: &[u8],
        max_bytes: usize,
    ) -> (Result<Vec<u8>, DecodeError>, usize) {
        let mut out = Output::new(max_bytes);
        let mut body = Body::new(coding, wire);
        let position = |body: &Body<'_>| match body {
            Body::Gzip(gzip) => gzip.pos,
            Body::Deflate(deflate) => deflate.pos,
        };
        for count in 1.. {
            let (pos, len) = (position(&body), out.body.len());
            let step = body.step(&mut out);
            // A raw restart moves back to 0 and clears the output: by these
            // measures, nothing consumed or produced.
            let consumed = position(&body).saturating_sub(pos);
            assert!(consumed <= STEP_INPUT, "step {count} consumed {consumed}");
            let produced = out.body.len().saturating_sub(len);
            assert!(produced <= STEP_OUTPUT, "step {count} produced {produced}");
            // Capacity, not just length, stays within the allowance.
            let capacity = out.body.capacity();
            assert!(
                capacity <= max_bytes,
                "step {count}: capacity {capacity} past {max_bytes}"
            );
            match step {
                Ok(true) => return (Ok(out.body), count),
                Ok(false) => assert!(out.body.len() <= max_bytes),
                Err(e) => {
                    assert!(out.body.len() <= max_bytes);
                    return (Err(e), count);
                }
            }
        }
        unreachable!()
    }

    #[test]
    fn every_step_is_bounded_in_input_and_output() {
        // Incompressible input: output-bound steps.
        let noise: Vec<u8> = (0..1_000_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        for (coding, wire) in every_coding(&noise) {
            let (result, count) = bounded_steps(coding, &wire, 1 << 21);
            assert_eq!(result.as_deref(), Ok(&noise[..]), "{coding:?}");
            assert!(
                count >= noise.len() / STEP_OUTPUT,
                "{coding:?}: {count} steps"
            );
        }
        // Many members, padding between them.
        let mut padded = Vec::new();
        for _ in 0..2_000 {
            padded.extend(gzip(b"abc"));
            padded.extend([0u8; 40]);
        }
        let (result, count) = bounded_steps(Coding::Gzip, &padded, 1 << 20);
        assert_eq!(result.map(|b| b.len()), Ok(6_000));
        assert!(count >= 2_000, "{count} steps");
        // A long run of padding: input-bound steps.
        let mut zeros = gzip(b"abc");
        zeros.extend(vec![0u8; 1 << 20]);
        let (result, count) = bounded_steps(Coding::Gzip, &zeros, 1 << 20);
        assert_eq!(result, Ok(b"abc".to_vec()));
        assert!(count > (1 << 20) / STEP_INPUT, "{count} steps");
        // Empty stored blocks consume input without output: input-bound. A
        // raw stream of 30,000 of them (5 bytes each), then a final empty
        // one; the zlib reading fails at once (0x00 is not a zlib header).
        let mut stored = Vec::new();
        for _ in 0..30_000 {
            stored.extend_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xff]);
        }
        stored.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
        let (result, count) = bounded_steps(Coding::Deflate, &stored, 10);
        assert_eq!(result, Ok(Vec::new()));
        assert!(count > stored.len() / STEP_INPUT, "{count} steps");
        // The bomb, and the cap overshooting by one byte at most.
        let (result, _) = bounded_steps(Coding::Gzip, &gzip_bomb(), 100_000);
        assert_eq!(result, Err(DecodeError::TooLarge));
        // The zlib reading discarded, then the raw one: both bounded.
        let (result, _) = bounded_steps(
            Coding::Deflate,
            &zlib_fails_late_raw_succeeds(40_000),
            1 << 20,
        );
        assert_eq!(result.map(|b| b.len()), Ok(40_001));
    }

    /// Capacity, not only length, is capped: a stored (level 0) gzip body of
    /// 8 MiB + 1 bytes grows the decoded buffer step by step, and at the cap,
    /// one byte under it and one byte over, the buffer's capacity never
    /// passes `max_bytes` (`bounded_steps` checks every step). `Vec`'s own
    /// doubling would end at 16 MiB.
    #[test]
    fn the_decoded_buffer_never_holds_more_than_the_cap() {
        let size = (8 << 20) + 1;
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let wire = {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::none());
            encoder.write_all(&data).unwrap();
            encoder.finish().unwrap()
        };
        let (decoded, _) = bounded_steps(Coding::Gzip, &wire, size);
        let decoded = decoded.unwrap();
        assert_eq!(decoded, data);
        assert!(decoded.capacity() <= size, "{}", decoded.capacity());
        let (decoded, _) = bounded_steps(Coding::Gzip, &wire, size + 1);
        assert!(decoded.unwrap().capacity() <= size + 1);
        let (decoded, _) = bounded_steps(Coding::Gzip, &wire, size - 1);
        assert_eq!(decoded, Err(DecodeError::TooLarge));
    }

    /// Steps `wire` to its end under an allocator that refuses any growth of
    /// the decoded buffer past `refuse_past` bytes. The result, and the
    /// buffer's final length and capacity.
    fn with_refused_growth(
        coding: Coding,
        wire: &[u8],
        max_bytes: usize,
        refuse_past: usize,
    ) -> (Result<(), DecodeError>, usize, usize) {
        let mut out = Output::new(max_bytes);
        out.refuse_growth_past = refuse_past;
        let mut body = Body::new(coding, wire);
        let result = loop {
            match body.step(&mut out) {
                Ok(true) => break Ok(()),
                Ok(false) => {}
                Err(e) => break Err(e),
            }
        };
        (result, out.body.len(), out.body.capacity())
    }

    /// The cap is decided before the buffer grows: output past it is never
    /// stored, so an allocator that would refuse that growth is never asked,
    /// and the answer is `TooLarge`, not a failed allocation. The review's
    /// case: 32,769 bytes under a 32,768-byte cap, where the second step's
    /// one byte proves the overflow, in every coding.
    #[test]
    fn the_cap_is_decided_before_the_buffer_grows() {
        for (coding, wire) in every_coding(&vec![b'x'; 32_769]) {
            assert_eq!(
                run(coding, &wire, 32_768),
                Err(DecodeError::TooLarge),
                "{coding:?}"
            );
            assert_eq!(
                with_refused_growth(coding, &wire, 32_768, 32_768),
                (Err(DecodeError::TooLarge), 32_768, 32_768),
                "{coding:?}: refused growth past the cap is never asked for"
            );
            // The seam bites: growth the cap keeps, refused, is OutOfMemory.
            assert_eq!(
                with_refused_growth(coding, &wire, 32_768, 100).0,
                Err(DecodeError::OutOfMemory),
                "{coding:?}"
            );
        }
    }

    #[test]
    fn multi_member_bodies_split_anywhere_still_decode() {
        // Members of every size around a step's output, back to back with
        // padding: the step boundaries fall everywhere inside them.
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        for (i, size) in [
            0usize,
            1,
            31,
            STEP_OUTPUT - 1,
            STEP_OUTPUT,
            STEP_OUTPUT + 1,
            100_000,
        ]
        .into_iter()
        .enumerate()
        {
            let data: Vec<u8> = (0..size).map(|j| (i * 7 + j) as u8).collect();
            wire.extend(gzip(&data));
            wire.extend(std::iter::repeat_n(0u8, i));
            expected.extend(data);
        }
        assert_eq!(run(Coding::Gzip, &wire, expected.len()).unwrap(), expected);
        assert_eq!(
            run(Coding::Gzip, &wire, expected.len() - 1),
            Err(DecodeError::TooLarge)
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
        for cut in [1, 2, zl.len() / 2, zl.len() - 1] {
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
        assert_eq!(
            run(Coding::Gzip, b"not gzip at all", 1 << 20),
            Err(DecodeError::Corrupt)
        );
        assert_eq!(
            run(Coding::Deflate, b"\xff\xff\xff\xff", 1 << 20),
            Err(DecodeError::Corrupt)
        );
    }

    #[test]
    fn the_decode_future_is_send() {
        fn send<T: Send>(_: &T) {}
        let wire = gzip(b"x");
        send(&decode(Coding::Gzip, &wire, 10, None));
    }
}
