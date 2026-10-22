//! A policy-free Inworld text-to-speech client for StrideLabs services.
//!
//! One non-streaming synthesis per call, on the consumer's
//! `reqwest::Client`:
//!
//! ```text
//! POST {base}/tts/v1/voice
//! Authorization: Basic <key>                       (marked sensitive)
//! Content-Type: application/json
//! {"text":…,"voiceId":…,"modelId":…,"language"?:…,"deliveryMode"?:…,
//!  "audioConfig":{"audioEncoding":…,"bitRate"?:…,"speakingRate"?:…,"sampleRateHertz"?:…}}
//!   -> 2xx {"audioContent":"<base64>","usage":{"processedCharactersCount":…,"modelId":…}}
//! ```
//!
//! Every unset option is omitted, never sent as `null`. The answer is the
//! decoded audio and the `usage` fields ([`Synthesis`]).
//!
//! Policy-free: the crate classifies and never retries, chunks text, or logs
//! the text, the key, a body or the audio. The model, the voice, the timeout,
//! the bounds, and what to do with each error class are the caller's.
//!
//! ```no_run
//! # async fn example(http: reqwest::Client, api_key: &str) -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::Duration;
//! use stridelabs_inworld::{AudioConfig, InworldClient, SynthesisRequest};
//!
//! let inworld = InworldClient::builder(http, api_key)
//!     .timeout(Duration::from_secs(90))
//!     .max_text_chars(1_900)
//!     .build()?;
//! let request = SynthesisRequest::new(
//!     "Hello there.",
//!     "Ashley",
//!     "inworld-tts-2-flash",
//!     AudioConfig::new("MP3").with_bit_rate(64_000),
//! );
//! match inworld.synthesize(&request).await {
//!     Ok(synthesis) => println!("{} bytes of MP3", synthesis.audio.len()),
//!     Err(error) if error.is_retryable() => println!("try again later: {error}"),
//!     Err(error) => println!("giving up: {error}"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # The client
//!
//! [`InworldClient::builder`] takes the caller's `reqwest::Client`, which
//! **must not follow redirects** (`reqwest::redirect::Policy::none()`): a
//! `3xx` is an answer here ([`InworldError::Rejected`]), so `Authorization`
//! is never replayed at a host the configuration did not name. It **must not
//! retry** either (`.retry(reqwest::retry::never())`; reqwest 0.13's default
//! replays a request refused at the protocol level), and should decode no
//! body (`no_gzip()` and the rest: a decoder drops `Content-Length`, which
//! defeats the response pre-check) and use no proxy it did not choose.
//! Feature `client-builder` adds `client_builder()`, a `reqwest::ClientBuilder`
//! set up that way: the rustls backend (rustls's aws-lc-rs provider, unless
//! the process installed another default first), `no_proxy()`, no
//! redirects, no retries and no decoders.
//!
//! The base URL is `https://`, or plain `http://` to a loopback IP literal,
//! the seam for a test's mock ([`InworldClientBuilder::base_url`]).
//!
//! # The bounds
//!
//! Builder options, with lumen's defaults ([`InworldBounds`]):
//!
//! | bound | default | when it is passed |
//! |---|---|---|
//! | [`InworldBounds::timeout`] | 15 s | the whole exchange, connect to the last body byte, set on each request: [`UnavailableReason::TimedOut`] |
//! | [`InworldBounds::max_response_bytes`] | 4 MiB | refused unread when `Content-Length` says so, otherwise cut chunk by chunk while streaming, never buffered whole: [`MalformedReason::BodyTooLarge`] |
//! | [`InworldBounds::max_audio_bytes`] | 2 MiB | on the base64 length, before decoding ([`MalformedReason::AudioContentTooLong`]), and on the decoded length ([`MalformedReason::AudioTooLarge`]) |
//! | [`InworldBounds::max_text_chars`] | 600 | Unicode scalar values, before anything is sent: [`InworldError::TextTooLong`] |
//!
//! The response is strict standard base64. **The MP3 check is on by
//! default** ([`InworldClientBuilder::mp3_check`]): the audio must open with
//! an ID3v2 tag or an MPEG frame sync (`0xFF`, then a byte whose top three
//! bits are set): exactly lumen 001 §6.3's `starts_with(b"ID3") || (len >= 2
//! && b[0] == 0xFF && (b[1] & 0xE0) == 0xE0)`, so a 2-byte frame sync passes.
//! (slaudio's Python `mp3.py` also refuses anything under 3 bytes; this does
//! not.) Only zero bytes of audio are refused as empty.
//!
//! # What a failure becomes
//!
//! | Inworld | [`InworldError`] | retryable |
//! |---|---|---|
//! | `408`, `429`, any status of `500` or more (`600`–`999` included), a timeout (before or after the headers), a connection that could not be made or broke | [`InworldError::Unavailable`] | yes |
//! | any other non-`2xx`: a `4xx`, a `3xx` not followed | [`InworldError::Rejected`] (`{ status, .. }`) | no |
//! | a `2xx` that is not JSON, not base64, empty, too large, or (check on) not MP3-shaped | [`InworldError::Malformed`] | no |
//! | a key that is empty after trimming or holds a byte no header can carry; nothing sent | [`InworldError::UnusableKey`] | no |
//! | text over the bound, or a NaN or infinite speaking rate; nothing sent | [`InworldError::TextTooLong`], [`InworldError::SpeakingRateNotFinite`] | no |
//!
//! # Nothing it handles reaches a log
//!
//! Every `Display` and `Debug` of an [`InworldError`] is fixed phrases, a
//! status code, a count or a `std::io::ErrorKind`, and its `source()` is
//! always `None`. A transport failure keeps no `reqwest::Error`: its source
//! chain can carry what the peer sent (h2 renders an HTTP/2 GOAWAY's debug
//! data in both `Display` and `Debug`), and `without_url()` strips only the
//! URL. It is reduced to a [`TransportCause`] instead: where it failed
//! ([`TransportStage`]: the connect, the send, or a body read), whether it
//! timed out, and the innermost I/O error kind. Never a `serde_json` message, the text, the key
//! or a body: an error body is never read, and a `2xx` body's parse errors
//! are dropped unrendered. The `Debug` of the client, its builder, a request,
//! a [`Synthesis`] and its [`Usage`] show neither the key, the text, the
//! audio nor the provider's `modelId` (its length only). The crate's
//! redaction tests hold each path with canaries.
//!
//! # Feature topology
//!
//! `default = []`. Feature-gated items are named in plain code spans, never
//! intra-doc links, so `cargo doc` without `--all-features` stays clean.
//!
//! | Feature | Default | Adds |
//! |---|---|---|
//! | `client-builder` | off | `client_builder()`, via reqwest's `rustls` (rustls's aws-lc-rs provider and the OS trust store; never ring). Off, the crate picks no TLS stack. |

mod client;
mod error;
mod request;
mod response;

pub use client::{
    InworldBounds, InworldClient, InworldClientBuilder, DEFAULT_BASE_URL, DEFAULT_MAX_AUDIO_BYTES,
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_MAX_TEXT_CHARS, DEFAULT_TIMEOUT, SYNTHESIS_PATH,
};
pub use error::{
    BuildError, InworldError, MalformedReason, TransportCause, TransportStage, UnavailableReason,
};
pub use request::{AudioConfig, SynthesisRequest};
pub use response::{Synthesis, Usage};

/// A `reqwest::ClientBuilder` for [`InworldClient::builder`]: reqwest's
/// rustls backend, `no_proxy()`, `redirect::Policy::none()`,
/// `retry::never()`, and every body decoder off.
///
/// - **TLS:** rustls with the OS trust store. Its provider is aws-lc-rs
///   (reqwest's `rustls` feature) unless the process installed another
///   default first; keep aws-lc-rs the only provider in the graph (the
///   workspace README's "One crypto provider").
/// - **No proxy:** reqwest would otherwise read `HTTPS_PROXY`/`ALL_PROXY`
///   from the environment and send the key through whatever they name.
/// - **No redirects:** a `3xx` is handed back, and becomes
///   [`InworldError::Rejected`]; `Authorization` never follows it.
/// - **No retries:** reqwest 0.13's default policy replays a request the
///   server refused at the protocol level (an HTTP/2 `REFUSED_STREAM`, a
///   GOAWAY). The crate never retries, and neither does its client: a
///   second attempt is the caller's decision ([`InworldError::is_retryable`]).
/// - **No decoders:** `no_gzip()`, `no_brotli()`, `no_deflate()` and
///   `no_zstd()`, whether or not a crate in the graph turned the decoders on.
///   A decoded response loses its `Content-Length`, and with it the
///   pre-check that refuses a declared-oversized body unread
///   ([`InworldBounds::max_response_bytes`]); Inworld's JSON is not asked to
///   come coded.
/// - **No timeout of its own:** each synthesis carries
///   [`InworldBounds::timeout`].
///
/// Add anything else (a user agent, pool settings) before `build()`. Build
/// one client and share it: it is the connection pool.
#[cfg(feature = "client-builder")]
pub fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .tls_backend_rustls()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
}
