# stridelabs-inworld

A policy-free Inworld text-to-speech client for StrideLabs services: one
non-streaming synthesis per call, on the consumer's `reqwest::Client`,
bounded, classified and safe to log. It replaces the hand-written clients in
tapper (`tapper-rs/src/voice/inworld.rs`), lumen
(`lumen-rs/src/voice/inworld.rs`) and slaudio's Python adapter
(`backend/app/integrations/tts/inworld.py`), to the spec agreed in lumen plan
001 §6.3 and slaudio plan 022 §3.6.

Policy-free means the crate classifies and never retries, chunks text, or
logs the text, the key, a body or the audio. The model, the voice, the
timeout, the bounds, and what to do with each error class stay in the
service.

## Feature topology

`default = []`.

| Feature | Default | Adds |
|---|---|---|
| `client-builder` | off | `client_builder()`: a `reqwest::ClientBuilder` with reqwest's rustls backend, `no_proxy()` and `redirect::Policy::none()`. It turns on reqwest's `rustls` feature: rustls's aws-lc-rs provider and the OS trust store, never ring. |

**No TLS without `client-builder`.** Like stridelabs-gcp, the crate's
`reqwest` (0.13) has no features at all, and every constructor takes your
`reqwest::Client`, so the TLS stack and the process's rustls provider are
your choice. Inworld is `https://`: either turn on `client-builder`, or
enable a TLS feature on your own reqwest (`rustls`: the aws-lc-rs provider
plus the OS trust store). `client-builder` is the same reqwest feature
stridelabs-http's `proxy` and `ssrf` turn on, so a service with both compiles
it once. Keep aws-lc-rs the only rustls provider in your graph (the root
README, "One crypto provider").

## Adding the dependency

```toml
[dependencies]
stridelabs-inworld = { git = "https://github.com/charliek/stridelabs-rust.git", rev = "<sha>", features = ["client-builder"] }
```

The crate is unreleased: pin `rev = "<sha>"` until a tag contains it, then
`tag = "vX.Y.Z"`. See the workspace root README for the local `[patch]`
co-development snippet.

## Usage

```rust
use std::time::Duration;
use stridelabs_inworld::{client_builder, AudioConfig, InworldClient, SynthesisRequest};

// At startup. One reqwest client, shared: it is the connection pool.
let http = client_builder().build()?;
let inworld = InworldClient::builder(http, &config.inworld_api_key)
    .timeout(Duration::from_secs(90))   // default 15 s
    .max_text_chars(1_900)              // default 600
    .build()?;

// Per synthesis.
let request = SynthesisRequest::new(
    &text,
    "Ashley",
    "inworld-tts-2-flash",
    AudioConfig::new("MP3").with_bit_rate(64_000).with_speaking_rate(1.0),
)
.with_language("en-US")
.with_delivery_mode("BALANCED");
match inworld.synthesize(&request).await {
    Ok(synthesis) => store(synthesis.audio, synthesis.usage.processed_characters_count),
    Err(error) if error.is_retryable() => tracing::warn!(%error, "Inworld unavailable"),
    Err(error) => tracing::error!(%error, "Inworld synthesis failed"),
}
```

## The wire

```text
POST {base}/tts/v1/voice
Authorization: Basic <key>                       (marked sensitive)
Content-Type: application/json
{"text":…,"voiceId":…,"modelId":…,"language"?:…,"deliveryMode"?:…,
 "audioConfig":{"audioEncoding":…,"bitRate"?:…,"speakingRate"?:…,"sampleRateHertz"?:…}}
  -> 2xx {"audioContent":"<base64>","usage":{"processedCharactersCount":…,"modelId":…}}
```

- **The body** is exactly those fields, in that order, and every unset
  option is **omitted**, never sent as `null`. Strings are sent as given; the
  speaking rate is not range-checked (Inworld answers an out-of-range one
  with a `4xx`), but a NaN or infinite one, which JSON cannot carry, is
  refused before sending.
- **The key** is used verbatim after trimming (an Inworld key is already the
  base64 credential), as `Authorization: Basic <key>`, with the header marked
  sensitive so hyper never renders it. A key that is empty after trimming, or
  holds a byte no header can carry, is `UnusableKey` on every synthesis, and
  nothing is sent.
- **The base URL** is `https://api.inworld.ai` unless set. It must be
  `https://`, or plain `http://` to a loopback IP literal (`127.0.0.0/8`,
  `[::1]`; not `localhost`), the seam for a test's mock, with no userinfo,
  query or fragment. A path prefix is kept.
- **The answer** is strict standard base64 (canonical padding, no
  whitespace, no stray trailing bits). It comes back as `Synthesis { audio:
  Bytes, usage: Usage { processed_characters_count: Option<u64>, model_id:
  Option<String> } }`. A `usage` field that is absent or has another type is
  `None` and never fails the synthesis; an empty `modelId` is `None`.
- **The MP3 check is on by default** (`mp3_check(false)` turns it off): the
  audio must open with an ID3v2 tag or an MPEG frame sync, exactly
  `starts_with(b"ID3") || (len >= 2 && b[0] == 0xFF && (b[1] & 0xE0) == 0xE0)`
  (slaudio's `mp3.py`). It is blind to the requested encoding: turn it off
  for anything but `MP3`.

## The client you hand in

- **It must not follow redirects.** Build it with
  `reqwest::redirect::Policy::none()`, as `client_builder()` does. A `3xx` is
  an answer here (`Rejected`), so `Authorization` is never replayed at a host
  the configuration did not name. A client that follows one sends the request
  somewhere else and has its answer read as Inworld's; reqwest strips the
  header on a cross-origin hop, but not on a same-origin one.
- **It should not use a proxy** you did not choose: reqwest reads
  `HTTPS_PROXY`/`ALL_PROXY` from the environment unless told `no_proxy()`
  (`client_builder()` is).
- **It should carry no default credentials** (`default_headers`): they go out
  on every request.
- **Its timeout does not matter.** Each synthesis carries the client's own
  timeout (`RequestBuilder::timeout`), which overrides it.

## The bounds

Builder options, with lumen's defaults (`InworldBounds::DEFAULT`):

| Bound | Default | When it is passed |
|---|---|---|
| `timeout` | 15 s | The whole exchange, connect to the last body byte, set on each request: a stall before the headers or after them is `Unavailable(TimedOut)`. Zero is refused at `build()`. |
| `max_response_bytes` | 4 MiB | Refused **unread** when the `Content-Length` declares more; otherwise read chunk by chunk and cut at the first chunk that would pass it, never buffered whole: `Malformed(BodyTooLarge)`. |
| `max_audio_bytes` | 2 MiB | Checked on the base64 length **before decoding** (`Malformed(AudioContentTooLong)`), then on the decoded length (`Malformed(AudioTooLarge)`). The pre-decode bound is a whole number of base64 quanta, so audio up to two bytes over passes it and is caught after decoding. |
| `max_text_chars` | 600 | Unicode scalar values (`chars().count()`), before anything is sent: `TextTooLong { chars, max }`. |

## Errors

`InworldError` is `#[non_exhaustive]`. Only `Unavailable` is retryable
(`is_retryable()`).

| Inworld | `InworldError` | Retryable |
|---|---|---|
| `408`, `429`, a `5xx` | `Unavailable { reason: Status(code), cause: None }` | yes |
| the timeout, before or after the headers | `Unavailable { reason: TimedOut, cause: Some(_) }` | yes |
| a connection that could not be made | `Unavailable { reason: Connect, cause: Some(_) }` | yes |
| a connection that broke, a body cut off before its declared length, an unparseable response, an HTTP/2 GOAWAY | `Unavailable { reason: Transport, cause: Some(_) }` | yes |
| any other non-`2xx`: a `4xx`, a `3xx` (never followed) | `Rejected(code)` | no |
| a `2xx` that is too large, not a JSON object, without a string `audioContent`, not base64, empty, over the audio bound, or (check on) not MP3-shaped | `Malformed(MalformedReason::…)` | no |
| a key empty after trimming, or holding a byte no header can carry | `UnusableKey` | no |
| text over `max_text_chars` | `TextTooLong { chars, max }` | no |
| a NaN or infinite speaking rate | `SpeakingRateNotFinite` | no |

The last three send nothing. A non-`2xx` body is never read, so no
provider-supplied text (an RPC message, an echo of the request) can reach an
error. A `408` is retryable, as lumen 001 §6.3 and slaudio's Python adapter
classify it.

`UnavailableReason` and `MalformedReason` are `Copy`, `#[non_exhaustive]`
enums whose `Display` is a fixed phrase, so a service can map each to its own
message without matching on text.

A transport failure's `cause` is a `TransportCause` (`Copy`,
`#[non_exhaustive]`): `stage`, a `TransportStage` (`Connect`, `Request`,
`Body`, `Decode`, `Other`, from reqwest's `is_connect`, `is_request`,
`is_body` and `is_decode`), `timed_out` (`is_timeout`), and `io`, the kind
of the innermost `std::io::Error` in the source chain when there is one. It
renders as fixed phrases, for example `Inworld is unavailable: the connection
could not be made (failed while connecting; I/O error: connection refused)`.
The `reqwest::Error` itself is dropped; no `InworldError` has a `source()`.
`InworldError` is `Clone`, `PartialEq` and `Eq`.

`BuildError` (from `build()`): `InvalidBaseUrl(&'static str)`, naming why
and never the URL, and `ZeroTimeout`.

## Nothing it handles reaches a log

- Every `Display` and `Debug` of an error is fixed phrases, a status code, a
  count or a `std::io::ErrorKind`, and `source()` is always `None`.
- A transport failure keeps no `reqwest::Error`. Its source chain can carry
  what the peer sent: h2 renders an HTTP/2 GOAWAY's debug data in both
  `Display` and `Debug`, and `without_url()` strips only the URL. So it is
  reduced to a `TransportCause` and dropped.
- Never a `serde_json` message (it can quote the body), the text, the key or
  a body: error bodies are never read, and a `2xx` body's parse errors are
  dropped unrendered.
- The `Debug` of the client, its builder, a `SynthesisRequest`, a
  `Synthesis` and its `Usage` show neither the key, the text, the audio nor
  the provider's `modelId`: the builder shows no base URL (it is not
  validated yet), the client the validated endpoint, a request its text's
  length, a synthesis its audio's length, `Usage` the model id's length
  (`Some(<12 chars>)`). The value itself is returned as given.

`tests/redaction.rs` plants canaries in the key, the text, the response
bodies, the base URL's path, a successful answer's `usage.modelId`, and the
places a peer can put them inside a transport failure (a malformed status
line, a header no parser accepts, an HTTP/2 GOAWAY's debug data), and
asserts none of them appears in any rendering of the error or the result
(`Display`, `{:?}`, `{:#?}`, and each `source()`). Controls prove the
canaries were really sent, and that the GOAWAY's debug data really is in
reqwest's own error, so its absence from ours means something.

## Tests

No test reaches the real Inworld: wiremock and raw TCP servers on
`127.0.0.1` only.

- `tests/bounds.rs`: the bounds, including lumen L1.8's four blind spots: an
  endless chunked stream cut at the response bound before the timeout; a
  stall after the headers (and one before them) ending at the timeout; a
  declared-oversized `Content-Length` that then stalls, refused at once; and
  audio of `MAX_AUDIO_BYTES + 2`, refused before decoding (`+ 1` is caught
  only after). The first three use a raw TCP server, since wiremock cannot
  stall after its headers or stream without end.
- `tests/synthesize.rs`: the exact request, every status class, redirects
  never followed, the trimmed key, the refusals that send nothing, the MP3
  check both ways, `usage` absent and present.
- `tests/redaction.rs`: the canaries above.
