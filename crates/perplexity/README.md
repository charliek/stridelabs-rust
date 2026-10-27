# stridelabs-perplexity

A policy-free web-search client for Perplexity's
[Agent API](https://docs.perplexity.ai/api-reference/agent-post), for
StrideLabs services: one search per call, on the consumer's
`reqwest::Client`, bounded, classified and safe to log. It replaces lumen's
hand-written Sonar client (`lumen-rs/src/chat_tools_net.rs`), whose chat
completions endpoint Perplexity retired on 2026-09-27 in favour of the
Agent API ([migration guide](https://docs.perplexity.ai/docs/agent-api/migrate-from-sonar/overview)),
to lumen plan 002 §3 W4b-1's spec. tapper searches through Perplexity too
and can adopt it in place of its own Sonar parse.

Policy-free means the crate classifies and never retries, or logs the input,
the key, a body or the answer. The effort, the timeout, the bounds, what to
show of an answer, and what to do with each error class stay in the service.
It is a search client, not an Agent API SDK: no models, presets, tools,
instructions, streaming or background responses.

## Feature topology

None, and no `default` features. It turns on serde_json's `raw_value`
(no dependency of its own) for the lenient reads below, so a consumer's
serde_json gains `RawValue`; nothing else changes.

**No TLS.** Like stridelabs-gcp and stridelabs-inworld's core, the crate's
`reqwest` (0.13, the workspace's, `default-features = false`) has no
features at all, and every constructor takes your `reqwest::Client`, so the
TLS stack and the process's rustls provider are your choice. Perplexity is
`https://`: enable a TLS feature on your own reqwest (`rustls`: the
aws-lc-rs provider plus the OS trust store). Keep aws-lc-rs the only rustls
provider in your graph (the root README, "One crypto provider").

## Adding the dependency

```toml
[dependencies]
stridelabs-perplexity = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.11.0" }
reqwest = { version = "0.13", default-features = false, features = ["rustls"] }
```

New in v0.10.0. See the workspace root README for the local `[patch]`
co-development snippet.

## Usage

```rust
use std::time::Duration;
use stridelabs_perplexity::{Effort, PerplexityClient, PerplexityError};

// At startup. One reqwest client, shared: it is the connection pool. Built
// the way "The client you hand in" below says.
let http = reqwest::Client::builder()
    .no_proxy()
    .redirect(reqwest::redirect::Policy::none())
    .retry(reqwest::retry::never())
    .no_gzip()
    .no_brotli()
    .no_deflate()
    .no_zstd()
    .build()?;
let perplexity = PerplexityClient::builder(http, &config.perplexity_api_key)
    .base_url(&config.perplexity_base_url) // default https://api.perplexity.ai
    .timeout(Duration::from_secs(30))      // default 30 s
    .effort(Effort::Fast)                  // default fast
    .build()?;

// Per search.
match perplexity.search(&query).await {
    Ok(answer) => {
        let sources = answer.sources(6, 200); // optional display rows
        reply(&answer.text, &sources);
        // A citation `[n]` in the text is a result id, never a position:
        let cited = answer.results.iter().find(|result| result.id == 5);
    }
    Err(PerplexityError::Unavailable(reason)) => tracing::warn!(%reason, "search unavailable"),
    Err(PerplexityError::Incomplete { status, .. }) => tracing::warn!(%status, "search did not complete"),
    Err(error) => tracing::error!(%error, "search failed"),
}
```

## The wire

```text
POST {base}/v1/agent
Authorization: Bearer <key>                      (marked sensitive)
Content-Type: application/json
{"effort":"fast","input":…,"max_output_tokens"?:…}
  -> 2xx {"status":"completed",
          "output":[{"type":"search_results","queries":[…],"results":[{"id":1,"url":…,"title":…,"snippet":…,
                                                                       "date"?:…,"last_updated"?:…,"source"?:…}]},
                    {"type":"message","content":[{"type":"output_text","text":"… [1]","annotations":[]}]}],
          "usage":{"input_tokens":…,"output_tokens":…,"total_tokens":…,"cost":{"total_cost":…,"currency":…}}, …}
```

- **The body** is exactly those fields, in that order: `effort`, `input`,
  and `max_output_tokens` only when set (never `null`). The input is sent as
  given.
- **The key** is used verbatim after trimming, as `Authorization: Bearer
  <key>`, with the header marked sensitive so hyper never renders it. A key
  that is empty after trimming (`BuildError::EmptyApiKey`), or holds a byte no
  header can carry (`BuildError::InvalidApiKey`), is refused by `build()`.
  Only the header value is kept, never the key as a string.
- **The base URL** is `https://api.perplexity.ai` unless set. It must be
  `https://`, or plain `http://` to a loopback IP literal (`127.0.0.0/8`,
  `[::1]`; not `localhost`), the seam for a test's mock, with no userinfo,
  query or fragment. A path prefix is kept and a trailing slash tolerated:
  lumen-fakes' `http://127.0.0.1:58200/perplexity` requests
  `/perplexity/v1/agent`.
- **The status decides first.** Only `completed` is an answer. `failed`,
  `incomplete`, `in_progress`, `queued`, `cancelled` or any other string is
  `Incomplete { status }` (an undocumented string is `ResponseStatus::Other`,
  never kept), whatever text the response carried: no partial text is
  returned as complete, and the response's `error` object is never read. A
  missing or non-string `status` is `Malformed(MissingStatus)`, and a
  `status` that comes twice (an escaped spelling of the key included,
  whatever the values and their order) is `Malformed(DuplicateStatus)`:
  last-wins would let `"incomplete","completed"` promote partial text.
- **So does every message's own status.** Inside a `completed` response, a
  `message` item whose `status` is present and not `completed` (any role's:
  fail closed) makes the response `Incomplete` with that status (a non-string
  one is `Other`; `null` is absent); a repeated `status` on an item counts
  every value. This is checked before the text, so an unfinished message is
  never `MissingAnswer`.
- **The answer** (`SearchAnswer`, `#[non_exhaustive]`) is faithful to the
  response:
  - `text`: every `output_text` part of every assistant `message` item, in
    order, concatenated with no separator. A message whose `role` is present
    and not `assistant` (a user-role echo of the query, a role that is not a
    string, a repeated role with any such value) contributes none; an absent
    or `null` role is the assistant's. Empty or only whitespace is
    `Malformed(MissingAnswer)`. Otherwise as given, untrimmed.
  - `results: Vec<SearchResult>`: every entry of every `search_results`
    item, in order. `SearchResult` (`#[non_exhaustive]`) is `id: i64`, `url:
    String` and `Option<String>`s for `title`, `date`, `last_updated`,
    `snippet` and `source`. **Citations use `results[].id`, not positions**:
    several `search_results` items share one id space, ids are kept as
    given, and gaps and repeats are allowed ([Perplexity's citation
    contract](https://docs.perplexity.ai/docs/cookbook/articles/streaming-citations)).
  - `status`: always `ResponseStatus::Completed` on an answer.
  - `usage: Option<Usage>`: `input_tokens`, `output_tokens`, `total_tokens`
    (non-negative integers), `total_cost` (a number) and `currency` (a
    non-empty string), each `Option`. A `usage` that is absent or not an
    object is `None`; an ill-typed field is `None`. Neither fails the search
    (the answer is what was paid for).
- **Malformed pieces are left out, not fatal.** A result entry with no
  integer `id` (a float, a string, out of `i64` range) or no non-empty string
  `url` is skipped; a `results` that is not an array gives no results from
  its item; an optional field of another type, or empty, is `None`. So is a
  number serde_json cannot represent (`1e400`, `-1e400`, an integer of 400
  digits) at any position the crate reads: a usage count or cost becomes
  `None`, an entry with such an `id` is skipped, such a `title` is `None`
  (a 30-digit integer is a float to serde_json: never a count or an id, but
  a cost). None of these fails the answer; a syntax error is still
  `Malformed(NotJson)`.
- **The body must be valid UTF-8 throughout,** checked before parsing, a
  field the crate never reads included (`Malformed(NotUtf8)`): serde_json
  would skip an ignored string by its delimiters alone.
- **The answer is read, not built.** The body is parsed straight into those
  fields by hand-written serde visitors: the top level must be a JSON object
  (else `Malformed(NotJson)`, as for trailing data), and every other value is
  taken only in the kinds its reader wants and otherwise skipped with serde's
  `IgnoredAny` (iteratively, whatever its depth), so the response bound is
  also the memory bound. A `serde_json::Value` of the body would cost some
  32 bytes per JSON value. Each value the crate reads is first captured as
  its raw text (a `&RawValue` borrowed from the body, nothing copied), then
  read: serde_json range-checks a number before any visitor sees it, so
  read directly, one `1e400` would fail the body. A key that repeats keeps
  its last value, except the completion evidence above (`status`, and a
  message's `role` and `status`).

### `SearchAnswer::from_json(body)`

The same parse `search()` runs on a `2xx` body, every rule above included,
on a body you already have: a recorded response, or a test's. It is the
way to build a `SearchAnswer` (a `#[non_exhaustive]` struct)
outside the crate, for a consumer's tests of what it makes of an answer
(its formatting, its cards) without a server. It applies no size bound:
the body is yours, where `search()` refuses one over `max_response_bytes`
first.

```rust
let answer = SearchAnswer::from_json(include_bytes!("fixtures/agent_response.json"))?;
assert!(answer.text.ends_with("[5]"));
```

### `SearchAnswer::sources(max, title_chars)`

An optional display helper, never applied implicitly: a `Vec<Source>`
(`#[non_exhaustive]`: `id`, `title`, `url`, `domain`, `date`), from
`results` in order, keeping only `http`/`https` URLs that parse and carry no
userinfo, the first of any duplicate URL (compared parsed: `https://A.example`
and `https://a.example/` are one), at most `max` rows. The title is trimmed and
cut to `title_chars` characters at a char boundary, the domain when the result
has none; the URL is the parsed URL re-serialized; the domain is the host,
lower-case, without a leading `www.`. `results` is untouched, so a citation
whose row the helper drops (a duplicate URL under another id) still resolves
there. lumen uses `sources(6, 200)` for its tool result and its sources card.

## The client you hand in

- **It must not follow redirects.** Build it with
  `reqwest::redirect::Policy::none()`. A `3xx` is an answer here
  (`Rejected`), so `Authorization` is never replayed at a host the
  configuration did not name. A client that follows one sends the request
  somewhere else and has its answer read as Perplexity's; reqwest strips the
  header on a cross-origin hop, but not on a same-origin one.
- **It must not retry.** Build it with `.retry(reqwest::retry::never())`.
  reqwest 0.13's default policy replays a request the server refused at the
  protocol level (an HTTP/2 `REFUSED_STREAM`, a GOAWAY `NO_ERROR`) up to
  twice. The crate's "exactly one exchange" would not hold, and whether to
  search again (a second billed search) is the caller's.
- **It should decode no body**: `.no_gzip().no_brotli().no_deflate().no_zstd()`.
  A decoder that any crate in the graph turns on (Cargo unifies reqwest's
  features) decodes a coded response and drops its `Content-Length`, which
  defeats the pre-check: a declared-oversized body that stalls is then
  waited out to the timeout instead of refused at once. The chunk-by-chunk
  cut still bounds what is read.
- **It should not use a proxy** you did not choose: reqwest reads
  `HTTPS_PROXY`/`ALL_PROXY` from the environment unless told `no_proxy()`.
- **It should carry no default credentials** (`default_headers`): they go out
  on every request.
- **Its timeout does not matter.** Each search carries the client's own
  timeout (`RequestBuilder::timeout`), which overrides it.

## The bounds

Builder options, with lumen's defaults:

| Bound | Default | When it is passed |
|---|---|---|
| `timeout` | 30 s | The whole exchange, connect to the last body byte, set on each request: a stall before the headers is `Unavailable(Timeout(Phase::Headers))`, after them `Unavailable(Timeout(Phase::Body))`. |
| `max_response_bytes` | 2 MiB | Refused **unread** when the `Content-Length` declares more; otherwise read chunk by chunk and cut at the first chunk that would pass it, never buffered whole: `Malformed(BodyTooLarge)`. The buffer reserves at most 64 KiB up front, whatever the declared length, and grows only as bytes arrive. (The recorded real answer came chunked, with no `Content-Length`: the cut is what bounds it.) |
| `max_input_chars` | 2,000 | Unicode scalar values (`chars().count()`), before anything is sent: `InputTooLong { chars, max }`. |
| `max_output_tokens` | unset | The API's own `max_output_tokens` (integer ≥ 1), sent only when set: a bound on the answer's length and its output cost. An answer it cuts short comes back `incomplete`, which is `Incomplete`. |

`effort` is one of the documented levels, `Effort::{Fast, Low, Medium, High,
XHigh}` (`#[non_exhaustive]`), sent as its lowercase name; `Fast` unless set.

Zero for any bound is refused at `build()`: `BuildError::ZeroTimeout`,
`ZeroMaxResponseBytes`, `ZeroMaxInputChars`, `ZeroMaxOutputTokens`.

## Errors

`PerplexityError` is `#[non_exhaustive]`, `Clone`, `PartialEq` and `Eq`.

| Perplexity | `PerplexityError` |
|---|---|
| `408`, `429`, any status of `500` or more (the `5xx`, and the `600`–`999` hyper also accepts) | `Unavailable(UnavailableReason::Status(code))` |
| the timeout, before or after the headers | `Unavailable(UnavailableReason::Timeout(phase))` |
| a connection that could not be made or broke, a body cut off before its declared length, an unparseable response head, an HTTP/2 GOAWAY | `Unavailable(UnavailableReason::Transport { phase, io, .. })` |
| any other non-`2xx`: a `4xx`, a `3xx` (never followed), a `1xx` final status | `Rejected { status, .. }` |
| a `2xx` whose `status` is not `completed`, or with a `message` item whose own `status` is not `completed` | `Incomplete { status, .. }` |
| a `2xx` that is too large, not UTF-8, not a JSON object, without a string `status`, with `status` twice, or `completed` with no assistant answer text | `Malformed(MalformedReason::{BodyTooLarge, NotUtf8, NotJson, MissingStatus, DuplicateStatus, MissingAnswer})` |
| input over `max_input_chars`; nothing sent | `InputTooLong { chars, max }` |

**The status is classified before any body is read**, and a non-`2xx` body
is never read, so no provider-supplied text (an error message, an echo of
the request) can reach an error. Only `Unavailable` may answer differently
next time; whether to retry, and how often, is the caller's (lumen maps
`Unavailable` and `Incomplete` to "search unavailable", `Rejected` to
"Search failed: {status}", and `Malformed` to a turn-aborting shape error).

`Phase` (`Connect`, `Headers`, `Body`) is where the crate was when it
failed: `Connect` when the send failed and reqwest's `is_connect` says it
was the connect, `Headers` for any other failure of the send (writing the
request, waiting for or parsing the head, and the whole-exchange timeout
ending any of them, a slow connect included), `Body` for any failure of a
body read (reqwest's `is_decode` would label a stall a decoding failure).
`io` is the kind of the innermost `std::io::Error` in reqwest's source chain,
when there is one. They render as fixed phrases, for example `Perplexity is
unavailable: the exchange failed while connecting; I/O error: connection
refused`.

`UnavailableReason`, `Phase`, `ResponseStatus` and `MalformedReason` are
`Copy`, `#[non_exhaustive]` enums whose `Display` is a fixed phrase, so a
service can map each to its own message without matching on text.
`Rejected`, `Incomplete` and `UnavailableReason::Transport` are struct
variants marked `#[non_exhaustive]`: match them with `..`.

`BuildError` (from `build()`): `InvalidBaseUrl(&'static str)`, naming why and
never the URL, `EmptyApiKey`, `InvalidApiKey`, and the four zero bounds.

## Nothing it handles reaches a log

- Every `Display` and `Debug` of an error is fixed phrases, a status code, a
  count, a documented response status or a `std::io::ErrorKind`, and
  `source()` is always `None`.
- A transport failure keeps no `reqwest::Error`. Its source chain can carry
  what the peer sent: h2 renders an HTTP/2 GOAWAY's debug data in both
  `Display` and `Debug`, and `without_url()` strips only the URL. So it is
  reduced to a phase, a timeout flag and an I/O error kind, and dropped.
- Never a `serde_json` message (it can quote the body), the input, the key,
  a body, the response's `error` object or an undocumented status string:
  error bodies are never read, and a `2xx` body's parse errors are dropped
  unrendered.
- The `Debug` of the client, its builder, a `SearchAnswer`, a
  `SearchResult`, a `Source` and a `Usage` show neither the key nor the
  query-derived text: the builder shows no base URL (it is not validated
  yet), the client the validated endpoint, an answer its text's length and
  its result count, a result or row each string's length (`Some(<12
  chars>)`), `Usage` its counts and cost and the currency's length. The
  values themselves are returned as given; a caller that logs them formats
  them explicitly.

`tests/redaction.rs` plants canaries in the key, the input, the response
bodies (an echo in a `4xx`/`5xx`, in a `failed` or `incomplete` response's
`error` and text, as the `status` itself), the base URL's path and
credentials, a successful answer's text, result fields and currency, and the
places a peer can put them inside a transport failure (a malformed status
line, a header no parser accepts, an HTTP/2 GOAWAY's debug data), and asserts
none of them appears in any rendering of the error or the result (`Display`,
`{:?}`, `{:#?}`, and each `source()`). Controls prove the canaries were
really sent, that a reqwest error really renders its URL, and that the
GOAWAY's debug data really is in reqwest's own error, so their absence from
ours means something.

## Tests

No test reaches the real Perplexity: wiremock and raw TCP servers on
`127.0.0.1` only. The one real response, `tests/fixtures/agent_response.json`,
was recorded by lumen plan 002's single billed contract call (T5-0, outside
every Cargo lane) and leak-scanned with the actual key as a sentinel.

- `tests/search.rs`: the exact request, the effort and output bound, the
  input sent as given, a path-prefix base, the trimmed key, the input bound
  (in characters), every status class (`600` and `999` included) classified
  before any body is read, redirects never followed, any `2xx` read, a
  timeout and a refused connection; the recorded response read faithfully
  (text, ten results ids 1..10, the `[5]` citation by id, two undated
  results, usage, the six display rows); and the parsing matrix: ids
  non-contiguous and repeated across several `search_results` items,
  duplicate URLs under different ids, malformed entries against a malformed
  list, `failed`/`incomplete`/`cancelled`/undocumented statuses, empty text,
  invalid UTF-8 inside an ignored field, a malformed `usage`, a user-role
  echo (alone, and beside the assistant's answer), an `incomplete` message
  in a `completed` response, a duplicate `status` in either order, and
  `1e400`/`-1e400`/a 30-digit integer in a usage count, an `id` and a
  `title`; and `SearchAnswer::from_json` agreeing with `search()` on the
  recorded response and on failing bodies.
- `tests/bounds.rs`: raw TCP servers for what wiremock cannot do (send the
  headers and stall, cut a body off, stream without end): a chunked body of
  exactly the bound read and one byte more cut by the chunk loop; a declared
  body one byte over refused; a declared-oversized `Content-Length` that then
  stalls, refused at once (the control, exactly the bound, times out in the
  body); an endless chunked stream cut at the bound before the timeout; a
  truncated body; a stall before the headers and one after them, each a
  timeout in its phase.
- `tests/redaction.rs`: the canaries above.
- Unit tests: the URL and builder rules, the key header, the defaults, the
  error renderings, the field-by-field reader (key order, repeated keys, deep
  skipped values, ill-typed fields, unrepresentable numbers at every lenient
  position, message roles and statuses, duplicate statuses), `sources`, and
  every `Debug`.

Each raw TCP server's handlers run on tasks of their own, where a failed
assertion would only close a socket, so every test that starts one awaits
them at its end (`RawServer::finish`), which re-raises a handler's panic.
