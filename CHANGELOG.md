# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is lockstep across all eight crates in this workspace (one
`[workspace.package].version`, bumped together regardless of which crate(s)
changed) rather than independent per-crate versioning —
see the root README's "Consuming these crates" section for what that means
for a consumer's pin.

## [Unreleased]

### Added

- `stridelabs-redis`: `RedisHandle::eval::<T>(script, keys, args, replay)`
  and `RedisHandle::ping()` (lumen plan 001 S1, for a voice relay's Lua
  lease and budget scripts and a readiness probe).
  - `eval` sends a raw `EVAL` (no `EVALSHA`, no redis-rs `script` feature,
    no `sha1_smol`) under a `Replay` the caller chooses: `Never` for any
    script that writes, including a lease acquire or takeover;
    `OnceOnFreshConnection` only for reads and writes whose re-execution is
    harmless (a script whose reply was lost after it ran IS run again).
    `T: EvalReply` is sealed and covers `i64` and `Vec<i64>`; decoding is
    strict (`{1,false,3}` is refused) and an error names the reply's shape,
    never its contents. Arguments are `EvalArg`s (text or integers via
    `.into()`) whose `Debug` names the kind and a text's length, never the
    value.
  - `ping` sends `PING` and is `Ok(())` only on the `PONG` status; after an
    I/O failure on a cached connection it is retried once on a fresh one.

- `stridelabs-auth`: verifying another issuer's tokens under claim rules the
  consumer chooses (lumen plan 001 S1: WorkOS access tokens, which carry no
  `aud` and whose `iss` names the client).
  - `ClaimChecks::new(issuer, Audience)`: `iss` must match exactly and is
    required; `exp` is required; `aud` is checked per the `Audience`. The
    leeway on `exp` and `nbf` is `with_leeway(Duration)` (default
    `DEFAULT_LEEWAY`, 60 s; whole seconds, capped at a day because
    jsonwebtoken's `now ± leeway` is unchecked `u64` arithmetic). A present
    `nbf` is checked by default (`with_nbf_validation(false)` turns it off).
    Accessors `issuer`, `audience`, `leeway`, `validates_nbf`. Its `Debug`
    renders an issuer carrying userinfo, a query or a fragment as
    `scheme://host[:port]/path`.
  - `Audience` (`#[non_exhaustive]`): `Required(String)` or `NotValidated`.
    There is no `Default` and no conversion that yields `NotValidated`; it
    skips the `aud` check and is safe only when the issuer binds the
    audience some other way.
  - `Verifier::for_issuer(checks, jwks_url, jwks_ttl: Option<Duration>,
    http)` builds its own `JwksCache` (`None` means `JWKS_TTL`), so it
    inherits the cache contract: a key set is never served past its TTL (a
    test pins it through `for_issuer`). `verify_bearer_claims` applies its
    rules; `Verifier::claim_checks()` returns them. `config()` is
    informational: a synthesized `SlauthConfig` whose audience under
    `NotValidated` is a NUL-prefixed sentinel no issuer mints, so a verifier
    wrongly rebuilt from it with `Verifier::new` refuses every real token.
  - `Verifier::claims_with_jwks_checked::<C>(token, &jwks, kid, &checks)`,
    the network-free form.
  - `test_support::TestClaims::without_audience()` and
    `TestClaims::not_before_in(secs)`.

- `stridelabs-observability`: per-target level caps that hold even when
  `RUST_LOG` is set (lumen plan 001 S1, for a WebSocket relay whose frame
  logs carry an API key). `TargetCaps` (`new`, `cap(target, Level |
  LevelFilter)`) are ceilings checked on top of the level filter, so neither
  `RUST_LOG=trace` nor `RUST_LOG=<target>=trace` can lift a capped target. A
  cap covers its target and module paths beneath it (not
  `tungstenite_extra`); a trailing `::` is ignored and an empty target is not
  a wildcard; every covering cap applies (the strictest wins). Spans and
  `log`-crate records (through the `tracing-log` bridge) are capped by their
  real target, and the filter's max-level hint is unchanged.
  - `init_logging_with(format, default_filter, &TargetCaps)`;
    `init_logging` is it with no caps, output byte-for-byte unchanged.
  - `try_init_logging_with(..) -> Result<(), LoggingInitError>` installs the
    same stack and returns `Ok` only when this call installed both the
    subscriber and the `log` bridge (`LoggingInitError`, `#[non_exhaustive]`:
    `AlreadyInitialized`, `SubscriberAlreadySet`, `LogBridgeNotInstalled`).
    Use it when the caps guard a secret: an earlier subscriber or `log`
    logger would otherwise leave them silently not in force.
- `stridelabs-http`: feature `redact-url` (pulls in `url` only: no client, no
  TLS) with `redact_url(raw) -> String`: `scheme://host[:port]/path`,
  userinfo, query and fragment dropped, `<unparseable URL>` for anything
  without a host. The same rule as stridelabs-auth's and stridelabs-gcp's
  private copies and tapper-rs's `http_tls::redact_url`.
- `stridelabs-http` (`ssrf`): the options a feed fetch needs, every one
  opt-in. A default policy's request is v0.8.0's byte for byte (pinned by a
  snapshot recorded on the v0.8.0 tree), and `fetch_public` returns the
  `Fetched` values it returned.
  - `fetch_public_response(url, &policy)` → `FetchResponse`
    (`#[non_exhaustive]`; `body`, `content_type`, `status`, `final_url:
    url::Url`, `headers: HeaderMap`, `redirects`), the answering hop's
    status, URL and parsed headers. `url::Url` is now public API of `ssrf`,
    as it was of `proxy`. Its `Debug` is hand-written: the body length, the
    status, the URL with its query and fragment redacted, header names
    only, and the redirect count. `final_url` and `headers` are not
    client-safe. `impl From<FetchResponse> for Fetched`; `fetch_public` is
    that conversion, and `Fetched` is unchanged.
  - `FetchPolicy::with_user_agent(HeaderValue)` and
    `FetchPolicy::with_header(HeaderName, HeaderValue) -> Result<_,
    ReservedHeader>`. Policy headers are trusted configuration, never
    secrets: they go on every hop, cross-host redirects included. The
    reserved names (hop-by-hop and framing, routing and every
    `x-forwarded-*`, method and route overrides, cloud metadata headers,
    credentials, the fetch's own `accept`/`accept-encoding`/`user-agent`,
    and the not-yet-designed `if-match`/`if-unmodified-since`/`if-range`/
    `range`) are refused, case-insensitively; the list is part of the
    contract. `If-None-Match` and `If-Modified-Since` replace, every other
    name appends.
  - Conditional requests: those two validators go to the first hop only and
    are dropped on any redirect (RFC 9110 section 15.4). A `304` answering
    them there is terminal: `FetchResponse { status: 304, body: empty,
    redirects: 0, final_url: the original }`, never a redirect, whatever
    the statuses policy says. `fetch_public` reports it as `HttpStatus`. A
    `304` without a validator, or past the first hop, is a 3xx as before.
  - `FetchPolicy::with_accepted_statuses(AcceptedStatuses)`
    (`#[non_exhaustive]`): `OkOnly` (default, `== 200`) or `AnySuccess`
    (any 2xx).
  - New feature `ssrf-decompress` (`["ssrf", "dep:flate2"]`):
    `FetchPolicy::with_decompression(Decompression)` (`#[non_exhaustive]`;
    `Off` by default, `GzipDeflate`). Under `GzipDeflate` the request sends
    `Accept-Encoding: gzip, deflate`; a response coded with exactly one of
    `gzip`, `x-gzip` or `deflate` (identity tokens aside, case-insensitive)
    is decoded, and anything else coded is refused as before. The wire
    bytes are capped at `max_bytes + max_bytes / 8 + 4096` (declared and
    streamed) and the decoded bytes at `max_bytes`; `TooLarge` wins the
    moment the decoded allowance would be passed (counting output an
    inflate call writes before it reports corruption, decided before it is
    stored) and never falls back to raw deflate. Neither body buffer's
    capacity passes its cap (the decoded body's, `max_bytes`); both are
    reserved fallibly, and a refused reservation is `FetchFailed`. The
    decode runs in bounded steps that yield between them, with the fetch's
    deadline checked before each step and on every answer: past it, any
    outcome (a body, an empty one, `TooLarge`, a corruption) is
    `TimedOut`. gzip is framed as CPython's `gzip`
    module frames it (reserved flag bits and the header CRC unchecked,
    FNAME and FCOMMENT of any length), every member, skipping zero padding;
    deflate is zlib, then raw, each required to end. Corrupt or truncated
    input is `FetchFailed`, never a partial body. Parity with feedparser
    6.0.12 is a tested subset (a 66-case golden fixture and its generator),
    with three recorded residues: `GZIP` and a `gzip`-then-`identity`
    header pair are decoded here, and stacked or unknown codings are
    refused here where feedparser passes them through.
  - No `with_*` method can let a fetch reach a non-public address, and
    `user:pass@` is still `EmbeddedCredentials` everywhere.
  - CI builds and lints `stridelabs-http:ssrf-decompress` on its own.
- `stridelabs-gcp`: `TokenProvider::invalidate(&self, rejected:
  &AccessToken) -> bool`, which evicts a token a Google API answered `401`
  to so that the next `token()` refreshes. It is synchronous, needs no
  runtime, and never starts, cancels or duplicates a refresh.
  - Matched by bearer string: any `AccessToken` with the cached bearer
    evicts it, and anything else returns `false` and changes nothing.
  - Callers whose rejections of one bearer overlap one refresh cost one
    eviction and that refresh, when it mints a different, cacheable bearer.
    A later caller holding the old bearer finds the new one cached and
    refreshes nothing. After a failed refresh the next call starts another,
    and the evicted token is never served again.
  - No re-install: a refresh already in flight when its bearer was evicted,
    that returns that same bearer (the metadata server re-serving its
    cached token), hands it to its waiters without caching it.
  - Logged at `debug` with the source and kind, never the bearer.
  - A new test pins that `TokenOptions::token_timeout` bounds the
    token-endpoint exchange; there is no API change there.
- `stridelabs-gcp`: an opt-in `401` refresh and replay on `GcsClient` and
  `VertexClient`, google-auth's `AuthorizedSession` loop. Each client gains
  `with_unauthorized_refresh(bool)` (default `false`),
  `with_max_refresh_attempts(u32)` (default 2, effective only when
  enabled), `unauthorized_refresh()` and `max_refresh_attempts()`.
  - Enabled, a completed `401` has its body read and dropped (at most
    16 KiB and 2 s, then the connection is dropped). Its bearer is
    invalidated, a token is taken again and the same request is sent again,
    up to the count per attempt: once per operation, or afresh in each
    attempt under `GcsClient::with_retry`. A persistent `401` costs N + 1
    requests and N refreshes (3 and 2 by default), and `0` replays nothing.
  - Never on a `403`, a `5xx` or a transport failure. Every replay runs
    inside the operation's timeout. A multipart upload's body and boundary
    are built once, and Vertex's JSON is serialized once (after the first
    token, as in v0.8.0, so a call that gets no token never encodes it), so
    every send of one call carries the same bytes.
  - On the metadata server a refresh can return the same bearer, so a
    replay can add requests without different credentials: one reason it is
    off by default.
  - Off, every request is v0.8.0's byte for byte, pinned by a raw-socket
    test whose expectations were recorded on the v0.8.0 tree. A `401` is
    still one request and `Status`.
  - Both clients' `Debug` prints the toggle and the count.
- `stridelabs-gcp`: `ObjectNamePolicy` (`#[non_exhaustive]`, `Default` =
  `Strict`), `GcsClient::with_object_name_policy` / `object_name_policy()`
  and `public_url_with(bucket, object, policy)`. `Strict` is v0.8.0's name
  check everywhere, and the free `public_url` stays `Strict`. `Literal` is a
  transport policy, not validation: uploads send every name (a query value
  or a JSON string), a download or a delete refuses only `""`, `.` and `..`
  (no URL path segment can carry them; nothing is sent and no token
  fetched), `public_url_with(.., Literal)` refuses no object name, and
  whatever else GCS refuses comes back as its `400`. A `Literal` public URL
  is exact addressing, not a safe URL: a `..` segment resolves elsewhere in
  a normalizing client, as Python's string does. Pinned by slaudio's 31
  golden names from google-cloud-storage 3.6.0
  (`crates/gcp/tests/fixtures/gcs_object_names.json`, with its
  provenance): `public_url_with(.., Literal)` is Python's for all 31, deletes
  go to Python's paths but for the three refused, both uploads send all 31,
  and `Strict` refuses the same 14 as v0.8.0.
- `stridelabs-gcp`: an opt-in retry, `GcsClient::with_retry(RetryPolicy)` /
  `retry_policy()`. `RetryPolicy` (`#[non_exhaustive]`, `Copy`,
  `PartialEq`; public `initial_delay`, `multiplier`, `max_delay`,
  `deadline`; `const` `with_*` setters) has `disabled()` (the default: one
  attempt, as in v0.8.0) and `google_default()` (1 s, ×2, 60 s, 120 s,
  google-cloud-storage's `DEFAULT_RETRY`).
  - google-api-core's schedule: a full-jitter draw under a ceiling that
    grows by the multiplier to `max_delay`, at least 1 ms a wait, until a
    success, a failure that is not transient, or a wait that would pass the
    deadline; then that attempt's error is returned unchanged (Python raises
    `RetryError` instead: a recorded difference). No attempt cap, as in
    Python; invalid values are normalized at use, never refused, and every
    nonzero deadline ends the loop.
  - Transient, decided where each failure happens (never by reading an
    error's text back): `408`, `429`, `500`, `502`, `503`, `504`; the
    client's `Timeout`, unless the attempt had already heard a status that
    is not; a transport failure before the response that timed out, failed
    to connect or broke in flight; any failure reading a body after the
    headers (an interrupted transfer); and those classes on the way to the
    token. Never: a `404`, any other status (`401`, `403`, `412` included),
    `TooLarge`, the `Invalid*` refusals, other token errors.
  - A status line, once in, is final. An error body that stalls until the
    attempt's timeout ends the attempt as `Timeout` (v0.8.0's error there;
    the default client returns exactly that), classed by the status: a
    `412` or `401` whose body never arrives is not retried, a `503`'s is.
    So is a token refresh's: an attempt cut off waiting on a refresh whose
    token endpoint already answered `400` is not retried, and a `401` being
    drained by the refresh is the attempt's answer until its replay goes
    out.
  - Token failures recover differently from Python's, not only in count:
    google-auth retries inside its refresh on `408`, `429`, `500`, `503`,
    `504`, and on any status (a `400` included) whose OAuth `error` is
    `internal_failure`, `server_error` or `temporarily_unavailable`; this
    client retries a token failure by status alone, so a token `400
    {"error":"temporarily_unavailable"}` then a token recovers in Python
    and fails here.
  - The error strings are unchanged: an interrupted body is still
    `Request { reason: "decode error" }`.
  - Each attempt takes a token, runs the opt-in `401` refresh with a budget
    of its own (a `401` replayed into a `503` is retried), and is bounded by
    the client's timeout, which is per attempt under a policy: the loop ends
    within the deadline plus one attempt.
  - Documented: library attempts are not wire requests (do not add a
    reqwest retry for the GCS host); a retried create-only upload whose
    first response was lost answers `412`, and a retried delete may return
    `Ok(false)`.
  - One `debug` line per retry: operation, attempt, `wait_ms`, the status
    or the transport category. Never a name, a message or a URL.
- `stridelabs-gcp`: `GcsClient::bucket_reachable(bucket)`, a startup probe
  (`GET {base}/storage/v1/b/{bucket}/o?maxResults=1`; any 2xx is `Ok(())`,
  anything else `Status { operation: "list" }`) on the same timeout, retry
  and refresh, point-in-time evidence that needs `storage.objects.list` (a
  `403` says nothing about whether the bucket exists); and
  `validate_bucket_name`, the bucket rule every operation applies, public.
  `GcsClient`'s `Debug` prints the name policy and the retry policy. All the
  new items are re-exported from the crate root.
- `stridelabs-testing` (`postgres`): `require_postgres_at(url)`, public and
  re-exported at the crate root (slaudio plan 025 L1). It connects to
  exactly `url` and reads no environment, with `require_postgres`'s 2 s
  timeout and redacted panic. `require_postgres` keeps its documented
  precedence, `DATABASE_URL` over its argument, so it is the call for the
  database a suite starts from; a URL a test built itself goes to `_at`.
  parcel's `schema_pool` needs it: the per-test `search_path` URL it passes
  to `require_postgres` is replaced by a set `DATABASE_URL` (as in CI), so
  its tests share one schema. Its fix is one line in
  `crates/parcel-server/tests/common/mod.rs`, with its bump to this release.
- `stridelabs-auth`: `jwks::MAX_JWKS_BYTES` (1 MiB), the JWKS body cap below.

### Changed

- `stridelabs-redis`: `Replay` (`Never`, `OnceOnFreshConnection`) is public,
  re-exported at the crate root, `#[non_exhaustive]`, with no `Default`; the
  built-in commands keep their policies.
- `stridelabs-redis` (error **text** only; no signature change): every
  `RedisError` payload is now a fixed summary the crate composes. None
  carries redis-rs's or the server's text any more, because both can echo
  passwords, keys, tokens and user ids (e.g. `unknown command 'EVAL', with
  args beginning with: …`, or a refused handshake echoing `HELLO 3 AUTH
  <user> <password>`).
  - `Command`: an error reply's code when Redis defines it (`ERR`,
    `WRONGTYPE`, `NOSCRIPT`, `BUSY`, `READONLY`, `OOM`, …) plus a fixed
    description of its class that says whether the command ran; any other
    code shows as undefined; a reply that did not convert shows as
    "incompatible type".
  - `Connect` and `Io`: the failure's class (timed out, connection refused,
    closed or reset, an I/O error's kind, not well-formed RESP,
    authentication failed, or an error reply's code). A refused handshake
    is still `Connect`.
  - `InvalidUrl`: only the name of the URL check that failed (redis-rs's
    "Invalid protocol version" appended the URL's `protocol` value).
  - The crate's own log lines use the same summaries. Reproduce with
    `redis-cli` to see the server's words; code that matched on payload
    text should match on the variant instead. A TLS or DNS failure now
    reads as an I/O error kind rather than rustls's or the resolver's
    message.

- `stridelabs-observability`: `thiserror` is a non-optional dependency (it
  was enabled only by `prometheus`) and `tracing-log` a normal one (it was a
  dev-dependency); neither adds a package to the lock.

- `stridelabs-auth`: `claims_with_jwks`, `verify_with_jwks` and
  `Verifier::new`'s verification run through `claims_with_jwks_checked` with
  slauth's rules (`aud` required, 60 s leeway, `nbf` unchecked); no
  behaviour change (the existing tests and `verifier_new_keeps_slauths_rules`
  pin it). `SlauthConfig`'s `Debug` now renders an issuer carrying userinfo,
  a query or a fragment as `scheme://host[:port]/path` (every other issuer
  prints exactly as before).

- **BREAKING (behaviour, security, for `Verifier`, `JwksCache` and
  `McpVerifier` users): a JWKS lookup never returns a set past its TTL.**
  Through v0.8.0 the TTL itself was not the serving bound. After a failed or
  cancelled refetch at expiry, the expired set answered again for the rest of
  a `MIN_REFETCH_INTERVAL` (30 s), up to `JWKS_TTL + MIN_REFETCH_INTERVAL`
  after its last successful fetch. A key the issuer had retired kept
  verifying while the issuer was failing, and a `with_ttl` below 30 s still
  served for `ttl + 30 s`. Now:
  - **Refresh ahead.** In the last 10 % of the TTL (at least 60 s, at most
    10 min; 6 min at the defaults), a lookup the set answers starts a
    background refresh. A failed refresh is retried from its completion
    (1 s, doubling, at most `MIN_REFETCH_INTERVAL`) while the set keeps
    answering until its TTL. Refresh-ahead needs traffic in that window.
    Without it, or with a TTL under three intervals, the first lookup at or
    after the TTL fetches.
  - **No stale fallback.** From the TTL on, a lookup waits for a fetch in
    flight or is refused with `AuthError::Jwks` (a 500 under `http`, a 503
    `Unavailable` in stridelabs-mcp), as stridelabs-python's `JWKSCache`
    refuses (`jwks.py:35-61`).
  - **Prompt recovery.** After a failure, the next fetch of a needed set is
    allowed 1 s after that failure completes, doubling to 8 s. Lookups in
    between are refused at once. A lookup that joins such a retry waits at
    most 2 s. Once the issuer returns, recovery takes at most what is left of
    an attempt still failing at that moment (up to `FETCH_TIMEOUT`), then the
    backoff (up to 8 s), then one successful fetch (up to `FETCH_TIMEOUT`):
    about 28 s at the defaults, and only once a lookup arrives. Python
    refetches on every request instead.
  - **Unknown kids stay rate-limited.** Against a set inside its TTL, an
    unknown `kid` refetches at most once per `MIN_REFETCH_INTERVAL`, as
    before.
  - **Fetches run on their own task, single-flight.** Cancelling the request
    that started one does not cancel it, and fresh lookups never wait behind
    it. Every lookup that joins a fetch has its own bound (`FETCH_TIMEOUT`
    plus 1 s on a first attempt, 2 s on a retry), a timer on the lookup's
    own runtime, so it holds whatever happens to the runtime hosting the
    fetch.
  - **Short TTLs.** The refetch floor `F` is `min(interval, max(ttl, 1 s))`.
    A TTL from 1 s up to the interval refetches at expiry. A TTL under 1 s is
    refused from its expiry until `F` after the last completed attempt. A
    zero TTL caches nothing, serves each fetch only to the lookups that
    waited on it, and starts fetches at most once per `F`: once a second
    while the interval is at least 1 s, once per interval when it is
    shorter.

  These bounds are per `JwksCache` instance, on its monotonic clock. Replicas
  that expire together retry together.

  **Migration:** no code change.
  - During an issuer outage that outlasts the refresh window, or that starts
    in an idle window, JWT requests are refused from the TTL on (previously
    up to 30 s later). They recover as above.
  - A lookup polled outside a tokio runtime gets `AuthError::Jwks` when it
    would start or join a fetch.
  - Lookups require a Tokio runtime with the time driver enabled, as reqwest
    does: a lookup that has to wait on a fetch, polled on a runtime built
    without `enable_time`, panics in tokio's timer.
  - The runtime that starts a fetch must keep being driven until it ends. A
    fetch frozen in an undriven runtime (a current-thread runtime whose
    `block_on` returned) holds the slot: lookups elsewhere give up at their
    bound until that runtime runs the fetch or is dropped.
  - `JwksCache`'s `Debug` output changed.
  - No public item was added, removed or re-typed.
- `stridelabs-auth` now names tokio's `rt` and `time` features (alongside
  `sync`) and depends on `futures-util` with `std` only. Both were already in every
  consumer's graph (reqwest, hyper); `futures-executor` stays out of an
  auth-only consumer's.

- `stridelabs-auth` (behaviour, for `Verifier`, `JwksCache` and
  `McpVerifier` users; slaudio plan 025 L1, as are the four below): **the
  JWKS body is capped at `jwks::MAX_JWKS_BYTES`, 1 MiB.** Through v0.8.0 it
  was read with `response.json()`, which buffers whatever the endpoint
  sends. It is now read chunk by chunk inside `FETCH_TIMEOUT`, and the read
  stops at the chunk that would pass the cap, so the body it keeps is at
  most the cap plus one chunk (transport and decoder buffers aside). A
  larger body is `AuthError::Jwks("response body is over 1048576 bytes")`:
  a failed fetch, handled as any other (nothing is cached from it, and the
  retry spacing applies). A body that fails mid-read is `reading the body
  failed: …` (it was `response was not a valid JWKS: error decoding
  response body`, which a body that does not parse still reads).
  - **A valid key set over 1 MiB now fails to load**, where v0.8.0 served
    it. Real issuers serve a few KiB (slauth's set is two or three RSA keys
    of under 2 KiB each).
  - The cap counts the bytes reqwest hands over: the body as sent, or, when
    the consumer's client decodes (a reqwest `gzip`, `brotli`, `zstd` or
    `deflate` feature anywhere in its graph), the decoded bytes, not the
    bytes on the wire.
- `stridelabs-testing` (`postgres`, behaviour): **an empty `DATABASE_URL`
  counts as unset**, as an empty `REDIS_URL` already did, so
  `require_postgres` connects to its argument instead of failing on `""`.
  parcel and spendwise-rs already filter an empty value in their own
  `database_url()`, and now agree with the pool they get. slauth's
  `database_url()` copies the old rule on purpose (its comment says so); it
  still fails loudly, since it passes the empty value as the argument, but
  should move to the new rule with its bump.
- `stridelabs-testing` (`redis`, panic text only): `require_redis`'s panic
  names what failed by redis-rs's error kind and an I/O failure's class
  (`Io (connection refused)`, `Server(ResponseError)`), never redis-rs's
  message. That message can quote the handshake's credentials: a Redis older
  than 6 answers `HELLO 3 AUTH <user> <password>` with `unknown command
  'HELLO', with args beginning with: …`, which redis-rs passes on (it
  recognises only the newer, backquoted form). The URL it tried is still
  named, redacted. A test pins it against a fake server sending that reply.
- `stridelabs-http` (`proxy`): **`UpstreamClient::build` switches off
  reqwest's gzip, brotli, zstd and deflate decoding** (`no_gzip()`,
  `no_brotli()`, `no_zstd()`, `no_deflate()`), as the `ssrf` client already
  did. Latent until now: nothing in this workspace's shipped graph enables
  those reqwest features, but in a consumer whose graph did (any crate
  turning on reqwest's `gzip`, say), feature unification made the proxy
  decode coded upstream bodies and send `Accept-Encoding` of its own. limen
  is the consumer.
  - The test build now has reqwest's gzip decoder, through a dev-dependency
    (see Dependencies), which is what a consumer's unification would give
    it; gzip runs the same suppression path as the other three. In that
    build one test shows a plain `reqwest::Client` asking for gzip and
    decoding a gzip fixture to its text; another shows `UpstreamClient`
    relaying the same fixture byte for byte, under its own
    `Content-Encoding`, with no `Accept-Encoding` sent. Without the `no_*`
    calls the second fails in a plain `cargo test --workspace
    --all-features`, and without the dev-dependency the first does.
- `stridelabs-http` (`ssrf`, `Debug` text only): `Fetched`'s `Debug` is
  hand-written and prints `Fetched { body: <N bytes>, .. }`, the body's
  length and neither its bytes nor the content type, as `FetchResponse`'s
  does. It derived `Debug`, which printed the body. stridelabs-mcp's
  `ImageFetcher` (imgmcp) is its user, and logs none.

### Security

- `Cargo.lock`: rustls-webpki 0.103.15 → 0.103.16 (RUSTSEC-2026-0382) and
  webpki-root-certs 1.0.9 → 1.0.10 (RUSTSEC-2026-0383), so `cargo audit` and
  `cargo deny check advisories` are clean again. All three advisories of this
  family (RUSTSEC-2026-0381, -0382, -0383) are the same defect: certificate
  paths through the distrusted emSign intermediates, whose private keys are
  now well known, were accepted. Lock only, no manifest change, no source
  change. rustls-webpki is compiled wherever rustls is (`stridelabs-http`'s
  `proxy`, `stridelabs-redis`'s `rediss://`); webpki-root-certs is
  rustls-platform-verifier's wasm32-only dependency, which a Linux or macOS
  build does not compile; webpki-roots (RUSTSEC-2026-0381) is not in this
  workspace's lock at all. A consumer's own `Cargo.lock` decides what it builds, so it bumps
  rustls-webpki (and webpki-roots / webpki-root-certs, where it has them)
  there.

### Dependencies

- `stridelabs-http` dev-dependency only: reqwest with its `gzip` feature,
  for the proxy decoder test above. Cargo.lock gains async-compression,
  compression-codecs and compression-core (pure Rust; the gzip itself is
  the flate2 already locked), reached only through that dev edge: `cargo
  tree -e normal`, for the workspace and for `stridelabs-http`, is
  unchanged, so no consumer compiles them. `cargo test --workspace`
  unifies the feature into every member's test build; stridelabs-gcp's
  v0.8.0 wire pins (`tests/wire_defaults.rs`) now inject a client with the
  decoders switched off, because the `Accept-Encoding: gzip` a decoding
  client adds is the client's, not stridelabs-gcp's, and the pins were
  recorded without one.
- `flate2` 1.1.10 (`default-features = false`, `rust_backend` +
  `runtime_detection`), new, optional, behind `stridelabs-http`'s
  `ssrf-decompress` only: with miniz_oxide, adler2, crc32fast and
  simd-adler32, pure Rust. `zlib-rs` gains a lock-only Cargo.lock entry
  through flate2's weak `zlib-rs?/std`; nothing compiles it.

## [0.8.0] - 2026-10-17

Two additive pieces for imgmcp's image privacy and cost work: a daily
window for the MCP rate limiter, and GCS uploads that set object metadata
at creation. Purely additive: every existing constructor, method and text
keeps its signature and meaning (the per-minute refusal text is unchanged
byte for byte), `cargo-semver-checks` in patch mode against v0.7.0 is clean
for every crate, and no dependency major changed. First consumer: imgmcp.

### Added

- `stridelabs-mcp`: windows as part of a limit. `Window` (`#[non_exhaustive]`:
  `Minute` = `unix_seconds / 60`, Python's; `Day` = `unix_seconds / 86_400`,
  the UTC day, resetting at 00:00 UTC; `secs()`, `as_str()`) and
  `RateLimit { class, window, limit }` (`RateLimit::per_minute`,
  `RateLimit::per_day`). New constructors `MemoryLimiter::from_limits` and
  `RedisRateLimiter::from_limits(handle, limits, prefix)`; the `new`
  constructors keep their per-minute `(RateClass, u32)` signatures. A
  repeated `(class, window)` is the last entry; a limit of 0 turns that
  window off.
  - One check reads the clock once and counts the call in the class's
    windows shortest first, stopping at the first refusal: a call counts in
    every window up to and including the one that refused it, so a burst
    refused per minute does not spend the day, and a call the day refuses
    still counts in the minute.
  - `MemoryLimiter`: one critical section covers all of a class's windows;
    each window length keeps its own forward-only index and drops its counts
    when it rolls over.
  - `RedisRateLimiter`: the minute key is unchanged
    (`{prefix}:{subject}:{class}:{unix/60}`); the day key is
    `{prefix}:{subject}:{class}:day:{unix/86400}`, each hit by the existing
    single-key `fixed_window_hit` with the window's length as TTL (no
    multi-key script). Fail-open is per check: the first Redis error allows
    the call, logs one warning (now with a `window` field), and stops — a
    counted minute is not rolled back, and a failed minute skips the day.
  - `RateLimited` (`#[non_exhaustive]`) gains `pub window: Window`;
    `RateLimited::new` still means a minute, and `RateLimited::in_window`
    names the window. A day refusal reads "Rate limit exceeded for {class}
    operations ({limit} per day). The limit resets at 00:00 UTC, in {H} h
    {M} min.", the time left rounded up to the minute. The minute text is
    Python's, unchanged.
  - The day window has no Python ancestor; `PARITY.md` lists its tests.
- `stridelabs-gcp`: `GcsClient::upload_with(bucket, object, bytes,
  content_type, &UploadOptions)`. `UploadOptions` (`#[non_exhaustive]`,
  `Default`, setters `with_custom_time`, `with_if_generation_match`,
  `with_cache_control`) carries a `customTime`, a `cacheControl` and an
  `ifGenerationMatch` precondition. Default options send exactly
  `upload`'s media upload; any option set makes it one multipart upload
  (`uploadType=multipart[&ifGenerationMatch=N]`): CRLF-framed, the
  serde_json metadata part (`name`, `contentType`, then `customTime` as RFC
  3339 UTC at whole seconds and `cacheControl`, when set) before the bytes,
  which go in unchanged, with a random boundary drawn again until it appears
  in neither part. On that multipart path the content type, the cache
  control (header values: no CR, LF or other control characters), the custom
  time (1970 to 9999) and the generation (not negative) are checked before a
  token is fetched,
  refused as the new `StorageError::InvalidArgument { reason }` (appended
  last, so no other variant's discriminant moves), which quotes neither the
  value nor the object. A failed precondition is GCS's
  412, a `StorageError::Status` like any other: no retry, no fallback.
  Timeout, auth, emulator base URL and error sanitizing are `upload`'s;
  `upload` itself is unchanged.

### Dependencies

- `stridelabs-gcp` now depends on `rand` 0.10 (the boundary's 128 random
  bits; already in every StrideLabs service's graph through
  `stridelabs-auth` and `stridelabs-observability`) and `memchr` 2 (a new
  workspace entry; already in every graph through futures-util), and on
  `time` 0.3 as a dev-dependency only (a reference for the hand-written RFC
  3339 formatter). `Cargo.lock` changes only in those edges and the eight
  versions.

## [0.7.0] - 2026-10-17

Two new crates, `stridelabs-redis` and `stridelabs-gcp`, and the additive
features the imgmcp port needs on `stridelabs-auth`, `stridelabs-http`,
`stridelabs-testing` and `stridelabs-mcp`: slauth PAT validation, an
SSRF-guarded public fetch, rate limiting in the MCP tool boundary, and the
Redis and Google Cloud pieces under them. No breaking change:
`cargo-semver-checks` (patch mode against v0.6.0, CI's pinned 0.51.0 and
0.50.0) is clean for every crate, and the dependency majors are v0.6.0's
plus `redis` 1 for the new crate. First consumer: imgmcp.

### Added

- `stridelabs-auth`: `PatValidator` / `is_slauth_pat`, the Rust twin of
  Python's `PATValidator`, reading `SlauthConfig.pat_validate_url`. A
  malformed token (prefix plus exactly 43 characters) is never sent; a
  rejection is `PatValidationError::Rejected` (a 401) and an outage
  `::Unavailable` (a 503), mapped as the Python client does. It takes the
  consumer's `reqwest::Client`, which **must not follow redirects**
  (`reqwest::redirect::Policy::none()`): then every 3xx is a service error,
  as with Python's httpx. With a following client, an answer whose final URL
  is not the validate URL is still refused, but that check is defence in
  depth only: a redirect back to the validate URL itself (`POST` → `303` →
  `GET` of the same URL) cannot be told from slauth answering, and a test
  pins that limitation. Hardened beyond Python: the answer is read with a
  16 KiB cap, only slauth's own reason codes pass through, and no error or
  log line renders the token or the URL (`Debug` shows the endpoint
  redacted: no userinfo, query or fragment). One 5 s deadline for the whole
  exchange.
- `stridelabs-http`, feature `tls`: `install_default_provider()` installs
  the aws-lc-rs rustls provider as the process default
  (`ProviderInstall`).
- `stridelabs-http`, feature `ssrf`: `fetch_public(url, &FetchPolicy)`, a
  port of Python `stridelabs-mcp`'s `ssrf.py` for fetching caller-supplied
  URLs. https only by default; userinfo and metadata host names refused; a
  hand-written address policy from the IANA IPv4 and IPv6 Special-Purpose
  Address Registries (IPv6 only inside `2000::/3`; IPv4-mapped and NAT64
  addresses unwrapped and rechecked). Every DNS answer must be public, and
  each hop is sent through a client whose resolver answers only that name
  with the validated address, with proxies off, no pooling across decisions
  and redirects off by default (re-validated per hop when allowed). One
  wall-clock budget across hops, a streamed byte cap, Python's error texts,
  nothing internal in an error. Nothing is ever decompressed
  (`Accept-Encoding: identity`; any other `Content-Encoding` is refused).
- `stridelabs-http`, feature `ssrf-test-support`: a loopback TLS
  test-server override, compiled out without the feature and inert until
  `with_loopback_test_server` is called. Not for release builds.
- `stridelabs-redis`, a new crate: `RedisHandle`, a lazy single-flight
  Redis handle built from a URL with no I/O (a malformed URL, `#insecure`
  or a zero timeout fails at construction; the first command dials, once
  across concurrent callers; an I/O failure discards the connection under a
  generation guard; 1 s dial and 500 ms response timeouts; `Debug` never
  shows the URL). `fixed_window_hit` is Python `stridelabs-mcp`'s
  `INCR` + `EXPIRE` Lua as a raw `EVAL`, never replayed after an
  outcome-unknown failure; `get` / `set_ex` retry once on a fresh connection
  after an I/O error on a cached one, and when that fresh connection cannot
  be made the caller gets the first attempt's outcome-unknown `Io`, never
  the dial's "never sent" `Connect`. Errors classify by where the round
  trip failed. `rediss://` through redis-rs `tokio-rustls-comp` in this
  crate only (native roots, no provider chosen: the consumer installs
  aws-lc-rs). Feature `live-tests` compiles the crate's real-Redis suite.
- `stridelabs-testing`, feature `redis`: `require_redis(default_url)`,
  fail-loud, `REDIS_URL` first. The URL redaction shared with
  `require_postgres` now renders a URL only when it has the expected
  structure. Built with no redis-rs TLS feature. Compose and CI gain Redis
  on 6390.
- `stridelabs-gcp`, a new crate: policy-free Google Cloud building blocks
  that take the consumer's `reqwest::Client` and enable no TLS feature.
  `TokenProvider` resolves Application Default Credentials from an
  enumerated subset (explicit base64 JSON, `GOOGLE_APPLICATION_CREDENTIALS`,
  the gcloud well-known file, then the metadata server) for
  `authorized_user` and `service_account` credentials; any other type is
  refused, and a configured-but-broken source fails construction rather
  than selecting another identity. Construction is local only; tokens are
  cached with a 60 s refresh margin and one spawned refresh per attempt
  that caller cancellation cannot cancel. `GcsClient` uploads
  (`uploadType=media`), downloads (bounded, 32 MiB default) and deletes,
  with bucket and object-name validation and `public_url`.
  - Feature `service-account-key`: the RS256 JWT-bearer exchange for
    `service_account` keys (jsonwebtoken with `use_pem`, on the workspace's
    aws-lc-rs backend). Off, such a credential is
    `GcpAuthError::Unsupported`, never a silent fallthrough.
  - Feature `vertex`: typed `generateContent` request and response, the
    endpoint builder (the `global` host as google-genai, with validated
    location, project, model and version), a response cap (64 MiB default)
    and `first_inline_image()` classifying `Image` / `Blocked` (`SAFETY`,
    `PROHIBITED`, `BLOCKLIST`, `RECITATION`, `SPII`, `promptFeedback`) /
    `Empty`.
  - Google's `error.message` (which may echo a prompt or object name) is
    only available through `sensitive_message()`; serde and reqwest errors
    are reduced to fixed categories, never rendered.
- `stridelabs-mcp`: rate limiting in the tool boundary. `RateClass`, an
  async object-safe `RateLimiter`, `RateLimited` (Python `stridelabs-mcp`'s
  text), `NoLimit` and `MemoryLimiter` (fixed 60 s windows). `ToolCall::
  rate_limit` checks after the scope check, inside the existing
  cancellation, timeout and panic region; a refusal is the new
  `Outcome::RateLimited` (`"ratelimited"`, appended so earlier discriminants
  are unchanged) with one audit line as before.
- `stridelabs-mcp`: `SlauthPatCredential`, a `CredentialVerifier` for
  `slp_live_` PATs on `PatValidator` (rejected is `Invalid`, unavailable is
  `Unavailable`, the ceiling scopes applied on every call), with an
  optional `PatCache` (key = the first 32 hex of sha256 of the token;
  successes only, stored as a `CachedPat` of the identity UUID and an
  absolute expiry, the validation's start plus a whole-second TTL of 1 s to
  1 day, which the credential enforces on every read so that neither a hit
  nor a write that lands late can extend it; every cache operation bounded
  at 250 ms; fail-through on any cache error or malformed entry). The
  validator's client must not follow redirects (above).
- `stridelabs-mcp`, feature `redis`: `RedisRateLimiter` (fixed window on
  `stridelabs-redis`, fails open on any backend error, never replayed) and
  `RedisPatCache` (`{uuid}:{expires_at}` under a required prefix, `SET … EX`
  as housekeeping only).
- `stridelabs-mcp`, feature `image-fetch`: `ImageFetcher`, Python
  `fetch.py`'s twin over the pinned public-only fetch (`data:` URIs,
  Content-Type and magic-byte checks, Python's messages); its setters cannot
  weaken the size cap, https-only, no-redirect or Accept rules.
- `stridelabs-mcp`, feature `cors`: `cors_layer()` for bearer-only MCP
  endpoints (any origin, no credentials, mirrored methods and headers,
  `Mcp-Session-Id` and `WWW-Authenticate` exposed).
- `stridelabs-mcp`: `canonical_tools_json` and, under `test-support`,
  `assert_committed_tools_are_fresh`, the MCP counterpart of the OpenAPI
  freshness test. Feature `live-tests` compiles the real-Redis tests.
  `PARITY.md` maps Python `stridelabs-mcp` 0.4.0's tests to the Rust ones.

### Security

- The SSRF address policy in `stridelabs-http` is built from the IANA IPv4
  and IPv6 Special-Purpose Address Registries as retrieved 2026-10-17; the
  guard is the policy, not a deny-list of well-known hosts.
- The workspace still has one crypto provider, aws-lc-rs. `stridelabs-gcp`
  and `stridelabs-auth` pull no rustls; `stridelabs-redis` and
  `stridelabs-mcp`'s `redis` and `image-fetch` features bring rustls, but
  only on aws-lc-rs and never ring (a rustls `ring` next to it makes
  `ClientConfig::builder()` panic). CI guards each.
- Dependency majors: `redis` 1 (new workspace dependency, no default
  features and no TLS feature at workspace level), `base64` 0.22 and
  `percent-encoding` 2 (both already in the lock). A consumer that names
  redis-rs types moves to the same major.
- `stridelabs-gcp` keeps secrets out of its errors, `Debug` and logs: an
  OAuth failure keeps only a validated `error` code, `TokenOptions` redacts
  in `Debug`, and every URL component (a hostile `location` could otherwise
  move the Vertex host) is validated before a token is fetched.

### CI and tooling

- New guards: "stridelabs-gcp pulls no rustls" and "stridelabs-mcp's redis
  and image-fetch put rustls on aws-lc-rs, never ring"; the stridelabs-mcp
  no-rustls guard now covers the core, `cors` and `test-support`.
- Per-feature build and clippy lanes, one feature at a time with `-p`
  alone, for `stridelabs-mcp`, `stridelabs-gcp`, `stridelabs-http`
  (`tls`, `ssrf`, `ssrf-test-support`), `stridelabs-redis` and
  `stridelabs-testing` (`redis`), so a feature that compiles only because
  another is on is caught.
- Redis 7 on 6390 beside Postgres, for the all-features lane's fail-loud
  integration tests.
- `cargo-semver-checks`, the `downstream-limen` `[patch]` loop and
  `scripts/downstream-check.sh` list all eight crates.

## [0.6.0] - 2026-10-17

A sixth crate, `stridelabs-mcp`: what a Rust service needs to serve MCP on
slauth, as the Python services do with stridelabs-python's `stridelabs-mcp`
(RFC 9728 metadata, slauth tokens bound to the resource, a stateless rmcp
Streamable HTTP endpoint, and a scoped, audited tool boundary). Everything
else is additive: `stridelabs-auth` can verify a token into the caller's
own claims type, which the new crate builds on. No breaking change; the
dependency majors are v0.5.0's, plus `rmcp` 3.5 for consumers of the new
crate.

### Added

- `stridelabs-auth`: `Verifier::verify_bearer_claims::<C>(token)` and its
  network-free twin `Verifier::claims_with_jwks::<C>(token, &jwks, kid,
  issuer, audience)`, for tokens whose claim rules are not a sign-in's (an
  MCP access token: audience = the resource URL, scopes, optional email).
  They run the same key selection, RS256 signature, `exp`, `iss` and `aud`
  checks (all three required) and return the claims as the caller's type,
  with no `email` or `sub` rules: the caller owns those. `verify_with_jwks`
  and `verify_bearer` are now built on them, so there is one copy of the
  validation logic; their behaviour is unchanged.
- `stridelabs-auth`: `test_support::TestClaims::claim(name, value)` adds an
  arbitrary claim to a minted token (`scope`, `scp`, `client_id`, …),
  applied last so it can also replace one of the builder's own. A builder
  that never calls it produces exactly the claim set it did before.
- **`stridelabs-mcp`**, a new crate: the hardened middle of an MCP server on
  rmcp 3.5, the Rust twin of Python `stridelabs-mcp`. First consumer:
  parcel's `/mcp`.
  - `ProtectedResource`: the canonical resource URL under slauth's
    `normalize_mcp_resource` rule (https only, no trailing slash, default
    port, query, fragment, userinfo, escapes or dot segments). Non-canonical
    input is rejected naming the canonical form rather than rewritten, so
    the configured string is the token audience. Derives the RFC 9728
    document, the challenge's metadata URL, the route and the allowed host.
  - `metadata_router`: the RFC 9728 document at both origin-root well-known
    paths, generic over the app's state.
  - `McpVerifier`: slauth JWTs with audience = the resource URL (scopes from
    `scope` and `scp`, string or array; `client_id`, else `azp`; email
    optional; non-empty `sub`), plus app credentials selected by prefix
    (`CredentialVerifier`, any async closure). `VerifyError` separates
    `Invalid` (401) from `Unavailable` (503; a JWKS fetch failure).
  - `McpAuthLayer`: RFC 6750 challenges (no `error` without a credential,
    `invalid_token` for a refused one, both with `resource_metadata` and the
    scope hint), `503 temporarily_unavailable` on an outage, optional
    boundary-level scopes (`403 insufficient_scope`), the `Principal` into
    the request extensions.
  - `server_config` / `router`: rmcp's Streamable HTTP service stateless
    (no sessions, JSON responses), `allowed_hosts` = the resource host plus
    extras, a pinned 4 MiB body limit, at exactly the resource's path behind
    the auth layer; `principal(&ctx)` reads the caller back in a tool.
  - `ToolCall`: per-tool scopes (`ScopeError`, the Python message), a
    timeout (default 30 s), cancellation, `ToolError` (`user` / `denied`
    shown to the model; `internal` and panics become "Internal server
    error." and are audited by type only), all as `isError` tool results,
    and exactly one `stridelabs.mcp.tool` audit line per run of the tool's
    code. Plus
    `clamp_limit` / `clamp_offset` / `Page`.
  - Feature `test-support`: `test_support::access_token(&resource)` mints MCP
    access tokens with stridelabs-auth's throwaway test keys.
- CI and tooling, not part of the crates: a "Guard: stridelabs-mcp pulls no
  rustls" step; `cargo-semver-checks` covers every crate and passes over,
  with a notice, a crate the baseline tag does not have yet (stridelabs-mcp
  until v0.6.0 is tagged); `downstream-limen` and
  `scripts/downstream-check.sh` patch all six crates.

### Security

- `Cargo.lock`: rustls 0.23.45 → 0.23.46 (RUSTSEC-2026-0346, -0347, -0348,
  -0349) and quinn-proto 0.11.16 → 0.11.19 (RUSTSEC-2026-0338 to -0342), so
  `cargo audit` is clean again. Lock only, no manifest change: rustls is
  compiled only under `stridelabs-http`'s `proxy`, and quinn-proto is a
  lock-only entry (reqwest's optional `quinn`) that nothing compiles. A
  consumer's own `Cargo.lock` decides what it builds, so it bumps the same
  two packages there.

## [0.5.0] - 2026-10-11

Every pending dependency major in one release, and the guards and CI that
keep what they changed true. This is a minor bump (0.x) with a long list of
breaking changes, set out first under Changed. A consumer moves its own
`reqwest`, `jsonwebtoken`, `sqlx`, `utoipa`, `tower-http` and
`metrics-exporter-prometheus` to the same majors when it moves to this tag,
because their types appear in these crates' public signatures.

- `stridelabs-auth` bounds how long a cached JWKS key outlives its last
  successful fetch (`JWKS_TTL + MIN_REFETCH_INTERVAL`, 3630 s), so a retired
  key no longer keeps verifying for as long as an issuer outage lasts, and it
  verifies only with a key fit for RS256 signatures.
- The workspace has one crypto provider, aws-lc-rs: ring is compiled nowhere,
  and `jsonwebtoken` runs on its `aws_lc_rs` backend. CI guards that, and the
  other properties a consumer's graph inherits (`stridelabs-testing` pulls no
  ring, `stridelabs-auth` no rustls, and the lock has no `rsa`), instead of
  trusting them.
- CI tells the truth: `cargo audit` gates main, manual runs and the weekly
  schedule (a scheduled failure opens an issue), `cargo-semver-checks` checks
  all five crates against the previous tag and is a real gate, and a
  downstream job builds limen against the candidate.
- `stridelabs-observability` writes Google Cloud Logging lines and request
  logs, bringing Rust services to parity with Python `stridelabs-logging`.

The minimum supported Rust version is unchanged at 1.97 (raised in v0.2.0;
see the README's "MSRV policy").

### Added

- `LogFormat::Cloud`: one Google Cloud Logging structured JSON object per
  line — `severity`, a top-level `message`, `logger`, an RFC 3339
  `timestamp`, `httpRequest` assembled from `httpRequest.*` fields, and
  `requestId`/`logging.googleapis.com/trace` lifted from the enclosing
  request span — the shape of Python's `CloudLoggingFormatter`.
- `LogFormat::from_environment(env)`: `Text` for exactly `"development"`,
  `Cloud` for anything else.
- `CloudLayer`, the `tracing-subscriber` layer behind `LogFormat::Cloud`,
  for composing a subscriber by hand; and the request-span contract
  constants `REQUEST_SPAN_NAME`, `REQUEST_ID_FIELD` and `TRACE_FIELD`.
- `RequestLogLayer` / `RequestLogService` / `RequestLogConfig`: an
  outermost tower layer that establishes each request's id (extension, else
  a valid `x-request-id`, else generated), opens the request span with the
  Cloud Trace id from `X-Cloud-Trace-Context` when a GCP project is
  configured (`GOOGLE_CLOUD_PROJECT`, else `GOOGLE_PROJECT_ID`), and writes
  one `stridelabs.request` entry per request (`"METHOD PATH STATUS"`,
  `httpRequest.{requestMethod, requestUrl, status, latency, protocol,
  userAgent, remoteIp}`; ERROR ≥ 500 or on an inner error or panic, WARN ≥
  400, 499 WARN for a dropped response future). Sensitive query values are
  redacted (`DEFAULT_REDACTED_QUERY_PARAMS`, names matched after
  percent-decoding and Unicode lowercasing); userinfo is stripped from the
  logged host, and a malformed `Host` or a non-`http(s)` `X-Forwarded-Proto`
  is never copied into `requestUrl`; request headers other than
  `User-Agent` and bodies are never logged; it writes no response header.
  The entry is written when the response head is ready, and the span covers
  the response future only (a streamed body or a spawned task needs
  `.instrument(Span::current())`). `REQUEST_LOG_TARGET` names the entry's
  target.
- `stridelabs-observability` feature `axum` (off by default): the
  `remoteIp` fallback to axum's `ConnectInfo<SocketAddr>` peer address.
- `JwksCache::with_ttl(Duration)` and
  `JwksCache::with_min_refetch_interval(Duration)`: builders replacing the
  cache's two durations (defaults `JWKS_TTL` and `MIN_REFETCH_INTERVAL`), so
  a consumer's tests can watch a set expire or the interval close without
  sleeping. `Verifier::new` still builds its cache with the defaults.
- CI and tooling, not part of the crates: `scripts/downstream-check.sh
  <consumer> <ref>` builds and tests tapper, slauth, limen or spendwise-rs
  against this checkout through `[patch]` path overrides (a development
  check, not `--locked`; it refuses a dirty tree and prints the tree id), and
  a `downstream-limen` CI job does the same for limen at a pinned commit.
  `ci-success` requires that job on every event, the weekly schedule
  included.

### Changed

- **BREAKING:** `LogFormat` is now `#[non_exhaustive]` (to add `Cloud`
  without every future format being a breaking change). A `match` on
  `LogFormat` outside the crate without a wildcard arm (`_ => ...`) no
  longer compiles.
- **BREAKING (behaviour, for `Verifier` and `JwksCache` users):** the JWKS
  stale bound. Inside the refetch interval the cache serves only a set whose
  last *successful* fetch is younger than `JWKS_TTL + MIN_REFETCH_INTERVAL`.
  Before, it served a set holding the kid however old it was, and every
  failed fetch attempt opened a fresh interval, so during an issuer outage a
  key the issuer had retired (say, because it leaked) kept verifying for as
  long as the outage lasted. Now **a retired key stops verifying at most
  `JWKS_TTL + MIN_REFETCH_INTERVAL` (3630 s) after the last successful
  fetch.** Past the bound a suppressed lookup fails with `AuthError::Jwks`
  (500 under the `http` feature), not `UnknownKid` (401), whether or not the
  set has the kid: inside the interval only a failed or cancelled attempt
  leaves a set that old, which is an outage rather than a verdict on the
  token, and a 401 would sign users out during it. Both fail closed.
- `metrics-exporter-prometheus` 0.17 → 0.18 (0.18.3; 0.18.2 is yanked).
  **BREAKING** for a consumer that names `PrometheusHandle`, which
  `prometheus::install` returns: it must depend on `metrics-exporter-prometheus`
  0.18 too (`metrics` stays 0.24). The scrape text `install` produces is
  unchanged, series for series, for counters, gauges, `*duration_seconds`
  histograms (the only ones `install` gives buckets) and ordinary
  default-summary histograms, except in the three cases below: their `# HELP`,
  `# TYPE` and sample lines are pinned by tests. (The order of the families,
  and of the series within one, was never fixed and still is not.)
  Exception 1, a renamed series: a histogram that falls back to the default
  summary (any histogram not ending `duration_seconds`) whose name ENDS IN
  `count` or `sum` loses that suffix on the matching series. 0.18's suffix
  helper skips a suffix the name already ends with, comparing
  `ends_with("count")` without the `_` (upstream `formatting.rs`,
  `add_suffix_if_missing`), so after `install()`
  `metrics::histogram!("discount")` renders `discount{…} 2` where 0.17.2
  rendered `discount_count{…} 2`, and `checksum{…} 4` where it rendered
  `checksum_sum{…} 4`; the other series of the summary (`discount_sum`,
  `checksum_count`, the quantiles) are unchanged.
  A consumer with such a metric must rename it or update the queries and
  alerts that read its `_count`/`_sum` series. A test pins this as observed on
  0.18.3, so an exporter release that fixes it shows up as a deliberate
  change. Exception 2, series that used to merge and no longer do, for ALL
  four kinds above (counters, gauges, `*duration_seconds` histograms and
  default-summary histograms): one metric recorded with two label keys that
  differ only in characters Prometheus replaces with `_` when it renders a
  label name (anything outside `[A-Za-z0-9_]`, and a digit in first position)
  and carry the same value. `"route-path" => "/a"` and `"route_path" => "/a"`
  both render as `route_path="/a"`. 0.17.2 sanitized the labels before
  grouping and rendered ONE series: a histogram pooled both spellings'
  observations (observations 1 and 3 gave `x_sum{route_path="/a"} 4` and
  `x_count{route_path="/a"} 2`), and a counter or gauge printed one line
  holding whichever of the two values the exporter visited last, not their sum
  and not the same one on every run. 0.18.3 groups on the raw labels and
  sanitizes only when it writes, so each spelling is its own series, and the
  two print with an identical name and labels: a counter or gauge prints two
  `x{route_path="/a"}` lines (here `1` and `3`), and a histogram prints two
  complete bucket or quantile sets, each with its own sum and count
  (`x_sum{route_path="/a"} 1` and `x_sum{route_path="/a"} 3`, each beside an
  `x_count{route_path="/a"} 1`), in no fixed order. Two samples with one name
  and label set cannot be two series in Prometheus; ingesting such duplicates
  is undefined, so do not rely on which one a scraper keeps. Use ONE spelling
  per label key (letters, digits and `_`, the same at every call site). Label
  values that render differently, and keys that differ only in case, were
  never merged and are unchanged; two values the exporter's escaping renders
  identically (e.g. differing only in backslash runs) split the same way.
  Four tests, one per kind, pin the 0.18.3 rendering as observed, so an
  exporter release that merges them again shows up as a deliberate change.
  Exception 3, a duplicate description: when one metric is described twice
  (`describe_counter!` and friends) before its first scrape, 0.18.3 keeps the
  LAST description in `# HELP` where 0.17.2 kept the first (the exporter
  queues descriptions in an evmap whose read view does not yet see the first
  one). A scrape between the two calls keeps the first. Describe each metric
  once.
  0.18's fix that puts the `_total` suffix on a counter's `# HELP` and
  `# TYPE` lines applies only with the new `with_recommended_naming(true)`,
  which `install` does not set; a consumer building its own exporter with it
  gets `# HELP x_total`, `# TYPE x_total counter` and `x_total{…} N` for a
  counter registered as `x`.
  Likewise `set_enable_unit_suffix(true)` (deprecated in 0.18; `install` does
  not set it) now suffixes `# HELP`/`# TYPE` like the samples and no longer
  repeats a unit already in the name (`x_seconds_seconds_bucket`).
- `tower-http` 0.6 → 0.7 (0.7.1). **BREAKING** for a consumer that names
  tower-http types: `cors_layer` returns `tower_http::cors::CorsLayer`, and
  `SecurityHeadersLayer`'s `Service` is a `tower_http::set_header` stack, so
  code that writes either type down must depend on tower-http 0.7 too (applying
  the layers with `.layer()` is unaffected).
- `utoipa` 5 → 6 (6.0.0 with utoipa-gen 6.0.1, both from 2026-09-22/23;
  `stridelabs-http`'s `openapi` feature). **BREAKING** for every consumer of
  the module: `documented_pairs`, `find_operation`, `expect_operation`,
  `to_pretty_json`, `expected_file_contents`, `check_committed_spec` and
  `assert_committed_spec_is_fresh` take a `&utoipa::openapi::OpenApi`, and
  `find_operation` / `expect_operation` return a
  `&utoipa::openapi::path::Operation`, so the caller must be on utoipa 6 (two
  majors are two unrelated `OpenApi` types). Those are the only utoipa types in
  the public API. A service that builds its router with
  `utoipa_axum::router::OpenApiRouter` moves to utoipa-axum 0.3, the release
  that requires utoipa 6; its `router.rs` (`nest`, `merge`, `route`) is
  byte-identical to 0.2.0, so the module docs' nest/merge guidance stands.
  `to_pretty_json` output is unchanged for an unchanged spec, now pinned
  byte for byte by a test of a fixed document that passed unchanged across the
  bump. What utoipa-gen 6 *derives* does change, though, so a consumer must
  diff its regenerated `openapi.json` and run its validator (Spectral or
  similar) rather than assume a one-line diff. Known upstream differences:
  the `oneOf` of an `Option<T>` field now lists the `$ref` first and
  `{"type":"null"}` second (utoipa 5 listed `null` first; the canonicalizer
  sorts object keys only, never arrays); a non-nullable `$ref` field carrying
  `title` or `default` loses its `oneOf` wrapper; a response declared with an
  empty description serializes as `{}` instead of `{"description":""}`, which
  OpenAPI 3.1 rejects (`description` is required), so give every response a
  description; and an `inline` unit-enum field that also carries a `title`, a
  description (a doc comment counts), a `default`, `read_only` or
  `write_only` derives an `allOf` of the string enum and `{"type":"object"}`,
  a schema no value satisfies, so do not inline such a field (reference the
  enum instead). `documented_pairs` does not list the two path-item slots
  utoipa 6 added for OpenAPI 3.2 (`query` and `additional_operations`): they
  have no `HttpMethod` variant, so the exhaustive match cannot see them, and
  neither the derive macro nor utoipa-axum can fill them; a test pins this.
- `sqlx` 0.8 → 0.9 (0.9.0, `stridelabs-testing`'s `postgres` feature).
  **BREAKING** for a consumer that names sqlx types from this crate:
  `require_postgres` returns an `sqlx::PgPool`, the only sqlx type in any
  public signature, so a consumer that names `PgPool` or hands the pool to its
  own sqlx code must be on sqlx 0.9 too (two sqlx majors are two unrelated
  `PgPool` types). The one query this crate runs is a `&'static str`, so
  sqlx 0.9's `SqlSafeStr` bound (dynamic SQL needs `AssertSqlSafe`) changes
  nothing here; it does apply to a consumer's own `format!`-built queries.
- `reqwest` 0.12 → 0.13 (0.13.5). **BREAKING** for a consumer that hands
  these crates a reqwest type or names one they return: it must be on reqwest
  0.13 too (two majors are two unrelated `Client` types). `stridelabs-auth`:
  `Verifier::new` and `JwksCache::new` take a `reqwest::Client`.
  `stridelabs-http` (`proxy` feature): `UpstreamClient::inner()` returns
  `&reqwest::Client`; `ClientBuildError::Build` and `ClientBuildError::CaParse`
  carry a `reqwest::Error`; `UpstreamFailure::classify`,
  `AppError::bad_gateway_upstream` and
  `AppError::bad_gateway_upstream_with_context` take a `&reqwest::Error`;
  `buffer_or_stream`, `buffer_or_stream_within` and `relay_response` take a
  `reqwest::Response`.
- **BREAKING (features):** where TLS is turned on. Nothing turns on a reqwest
  TLS feature at workspace level any more, and `stridelabs-auth` turns on none:
  it never builds a client outside its tests, so the TLS stack (and with it
  the process's rustls provider) is the consumer's choice. A consumer that
  fetched an `https://` JWKS through a client whose TLS came from
  stridelabs-auth's reqwest must now enable a TLS feature on its own reqwest
  0.13. Only `stridelabs-http`'s `proxy` enables one: `rustls`, reqwest 0.13's
  rename of 0.12's `rustls-tls` (`rustls-tls-native-roots` no longer exists).
  CI's "Guard: stridelabs-auth pulls no rustls" fails if `stridelabs-auth`'s
  normal graph, with default features or with all of them, ever contains
  `rustls` again.
- **BREAKING (behaviour, `proxy`):** the TLS trust model. reqwest 0.13's
  `rustls` uses rustls's aws-lc-rs provider (unless the process installed a
  default provider first) and `rustls-platform-verifier`: **the OS trust store
  plus any extra roots, with no bundled webpki roots** (0.12's `rustls-tls`
  carried Mozilla's). `UpstreamClient::build`'s `ca_bundle_pem` is merged into
  that store, as before. On Linux the store is the system CA bundle
  (`SSL_CERT_FILE`/`SSL_CERT_DIR` respected), so **a consumer's image needs
  `ca-certificates`**: without a bundle, `UpstreamClient::build(true, None)`
  fails with `ClientBuildError::Build`. mkcert and corporate roots installed in
  the OS store still verify. aws-lc-sys, a C build, joins every `proxy`
  consumer's graph. If that graph also enables rustls's `ring` (redis-rs's
  `tls-rustls`, sqlx's `tls-rustls-ring`), rustls has two providers and every
  `rustls::ClientConfig::builder()` relying on the crate-feature default
  panics: keep aws-lc-rs the only one.
- `jsonwebtoken` 9 → 11 (11.1.0, `stridelabs-auth`) with the `aws_lc_rs`
  crypto backend. **BREAKING** for a consumer that names jsonwebtoken types
  from this crate: `Verifier::verify_with_jwks` takes a
  `&jsonwebtoken::jwk::JwkSet`, `JwksCache::jwks_for_kid` returns an
  `Arc<JwkSet>`, and `test_support::TestKey::jwks` and `test_support::test_jwks`
  return a `JwkSet`, so code that passes or receives one must be on
  jsonwebtoken 11 too. Nothing else exposes a jsonwebtoken type: `Claims` and
  `VerifiedIdentity` are plain structs, `AuthError` holds no jsonwebtoken
  error as a source (`InvalidToken` carries a fixed classification phrase),
  and `TestKey::{pem, jwks_json, mint, mint_with_kid}` deal in strings and
  `Serialize` claims. How rejections are classified changes only as "only a
  key fit for RS256 signatures verifies" below says. jsonwebtoken 11's new
  error kinds (`InvalidClaimFormat`, `UnsupportedAlgorithm`,
  `InvalidEddsaKey`, `Signing`, `Provider`) fall into `InvalidToken`'s
  existing "token is malformed" arm, and none of them arises on `Verifier`'s
  RS256 path: `InvalidClaimFormat` (a malformed `exp`/`nbf`) because `exp` is
  a required claim, so a malformed one is still "a required claim is
  missing", and `nbf` is not validated; `UnsupportedAlgorithm` (a JWK of
  unknown key type) because only RSA keys reach `DecodingKey::from_jwk`; the
  other three belong to signing, EdDSA keys and custom providers.
- **BREAKING (behaviour): one jsonwebtoken backend per graph.** jsonwebtoken
  10+ chooses its crypto from crate features, which Cargo unifies across a
  consumer's whole graph, and with none or both of `aws_lc_rs` and
  `rust_crypto` on it compiles cleanly and then panics at the first sign or
  verify. This crate turns on `aws_lc_rs`, so a consumer whose graph also
  enables `rust_crypto` (on its own jsonwebtoken 10+, or through another
  dependency) panics in `Verifier::verify_bearer`,
  `Verifier::verify_with_jwks` and `TestKey::mint`. The consumer rule:
  **never enable jsonwebtoken `rust_crypto`; use aws-lc-rs as the only rustls
  provider** (install it at startup with
  `rustls::crypto::aws_lc_rs::default_provider().install_default()` if your
  service builds rustls configs itself). `rust_crypto` is
  rejected because it brings back `rsa` (RUSTSEC-2023-0071). aws-lc-sys, a C
  build, replaces ring in every `stridelabs-auth` consumer's graph,
  production included. A test signs a token with the test-support key and
  verifies it through the JWKS path and `jsonwebtoken::decode` in both CI
  lanes; with no backend, or both, it panics. ring is no longer compiled
  anywhere in the workspace, and CI's "Guard: the workspace compiles no ring"
  step (a listing of every member's compiled graph, all features and targets)
  fails if it is again. `Cargo.lock` still lists ring, through optional edges
  nothing compiles, which is why the guard does not grep the lock.
- **BREAKING (behaviour, security): only a key fit for RS256 signatures
  verifies.** `Verifier` verifies a token with a JWK under its `kid` only if
  the key is RSA and its `alg`, `use` and `key_ops`, where present, say RS256,
  `sig` and `verify`; keys sharing a kid are all considered. Before, any key
  under the kid was used: `DecodingKey::from_jwk` ignores those labels, so an
  RSA key the issuer published for encryption (`use: enc`, `alg: RSA-OAEP`)
  verified tokens in 0.4.0, and jsonwebtoken 11 widened that to labels 9 did
  not know (`alg: RSA-OAEP-512` now parses, as `UNKNOWN_ALGORITHM`). A kid
  with no fit key is now `AuthError::UnknownKid` (a 401 under the `http`
  feature), not `Jwks`: there is no verification key by that name, and since
  the kid is the caller's choice, a 500 would let anyone raise the service's
  error rate against an issuer that publishes encryption keys. Against 0.4.0,
  for a token naming that kid:
  - an RSA key labelled for something else (any `alg` but RS256, a `use`
    other than `sig`, `key_ops` without `verify`): verified, now `UnknownKid`;
  - a non-RSA key (EC, OKP, `oct`): `InvalidToken("algorithm is not
    accepted")`, now `UnknownKid` (both 401);
  - a key jsonwebtoken 9 could not parse at all (an `alg` it did not know, or
    an unknown `kty`): 0.4.0 rejected the whole set, so every token failed
    with `Jwks` (500); jsonwebtoken 11 parses the set, tokens under its other
    kids verify, and one naming that key is `UnknownKid`.

  A correctly labelled signing key, or one with no labels, verifies as
  before. Rejections not listed here are classified as before.
- **BREAKING (behaviour, `stridelabs-testing`):** no TLS. The `postgres`
  feature's sqlx is built with no `tls-*` feature (it used to enable
  `tls-rustls-ring`) because the pool talks to a local or CI Postgres in the
  clear, and a TLS feature there unifies into every consumer's test graph,
  where `ring` next to the aws-lc-rs provider of reqwest 0.13's `rustls`
  makes `rustls::ClientConfig::builder()` panic. Behaviour change for a
  consumer whose test URL demands TLS: `sslmode=require` (or
  `verify-ca`/`verify-full`) now panics with sqlx's "built without TLS
  support" error, pinned by a test; the default `prefer` connects in the
  clear. CI's "Guard: stridelabs-testing pulls no ring" step fails if a TLS
  feature brings `ring` back.
- `RequestIdLayer` reuses an existing `RequestId` request extension (held
  to the same validity rule as the header) before the `x-request-id` header,
  so behind an outer `RequestLogLayer` it echoes the id that was logged.
- `LogFormat::Json`'s documentation now lists the `span`/`spans` keys its
  lines have always carried inside a span; the format itself is unchanged.
- Internal dependency bumps, no API change: `rand` 0.9 → 0.10
  (`stridelabs-auth`, `stridelabs-observability`) and `sha2` 0.10 → 0.11
  (`stridelabs-auth`). Neither crate's types appear in a public signature,
  and `pat::hash` output is unchanged: lowercase SHA-256 hex, pinned by a
  known-vector test, so stored token hashes stay valid.
- Internal dependency swap, no API change: `serde_yaml` 0.9 (archived) →
  `yaml_serde` 0.10, the YAML organization's maintained fork
  (`stridelabs-config`; the parser underneath moves from `unsafe-libyaml` to
  its fork `libyaml-rs`). `FileError::Parse` messages are unchanged —
  field path, line/column and parser context render identically — and are now
  pinned by two exact-message tests.
- `cors_layer`'s `Vary` is unchanged, and now explicit: it sets `Vary: origin,
  access-control-request-method, access-control-request-headers` itself. That
  is the header tower-http 0.6 always sent; 0.7 derives the list from the
  policy and would send `origin` alone for `cors_layer`'s origin list with
  constant method/header lists, so the bump by itself would have changed the
  wire. The header is pinned by a test on ordinary, disallowed-origin,
  no-`Origin` and preflight responses. Nothing else tower-http 0.7 emits for
  `cors_layer` or `security_headers` differs from 0.6 (status, headers,
  values and header order compared over 15 request shapes), so `Vary` is the
  only change guarded.
- The RUSTSEC-2023-0071 (`rsa`, Marvin timing side-channel; no upstream fix)
  ignore is gone from CI's `cargo audit` step and `deny.toml`: sqlx 0.9 no
  longer compiles `rsa` (MySQL's RSA auth is behind its opt-in `mysql-rsa`
  feature), so `Cargo.lock` has no `rsa` entry and `cargo audit` runs with no
  ignores. A "Guard: no rsa in Cargo.lock" CI step keeps it that way.
- reqwest errors are now rendered without URLs. `AuthError::Jwks` renders the
  `reqwest::Error` from a failed JWKS fetch or JSON decode with
  `without_url()`; before, it ended `for url (…)` with the JWKS URL's query
  string, which reached logs (the `http` feature's 500 logs it in full).
  Userinfo never reached it: reqwest moves it into an `Authorization` header.
  A canary test, a JWKS URL carrying both, pins the error's `Display` and
  `Debug` and the `http` feature's log line. In `proxy` nothing changes:
  `UpstreamFailure` and `bad_gateway_upstream` never render the error. But
  reqwest 0.13 now attaches the URL to a `Response::bytes()`/`json()` failure
  too, so a consumer that logs `%err` or `?err` from a body read now leaks the
  URL and its query string where 0.12 did not: call `.without_url()` first, or
  log `UpstreamFailure` instead.
- `Debug` for `SlauthConfig`, `JwksCache` and `Verifier` no longer prints a
  URL's userinfo, query or fragment: the JWKS URL (and `pat_validate_url`)
  renders as `scheme://host[:port]/path`, and a string that does not parse as
  a URL with a host as `<unparseable URL>`.

### Fixed

- `prometheus::install` is now safe to call from several threads at once.
  Two first callers could both find no handle yet, and the loser failed with
  "attempted to set a recorder after the metrics system was already
  initialized"; the first install is now serialized, so every caller gets
  `Ok` with the same handle.

### Not done

Two more `JwksCache` entry points were weighed alongside the builders and
deliberately left out:

- an all-keys accessor, for verifying a token that carries no `kid`: the
  access tokens slauth issues all carry one, and `Verifier` keeps rejecting
  a kid-less token with `MissingKid`;
- a public `refresh()` forcing a refetch, for an issuer that reuses a `kid`
  mid-rotation: slauth's issuer rotates by publishing a new `kid`, which the
  unknown-kid refetch already picks up.

## [0.4.0] - 2026-08-16

### Added

- `proxy::body`: `Buffered::TimedOut`, `buffer_or_stream_within` and
  `buffer_request_or_stream` — the body-buffering deadline variants and the
  biased-timer `buffer_bounded` core, ported from limen and generic over
  axum `Body` streams.
- `proxy::forwarded::apply_forwarded` — an `X-Forwarded-*` policy engine
  (`ForwardedPolicy`, `XffPolicy`, `XfpPolicy`) that makes a proxy's XFF/XFP
  trust decision explicit per leg, with no `Default` impl.
- `methods` module — `CLASSIFIED_METHODS`, `method_filter`,
  `refusing_unserved_over` — truthful HTTP method refusal helpers built
  around a caller-chosen method universe, with no-op (not panic) behavior on
  an empty refused set.
- `proxy::UpstreamFailure` — a pure `reqwest::Error` classifier plus a
  `tracing` logging helper, and `AppError::bad_gateway_upstream` /
  `AppError::bad_gateway_upstream_with_context` — a redacted `502`
  constructor for consumers on this crate's `AppError` envelope.
- `deny.toml` (license allow-list) plus a `cargo-deny check licenses` step
  in CI's `build-test` job, and a separate non-required `audit` job running
  `cargo-audit`.
- `cargo-semver-checks` in CI, run per-crate against the latest reachable
  `v*` tag (advisory/non-blocking until `v0.4.0` itself is tagged and
  becomes the new baseline).
- This CHANGELOG.

### Changed

- **BREAKING:** `proxy::body::Buffered` is now `#[non_exhaustive]` (to make
  room for the `TimedOut` variant above without every future variant being a
  major-version break). A `match` on `Buffered` outside this crate that does
  not include a wildcard arm (`_ => ...`) now fails to compile.

## [0.3.0] - 2026-08-04

`stridelabs-http`'s `openapi` feature sharpened from first-consumer
feedback: the public API surface tightened and `OperationNotFound`'s
contract corrected to match what it actually returns.

## [0.2.0] - 2026-08-03

`stridelabs-http` gained an optional `openapi` feature (canonicalizing
serializer, exhaustive `(method, path)` enumeration, committed-spec
freshness check), and the pinned Rust toolchain moved to 1.97.1.

Amended later: the toolchain bump also raised the workspace `rust-version`
(the MSRV) from 1.96 (`v0.1.0`) to 1.97 (`v0.2.0` and every later tag), and
this entry did not say so. Minimum supported Rust version raised to 1.97.
Consumers must be on Rust 1.97 or newer. Earlier tags are unaffected.

## [0.1.0] - 2026-07-25

Initial release: `stridelabs-config`, `stridelabs-observability`,
`stridelabs-http`, `stridelabs-auth` and `stridelabs-testing`, seeded from
spendwise-rs and limen.
