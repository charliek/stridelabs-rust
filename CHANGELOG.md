# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is lockstep across all twelve crates in this workspace (one
`[workspace.package].version`, bumped together regardless of which crate(s)
changed) rather than independent per-crate versioning —
see the root README's "Consuming these crates" section for what that means
for a consumer's pin.

## [Unreleased]

### Fixed

- `stridelabs-auth`: **a PAT validation states `Content-Length: 0`**.
  `PatValidator` sent its body-less `POST /api/v1/pat/validate` with no
  `Content-Length` (hyper writes none for an empty body). Over HTTP/1.1,
  Google's front end, in front of slauth on Cloud Run, answers such a
  `POST` with a **411 Length Required**. The validator maps that to
  `Unavailable("Authentication service error")`, so **every slauth PAT got
  a 503**, on REST and MCP alike (slaudio staging, 2026-10-27, logged
  `unexpected slauth PAT validation status status="411 Length Required"`).
  The same day, against production slauth, an HTTP/1.1 request without a
  body got a 411, one with `Content-Length: 0` got a 200, and HTTP/2
  succeeded either way.
  - **Who is affected:** every consumer since v0.7.0 that validates slauth
    PATs over HTTP/1.1 behind Google's front end, or behind any proxy that
    requires a length on a `POST`. That includes every consumer whose
    reqwest lacks the `http2` feature, which speaks nothing but HTTP/1.1.
    Local slauth has no such front end, which is why no local test caught
    it.
  - **The fix:** the request now carries exactly one `Content-Length: 0` and
    an empty body, as Python's httpx client sends it. The header is set by
    hand because an empty `.body(..)` puts nothing on the wire (hyper keeps
    a length the caller sets and adds none of its own). No API change.
- `stridelabs-gcp`: **an empty media upload states its length**.
  `GcsClient::upload` (and `upload_with` with only a CRC32C) sent a
  zero-byte object's `POST` with no `Content-Length`, the same hyper
  behaviour as above. Over HTTP/1.1, Google's front end refuses that with a
  411, so a zero-byte object could not be written. A media upload now
  always states its length (exactly one header, whatever the size). The
  multipart upload and every other request already carried a non-empty
  body or none that needs a length. No API change.

## [0.11.0] - 2026-10-27

A joint release, mostly lumen plan 003 (S1a: `stridelabs-postgres`'s begin guard, behind a new feature `guard`; S1b:
`stridelabs-auth`'s opt-in integer time claims, with the opt-in string issuer that builds on it; S1d: an empty key set is
a failed fetch; S2: a new crate, `stridelabs-voice`, the provider-neutral voice core extracted from tapper's, with `muse`
and `inworld` adapters; `stridelabs-testing`'s two message hooks), slaudio plan 027's `stridelabs-mcp` claim checks
(`McpVerifier::with_cache`, `with_scope_source`, `screen`, `claim_checks`), `stridelabs-observability`'s
`RequestLogLevel` (requested by tapper plan 017 and lumen), `stridelabs-gcp`'s `GcsClient::exists` (parcel plan 002) and
`scripts/downstream-check.sh` learning parcel and tapper's GCS emulator variable. **Changed:** `stridelabs-auth` on an
empty JWKS response (`{"keys": []}`), listed under Fixed: it was cached as the issuer's set, so a token got
`UnknownKid`/`UnseenKid` (a 401); it now fails the fetch as `AuthError::Jwks("response has no keys")`, so a consumer sees
its key-set error (its `Jwks` mapping, a 5xx), the previous set keeps serving and the failure counts toward the backoff;
a test that asserts the old kid error for an empty set fails. No API change. Everything else is additive or opt-in
(every new option is off by default, and the new crate and features add nothing to a consumer that does not name them),
and the dev-profile debug-info change in the workspace `Cargo.toml` never reaches a consumer. Downstream-checked against
each merge: downstream-limen passed on every one; no other downstream result is claimed here. Details below.

### Added

- `stridelabs-postgres`: **the begin guard**, behind a new feature `guard`
  (lumen plan 003 S1a: lumen-rs's `begin_on` and release check, upstreamed
  as a per-pool guard; tapper adopts it later). A consumer that does not
  turn `guard` on sees no change: `lazy_pool` and `PoolSettings` are
  untouched.
  - **`GuardedPool::lazy(options, PoolSettings, BeginGuard)`**: a lazy pool
    whose `after_release` hook probes released connections with a bounded
    `ROLLBACK` while the pool's own quarantine window is open (until its
    deadline has passed AND `max_connections` releases have been probed).
    Derefs to `PgPool`. **`GuardedPool::acquire(bound)`** →
    **`GuardedConnection`** (derefs to `PgConnection`; `detach()`),
    **`GuardedPool::begin(bound, TxBounds)`** and
    **`GuardedConnection::begin(TxBounds)`**: a plain `BEGIN`, then the
    bounds statement, in a spawned task (no caller cancellation abandons
    either), each within `begin_timeout`; a timeout, error or panic opens the
    window before the connection is dropped. **`GuardedPool::sibling(settings,
    Option<&str>)`**: a second pool on the same options with its own window
    and the parent's guard, only `application_name` changeable (printable
    ASCII, 1–63 bytes, else `UrlRefusal::NulByte` / `InvalidValue`).
  - **`BeginGuard`** (`new(begin_timeout)`, `with_probe_timeout`,
    `with_window`; `const fn`s refusing a zero timeout, one over
    `MAX_TIMEOUT` (10 min) or a window over `MAX_WINDOW` (1 h)) and
    **`TxBounds`** (`from_millis(lock_ms, statement_ms)`, `const fn`,
    refusing `lock_ms` 0, `lock_ms >= statement_ms` or over `MAX_MILLIS`;
    `NONE`; `sql()` renders `SET LOCAL lock_timeout = '…ms'; SET LOCAL
    statement_timeout = '…ms'`, one simple query).
  - Two WARN lines under target `stridelabs_postgres::guard`, fixed text,
    value-free: `a BEGIN was abandoned; probing released connections`
    (`cause` = `timeout` | `error` | `panic` | `set_local_timeout`) and `a
    released connection failed its probe; closed` (`error` =
    `error_summary`). Errors stay `sqlx::Error`.
  - Feature **`test-support`** (`guard` plus two `#[doc(hidden)]` seams for
    a consumer's tests: `GuardedPool::set_window_opened_at`,
    `TxBounds::REFUSED_BY_THE_SERVER`). `live-tests` now also compiles the
    guard's real-Postgres suite, against a small fault relay. `tokio` (`rt`,
    `time`) and `futures-util` become optional direct dependencies, under
    `guard`.
  - The README states what the guard guarantees (connection ownership, not
    exclusive transaction entry: `Deref` leaves sqlx's other entry points
    reachable, a caller precondition a consumer's source scan should
    enforce), its residuals (the error/panic race, release order, the silent
    peer, single-occupancy `after_release`), that `sibling` inherits the
    guard, that the raw-error WARN sqlx logs beside a failed probe is hidden
    only where `LOG_CAPS` is installed, and the dependency on sqlx's
    `#[doc(hidden)]` `Transaction::begin`.
  - `IGNORED_URL_PARAMETERS`' docs no longer say leaving the keepalives to
    the OS changes nothing: sqlx 0.9 sets no TCP keepalive and has no socket
    hook, so a silent peer is unbounded.
- `stridelabs-observability`: **`RequestLogLevel(pub tracing::Level)`**, a
  response extension that lowers the level of `RequestLogLayer`'s entry for
  that request (re-exported beside `RequestLogLayer`). A handler, an
  extractor's rejection or an inner layer inserts it into the response's
  extensions; the entry takes it only when it is less severe than the
  status's (`ERROR` ≥ 500, `WARN` ≥ 400, else `INFO`), and a raise or an
  equal level is ignored, so an app can quieten an expected,
  attacker-driven 5xx it chose to return but can never re-rank an entry
  upward or hide a 5xx it didn't decide on. An inner `Err` (500 `ERROR`), a
  panic (500 `ERROR`) and a dropped future (499 `WARN`) never consult it.
  Status, message and `httpRequest` are unchanged; under `CloudLayer`,
  `DEBUG` and `TRACE` both write `"severity":"DEBUG"`. No feature flag:
  nothing changes unless a response carries the extension. Requested by
  tapper (plan 017: a token naming an unseen key id, refused inside the
  JWKS refetch floor, should be one `INFO` entry, not an `ERROR`) and lumen
  (forged-kid requests produce one `ERROR` entry per request today).
  `scripts/downstream-check.sh` checks tapper; lumen and parcel are
  informational there (parcel does not use `RequestLogLayer`).
- `stridelabs-testing`: two message hooks for a consumer's own test setup
  (lumen plan 003). The existing functions and their messages are unchanged
  byte for byte; they share one validation path with the new ones.
  - **`require_local_url_hinted(var, hint)`**: `require_local_url` whose
    refusal for an unset or empty variable reads `<VAR> is not set. <hint>`,
    the consumer's `hint` verbatim (how to create the test database), then
    the usual explanation. Every other refusal is `require_local_url`'s.
  - **`require_local_redis_url_with_example(var, policy, example_url)`**
    (feature `redis`): `require_local_redis_url` whose refusals that suggest
    a URL (the database-0 refusal under `RefuseZero`, and the unset one,
    ``<VAR> is not set. Set it to a local Redis URL such as `<example_url>`.``)
    name the consumer's `example_url` (`redis://localhost:56379/1`) instead
    of the fixed `redis://localhost:6379/1`.
- `stridelabs-mcp`: two opt-ins for `McpVerifier`, so an MCP endpoint can
  check JWTs as the app's REST API (and its Python MCP server) does
  (slaudio plan 027). A consumer that uses neither sees no change:
  `McpVerifier::new` keeps `Verifier::new`'s rules (a 60 s leeway, `nbf`
  unchecked) and scopes stay the union of `scope` and `scp`.
  - **`McpVerifier::with_cache(&resource, checks: ClaimChecks, cache:
    JwksCache) -> Result<McpVerifier, ClaimChecksError>`**: stridelabs-auth's
    `Verifier::with_cache` for the MCP endpoint, so a zero leeway, `nbf`
    checked and the consumer's cache settings (`report_unusable_keys`, TTL,
    refetch interval). `checks` must be the resource's: issuer
    `resource.issuer()` exactly and `Audience::Required(resource.url())`;
    anything else, `IfPresent` and `NotValidated` included, is
    **`ClaimChecksError`** (`IssuerMismatch` / `AudienceMismatch`, fixed
    messages). **`ProtectedResource::claim_checks()`** returns exactly
    those, with `ClaimChecks::new`'s defaults (60 s leeway, `nbf` checked),
    to adjust. Plus **`McpVerifier::screen(ScreenPolicy)`** (either
    constructor; `Basic` by default) and **`McpVerifier::claim_checks()`**.
  - **`McpVerifier::with_scope_source(ScopeSource)`**: `ScopeSource::Union`
    (the default, today's behaviour) or **`ScopeSource::ScopeThenScp`**,
    fastmcp's precedence: `scope` when present (an empty one grants
    nothing), else `scp`, so a token carrying both is never granted a scope
    only `scp` names. Under either, a malformed `scope` or `scp` stays
    `Invalid` (even the one `ScopeThenScp` does not read), and `null`
    counts as absent.
- `stridelabs-auth`: **`ClaimChecks::with_integer_time_claims(bool)`** (off by
  default) and **`ClaimChecks::requires_integer_time_claims()`**: on, each
  `exp`, `nbf` and `iat` a token carries must be a non-negative JSON integer,
  so a fraction, a whole float (`3600.0`), an exponent form (`1.8e9`), a
  negative number, a boolean, a string and `null` are refused as the
  existing `AuthError::InvalidToken`, reason "a time claim is not a whole
  number of seconds" (jsonwebtoken rounds a float `exp`/`nbf` and never
  reads `iat`). Absent `nbf`/`iat` pass; `exp` stays required; a claim
  jsonwebtoken already refuses keeps its reason, and a payload naming one
  of the three twice is "claims are malformed". Each claim's type is read
  from the payload's JSON text, never through a `serde_json::Value` (which
  reads `null` in an `Option` as absent and, with serde_json's `raw_value`
  on, the object `{"$serde_json::private::RawValue":"0"}` as `0`). It applies wherever a consumer's
  `ClaimChecks` do (`Verifier::for_issuer`, `Verifier::with_cache`,
  `claims_with_jwks_checked`); `Verifier::new`, `claims_with_jwks` and
  `verify_with_jwks` keep it off. `Debug` prints the field. The rule is
  also public as **`time_claims_are_whole_seconds(payload_json: &[u8])`**,
  over the payload's JSON text, for a verifier that reads the payload
  itself. The rule tapper and slaudio
  hold app-side (lumen plan 003 W3.5).
- `stridelabs-auth`: **`ClaimChecks::with_string_issuer(bool)`** (off by
  default) and **`ClaimChecks::requires_string_issuer()`**: on, a token whose
  `iss` is not a JSON string is refused as the existing
  `AuthError::InvalidToken`, reason "the issuer claim is not a string".
  RFC 7519 §4.1.1 makes `iss` a single StringOrURI, but jsonwebtoken also
  takes an array that holds the issuer (`["<issuer>"]`, alone or beside
  other strings); that array is what the option refuses. `iss` stays
  required and exact-matched; an `iss` jsonwebtoken already refuses keeps
  its reason (a number, boolean, `null` or object is "a required claim is
  missing", an array without the issuer "issuer is not accepted"), and a
  payload naming `iss` twice is "claims are malformed". Builds on
  `with_integer_time_claims` rather than beside it: S1b's type-preserving
  reader also reads `iss` when this option is on (a string, escaped or not,
  versus anything else, the raw-value object included), and one read of the
  payload serves both options. Each option reads only its own claims: a
  claim of an option that is off is skipped unread, whatever it holds
  (`1e400`, a number serde_json cannot read, included) and however often it
  is named. So `time_claims_are_whole_seconds` reads every payload as it
  did (an `iss` of any value, repeated or not, is ignored), and this option
  alone never reads or refuses over a time claim. With both on, the time
  claims are checked first, so a token both refuse carries "a time claim is
  not a whole number of seconds" and turning this option on never changes
  the reason for a token the other already refuses. It applies wherever a
  consumer's `ClaimChecks` do (`Verifier::for_issuer`, `Verifier::with_cache`,
  `claims_with_jwks_checked`, `McpVerifier::with_cache`); `Verifier::new`,
  `claims_with_jwks`, `verify_with_jwks` and `McpVerifier::new` keep it off.
  `Debug` prints the field. The rule is also public as
  **`issuer_is_a_string(payload_json: &[u8])`**, beside S1b's predicate,
  for a verifier that reads the payload itself (an absent `iss` passes it).
  `stridelabs-mcp` documents both type rules as opt-in on
  `McpVerifier::new` and `McpVerifier::with_cache`, whose example now turns
  both on:
  `resource.claim_checks().with_integer_time_claims(true).with_string_issuer(true)`.
  No behaviour change there; new tests pin that `new`, and `with_cache` over
  plain `resource.claim_checks()`, still accept an array issuer and a
  fractional `exp`. The string-issuer rule is the one slaudio's Python MCP
  server (fastmcp on PyJWT) applies, held app-side by its Rust endpoint
  until now (slaudio W3 A1 review).

- `stridelabs-gcp`: **`GcsClient::exists(bucket, object) -> Result<bool,
  StorageError>`** (parcel plan 002), the existence probe a service wants
  before it stores bytes it may already hold. One metadata `GET
  {base}/storage/v1/b/{bucket}/o/{object}?fields=name`: `true` on a 2xx
  (whose body is never read), `false` on a 404 (one request, never retried,
  as `download` and `delete` treat it), any other status
  `StorageError::Status { operation: "exists", .. }`. Everything else is the
  other operations': bucket validation, the client's `ObjectNamePolicy`
  (refused names fail before a token or a request), its timeout and retry
  policy, a bounded error body and value-free errors. Additive: no feature,
  no dependency, no change to an existing call.
- **`stridelabs-voice`, a new crate: the provider-neutral voice core** two
  apps share (lumen plan 003; extracted from tapper's `tapper-rs/src/voice/`
  at `82be95f`, which had hardened lumen's copy). What lets a client talk to
  an app (a speech-to-text relay over a WebSocket) and hear it answer (text
  to speech, one sentence per request) inside a spending ceiling, with the
  speech providers swappable behind it. The core names no provider; a
  provider is an adapter behind a feature. Both apps run this crate's Redis
  scripts and key shapes byte for byte (the scripts' SHA-1s are pinned by a
  test), so either adopts it with no change on the wire.
  - **The core (no feature at all):** the client protocol, revision 1
    (`PROTOCOL.md` is canonical; `protocol`: the relay's events, both
    close-code tables, `END_FRAME`, the `rate`/`encoding` parameters, the
    allowed audio types, and a golden fixture whose SHA-256 a test pins);
    the speech-to-text provider traits (`SttProvider`, `SttSession`,
    `SttEvent`, fixed-class errors: `stt`) and the text-to-speech trait
    (`TtsProvider`, `VoiceCatalog`, the request's strict parse: `tts`), each
    with its contract in the module docs; the UTC day and month windows
    (`window`); the text-to-speech character budget with its per-sentence
    idempotency key (`budget`) and the speech-to-text audio budget with a
    fenced lease and a session meter (`lease`), on `stridelabs-redis` under
    the replay policy each call needs; every refusal a voice route answers
    (`refusal`: status, `{"detail"}` body, headers, the `429` body); the
    usage seam (`usage`); and `Voice`, built from `VoiceParts` and checked by
    `Voice::new` (`VoiceSetupError`), with `RelaySettings::check`.
  - **Feature `axum`:** the relay (`relay`: one session, its close machine
    and two log lines, the provider-run cap), the stream's admission
    (`stream`, `Voice::open_stream`, `StreamContext`: the configuration `503`,
    the `426`, the `422`s, the ping, the ticket and the fenced acquire, the
    takeover, the upgrade), the text-to-speech flow (`Voice::speak`,
    `TtsReply`, `tts::read_request`), `VoiceRefusal::into_response_with`
    (a refusal rendered through the app's own envelope) and `LOG_CAPS`
    (tungstenite's targets, to fold into the app's caps). axum is
    `default-features = false` with `ws`: the socket and the extractors, not
    a server.
  - **Features `muse` and `inworld`:** the Muse speech-to-text adapter
    (`MuseStt`, dialled through the `tokio_tungstenite::Connector` the app
    hands in) and the Inworld text-to-speech adapter (`InworldTts` over the
    `InworldClient` the app built). **The crate builds no HTTP client, no
    rustls `ClientConfig`, no connector, and selects no crypto provider**: the
    app injects each, and installs aws-lc-rs.
  - **Features `openapi`** (`utoipa::ToSchema` on `LimitScope` and
    `VoiceLimitBody`), **`test-support`** (the scripted adapters
    `ScriptedStt`/`ScriptedTts`/`RecordingUsage` in `testing`, the test seams,
    and, with `axum` and an adapter, that adapter's mock provider
    `muse::mock::MockMuse` / `inworld::mock::MockInworld`) and
    **`live-tests`** (not for consumers: the crate's real-Redis suites).
  - **Guards in CI:** `crates/voice/tests/guards.rs` fails if a core module
    names `muse`, `inworld`, `meta.ai` or `tungstenite::Message` (the
    adapters and `lib.rs`'s gating lines, listed exactly, excepted) or if any
    source builds a `reqwest` client, a `ClientBuilder`, a rustls client
    config, a connector or a `connect_async`; "Guard: stridelabs-voice's core
    build compiles no provider adapter" builds `axum,test-support` and checks
    the compiled features and graph (no `stridelabs-inworld`, no `reqwest`);
    "Guard: stridelabs-voice selects no crypto provider" checks that no
    feature set names `aws_lc_rs`, `aws-lc-rs` or `ring` on rustls and that no
    `ring`, `aws-lc-rs` or `aws-lc-sys` package is in the graph (dev edges
    excluded, with a positive control that they do list aws_lc_rs). CI also
    gains the crate's per-feature build and clippy lanes, three test lanes
    per feature set, and its place in the cargo-semver-checks list (checked
    from the first tag that contains it) and in the downstream checks'
    `[patch]` list.
  - The crate's README carries the feature topology, the Redis keys and
    scripts, the consumer's obligations, the named limits and an appendix:
    the walkthrough of two further providers (Deepgram and OpenAI file
    transcription for speech to text, ElevenLabs for text to speech) mapped
    onto the traits and the protocol's constants, from public documentation,
    and what it changed and recorded.

### Changed

- `scripts/downstream-check.sh`: **parcel** is an informational consumer
  (`parcel`, its root workspace on parcel's `main`: pass `origin/main` or set
  `DOWNSTREAM_PARCEL_REF`). Clippy and test run parcel's CI flags
  (`--workspace`, clippy also `--all-targets --all-features`). It never
  decides the exit. Preflight needs parcel's compose Postgres (`localhost:5439`,
  or the URL in `DOWNSTREAM_PARCEL_DATABASE_URL`, passed to the run as
  `DATABASE_URL`) and its fake-gcs-server on `localhost:4447`; the header
  names the collision with the `STRIDELABS_PG_PORT=5439` example in this
  library's CLAUDE.md. An override that names no database or parcel's dev
  database `parcel` (the tests drop old schemas in the database they are
  given), or whose query sets `host`, `hostaddr`, `port` or `dbname` (sqlx
  applies them over the URL, so preflight would check another endpoint), is
  refused with the rule broken and never the value. The service's own
  settings are unset for the run: `DATABASE_URL` otherwise,
  `STORAGE_EMULATOR_HOST`, `GOOGLE_CREDENTIALS`, `APP_ENV`, the proxy
  variables and the like by name, and every exported variable starting
  `AUTH_`, `SLAUTH_`, `GCS_`, `BLOB_` or `PARCEL_` by prefix (parcel builds
  its provider settings' names, `AUTH_<PROVIDER>_*`, at run time).
- `scripts/downstream-check.sh`: the output filter now masks a whole
  `postgres://` or `postgresql://` URL (`postgres://<redacted>`), also one
  with no userinfo and no secret parameter, so the override's host, port and
  database never reach the terminal or a log in a consumer's failure
  message; the masking of other schemes and of secret parameters is unchanged.
- `scripts/downstream-check.sh`: tapper's run sets
  `TAPPER_RS_TEST_GCS_EMULATOR_URL` (tapper plan 017 C-3 makes its GCS tests
  read it, loopback only, no default) to `http://127.0.0.1:4443`, or passes the
  caller's value through (also when set to empty, which tapper's own tests
  then refuse loudly), and preflight checks the address it names. A tapper
  ref that does not read it yet ignores it.

### Fixed

- `stridelabs-auth`: **an empty key set is a failed fetch** (lumen plan 003
  S1d). A JWKS response that parses with zero entries in `keys`
  (`{"keys": []}`) was cached as the issuer's set: on a cold cache the first
  token got `UnknownKid` (a 401, a sign-out) and those inside the refetch
  floor `UnseenKid`, and on a warm cache an empty refresh replaced a good set
  and refused every token until the next fetch. Now it fails the attempt
  with `AuthError::Jwks("response has no keys")`, through the same path as an
  unparseable body: the previous set keeps serving until its TTL, the failure
  counts toward the backoff, every lookup waiting on that attempt gets the
  error, and no kid is remembered as seen from it. Consumers see a key-set
  error (their `Jwks` mapping, a 5xx) instead of `UnknownKid`/`UnseenKid`.
  Only zero entries counts as empty: a set whose keys are all unusable is
  still served (and, under `report_unusable_keys`, is `UnusableKey`, as
  before). No API change.

## [0.10.0] - 2026-10-23

A joint release: tapper plan 016 C-1 (stridelabs-auth's opt-in strict screen, `Audience::IfPresent`, `Verifier::with_cache`
and unusable-key reporting), C-2 (stridelabs-gcp's sanitised errors, offline key validation and opt-in crc32c) and C-3
(a new crate, `stridelabs-postgres`; the `stridelabs-config` lookup seam and `file` feature; `stridelabs-testing`'s
local-only guards) with its `neon_pooler_url` follow-up, lumen plan 002's new crate, `stridelabs-perplexity`, and a
lock-only advisory fix (ctutils 0.4.5, RUSTSEC-2026-0385). **Changed:** `stridelabs-gcp`'s error payloads and text (a
test that asserts the old text fails; match on variants, never on text), `stridelabs-config`'s `file` feature (default
on, so no change for a current user) and the workspace's trimmed `sqlx` entry (no consumer-visible change).
Everything else is additive or opt-in. Downstream-checked against each merge: tapper and lumen (informational) and
slaudio (informational) passed, with tapper's one expected premise-test failure from C-2
(`google_credentials::tests::only_a_service_account_key_is_accepted` asserts v0.9.0's credential-type leak), which
tapper updates on adoption; parcel is not covered. Details below.

### Added

- `stridelabs-auth`: four opt-in additions for a resource server that keeps
  claim rules of its own (tapper plan 016 C-1, so that tapper-rs can replace
  its hand-written verifier with this crate's at C-5, keeping its behaviour).
  A consumer that uses none of them sees no change: v0.9.0's tests pass
  unchanged, and `for_issuer`, now built on `with_cache`, builds the same
  verifier.
  - **`Audience::IfPresent(String)`**, on the `#[non_exhaustive]` enum: an
    absent `aud` passes; a string must equal the value; an array must
    contain it and hold nothing but strings. A malformed `aud` (a number, a
    boolean, an object, `null`, an array holding a non-string) is refused,
    "audience is not accepted". jsonwebtoken lets an `aud` it cannot parse
    through when `aud` is not required, so the crate checks `IfPresent`
    itself, after the signature and the other claims; `exp` and `iss` stay
    required. Safe only when the issuer names the audience in every token
    it mints for another service (Hydra stamps an empty array, which this
    refuses, when a client asked for none).
  - **`Verifier::with_cache(checks, cache: JwksCache)`**: `for_issuer` over a
    cache the consumer built, so its TTL, its refetch interval (tapper's
    suites run with none), its HTTP client and `report_unusable_keys` are the
    consumer's. Pairing the cache with the rules is then the caller's job.
    `config()` is synthesized as for `for_issuer`, from the cache's URL
    (under `IfPresent`, its audience is the value).
  - **`JwksCache::report_unusable_keys(bool)`** (off by default: v0.9.0's
    behaviour) and `reports_unusable_keys()`. On, a set inside its TTL
    answers a lookup for a kid it holds only if some key under the kid can
    verify RS256: an RSA key whose `alg`, `use` and `key_ops`, where present,
    allow it, and whose `n` and `e` are what aws-lc-rs, the RS256 verifier,
    accepts: unpadded base64url, minimal big-endian octets (no leading zero
    octet, as RFC 7518 also requires), an odd `e` of 2 to 33 bits (so 3 or
    more: not 0 or 1), and an odd modulus of 2048 to 8192 bits. Otherwise the
    lookup is **`AuthError::UnusableKey(UnusableReason)`**, a new variant on
    the `#[non_exhaustive]` `AuthError` that carries no kid (the crate's
    error rule) but the first key's reason: `UnusableReason`
    (`#[non_exhaustive]`, `Copy`) is `NotRsa`, `MalformedComponents` (`n` or
    `e` missing, not a string, not unpadded base64url, or not one aws-lc-rs
    accepts), `ModulusSize`, `Alg`, `Use` or `KeyOps`, each a fixed phrase.
    Such a kid
    takes the unknown kid's refetch floor: **one refetch per floor**, so a
    usable key the issuer rotates in under it is picked up, and from memory
    inside the floor, so a persistently broken key costs one fetch per floor,
    not one per request. The verdicts are worked out once for every fetched
    set, on the fetch's task, never under the cache's lock, and the setting
    is read at each lookup, so it holds from the moment it is set, for a set
    fetched before it included. A verifier over such a
    cache selects only a key that passes the same checks; the default
    selection is unchanged (a kid with no fit key is `UnknownKid`, a fit key
    that cannot be built is `Jwks`). The `http` bridge maps `UnusableKey`
    where it maps `Jwks`, to `AppError::Internal` (a 500), and
    stridelabs-mcp's `From<AuthError> for VerifyError` to `Unavailable`
    (neither path can produce it today: both verifiers build their own
    caches).

    **Consumers that map `Jwks` to 503 should map `UnusableKey` to 503
    too**: the issuer published that kid, so a broken key entry is the
    issuer's defect, and a 401 would sign out every holder of a valid token
    until the set's next refresh. A `match` on `AuthError` already has a
    wildcard arm (it is `#[non_exhaustive]` since v0.9.0), so nothing breaks
    to compile; without the arm, `UnusableKey` goes wherever the wildcard
    sends it (a 401 in lumen's mapping), and only from a cache that turned
    reporting on.
  - **`Verifier::screen(ScreenPolicy)`** and `screen_policy()`, with a new
    public `screen` module: `ScreenPolicy` (`#[non_exhaustive]`, also at the
    crate root), `MAX_TOKEN_BYTES` (16 KiB) and `MAX_KID_BYTES` (256).
    `ScreenPolicy::Basic`, the default, is what every verifier has always
    checked before the key lookup: a header that parses and carries a `kid`.
    `ScreenPolicy::Strict` also refuses, still before the lookup (so with no
    fetch, and never with `Jwks`, `UnseenKid` or `UnusableKey` while the
    issuer is down): a token over 16 KiB, not exactly three non-empty
    unpadded-base64url segments, with a header jsonwebtoken cannot parse, or
    a payload that is not UTF-8 throughout or not a JSON object
    (`MalformedToken`); a `crit` header parameter in any form, `[]` and
    `null` included (`InvalidToken`); an
    `alg` other than RS256 (`InvalidToken("algorithm is not accepted")`); a
    missing or empty `kid` (`MissingKid`); a `kid` over 256 bytes
    (`InvalidToken("key id is too long")`). Every refusal is a 401 in the
    house mappings, and its reason (a fixed phrase) is logged at `debug`.
    Ported from tapper-rs's pre-lookup screen, with its test cases, so
    tapper's swap keeps its behaviour.
  - **`screen::check(token, ScreenPolicy) -> Result<(), AuthError>`**: the
    screen alone, with no verifier, no key and no I/O, from the same code a
    verifier with that policy runs before its key lookup, so the two cannot
    drift (a test holds them to the same answer on every case of the strict
    table, under both policies). For a consumer that answers some tokens
    with no verifier at hand (lumen-rust's review: its unconfigured-issuer
    path refuses a malformed token with a 401 before it answers 503). It is
    reached through the public `screen` module, not re-exported at the
    crate root, where a bare `check` would not say what it checks.
  - `Verifier`'s `Debug` adds its `screen`, and `JwksCache`'s its
    `report_unusable_keys`.
  - `base64` (0.22, jsonwebtoken's own) is a direct dependency now, for the
    screen, `IfPresent` and the key checks: `Cargo.lock` gains the edge, and
    no crate joins the graph.
  - Downstream: `scripts/downstream-check.sh` passed for tapper (required),
    and for lumen, an informational case (#49), against lumen `0e05591`
    (785 passed, 0 failed, 11 ignored). lumen-rs's own pin (rev `6d08a4a`)
    uses `for_issuer`, which is unchanged. parcel (through stridelabs-mcp)
    is not covered by the script; the paths it uses are unchanged.
- `stridelabs-gcp`: offline validation of a service-account key (tapper
  plan 016 C-2; slaudio-rust's follow-up 4, which it handed to tapper). With
  `service-account-key`, the key type is public, `auth::ServiceAccountKey`
  (also at the crate root), so that a service can refuse to start on a key
  that could never mint a token instead of failing its first request.
  Building a provider is unchanged: no constructor calls `validate`.
  - `ServiceAccountKey::from_json(json)` parses exactly as
    `TokenProvider::from_service_account_json` does, with the same errors
    (`InvalidCredentials` from `credentials JSON`, naming the field;
    `Unsupported` for another `type`).
  - `validate()` checks offline, with nothing sent, what building a
    provider does not. **It signs**: one throwaway RS256 assertion, signed
    as a token request signs it and dropped (its `iat` is 0, so it expired
    in 1970). This catches an RSA public key, or a private key missing
    fields, whose PEM parses but which jsonwebtoken refuses when it signs.
    **`token_uri` is safe to post the assertion to**: `https`, or `http`
    only to the literal `localhost`, `127.0.0.0/8` or `::1`, and no
    userinfo, query or fragment (empty ones included).
  - A refusal is a `KeyDefect` (`#[non_exhaustive]`, `Copy`): `CannotSign`,
    `TokenUriUnparseable`, `TokenUriScheme`, `TokenUriPlainHttp` or
    `TokenUriCarriesExtras`, each a fixed phrase naming the field, never key
    material or any part of the URL.
  - `ServiceAccountKey`'s `Debug` prints the `client_email` and the
    `token_uri`'s origin (`scheme://host[:port]`), never the key, its id or
    the URI's path.
  - Ported from tapper-rs's startup check (`google_credentials.rs`), with
    its cases; tapper replaces its own with this at plan 016 C-5.
- `stridelabs-gcp`: an opt-in CRC32C on uploads (tapper plan 016 C-2;
  slaudio-rust's handoff, and a lumen plan-002 candidate):
  `UploadOptions::with_crc32c(u32)` and the public field
  `crc32c: Option<u32>` on the `#[non_exhaustive]` struct. The caller
  computes the CRC-32C (Castagnoli) of the bytes; the crate adds no
  dependency. GCS refuses a mismatch with a `400` (`StorageError::Status`,
  never retried) and writes nothing. It is sent base64 of its big-endian
  bytes, the way Google's "Data validation and change detection" page
  documents for the JSON API: **alone**, the media upload stays a media
  upload and gains `X-Goog-Hash: crc32c=<b64>`; **with any other option**,
  the multipart upload's metadata carries `"crc32c":"<b64>"`, last, and no
  header. Without it, every request is byte for byte what it was.
  - **Verification, exactly** (against fake-gcs-server 1.56.1, never real
    GCS): the **multipart** form is **verified** (a wrong value is a `400`
    and nothing is written; the right one is stored). The **media-upload
    header** form is **UNVERIFIED**: fake-gcs-server never reads
    `X-Goog-Hash` on a media upload and stores the object whatever it says,
    so only Google's documentation says real GCS checks it. A service that
    needs the checksum enforced should not rely on the header form until it
    is checked against real GCS.
  - The wire forms are pinned by wiremock tests; the emulator check is the
    `#[ignore]`d `crc32c_against_fake_gcs_server` (`tests/storage.rs`, run
    with `STRIDELABS_FAKE_GCS_URL`), which also pins the emulator's
    blindness to the header so that it fails the day that changes.
- lumen-rs (rev `6d08a4a`) and parcel are not covered by
  `scripts/downstream-check.sh`. lumen-rs uses `TokenProvider`, `GcsClient`
  and the `vertex` module, whose requests are unchanged on the wire unless
  `with_crc32c` is set (its error text changes, below); parcel has no
  stridelabs-gcp dependency today.
- `stridelabs-postgres`, a new crate (tapper plan 016 C-3): Postgres
  connection hygiene on sqlx, promoted from tapper-rs's `db.rs` (itself
  hardened from lumen-rs's copy) and checked against slaudio's
  `parse_connect_options`, so tapper (at C-5) and lumen can replace their
  copies with it. lumen-rust asked that it keep lumen-rs's semantics, so that
  lumen's swap is a deletion; it does, with the two differences listed last.
  sqlx is a required dependency with `postgres` and `runtime-tokio` only (no
  `macros`, no `time`, no `migrate`) and **no TLS feature**: the consumer's
  own sqlx picks the stack (tapper, lumen and slaudio all name
  `tls-rustls-aws-lc-rs`), as stridelabs-auth and stridelabs-gcp leave the
  HTTP client's TLS to the consumer. A TLS feature here would put a second
  rustls provider next to a `tls-rustls-ring` consumer's, and would unify
  into stridelabs-testing's TLS-free pool in this workspace's all-features
  lane. A new CI guard, "Guard: stridelabs-postgres picks no TLS stack", holds
  that (no rustls, ring, aws-lc-rs, native TLS, `sqlx-macros` or `time` in its
  graph).
  - **`connect_options(url) -> Result<PgConnectOptions, UrlRefusal>`**: the
    URL checked before sqlx parses it. A query-parameter allow-list
    (`SUPPORTED_URL_PARAMETERS`; `IGNORED_URL_PARAMETERS` accepted, validated
    and not passed on), because sqlx's parser logs an
    unrecognised parameter with its value and its errors quote a bad value; a
    `search_path` in the startup options refused, read with PostgreSQL's own
    `pg_split_opts` tokenisation (the vertical tab included) and `getopt`
    rules, names compared exactly (so `myapp.search_path_hint` passes); a
    percent-decoded NUL refused in every startup and authentication field,
    in what sqlx parsed (its `PG*` defaults included) and in `PGUSER`,
    `PGDATABASE`, `PGAPPNAME`, `PGOPTIONS`, `PGHOST`, `PGHOSTADDR` and
    `PGPASSWORD`, read through a private lookup seam so the tests set no
    variable; and no password file ever read (an explicitly empty password
    when nothing supplies one). **`UrlRefusal`** (`#[non_exhaustive]`:
    `NotAUrl`, `Scheme`, `UnsupportedParameters { named, unnamed }`,
    `InvalidValue`, `Unparseable`, `SearchPath`, `NulByte`) never prints a
    value, and names only parameters from the crate's own lists (lumen's
    requirement); an unknown name is counted, never printed.
  - **`error_summary(&sqlx::Error) -> ErrorSummary`**: a SQLSTATE (five
    ASCII digits or capitals, else not printed) and a fixed description, or
    a fixed class name; never the server's message. Its `Debug` is its
    `Display`.
  - **`lazy_pool(options, PoolSettings)`**: the pool, built from checked
    options without connecting. `PoolSettings` (`#[non_exhaustive]`, `Copy`)
    carries `max_connections`, `acquire_timeout`, `idle_timeout`,
    `max_lifetime` and `test_before_acquire`, with sqlx 0.9's own defaults
    pinned and `with_*` setters; `pool_options()` hands sqlx's
    `PgPoolOptions` to a consumer that needs more (slaudio's
    `test_before_acquire` and lifetimes fit it).
  - **`neon_pooler(&PgConnectOptions) -> Option<PoolerRef>`**: whether the
    options reach Neon's pooled endpoint, by a `-pooler` host label (as is or
    percent-decoded) or by `endpoint=…-pooler` / `project=…-pooler` in the
    startup options (`options=` or `PGOPTIONS`), read through both Neon's and
    PostgreSQL's tokenisers. Detection only: refusing stays with the
    consumer (tapper's and lumen's migrate commands refuse).
    `neon_pooler_host(&str)` is the host half, for a consumer that also
    refuses a pooler named where sqlx would not dial it (an authority
    redirected by `?host=`). `PoolerRef` (`Host`, `Endpoint`) holds only a
    label or an endpoint id (letters, digits, `-`) or a fixed placeholder.
  - **`neon_pooler_url(url, &PgConnectOptions) -> Option<PoolerRef>`**
    (lumen-rust's consumer check, so tapper's and lumen's migrate refusal
    becomes a deletion): `neon_pooler`, plus every host the URL names that
    sqlx will not dial, so an AMBIGUOUS URL is detected too: a `-pooler`
    label in the authority (as is or percent-decoded) while `?host=` or
    `?hostaddr=` redirects the connection, or in a `host` value a later one
    overrides. The dialled host is reported first, then the URL's other
    hosts, then a startup-options endpoint, as both apps do. It takes the
    options `connect_options(url)` returned rather than parsing them again,
    so the refusal is one `match` after the `connect_options` call both
    apps already make. Both apps also read `hostaddr` values, which
    `connect_options` only accepts as IP addresses (no label), so this one
    reads `host` values only; a test pins that premise. It is strictly
    broader than either app's check, never narrower: a `host` value is
    percent-decoded once more before its labels are read (so a doubly
    encoded `ep-x%252Dpooler` is detected, where both apps accept it), and
    the startup options are also read with PostgreSQL's tokeniser (lumen
    `0e05591` reads Neon's only; tapper reads both). A URL either app
    accepts can therefore be refused after the swap, never the reverse.
  - **`LOG_CAPS`**: `sqlx_core::pool`, `sqlx_postgres::options`,
    `sqlx::postgres::notice` and `sqlx_postgres::message`, each `OFF`, as
    plain `(target, LevelFilter)` pairs to fold into a
    stridelabs-observability `TargetCaps` (or any other filter), rather than
    a `TargetCaps` behind a feature: the crate then depends on no logging
    setup. The first two log a raw error and a URL parameter's value; the
    notice target logs every server notice verbatim from a connection that
    succeeds (an `application_name` past 63 bytes, which `connect_options`
    accepts, is truncated with a NOTICE quoting it: found by the astra
    review); the message target logs a misbehaving peer's `CopyDone` body.
    tapper's own `log_caps()` caps only the first two, so its C-5 swap
    gains the other two. The tests pin the first three to where sqlx 0.9
    logs, the notice one with a real truncation notice from the compose
    Postgres; every other sqlx 0.9 log call is listed as uncapped, with the
    reason, in `LOG_CAPS`' docs.
  - Differences from lumen-rs's copy: the pooler check reads the startup
    options through PostgreSQL's tokeniser as well as Neon's (tapper's plan
    015 C-3 hardening; strictly broader), and `sqlx::Error::Migrate` renders
    as `database client error` rather than `migration error` (the crate does
    not turn on sqlx's `migrate`, so it cannot name the variant; neither app
    passes one to `error_summary`). Neither app's URL normaliser moves here:
    `channel_binding` is refused by name, as both apps' allow-lists refuse
    it after normalising.
  - lumen-rs (rev `6d08a4a`) and parcel are not covered by
    `scripts/downstream-check.sh`; neither uses the crate yet. The script's
    crate list (and CI's limen patch) gains `postgres`.
- `stridelabs-config` (tapper plan 016 C-3; lumen's plan-002 candidates
  adopt the seam): the lookup seam is public. **`env_or_from`,
  `env_parse_from` and `parse_string_array_from`** take an
  `impl Fn(&str) -> Option<String>`, the seam a consumer's
  `Config::from_lookup` builds on, and their errors are **value-free**: an
  `EnvError` from `env_parse_from` or `parse_string_array_from` names the
  variable and a fixed reason (the new `VALUE_DOES_NOT_PARSE` and
  `NOT_A_STRING_ARRAY`), never the value or the parser's text (serde_json's
  `invalid type: string "…"`, a `FromStr` error that echoes its input), so
  they are safe for a secret and for printed startup refusals.
  `env_parse_from` asks nothing of `T::Err` (it never renders it). The plain
  `env_or`, `env_parse` and `parse_string_array` are unchanged, parser text
  included. No `Refusals` type: `Errors` already accumulates, and its rustdoc
  and the README now show it collecting startup refusals. lumen-rs (rev
  `6d08a4a`) and parcel are not covered by `scripts/downstream-check.sh`.
- `stridelabs-config`: a **`file` feature, on by default**, gating
  `load_yaml`, `load_json`, `Loaded` and `FileError` (tapper plan 016 C-3).
  A consumer that names the crate with no `features` keeps everything; one
  that sets `default-features = false` gets the env helpers and `Errors`
  with no `yaml_serde`, `libyaml-rs`, `serde_path_to_error` or `serde` in
  its graph (tapper, which dropped the crate at its plan 015 C-2, would
  re-adopt it only without YAML in its graph). A new CI guard, "Guard:
  stridelabs-config without `file` pulls no YAML", holds that, and the
  per-feature lane builds and lints the crate with and without it.
- `stridelabs-testing`: **`require_local_url(var)`**, unconditional (tapper
  plan 016 C-3, modelled on tapper-rs's `tests/test_redis` reader and
  slaudio's harness guards): the URL in the suite's own variable, which must
  be set (no default: a default is the dev stack's server) and whose host,
  and every `host`/`hostaddr` query parameter, must be loopback
  (`localhost`, `127.0.0.0/8`, `::1`); otherwise a panic naming the
  variable, the problem and the fix, never the value. With feature `redis`,
  **`require_local_redis_url(var, RedisDbPolicy)`** adds that redis-rs can
  open the URL and that its database is one the policy allows:
  **`RedisDbPolicy`** (`#[non_exhaustive]`) is `AllowZero` by default
  (slaudio's suites share database 0 under a key prefix) or the opt-in
  `RefuseZero`, which refuses database 0 named or implied (tapper's suites
  seed windows and budgets the dev stack would read). Neither connects.
  lumen-rs (rev `6d08a4a`) and parcel are not covered by
  `scripts/downstream-check.sh`.

- `stridelabs-perplexity`, a new crate (lumen plan 002 W4b-1): a
  policy-free web-search client for Perplexity's Agent API on the consumer's
  `reqwest::Client`, which it never retries or logs through. Perplexity
  retired Sonar chat completions on 2026-09-27; lumen's `web_search` moves to
  it first, and tapper can adopt it in place of its own Sonar parse. No
  features: its `reqwest` has none, so it picks no TLS stack.
  - `PerplexityClient::builder(http, api_key)` → `PerplexityClientBuilder`
    (`base_url`, `timeout` (30 s), `max_response_bytes` (2 MiB),
    `max_input_chars` (2,000), `effort` (`Effort::Fast`; also `Low`,
    `Medium`, `High`, `XHigh`, `#[non_exhaustive]`), `max_output_tokens`
    (unset)) → `build()`, refusing a base URL that is not `https://` (plain
    `http://` only to a loopback IP literal, the test seam) or carries
    userinfo, a query or a fragment (`BuildError::InvalidBaseUrl`), a key
    that is empty after trimming or no header can carry
    (`EmptyApiKey`, `InvalidApiKey`), and a zero timeout or bound
    (`ZeroTimeout`, `ZeroMaxResponseBytes`, `ZeroMaxInputChars`,
    `ZeroMaxOutputTokens`). A base URL's path prefix is kept and a trailing
    slash tolerated. The client must follow no redirects and must not retry,
    and should decode no body (a decoder drops `Content-Length`, defeating
    the pre-check) and use no proxy it did not choose; its own timeout does
    not matter.
  - `search(&str)` sends one `POST {base}/v1/agent` with exactly `{effort,
    input, max_output_tokens?}` and `Authorization: Bearer <key>` (trimmed,
    verbatim, marked sensitive), the input bound checked first
    (`PerplexityError::InputTooLong`). The status is classified before any
    body is read: `408`, `429` and `500`–`999` are `Unavailable(Status)`,
    every other non-`2xx` (a `3xx` included) `Rejected { status }`; a
    timeout is `Unavailable(Timeout(Phase))` and a transport failure
    `Unavailable(Transport { phase, io })`, `Phase` being `Connect`,
    `Headers` or `Body`. The body is read chunk by chunk under the bound
    (refused unread on a `Content-Length` over it), must be UTF-8 throughout,
    and only a `completed` response is an answer: any other status, or a
    `message` item's own `status` other than `completed`, is `Incomplete {
    status: ResponseStatus }`, with no partial text returned, and a
    top-level `status` that comes twice is refused whatever its order.
    `Malformed(MalformedReason)` is `BodyTooLarge`, `NotUtf8`, `NotJson`,
    `MissingStatus`, `DuplicateStatus` or `MissingAnswer`.
  - The answer is a faithful `SearchAnswer` (`#[non_exhaustive]`): `text`
    (every `output_text` of every assistant `message` item, concatenated; a
    message whose `role` is present and not `assistant`, such as an echo of
    the query, contributes none), `results`
    (every entry of every `search_results` item, in order, `SearchResult {
    id, url, title?, date?, last_updated?, snippet?, source? }`, ids as given
    so a citation `[id]` resolves across batches; an entry with no integer
    `id` or no `url` is skipped, a non-array `results` gives nothing),
    `status`, and `usage: Option<Usage>` (token counts, `total_cost`,
    `currency`; a malformed `usage` never fails the answer). It is read
    straight into those fields by serde visitors, everything else skipped
    with `IgnoredAny`, so the response bound is also the memory bound; each
    value read is captured first as a borrowed `RawValue` (serde_json's
    `raw_value` feature, no new crate), so a number serde_json cannot
    represent (`1e400`) is left out at its own position instead of failing
    the body. `SearchAnswer::from_json(&[u8])` runs the same parse on a body
    the caller has (a recorded response, a consumer's formatting tests).
    `SearchAnswer::sources(max, title_chars)` is an optional display helper:
    http(s) URLs only, no userinfo, the first of a duplicate URL, capped,
    titles cut at a char boundary, `www.` dropped from the domain; `results`
    is untouched.
  - No error keeps a `reqwest::Error`, a body, the key or the input, and
    every `source()` is `None`; the `Debug` of the client, the builder and
    every result type shows lengths and counts, never the key, the text,
    titles or URLs. Canary tests cover body echoes (the response's `error`
    and an undocumented status string included), malformed headers, URL
    credentials, an HTTP/2 GOAWAY's debug data, and every `Debug`; raw TCP
    servers cover the stream bounds. The fixture
    `tests/fixtures/agent_response.json` is one recorded billed response.

### Changed

- `stridelabs-gcp` (error payloads and text; **no variant changes shape**):
  upstream text is reduced **when an error is built**, so the derived
  `Debug` (`?error`) holds no more than `Display` shows. An endorsed fix,
  slaudio-rust's follow-ups 1, 2 and 5 (handed to tapper; tapper plan 016
  C-2), whose workarounds tapper-rs carries in `google_errors.rs` and
  `google_credentials.rs`.
  - **`error.status`** (`StorageError::Status` and `VertexError::Status`,
    `google_status`; one envelope reader serves GCS and Vertex) is one of
    google.rpc.Code's 17 names or `"other"`. Before, any
    `[A-Za-z0-9_.-]{1,64}` passed through, and anything else was `None`; an
    empty or non-string `status` is still `None`.
  - **The OAuth `error`** (`GcpAuthError::Status`, `detail`) is one of
    RFC 6749's six token-endpoint codes or `access_denied`, `server_error`
    or `temporarily_unavailable`, `"other"` for any other non-empty `error`
    string (one that is not a plain code was `""` before; an unlisted code,
    Google's `invalid_rapt` for example, reads `other`), or `""` when the
    body has none. `Display`: `…answered HTTP 400: invalid_grant` or
    `…: other`.
  - **A token endpoint** (`GcpAuthError::{Request, Status,
    InvalidResponse}`, `endpoint`) is its origin, `scheme://host[:port]`,
    no longer `…/path`: a service-account key's `token_uri` is used
    verbatim, and a broker's path can hold a secret. The port stays: it is
    a number, and it tells a mock or a non-default port apart.
  - **An unsupported credential `type`** (`GcpAuthError::Unsupported`) is
    named only when google-auth knows it (`credential type
    "external_account" in …`); any other is `credential type other in …`.
    Before, any plain `[a-z_]{1,64}` name was quoted, and anything else
    shown as `<unrecognized>`.
  - **A credential file that cannot be read** (`InvalidCredentials`,
    `reason`) is a fixed phrase for its `io::ErrorKind`: `the file does not
    exist`, `the file cannot be read: permission denied`, `…: it is a
    directory`, or `the file cannot be read`. Before, any kind but not-found
    appended the `io::Error`'s own text (`Permission denied (os error 13)`),
    which an `AdcEnvironment` of a consumer's own can fill with anything.
  - **`TokenOptions`' `Debug`** shows the token endpoint
    (`default_token_uri`) as its origin, `scheme://host[:port]`, as the
    errors do, no longer `…/path`. Base URLs keep their path in `Debug`:
    `TokenOptions`' metadata base URL, `GcsClient`'s and `VertexClient`'s,
    since a base URL is configuration, not a token path.
  - Mapping: match on the variant and its fields, never on the text. A
    consumer with an allow-list of its own (tapper-rs's `google_errors.rs`)
    keeps working; `"other"` is never on any list. To see a full token
    endpoint, log it from your own configuration.
  - **Heads-up, lumen-rs and slaudio:** a test that asserts the old text
    fails: an endpoint with its path, a plain unlisted code passed through,
    a quoted unknown `type`, or `<unrecognized>`. The crate's own tests that
    asserted those were updated for the same reason.
  - Errors a consumer constructs itself (the variants are plain struct and
    tuple variants) hold what it puts in them.
- `stridelabs-gcp` (documentation only; no behaviour change): **an
  `authorized_user` token is not limited to the scopes the provider asked
  for.** The refresh-token grant sends no `scope`, so every token carries
  whatever the gcloud login was granted (typically `cloud-platform`). Now
  stated loudly in the `auth` module docs, `from_authorized_user_json`,
  `from_environment`, `CredentialKind::AuthorizedUser` and the README: a
  service whose security depends on its scopes must refuse
  `CredentialKind::AuthorizedUser` itself. Unchanged on purpose: imgmcp's
  local development runs on it (slaudio-rust's follow-up 3). The same docs
  say that **the metadata server is no scope boundary by itself** either:
  the crate sends `?scopes=` without `enforce_scopes=true`, so Compute
  Engine answers with every scope the instance was given unless the
  instance or project sets `enable-access-token-enforce-scopes` to `true`.
  The request is unchanged (`enforce_scopes=true` would make a request for
  scopes outside the instance's an error, a decision of its own).
- `stridelabs-testing` (manifest only; no behaviour or graph change): `url`
  is a non-optional dependency (wiremock already puts it in every
  consumer's test graph), so the `postgres` and `redis` features no longer
  name `dep:url`. The workspace's `sqlx` entry is now the driver and the
  runtime only, and stridelabs-testing names `uuid`, `time`, `migrate` and
  `macros` itself, so its sqlx is built exactly as before while
  stridelabs-postgres's stays minimal.

### Fixed

- `Cargo.lock`: ctutils 0.4.3 → 0.4.5, reached through sha2 → digest in stridelabs-auth (RUSTSEC-2026-0385), so `cargo audit`
  is green. Lock-only; no manifest or code change.

## [0.9.0] - 2026-10-22

A joint release: slaudio's port gaps and their curation (plan 024's #44, plan 025's L1 #48 and L2 #50), lumen's S1
additions (#46), a lock-only advisory fix (#47), downstream-check's lumen case (#49), and a new crate,
`stridelabs-inworld` (slaudio plan 022 L3b, to lumen 001 §6.3, reviewed by lumen). **BREAKING (behaviour, security):** a JWKS key set is never served past its TTL, and `AuthError` is
`#[non_exhaustive]` with a new `UnseenKid` verdict (a `match` needs a wildcard arm; map `UnseenKid` where `Jwks`
goes). Everything else is additive or opt-in: lumen's `Verifier::for_issuer`/`ClaimChecks`, `RedisHandle::eval`,
`TargetCaps` and `redact_url`; the SSRF fetch's feed options; `TokenProvider::invalidate`; GCS `ObjectNamePolicy`
and a `retry` module; the JWKS body cap. Downstream-checked against imgmcp, limen and slaudio (and lumen's suite
against L2). Details below.

### Added

- `stridelabs-inworld`, a new crate (slaudio plan 022 L3b, to lumen plan 001
  §6.3's spec): a policy-free Inworld text-to-speech client on the
  consumer's `reqwest::Client`, which it never retries, chunks or logs
  through. First consumers: slaudio's Rust port, then tapper and lumen.
  - `InworldClient::builder(http, api_key)` → `InworldClientBuilder`
    (`base_url`, `timeout`, `max_response_bytes`, `max_audio_bytes`,
    `max_text_chars`, `mp3_check`) → `build()`, refusing a base URL that is
    not `https://` (plain `http://` only to a loopback IP literal, the test
    seam) or carries userinfo, a query or a fragment
    (`BuildError::InvalidBaseUrl`), and a zero timeout
    (`BuildError::ZeroTimeout`). The client must follow no redirects and must
    not retry (reqwest 0.13's default replays a POST refused with
    `REFUSED_STREAM`), and should decode no body (a decoder drops
    `Content-Length`, defeating the pre-check) and use no proxy it did not
    choose; its own timeout does not matter.
  - `synthesize(&SynthesisRequest)` sends one `POST {base}/tts/v1/voice`
    with exactly `{text, voiceId, modelId, language?, deliveryMode?,
    audioConfig{audioEncoding, bitRate?, speakingRate?, sampleRateHertz?}}`,
    every unset option omitted, and `Authorization: Basic <key>` (trimmed,
    verbatim, marked sensitive). It returns a `Synthesis` (`#[non_exhaustive]`:
    the audio as `Bytes`, and `Usage` with `processed_characters_count` and
    `model_id` as `Option`s, an ill-typed field `None`). The body is read
    straight into those fields, never built as a `serde_json::Value`: the top
    level must be an object, everything else is skipped with `IgnoredAny`,
    so the 4 MiB response bound is also the memory bound, and a repeated key
    keeps its last value. `Usage`'s `Debug`
    shows the model id as its length only (`Some(<12 chars>)`): it is the
    provider's string, and could echo the request.
  - `InworldBounds` (`#[non_exhaustive]`, `DEFAULT`, lumen's numbers): a
    15 s whole-exchange timeout set on each request; a 4 MiB response,
    refused unread past its `Content-Length` and otherwise cut chunk by
    chunk, never buffered whole (at most 64 KiB reserved up front, whatever
    the declared length); 2 MiB of audio, checked on the base64
    length before decoding and on the decoded length; 600 characters of
    text, before anything is sent.
  - Strict standard base64, then the MP3 sniff, on by default: exactly
    §6.3's `starts_with(b"ID3") || (len >= 2 && b[0] == 0xFF && (b[1] &
    0xE0) == 0xE0)`, so a 2-byte frame-sync clip passes (slaudio's Python
    `mp3.py` also refuses anything under 3 bytes); only zero bytes are
    `EmptyAudio`.
  - `InworldError` (`#[non_exhaustive]`, `Clone`, `PartialEq`, `Eq`,
    `is_retryable()`): `Unavailable { reason, cause, .. }` for a `408`, a
    `429`, any status of `500` or more (`600`–`999` included), a timeout, or
    a failed or broken connection (`UnavailableReason`: `Status`,
    `TimedOut`, `Connect`, `Transport`), the only retryable class;
    `Rejected { status, .. }` for any other non-`2xx`, every `3xx` included.
    Both are `#[non_exhaustive]` struct variants, so a field (an RPC code)
    can join them without breaking a caller; `Malformed(MalformedReason)`
    for a `2xx` that is too large, not UTF-8, not a JSON object, without a string
    `audioContent`, not base64, empty, over the audio bound or not
    MP3-shaped; `UnusableKey`, `TextTooLong { chars, max }` and
    `SpeakingRateNotFinite`, which send nothing. Every `Display` and `Debug`
    is fixed phrases, a status, a count or a `std::io::ErrorKind`, and
    `source()` is always `None`: no error keeps a `reqwest::Error`, whose
    source chain can carry what the peer sent (h2 renders a GOAWAY's debug
    data in both `Display` and `Debug`; `without_url()` strips only the
    URL). A transport failure's `cause` is a `TransportCause` (`Copy`,
    `#[non_exhaustive]`): its `TransportStage` (`Connect`, `Request` or
    `Body`: where the crate was when it failed, so a stall after the headers
    is `Body`, not reqwest's decode label), `timed_out`, and the innermost
    `io::ErrorKind` found by downcasting the chain. Error bodies
    are never read. Canary tests hold the key, the text, a response body,
    the URL, a success's `usage.modelId`, and what a peer puts inside a
    transport failure (a malformed status line, an unparseable header, an
    HTTP/2 GOAWAY's debug data, with a control showing reqwest's own error
    renders it) out of every rendering, and the `Debug`s show neither the
    key, the text, the audio nor the model id.
  - Feature `client-builder` (off by default): `client_builder()`, a
    `reqwest::ClientBuilder` with reqwest's rustls backend (aws-lc-rs),
    `no_proxy()`, `redirect::Policy::none()`, `retry::never()`, and
    `no_gzip()`, `no_brotli()`, `no_deflate()` and `no_zstd()`. Tests prove
    each of the last four properties against a control that lacks it: no
    redirect followed, no `REFUSED_STREAM` replayed, a `gzip` answer's
    `Content-Length` still refused unread, and no proxy used from an
    environment that names one (a child process, so the test never sets a
    variable in its own). Without the feature the crate turns on no reqwest
    feature at all.
  - Its bounds tests include lumen L1.8's four blind spots, the first three
    against a raw TCP server: an endless chunked stream cut at the bound
    before the timeout, a stall after the headers, a declared-oversized
    `Content-Length` that then stalls, and audio of `MAX_AUDIO_BYTES + 2`
    refused before decoding. Also: a chunked body one byte over the bound cut
    by the chunk loop alone; and a body just under the bound that is
    nearly all skipped values, parsed quickly and, on Linux, within a 24 MiB
    peak-RSS growth (a `Value` of it grows about 77 MiB). The raw servers'
    handlers are awaited by every test, so an assertion inside one fails it.
    `Cargo.lock` gains the crate's own entry, and reqwest's entry an `h2`
    edge: the tests' dev-only `reqwest/http2` (h2c, for the GOAWAY canary and
    the retry test) and `gzip` (the decoder test's control), whose crates
    were already locked through wiremock and stridelabs-http's dev-only
    `gzip`.
  - CI lists it in its per-feature lanes, the `cargo-semver-checks` loop
    (new since the baseline tag, so passed over until the next one) and the
    `downstream-limen` `[patch]`, with a guard that its core pulls no TLS at
    all (no rustls, and no `native-tls`, `openssl`, `openssl-sys`,
    `hyper-tls` or `tokio-native-tls`) and that `client-builder` puts rustls
    on aws-lc-rs, never ring and never native TLS;
    `scripts/downstream-check.sh` patches it too.

- `scripts/downstream-check.sh`: an informational `lumen` consumer (the
  `lumen-rs` workspace on lumen's `main`; pass `origin/main` or set
  `DOWNSTREAM_LUMEN_REF`). It never decides the exit. Its preflight needs
  Postgres, Redis (DB other than 0) and fake-gcs-server; the test URLs are
  `LUMEN_RS_TEST_DATABASE_URL` / `_REDIS_URL` / `_GCS_URL`, passed explicitly
  (defaults: lumen's compose) with the service's own settings unset.

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
    status, the URL as `scheme://host[:port]/path` with its query and
    fragment redacted (never userinfo), header names only, and the redirect
    count. `final_url` and `headers` are not client-safe. `impl
    From<FetchResponse> for Fetched`; `fetch_public` is that conversion, and
    `Fetched` is unchanged.
  - `FetchPolicy::with_user_agent(HeaderValue)`: the `User-Agent` sent on
    every hop, cross-host redirects included. Trusted configuration, never a
    secret.
  - `FetchPolicy::with_accepted_statuses(AcceptedStatuses)`
    (`#[non_exhaustive]`): `OkOnly` (default, `== 200`) or `AnySuccess`
    (any 2xx). A 3xx, a `304` included, is a redirect as before.
  - New feature `ssrf-decompress` (`["ssrf", "dep:flate2", "tokio/rt"]`):
    `FetchPolicy::with_decompression(Decompression)` (`#[non_exhaustive]`;
    `Off` by default, `GzipDeflate`). Under `GzipDeflate` the request sends
    `Accept-Encoding: gzip, deflate`; a response coded with exactly one of
    `gzip`, `x-gzip` or `deflate` (identity tokens aside, case-insensitive)
    is decoded, and anything else coded is refused as before. Decoding is
    flate2's: gzip with `MultiGzDecoder` (every member, back to back),
    deflate with `ZlibDecoder`, or as raw deflate when the body has no zlib
    header (a mislabelled `deflate`, as browsers accept). The wire bytes are
    capped at `max_bytes + max_bytes / 8 + 4096` (declared and streamed) and
    the decoded bytes at `max_bytes` (`TooLarge`); neither body buffer's
    capacity passes its cap, and both are reserved fallibly (a refused
    reservation is `FetchFailed`). The decode runs in bounded steps (at most
    16 KiB in and 32 KiB out each, so thousands of tiny gzip members are
    many short steps) that yield between them, with the fetch's deadline
    checked before each step and on every answer: past it, any outcome (a
    body, an empty one, `TooLarge`, a corruption) is `TimedOut`. An empty
    coded body is an empty body. Corrupt or truncated input, or anything
    after a gzip member that is not another member, is `FetchFailed`, never
    a partial body. The library's tests cover multi-member gzip, thousands
    of tiny members, zlib, raw deflate, a bomb, truncation and the deadline.
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
- `stridelabs-gcp`: `ObjectNamePolicy` (`#[non_exhaustive]`, `Default` =
  `Strict`), `GcsClient::with_object_name_policy` / `object_name_policy()`
  and `public_url_with(bucket, object, policy)`. `Strict` is v0.8.0's name
  check everywhere, and the free `public_url` stays `Strict`. `Literal` is
  GCS's literal addressing, for objects whose names `Strict` refuses and
  that must stay addressable: a transport policy, not validation. Uploads
  send every name (a query value or a JSON string), a download or a delete
  refuses only `""`, `.` and `..` (no URL path segment can carry them;
  nothing is sent and no token fetched), `public_url_with(.., Literal)`
  refuses no object name, and whatever else GCS refuses comes back as its
  `400`. A `Literal` public URL is exact addressing, not a safe URL: a `..`
  segment resolves elsewhere in a normalizing client. Encoding is the same
  under both policies (RFC 3986 unreserved characters literal, everything
  else percent-encoded), pinned by a 31-name table the library's tests own.
- `stridelabs-gcp`: an opt-in retry, `GcsClient::with_retry(RetryPolicy)` /
  `retry_policy()`, in a new public `retry` module (`RetryPolicy` is
  re-exported from `storage` and the crate root). `RetryPolicy`
  (`#[non_exhaustive]`, `Copy`, `PartialEq`; public `initial_delay`,
  `multiplier`, `max_delay`, `deadline`, `max_attempts: Option<u32>`;
  `const` `with_*` setters, `with_max_attempts(n)` among them) has
  `disabled()` (the default: one attempt, as in v0.8.0) and
  `google_default()` (1 s, ×2, 60 s, 120 s, no attempt cap: the Cloud
  Storage client libraries' documented defaults).
  - Cloud Storage's documented retry strategy: capped exponential backoff,
    a full-jitter draw under a ceiling that grows by the multiplier to
    `max_delay`, at least 1 ms a wait, until a success, a failure that is
    not transient, the attempt cap, or a wait that would pass the deadline;
    then that attempt's error is returned unchanged. Invalid values are
    normalized at use, never refused, and every nonzero deadline ends the
    loop.
  - Transient, decided where each failure happens (never by reading an
    error's text back): `408`, `429`, `500`, `502`, `503`, `504`; a
    transport failure before the response that timed out, failed to
    connect or broke in flight; any failure reading a body after the
    headers (an interrupted transfer); those classes on the way to the
    token; and an attempt cut off by the client's timeout (`Timeout`),
    unless that attempt had itself received an error status that is not
    transient (a `412` or `401` whose body never arrives is not retried, a
    `503`'s is). Never: a `404`, any other status (`401`, `403`, `412`
    included), `TooLarge`, the `Invalid*` refusals, other token errors. A
    `401` is returned at once; recovering from one is the caller's
    (`TokenProvider::invalidate` and one replay).
  - The error strings are unchanged: an interrupted body is still
    `Request { reason: "decode error" }`.
  - Each attempt takes a token and is bounded by the client's timeout,
    which is per attempt under a policy: the loop ends within the deadline
    plus one attempt.
  - Documented: library attempts are not wire requests (do not add a
    reqwest retry for the GCS host); a retried create-only upload whose
    first response was lost answers `412`, and a retried delete may return
    `Ok(false)`.
  - One `debug` line per retry: operation, attempt, `wait_ms`, the status
    or the transport category. Never a name, a message or a URL.
- `stridelabs-gcp`: `GcsClient::bucket_reachable(bucket)`, a startup probe
  (`GET {base}/storage/v1/b/{bucket}/o?maxResults=1`; any 2xx is `Ok(())`,
  anything else `Status { operation: "list" }`) on the same timeout and
  retry, point-in-time evidence that needs `storage.objects.list` (a
  `403` says nothing about whether the bucket exists); and
  `validate_bucket_name`, the bucket rule every operation applies, public.
  `GcsClient`'s `Debug` prints the name policy and the retry policy. All the
  new items are re-exported from the crate root.
- `stridelabs-testing` (`postgres`): `require_postgres_at(url)`, public and
  re-exported at the crate root (slaudio plan 025 L1). It connects to
  exactly `url` and reads no environment, with `require_postgres`'s 2 s
  timeout and redacted URL; its panic says to check the URL passed, where
  `require_postgres`'s says to point `DATABASE_URL` elsewhere.
  `require_postgres` keeps its documented precedence, `DATABASE_URL` over
  its argument, so it is the call for the database a suite starts from; a
  URL a test built itself goes to `_at`.
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
    (1 s, doubling to 8 s, never more than the refetch floor) while the set
    keeps answering until its TTL. Refresh-ahead needs traffic in that window.
    Without it, or with a TTL under three intervals, the first lookup at or
    after the TTL fetches.
  - **No stale fallback.** From the TTL on, a lookup waits for a fetch in
    flight or is refused with `AuthError::Jwks` (a 500 under `http`, a 503
    `Unavailable` in stridelabs-mcp).
  - **Prompt recovery.** After a failure, the next fetch of a needed set is
    allowed on the same spacing, 1 s after that failure completes, doubling
    to 8 s. Lookups in between are refused at once. A lookup that joins such
    a retry waits at most 2 s. Once the issuer returns, recovery takes at
    most what is left of an attempt still failing at that moment (up to
    `FETCH_TIMEOUT`), then the backoff (up to 8 s), then one successful
    fetch (up to `FETCH_TIMEOUT`): about 28 s at the defaults, and only once
    a lookup arrives.
  - **Unknown kids stay rate-limited.** Against a set inside its TTL, an
    unknown `kid` refetches at most once per `MIN_REFETCH_INTERVAL`, as
    before. Inside that floor the answer depends on the kid (below,
    `AuthError::UnseenKid`).
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
  - Lookups require a Tokio runtime with IO and the time driver enabled, as
    reqwest does: a lookup that starts a fetch (a refresh-ahead included)
    or joins one panics outside a runtime, as v0.8.0's fetch did, and one
    that has to wait on a fetch, polled on a runtime built without
    `enable_time`, panics in tokio's timer. A fresh hit needs no runtime.
  - The runtime that starts a fetch must keep being driven until it ends. A
    fetch frozen in an undriven runtime (a current-thread runtime whose
    `block_on` returned) holds the slot: lookups elsewhere give up at their
    bound until that runtime runs the fetch or is dropped.
  - `JwksCache`'s `Debug` output changed.
  - No public item was removed or re-typed; `AuthError::UnseenKid` (below)
    is the one addition.
- **BREAKING (type and behaviour, for `AuthError` matchers and `JwksCache`
  users; slaudio plan 025 L2): `AuthError` is `#[non_exhaustive]` and gains
  `UnseenKid`**, "token signed by a key not seen yet; refetch suppressed".
  Inside the unknown-kid refetch floor, a lookup for a kid the current set
  lacks now tells two cases apart, by the kids of the sets the cache
  fetched (the last few sets' kids, at most 64; only a fetched set adds to
  that memory, so forged kids cannot grow it):
  - a kid seen in an earlier set and since removed (a retired key) is
    `UnknownKid`, as before, so a client refreshes its token at once;
  - a kid no fetched set held (a rotation newer than the last fetch, or a
    forged kid) is `UnseenKid`, where it was `UnknownKid`. The token is
    still refused; the next lookup past the floor refetches, and a kid
    still absent after a refetch is `UnknownKid`.
  - The `http` bridge maps `UnseenKid` where it maps `Jwks`, to
    `AppError::Internal` (a 500, detail logged), and stridelabs-mcp's
    `From<AuthError> for VerifyError` maps it to `Unavailable` (a 503 that
    keeps the client's token). So a never-seen kid inside the floor is a
    500 (http) or 503 (mcp) where it was a 401.
  - **Operational:** anyone can mint a token with a random kid, so a flood
    of forged kids inside the floor is now one 5xx per request, and under
    the `http` bridge one logged 500. Its logged detail is
    `slauth JWKS: … refetch suppressed`, distinct from a fetch failure's,
    so 5xx alerting can exclude it; rate-limit unauthenticated traffic in
    the consumer if that volume matters.

  **Migration:** a `match` on `AuthError` needs a wildcard arm; send
  `UnseenKid` where `Jwks` goes if you map the error yourself (lumen maps
  `Jwks` to 503 and everything else to 401, so `UnseenKid` is a 401 there
  until it adds the arm). parcel and imgmcp use the mcp mapping and need no
  change.
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
  unifies the feature into every member's test build, so stridelabs-gcp's
  wire tests (`tests/wire_defaults.rs`) assert the request line, the
  bearer, the quota project, the content type and the body, not the
  `Accept-Encoding` the injected client adds.
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
