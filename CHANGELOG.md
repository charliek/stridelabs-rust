# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is lockstep across all five crates in this workspace (one
`[workspace.package].version`, bumped together regardless of which crate(s)
changed) rather than independent per-crate versioning —
see the root README's "Consuming these crates" section for what that means
for a consumer's pin.

## [Unreleased]

`stridelabs-observability` writes Google Cloud Logging lines and request
logs, bringing Rust services to parity with Python `stridelabs-logging`. The
next release must be a minor bump (0.x): `LogFormat` became
`#[non_exhaustive]`. None of this is in `v0.4.0`: until it is released,
consumers pin a commit (`rev = "…"`), not a tag.

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

### Changed

- **BREAKING:** `LogFormat` is now `#[non_exhaustive]` (to add `Cloud`
  without every future format being a breaking change). A `match` on
  `LogFormat` outside the crate without a wildcard arm (`_ => ...`) no
  longer compiles.
- `RequestIdLayer` reuses an existing `RequestId` request extension (held
  to the same validity rule as the header) before the `x-request-id` header,
  so behind an outer `RequestLogLayer` it echoes the id that was logged.
- `LogFormat::Json`'s documentation now lists the `span`/`spans` keys its
  lines have always carried inside a span; the format itself is unchanged.
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
- `metrics-exporter-prometheus` 0.17 → 0.18 (0.18.3; 0.18.2 is yanked).
  **BREAKING** for a consumer that names `PrometheusHandle`, which
  `prometheus::install` returns: it must depend on `metrics-exporter-prometheus`
  0.18 too (`metrics` stays 0.24). The scrape text `install` produces is
  unchanged for counters, gauges, `*duration_seconds` histograms (the only
  ones `install` gives buckets) and ordinary default-summary histograms: their
  `# HELP`, `# TYPE` and sample lines are pinned by tests. One exception, a
  renamed series: a histogram that falls back to the default summary (any
  histogram not ending `duration_seconds`) whose name ENDS IN `count` or `sum`
  loses that suffix on the matching series. 0.18's suffix helper skips a suffix
  the name already ends with, comparing `ends_with("count")` without the `_`
  (upstream `formatting.rs`, `add_suffix_if_missing`), so after `install()`
  `metrics::histogram!("discount")` renders `discount{…} 2` where 0.17.2
  rendered `discount_count{…} 2`, and `checksum{…} 4` where it rendered
  `checksum_sum{…} 4`; the other series of the summary (`discount_sum`,
  `checksum_count`, the quantiles) are unchanged. A consumer with such a metric
  must rename it or update the queries and alerts that read its `_count`/`_sum`
  series. A test pins this as observed on 0.18.3, so an exporter release that
  fixes it shows up as a deliberate change. 0.18's fix that puts
  the `_total` suffix on a counter's `# HELP` and `# TYPE` lines applies only
  with the new `with_recommended_naming(true)`, which `install` does not set; a
  consumer building its own exporter with it gets `# HELP x_total`,
  `# TYPE x_total counter` and `x_total{…} N` for a counter registered as `x`.
  Likewise `set_enable_unit_suffix(true)` (deprecated in 0.18; `install` does
  not set it) now suffixes `# HELP`/`# TYPE` like the samples and no longer
  repeats a unit already in the name (`x_seconds_seconds_bucket`).
- `tower-http` 0.6 → 0.7 (0.7.1). **BREAKING** for a consumer that names
  tower-http types: `cors_layer` returns `tower_http::cors::CorsLayer`, and
  `SecurityHeadersLayer`'s `Service` is a `tower_http::set_header` stack, so
  code that writes either type down must depend on tower-http 0.7 too (applying
  the layers with `.layer()` is unaffected).
- `cors_layer`'s `Vary` is unchanged, and now explicit: it sets `Vary: origin,
  access-control-request-method, access-control-request-headers` itself. That
  is the header tower-http 0.6 always sent; 0.7 derives the list from the policy and would send
  `origin` alone for `cors_layer`'s origin list with constant method/header
  lists, so the bump by itself would have changed the wire. The header is
  pinned by a test on ordinary, disallowed-origin, no-`Origin` and preflight
  responses. Nothing else tower-http 0.7 emits for `cors_layer` or
  `security_headers` differs from 0.6 (status, headers, values and header
  order compared over 15 request shapes), so `Vary` is the only change
  guarded.
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
  bump. One derived difference, not ours: the `oneOf` of an `Option<T>` field
  now lists the `$ref` first and `{"type":"null"}` second (utoipa 5 listed
  `null` first), so a committed `openapi.json` with an optional field gains
  exactly that diff when regenerated; the canonicalizer sorts object keys
  only, never arrays, and the uncanonicalized `serde_json::to_value` already
  has the new order. `documented_pairs` does not list the two path-item slots
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
- `stridelabs-testing` has no TLS. The `postgres` feature's sqlx is built with
  no `tls-*` feature (it used to enable `tls-rustls-ring`) because the pool
  talks to a local or CI Postgres in the clear, and a TLS feature there
  unifies into every consumer's test graph, where `ring` next to the aws-lc-rs
  provider of reqwest 0.13's `rustls` makes `rustls::ClientConfig::builder()`
  panic. Behaviour change for a consumer whose test URL demands TLS:
  `sslmode=require` (or `verify-ca`/`verify-full`) now panics with sqlx's
  "built without TLS support" error, pinned by a test; the default `prefer`
  connects in the clear. CI's "Guard: stridelabs-testing pulls no ring" step
  fails if a TLS feature comes back.
- The RUSTSEC-2023-0071 (`rsa`, Marvin timing side-channel; no upstream fix)
  ignore is gone from CI's `cargo audit` step and `deny.toml`: sqlx 0.9 no
  longer compiles `rsa` (MySQL's RSA auth is behind its opt-in `mysql-rsa`
  feature), so `Cargo.lock` has no `rsa` entry and `cargo audit` runs with no
  ignores. A "Guard: no rsa in Cargo.lock" CI step keeps it that way.
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
(the MSRV) from 1.96 to 1.97, and this entry did not say so. `v0.1.0`
declares 1.96; `v0.2.0` and every later tag declare 1.97. Minimum supported
Rust version raised to 1.97. Consumers must be on Rust 1.97 or newer.
Earlier tags are unaffected.

## [0.1.0] - 2026-07-25

Initial release: `stridelabs-config`, `stridelabs-observability`,
`stridelabs-http`, `stridelabs-auth` and `stridelabs-testing`, seeded from
spendwise-rs and limen.
