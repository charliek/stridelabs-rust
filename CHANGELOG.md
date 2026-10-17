# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is lockstep across all eight crates in this workspace (one
`[workspace.package].version`, bumped together regardless of which crate(s)
changed) rather than independent per-crate versioning —
see the root README's "Consuming these crates" section for what that means
for a consumer's pin.

## [Unreleased]

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
