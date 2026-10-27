# stridelabs-rust

Shared Rust crates for StrideLabs services — the Rust twin of
[stridelabs-python](https://github.com/charliek/stridelabs-python). Common
patterns and practices live here once, so services stay consistent.

**Status: all twelve crates implemented.** The workspace scaffold (Cargo
workspace, CI, toolchain pins) and `stridelabs-config`,
`stridelabs-observability`, `stridelabs-http`, `stridelabs-auth`,
`stridelabs-testing`, `stridelabs-mcp`, `stridelabs-redis`,
`stridelabs-gcp`, `stridelabs-inworld`, `stridelabs-postgres`,
`stridelabs-perplexity` and `stridelabs-voice` are all in place. See each crate's own README for its full
API and feature topology.

## Crates

| Crate | Status | Contents | Seeded from |
|---|---|---|---|
| `stridelabs-config` | Implemented | Env-var config helpers with a public lookup seam whose errors never carry a value, layered file loading with field-pathed errors (feature `file`, on by default), a validation/startup-refusal accumulator | Two existing services' config loaders |
| `stridelabs-observability` | Implemented | tracing init (text/JSON/Cloud Logging, per-target level caps that hold under `RUST_LOG`), request-ID and request-logging tower layers, Prometheus wiring | A production reverse proxy's `observability` module; Python `stridelabs-logging`'s Cloud Logging format and request middleware |
| `stridelabs-http` | Implemented | `AppError`→`IntoResponse` convention, security-headers + CORS layers, graceful shutdown, reverse-proxy primitives (feature `proxy`), an SSRF-hardened outbound fetch (feature `ssrf`), the process-wide rustls provider install (feature `tls`), OpenAPI spec mechanics (feature `openapi`), URL redaction for log lines (feature `redact-url`) | An existing service's `error.rs`, a reverse proxy's HTTP layer, the `http/openapi.rs` and `tls.rs` of slauth, the StrideLabs auth service, and Python `stridelabs.mcp.ssrf` |
| `stridelabs-auth` | Implemented | Resource-server token verification: slauth's access tokens, and other issuers' (e.g. WorkOS, whose tokens carry no `aud`) under claim rules the consumer chooses (`Verifier::for_issuer`, or `Verifier::with_cache` over the consumer's own cache); rate-limited JWKS cache, RS256 verification, opt-in unusable-key reporting and a strict pre-lookup screen, bearer extraction, slauth PAT validation, PAT hashing, offline test-key minting | An existing service's `auth/` module; Python `stridelabs-auth`'s `PATValidator` |
| `stridelabs-testing` | Implemented | Fail-loud real-Postgres pool and real-Redis probe, a guard that keeps a suite's test URL on this machine (and, opt-in, off Redis database 0), `oneshot` axum router-test helpers, a one-line wiremock JSON stub | Existing integration-test idioms, hardened; tapper's and slaudio's test-URL guards |
| `stridelabs-mcp` | Implemented | The middle of an MCP server on rmcp: RFC 9728 protected-resource metadata, slauth bearer verification at the MCP boundary (audience = the resource URL, 503 on an issuer outage), a stateless Streamable HTTP router, a scoped, rate-limited, audited tool boundary, and slauth PATs as a credential; behind features, a Redis-backed limiter and PAT cache, an SSRF-hardened image fetch and a CORS preset | Python `stridelabs-mcp` (itself extracted from slaudio's MCP surface) |
| `stridelabs-redis` | Implemented | A lazy, single-flight Redis handle: an atomic fixed-window counter that is never replayed, idempotent `GET` / `SET EX`, `EVAL` under a caller-chosen replay policy, `PING` | tapper's hardened rate-limiter connection slot |
| `stridelabs-gcp` | Implemented | Policy-free Google Cloud building blocks on the consumer's `reqwest::Client`: an ADC access-token provider, a small GCS JSON-API client, Vertex AI `generateContent` (feature `vertex`) | tapper's and parcel's GCS clients; google-auth's ADC chain and google-genai's Vertex rules, as imgmcp used them |
| `stridelabs-inworld` | Implemented | A policy-free Inworld text-to-speech client on the consumer's `reqwest::Client`: one bounded, classified, log-safe synthesis (whole-exchange timeout, streamed response cap, pre-decode base64 guard, decoded-audio and text bounds, an optional MP3 shape check) | tapper's and lumen's `voice/inworld.rs`; slaudio's Python Inworld adapter |
| `stridelabs-postgres` | Implemented | Postgres connection hygiene on sqlx: a `DATABASE_URL` allow-list whose refusals never print a value (no `search_path`, no NUL byte, no password file), value-free `sqlx::Error` summaries, a lazy pool, Neon pooler detection, the sqlx log targets to cap; a begin guard (feature `guard`: a bounded, cancel-safe `BEGIN` with `SET LOCAL` bounds, and a per-pool release probe); no TLS stack of its own | tapper's `db.rs` (hardened from lumen-rs's), checked against slaudio's `parse_connect_options`; the guard from lumen-rs's `db.rs` (plan 003) |
| `stridelabs-perplexity` | Implemented | A policy-free Perplexity Agent API web-search client on the consumer's `reqwest::Client`: one bounded, classified, log-safe search (whole-exchange timeout, streamed response cap, input bound), a faithful answer (text, every search result with its citation id, status, usage) and an optional display helper (`sources`) | lumen's Sonar `web_search` (Sonar's chat completions were retired 2026-09-27), to lumen plan 002 W4b-1 |
| `stridelabs-voice` | Implemented | The voice core apps share, provider-neutral: the client protocol (revision 1, `PROTOCOL.md`, with its golden fixture), the speech-to-text and text-to-speech provider traits, the UTC windows, a text-to-speech character budget and a speech-to-text audio budget with a fenced lease on Redis scripts shared byte for byte, the checked `Voice` and its refusals; behind `axum` the speech-to-text relay with its admission and the text-to-speech flow; the Muse and Inworld adapters behind features of their own (the app's connector and client; no crypto provider, no client built here) | tapper's and lumen's `voice/` (`tapper-rs/src/voice/` at `82be95f`), lumen plan 003 |

See [§ Feature topology](#feature-topology-all-twelve-crates) below for what
each crate turns on by default versus behind a feature flag.

## Conventions

- Cargo virtual workspace; lockstep versions via `[workspace.package]`; shared
  `[workspace.lints]` and `[workspace.dependencies]`.
- **`publish = false` on every crate.** These never go to crates.io — see
  [Consuming these crates](#consuming-these-crates) for how a service
  actually depends on them.
- **Tests fail loudly on a missing external dependency — never skip.**
  `stridelabs-testing::require_postgres` is the concrete example: it panics
  with a message naming the env var and the compose/`make up` command rather
  than silently skipping the test, which is exactly the `pool_or_skip()`
  pattern it exists to replace (nine of eleven test files in one service had
  their own copy). A green test suite must mean the behavior it claims to
  cover actually ran.
- OpenAPI default for services: utoipa 6 + utoipa-axum 0.3, Swagger UI dev-gated,
  spec exported and linted in CI.
- Issuer-side JWT helpers stay app-local until a second issuer exists (same
  "defer until a second consumer" rule as stridelabs-python).

## Consuming these crates

None of these crates are published to crates.io (`publish = false`
everywhere) — they're consumed as a **git dependency**, pinned to either a
release tag or a commit rev, fetched over plain `https`.

This repository is public, so it's reachable anonymously over plain `https`
— no credentials needed.

### Adding the dependency

Once a version is tagged, pin the tag:

```toml
[dependencies]
stridelabs-config = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.11.1" }
```

Before the first tag exists — or when depending on a reviewed-but-unreleased
change — pin the exact commit instead:

```toml
[dependencies]
stridelabs-config = { git = "https://github.com/charliek/stridelabs-rust.git", rev = "<full commit sha>" }
```

`rev` pins are meant to be temporary: once the corresponding change is
released and tagged, bump the consumer back to `tag = "vX.Y.Z"` so its
manifest reads the same way for everyone, forever. Every crate is versioned
in lockstep (one `[workspace.package].version` for the whole workspace), so a
consumer pins **one** tag/rev for however many of the twelve crates it uses.

### MSRV policy

The minimum supported Rust version is `rust-version` in the workspace
`Cargo.toml` (currently 1.97, in force since v0.2.0). It tracks the minor
version of the pinned toolchain (`rust-toolchain.toml`, currently 1.97.1):
a patch bump of the toolchain leaves it alone, and moving the pin to a new
minor moves it too. Cargo rejects a consumer on an older compiler from the
declared `rust-version` alone, even where the source would still build, so an
MSRV bump is a minor release (0.x), and its CHANGELOG section carries this
line, with X the new version:

> Minimum supported Rust version raised to X. Consumers must be on Rust X or newer. Earlier tags are unaffected.

A tag is immutable, so a consumer pinned to an earlier tag keeps that tag's
manifest and the MSRV it declares. That fixes this workspace's source, not the
consumer's dependency graph: transitive versions come from the consumer's own
`Cargo.lock` (keep it committed), not from this repository's, so a fresh
resolve can pick up a registry release that needs a newer compiler than the
tag declares.

### Local co-development

While iterating on a change to this workspace *and* a consumer at the same
time, override the git dependency with a path via `[patch]` in the
consumer's root `Cargo.toml` — never committed, since it points outside that
repository:

```toml
[patch."https://github.com/charliek/stridelabs-rust.git"]
stridelabs-config = { path = "../stridelabs-rust/crates/config" }
stridelabs-observability = { path = "../stridelabs-rust/crates/observability" }
stridelabs-http = { path = "../stridelabs-rust/crates/http" }
stridelabs-auth = { path = "../stridelabs-rust/crates/auth" }
stridelabs-testing = { path = "../stridelabs-rust/crates/testing" }
stridelabs-mcp = { path = "../stridelabs-rust/crates/mcp" }
stridelabs-redis = { path = "../stridelabs-rust/crates/redis" }
stridelabs-gcp = { path = "../stridelabs-rust/crates/gcp" }
stridelabs-inworld = { path = "../stridelabs-rust/crates/inworld" }
stridelabs-postgres = { path = "../stridelabs-rust/crates/postgres" }
stridelabs-perplexity = { path = "../stridelabs-rust/crates/perplexity" }
stridelabs-voice = { path = "../stridelabs-rust/crates/voice" }
```

`[patch]` keys the whole *source* (the git URL), not one crate — list every
crate from this workspace the consumer actually depends on, whether directly
or transitively (e.g. `stridelabs-auth`'s `http` feature depends on
`stridelabs-http`, so the consumer's `[patch]` block needs both if it uses
that feature). A patch entry for a crate the consumer doesn't depend on is
harmless — Cargo only applies the ones that match a real dependency — so
listing all twelve up front, as above, is the simplest thing that stays correct
as a consumer's dependency set grows. The `[patch]` key must match the
`https://…` source URL the consumer's `[dependencies]` actually used.

A patch only takes effect if the consumer's `Cargo.lock` can use it. A consumer
locked to another version of this library (say `0.4.0` while the workspace is
at `0.5.0`) leaves the patch **silently unused** and keeps building the old git
dependency, so after adding the block:

1. Move the locked crates onto it: `cargo update -p stridelabs-config -p
   stridelabs-http …`, one `-p` for each `stridelabs-*` package the consumer's
   `Cargo.lock` names.
2. Check it took: `cargo tree -i stridelabs-config` (or `cargo metadata`) shows
   the local path rather than the git URL. Cargo prints "patch … was not used in
   the crate graph" when it did not.

`scripts/downstream-check.sh` is the automated form: it does both against this
checkout for tapper, slauth, limen, imgmcp, spendwise-rs, slaudio, lumen or parcel, then proves
with `cargo metadata` that every `stridelabs-*` package is this checkout's own
crate. It finds each consumer's checkout next to this one or under
`~/projects` (`DOWNSTREAM_PROJECTS` and `DOWNSTREAM_<NAME>_REPO` override), and
keeps its archives and target dirs under
`${XDG_CACHE_HOME:-~/.cache}/stridelabs-downstream` (`DOWNSTREAM_SCRATCH`
overrides); the script's header lists each consumer's services and variables.
slaudio's Rust port lives on its `rust-port` branch, so pass
`DOWNSTREAM_SLAUDIO_REF=origin/rust-port` (an `all <ref>` run otherwise reports
slaudio NOT RUN). lumen (informational) is not given a ref automatically: pass `origin/main`
or set `DOWNSTREAM_LUMEN_REF`. Its tests read `LUMEN_RS_TEST_DATABASE_URL`, `LUMEN_RS_TEST_REDIS_URL` and `LUMEN_RS_TEST_GCS_URL` (default `http://localhost:54443`, lumen's own
fake-gcs; never tapper's 4443). parcel (informational, likewise pass `origin/main`) runs its
root workspace against its own compose Postgres (`localhost:5439`, a port that is also the
example in this library's CLAUDE.md, so don't move the library's Postgres there) and fake-gcs-server
(`localhost:4447`); `DOWNSTREAM_PARCEL_DATABASE_URL` points it elsewhere. tapper's run names its
fake-gcs-server through `TAPPER_RS_TEST_GCS_EMULATOR_URL` (default `http://127.0.0.1:4443`).

### Feature topology (all twelve crates)

Every crate that defines optional features defaults to `default = []` — a
consumer opts into the heavier parts of its dependency graph (a TLS stack, a
database driver, a metrics exporter) explicitly, one feature at a time.
`stridelabs-config` is the exception: its `file` feature is on by default,
because file loading was unconditional before the feature existed; a
consumer configured from its environment alone turns it off
(`default-features = false`) to keep YAML out of its graph.
`stridelabs-perplexity` has no feature flags at all: everything it provides is
unconditional. Full detail — including *why* each
gate exists — lives in each crate's own README; this is the map of what turns
on what.

| Crate | Feature | Default | Adds |
|---|---|---|---|
| `stridelabs-config` | `file` | **on** | `load_yaml`/`load_json`/`Loaded`/`FileError`, via `yaml_serde`, `serde_path_to_error` and `serde`; off, the crate is the env helpers and `Errors` only |
| `stridelabs-observability` | `prometheus` | off | `metrics` + `metrics-exporter-prometheus`: recorder install, `status_class`, `DURATION_BUCKETS` |
| `stridelabs-observability` | `axum` | off | `RequestLogLayer`'s peer-address fallback for `remoteIp`, read from axum's `ConnectInfo<SocketAddr>` |
| `stridelabs-http` | `cors` | off | `cors_layer`, via `tower-http/cors` |
| `stridelabs-http` | `openapi` | off | spec canonicalization, `(method, path)` enumeration, committed-spec freshness check, via `utoipa` |
| `stridelabs-http` | `proxy` | off | reverse-proxy primitives, via `reqwest` (with `rustls`: the aws-lc-rs provider and the OS trust store)/`url`/`bytes`/`futures` |
| `stridelabs-http` | `ssrf` | off | `fetch_public` and `fetch_public_response`, the SSRF-hardened fetch of a URL somebody else chose (public-address policy, DNS pinning, capped body; request headers, statuses, validators, the answering hop's URL and headers), via the same `reqwest`/`url`/`bytes`/`futures` as `proxy` |
| `stridelabs-http` | `ssrf-decompress` | off | `ssrf` plus opt-in gzip/deflate decoding of a fetched body under a decoded-size cap, via `flate2` (pure Rust, no C toolchain) |
| `stridelabs-http` | `ssrf-test-support` | off | `ssrf::LoopbackTestServer`, to point a fetch at a local TLS test server — `[dev-dependencies]` only |
| `stridelabs-http` | `tls` | off | `tls::install_default_provider`, making aws-lc-rs the process's rustls provider, via `rustls` |
| `stridelabs-http` | `redact-url` | off | `redact_url`, a URL for a log line without its userinfo, query or fragment, via `url` (no HTTP client, no TLS) |
| `stridelabs-auth` | `axum` | off | `bearer_token(&Parts)`, via the `http` types crate |
| `stridelabs-auth` | `http` | off | `From<AuthError> for stridelabs_http::AppError` |
| `stridelabs-auth` | `test-support` | off | offline JWT minting against two committed throwaway keypairs |
| `stridelabs-testing` | `postgres` | off | `require_postgres` and `require_postgres_at`, via `sqlx`'s Postgres driver |
| `stridelabs-testing` | `redis` | off | `require_redis`, `require_local_redis_url` and `RedisDbPolicy`, via redis-rs (no TLS) |
| `stridelabs-mcp` | `test-support` | off | MCP access-token minting for a `ProtectedResource` (via `stridelabs-auth/test-support`) and the committed `tools/list` freshness check; with `image-fetch`, also stridelabs-http's `ssrf-test-support` |
| `stridelabs-mcp` | `cors` | off | `cors_layer()`, the app-wide CORS preset, via `tower-http/cors` |
| `stridelabs-mcp` | `redis` | off | `RedisRateLimiter` and `RedisPatCache`, via `stridelabs-redis` |
| `stridelabs-mcp` | `image-fetch` | off | `ImageFetcher`, via stridelabs-http's `ssrf` + `base64` |
| `stridelabs-mcp` | `live-tests` | off | **not for consumers**: compiles the crate's real-Redis suite |
| `stridelabs-redis` | `live-tests` | off | **not for consumers**: compiles the crate's real-Redis suite (everything else is unconditional) |
| `stridelabs-gcp` | `service-account-key` | off | `service_account` credentials: RS256 assertion signing via jsonwebtoken's `use_pem` |
| `stridelabs-gcp` | `vertex` | off | the `vertex` module (no extra dependency) |
| `stridelabs-inworld` | `client-builder` | off | `client_builder()`, a `reqwest::ClientBuilder` with the rustls backend, no proxy and no redirects, via `reqwest` (with `rustls`: the aws-lc-rs provider and the OS trust store) |
| `stridelabs-postgres` | `guard` | off | the begin guard (`GuardedPool`, `GuardedConnection`, `BeginGuard`, `TxBounds`), via `tokio` (`rt`, `time`) and `futures-util`, both already in sqlx's graph |
| `stridelabs-postgres` | `test-support` | off | `guard`, plus its two hidden test seams (`GuardedPool::set_window_opened_at`, `TxBounds::REFUSED_BY_THE_SERVER`) — `[dev-dependencies]` only |
| `stridelabs-postgres` | `live-tests` | off | **not for consumers**: compiles the crate's real-Postgres suites (everything else is unconditional; sqlx is required, with `postgres` and `runtime-tokio` only) |
| `stridelabs-perplexity` | *(none — everything is unconditional; its `reqwest` has no features, so no TLS)* | — | — |
| `stridelabs-voice` | `axum` | off | the speech-to-text relay (`relay`), the stream's admission (`stream`, `Voice::open_stream`) and the text-to-speech flow (`Voice::speak`), on axum's WebSocket (`ws`, no server), plus `LOG_CAPS`; via `axum`, `tungstenite` and `futures-util`, and tokio's `rt` and `macros` |
| `stridelabs-voice` | `muse` | off | the Muse speech-to-text adapter, dialled through the app's `tokio_tungstenite::Connector` (tokio-tungstenite with `connect` and `rustls-tls-native-roots`, its rustls with no provider feature), plus `LOG_CAPS` |
| `stridelabs-voice` | `inworld` | off | the Inworld text-to-speech adapter over the app's `InworldClient`, via `stridelabs-inworld` (no features) |
| `stridelabs-voice` | `openapi` | off | `utoipa::ToSchema` on `LimitScope` and `VoiceLimitBody`, via `utoipa` |
| `stridelabs-voice` | `test-support` | off | the scripted adapters (`testing`), the test seams, and with `axum` and an adapter that adapter's mock provider server — `[dev-dependencies]` only |
| `stridelabs-voice` | `live-tests` | off | **not for consumers**: compiles the crate's real-Redis suites (with `test-support` and `axum`) |

`stridelabs-testing`'s `oneshot`, `wiremock` and `local` modules have no
feature gate of their own — all are cheap and every consumer of the crate
wants them; only the Postgres driver and the Redis client are worth gating.

`stridelabs-http`'s `proxy` and `ssrf` and `stridelabs-inworld`'s
`client-builder` are the only features anywhere here that turn on reqwest's
TLS (`stridelabs-mcp`'s `image-fetch` reaches it through `ssrf`);
`stridelabs-http`'s `tls` adds a direct `rustls` dependency only to install
the provider. `stridelabs-redis` turns on redis-rs's `tokio-rustls-comp` for
`rediss://`, so `stridelabs-mcp`'s `redis` brings rustls too, with no crypto
provider of its own (see below). `stridelabs-auth`, `stridelabs-gcp`,
`stridelabs-mcp`'s core, `stridelabs-inworld` without `client-builder` and
`stridelabs-perplexity` have none — they take the consumer's `reqwest::Client`, so the TLS stack and
the process's rustls provider stay the consumer's choice (and
`stridelabs-mcp` builds rmcp with no HTTP-client feature) — and
`stridelabs-testing`'s Postgres pool and Redis probe talk to their servers in
the clear. `stridelabs-voice` is not TLS-free (rustls is in its graph in
every combination, through `stridelabs-redis`'s `rediss://` support, and
`muse` adds tokio-tungstenite's rustls transport) but selects no crypto
provider, and builds no client: the `muse` dial takes the app's
`tokio_tungstenite::Connector` and the `inworld` adapter the app's client,
so the provider is the app's (CI-guarded, below). `stridelabs-postgres` names no sqlx TLS feature either: the
consumer's own sqlx dependency picks it (`tls-rustls-aws-lc-rs`, below), and
Cargo unifies it into the crate's sqlx.

### One crypto provider: aws-lc-rs

`stridelabs-auth` signs and verifies JWTs with jsonwebtoken 11's `aws_lc_rs`
backend (as does `stridelabs-gcp`'s `service-account-key`), and `proxy`'s,
`ssrf`'s and `stridelabs-inworld`'s `client-builder`'s TLS uses rustls's
aws-lc-rs provider. jsonwebtoken (10+) and rustls
both choose their crypto from crate features at runtime, and Cargo unifies
features across a consumer's whole graph, so a second backend anywhere in
that graph does not fail the build: the process panics at its first JWT sign
or verify, or its first `rustls::ClientConfig::builder()`. The consumer rule:

- **Never enable jsonwebtoken `rust_crypto`**, on your own jsonwebtoken or
  anywhere else in your graph. Next to this workspace's `aws_lc_rs` it makes
  jsonwebtoken panic, `stridelabs-auth`'s verification and test-token minting
  included, and it brings back the `rsa` crate (RUSTSEC-2023-0071, no fix).
- **Use aws-lc-rs as the only rustls provider**: no rustls `ring` feature
  (redis-rs 0.27's `tls-rustls`, sqlx `tls-rustls-ring`, …). Install it as
  the process default at startup, before anything connects:
  `stridelabs_http::tls::install_default_provider()` (feature `tls`). A
  `rediss://` dial through `stridelabs-redis` needs it, since that crate
  picks no provider of its own, and so does any other
  `rustls::ClientConfig::builder()` your graph relies on.

Nothing checks either rule at compile time. For the jsonwebtoken half, a test
that mints and verifies a token (`stridelabs_auth::test_support`, feature
`test-support`) panics in your own CI when the rule is broken; this
workspace's own tests do exactly that.
