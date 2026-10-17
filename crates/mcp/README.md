# stridelabs-mcp

The hardened middle of a StrideLabs MCP server: everything between an HTTP
request at `/mcp` and an app's tool code. The Rust twin of
stridelabs-python's `stridelabs-mcp`, built on
[rmcp](https://docs.rs/rmcp) 3.5 (the official Rust MCP SDK).

The app writes its tools as an rmcp `ServerHandler`. This crate supplies:

- **`ProtectedResource`**: the endpoint's canonical resource URL (the token
  audience slauth mints, validated by slauth's own rule), its issuer and
  scopes, and everything derived from them: the RFC 9728 document, the
  metadata URL challenges point at, the route, the allowed `Host`.
- **`metadata_router`**: the RFC 9728 protected-resource metadata document at
  both origin-root well-known paths (one resource per origin: the bare path
  can only name one).
- **`McpVerifier`**: slauth RS256 JWTs with **audience = the resource URL**
  (scopes from `scope` and Hydra's `scp`), plus app-verified credentials
  selected by prefix (`CredentialVerifier`: slauth `slp_live_` PATs, the
  app's own API tokens). An issuer outage is `Unavailable` (503), never a
  rejection.
- **`McpAuthLayer`**: the HTTP boundary. RFC 6750 `401`s carrying
  `resource_metadata` and the scope hint, `503` on an outage, the
  `Principal` into the request.
- **`server_config` / `router`**: rmcp's Streamable HTTP service, stateless
  with JSON responses, `Host`-checked, at exactly the resource's path, behind
  the auth layer.
- **`ToolCall`**: the tool boundary. Principal, per-tool scopes, an optional
  rate limit, timeout, safe errors (`ToolError`), exactly one audit line per
  run. Plus `clamp_limit` / `clamp_offset` / `Page` for list tools.
- **`RateLimiter`**: the seam `ToolCall::rate_limit` calls after the scope
  check, with `MemoryLimiter` (Python's fixed one-minute window, in memory)
  and `NoLimit`; `RedisRateLimiter` (feature `redis`) shares the window
  across instances and fails open.
- **`SlauthPatCredential`**: slauth `slp_live_` PATs as a
  `CredentialVerifier` — slauth's verdict, the app's ceiling scopes — with an
  optional fail-through `PatCache` (`RedisPatCache`, feature `redis`).
- **`ImageFetcher`** (feature `image-fetch`): Python `fetch.py`'s twin, the
  SSRF-hardened fetch of an image an LLM chose (`https` or `data:`), with
  Python's messages.
- **`cors_layer`** (feature `cors`): the app-wide CORS preset for an MCP
  service.
- **`canonical_tools_json`**: the committed `tools/list` contract
  (`mcp-tools.json`), byte-stable, and its freshness check (feature
  `test-support`).

## Adding the dependency

```toml
[dependencies]
stridelabs-mcp = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.7.0" }
rmcp = { version = "3.5", default-features = false, features = ["server", "macros"] }

[dev-dependencies]
stridelabs-mcp = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.7.0", features = ["test-support"] }
```

Rate limiting, `SlauthPatCredential`, `canonical_tools_json` and the
`cors`, `redis` and `image-fetch` features are new in v0.7.0:

```toml
[dependencies]
stridelabs-mcp = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.7.0", features = ["cors", "redis", "image-fetch"] }

[dev-dependencies]
stridelabs-mcp = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.7.0", features = ["cors", "redis", "image-fetch", "test-support"] }
```

rmcp's types are this crate's API (`ServerHandler`, `RequestContext`,
`CallToolResult`, `StreamableHttpServerConfig`), so depend on the same major;
`stridelabs_mcp::rmcp` re-exports it for naming types. `macros` is for
`#[tool]` / `#[tool_router]`, which this crate does not use itself. **Never
enable rmcp's `local` feature**: it compiles the Streamable HTTP service out.

(During development against an unreleased commit, pin `rev = "<sha>"` instead
of `tag`; see the workspace root README for the local `[patch]` snippet.)

## Wiring

```rust
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler};
use stridelabs_mcp::{McpAuthLayer, McpVerifier, ProtectedResource, ToolCall, ToolError};

struct ParcelMcp {
    state: AppState,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl ParcelMcp {
    #[tool(description = "Fetch one of your parcels.")]
    async fn get_parcel(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(args): Parameters<GetParcel>,
    ) -> Result<CallToolResult, ErrorData> {
        ToolCall::new("get_parcel")
            .scopes(["parcel:read"])
            .run(&ctx, |principal| async move {
                let user = self.state.user_for(&principal).await?;   // impl From<AppError> for ToolError
                let parcel = self.state.parcel(&user, &args.id).await?
                    .ok_or_else(|| ToolError::user("No such parcel."))?;
                Ok(CallToolResult::structured(serde_json::to_value(parcel).map_err(ToolError::internal)?))
            })
            .await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ParcelMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

// At startup:
let resource = ProtectedResource::new(
    &config.mcp_resource_url,            // "https://parcel.stridelabs.ai/mcp"
    &config.slauth_issuer,               // "https://auth.stridelabs.ai"
    ["parcel:read", "parcel:write"],
)?;
let verifier = McpVerifier::new(&resource, &config.slauth_jwks_url, http.clone())
    .with_credential("pcl_", ApiTokens::new(db.clone()));   // optional: the app's own tokens
let mcp_config = stridelabs_mcp::server_config(&resource, &config.extra_hosts)
    .with_cancellation_token(shutdown.child_token());

let app = app
    .merge(stridelabs_mcp::metadata_router(&resource))
    .merge(stridelabs_mcp::router(McpAuthLayer::new(verifier), mcp_config, move || {
        Ok(ParcelMcp { state: state.clone(), tool_router: ParcelMcp::tool_router() })
    }));
```

A compiled version of this is the crate-level doc example (`src/lib.rs`), and
`tests/mcp_http.rs` drives a complete one over a socket.

**Merge both routers; don't `nest` them.** `router` puts the endpoint at the
resource's full path, and the metadata paths live at the origin root
(`/.well-known/oauth-protected-resource` and
`/.well-known/oauth-protected-resource/mcp`), outside the endpoint and its
bearer check: an unauthenticated client fetching them is the point.

## What stays in the app

The scope taxonomy and the rate classes (and each class's limit); which
credentials besides slauth JWTs it accepts, and how it validates them (the
`CredentialVerifier` it supplies, or `SlauthPatCredential` with its PAT
ceiling); mapping a `Principal` to its own user row (provisioning, linking by
email when there is one); quotas; database sessions and transactions;
settings and their validation; and the tools themselves.

## Behaviour

### The canonical resource URL

`ProtectedResource::new` applies slauth's rule (`normalize_mcp_resource`):
`https` only (local dev is https too, behind prox), lowercase scheme and host,
no trailing slash, no default `:443` (another port is kept), no query,
fragment, userinfo, percent-escapes, backslashes, non-ASCII or empty/dot path
segments. Where slauth normalizes merely non-canonical input, this crate
**rejects** it with `ResourceError::NotCanonical { canonical }`, naming the
string to configure, so the configured value is the token audience byte for
byte. Two extra restrictions, for strings slauth would accept but no
deployment uses: the host must be a DNS-style name or a bracketed IPv6
literal, and path segments may use only RFC 3986 unreserved characters (the
path becomes an axum route and is quoted into headers). Errors never echo the
URL they were given.

A test server on plain http still names an `https` resource: the URL is an
identifier, never dialled. The `Host` check is configured separately.

### The HTTP boundary

| Request | Response |
|---|---|
| no bearer token | `401`, `WWW-Authenticate: Bearer resource_metadata="…", scope="…"` (no `error`, RFC 6750 §3.1) |
| a refused token | `401`, `Bearer error="invalid_token", error_description="…", resource_metadata="…", scope="…"` |
| verifier unavailable (JWKS fetch failed, app token store down) | `503 {"error":"temporarily_unavailable", …}`; the client keeps its token |
| valid, but missing a boundary-level scope (opt-in) | `403`, `Bearer error="insufficient_scope", …, scope="<held + required>"` |
| valid | the request, with its `Principal` in the extensions |

Bodies are JSON `{"error", "error_description"}` with fixed descriptions; the
verifier's specific reason is logged (`stridelabs.mcp.auth`, `debug` for a
refusal, `warn` for an outage) and never returned. The `scope` hint defaults
to the supported scopes, space-joined; `with_scope_hint` narrows it, and an
empty hint omits the parameter. Per-tool scopes are the norm, so the
boundary requires none unless `McpAuthLayer::with_required_scopes` says so.

### JWT claims

Everything stridelabs-auth's `Verifier::verify_bearer_claims` checks (an
RS256-fit key under the `kid`, signature, `exp`, `iss`, `aud`, all required),
with audience = the resource URL and issuer = the resource's issuer, by
construction. Then: `sub` non-empty; scopes = the union of `scope` and
`scp`, either a space-separated string or an array; `client_id` from
`client_id`, else `azp`; `email` and `name` optional (empty = absent).
`Principal`'s `Debug` never prints the email or name.

### Stateless transport

`server_config` turns rmcp's legacy sessions off and JSON responses on, and
`router` serves with `NeverSessionManager` (forcing sessions off whatever the
config says, since every legacy `initialize` would otherwise fail). MCP
2026-07-28 has no sessions; for 2025-03-26 / 2025-06-18 / 2025-11-25 clients,
statelessness is what Cloud Run (scale to zero, no affinity) and clients that
re-initialize per call need. No `Mcp-Session-Id` is ever issued. A tool that
emits a notification before its result is answered as SSE so nothing is
lost. `GET` and `DELETE` answer `405` (after the bearer check).

`allowed_hosts` is the resource's host (any port) plus the extras passed —
rmcp's default is loopback only, which refuses every public request. Origin
validation stays off: the endpoint takes bearer tokens only, so a
cross-origin page has no ambient credential to abuse (chain rmcp's
`.with_allowed_origins(…)` to turn it on). The body limit is
`MAX_REQUEST_BODY_BYTES` (4 MiB, rmcp's default, pinned).

The endpoint is exactly the resource's path: `/mcp/` and `/mcp/anything`
are `404`. (rmcp's service ignores the request path, so the
`nest_service("/mcp", …)` its examples use would answer MCP at every
subpath.)

### The tool boundary

`ToolCall::new(name).scopes([..]).rate_limit(limiter, class).timeout(d).run(&ctx, |principal| async { … })`
(`rate_limit` is optional):

| Case | Result (`isError: true` unless ok) | `outcome` | `error_class` |
|---|---|---|---|
| body returns `Ok(result)` | the result | `ok` (`error` if the result is itself `isError`) | — (`CallToolResult`) |
| no principal (not behind the layer) | "Not authenticated." | `denied` | `NotAuthenticated` |
| missing scope | "Missing required scope(s): X. This credential grants: Y. Reconnect with the required scopes to use this tool." | `denied` | `ScopeError` |
| the rate limiter refuses | "Rate limit exceeded for {class} operations ({limit} per minute). Retry in {n} seconds." | `ratelimited` | `RateLimited` |
| `ToolError::user(msg)` | `msg` | `error` | `ToolError::User` |
| `ToolError::denied(msg)` | `msg` | `denied` | `ToolError::Denied` |
| timeout (default 30 s; the rate limit check and the body together) | "The operation timed out. Please try again." | `timeout` | `Timeout` |
| `ToolError::internal(e)` | "Internal server error." | `internal` | `e`'s type name |
| panic (in the body or the limiter) | "Internal server error." | `internal` | `panic` |
| request cancelled, or the call dropped (during the rate limit check too) | "The request was cancelled." | `cancelled` | `Cancelled` / `Dropped` |

Failures are tool results, not JSON-RPC errors, so the model sees them.
`ToolError::internal` keeps only the error's type name: an unexpected
error's message can carry user data, so it is dropped unread. There is no
blanket `From<E: Error> for ToolError`, on purpose: write `impl From<AppError>
for ToolError` mapping user-safe variants to `ToolError::user`, and `?` works.

Exactly **one** audit line per run of a tool's code, target
`stridelabs.mcp.tool`, message
`mcp_tool_call`: `tool`, `outcome`, `duration_ms`, `required_scopes`, `sub`,
`auth_method`, `scopes`, `client_id`, `error_class`. Never a token, email or
name. `INFO` (`ratelimited` included); `WARN` for `timeout`/`cancelled`;
`ERROR` for `internal`. A dropped call still writes its line. A `tools/call`
that rmcp answers before any tool runs (arguments that don't deserialize: an
`isError` result; an unknown tool: a JSON-RPC error) writes none, and
consumes no rate limit; log those in your `ServerHandler::call_tool` if your
audit trail needs them.

Two logging notes for a production subscriber: rmcp's own `debug` line for
each request includes its arguments (tool input is user data), so keep the
`rmcp` target at `info` or above; and a panicking tool's message still
reaches the process's panic hook before the boundary catches it.

### Rate limiting

```rust
use std::sync::Arc;
use stridelabs_mcp::{MemoryLimiter, RateClass, RateLimiter, ToolCall};

const GENERATE: RateClass = RateClass("generate");

// Once, in the app state: one limiter shared by every handler instance (the
// stateless router builds a handler per request).
let limiter: Arc<dyn RateLimiter> = Arc::new(MemoryLimiter::new([(RateClass::READ, 60), (GENERATE, 6)]));

// Per tool:
ToolCall::new("create_image")
    .scopes(["image:generate"])
    .rate_limit(limiter.clone(), GENERATE)
```

- **The order is Python's**: authenticate, check scopes, then count. A call
  refused for its scopes (or never routed: bad arguments, an unknown tool)
  consumes nothing. Every run that passes the scopes counts, refused ones
  included, as Redis's `INCR` does.
- **The check runs inside the call's timeout, cancellation and panic
  capture**, together with the body: a limiter that hangs ends the call as
  `timeout`, one that panics as `internal`, and a cancelled request stops
  waiting for it. (A deliberate broadening: Python's timeout covered the
  body alone.) The body gets what is left of the deadline.
- **A fixed one-minute window**, `unix_seconds / 60` per `(subject, class)`,
  not a sliding one; the refusal's "Retry in N seconds" is what is left of
  the current window. A class with no limit, or a limit of 0, is not limited
  (and not counted).
- **`MemoryLimiter`'s windows only move forward**: it reads the clock inside
  its lock, and a reading from an earlier window than the newest it has seen
  (a delayed check, a clock stepped back) counts against the newest window
  instead of reopening an old one or resetting the current one. Counts are
  `u64`, so even a limit of `u32::MAX` refuses the call after it. An
  injected clock (`with_clock`, on either limiter) must itself be
  `UnwindSafe + RefUnwindSafe`.
- **`RateClass` is the app's vocabulary** (`RateClass("generate")`);
  `RateClass::READ` and `RateClass::WRITE` are Python's two default buckets.
- **Implementations.** `NoLimit`; `MemoryLimiter` (in process; its counts
  are dropped when the window rolls over, so memory is bounded by the
  subjects active in one minute); `RedisRateLimiter` (feature `redis`, below).
  Your own: implement `RateLimiter::check` (object-safe, a boxed `Send`
  future). Every `Err` it returns is shown to the model as a refusal; what a
  failure of its own store means is its policy — fail open, as the house
  rule is. The trait requires `UnwindSafe + RefUnwindSafe`, so that a
  `ToolCall` holding one keeps those auto traits; a limiter whose state a
  panic cannot leave half-updated asserts them (`impl UnwindSafe for …`), as
  `RedisRateLimiter` does.

### slauth PATs: `SlauthPatCredential` and its cache

```rust
use stridelabs_auth::{PatValidator, SLAUTH_PAT_PREFIX};
use stridelabs_mcp::{McpVerifier, RedisPatCache, SlauthPatCredential};

// The validator's client MUST follow no redirects (below).
let no_redirects = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .build()?;
let pats = SlauthPatCredential::new(
    PatValidator::new(&config.slauth_pat_validate_url, no_redirects),
    ["image:generate"],                                        // the PAT ceiling
)
.with_cache(RedisPatCache::new(redis.clone(), "imgmcp:pat:validate"));
let verifier = McpVerifier::new(&resource, &config.slauth_jwks_url, http)
    .with_credential(SLAUTH_PAT_PREFIX, pats);
```

**The `PatValidator`'s client must not follow redirects**
(`reqwest::redirect::Policy::none()`; reqwest's default follows them). The
client is yours, so its TLS stack and roots stay your choice — and so does
its redirect policy. With a following client, a redirect back to the
validate URL itself (`POST` → `303` → `GET` of the same URL) is
indistinguishable from slauth answering: whatever answers the `GET` is taken
as the verdict, and a success is then cached. The validator's final-URL check
(an answer from anywhere else is a service error) is defence in depth, not a
substitute; see stridelabs-auth's README.

| slauth's answer (`PatValidator::validate`) | Result |
|---|---|
| the identity | a `Principal`: subject = the identity UUID (hyphenated), scopes = **exactly the ceiling**, `AuthMethod::Token`, no email, name or client id |
| `Rejected` (malformed, unknown, revoked, expired) | `VerifyError::Invalid(reason)` → `401 invalid_token` |
| `Unavailable` (slauth down, slow, or answering nonsense) | `VerifyError::Unavailable(reason)` → `503`; the client keeps its token |

The cache (optional, any `PatCache`) follows Python imgmcp's rules, tightened:

- **The key is a digest, never the token**: the first 32 lowercase hex
  characters of the token's SHA-256 (`pat_cache_key`), namespaced by the
  cache. `RedisPatCache` **requires** a prefix (`{prefix}:{digest}`), so
  verifiers sharing a Redis never share each other's positive results. It is
  used as given, unchecked: a unique prefix per verifier is the caller's to
  choose.
- **Only a success is stored: the identity and an absolute expiry**
  (`CachedPat`: the validation's start plus `PAT_CACHE_TTL`, 120 s by
  default; `with_cache_ttl` changes it). The TTL is whole seconds rounded
  **down**, so the one given is a true bound on staleness, from 1 s to
  `PAT_CACHE_MAX_TTL` (a day; `Duration::MAX` is a day). `RedisPatCache`
  stores `{uuid}:{expires_at}` (Unix seconds); anything else there, a bare
  UUID included, is malformed. The ceiling is applied afresh on every hit; a
  rejection or an outage is never cached.
- **Fail-through.** A cache error, a malformed value, or any cache operation
  slower than `PAT_CACHE_TIMEOUT` (250 ms) is a `warn` line and a direct
  validation against slauth. After a failed read nothing is written back; a
  failed write still returns the success, with no second validation.
- **The expiry is absolute, and the credential enforces it**: an entry read
  at or after its `expires_at` is a miss, whatever the store's own TTL says.
  So nothing stretches it — not a hit (which writes nothing), and not a
  write that lands late: a `SET` Redis runs after the credential gave up on
  it at 250 ms restarts the key's own TTL (`SET … EX`, housekeeping only),
  but the value it carries still expires 120 s after the validation.
  `with_clock` injects the clock that stamps and judges expiries, for tests.

**Staleness:** a cached success is trusted until its expiry, so a PAT revoked
in slauth keeps working here for up to the TTL after the validation that
cached it — 120 s by default, Python's trade-off, and a bound that holds
against late writes (given that the instances sharing a cache keep their
clocks in step: the expiry is a wall-clock time). Shorten the TTL if that
window matters more than slauth's load.

### Redis (feature `redis`)

`RedisRateLimiter::new(handle, limits, prefix)` and
`RedisPatCache::new(handle, prefix)`, on stridelabs-redis's lazy,
single-flight `RedisHandle` (open it at boot: a malformed URL fails the boot,
not every command).

- The limiter's key is Python's, `{prefix}:{subject}:{class}:{unix_minute}`
  (`DEFAULT_RATE_LIMIT_PREFIX` is Python's `mcp:rl`; give each service its
  own on a shared Redis). The hit is stridelabs-redis's atomic
  `fixed_window_hit` (`INCR`, plus the 60 s `EXPIRE` on the first hit, in one
  script), **never replayed** after a lost reply.
- **It fails open**: any Redis error is a `warn` line on
  `stridelabs.mcp.ratelimit` (`RATE_LIMIT_LOG_TARGET`) and an allowed call.
  The limit is a cost bound, not an authorization check.
- `rediss://` means rustls: stridelabs-redis installs **no** crypto provider,
  so install aws-lc-rs at startup (`stridelabs_http::tls::install_default_provider`,
  stridelabs-http feature `tls`) — see stridelabs-redis's README.

### Image fetch (feature `image-fetch`)

```rust
let fetcher = stridelabs_mcp::ImageFetcher::new(10 * 1024 * 1024, "The image is too large (max 10 MB).");
let bytes = fetcher.fetch(&args.source).await?;   // ImageFetchError -> ToolError::user
```

Python `stridelabs.mcp.fetch`'s policy, step for step, with its messages byte
for byte:

- **`data:` URIs** (the scheme case-insensitive, no network): the media type
  must be `image/*` and name neither SVG nor XML, the payload `;base64` —
  whitespace and line wrapping tolerated, capped *before* decoding (base64
  grows 4/3), decoded strictly (CPython's `validate=True`), and capped again
  after.
- **`https://` URLs** through stridelabs-http's `fetch_public`: https only
  ("Only https:// image URLs (or data: URIs) are allowed."), no embedded
  credentials, no metadata hosts, every resolved address public and the
  connection pinned to one, **no redirects**, `Accept: image/*`, the body
  capped at `max_bytes`, 10 s for everything (`IMAGE_FETCH_TIMEOUT`). Then
  the `Content-Type` must be `image/*`, not SVG, not ending in `xml`.
- **Then the bytes are sniffed** on both paths — JPEG, PNG, GIF or WebP magic,
  whatever the headers said. The caller still re-encodes or stores them as
  its final sanitizer.

The fetcher builds its https policy itself, and its setters change only what
cannot weaken it — the cap, https only, no redirects and `Accept: image/*`
stay: `with_resolver` (the DNS seam; every answer is still judged by the
address policy), `with_timeout` (the budget), and, with this crate's
`test-support` (which turns on stridelabs-http's `ssrf-test-support`),
`with_loopback_test_server` for a local TLS test server. Differences from
Python are stridelabs-http's SSRF ones (its README): notably a compressed
response is refused, not decoded.

### CORS (feature `cors`)

`cors_layer()`: any origin, **no credentials** (bearer tokens, never
cookies), the preflight's method and headers mirrored back (a `*` would not
cover `Authorization`), `Mcp-Session-Id` and `WWW-Authenticate` exposed so a
browser client can read a `401`'s `resource_metadata`, preflights cacheable
for 600 s. Apply it **app-wide**, outermost but for the request log, so it
answers preflights before the auth layer and decorates its `401`/`403`/`503`:

```rust
let app = app
    .merge(stridelabs_mcp::metadata_router(&resource))
    .merge(stridelabs_mcp::router(auth, mcp_config, factory))
    .layer(stridelabs_mcp::cors_layer());
```

### The tools snapshot

A service with no REST API has no OpenAPI document; its contract is its tool
list. `canonical_tools_json(&tools)` renders `{"tools": [...]}` sorted by
name with every key sorted, LF and one trailing newline — byte-stable
whatever order the router lists and whatever `serde_json` features the graph
unified. Unconditional, so the service binary can print it
(`svc tools > mcp-tools.json`); the check is test-support's
`assert_committed_tools_are_fresh(path, &json, "<regen command>")`, which
names the first differing line (or the CRLF / trailing-newline problem) and
the command to run. Pin the file to LF in `.gitattributes`
(`mcp-tools.json text eol=lf`).

### Reading the principal

`stridelabs_mcp::principal(&ctx) -> Option<&Principal>` reads it from the
HTTP `Parts` rmcp puts into `ctx.extensions`; `ToolCall::run` does this for
you.

## Feature topology

`default = []`.

| Feature | Default | Adds |
|---|---|---|
| `test-support` | off | `test_support`: `access_token(&resource)` mints MCP access tokens (subject, scopes, client id, expiry, any claim) with stridelabs-auth's committed throwaway keys; `jwks_json()` is the matching key set; `check_committed_tools` / `assert_committed_tools_are_fresh` for `mcp-tools.json`. With `image-fetch`, also turns on stridelabs-http's `ssrf-test-support` |
| `cors` | off | `cors_layer()`, via tower-http's `cors`. No client, no TLS |
| `redis` | off | `RedisRateLimiter`, `RedisPatCache`, via stridelabs-redis — which brings rustls (redis-rs `tokio-rustls-comp`, with **no** provider: the app installs aws-lc-rs) |
| `image-fetch` | off | `ImageFetcher` / `ImageFetchError` (and re-exports `SsrfError`, `HostResolver`, and with `test-support` `LoopbackTestServer`), via stridelabs-http's `ssrf` — an HTTP client and TLS stack (reqwest `rustls`, aws-lc-rs) — and `base64` |
| `live-tests` | off | **Not for consumers.** Compiles this crate's real-Redis suite (`tests/redis_live.rs`), which needs a running Redis and panics without one. On in the workspace's all-features lane |

Dependencies a production graph gets from the core: rmcp (`server`,
`transport-streamable-http-server`, `schemars`; default features off, so no
HTTP client, no `oauth2`), stridelabs-auth (`axum`), axum, tower, `sha2` and
`uuid` (both already there through stridelabs-auth), and a `reqwest` with
**no features**: `McpVerifier::new` takes the app's client, so the TLS stack
(and the process's rustls provider) stays the app's choice. CI's "Guard:
stridelabs-mcp pulls no rustls" keeps it that way for the core, `cors` and
`test-support`; `redis` and `image-fetch` are TLS by design, and their own
guard holds rustls to aws-lc-rs, with no `ring` anywhere.

## Testing a consumer

With `test-support`, serve the test key set and mint tokens:

```rust
use stridelabs_mcp::test_support::{access_token, jwks_json};

let jwks = stridelabs_testing::serve_json(200, serde_json::from_str(jwks_json())?).await;
let verifier = McpVerifier::new(&resource, format!("{}/jwks", jwks.uri()), reqwest::Client::new());
let config = stridelabs_mcp::server_config(&resource, ["127.0.0.1"]);   // a loopback test server

let token = access_token(&resource).subject("user-1").scopes(["parcel:read"]).mint();
// POST http://127.0.0.1:<port>/mcp with
//   Authorization: Bearer {token}
//   Content-Type: application/json
//   Accept: application/json, text/event-stream
//   MCP-Protocol-Version: 2025-06-18
```

(`serve_json` answers every path; with `wiremock` directly, answer
`GET /jwks` with `jwks_json()` as `application/json`.) The rejection shapes
are one call each: `.expires_in(-3600)` (jsonwebtoken allows 60 s of
leeway, so a token a few seconds past `exp` still verifies),
`.signed_by_untrusted_key()`, `.claim("aud", json!("other"))`,
`.subject("")`.

Offline doubles for the rest: `MemoryLimiter::new(..).with_clock(|| t)` pins
the window (and `RedisRateLimiter::with_clock` for a live Redis test); any
`PatCache` (an in-memory map) stands in for Redis; a wiremock answering
`POST /api/v1/pat/validate` stands in for slauth. `tests/` here has worked
examples of each, and `PARITY.md` maps the Python package's tests onto them.

## Not included

From the Python package, deliberately left out: the quota base class (a
quota is the app's own check; `ToolError::denied` is its refusal), per-call
DB sessions (the app owns its pool and transactions), the per-tool kill
switch (rmcp's `ToolRouter::with_disabled` / `disable_route` already does
it; give the handler the configured router and use
`#[tool_handler(router = self.tool_router)]`), Python's scope-derived
`resolve_rate_class` (a tool names its class in `ToolCall::rate_limit`), and
the SSRF core itself, which lives in stridelabs-http's `ssrf` feature (this
crate's `image-fetch` is the image layer on top of it). See `PARITY.md` for
the test-by-test map.
