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
- **`ToolCall`**: the tool boundary. Principal, per-tool scopes, timeout,
  safe errors (`ToolError`), exactly one audit line per run. Plus
  `clamp_limit` / `clamp_offset` / `Page` for list tools.

## Adding the dependency

```toml
[dependencies]
stridelabs-mcp = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.6.0" }
rmcp = { version = "3.5", default-features = false, features = ["server", "macros"] }

[dev-dependencies]
stridelabs-mcp = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.6.0", features = ["test-support"] }
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

The scope taxonomy; which credentials besides slauth JWTs it accepts, and how
it validates them (the `CredentialVerifier` it supplies); mapping a
`Principal` to its own user row (provisioning, linking by email when there is
one); quotas and rate limits; database sessions and transactions; settings
and their validation; and the tools themselves.

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

`ToolCall::new(name).scopes([..]).timeout(d).run(&ctx, |principal| async { … })`:

| Case | Result (`isError: true` unless ok) | `outcome` | `error_class` |
|---|---|---|---|
| body returns `Ok(result)` | the result | `ok` (`error` if the result is itself `isError`) | — (`CallToolResult`) |
| no principal (not behind the layer) | "Not authenticated." | `denied` | `NotAuthenticated` |
| missing scope | "Missing required scope(s): X. This credential grants: Y. Reconnect with the required scopes to use this tool." | `denied` | `ScopeError` |
| `ToolError::user(msg)` | `msg` | `error` | `ToolError::User` |
| `ToolError::denied(msg)` | `msg` | `denied` | `ToolError::Denied` |
| timeout (default 30 s) | "The operation timed out. Please try again." | `timeout` | `Timeout` |
| `ToolError::internal(e)` | "Internal server error." | `internal` | `e`'s type name |
| panic | "Internal server error." | `internal` | `panic` |
| request cancelled, or the call dropped | "The request was cancelled." | `cancelled` | `Cancelled` / `Dropped` |

Failures are tool results, not JSON-RPC errors, so the model sees them.
`ToolError::internal` keeps only the error's type name: an unexpected
error's message can carry user data, so it is dropped unread. There is no
blanket `From<E: Error> for ToolError`, on purpose: write `impl From<AppError>
for ToolError` mapping user-safe variants to `ToolError::user`, and `?` works.

Exactly **one** audit line per run of a tool's code, target
`stridelabs.mcp.tool`, message
`mcp_tool_call`: `tool`, `outcome`, `duration_ms`, `required_scopes`, `sub`,
`auth_method`, `scopes`, `client_id`, `error_class`. Never a token, email or
name. `INFO`; `WARN` for `timeout`/`cancelled`; `ERROR` for `internal`. A
dropped call still writes its line. A `tools/call` that rmcp answers before
any tool runs (arguments that don't deserialize: an `isError` result; an
unknown tool: a JSON-RPC error) writes none; log those in your
`ServerHandler::call_tool` if your audit trail needs them.

Two logging notes for a production subscriber: rmcp's own `debug` line for
each request includes its arguments (tool input is user data), so keep the
`rmcp` target at `info` or above; and a panicking tool's message still
reaches the process's panic hook before the boundary catches it.

### Reading the principal

`stridelabs_mcp::principal(&ctx) -> Option<&Principal>` reads it from the
HTTP `Parts` rmcp puts into `ctx.extensions`; `ToolCall::run` does this for
you.

## Feature topology

`default = []`.

| Feature | Default | Adds |
|---|---|---|
| `test-support` | off | `test_support`: `access_token(&resource)` mints MCP access tokens (subject, scopes, client id, expiry, any claim) with stridelabs-auth's committed throwaway keys; `jwks_json()` is the matching key set |

Dependencies a production graph gets: rmcp (`server`,
`transport-streamable-http-server`, `schemars`; default features off, so no
HTTP client, no `oauth2`), stridelabs-auth (`axum`), axum, tower, and a
`reqwest` with **no features**: `McpVerifier::new` takes the app's client, so
the TLS stack (and the process's rustls provider) stays the app's choice.
CI's "Guard: stridelabs-mcp pulls no rustls" keeps it that way.

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

## Not included

From the Python package, deliberately left out: Redis rate limiting and the
quota base class (app policy, and no Rust consumer needs them yet), per-call
DB sessions (the app owns its pool and transactions), the per-tool kill
switch (rmcp's `ToolRouter::with_disabled` / `disable_route` already does
it), and the SSRF-hardened fetch and image modules (they wait for the imgmcp
port, their first Rust consumer).
