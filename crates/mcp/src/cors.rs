//! The app-wide CORS preset for an MCP service (feature `cors`).
//!
//! Browser-based MCP clients (the claude.ai connector UI, the MCP Inspector)
//! reach `/mcp` cross-origin, and must be able to read the response headers
//! that drive the protocol from JavaScript: CORS hides every non-safelisted
//! response header unless it is exposed, and the RFC 9728 discovery a client
//! starts from a `401` lives in `WWW-Authenticate`.

use std::time::Duration;

use http::header::WWW_AUTHENTICATE;
use http::HeaderName;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};

/// The CORS layer for an MCP service: any origin, **no credentials**, the
/// preflight's requested method and headers mirrored back, and
/// `Mcp-Session-Id` and `WWW-Authenticate` exposed. Preflight answers are
/// cacheable for 600 s.
///
/// - **Any origin, no credentials.** MCP authenticates with bearer tokens,
///   never cookies, so a cross-origin page has no ambient credential to
///   abuse; with credentials off, `Access-Control-Allow-Origin: *` is valid.
/// - **Mirrored methods and headers**, because a `*`
///   `Access-Control-Allow-Headers` does not cover `Authorization` (the
///   Fetch standard carves it out of the wildcard), which every MCP request
///   carries.
/// - **Exposed headers**: `WWW-Authenticate`, so a browser client can read a
///   `401`'s `resource_metadata` and start OAuth discovery; `Mcp-Session-Id`
///   for the older protocol revisions' sessions (a stateless server never
///   sends one, but a client may look).
///
/// Apply it to the **whole app**, outermost but for the request log, so it
/// answers preflights before the auth layer sees them (tower-http treats
/// every `OPTIONS` as one) and decorates the auth layer's `401`/`403`/`503`
/// refusals as well as the endpoint's answers:
///
/// ```no_run
/// # fn wire(app: axum::Router) -> axum::Router {
/// let app = app.layer(stridelabs_mcp::cors_layer());
/// # app
/// # }
/// ```
pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::any())
        .allow_methods(AllowMethods::mirror_request())
        .allow_headers(AllowHeaders::mirror_request())
        .expose_headers([HeaderName::from_static("mcp-session-id"), WWW_AUTHENTICATE])
        .max_age(Duration::from_secs(600))
}
