//! Assembling the authenticated, stateless MCP endpoint.
//!
//! rmcp's `StreamableHttpService` speaks the protocol; this module configures
//! it for StrideLabs deployments and puts [`McpAuthLayer`] in front of it.
//!
//! # Stateless, JSON responses
//!
//! [`server_config`] turns rmcp's legacy session mode off and JSON responses
//! on, and [`router`] serves with `NeverSessionManager`. MCP 2026-07-28 has no
//! sessions at all; for the older revisions clients still send (2025-03-26,
//! 2025-06-18, 2025-11-25), statelessness is what a Cloud Run service needs:
//! it scales to zero and gives no session affinity, so a session held in
//! one instance's memory is gone on the next request. Clients that
//! re-initialize per call (ChatGPT does) are served the same way. Each
//! `initialize` is answered without an `Mcp-Session-Id`, and every request
//! stands alone. A tool that emits a notification before its result (a
//! progress update) is answered as an SSE stream instead, so nothing is lost.
//!
//! # The route
//!
//! [`router`] returns a router with the endpoint at exactly
//! [`ProtectedResource::endpoint_path`] (`/mcp` for `https://host/mcp`).
//! **Merge it** (`app.merge(router)`); don't `nest` it: the path is already
//! the full one. `/mcp/` and anything below `/mcp` are not the endpoint and
//! answer `404` — rmcp's service ignores the path, so mounting it with
//! `nest_service("/mcp", …)` would serve MCP at every subpath, and a client
//! configured with `…/mcp/` would see metadata naming `…/mcp` and refuse it
//! anyway (RFC 9728 §3.3: the `resource` must match the URL used).
//!
//! # The `Host` check
//!
//! rmcp refuses (`403`) a request whose `Host` is not in `allowed_hosts`,
//! against DNS rebinding. Its default is loopback only, which refuses every
//! request a public deployment receives. [`server_config`] allows the
//! resource's host (on any port) plus the extras an app passes — a Cloud Run
//! `*.run.app` URL, `127.0.0.1` for a test server. Origin validation stays
//! rmcp's default (off): the endpoint takes bearer tokens only, never cookies,
//! so a cross-origin page has no ambient credential to abuse. An app that
//! wants it chains rmcp's own `.with_allowed_origins(…)`.

use std::iter;
use std::sync::Arc;

use axum::Router;
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{RoleServer, ServerHandler};
use tower::Layer;

use crate::auth::McpAuthLayer;
use crate::principal::Principal;
use crate::resource::ProtectedResource;

/// The largest JSON-RPC request body [`server_config`] accepts (`413`
/// beyond it): rmcp's own default, pinned here so an rmcp upgrade cannot
/// move it silently. Generous for model-written tool arguments, and room for
/// an image passed inline as a data URI.
pub const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

/// A stateless rmcp server configuration for `resource`: legacy sessions
/// off, JSON responses on, `allowed_hosts` = the resource's host plus
/// `extra_hosts` (`"host"` allows any port, `"host:port"` one), and a
/// [`MAX_REQUEST_BODY_BYTES`] body limit.
///
/// Chain rmcp's own builders for the rest, e.g.
/// `.with_cancellation_token(shutdown.child_token())` to end in-flight
/// requests at shutdown.
pub fn server_config<I, H>(
    resource: &ProtectedResource,
    extra_hosts: I,
) -> StreamableHttpServerConfig
where
    I: IntoIterator<Item = H>,
    H: Into<String>,
{
    let hosts =
        iter::once(resource.host().to_owned()).chain(extra_hosts.into_iter().map(Into::into));
    StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(hosts)
        .with_max_request_body_bytes(MAX_REQUEST_BODY_BYTES)
}

/// The authenticated MCP endpoint, at `auth`'s resource's
/// [`endpoint_path`](ProtectedResource::endpoint_path), as a router to
/// **merge** into the app.
///
/// `factory` builds the [`ServerHandler`] for each request (stateless: there
/// is no session to keep one in), so it should be cheap — clone an `Arc` of
/// app state into it. Every request passes [`McpAuthLayer`] first, which
/// puts the caller's [`Principal`] where [`principal()`] and
/// [`crate::ToolCall::run`] find it.
///
/// The service runs with no session manager, so `config`'s legacy session
/// mode is switched off whatever it says (with it on, every pre-2026
/// `initialize` would fail to create a session). Everything else in `config`
/// is used as given; build it with [`server_config`].
pub fn router<S, H, F>(
    auth: McpAuthLayer,
    config: StreamableHttpServerConfig,
    factory: F,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    H: ServerHandler,
    F: Fn() -> Result<H, std::io::Error> + Send + Sync + 'static,
{
    let path = auth.resource().endpoint_path().to_owned();
    let service = StreamableHttpService::new(
        factory,
        Arc::new(NeverSessionManager::default()),
        config.with_legacy_session_mode(false),
    );
    Router::new().route_service(&path, auth.layer(service))
}

/// The authenticated caller of the request `ctx` belongs to.
///
/// rmcp hands a tool the HTTP request's `Parts` (axum extensions included)
/// in `ctx.extensions`, and [`McpAuthLayer`] put the [`Principal`] there.
/// `None` only when the request did not come through the layer — an
/// in-process client, or an endpoint mounted without it; a tool should treat
/// that as unauthenticated ([`crate::ToolCall::run`] does).
pub fn principal(ctx: &RequestContext<RoleServer>) -> Option<&Principal> {
    ctx.extensions
        .get::<http::request::Parts>()?
        .extensions
        .get::<Principal>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource() -> ProtectedResource {
        ProtectedResource::new("https://parcel.stridelabs.ai/mcp", "https://auth", ["a"])
            .expect("canonical")
    }

    #[test]
    fn the_config_is_stateless_json_for_the_resource_host_and_extras() {
        let config = server_config(&resource(), ["parcel-abc.a.run.app", "127.0.0.1"]);

        assert!(!config.legacy_session_mode);
        assert!(config.json_response);
        assert_eq!(
            config.allowed_hosts,
            ["parcel.stridelabs.ai", "parcel-abc.a.run.app", "127.0.0.1"]
        );
        assert!(config.allowed_origins.is_empty());
        assert_eq!(config.max_request_body_bytes, MAX_REQUEST_BODY_BYTES);
    }

    #[test]
    fn with_no_extras_only_the_resource_host_is_allowed() {
        let config = server_config(&resource(), Vec::<String>::new());

        assert_eq!(config.allowed_hosts, ["parcel.stridelabs.ai"]);
    }
}
