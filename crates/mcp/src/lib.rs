//! The hardened middle of a StrideLabs MCP server: everything between an
//! HTTP request at `/mcp` and an app's tool code.
//!
//! The Rust twin of stridelabs-python's `stridelabs-mcp`, on
//! [rmcp](https://docs.rs/rmcp) (the official Rust MCP SDK). The app writes
//! its tools as an rmcp `ServerHandler`; this crate supplies:
//!
//! - [`ProtectedResource`] — the endpoint's canonical resource URL (the
//!   token audience slauth mints, validated by slauth's own rule), its
//!   issuer and scopes, and everything derived from them.
//! - [`metadata_router`] — the RFC 9728 protected-resource metadata document
//!   at both origin-root well-known paths.
//! - [`McpVerifier`] — slauth RS256 JWTs with audience = the resource URL
//!   (scopes from `scope` and Hydra's `scp`), plus app-verified credentials
//!   selected by prefix ([`CredentialVerifier`]); an issuer outage is
//!   [`VerifyError::Unavailable`], never a rejection.
//! - [`McpAuthLayer`] — the HTTP boundary: RFC 6750 `401`s carrying
//!   `resource_metadata` and the scope hint, `503` on an outage, the
//!   [`Principal`] into the request.
//! - [`server_config`] / [`router`] — rmcp's Streamable HTTP service,
//!   stateless with JSON responses, `Host`-checked against the resource, at
//!   exactly the resource's path, behind the auth layer.
//! - [`ToolCall`] — the tool boundary: principal, per-tool scopes, timeout,
//!   safe errors ([`ToolError`]), one audit line per run; plus
//!   [`clamp_limit`] / [`clamp_offset`] / [`Page`] for list tools.
//!
//! # Wiring
//!
//! ```no_run
//! use rmcp::handler::server::router::tool::ToolRouter;
//! use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig};
//! use rmcp::service::RequestContext;
//! use rmcp::{tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler};
//! use stridelabs_mcp::{McpAuthLayer, McpVerifier, ProtectedResource, ToolCall};
//!
//! #[derive(Clone)]
//! struct ParcelMcp {
//!     tool_router: ToolRouter<Self>,
//! }
//!
//! #[tool_router]
//! impl ParcelMcp {
//!     #[tool(description = "Who am I signed in as?")]
//!     async fn whoami(&self, ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
//!         ToolCall::new("whoami")
//!             .run(&ctx, |principal| async move {
//!                 Ok(CallToolResult::success(vec![ContentBlock::text(principal.subject)]))
//!             })
//!             .await
//!     }
//! }
//!
//! #[tool_handler(router = self.tool_router)]
//! impl ServerHandler for ParcelMcp {
//!     fn get_info(&self) -> ServerConfig {
//!         ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
//!     }
//! }
//!
//! # async fn wire(app: axum::Router, http: reqwest::Client) -> Result<axum::Router, Box<dyn std::error::Error>> {
//! let resource = ProtectedResource::new(
//!     "https://parcel.stridelabs.ai/mcp",
//!     "https://auth.stridelabs.ai",
//!     ["parcel:read", "parcel:write"],
//! )?;
//! let verifier = McpVerifier::new(&resource, "https://auth.stridelabs.ai/.well-known/jwks.json", http);
//! let config = stridelabs_mcp::server_config(&resource, ["parcel-abc123.a.run.app"]);
//!
//! let app = app
//!     .merge(stridelabs_mcp::metadata_router(&resource))
//!     .merge(stridelabs_mcp::router(McpAuthLayer::new(verifier), config, || {
//!         Ok(ParcelMcp { tool_router: ParcelMcp::tool_router() })
//!     }));
//! # Ok(app)
//! # }
//! ```
//!
//! # What stays in the app
//!
//! The scope taxonomy, which credentials besides slauth JWTs it accepts (and
//! how it validates them), mapping a [`Principal`] to its own user row, quotas
//! and rate limits, its database sessions, and the tools themselves.
//!
//! # rmcp
//!
//! rmcp's types are this crate's API (`ServerHandler`, `RequestContext`,
//! `CallToolResult`, `StreamableHttpServerConfig`), so a consumer depends on
//! the same major, `rmcp = { version = "3.5", default-features = false,
//! features = ["server", "macros"] }`; [`rmcp`] is re-exported for naming
//! types without that dependency. **Never enable rmcp's `local` feature**: it
//! compiles the Streamable HTTP service out.
//!
//! # Feature topology
//!
//! `default = []`.
//!
//! | Feature | Default | Adds |
//! |---|---|---|
//! | `test-support` | off | `test_support` — MCP access tokens for a `ProtectedResource`, signed with stridelabs-auth's committed throwaway keys, for consumers' end-to-end tests |
//!
//! As in stridelabs-auth, the feature-gated module is named in plain code,
//! not linked: it does not exist in a default build's docs.

pub mod auth;
pub mod metadata;
pub mod principal;
pub mod resource;
pub mod server;
pub mod tool;
pub mod verifier;

// Compiled for this crate's own tests whether or not the feature is on, so
// both test lanes run its tests; the feature only makes it public.
#[cfg(feature = "test-support")]
pub mod test_support;
#[cfg(all(test, not(feature = "test-support")))]
mod test_support;

pub use rmcp;

pub use auth::{McpAuthLayer, McpAuthService, AUTH_LOG_TARGET};
pub use metadata::metadata_router;
pub use principal::{AuthMethod, Principal, ScopeError};
pub use resource::{ProtectedResource, ResourceError, ResourceMetadata, METADATA_PATH};
pub use server::{principal, router, server_config, MAX_REQUEST_BODY_BYTES};
pub use tool::{
    clamp_limit, clamp_offset, Outcome, Page, ToolCall, ToolError, AUDIT_TARGET, DEFAULT_LIMIT,
    DEFAULT_TOOL_TIMEOUT, MAX_LIMIT,
};
pub use verifier::{CredentialVerifier, McpVerifier, VerifyError, VerifyFuture};
