//! Shared HTTP plumbing for StrideLabs axum services: the house error type
//! and its wire representation, ready-made security-header and CORS layers,
//! graceful-shutdown primitives, and (behind features) the mechanical layer
//! of a reverse proxy, an SSRF-hardened outbound fetch, and the process-wide
//! rustls provider install.
//!
//! Extracted from an existing service's `error.rs` (the [`error::AppError`]
//! enum and its redacting [`axum::response::IntoResponse`] impl) and a
//! production reverse proxy's `http::{server,proxy,body,client}` (the
//! shutdown pair and the whole of
//! `proxy`). The pieces that were only ever
//! *implicit* in those services — a security-headers layer, an
//! explicit-origin CORS builder — are written here as first-class API so
//! every service gets them by adding a layer rather than by remembering to.
//!
//! # Feature topology
//!
//! `default = []`. Everything unconditional here (`error`, `headers`,
//! `methods`, `shutdown`) is wanted by every axum service, so gating it
//! would only add friction. `methods` is pure `axum::routing` — no
//! `reqwest`, no client, nothing the `proxy` gate exists to keep out — which
//! is why it sits alongside `error`/`headers`/`shutdown` rather than behind
//! `proxy`, even though its first consumer uses it mostly on
//! reverse-proxy routes.
//!
//! Note that the feature-gated modules below are named in plain code spans,
//! never intra-doc links: every one of them is off by default, so a link
//! would be an unresolved-link warning on `cargo doc` without
//! `--all-features` (which is how a consumer documenting its own graph
//! usually builds). They resolve in the sidebar once the matching feature is
//! on, which is the only time they exist at all.
//!
//! | Feature | Default | Adds |
//! |---|---|---|
//! | `cors` | off | `cors::cors_layer`, via `tower-http/cors` |
//! | `openapi` | off | `openapi` — spec canonicalization, route enumeration and a freshness check, via `utoipa` |
//! | `proxy` | off | `proxy` — reverse-proxy primitives, plus `AppError::bad_gateway_upstream` (it takes a `reqwest::Error`) — via `reqwest`/`url`/`bytes`/`futures` (and `tokio/time`) |
//! | `ssrf` | off | `ssrf` — an SSRF-hardened outbound fetch (public-address policy, DNS pinning, capped body; request headers, statuses, validators, the answering hop's URL and headers), via `reqwest`/`url`/`bytes`/`futures` (and `tokio/time`, `tokio/net`) |
//! | `ssrf-decompress` | off | `ssrf` plus opt-in gzip/deflate decoding of a fetched body under a decoded-size cap (`ssrf::Decompression`), via `flate2` (pure Rust) |
//! | `ssrf-test-support` | off | `ssrf::LoopbackTestServer`, the one way to point a fetch at a local TLS test server — enable from `[dev-dependencies]`, and check the shipped graph for it (`ssrf` docs) |
//! | `tls` | off | `tls::install_default_provider`, making aws-lc-rs the process's rustls provider, via `rustls` |
//!
//! `proxy` is the one that really earns its gate: it pulls in an HTTP
//! *client* and a TLS stack, which no service that merely answers requests
//! should be compiling. Its items stay namespaced under `proxy` rather than
//! being re-exported at the crate root — `filter_headers` and `relay_response`
//! only mean anything in that context, and a dozen more names at the root
//! would bury the four that every service uses.
//!
//! `ssrf` shares `proxy`'s client stack and earns its gate the same way. It
//! is a separate feature because the two answer different questions —
//! `proxy` talks to an upstream the operator configured, `ssrf` to a URL
//! somebody else chose — and a service that needs one rarely needs the other.
//! `tls` is the smallest gate (one function), and is gated anyway because
//! that function is a direct `rustls` dependency, which a service with no
//! rustls in its graph has no reason to take on.
//!
//! `openapi` stays namespaced for the same reason as `proxy` (and pays a
//! smaller but real gate: `utoipa` drags a proc-macro crate in). It holds
//! only the *mechanics* of publishing a spec — canonical serialization,
//! `(method, path)` enumeration, a committed-file freshness check. The
//! document itself — security schemes, `info`, tags, which routes are in it
//! — is per-service policy and stays in the service; see that module's docs.
//!
//! # A deliberate exception to the workspace's "typed errors only" rule
//!
//! Every other crate in this workspace keeps `anyhow` out of its public API:
//! a library's error type is part of its contract, so it stays enumerable and
//! matchable (`thiserror`). [`error::AppError::Internal`] breaks that rule on
//! purpose. It sits at the *application* boundary, not a library one — the
//! thing on the other side of it is an axum handler whose failure modes are
//! open-ended by nature, and whose detail is logged and then thrown away
//! rather than matched on. `anyhow::Error` is the right type there, and
//! `#[from]` is what makes `?` work across a handler's whole zoo of
//! dependencies. This asymmetry is intentional; it is not an oversight to be
//! "fixed".

pub mod error;
pub mod headers;
pub mod methods;
pub mod shutdown;

#[cfg(feature = "cors")]
pub mod cors;

#[cfg(feature = "openapi")]
pub mod openapi;

#[cfg(feature = "proxy")]
pub mod proxy;

#[cfg(feature = "ssrf")]
pub mod ssrf;

#[cfg(feature = "tls")]
pub mod tls;

pub use error::{AppError, AppResult};
pub use headers::{security_headers, SecurityHeadersLayer};
pub use methods::{default_refusal, method_filter, refusing_unserved_over, CLASSIFIED_METHODS};
pub use shutdown::{shutdown_signal, wait_for_shutdown};

#[cfg(feature = "cors")]
pub use cors::cors_layer;
