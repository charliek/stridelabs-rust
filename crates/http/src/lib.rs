//! Shared HTTP plumbing for StrideLabs axum services: the house error type
//! and its wire representation, ready-made security-header and CORS layers,
//! and graceful-shutdown primitives.
//!
//! Extracted from spendwise-rs's `error.rs` (the [`error::AppError`] enum and
//! its redacting [`axum::response::IntoResponse`] impl) and limen's
//! `http::server` (the shutdown pair). The pieces that were only ever
//! *implicit* in those services — a security-headers layer, an
//! explicit-origin CORS builder — are written here as first-class API so
//! every service gets them by adding a layer rather than by remembering to.
//!
//! # Feature topology
//!
//! `default = []`. Everything unconditional here (`error`, `headers`,
//! `shutdown`) is wanted by every axum service, so gating it would only add
//! friction.
//!
//! | Feature | Default | Adds |
//! |---|---|---|
//! | `cors` | off | [`cors::cors_layer`], via `tower-http/cors` |
//!
//! A `proxy` feature (reverse-proxy primitives: hop-by-hop header filtering,
//! body buffering, `UpstreamClient`) is *reserved but not yet declared* — see
//! the comment in `Cargo.toml`. It is deliberately absent from the table
//! above rather than listed as "off", since `features = ["proxy"]` is a hard
//! resolver error today, not a no-op.
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
pub mod shutdown;

#[cfg(feature = "cors")]
pub mod cors;

pub use error::{AppError, AppResult};
pub use headers::{security_headers, SecurityHeadersLayer};
pub use shutdown::{shutdown_signal, wait_for_shutdown};

#[cfg(feature = "cors")]
pub use cors::cors_layer;
