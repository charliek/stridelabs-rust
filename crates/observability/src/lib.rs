//! Shared observability primitives for StrideLabs services: `tracing`
//! subscriber setup, a real tower request-id layer, and (behind the
//! `prometheus` feature) Prometheus recorder wiring.
//!
//! Extracted from limen's `observability` module (`logging`, `request_id`,
//! `prometheus`). Two deliberate departures from the limen originals, both
//! because a shared crate can't assume a specific service's env-var or
//! metric-naming conventions:
//!
//! - [`logging::init_logging`] takes its [`logging::LogFormat`] as a
//!   parameter instead of reading a hard-coded env var (`LIMEN_LOG_FORMAT`)
//!   inside the function — callers source the format from their own config
//!   (e.g. via `stridelabs_config::env_or`).
//! - `request_id` is a real [`tower::Layer`]/[`tower::Service`] pair
//!   (`RequestIdLayer`), not a pair of free functions called by hand at the
//!   proxy call site — so any axum/tower service gets extension-insertion
//!   and response-echo (including on error responses) just by adding the
//!   layer, rather than every consumer wiring the plumbing itself.
//!
//! `prometheus` is off by default (`default = []`) — most consumers don't
//! render `/metrics`, and pulling in the exporter + `metrics` facade
//! unconditionally would be dead weight for the ones that don't. See this
//! crate's README for the full feature topology.

pub mod logging;
pub mod request_id;

#[cfg(feature = "prometheus")]
pub mod prometheus;

pub use logging::{init_logging, LogFormat};
pub use request_id::{RequestId, RequestIdLayer, RequestIdService, REQUEST_ID_HEADER};

#[cfg(feature = "prometheus")]
pub use prometheus::{install, status_class, DURATION_BUCKETS};
