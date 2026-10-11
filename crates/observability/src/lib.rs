//! Shared observability primitives for StrideLabs services: `tracing`
//! subscriber setup, real tower request-id and request-logging layers, and
//! (behind the `prometheus` feature) Prometheus recorder wiring.
//!
//! Extracted from an existing service's `observability` module (`logging`,
//! `request_id`, `prometheus`). Two deliberate departures from the originals,
//! both because a shared crate can't assume a specific service's env-var or
//! metric-naming conventions:
//!
//! - [`logging::init_logging`] takes its [`logging::LogFormat`] as a
//!   parameter instead of reading a hard-coded, service-specific env var
//!   inside the function — callers source the format from their own config
//!   (e.g. via `stridelabs_config::env_or`).
//! - `request_id` is a real [`tower::Layer`]/[`tower::Service`] pair
//!   (`RequestIdLayer`), not a pair of free functions called by hand at the
//!   proxy call site — so any axum/tower service gets extension-insertion
//!   and response-echo (including on error responses) just by adding the
//!   layer, rather than every consumer wiring the plumbing itself.
//!
//! `cloud` is new here rather than extracted: [`cloud::CloudLayer`] writes
//! Google Cloud Logging structured lines (`severity`, a top-level
//! `message`, `httpRequest`, request/trace correlation) in the shape Python's
//! `stridelabs-logging` writes, selected by [`LogFormat::Cloud`] and, for
//! any non-development environment, by [`LogFormat::from_environment`].
//! [`REQUEST_SPAN_NAME`], [`REQUEST_ID_FIELD`] and [`TRACE_FIELD`] are the
//! contract a request span uses to put its ids on every line inside it.
//!
//! `request_log` is new too: [`RequestLogLayer`] is the outermost layer that
//! establishes each request's id, opens that request span (with the Cloud
//! Trace id from `X-Cloud-Trace-Context`), and writes one `httpRequest`
//! entry per request — Python's `RequestLoggingMiddleware`.
//!
//! `prometheus` is off by default (`default = []`) — most consumers don't
//! render `/metrics`, and pulling in the exporter + `metrics` facade
//! unconditionally would be dead weight for the ones that don't. See this
//! crate's README for the full feature topology.

pub mod cloud;
pub mod logging;
pub mod request_id;
pub mod request_log;

#[cfg(feature = "prometheus")]
pub mod prometheus;

#[cfg(test)]
mod test_support;

pub use cloud::{CloudLayer, REQUEST_ID_FIELD, REQUEST_SPAN_NAME, TRACE_FIELD};
pub use logging::{init_logging, LogFormat};
pub use request_id::{RequestId, RequestIdLayer, RequestIdService, REQUEST_ID_HEADER};
pub use request_log::{
    RequestLogConfig, RequestLogLayer, RequestLogService, DEFAULT_REDACTED_QUERY_PARAMS,
    REQUEST_LOG_TARGET,
};

#[cfg(feature = "prometheus")]
pub use prometheus::{install, status_class, DURATION_BUCKETS};
