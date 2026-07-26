//! Prometheus recorder installation plus the small conventions every service
//! wires the same way: a bounded status-class label and a shared duration
//! histogram bucket list. Gated behind the `prometheus` feature (default
//! off) — most consumers don't render `/metrics`, and the exporter +
//! `metrics` facade would be dead weight for the ones that don't.
//!
//! Ported from limen's `observability::prometheus` (`install`,
//! `status_class`, `DURATION_BUCKETS`). Deliberately NOT ported: limen's
//! domain metric wrappers (`record_request`, `InFlight`, the shadow-traffic
//! and circuit-breaker gauges, …) — those are bound to limen's specific
//! metric names and shadow-proxy domain, not a generic primitive. A consumer
//! defines its own metric names and emits through the `metrics` facade
//! directly; this module only owns recorder installation and the
//! `status_class`/`DURATION_BUCKETS` conventions.

use std::sync::OnceLock;

use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

/// Latency histogram buckets in seconds (sub-millisecond to 10s), applied by
/// [`install`] to every metric whose name ends in `duration_seconds` — the
/// house convention for a duration histogram (e.g.
/// `http_request_duration_seconds`). A consumer's own duration metrics only
/// need to follow that naming suffix to pick up the same bucket boundaries.
pub const DURATION_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the global Prometheus recorder (idempotent) and return a handle
/// for rendering `/metrics`.
///
/// Safe to call more than once — `metrics`'s global recorder can only be set
/// once per process, so only the first call actually installs one; every
/// call, first or later, returns a clone of that same handle.
pub fn install() -> PrometheusHandle {
    HANDLE
        .get_or_init(|| {
            PrometheusBuilder::new()
                .set_buckets_for_metric(
                    Matcher::Suffix("duration_seconds".to_string()),
                    DURATION_BUCKETS,
                )
                .expect("duration buckets are non-empty")
                .install_recorder()
                .expect("install Prometheus recorder")
        })
        .clone()
}

/// The status *class* label for a numeric HTTP status code: `"1xx"` through
/// `"5xx"`, or `"other"` outside that range. Bucketing keeps label
/// cardinality low (a handful of values, not hundreds of distinct codes).
pub fn status_class(status: u16) -> &'static str {
    match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_is_idempotent_and_returns_a_handle_both_times() {
        let a = install();
        let b = install();
        // Both calls hand back a handle over the same underlying registry,
        // so they must render identical output.
        assert_eq!(a.render(), b.render());
    }

    #[test]
    fn status_class_boundaries() {
        assert_eq!(status_class(0), "other");
        assert_eq!(status_class(99), "other");
        assert_eq!(status_class(100), "1xx");
        assert_eq!(status_class(199), "1xx");
        assert_eq!(status_class(200), "2xx");
        assert_eq!(status_class(299), "2xx");
        assert_eq!(status_class(300), "3xx");
        assert_eq!(status_class(404), "4xx");
        assert_eq!(status_class(500), "5xx");
        assert_eq!(status_class(599), "5xx");
        assert_eq!(status_class(600), "other");
    }
}
