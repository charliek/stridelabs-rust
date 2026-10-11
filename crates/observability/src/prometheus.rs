//! Prometheus recorder installation plus the small conventions every service
//! wires the same way: a bounded status-class label and a shared duration
//! histogram bucket list. Gated behind the `prometheus` feature (default
//! off) — most consumers don't render `/metrics`, and the exporter +
//! `metrics` facade would be dead weight for the ones that don't.
//!
//! Carried over from an existing service's `observability::prometheus`
//! (`install`, `status_class`, `DURATION_BUCKETS`). Deliberately NOT
//! extracted: that service's domain metric wrappers (`record_request`,
//! `InFlight`, the shadow-traffic and circuit-breaker gauges, …) — those are
//! bound to its specific
//! metric names and shadow-proxy domain, not a generic primitive. A consumer
//! defines its own metric names and emits through the `metrics` facade
//! directly; this module only owns recorder installation and the
//! `status_class`/`DURATION_BUCKETS` conventions.

use std::sync::{Mutex, OnceLock, PoisonError};

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

/// Held across the whole first install. `OnceLock` alone cannot serialize it:
/// two first callers can both find `HANDLE` empty, and the loser's
/// `install_recorder` then fails because the global recorder is already set.
static INSTALL: Mutex<()> = Mutex::new(());

/// [`install`] could not set the global recorder — in practice, because
/// something outside this crate already installed one.
#[derive(Debug, thiserror::Error)]
#[error("could not install the Prometheus recorder: {0}")]
pub struct PrometheusInstallError(String);

/// Install the global Prometheus recorder (idempotent) and return a handle
/// for rendering `/metrics`.
///
/// Safe to call more than once, and from several threads at once —
/// `metrics`'s global recorder can only be set once per process, so only the
/// first call actually installs one; every call, first or later, concurrent or
/// not, returns a clone of that same handle.
/// Returns an error rather than panicking when the recorder cannot be
/// installed: this crate's own callers are serialized, but a host that
/// installed its own global recorder first is a real, recoverable condition —
/// and a library has no business aborting the process over it.
pub fn install() -> Result<PrometheusHandle, PrometheusInstallError> {
    // Fast path once installed: no lock on the hot read.
    if let Some(handle) = HANDLE.get() {
        return Ok(handle.clone());
    }

    // The mutex guards no data, so a poisoned lock (a panic mid-install) is
    // safe to step over; the re-check below decides whether to install.
    let _first_install = INSTALL.lock().unwrap_or_else(PoisonError::into_inner);

    // A caller that waited on the lock finds the winner's handle here.
    if let Some(handle) = HANDLE.get() {
        return Ok(handle.clone());
    }

    let handle = builder()?
        .install_recorder()
        .map_err(|err| PrometheusInstallError(err.to_string()))?;

    // Only this critical section ever fills the cell, so it is still empty.
    Ok(HANDLE.get_or_init(|| handle).clone())
}

/// The exporter configuration [`install`] applies. Split out so a test can
/// render through the same wiring on a local recorder: the process-global one
/// can be set only once, so two tests installing it in parallel race.
fn builder() -> Result<PrometheusBuilder, PrometheusInstallError> {
    PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Suffix("duration_seconds".to_string()),
            DURATION_BUCKETS,
        )
        .map_err(|err| PrometheusInstallError(err.to_string()))
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
    use std::sync::{Arc, Barrier};

    use super::*;

    #[test]
    fn install_is_idempotent_and_returns_a_handle_both_times() {
        let a = install().expect("first install succeeds in a fresh process");
        let b = install().expect("second install returns the memoized handle");
        // Both calls hand back a handle over the same underlying registry,
        // so they must render identical output.
        assert_eq!(a.render(), b.render());
    }

    #[test]
    fn concurrent_first_installs_all_succeed_with_the_same_handle() {
        // The first `install()` in a process sets the global recorder; callers
        // racing for that first install must all get `Ok` rather than the
        // losers hitting "recorder already set". The barrier releases every
        // thread together so they all reach the not-yet-installed state at
        // once. (Another test may have installed already, in which case this
        // degrades to a concurrent-idempotence check; run alone it is the
        // first caller in the process.)
        const THREADS: usize = 16;
        let barrier = Arc::new(Barrier::new(THREADS));

        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    install()
                })
            })
            .collect();

        let renders: Vec<String> = workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .expect("a worker thread panicked")
                    .expect("every concurrent install succeeds")
                    .render()
            })
            .collect();

        // Nothing records into the global registry in this test binary, so
        // handles over the one installed recorder render identically.
        assert!(
            renders.windows(2).all(|pair| pair[0] == pair[1]),
            "handles disagree: {renders:?}"
        );
    }

    /// Every rendered line that names `metric`, in render order: its `# HELP`
    /// and `# TYPE` lines and every sample.
    fn lines_naming<'a>(scrape: &'a str, metric: &str) -> Vec<&'a str> {
        scrape.lines().filter(|l| l.contains(metric)).collect()
    }

    #[test]
    fn the_scrape_output_for_a_counter_gauge_and_duration_histogram_is_pinned() {
        // This is the text a Prometheus server parses, so a bump of the
        // exporter that changes it (naming, suffixes, bucket lines) must show
        // up here as a failing test rather than as a surprise on a dashboard.
        // `builder()` is the configuration `install()` uses: it applies
        // DURATION_BUCKETS to `*duration_seconds`, which is what makes that
        // one a real histogram. A local recorder keeps the test off the
        // process-global one.
        let recorder = builder().expect("bucket config is valid").build_recorder();
        let handle = recorder.handle();

        metrics::with_local_recorder(&recorder, || {
            metrics::describe_counter!("pin_requests", "Requests handled.");
            metrics::counter!("pin_requests", "route" => "/a").increment(3);
            metrics::describe_gauge!("pin_in_flight", "Requests in flight.");
            metrics::gauge!("pin_in_flight").set(2.0);
            metrics::describe_histogram!("pin_handler_duration_seconds", "Handler latency.");
            metrics::histogram!("pin_handler_duration_seconds").record(0.03);
        });

        let scrape = handle.render();

        assert_eq!(
            lines_naming(&scrape, "pin_requests"),
            [
                "# HELP pin_requests Requests handled.",
                "# TYPE pin_requests counter",
                "pin_requests{route=\"/a\"} 3",
            ],
            "counter lines in:\n{scrape}"
        );
        assert_eq!(
            lines_naming(&scrape, "pin_in_flight"),
            [
                "# HELP pin_in_flight Requests in flight.",
                "# TYPE pin_in_flight gauge",
                "pin_in_flight 2",
            ],
            "gauge lines in:\n{scrape}"
        );
        // One observation of 0.03 s: it falls in the 0.05 bucket and every
        // bucket above it, none below. The `le` values are DURATION_BUCKETS.
        assert_eq!(
            lines_naming(&scrape, "pin_handler_duration_seconds"),
            [
                "# HELP pin_handler_duration_seconds Handler latency.",
                "# TYPE pin_handler_duration_seconds histogram",
                "pin_handler_duration_seconds_bucket{le=\"0.001\"} 0",
                "pin_handler_duration_seconds_bucket{le=\"0.005\"} 0",
                "pin_handler_duration_seconds_bucket{le=\"0.01\"} 0",
                "pin_handler_duration_seconds_bucket{le=\"0.025\"} 0",
                "pin_handler_duration_seconds_bucket{le=\"0.05\"} 1",
                "pin_handler_duration_seconds_bucket{le=\"0.1\"} 1",
                "pin_handler_duration_seconds_bucket{le=\"0.25\"} 1",
                "pin_handler_duration_seconds_bucket{le=\"0.5\"} 1",
                "pin_handler_duration_seconds_bucket{le=\"1\"} 1",
                "pin_handler_duration_seconds_bucket{le=\"2.5\"} 1",
                "pin_handler_duration_seconds_bucket{le=\"5\"} 1",
                "pin_handler_duration_seconds_bucket{le=\"10\"} 1",
                "pin_handler_duration_seconds_bucket{le=\"+Inf\"} 1",
                "pin_handler_duration_seconds_sum 0.03",
                "pin_handler_duration_seconds_count 1",
            ],
            "histogram lines in:\n{scrape}"
        );
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
