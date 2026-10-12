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
    use super::*;

    #[test]
    fn install_is_idempotent_and_returns_a_handle_both_times() {
        let a = install().expect("first install succeeds in a fresh process");
        let b = install().expect("second install returns the memoized handle");
        // Both calls hand back a handle over the same underlying registry.
        // Two empty renders would be equal for unrelated registries too, so
        // record one sample through the global recorder and require both
        // handles to expose it. (The race between FIRST callers is covered by
        // tests/prometheus_concurrent_install.rs, a process of its own.)
        metrics::counter!("idempotent_install_probe_total").increment(1);
        for (which, handle) in [("first", &a), ("second", &b)] {
            let scrape = handle.render();
            assert!(
                scrape
                    .lines()
                    .any(|l| l == "idempotent_install_probe_total 1"),
                "the {which} handle does not see the probe sample:\n{scrape}"
            );
        }
    }

    /// What `record` observes, rendered through `builder()`'s configuration on a
    /// local recorder, which keeps the tests off the process-global one.
    fn render_recording(record: impl FnOnce()) -> String {
        let recorder = builder().expect("bucket config is valid").build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, record);
        handle.render()
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
        // one a real histogram.
        let scrape = render_recording(|| {
            metrics::describe_counter!("pin_requests", "Requests handled.");
            metrics::counter!("pin_requests", "route" => "/a").increment(3);
            metrics::describe_gauge!("pin_in_flight", "Requests in flight.");
            metrics::gauge!("pin_in_flight").set(2.0);
            metrics::describe_histogram!("pin_handler_duration_seconds", "Handler latency.");
            metrics::histogram!("pin_handler_duration_seconds").record(0.03);
        });

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

    /// What a default-summary histogram (no buckets configured for its name)
    /// renders for `metric` after observing 1.0 and 3.0 through `builder()`'s
    /// configuration: the quantile labels in render order, then every other
    /// line naming it (`# HELP`, `# TYPE`, `_sum`, `_count`). The quantile
    /// VALUES are left out on purpose: they are sketch estimates (the 0.5
    /// quantile of {1, 3} renders as 0.9998999999999999), not wire shape.
    fn summary_render(metric: &'static str, help: &'static str) -> (Vec<String>, Vec<String>) {
        let scrape = render_recording(|| {
            metrics::describe_histogram!(metric, help);
            metrics::histogram!(metric).record(1.0);
            metrics::histogram!(metric).record(3.0);
        });
        let lines = lines_naming(&scrape, metric);
        let quantiles = lines
            .iter()
            .filter_map(|l| l.split_once("quantile=\"")?.1.split_once('"'))
            .map(|(q, _)| q.to_string())
            .collect();
        let rest = lines
            .iter()
            .filter(|l| !l.contains("quantile=\""))
            .map(|l| l.to_string())
            .collect();
        (quantiles, rest)
    }

    const DEFAULT_QUANTILES: [&str; 7] = ["0", "0.5", "0.9", "0.95", "0.99", "0.999", "1"];

    #[test]
    fn a_histogram_without_buckets_renders_as_a_summary_with_sum_and_count() {
        // Only `*duration_seconds` gets buckets from `install()`; every other
        // histogram is a summary. Pinned so an exporter bump that changes the
        // quantile set or the `_sum`/`_count` series fails here.
        let (quantiles, rest) = summary_render("pin_payload_size", "Payload bytes.");

        assert_eq!(quantiles, DEFAULT_QUANTILES);
        assert_eq!(
            rest,
            [
                "# HELP pin_payload_size Payload bytes.",
                "# TYPE pin_payload_size summary",
                "pin_payload_size_sum 4",
                "pin_payload_size_count 2",
            ]
        );
    }

    #[test]
    fn a_summary_whose_name_ends_in_count_or_sum_loses_that_series_suffix() {
        // metrics-exporter-prometheus 0.18.3 appends `_count`/`_sum` to a
        // summary's name only when the name does not already END WITH
        // "count"/"sum" (`add_suffix_if_missing` in its formatting.rs is a
        // plain `ends_with("count")`, with no `_` in the comparison). So
        // `discount` renders its count series as `discount 2` where 0.17.2
        // rendered `discount_count 2`, and `checksum`'s sum as `checksum 4`
        // where 0.17.2 rendered `checksum_sum 4`. This is an upstream quirk,
        // pinned as OBSERVED so that an exporter release that fixes it shows
        // up as a deliberate edit to this test (and to the CHANGELOG entry
        // that documents it), not as a dashboard that quietly changed twice.
        let (quantiles, rest) = summary_render("pin_discount", "Ends in count.");
        assert_eq!(quantiles, DEFAULT_QUANTILES);
        assert_eq!(
            rest,
            [
                "# HELP pin_discount Ends in count.",
                "# TYPE pin_discount summary",
                "pin_discount_sum 4",
                "pin_discount 2",
            ]
        );

        let (quantiles, rest) = summary_render("pin_checksum", "Ends in sum.");
        assert_eq!(quantiles, DEFAULT_QUANTILES);
        assert_eq!(
            rest,
            [
                "# HELP pin_checksum Ends in sum.",
                "# TYPE pin_checksum summary",
                "pin_checksum 4",
                "pin_checksum_count 2",
            ]
        );
    }

    // Label KEYS that differ only in a character Prometheus replaces: the
    // exporter renders `"route-path"` and `"route_path"` both as `route_path`.
    //
    // metrics-exporter-prometheus 0.18.3 keeps a series' labels as the RAW
    // key/value pairs and sanitizes them only when it renders, so these are two
    // series that print with the same name and labels. 0.17.2 sanitized first,
    // so it merged them: a histogram's observations were pooled (`_sum 4`,
    // `_count 2`) and a counter or gauge printed ONE line holding whichever of
    // the two values it visited last (not their sum, and not the same one from
    // run to run). The four tests below pin the 0.18.3 output as OBSERVED, one
    // per metric kind, so that an exporter release that merges them again shows
    // up as a deliberate edit to these tests (and to the CHANGELOG entry that
    // documents it) rather than as a dashboard that quietly changed. The fix on
    // the caller's side is one spelling per label key.

    /// Every rendered line that starts with `prefix`, sorted. The exporter
    /// holds a family's series in a hash map, so the order of the series within
    /// a family differs from process to process; a test that cares about WHICH
    /// lines are rendered, not their order, compares the sorted lines.
    fn sorted_lines_starting<'a>(scrape: &'a str, prefix: &str) -> Vec<&'a str> {
        let mut lines: Vec<&str> = scrape.lines().filter(|l| l.starts_with(prefix)).collect();
        lines.sort_unstable();
        lines
    }

    #[test]
    fn sanitized_alike_label_keys_render_a_counter_as_two_lines() {
        let scrape = render_recording(|| {
            metrics::counter!("pin_dup_requests", "route-path" => "/a").increment(1);
            metrics::counter!("pin_dup_requests", "route_path" => "/a").increment(3);
        });

        assert_eq!(
            sorted_lines_starting(&scrape, "pin_dup_requests{"),
            [
                "pin_dup_requests{route_path=\"/a\"} 1",
                "pin_dup_requests{route_path=\"/a\"} 3",
            ],
            "counter lines in:\n{scrape}"
        );
    }

    #[test]
    fn sanitized_alike_label_keys_render_a_gauge_as_two_lines() {
        let scrape = render_recording(|| {
            metrics::gauge!("pin_dup_in_flight", "route-path" => "/a").set(1.0);
            metrics::gauge!("pin_dup_in_flight", "route_path" => "/a").set(3.0);
        });

        assert_eq!(
            sorted_lines_starting(&scrape, "pin_dup_in_flight{"),
            [
                "pin_dup_in_flight{route_path=\"/a\"} 1",
                "pin_dup_in_flight{route_path=\"/a\"} 3",
            ],
            "gauge lines in:\n{scrape}"
        );
    }

    #[test]
    fn sanitized_alike_label_keys_render_a_summary_as_two_series() {
        // A default-summary histogram (its name does not end `duration_seconds`):
        // two summaries, each with the observations of one spelling. Their
        // quantile VALUES are sketch estimates, so only the number of series is
        // pinned there.
        let scrape = render_recording(|| {
            metrics::histogram!("pin_dup_payload_size", "route-path" => "/a").record(1.0);
            metrics::histogram!("pin_dup_payload_size", "route_path" => "/a").record(3.0);
        });

        assert_eq!(
            sorted_lines_starting(&scrape, "pin_dup_payload_size_sum{"),
            [
                "pin_dup_payload_size_sum{route_path=\"/a\"} 1",
                "pin_dup_payload_size_sum{route_path=\"/a\"} 3",
            ],
            "summary sums in:\n{scrape}"
        );
        assert_eq!(
            sorted_lines_starting(&scrape, "pin_dup_payload_size_count{"),
            [
                "pin_dup_payload_size_count{route_path=\"/a\"} 1",
                "pin_dup_payload_size_count{route_path=\"/a\"} 1",
            ],
            "summary counts in:\n{scrape}"
        );
        assert_eq!(
            sorted_lines_starting(&scrape, "pin_dup_payload_size{")
                .into_iter()
                .filter(|l| l.contains("quantile=\"0.5\""))
                .count(),
            2,
            "median lines in:\n{scrape}"
        );
    }

    #[test]
    fn sanitized_alike_label_keys_render_a_bucketed_histogram_as_two_series() {
        // A `*duration_seconds` histogram, the only kind `install()` gives
        // buckets: two full bucket sets, one per spelling.
        let scrape = render_recording(|| {
            metrics::histogram!("pin_dup_handler_duration_seconds", "route-path" => "/a")
                .record(0.03);
            metrics::histogram!("pin_dup_handler_duration_seconds", "route_path" => "/a")
                .record(0.3);
        });

        assert_eq!(
            sorted_lines_starting(&scrape, "pin_dup_handler_duration_seconds_sum{"),
            [
                "pin_dup_handler_duration_seconds_sum{route_path=\"/a\"} 0.03",
                "pin_dup_handler_duration_seconds_sum{route_path=\"/a\"} 0.3",
            ],
            "bucketed sums in:\n{scrape}"
        );
        assert_eq!(
            sorted_lines_starting(&scrape, "pin_dup_handler_duration_seconds_count{"),
            [
                "pin_dup_handler_duration_seconds_count{route_path=\"/a\"} 1",
                "pin_dup_handler_duration_seconds_count{route_path=\"/a\"} 1",
            ],
            "bucketed counts in:\n{scrape}"
        );
        assert_eq!(
            sorted_lines_starting(
                &scrape,
                "pin_dup_handler_duration_seconds_bucket{route_path=\"/a\",le=\"+Inf\"}"
            ),
            [
                "pin_dup_handler_duration_seconds_bucket{route_path=\"/a\",le=\"+Inf\"} 1",
                "pin_dup_handler_duration_seconds_bucket{route_path=\"/a\",le=\"+Inf\"} 1",
            ],
            "bucketed +Inf lines in:\n{scrape}"
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
