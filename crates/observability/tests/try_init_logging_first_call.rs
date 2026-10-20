//! `try_init_logging_with` as the first logging initialization in a process.
//!
//! This file must keep exactly ONE `#[test]`. The subscriber, the `log`
//! bridge and the crate's one-time initialization are all process-global and
//! set once: any earlier call (another test in the same binary) would make
//! this one "already initialized". Cargo runs each file under `tests/` as its
//! own process, so a test alone in its file is guaranteed the first call.

use stridelabs_observability::{
    init_logging, try_init_logging_with, LogFormat, LoggingInitError, TargetCaps,
};
use tracing::Level;
use tracing_log::log;

/// A `log` logger to try setting after the bridge.
struct Foreign;

impl log::Log for Foreign {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, _: &log::Record<'_>) {}
    fn flush(&self) {}
}

static FOREIGN: Foreign = Foreign;

#[test]
fn the_first_call_installs_the_subscriber_and_the_log_bridge() {
    let caps = TargetCaps::new().cap("tungstenite", Level::INFO);
    // A `trace` default, so (with `RUST_LOG` unset) it is the caps, not the
    // level filter, that disable tungstenite's `trace` below.
    try_init_logging_with(LogFormat::Text, "trace", &caps)
        .expect("the first call in a fresh process installs");

    // The installed subscriber is the capped one, for `tracing` events and,
    // through the bridge, `log` records.
    assert!(!tracing::enabled!(target: "tungstenite::protocol", Level::TRACE));
    assert!(!log::log_enabled!(target: "tungstenite::protocol", log::Level::Trace));
    // The bridge is the process's `log` logger: no other can be set now.
    assert!(
        log::set_logger(&FOREIGN).is_err(),
        "the `log` bridge was not installed"
    );

    // Every later call says it installed nothing, whatever its arguments...
    let again = try_init_logging_with(LogFormat::Json, "info", &TargetCaps::new());
    assert!(
        matches!(again, Err(LoggingInitError::AlreadyInitialized)),
        "{again:?}"
    );
    // ...while the infallible two stay silent no-ops.
    init_logging(LogFormat::Cloud, "warn");
}
