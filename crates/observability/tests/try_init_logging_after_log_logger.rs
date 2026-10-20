//! `try_init_logging_with` after something else set the `log` crate's
//! logger: the `tracing` subscriber installs, but the bridge can't, so `log`
//! records (tungstenite's) would bypass the caps.
//!
//! This file must keep exactly ONE `#[test]`: it needs a process whose `log`
//! logger it set itself and whose `tracing` subscriber is still unset, which
//! only a test alone in its binary (Cargo runs each file under `tests/` as
//! its own process) is guaranteed.

use stridelabs_observability::{try_init_logging_with, LogFormat, LoggingInitError, TargetCaps};
use tracing::Level;
use tracing_log::log;

/// Some other `log` backend (env_logger, say), set before logging is.
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
fn a_call_after_a_log_logger_reports_the_missing_bridge() {
    log::set_logger(&FOREIGN).expect("a fresh process has no `log` logger");

    let caps = TargetCaps::new().cap("tungstenite", Level::INFO);
    let first = try_init_logging_with(LogFormat::Text, "trace", &caps);
    assert!(
        matches!(first, Err(LoggingInitError::LogBridgeNotInstalled)),
        "{first:?}"
    );

    // The `tracing` half did install, caps and all, as the error says.
    assert!(tracing::dispatcher::has_been_set());
    assert!(!tracing::enabled!(target: "tungstenite::protocol", Level::TRACE));

    let again = try_init_logging_with(LogFormat::Text, "trace", &caps);
    assert!(
        matches!(again, Err(LoggingInitError::AlreadyInitialized)),
        "{again:?}"
    );
}
