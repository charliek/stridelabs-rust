//! `try_init_logging_with` after something else installed the global
//! `tracing` subscriber (a test harness, a host that set up its own).
//!
//! This file must keep exactly ONE `#[test]`: it needs a process whose
//! global subscriber it set itself, which only a test alone in its binary
//! (Cargo runs each file under `tests/` as its own process) is guaranteed.

use stridelabs_observability::{try_init_logging_with, LogFormat, LoggingInitError, TargetCaps};
use tracing::subscriber::NoSubscriber;
use tracing::Level;

#[test]
fn a_call_after_another_subscriber_reports_that_it_installed_nothing() {
    tracing::subscriber::set_global_default(NoSubscriber::default())
        .expect("a fresh process has no global subscriber");

    let caps = TargetCaps::new().cap("tungstenite", Level::INFO);
    let first = try_init_logging_with(LogFormat::Text, "info", &caps);
    assert!(
        matches!(first, Err(LoggingInitError::SubscriberAlreadySet)),
        "{first:?}"
    );

    // The one attempt is spent, so a retry is told so rather than failing
    // the same way again.
    let again = try_init_logging_with(LogFormat::Text, "info", &caps);
    assert!(
        matches!(again, Err(LoggingInitError::AlreadyInitialized)),
        "{again:?}"
    );
}
