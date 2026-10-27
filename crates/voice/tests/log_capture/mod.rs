//! Capturing what the relay logs, as an app writes it: the observability
//! crate's `CloudLayer` (one Cloud Logging JSON object per line: `message`,
//! `logger` (the target), then the event's fields) behind an `EnvFilter`.
//!
//! Copied from tapper (`tapper-rs/tests/log_capture/mod.rs`, `82be95f`); the
//! one addition is [`capture_dispatch`], for a multi-thread runtime whose
//! workers each install it.
//!
//! Lives at `tests/log_capture/mod.rs`, not `tests/log_capture.rs`, so it is
//! a module of each binary that declares it and never a test binary of its
//! own.
//!
//! - **This thread only.** A `#[tokio::test]` runtime is current-thread, so
//!   what a test drives logs on its own thread (the served connections and
//!   the relay sessions are tasks on it), and a parallel test's lines never
//!   land in its capture.
//! - **Callsite interest.** `tracing-core` caches each callsite's interest,
//!   and while at most ONE dispatcher is registered it computes that interest
//!   from the CALLING THREAD's current dispatcher only: a parallel test that
//!   hits the same callsites without a subscriber then caches "never" for
//!   them, and a capture on another thread silently loses its lines. With two
//!   or more registered dispatchers the interest is the union over all of
//!   them, so the first capture registers a no-op one for the life of the
//!   process.
//! - **The `log` bridge.** Records a dependency writes through the `log`
//!   facade (tungstenite's frame dumps, among others) are captured too: an
//!   app's `.try_init()` bridges them into the same layer, so a capture
//!   without the bridge would pass a secret logged that way. The bridge
//!   (`LogTracer`) is the process's one global logger, installed by the first
//!   capture; it hands each record to the CURRENT dispatcher, which during a
//!   capture is this thread's.

use std::io;
use std::sync::{Arc, Mutex, OnceLock};

use stridelabs_observability::CloudLayer;
use tracing_subscriber::prelude::*;

/// What a capture's `CloudLayer` wrote.
#[derive(Clone, Default)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("the capture").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Capture {
    /// Everything written so far.
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("the capture").clone()).expect("log output is UTF-8")
    }

    /// Every line written so far, each required to be one JSON object.
    pub fn lines(&self) -> Vec<serde_json::Value> {
        self.text()
            .lines()
            .map(|line| {
                let value: serde_json::Value = serde_json::from_str(line)
                    .unwrap_or_else(|failure| panic!("not a JSON line ({failure}): {line}"));
                assert!(value.is_object(), "not a JSON object: {line}");
                value
            })
            .collect()
    }
}

/// The library's `CloudLayer` behind `filter` (`EnvFilter` directives;
/// `"trace"` is every level), as a dispatcher a thread can install, with the
/// process-wide `log` bridge and the no-op second dispatcher in place; and
/// what it captures.
pub fn capture_dispatch(filter: &str) -> (Capture, tracing::Dispatch) {
    static KEEP: OnceLock<tracing::Dispatch> = OnceLock::new();
    KEEP.get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
    static LOG_BRIDGE: OnceLock<()> = OnceLock::new();
    LOG_BRIDGE.get_or_init(|| {
        tracing_log::LogTracer::init()
            .expect("the `log` bridge installs: nothing else in this binary sets a logger");
    });
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(filter))
        .with(CloudLayer::new(move || writer.clone()));
    (capture, tracing::Dispatch::new(subscriber))
}

/// [`capture_dispatch`] as this thread's default subscriber. Hold the guard
/// for as long as the capture should last.
pub fn capture_logs(filter: &str) -> (Capture, tracing::dispatcher::DefaultGuard) {
    let (capture, dispatch) = capture_dispatch(filter);
    (capture, tracing::dispatcher::set_default(&dispatch))
}
