//! A log capture for tests, shared by the integration tests (`common`) and
//! the unit tests in `src/auth/single_flight_tests.rs`, which include this
//! file by path. Only `std` and `tracing`, so it compiles in both.

use std::fmt::{self, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Every event (and span field) logged on this thread while the guard from
/// [`LogCapture::install`] lives, one line each: level, target, fields. A
/// thread-local default, so tests running in parallel never write into each
/// other's capture; drive the code under test on a current-thread runtime so
/// the tasks it spawns log on this thread too. Built on `tracing`'s own
/// `Subscriber` trait, so it adds no dependency.
#[derive(Clone, Default)]
pub struct LogCapture {
    lines: Arc<Mutex<Vec<String>>>,
    next_span: Arc<AtomicU64>,
}

impl LogCapture {
    /// This capture as the thread's default.
    ///
    /// tracing-core caches each callsite's interest. While at most one
    /// dispatcher is registered it computes that from whichever thread's
    /// default is current, so a callsite a parallel test hits first, with no
    /// capture on its thread, would be cached as never-enabled and skipped
    /// here too. With a second dispatcher alive for good, every rebuild asks
    /// all live dispatchers, this capture included.
    pub fn install(&self) -> tracing::subscriber::DefaultGuard {
        static SECOND: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
        SECOND.get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
        tracing::subscriber::set_default(self.clone())
    }

    pub fn text(&self) -> String {
        self.lines.lock().unwrap().join("\n")
    }

    fn push(&self, line: String) {
        self.lines.lock().unwrap().push(line);
    }
}

struct Fields(String);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

impl tracing::Subscriber for LogCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut fields = Fields(format!("span {}", span.metadata().name()));
        span.record(&mut fields);
        self.push(fields.0);
        tracing::span::Id::from_u64(self.next_span.fetch_add(1, Ordering::SeqCst) + 1)
    }

    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut fields = Fields("span record".to_owned());
        values.record(&mut fields);
        self.push(fields.0);
    }

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let metadata = event.metadata();
        let mut fields = Fields(format!("{} {}", metadata.level(), metadata.target()));
        event.record(&mut fields);
        self.push(fields.0);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}
