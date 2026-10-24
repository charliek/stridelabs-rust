//! A recording `tracing` layer, shared by the unit tests (`src/lib.rs`
//! includes this file by path) and the live suite (`tests/live.rs`).

use std::fmt::{self, Write as _};
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::{Context, Layer};

/// Every event the subscriber it is layered into sees: its target and its
/// fields, rendered.
#[derive(Clone, Default)]
pub struct Recorded(Arc<Mutex<Vec<(String, String)>>>);

impl Recorded {
    /// The `(target, fields)` of every event recorded so far.
    pub fn events(&self) -> Vec<(String, String)> {
        self.0.lock().expect("recorder").clone()
    }
}

impl<S: tracing::Subscriber> Layer<S> for Recorded {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        let target = event.metadata().target().to_owned();
        self.0.lock().expect("recorder").push((target, fields.0));
    }
}

struct Fields(String);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

/// Whether one of `caps` turns `target` off: the cap's target itself or a
/// module path beneath it (`TargetCaps`' rule).
pub fn capped_off(caps: &[(&str, LevelFilter)], target: &str) -> bool {
    caps.iter().any(|(cap, level)| {
        *level == LevelFilter::OFF
            && target
                .strip_prefix(cap)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
    })
}
