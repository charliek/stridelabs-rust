//! Test-only helpers for this crate's logging tests: a writer that captures
//! what a layer writes, a strict JSON reading of it, and a clock that always
//! reads the same instant.

use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{Layer, Registry};

/// A [`MakeWriter`] appending everything written into one shared buffer, so
/// a test reads back exactly what a layer wrote — without stdout, and
/// without the process-global subscriber a test can't install or remove.
#[derive(Clone, Default)]
pub(crate) struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    /// Run `f` under a thread-scoped subscriber whose only layer is the one
    /// `make_layer` builds over a fresh capture, and return that capture.
    pub(crate) fn run<L>(make_layer: impl FnOnce(Capture) -> L, f: impl FnOnce()) -> Self
    where
        L: Layer<Registry> + Send + Sync + 'static,
    {
        let capture = Self::default();
        let subscriber = tracing_subscriber::registry().with(make_layer(capture.clone()));
        tracing::subscriber::with_default(subscriber, f);
        capture
    }

    /// Everything written so far, one entry per line.
    pub(crate) fn lines(&self) -> Vec<String> {
        std::str::from_utf8(&self.0.lock().unwrap())
            .expect("log output is UTF-8")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Every line parsed as one JSON object, failing the test on any line
    /// that isn't — including one repeating a key at any depth, which
    /// `serde_json::Value` would silently collapse to its last occurrence.
    pub(crate) fn json_lines(&self) -> Vec<Value> {
        self.lines()
            .iter()
            .map(|line| {
                let Strict(value) = serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("not a valid JSON line ({e}): {line}"));
                assert!(value.is_object(), "not a JSON object: {line}");
                value
            })
            .collect()
    }
}

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A JSON value deserialized with every object's keys checked for
/// uniqueness. Cloud Logging keeps one of a duplicated member, so a
/// duplicate is a real defect a `Value` comparison would hide.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let Strict(value) = map.next_value()?;
            if object.contains_key(&key) {
                return Err(A::Error::custom(format_args!("duplicate key {key:?}")));
            }
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// What [`FixedTime`] writes.
pub(crate) const FIXED_TIMESTAMP: &str = "2026-10-11T12:34:56.789012Z";

/// A clock stuck at [`FIXED_TIMESTAMP`], so tests can compare whole lines
/// byte for byte.
pub(crate) struct FixedTime;

impl FormatTime for FixedTime {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        w.write_str(FIXED_TIMESTAMP)
    }
}
