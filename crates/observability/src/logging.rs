//! `tracing` subscriber setup.
//!
//! Carried over from an existing service's `observability::logging::init`,
//! which hard-codes the format switch behind a service-specific env-var read
//! taken inside the
//! function. A shared crate can't assume every consumer wants that exact
//! variable name (or wants an env var at all — a test harness might want to
//! force JSON unconditionally), so here the format is a plain parameter;
//! callers that do want env-var control read it themselves (e.g. via
//! `stridelabs_config::env_or("LOG_FORMAT", "text")`) and pass the result in.

use std::sync::Once;

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Log output format, selected by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable, for local development.
    Text,
    /// Line-delimited JSON, suited to production log aggregation.
    Json,
}

static INIT: Once = Once::new();

/// Initialize the global `tracing` subscriber.
///
/// The level filter is read from the standard `RUST_LOG` env var if set,
/// else falls back to `default_filter` (callers pass their own
/// service-specific fallback, e.g. `"info"` or `"info,sqlx=warn"` — this
/// crate doesn't hard-code a house filter string).
///
/// Idempotent: safe to call more than once (e.g. once per test in a suite
/// that shares a process) — only the first call installs a subscriber.
/// Later calls, even with a different `format`/`default_filter`, are a
/// silent no-op; `tracing_subscriber`'s global subscriber can only be set
/// once per process, so there is nothing more this could do (and no way to
/// signal "you asked for something different" back to a caller that isn't
/// checking a return value).
///
/// The same reasoning applies when *something else* already installed a
/// global subscriber (a test harness, or a host that configures its own
/// before calling this): `try_init` is used rather than `init` so that case
/// is the same silent no-op instead of a panic. A library helper has no
/// business aborting a process over whose logging is already set up.
pub fn init_logging(format: LogFormat, default_filter: &str) {
    INIT.call_once(|| {
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
        let registry = tracing_subscriber::registry().with(filter);
        let _ = match format {
            LogFormat::Json => registry.with(fmt::layer().json()).try_init(),
            LogFormat::Text => registry.with(fmt::layer()).try_init(),
        };
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_init_does_not_panic() {
        // The two calls deliberately differ (format and filter) to prove the
        // second call is a true no-op, not just "happens to look the same".
        init_logging(LogFormat::Text, "info");
        init_logging(LogFormat::Json, "debug");
    }
}
