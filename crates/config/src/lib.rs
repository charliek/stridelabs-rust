//! Shared config-loading primitives for StrideLabs services: env-var helpers,
//! layered YAML/JSON file loading with field-pathed parse errors, and a small
//! validation-error accumulator.
//!
//! Extracted from the config loaders of two existing services (the
//! `serde_path_to_error` load skeleton, the `Loaded`/base-dir pattern, the
//! error accumulator, the socket/fraction checks, and the
//! `env_or`/`env_parse`/`parse_string_array` helpers), so the same patterns
//! aren't reinvented per service. What is deliberately **not**
//! extracted: the env/CLI-overlay `ConfigOverrides` pattern — it is bound
//! to a given service's specific set of overridable knobs, not a generic
//! primitive (see this crate's README for the recommended equivalent).
//!
//! This crate has **no feature flags** — everything here is small and used
//! widely enough that gating it behind a feature would only add friction for
//! every consumer.

pub mod env;
pub mod file;
pub mod validate;

pub use env::{env_or, env_parse, parse_string_array, EnvError};
pub use file::{load_json, load_yaml, FileError, Loaded};
pub use validate::{validate_fraction, validate_socket_addr, Errors, ValidationError};
