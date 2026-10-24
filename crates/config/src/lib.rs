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
//! # Feature topology
//!
//! | Feature | Default | Adds |
//! |---|---|---|
//! | `file` | **on** | the `file` module (`load_yaml`, `load_json`, `Loaded`, `FileError`), via `yaml_serde`, `serde_path_to_error` and `serde` |
//!
//! `file` is on by default, so naming the crate with no `features` gives
//! everything it always had. A service configured from its environment alone
//! sets `default-features = false` and gets the env helpers and the
//! validation accumulator with no YAML parser in its graph. (Items behind
//! `file` are named in plain code spans here, never intra-doc links, so the
//! docs build without it.)
//!
//! # Startup refusals
//!
//! A service that refuses to start on bad configuration should report every
//! problem at once, not the first: read each setting through the `_from`
//! seam ([`env_parse_from`], [`parse_string_array_from`], whose errors name
//! the variable and a fixed reason, never the value), and collect what it
//! refuses in an [`Errors`]. See [`Errors`] for the pattern.

pub mod env;
#[cfg(feature = "file")]
pub mod file;
pub mod validate;

pub use env::{
    env_or, env_or_from, env_parse, env_parse_from, parse_string_array, parse_string_array_from,
    EnvError, NOT_A_STRING_ARRAY, VALUE_DOES_NOT_PARSE,
};
#[cfg(feature = "file")]
pub use file::{load_json, load_yaml, FileError, Loaded};
pub use validate::{validate_fraction, validate_socket_addr, Errors, ValidationError};
