# stridelabs-config

Env-var config helpers + layered YAML/JSON file loading with field-pathed
errors, for StrideLabs services. Extracted from limen's `config::load` /
`config::validate` and spendwise-rs's `config.rs`.

**No feature flags.** Everything in this crate is small and used widely
enough that gating any of it behind a feature would only add friction for
consumers — `default = []` isn't even meaningful here since there's nothing
to turn off.

## Adding the dependency

```toml
[dependencies]
stridelabs-config = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.4.0" }
```

(During development against an unreleased commit, pin `rev = "<sha>"`
instead of `tag`; see the workspace root README for the local `[patch]`
co-development snippet.)

## `env` — 12-factor environment variables

```rust
use stridelabs_config::{env_or, env_parse, parse_string_array, EnvError};

let log_format = env_or("LOG_FORMAT", "text");

let port: u16 = env_parse("PORT", 8080)?;

let cors_origins: Vec<String> = parse_string_array("CORS_ORIGINS")?;
# Ok::<(), EnvError>(())
```

- `env_or(key, default)` — missing, **empty**, or non-Unicode falls back to
  `default` (never errors; there's no sensible way to report "not Unicode"
  more usefully than "not set"). Empty counts as unset because that's how a
  variable arrives when a compose file writes `FOO:` or a k8s manifest writes
  `value: ""` — someone left it unfilled.
- `env_parse::<T>(key, default)` — missing or empty falls back to `default`;
  present-but-unparsable is `Err(EnvError)` naming the variable.
- `parse_string_array(key)` — parses a JSON array of strings
  (`CORS_ORIGINS=["https://a","https://b"]`); missing or blank yields `[]`;
  malformed JSON is `Err(EnvError)`.

Internally, all three route through an injectable lookup closure instead of
calling `std::env::var` directly, so unit tests never mutate the real process
environment (`std::env::set_var` races with every other test in the binary).

## `file` — layered YAML/JSON loading

```rust
use std::path::Path;
use serde::Deserialize;
use stridelabs_config::{load_yaml, Loaded};

#[derive(Deserialize)]
struct Config {
    listen_addr: String,
}

let Loaded { value, base_dir } = load_yaml::<Config>(Path::new("service.yaml"))?;
// `base_dir` is the config file's directory — use it to resolve any
// sibling file the config references by relative path.
# Ok::<(), stridelabs_config::FileError>(())
```

`load_yaml` and `load_json` are separate functions (no by-extension format
dispatch) so the caller states the intended format explicitly. `load_json`
rejects YAML syntax and trailing content after the document; note the reverse
is not symmetric — any valid JSON document is also valid YAML 1.2, so
`load_yaml` accepts JSON by nature of the format, not by dispatch. Parse
errors go through `serde_path_to_error`, so `FileError::Parse.message` names
the offending field path (e.g. `nested.port: invalid type: ...`), not just
"invalid YAML".

## `validate` — an error accumulator + common field checks

```rust
use stridelabs_config::{validate_fraction, validate_socket_addr, Errors};

fn validate(listen_addr: &str, sample_rate: f64) -> Result<(), Vec<stridelabs_config::ValidationError>> {
    let mut errs = Errors::new();
    validate_socket_addr("server.listen_addr", listen_addr, &mut errs);
    validate_fraction("sampling.rate", sample_rate, &mut errs);
    errs.into_result()
}
```

`Errors` collects every problem in one pass rather than bailing at the first
`?`. `validate_fraction` checks `0.0..=1.0` and is NaN-safe by construction
(range `contains` is false for NaN on both ends).

## What's not here

limen's `ConfigOverrides` (a merged env/CLI overlay applied on top of a
parsed file) is domain-bound to that service's specific set of overridable
knobs — it isn't a generic primitive, so it wasn't extracted. If a consumer
needs the same shape, define its own `Overrides` struct with `Option<T>`
fields, build it via `env::env_or`/`env_parse` against `Option`-wrapped
defaults, and apply it with a small `fn apply(&self, config: &mut Config)`
(see limen's `src/config/load.rs` for the pattern this crate deliberately
left in the consuming service).
