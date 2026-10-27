# stridelabs-config

Env-var config helpers + layered YAML/JSON file loading with field-pathed
errors, for StrideLabs services.

## Feature topology

| Feature | Default | Adds |
|---|---|---|
| `file` | **on** | `load_yaml`, `load_json`, `Loaded`, `FileError` (the `file` module), via `yaml_serde`, `serde_path_to_error` and `serde` |

`file` is on by default, so naming the crate with no `features` keeps
everything it ever had. A service configured from its environment alone
turns it off and gets the env helpers and the validation accumulator with no
YAML parser in its graph:

```toml
stridelabs-config = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.11.1", default-features = false }
```

(The `file` feature is new in v0.10.0.)

(`cargo tree -e normal -p stridelabs-config --no-default-features` shows
`serde_json` and `thiserror` only.)

## Adding the dependency

```toml
[dependencies]
stridelabs-config = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.11.1" }
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

### The lookup seam: `env_or_from`, `env_parse_from`, `parse_string_array_from`

Each helper has a `_from` twin that reads through a lookup closure
(`impl Fn(&str) -> Option<String>`) instead of the process environment: the
seam a consumer's `Config::from_lookup` builds on, and what its unit tests
hand a `HashMap` to, so no test ever mutates the real environment
(`std::env::set_var` races with every other test in the binary).

**Their errors are value-free.** An `EnvError` from `env_parse_from` or
`parse_string_array_from` names the variable and a fixed reason
(`VALUE_DOES_NOT_PARSE`, `NOT_A_STRING_ARRAY`), never the value or the
parser's text, which can quote it (serde_json's `invalid type: string "…"`,
a `FromStr` error that echoes its input). Use them for any setting that can
hold a secret, and for refusals that get printed or logged. The plain
`env_parse` and `parse_string_array` keep the parser's text, as they always
have. (`env_parse_from` also asks nothing of `T::Err`: it never renders it.)

```rust
use std::collections::HashMap;
use stridelabs_config::{env_or_from, env_parse_from, VALUE_DOES_NOT_PARSE};

let vars = HashMap::from([("PORT", "80a0"), ("LOG_FORMAT", "json")]);
let get = |key: &str| vars.get(key).map(|value| value.to_string());

assert_eq!(env_or_from("LOG_FORMAT", "text", &get), "json");
let refusal = env_parse_from::<u16>("PORT", 8080, &get).unwrap_err();
assert_eq!(refusal.to_string(), format!("invalid value for PORT: {VALUE_DOES_NOT_PARSE}"));
```

## Startup refusals: collect them in `Errors`

A service that refuses to start on bad configuration should print every
problem at once, not the first. There is no separate refusal type: read each
setting through the `_from` seam and push what it refuses into an `Errors`
(below), writing your own rules' messages the same way (the setting and the
rule, never the value). `Errors::into_result` hands back every refusal in
order; print each and exit non-zero. `validate_socket_addr` and
`validate_fraction` quote the value they refuse, so keep them for settings
that are not secret. The rustdoc on `Errors` has a worked `startup_check`.

## `file` — layered YAML/JSON loading (feature `file`, on by default)

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

A `ConfigOverrides`-style type (a merged env/CLI overlay applied on top of a
parsed file) is domain-bound to a given service's specific set of overridable
knobs — it isn't a generic primitive, so it wasn't extracted. If a consumer
needs the same shape, define its own `Overrides` struct with `Option<T>`
fields, build it via `env::env_or`/`env_parse` against `Option`-wrapped
defaults, and apply it with a small `fn apply(&self, config: &mut Config)`.
That pattern deliberately stays in the consuming service.
