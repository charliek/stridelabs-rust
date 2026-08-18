//! Environment-variable helpers for 12-factor config loading.
//!
//! Reading `std::env::var` directly from every call site is untestable
//! without racing every other test in the binary — `std::env::set_var`
//! mutates *process*-wide state, not per-test state, so tests that set env
//! vars to exercise these helpers would be flaky under `cargo test`'s default
//! multi-threaded runner. Instead, every public function here is a thin
//! wrapper around a private `*_from` variant that takes an injectable lookup
//! closure (`impl Fn(&str) -> Option<String>`); the public API always plugs
//! in `std::env::var(..).ok()`, and unit tests plug in a fake `HashMap`
//! lookup instead. This is the `from_lookup` seam from one of the originating
//! config loaders, generalized to these three helpers.

use std::fmt;
use std::str::FromStr;

/// An environment variable was present but its value could not be parsed
/// into the requested type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid value for {var}: {message}")]
pub struct EnvError {
    /// The variable name that failed to parse.
    pub var: String,
    /// Why parsing failed.
    pub message: String,
}

/// Read `key` from the environment; return `default` if it is unset, **empty**,
/// or not valid Unicode (`std::env::var`'s only other failure mode) — all
/// collapse to the same "nothing usable was set" outcome.
///
/// Empty counts as unset because that is how an env var arrives when a
/// compose file writes `FOO:`, a k8s manifest writes `value: ""`, or a
/// `.env` line is left blank — a variable someone left unfilled, not a
/// deliberate empty value. Taking `""` literally turns those into
/// boot failures far from their cause (an empty `BIND_ADDR` that fails to
/// parse, an empty issuer that 401s every token). This also matches
/// [`env_parse`] and [`parse_string_array`], which both treat empty as
/// absent.
pub fn env_or(key: &str, default: &str) -> String {
    env_or_from(key, default, |k| std::env::var(k).ok())
}

fn env_or_from(key: &str, default: &str, get: impl Fn(&str) -> Option<String>) -> String {
    get(key)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Read `key` from the environment and parse it as `T`. Missing or empty
/// yields `default`; present-but-unparsable — including a value that is not
/// valid Unicode — is an `Err` naming the variable. (Unlike [`env_or`], a
/// present-but-broken value here is an error, not an absence: silently
/// falling back would mask a real misconfiguration.)
pub fn env_parse<T>(key: &str, default: T) -> Result<T, EnvError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    reject_non_unicode(key)?;
    env_parse_from(key, default, |k| std::env::var(k).ok())
}

/// `std::env::var`'s only non-missing failure is `NotUnicode`. The lookup
/// seam collapses errors to `Option`, so the strict helpers screen for this
/// case up front. Not unit-testable without mutating process env (a non-UTF-8
/// var can only exist for real); the logic is a single match arm.
fn reject_non_unicode(key: &str) -> Result<(), EnvError> {
    match std::env::var(key) {
        Err(std::env::VarError::NotUnicode(_)) => Err(EnvError {
            var: key.to_string(),
            message: "value is not valid Unicode".to_string(),
        }),
        _ => Ok(()),
    }
}

fn env_parse_from<T>(
    key: &str,
    default: T,
    get: impl Fn(&str) -> Option<String>,
) -> Result<T, EnvError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    match get(key) {
        Some(v) if !v.is_empty() => v.parse::<T>().map_err(|e| EnvError {
            var: key.to_string(),
            message: e.to_string(),
        }),
        _ => Ok(default),
    }
}

/// Parse a JSON array of strings from an env var (e.g. `CORS_ORIGINS=["a","b"]`).
/// Missing or blank (whitespace-only) yields an empty list; present-but-invalid
/// JSON, JSON that isn't an array of strings, or a non-Unicode value is an
/// `Err` naming the variable.
pub fn parse_string_array(key: &str) -> Result<Vec<String>, EnvError> {
    reject_non_unicode(key)?;
    parse_string_array_from(key, |k| std::env::var(k).ok())
}

fn parse_string_array_from(
    key: &str,
    get: impl Fn(&str) -> Option<String>,
) -> Result<Vec<String>, EnvError> {
    match get(key) {
        Some(v) if !v.trim().is_empty() => serde_json::from_str(&v).map_err(|e| EnvError {
            var: key.to_string(),
            message: format!("must be a JSON array of strings: {e}"),
        }),
        _ => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: HashMap<&str, &str> = pairs.iter().copied().collect();
        move |k| map.get(k).map(|v| v.to_string())
    }

    #[test]
    fn env_or_missing_falls_back_to_default() {
        assert_eq!(env_or_from("FOO", "fallback", lookup(&[])), "fallback");
    }

    #[test]
    fn env_or_present_wins() {
        assert_eq!(
            env_or_from("FOO", "fallback", lookup(&[("FOO", "set")])),
            "set"
        );
    }

    #[test]
    fn env_or_empty_falls_back_to_default() {
        // An unfilled variable (compose `FOO:`, k8s `value: ""`, blank .env
        // line) must not win over the default — taking it literally turns a
        // missing value into a boot failure far from its cause. Matches
        // env_parse/parse_string_array, which already treat empty as absent.
        assert_eq!(
            env_or_from("FOO", "fallback", lookup(&[("FOO", "")])),
            "fallback"
        );
    }

    #[test]
    fn env_parse_missing_falls_back_to_default() {
        let result: Result<u32, EnvError> = env_parse_from("PORT", 8080, lookup(&[]));
        assert_eq!(result.unwrap(), 8080);
    }

    #[test]
    fn env_parse_empty_falls_back_to_default() {
        let result: Result<u32, EnvError> = env_parse_from("PORT", 8080, lookup(&[("PORT", "")]));
        assert_eq!(result.unwrap(), 8080);
    }

    #[test]
    fn env_parse_bad_value_errors_with_var_name() {
        let result: Result<u32, EnvError> =
            env_parse_from("PORT", 8080, lookup(&[("PORT", "not-a-number")]));
        let err = result.unwrap_err();
        assert_eq!(err.var, "PORT");
        assert!(err.to_string().contains("PORT"));
    }

    #[test]
    fn env_parse_good_value_parses() {
        let result: Result<u32, EnvError> = env_parse_from("PORT", 8080, lookup(&[("PORT", "99")]));
        assert_eq!(result.unwrap(), 99);
    }

    #[test]
    fn parse_string_array_missing_is_empty() {
        let result = parse_string_array_from("ORIGINS", lookup(&[]));
        assert_eq!(result.unwrap(), Vec::<String>::new());
    }

    #[test]
    fn parse_string_array_blank_is_empty() {
        let result = parse_string_array_from("ORIGINS", lookup(&[("ORIGINS", "   ")]));
        assert_eq!(result.unwrap(), Vec::<String>::new());
    }

    #[test]
    fn parse_string_array_happy_path() {
        let result = parse_string_array_from(
            "ORIGINS",
            lookup(&[("ORIGINS", r#"["https://a", "https://b"]"#)]),
        );
        assert_eq!(result.unwrap(), vec!["https://a", "https://b"]);
    }

    #[test]
    fn parse_string_array_malformed_errors_with_var_name() {
        let result = parse_string_array_from("ORIGINS", lookup(&[("ORIGINS", "not json")]));
        let err = result.unwrap_err();
        assert_eq!(err.var, "ORIGINS");
    }
}
