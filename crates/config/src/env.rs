//! Environment-variable helpers for 12-factor config loading.
//!
//! Reading `std::env::var` directly from every call site is untestable
//! without racing every other test in the binary — `std::env::set_var`
//! mutates *process*-wide state, not per-test state, so tests that set env
//! vars to exercise these helpers would be flaky under `cargo test`'s default
//! multi-threaded runner. Instead, each helper has a `*_from` twin that takes
//! an injectable lookup closure (`impl Fn(&str) -> Option<String>`): the plain
//! helper plugs in `std::env::var(..).ok()`, and a consumer's own
//! configuration seam (a `Config::from_lookup`) or its unit tests plug in a
//! fake `HashMap` lookup instead.
//!
//! **The `_from` twins' errors are value-free.** An [`EnvError`] from
//! [`env_parse_from`] or [`parse_string_array_from`] names the variable and a
//! fixed reason, and never carries the value or the parser's text (which can
//! quote it: serde_json's `invalid type: string "…"`, a `FromStr` error that
//! echoes its input). That makes them safe for a setting that can hold a
//! secret, and for startup refusals that are printed or logged. The plain
//! [`env_parse`] and [`parse_string_array`] keep their parser's text, as they
//! always have.

use std::fmt;
use std::str::FromStr;

/// An environment variable was present but its value could not be parsed
/// into the requested type.
///
/// Built by the `_from` helpers, `message` is a fixed reason
/// ([`VALUE_DOES_NOT_PARSE`], [`NOT_A_STRING_ARRAY`]); built by
/// [`env_parse`] or [`parse_string_array`], it carries the parser's text,
/// which can quote the value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid value for {var}: {message}")]
pub struct EnvError {
    /// The variable name that failed to parse.
    pub var: String,
    /// Why parsing failed.
    pub message: String,
}

/// [`env_parse_from`]'s reason for a value that does not parse.
pub const VALUE_DOES_NOT_PARSE: &str = "does not parse as the expected type (value not shown)";

/// [`parse_string_array_from`]'s reason for a value that is not a JSON array
/// of strings.
pub const NOT_A_STRING_ARRAY: &str = "must be a JSON array of strings (value not shown)";

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

/// [`env_or`] over the lookup `get` instead of the process environment:
/// `default` when `get` has nothing for `key`, or an empty value.
///
/// An empty value is treated as unset, as [`env_or`] treats it. A consumer
/// for whom empty and unset mean different things (an empty value that
/// deliberately switches something off) reads that setting with its raw
/// lookup instead.
///
/// ```
/// use stridelabs_config::env_or_from;
///
/// let get = |key: &str| (key == "LOG_FORMAT").then(|| "json".to_string());
/// assert_eq!(env_or_from("LOG_FORMAT", "text", get), "json");
/// assert_eq!(env_or_from("LOG_LEVEL", "info", get), "info");
/// ```
pub fn env_or_from(key: &str, default: &str, get: impl Fn(&str) -> Option<String>) -> String {
    get(key)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Read `key` from the environment and parse it as `T`. Missing or empty
/// yields `default`; present-but-unparsable — including a value that is not
/// valid Unicode — is an `Err` naming the variable. (Unlike [`env_or`], a
/// present-but-broken value here is an error, not an absence: silently
/// falling back would mask a real misconfiguration.)
///
/// The error carries the parser's text, which can quote the value; use
/// [`env_parse_from`] for a setting that can hold a secret.
pub fn env_parse<T>(key: &str, default: T) -> Result<T, EnvError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    reject_non_unicode(key)?;
    parse_with(
        key,
        default,
        |k| std::env::var(k).ok(),
        |e: T::Err| e.to_string(),
    )
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

/// [`env_parse`] over the lookup `get`, with a **value-free** error: missing
/// or empty yields `default`; a value that does not parse is an [`EnvError`]
/// naming `key`, whose message is [`VALUE_DOES_NOT_PARSE`], never the value
/// or the parser's text. (A lookup has no "not Unicode" case: that is the
/// lookup's to decide, e.g. by returning `None`.)
///
/// An empty value is treated as unset (it yields `default`). A consumer for
/// whom empty and unset mean different things reads that setting with its
/// raw lookup instead.
///
/// ```
/// use stridelabs_config::{env_parse_from, VALUE_DOES_NOT_PARSE};
///
/// let get = |key: &str| (key == "PORT").then(|| "80a0".to_string());
/// let error = env_parse_from::<u16>("PORT", 8080, get).unwrap_err();
/// assert_eq!(error.var, "PORT");
/// assert_eq!(error.message, VALUE_DOES_NOT_PARSE);
/// assert!(!error.to_string().contains("80a0"));
/// ```
pub fn env_parse_from<T>(
    key: &str,
    default: T,
    get: impl Fn(&str) -> Option<String>,
) -> Result<T, EnvError>
where
    T: FromStr,
{
    parse_with(key, default, get, |_| VALUE_DOES_NOT_PARSE.to_string())
}

/// `get(key)` parsed as `T` (missing or empty: `default`), a failure's
/// message built by `message`: the parser's text, or a fixed reason.
fn parse_with<T: FromStr>(
    key: &str,
    default: T,
    get: impl Fn(&str) -> Option<String>,
    message: impl FnOnce(T::Err) -> String,
) -> Result<T, EnvError> {
    match get(key) {
        Some(v) if !v.is_empty() => v.parse::<T>().map_err(|e| EnvError {
            var: key.to_string(),
            message: message(e),
        }),
        _ => Ok(default),
    }
}

/// Parse a JSON array of strings from an env var (e.g. `CORS_ORIGINS=["a","b"]`).
/// Missing or blank (whitespace-only) yields an empty list; present-but-invalid
/// JSON, JSON that isn't an array of strings, or a non-Unicode value is an
/// `Err` naming the variable.
///
/// The error carries serde_json's text, which can quote part of the value;
/// use [`parse_string_array_from`] for a setting that can hold a secret.
pub fn parse_string_array(key: &str) -> Result<Vec<String>, EnvError> {
    reject_non_unicode(key)?;
    string_array_with(
        key,
        |k| std::env::var(k).ok(),
        |e| format!("must be a JSON array of strings: {e}"),
    )
}

/// [`parse_string_array`] over the lookup `get`, with a **value-free**
/// error: missing or blank yields `[]`; anything but a JSON array of strings
/// is an [`EnvError`] naming `key`, whose message is [`NOT_A_STRING_ARRAY`],
/// never the value or serde_json's text.
///
/// An empty or whitespace-only value is treated as unset (it yields `[]`).
/// A consumer for whom empty and unset mean different things reads that
/// setting with its raw lookup instead.
///
/// ```
/// use stridelabs_config::{parse_string_array_from, NOT_A_STRING_ARRAY};
///
/// let get = |key: &str| (key == "CORS_ORIGINS").then(|| r#"["https://a", 7]"#.to_string());
/// let error = parse_string_array_from("CORS_ORIGINS", get).unwrap_err();
/// assert_eq!(error.message, NOT_A_STRING_ARRAY);
/// ```
pub fn parse_string_array_from(
    key: &str,
    get: impl Fn(&str) -> Option<String>,
) -> Result<Vec<String>, EnvError> {
    string_array_with(key, get, |_| NOT_A_STRING_ARRAY.to_string())
}

/// `get(key)` as a JSON array of strings (missing or blank: `[]`), a
/// failure's message built by `message`.
fn string_array_with(
    key: &str,
    get: impl Fn(&str) -> Option<String>,
    message: impl FnOnce(serde_json::Error) -> String,
) -> Result<Vec<String>, EnvError> {
    match get(key) {
        Some(v) if !v.trim().is_empty() => serde_json::from_str(&v).map_err(|e| EnvError {
            var: key.to_string(),
            message: message(e),
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

    const CANARY: &str = "env-value-canary";

    /// A `FromStr` whose error quotes its input, as many do.
    #[derive(Debug)]
    struct Echo;

    impl FromStr for Echo {
        type Err = String;

        fn from_str(input: &str) -> Result<Self, String> {
            Err(format!("cannot read {input:?}"))
        }
    }

    /// The `_from` seam's errors name the variable and a fixed reason, never
    /// the value or the parser's text, even where the parser quotes the
    /// value (the premise, checked first).
    #[test]
    fn the_from_seam_errors_never_carry_the_value_or_the_parser_text() {
        assert!(CANARY.parse::<Echo>().unwrap_err().contains(CANARY));
        let error = env_parse_from::<Echo>(
            "SECRET_SETTING",
            Echo,
            lookup(&[("SECRET_SETTING", CANARY)]),
        )
        .unwrap_err();
        assert_eq!(error.var, "SECRET_SETTING");
        assert_eq!(error.message, VALUE_DOES_NOT_PARSE);
        assert_eq!(
            error.to_string(),
            "invalid value for SECRET_SETTING: does not parse as the expected type (value not shown)"
        );

        let quoted = format!("\"{CANARY}\"");
        assert!(serde_json::from_str::<Vec<String>>(&quoted)
            .unwrap_err()
            .to_string()
            .contains(CANARY));
        for value in [quoted.as_str(), r#"["ok", 12345]"#, "not json", "[\"a\""] {
            let error =
                parse_string_array_from("ORIGINS", lookup(&[("ORIGINS", value)])).unwrap_err();
            assert_eq!(error.var, "ORIGINS");
            assert_eq!(error.message, NOT_A_STRING_ARRAY, "{value}");
            assert!(!error.to_string().contains(CANARY), "{error}");
            assert!(!error.to_string().contains("12345"), "{error}");
        }
    }

    /// The value-free seam never renders the parser's error, so it does not
    /// ask for `Display` on it.
    #[test]
    fn env_parse_from_needs_no_display_on_the_parse_error() {
        struct Flag(bool);
        impl FromStr for Flag {
            type Err = ();
            fn from_str(input: &str) -> Result<Self, ()> {
                match input {
                    "on" => Ok(Flag(true)),
                    "off" => Ok(Flag(false)),
                    _ => Err(()),
                }
            }
        }
        let on = env_parse_from("FLAG", Flag(false), lookup(&[("FLAG", "on")])).unwrap();
        assert!(on.0);
        assert!(env_parse_from("FLAG", Flag(false), lookup(&[("FLAG", "maybe")])).is_err());
    }

    #[test]
    fn parse_string_array_malformed_errors_with_var_name() {
        let result = parse_string_array_from("ORIGINS", lookup(&[("ORIGINS", "not json")]));
        let err = result.unwrap_err();
        assert_eq!(err.var, "ORIGINS");
    }
}
