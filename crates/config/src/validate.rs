//! Semantic validation plumbing shared across configs: an error accumulator
//! (so a caller reports every problem in one pass instead of failing at the
//! first) plus the handful of field-level checks common enough to earn a
//! place here — socket addresses and `0.0..=1.0` fractions. Anything
//! domain-specific (URL schemes, route-ID uniqueness, cross-field rules)
//! stays in the consuming crate/service; this module only owns the pattern.
//!
//! Carried over from an existing service's `config::validate` (`Errors`
//! accumulator, `validate_socket_addr`, `validate_fraction`), generalized
//! from a module-private helper into this crate's public API.

use std::fmt;
use std::net::SocketAddr;

/// A single semantic validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// Where the problem is — a caller-defined path, e.g. `server.listen_addr`
    /// or `routes[3].timeout_ms`.
    pub location: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}

/// Accumulates validation errors so a caller can report every problem found
/// in a config, not just the first.
#[derive(Debug, Default)]
pub struct Errors(Vec<ValidationError>);

impl Errors {
    /// Start with no recorded errors.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a validation failure at `location`.
    pub fn push(&mut self, location: impl Into<String>, message: impl Into<String>) {
        self.0.push(ValidationError {
            location: location.into(),
            message: message.into(),
        });
    }

    /// True if nothing has been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the accumulator: `Ok(())` if nothing was recorded, else every
    /// recorded error in the order they were pushed.
    pub fn into_result(self) -> Result<(), Vec<ValidationError>> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(self.0)
        }
    }
}

/// Validate that `value` parses as a socket address (`IP:port`).
pub fn validate_socket_addr(location: &str, value: &str, errs: &mut Errors) {
    if value.parse::<SocketAddr>().is_err() {
        errs.push(
            location,
            format!(
                "{value:?} is not a valid socket address (expected IP:port, e.g. 0.0.0.0:8080)"
            ),
        );
    }
}

/// Validate that `value` is a fraction within `0.0..=1.0`. NaN-safe:
/// `RangeInclusive::contains` compares with `<`/`>`, and every such
/// comparison against `NaN` is false, so `!contains(&f64::NAN)` is `true` and
/// NaN is rejected without a separate `is_nan()` check.
pub fn validate_fraction(location: &str, value: f64, errs: &mut Errors) {
    if !(0.0..=1.0).contains(&value) {
        errs.push(location, format!("must be within 0.0..=1.0 (got {value})"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_accumulates_and_reports_in_order() {
        let mut errs = Errors::new();
        assert!(errs.is_empty());
        errs.push("a", "first problem");
        errs.push("b", "second problem");
        assert!(!errs.is_empty());

        let result = errs.into_result().unwrap_err();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].location, "a");
        assert_eq!(result[0].message, "first problem");
        assert_eq!(result[1].location, "b");
    }

    #[test]
    fn empty_errors_into_result_is_ok() {
        assert!(Errors::new().into_result().is_ok());
    }

    #[test]
    fn validation_error_display_format() {
        let e = ValidationError {
            location: "server.port".to_string(),
            message: "must be nonzero".to_string(),
        };
        assert_eq!(e.to_string(), "server.port: must be nonzero");
    }

    #[test]
    fn socket_addr_good() {
        let mut errs = Errors::new();
        validate_socket_addr("addr", "127.0.0.1:8080", &mut errs);
        assert!(errs.is_empty());
    }

    #[test]
    fn socket_addr_bad() {
        let mut errs = Errors::new();
        validate_socket_addr("addr", "not-an-addr", &mut errs);
        assert!(!errs.is_empty());
        assert_eq!(errs.into_result().unwrap_err()[0].location, "addr");
    }

    #[test]
    fn fraction_boundaries_are_inclusive() {
        let mut errs = Errors::new();
        validate_fraction("f", 0.0, &mut errs);
        validate_fraction("f", 1.0, &mut errs);
        assert!(errs.is_empty());
    }

    #[test]
    fn fraction_just_outside_boundaries_is_rejected() {
        let mut errs = Errors::new();
        validate_fraction("f", -0.1, &mut errs);
        validate_fraction("f", 1.1, &mut errs);
        assert_eq!(errs.into_result().unwrap_err().len(), 2);
    }

    #[test]
    fn fraction_nan_is_rejected() {
        let mut errs = Errors::new();
        validate_fraction("f", f64::NAN, &mut errs);
        assert!(!errs.is_empty());
    }
}
