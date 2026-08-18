//! Why a token was rejected — and, just as importantly, what that answer is
//! allowed to say.
//!
//! # The redaction rule
//!
//! **No variant of [`AuthError`] carries any part of the token.** Not the
//! token, not a claim value, not the `kid`. Every one of those is
//! attacker-supplied on precisely the requests that produce an error, and
//! these strings end up in logs and (via the `http` feature) potentially near
//! a response body. A fixed message per failure mode is enough to debug with
//! and gives a prober nothing to work with.
//!
//! [`AuthError::InvalidToken`] is the one variant with a payload derived from
//! the token at all, and even it is a *classification*: the `jsonwebtoken`
//! error kind is mapped to one of a fixed set of phrases by the crate's
//! `invalid_token`, never rendered with `Display`. That is a deliberate
//! departure from the original implementation this crate replaced, whose
//! `format!("token rejected: {e}")` could quote the claim value that failed
//! to deserialize.
//!
//! # Why this crate has its own error type
//!
//! `AuthError` is a plain `thiserror` enum with no HTTP in it, so the crate's
//! default build doesn't drag in `stridelabs-http` (or axum, or anything that
//! knows what a status code is). Services that use the house error type turn
//! on the `http` feature and get the [`From`] impl below.

/// Why an access token was not accepted.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// No `Authorization: Bearer …` header on the request.
    #[error("missing bearer token")]
    MissingToken,
    /// Not a JWT at all — the header couldn't be decoded.
    #[error("malformed token")]
    MalformedToken,
    /// The JWT header has no `kid`, so there is no way to say which of the
    /// issuer's keys should have signed it. The issuers this crate targets
    /// always set one.
    #[error("token is missing a key id")]
    MissingKid,
    /// The token's `kid` is not in the issuer's JWKS — after a refetch, or
    /// after a refetch was suppressed by [`crate::MIN_REFETCH_INTERVAL`].
    #[error("token signed by an unknown key")]
    UnknownKid,
    /// Signature, `iss`, `aud`, `exp` or claim-shape check failed. The
    /// payload is a fixed classification (a fixed phrase per
    /// `jsonwebtoken` error kind), never token-derived text.
    #[error("token rejected: {0}")]
    InvalidToken(String),
    /// No `email` claim, or an empty one.
    #[error("token is missing an email claim")]
    MissingEmail,
    /// No `sub` claim, or an empty one.
    #[error("token is missing a subject claim")]
    MissingSubject,
    /// The issuer's JWKS could not be fetched or parsed. This is the one
    /// failure here that is the *server's* fault, and the only one that maps
    /// to a 5xx.
    #[error("JWKS unavailable: {0}")]
    Jwks(String),
}

/// Classify a `jsonwebtoken` failure into an [`AuthError::InvalidToken`].
///
/// The mapping is total but lossy on purpose: several distinct kinds collapse
/// onto the same phrase, because the extra precision would only ever be
/// useful to someone trying to shape a token that gets through.
pub(crate) fn invalid_token(err: &jsonwebtoken::errors::Error) -> AuthError {
    use jsonwebtoken::errors::ErrorKind;

    let reason = match err.kind() {
        ErrorKind::InvalidSignature => "signature is invalid",
        ErrorKind::ExpiredSignature => "token has expired",
        ErrorKind::ImmatureSignature => "token is not valid yet",
        ErrorKind::InvalidIssuer => "issuer is not accepted",
        ErrorKind::InvalidAudience => "audience is not accepted",
        ErrorKind::InvalidSubject => "subject is not accepted",
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
            "algorithm is not accepted"
        }
        ErrorKind::MissingRequiredClaim(_) => "a required claim is missing",
        // `Json` means the claims deserialized badly — its `Display` can
        // quote the offending value, so it is classified like the rest.
        ErrorKind::Json(_) => "claims are malformed",
        // Everything else (base64, UTF-8, key-shape and the non-exhaustive
        // tail) means the bytes we were handed aren't a usable token.
        _ => "token is malformed",
    };
    AuthError::InvalidToken(reason.to_string())
}

/// Map an authentication failure onto the house HTTP error type.
///
/// - [`AuthError::Jwks`] is a **server** failure: this service couldn't reach
///   or parse the issuer's key set, which says nothing about the caller's
///   token. It becomes `AppError::Internal`, so the detail is logged and the
///   client gets a 500 with a fixed body.
/// - Everything else becomes `AppError::Unauthorized` with a **single generic
///   message**, deliberately not the specific reason. `AppError`'s contract is
///   that a non-`Internal` payload is returned to the client verbatim, and
///   telling a caller *which* check failed ("audience is not accepted" vs
///   "signature is invalid") is a free oracle for anyone assembling a token.
///   The specific `AuthError` is still available to the caller before the
///   conversion, which is where it belongs: in a log line, not a response.
#[cfg(feature = "http")]
impl From<AuthError> for stridelabs_http::AppError {
    fn from(err: AuthError) -> stridelabs_http::AppError {
        match err {
            AuthError::Jwks(detail) => {
                stridelabs_http::AppError::Internal(anyhow::anyhow!("slauth JWKS: {detail}"))
            }
            _ => stridelabs_http::AppError::Unauthorized("invalid or missing credentials".into()),
        }
    }
}

#[cfg(all(test, feature = "http"))]
mod http_tests {
    use http::StatusCode;
    use stridelabs_http::AppError;

    use super::*;

    #[test]
    fn jwks_failure_is_a_server_error() {
        let app: AppError = AuthError::Jwks("endpoint returned 503".into()).into();

        assert_eq!(app.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            matches!(app, AppError::Internal(_)),
            "a JWKS outage is this service's problem, not the caller's"
        );
    }

    #[test]
    fn every_other_failure_is_a_generic_401() {
        let cases = [
            AuthError::MissingToken,
            AuthError::MalformedToken,
            AuthError::MissingKid,
            AuthError::UnknownKid,
            AuthError::InvalidToken("signature is invalid".into()),
            AuthError::MissingEmail,
            AuthError::MissingSubject,
        ];

        for err in cases {
            let reason = err.to_string();
            let app: AppError = err.into();

            assert_eq!(app.status(), StatusCode::UNAUTHORIZED, "{reason}");
            assert_eq!(
                app.to_string(),
                "invalid or missing credentials",
                "the specific reason must not reach the client ({reason})"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::errors::{Error as JwtError, ErrorKind};

    use super::*;

    #[test]
    fn jsonwebtoken_errors_are_classified_not_rendered() {
        let cases = [
            (ErrorKind::InvalidSignature, "signature is invalid"),
            (ErrorKind::ExpiredSignature, "token has expired"),
            (ErrorKind::InvalidIssuer, "issuer is not accepted"),
            (ErrorKind::InvalidAudience, "audience is not accepted"),
            (ErrorKind::InvalidAlgorithm, "algorithm is not accepted"),
            (ErrorKind::InvalidToken, "token is malformed"),
        ];

        for (kind, expected) in cases {
            let AuthError::InvalidToken(reason) = invalid_token(&JwtError::from(kind)) else {
                unreachable!("invalid_token only ever builds InvalidToken");
            };
            assert_eq!(reason, expected);
        }
    }

    #[test]
    fn malformed_claims_do_not_leak_the_offending_value() {
        // A claims-shape failure is the case where `Display` on the original
        // error would quote token content back at us.
        let json_err: serde_json::Error =
            serde_json::from_str::<u8>("\"hunter2\"").expect_err("must not parse");
        assert!(json_err.to_string().contains("hunter2"), "premise check");

        let err = invalid_token(&JwtError::from(ErrorKind::Json(json_err.into())));

        assert_eq!(err.to_string(), "token rejected: claims are malformed");
        assert!(!err.to_string().contains("hunter2"));
    }
}
