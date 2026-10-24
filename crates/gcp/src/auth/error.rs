//! Why no access token — and what that answer is allowed to say.
//!
//! # The redaction rule
//!
//! **No variant carries credential material**: not a private key, not a
//! refresh token or client secret, not an access token, not a URL's query
//! string or userinfo. These strings end up in logs.
//!
//! Every rule holds for what a variant **stores**, not only for its
//! `Display`: upstream text is reduced when the error is constructed, so the
//! derived `Debug` (`?error`) has nothing more to show.
//!
//! - A credential file that fails to parse is described by *where* it came
//!   from and *which field* is wrong, never by its content. serde_json's
//!   `Display` can quote the offending value (`invalid type: string "…"`), so
//!   a parse failure is reported as its category and position only. An
//!   unsupported `type` is named only when google-auth knows it
//!   (`external_account`, `impersonated_service_account`, …); any other is
//!   `other`.
//! - A token endpoint's answer is never quoted. A success body *is* an access
//!   token. A failure is reported as its status plus the RFC 6749 `error`
//!   code, only when it is one RFC 6749 registers (`invalid_grant`, …); any
//!   other is `other`. `error_description` is free text a server may
//!   fill with anything, so it is dropped, along with the rest of the body.
//! - Endpoints appear as their origin, `scheme://host[:port]`: never the
//!   path, which for a service account is its key file's `token_uri`,
//!   verbatim, and can hold a secret. A `reqwest::Error` is reduced to a
//!   fixed category (`timed out`, `connection failed`, …) and its text is
//!   never formatted: `without_url()` strips only the outer URL, and the
//!   source chain can carry another one.

use crate::util::detail_suffix;

/// Why a [`crate::TokenProvider`] could not be built, or could not produce a
/// token.
///
/// `Clone` so one refresh attempt's failure can answer every call waiting on
/// that attempt.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum GcpAuthError {
    /// A credential outside the supported subset: a `type` other than
    /// `service_account` or `authorized_user` (`external_account`,
    /// `impersonated_service_account`, …), or a `service_account` key in a
    /// build without the `service-account-key` feature. Never a fallthrough
    /// to the next source.
    ///
    /// The message is the crate's own. It names the `type` found only when
    /// google-auth knows it, and says `other` for any other, so a file whose
    /// `type` is not a credential type is never echoed.
    #[error("unsupported credentials: {0}")]
    Unsupported(String),

    /// A configured credential source that cannot be used: an env var or
    /// argument that is set but empty, a file that is missing or unreadable,
    /// text that is not base64 or not JSON, a missing or mistyped field, a
    /// private key that is not an RSA PEM.
    #[error("invalid credentials from {origin}: {reason}")]
    InvalidCredentials {
        /// Where the credential came from, e.g. `GOOGLE_APPLICATION_CREDENTIALS
        /// file /path/key.json`. A path, never content.
        origin: String,
        /// What is wrong with it: a fixed phrase naming the field or the
        /// failure category, never a value.
        reason: String,
    },

    /// The token request did not complete: a connection failure, a timeout,
    /// a body that could not be read.
    #[error("access token request to {endpoint} failed: {reason}")]
    Request {
        /// The endpoint's origin, `scheme://host[:port]`: never its path,
        /// query, fragment or userinfo.
        endpoint: String,
        /// The transport failure's fixed category (`timed out`,
        /// `connection failed`, …), never its text.
        reason: String,
    },

    /// The token endpoint answered with a non-2xx status.
    #[error("access token request to {endpoint} answered HTTP {status}{}", detail_suffix(.detail))]
    Status {
        /// The endpoint's origin, `scheme://host[:port]`: never its path,
        /// query, fragment or userinfo.
        endpoint: String,
        /// The HTTP status code.
        status: u16,
        /// The OAuth `error` code when the body carried one: a code RFC
        /// 6749 registers (`invalid_grant`, …), or `other` for any other.
        /// Empty when the body carried no `error` string.
        detail: String,
    },

    /// A 2xx answer that is not a usable token: not JSON, larger than
    /// [`crate::auth::MAX_TOKEN_RESPONSE`], no `access_token`, or an
    /// `expires_in` that is present but not a positive integer. Such a token
    /// is never cached.
    #[error("access token response from {endpoint} is unusable: {reason}")]
    InvalidResponse {
        /// The endpoint's origin, `scheme://host[:port]`: never its path,
        /// query, fragment or userinfo.
        endpoint: String,
        /// A fixed phrase; the body is never quoted (a 2xx body carries the
        /// token).
        reason: String,
    },

    /// Signing a service account's JWT-bearer assertion failed. The
    /// underlying error is dropped: a key-handling error has no business in
    /// a log line.
    #[error("signing the service-account assertion failed")]
    Signing,

    /// The refresh task stopped before it finished: it panicked, or the
    /// runtime is shutting down. Not cached; the next call starts a new one.
    #[error("the access token refresh stopped before it finished")]
    RefreshAborted,
}

impl GcpAuthError {
    pub(crate) fn invalid(origin: &str, reason: impl Into<String>) -> GcpAuthError {
        GcpAuthError::InvalidCredentials {
            origin: origin.to_owned(),
            reason: reason.into(),
        }
    }
}
