//! Why no access token — and what that answer is allowed to say.
//!
//! # The redaction rule
//!
//! **No variant carries credential material**: not a private key, not a
//! refresh token or client secret, not an access token, not a URL's query
//! string or userinfo. These strings end up in logs.
//!
//! - A credential file that fails to parse is described by *where* it came
//!   from and *which field* is wrong, never by its content. serde_json's
//!   `Display` can quote the offending value (`invalid type: string "…"`), so
//!   a parse failure is reported as its category and position only. An
//!   unsupported `type` is quoted only when it is a plain `[a-z_]{1,64}` name.
//! - A token endpoint's answer is never quoted. A success body *is* an access
//!   token. A failure is reported as its status plus the RFC 6749 §5.2
//!   `error` code — only when it is a plain code (`[A-Za-z0-9_.-]{1,64}`).
//!   `error_description` is free text a server may fill with anything, so it
//!   is dropped, along with the rest of the body.
//! - Endpoints appear as `scheme://host[:port]/path`. A `reqwest::Error` is
//!   rendered `without_url()`.

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
        /// The endpoint, as `scheme://host[:port]/path`.
        endpoint: String,
        /// The transport's reason, rendered without the URL.
        reason: String,
    },

    /// The token endpoint answered with a non-2xx status.
    #[error("access token request to {endpoint} answered HTTP {status}{}", detail_suffix(.detail))]
    Status {
        /// The endpoint, as `scheme://host[:port]/path`.
        endpoint: String,
        /// The HTTP status code.
        status: u16,
        /// The OAuth `error` code (`invalid_grant`, …) when the body carried
        /// a plain one; otherwise empty.
        detail: String,
    },

    /// A 2xx answer that is not a usable token: not JSON, larger than
    /// [`crate::auth::MAX_TOKEN_RESPONSE`], no `access_token`, or an
    /// `expires_in` that is present but not a positive integer. Such a token
    /// is never cached.
    #[error("access token response from {endpoint} is unusable: {reason}")]
    InvalidResponse {
        /// The endpoint, as `scheme://host[:port]/path`.
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
