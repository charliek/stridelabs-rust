//! The house application error type and its HTTP representation.
//!
//! Ported from spendwise-rs's `backend/src/error.rs`. The wire contract is
//! preserved exactly — status mapping, the redaction of internal detail, and
//! the `{"error": {"message", "type"}}` body shape — because services already
//! ship clients that read it.
//!
//! Two deliberate departures from the original:
//!
//! - **No `PaymentRequired` variant.** It exists in spendwise because that
//!   service has a monthly budget; a shared crate has no business knowing
//!   about budgets. Apps that need it define a one-line helper over
//!   [`AppError::custom_client`] instead of growing the shared enum.
//! - **A [`AppError::Custom`] escape hatch**, reachable only through
//!   [`AppError::custom_client`], so app-specific 4xx statuses don't each
//!   require a new variant here.
//!
//! See the crate-level docs for why [`AppError::Internal`] carries an
//! `anyhow::Error` when every other crate in this workspace keeps `anyhow`
//! out of its public API.

use axum::response::{IntoResponse, Response};
use axum::Json;
use http::StatusCode;
use serde_json::json;

/// An error on its way out of an axum handler.
///
/// Every variant's payload **is shown to the client verbatim** except
/// [`AppError::Internal`], whose detail is logged and replaced with a fixed
/// string. Treat the `String` in the other variants as a public,
/// user-readable sentence, never as a place to stash a diagnostic.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    /// A uniqueness conflict (e.g. a handle already in use).
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    TooManyRequests(String),
    /// Upstream provider failed.
    #[error("{0}")]
    BadGateway(String),
    /// An app-specific client error, for statuses this enum has no variant
    /// for (spendwise's `402 Payment Required`, a `409`-adjacent `423
    /// Locked`, …).
    ///
    /// Marked `#[non_exhaustive]` so it cannot be built with struct-literal
    /// syntax outside this crate: [`AppError::custom_client`] is the only
    /// constructor, which is what keeps the "4xx only" contract meaningful.
    /// Matching still works, with a trailing `..`.
    #[error("{message}")]
    #[non_exhaustive]
    Custom { status: StatusCode, message: String },
    /// Unexpected server-side failure. The detail is logged, never returned.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    /// Build a client error (4xx) with a caller-chosen status.
    ///
    /// `message` is returned to the client verbatim, which is the whole point
    /// of the constructor and also the reason it is restricted to client
    /// errors: a 5xx message would be leaking server-side detail, exactly
    /// what [`AppError::Internal`]'s redaction exists to prevent. Server
    /// failures go through `AppError::Internal` (or `?` on an
    /// `anyhow::Result`), which logs the cause and returns a fixed string.
    ///
    /// The restriction is a `debug_assert!`: debug and test builds panic on a
    /// non-4xx status, release builds pass it through. That is a deliberate
    /// choice over a `Result` — passing a 5xx here is a programming error to
    /// be caught in CI, not a runtime condition every call site should have
    /// to handle, and silently rewriting it to a 500 in release would hide
    /// the bug rather than surface it. As a second line of defense, if a
    /// server-error `Custom` does reach [`IntoResponse`] in a release build,
    /// its status is kept (so the misuse stays observable) but its message is
    /// redacted exactly like [`AppError::Internal`]'s.
    ///
    /// ```
    /// use stridelabs_http::AppError;
    /// use http::StatusCode;
    ///
    /// // The app-specific variant this crate deliberately doesn't own:
    /// fn payment_required(msg: impl Into<String>) -> AppError {
    ///     AppError::custom_client(StatusCode::PAYMENT_REQUIRED, msg)
    /// }
    /// ```
    pub fn custom_client(status: StatusCode, message: impl Into<String>) -> AppError {
        debug_assert!(
            status.is_client_error(),
            "AppError::custom_client is for 4xx statuses (got {status}); \
             server errors must go through AppError::Internal so their \
             detail is redacted"
        );
        AppError::Custom {
            status,
            message: message.into(),
        }
    }

    /// The HTTP status this error renders as.
    ///
    /// Public so callers can classify an error (metrics labels, log fields,
    /// retry decisions) without going all the way through
    /// [`IntoResponse`] and inspecting the built response.
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            AppError::BadGateway(_) => StatusCode::BAD_GATEWAY,
            AppError::Custom { status, .. } => *status,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        // Internal errors are logged in full but never leaked to the client.
        let message = match &self {
            AppError::Internal(err) => {
                tracing::error!(error = ?err, "internal error");
                "internal server error".to_string()
            }
            // Defense in depth for release builds, where `custom_client`'s
            // debug_assert is compiled out: a server-error `Custom` keeps its
            // status (so the misuse stays visible) but its message is redacted
            // like `Internal` — the crate's core promise is that 5xx detail
            // never reaches a client, and that must hold even for misuse.
            AppError::Custom { status, message } if status.is_server_error() => {
                tracing::error!(%status, %message, "custom_client misused with a server error");
                "internal server error".to_string()
            }
            other => other.to_string(),
        };
        let body = Json(json!({
            "error": {
                "message": message,
                "type": status.canonical_reason().unwrap_or("error"),
            }
        }));
        (status, body).into_response()
    }
}

/// The return type of essentially every handler and service function in a
/// StrideLabs axum app.
pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use serde_json::Value;

    use super::*;

    /// Drive an error through `IntoResponse` and hand back the pair every
    /// test here asserts on: the status, and the body parsed as JSON.
    async fn respond(err: AppError) -> (StatusCode, Value) {
        let res = err.into_response();
        let status = res.status();
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[test]
    fn every_variant_maps_to_its_status() {
        let cases = [
            (AppError::BadRequest("x".into()), StatusCode::BAD_REQUEST),
            (AppError::Unauthorized("x".into()), StatusCode::UNAUTHORIZED),
            (AppError::Forbidden("x".into()), StatusCode::FORBIDDEN),
            (AppError::NotFound("x".into()), StatusCode::NOT_FOUND),
            (AppError::Conflict("x".into()), StatusCode::CONFLICT),
            (
                AppError::TooManyRequests("x".into()),
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (AppError::BadGateway("x".into()), StatusCode::BAD_GATEWAY),
            (
                AppError::custom_client(StatusCode::PAYMENT_REQUIRED, "x"),
                StatusCode::PAYMENT_REQUIRED,
            ),
            (
                AppError::Internal(anyhow::anyhow!("x")),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];

        for (err, expected) in cases {
            assert_eq!(err.status(), expected, "{err:?}");
        }
    }

    #[tokio::test]
    async fn response_status_matches_status() {
        // `status()` is what `IntoResponse` is built from, but that's an
        // implementation detail — pin the two together so a future rewrite of
        // `into_response` can't drift from the public accessor.
        for err in [
            AppError::NotFound("x".into()),
            AppError::custom_client(StatusCode::LOCKED, "x"),
            AppError::Internal(anyhow::anyhow!("x")),
        ] {
            let expected = err.status();
            let (status, _) = respond(err).await;
            assert_eq!(status, expected);
        }
    }

    #[tokio::test]
    async fn body_is_exactly_error_message_and_canonical_type() {
        let (status, body) = respond(AppError::NotFound("no such widget".into())).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        // Full-value equality, not field probing: the shape is the wire
        // contract, so an extra key is a breaking change and must fail here.
        assert_eq!(
            body,
            json!({"error": {"message": "no such widget", "type": "Not Found"}})
        );
    }

    #[tokio::test]
    async fn body_is_json() {
        let res = AppError::BadRequest("nope".into()).into_response();

        assert_eq!(
            res.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn internal_detail_is_redacted() {
        let err = AppError::Internal(anyhow::anyhow!("connection to db as user hunter2 failed"));

        let (status, body) = respond(err).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body,
            json!({"error": {"message": "internal server error", "type": "Internal Server Error"}})
        );
        assert!(
            !body.to_string().contains("hunter2"),
            "the anyhow detail must not reach the client"
        );
    }

    #[tokio::test]
    async fn custom_client_carries_its_status_and_message() {
        let err = AppError::custom_client(StatusCode::PAYMENT_REQUIRED, "monthly budget exhausted");

        let (status, body) = respond(err).await;

        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(
            body,
            json!({"error": {"message": "monthly budget exhausted", "type": "Payment Required"}})
        );
    }

    #[test]
    #[should_panic(expected = "AppError::custom_client is for 4xx statuses")]
    fn custom_client_rejects_server_errors_in_debug_builds() {
        // `debug_assert!` is compiled in for `cargo test`, so this documents
        // the contract *and* proves the guard is live in CI.
        let _ = AppError::custom_client(StatusCode::BAD_GATEWAY, "oops");
    }

    #[tokio::test]
    async fn server_error_custom_is_redacted_in_response() {
        // The release-build backstop: `custom_client`'s debug_assert is
        // compiled out there, so construct the misuse directly (crate-internal
        // struct-literal access) and prove the message never reaches the wire
        // while the status stays visible.
        let err = AppError::Custom {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "db password is hunter2".into(),
        };

        let (status, body) = respond(err).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["message"], "internal server error");
        assert!(!body.to_string().contains("hunter2"));
    }

    #[tokio::test]
    async fn anyhow_converts_via_the_question_mark_operator() {
        fn handler() -> AppResult<()> {
            Err(anyhow::anyhow!("some dependency blew up"))?
        }

        let (status, body) = respond(handler().unwrap_err()).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["message"], "internal server error");
    }
}
