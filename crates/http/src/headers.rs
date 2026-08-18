//! Baseline security response headers, as one tower layer.
//!
//! New API rather than a port: both originating services set (some of)
//! these ad hoc, which means "did we remember it on this router?" is a
//! per-service question. Here it's one call, applied to every response the
//! wrapped service produces — successes, 4xx, 5xx alike, since the setters
//! run on the response on its way out and don't care what produced it.

use http::header::{
    HeaderName, HeaderValue, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use tower::layer::util::Stack;
use tower::Layer;
use tower_http::set_header::SetResponseHeaderLayer;

/// One `SetResponseHeaderLayer` per baseline header, stacked. Deliberately
/// private: the arity is exactly the implementation detail that
/// [`SecurityHeadersLayer`] exists to hide, so adding a fourth header stays a
/// non-breaking change.
type Composed = Stack<
    SetResponseHeaderLayer<HeaderValue>,
    Stack<SetResponseHeaderLayer<HeaderValue>, SetResponseHeaderLayer<HeaderValue>>,
>;

fn header(name: HeaderName, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(name, HeaderValue::from_static(value))
}

fn composed() -> Composed {
    Stack::new(
        header(X_CONTENT_TYPE_OPTIONS, "nosniff"),
        Stack::new(
            header(X_FRAME_OPTIONS, "DENY"),
            header(REFERRER_POLICY, "strict-origin-when-cross-origin"),
        ),
    )
}

/// The layer returned by [`security_headers`]. See that function for what it
/// sets and why.
///
/// A named unit struct rather than an alias for the underlying composition,
/// which matters for the use it advertises: a caller can store it in a struct
/// field or name it as a return type, and a future version that adds a fourth
/// header (a CSP, say) doesn't change the type they wrote down. It also
/// matches how `stridelabs-observability` exposes `RequestIdLayer`, so the two
/// layers a service imports together look alike.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityHeadersLayer;

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = <Composed as Layer<S>>::Service;

    fn layer(&self, inner: S) -> Self::Service {
        composed().layer(inner)
    }
}

/// A layer that stamps the baseline security headers on every response:
///
/// | Header | Value | Why |
/// |---|---|---|
/// | `x-content-type-options` | `nosniff` | Stops the browser from second-guessing our `content-type` (an API returning JSON must never be sniffed as HTML and executed). |
/// | `x-frame-options` | `DENY` | No framing at all. These are APIs and auth surfaces; there is no legitimate embed, so clickjacking gets no seam. |
/// | `referrer-policy` | `strict-origin-when-cross-origin` | Full URLs (which carry ids, and sometimes tokens) never leave for a third-party origin. |
///
/// Values are set with `overriding` semantics: whatever the handler set is
/// replaced. A security baseline that any handler can silently opt out of by
/// setting its own value isn't a baseline — a route that genuinely needs
/// different framing rules should not be behind this layer at all.
///
/// ```
/// use axum::{routing::get, Router};
/// use stridelabs_http::security_headers;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(security_headers());
/// ```
pub fn security_headers() -> SecurityHeadersLayer {
    SecurityHeadersLayer
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::routing::{get, MethodRouter};
    use axum::Router;
    use http::{Request, Response, StatusCode};
    use tower::ServiceExt;

    use super::*;
    use crate::AppError;

    /// Every test here layers the baseline over a single route and varies only
    /// the handler, so the handler is the only thing a test spells out.
    fn app(route: MethodRouter) -> Router {
        Router::new().route("/", route).layer(security_headers())
    }

    /// Assert the full baseline is present on a response, so each test states
    /// only what is interesting about *how* that response was produced.
    fn assert_secure(res: &Response<Body>) {
        let headers = res.headers();
        assert_eq!(headers.get(X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
        assert_eq!(headers.get(X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(
            headers.get(REFERRER_POLICY).unwrap(),
            "strict-origin-when-cross-origin"
        );
    }

    fn request() -> Request<Body> {
        Request::builder().uri("/").body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn all_three_headers_are_set_on_a_success() {
        let res = app(get(|| async { "ok" }))
            .oneshot(request())
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_secure(&res);
    }

    #[tokio::test]
    async fn all_three_headers_are_set_on_an_error_response() {
        // The headers must survive the error path too — that's where a
        // hand-rolled "set them in the happy-path handler" approach leaks.
        let res = app(get(|| async {
            Err::<&str, _>(AppError::Internal(anyhow::anyhow!("boom")))
        }))
        .oneshot(request())
        .await
        .unwrap();

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_secure(&res);
    }

    #[tokio::test]
    async fn a_handler_cannot_weaken_the_baseline() {
        let res = app(get(|| async { ([(X_FRAME_OPTIONS, "SAMEORIGIN")], "ok") }))
            .oneshot(request())
            .await
            .unwrap();

        assert_secure(&res);
    }
}
