//! An explicit-origin CORS layer builder (feature `cors`).
//!
//! New API rather than a port: one of the originating services parses a
//! `cors_origins` config list and then never uses it, and the reverse proxy
//! the rest of this crate's proxy layer came from has no browser-facing
//! surface at all. This is the shape both should have had — the policy comes entirely
//! from the caller (origins, methods, headers), so nothing about one
//! service's front-end is baked into a shared crate.
//!
//! # Why the signature takes explicit lists
//!
//! `tower_http::cors::Any` combined with `allow_credentials(true)` is a
//! **runtime panic** in tower-http (it is also forbidden by the CORS spec: a
//! wildcard `access-control-allow-origin` is invalid on a credentialed
//! response). Because credentials are always on here and origins/methods/
//! headers can only arrive as concrete values, there is no way to express the
//! panicking combination through this function — it is ruled out by
//! construction rather than by a warning in a doc comment.

use http::{header, HeaderName, HeaderValue, Method};
use tower_http::cors::CorsLayer;

/// Build a credentialed CORS layer from an explicit policy.
///
/// - `origins` — allowed origins, e.g. `["https://app.example.com"]`. An
///   empty list allows no cross-origin request; callers that want CORS off
///   entirely should skip the layer instead (see below).
/// - `methods` — allowed request methods, echoed on preflight.
/// - `headers` — allowed request headers, echoed on preflight.
///
/// Credentials are always allowed (`access-control-allow-credentials: true`),
/// since every StrideLabs browser client authenticates with either a cookie
/// or an `Authorization` header.
///
/// Every response the layer touches carries one
/// `vary: origin, access-control-request-method, access-control-request-headers`
/// header, set explicitly rather than left to tower-http's default.
///
/// An origin string that isn't a valid header value is **skipped with a
/// `tracing::warn!`** rather than aborting: that is a typo in deployment
/// config, and the useful behavior is a service that starts, serves its other
/// origins, and says loudly in the logs which entry it dropped — not a boot
/// failure, and not a silent misconfiguration either.
///
/// ```
/// use axum::{routing::get, Router};
/// use http::{header, Method};
/// use stridelabs_http::cors_layer;
///
/// let origins = vec!["https://app.example.com".to_string()];
/// let mut app: Router = Router::new().route("/", get(|| async { "ok" }));
///
/// // Wire it conditionally: no configured origins means no layer at all,
/// // rather than a layer that rejects everything.
/// if !origins.is_empty() {
///     app = app.layer(cors_layer(
///         &origins,
///         &[Method::GET, Method::POST],
///         &[header::AUTHORIZATION, header::CONTENT_TYPE],
///     ));
/// }
/// ```
pub fn cors_layer(origins: &[String], methods: &[Method], headers: &[HeaderName]) -> CorsLayer {
    let allowed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|origin| {
            HeaderValue::from_str(origin)
                .inspect_err(|_| {
                    tracing::warn!(%origin, "ignoring CORS origin: not a valid header value");
                })
                .ok()
        })
        .collect();

    CorsLayer::new()
        .allow_origin(allowed)
        .allow_methods(methods.to_vec())
        .allow_headers(headers.to_vec())
        .allow_credentials(true)
        // Explicit, so the wire does not depend on tower-http's default: 0.6
        // always sent these three names; 0.7 derives the list from the
        // policy and, for an origin list with constant method/header lists,
        // would send `origin` alone (tower-rs/tower-http#674).
        .vary([
            header::ORIGIN,
            header::ACCESS_CONTROL_REQUEST_METHOD,
            header::ACCESS_CONTROL_REQUEST_HEADERS,
        ])
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use http::{header, Request, Response, StatusCode};
    use tower::ServiceExt;

    use super::*;

    const ALLOWED: &str = "https://app.example.com";

    /// A router carrying the layer under test, built from the same policy in
    /// every test so assertions differ only in the request.
    fn app(origins: &[String]) -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(cors_layer(
                origins,
                &[Method::GET, Method::POST],
                &[header::AUTHORIZATION, header::CONTENT_TYPE],
            ))
    }

    fn allowed_origin_app() -> Router {
        app(&[ALLOWED.to_string()])
    }

    /// A plain (non-preflight) cross-origin GET.
    async fn get_from(app: Router, origin: &str) -> Response<Body> {
        let req = Request::builder()
            .uri("/")
            .header(header::ORIGIN, origin)
            .body(Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap()
    }

    /// An `OPTIONS` preflight for a `POST`, which is what makes tower-http
    /// emit the allow-methods/allow-headers lists.
    async fn preflight(app: Router, origin: &str) -> Response<Body> {
        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/")
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
            .body(Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap()
    }

    fn header_value(res: &Response<Body>, name: header::HeaderName) -> Option<String> {
        res.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    }

    #[tokio::test]
    async fn allowed_origin_is_echoed() {
        let res = get_from(allowed_origin_app(), ALLOWED).await;

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            header_value(&res, header::ACCESS_CONTROL_ALLOW_ORIGIN).as_deref(),
            Some(ALLOWED),
            "a credentialed policy must echo the concrete origin, never `*`"
        );
    }

    #[tokio::test]
    async fn disallowed_origin_gets_no_allow_origin_header() {
        let res = get_from(allowed_origin_app(), "https://evil.example.com").await;

        // tower-http lets the request through to the handler; it is the
        // *absence* of the allow-origin header that makes the browser discard
        // the response, so that absence is what to assert on.
        assert_eq!(
            header_value(&res, header::ACCESS_CONTROL_ALLOW_ORIGIN),
            None
        );
    }

    #[tokio::test]
    async fn preflight_advertises_the_configured_methods_and_headers() {
        let res = preflight(allowed_origin_app(), ALLOWED).await;

        let methods = header_value(&res, header::ACCESS_CONTROL_ALLOW_METHODS).unwrap();
        assert!(methods.contains("GET"), "{methods}");
        assert!(methods.contains("POST"), "{methods}");

        let headers = header_value(&res, header::ACCESS_CONTROL_ALLOW_HEADERS).unwrap();
        assert!(headers.contains("authorization"), "{headers}");
        assert!(headers.contains("content-type"), "{headers}");
    }

    #[tokio::test]
    async fn credentials_are_allowed() {
        let res = get_from(allowed_origin_app(), ALLOWED).await;

        assert_eq!(
            header_value(&res, header::ACCESS_CONTROL_ALLOW_CREDENTIALS).as_deref(),
            Some("true")
        );
    }

    #[tokio::test]
    async fn an_invalid_origin_is_skipped_and_the_rest_still_work() {
        // A space makes it an invalid header value; it must not take the
        // whole policy down with it.
        let origins = ["https://bad origin".to_string(), ALLOWED.to_string()];

        let res = get_from(app(&origins), ALLOWED).await;

        assert_eq!(
            header_value(&res, header::ACCESS_CONTROL_ALLOW_ORIGIN).as_deref(),
            Some(ALLOWED)
        );
    }

    /// Every `Vary` header on a response, one string per header line.
    fn vary_lines(res: &Response<Body>) -> Vec<String> {
        res.headers()
            .get_all(header::VARY)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    /// Pins `Vary` on every kind of response the layer touches. The allow-origin
    /// header differs per request origin, so a shared cache needs `Vary: origin`;
    /// the two `access-control-request-*` names are what the preflight answer
    /// depends on. tower-http 0.6 always sent all three, in one header line, and
    /// that is the wire these services have always had.
    #[tokio::test]
    async fn vary_is_the_same_three_names_on_ordinary_and_preflight_responses() {
        const VARY: &str = "origin, access-control-request-method, access-control-request-headers";
        let hostile = "https://evil.example.com";
        let no_origin = Request::builder().uri("/").body(Body::empty()).unwrap();

        let cases = [
            (
                "ordinary GET, allowed origin",
                get_from(allowed_origin_app(), ALLOWED).await,
            ),
            (
                "ordinary GET, disallowed origin",
                get_from(allowed_origin_app(), hostile).await,
            ),
            (
                "ordinary GET, no Origin header",
                allowed_origin_app().oneshot(no_origin).await.unwrap(),
            ),
            (
                "preflight, allowed origin",
                preflight(allowed_origin_app(), ALLOWED).await,
            ),
            (
                "preflight, disallowed origin",
                preflight(allowed_origin_app(), hostile).await,
            ),
        ];

        for (what, res) in cases {
            assert_eq!(vary_lines(&res), [VARY], "Vary on: {what}");
        }
    }

    #[tokio::test]
    async fn an_empty_origin_list_allows_nothing() {
        let res = get_from(app(&[]), ALLOWED).await;

        assert_eq!(
            header_value(&res, header::ACCESS_CONTROL_ALLOW_ORIGIN),
            None
        );
    }
}
