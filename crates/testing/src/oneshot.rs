//! Helpers over `tower::ServiceExt::oneshot` for driving an axum `Router`
//! directly in tests, without binding a socket.
//!
//! Ported from the ad hoc `get`/`body_json` pair duplicated across
//! spendwise-rs's integration tests (e.g. `tests/auth.rs:42-53`) and the same
//! oneshot idiom this workspace's own `stridelabs-http` crate already uses in
//! its `cors` tests. [`req`] is the general form the other three are built
//! from, for the request shapes they don't cover (a non-GET/POST method, a
//! non-JSON body, extra headers).

use axum::body::{to_bytes, Body};
use axum::response::Response;
use axum::Router;
use http::{Method, Request};
use serde::Serialize;
use serde_json::Value;
use tower::ServiceExt;

/// Drive a `GET {uri}` through `router` and return the response.
pub async fn get(router: Router, uri: &str) -> Response {
    req(router, Method::GET, uri, None, &[]).await
}

/// Drive a `POST {uri}` through `router`, JSON-serializing `body` as the
/// request payload (`content-type: application/json`).
pub async fn post_json(router: Router, uri: &str, body: &impl Serialize) -> Response {
    let value = serde_json::to_value(body).expect("serialize request body to JSON");
    req(router, Method::POST, uri, Some(value), &[]).await
}

/// The general form: any method, an optional JSON body, and extra headers.
///
/// `content-type: application/json` is set automatically whenever `body` is
/// `Some`; `headers` are applied afterwards with insert-semantics, so a
/// caller-supplied `content-type` genuinely REPLACES the automatic one
/// rather than appending a second value (builder `.header()` calls append).
pub async fn req(
    router: Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> Response {
    let mut builder = Request::builder().method(method).uri(uri);

    let body = match body {
        Some(value) => {
            builder = builder.header(http::header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&value).expect("serialize JSON body"))
        }
        None => Body::empty(),
    };

    let mut request = builder.body(body).expect("build request");
    for (name, value) in headers {
        let name = http::HeaderName::try_from(*name).expect("valid header name");
        let value = http::HeaderValue::try_from(*value).expect("valid header value");
        request.headers_mut().insert(name, value);
    }
    let request = request;

    // `Router` is an infallible `tower::Service` (its error type is
    // `Infallible`), so a oneshot call can only fail if the request itself
    // was malformed enough to reject before dispatch — which `builder.body`
    // above would already have caught.
    router
        .oneshot(request)
        .await
        .expect("axum Router is an infallible service")
}

/// Read a response body to completion and parse it as JSON.
///
/// # Panics
///
/// Panics if the body cannot be read or is not valid JSON — deliberate for a
/// test helper: the panic message at the failing assertion beats an
/// `unwrap()` chain in every test.
pub async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    serde_json::from_slice(&bytes).expect("response body is valid JSON")
}

#[cfg(test)]
mod tests {
    use axum::routing::{get as get_route, post};
    use axum::Json;
    use http::{HeaderMap, StatusCode};
    use serde_json::json;

    use super::*;

    /// A tiny router exercising the three request shapes the helpers cover:
    /// a plain GET, a JSON echo, and a header readback.
    fn app() -> Router {
        Router::new()
            .route("/ping", get_route(|| async { "pong" }))
            .route(
                "/echo",
                post(|Json(body): Json<Value>| async move { Json(body) }),
            )
            .route(
                "/seen-header",
                get_route(|headers: HeaderMap| async move {
                    headers
                        .get("x-test")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string()
                }),
            )
    }

    #[tokio::test]
    async fn get_round_trips_a_plain_request() {
        let response = get(app(), "/ping").await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&bytes[..], b"pong");
    }

    #[tokio::test]
    async fn post_json_round_trips_a_serialized_body() {
        let response = post_json(app(), "/echo", &json!({"hello": "world"})).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await, json!({"hello": "world"}));
    }

    #[tokio::test]
    async fn req_attaches_extra_headers() {
        let response = req(
            app(),
            Method::GET,
            "/seen-header",
            None,
            &[("x-test", "seen")],
        )
        .await;

        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&bytes[..], b"seen");
    }

    #[tokio::test]
    async fn req_with_no_headers_leaves_the_readback_empty() {
        let response = req(app(), Method::GET, "/seen-header", None, &[]).await;

        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&bytes[..], b"");
    }

    #[tokio::test]
    async fn body_json_parses_the_response_body() {
        let response = post_json(app(), "/echo", &json!({"a": 1})).await;

        assert_eq!(body_json(response).await, json!({"a": 1}));
    }

    #[tokio::test]
    async fn a_missing_route_still_round_trips_through_oneshot() {
        // Not every request the helpers drive hits a registered route; that
        // must produce axum's normal 404, not a panic in the helper itself.
        let response = get(app(), "/does-not-exist").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
