//! A real `tower` layer for request-id resolution and propagation.
//!
//! Carried over from an existing service's `observability::request_id`, which
//! exposed the resolve/generate logic as free functions called by hand at the
//! proxy's call site. That only works because that service has exactly
//! one call site; a shared crate needs the behavior to attach to *any*
//! axum/tower service declaratively, so this is rebuilt as a proper
//! [`tower::Layer`]/[`tower::Service`] pair: add [`RequestIdLayer`] to a
//! `Router`/`ServiceBuilder` and every request gets an id resolved, inserted
//! into its extensions, and echoed on the response header — including error
//! responses, since the wrapping happens around the whole inner
//! `Service::call` future, not a post-success hook bolted onto one handler.
//!
//! Built directly on `tower`/`http` (not `axum`) so it stays usable by any
//! `http::Request`/`http::Response` based service — axum's `Router` is one
//! such service, since axum re-exports the same `http` crate types.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{HeaderValue, Request, Response};
use tower::{Layer, Service};

/// The header carrying the request/trace id, both inbound (if the client
/// already sent one) and outbound (always echoed on the response).
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// The request id resolved by [`RequestIdLayer`], inserted into the
/// request's extensions so downstream handlers/middleware can read it (e.g.
/// to include in a log span, or to forward to an upstream call).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub String);

/// A [`tower::Layer`] that resolves a request id for every request passing
/// through — reusing a reasonable client-supplied `x-request-id` header, or
/// generating a fresh one — inserts it into the request's extensions as
/// [`RequestId`], and echoes it on the response's `x-request-id` header.
///
/// The echo happens for every response the inner service produces,
/// including error status responses (4xx/5xx): the layer wraps the entire
/// inner future, not just a successful-response branch.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestIdLayer;

impl<S> Layer<S> for RequestIdLayer {
    type Service = RequestIdService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestIdService { inner }
    }
}

/// The [`tower::Service`] installed by [`RequestIdLayer`]. See the layer's
/// docs for behavior.
#[derive(Debug, Clone, Copy)]
pub struct RequestIdService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RequestIdService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let id = resolve(&req);

        // Build the header value from `id` before moving it into the
        // extensions, so the resolved id is threaded through as one
        // `String` instead of being cloned.
        //
        // `id` is always either a client value that already passed
        // `is_reasonable` (bounded, ascii-graphic — a valid header value by
        // construction) or our own generated lowercase-hex string, so this
        // can't actually fail; `expect` documents that invariant rather than
        // threading an unreachable error case through the return type.
        let header_value =
            HeaderValue::from_str(&id).expect("resolved request id is always a valid header value");
        req.extensions_mut().insert(RequestId(id));

        let fut = self.inner.call(req);
        Box::pin(async move {
            let mut res = fut.await?;
            res.headers_mut().insert(REQUEST_ID_HEADER, header_value);
            Ok(res)
        })
    }
}

/// The incoming `x-request-id` if present and reasonable, else a fresh id.
fn resolve<ReqBody>(req: &Request<ReqBody>) -> String {
    req.headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| is_reasonable(s))
        .map(str::to_string)
        .unwrap_or_else(generate)
}

/// Whether a client-supplied id is safe to reuse: non-empty, bounded, and
/// printable ASCII — so a malicious or buggy client can't smuggle control
/// characters or an unbounded value into logs and the echoed response
/// header.
fn is_reasonable(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Mint a fresh 128-bit id as 32 lowercase hex characters.
fn generate() -> String {
    let hi: u64 = rand::random();
    let lo: u64 = rand::random();
    format!("{hi:016x}{lo:016x}")
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use http::StatusCode;
    use tower::ServiceExt;

    use super::*;

    /// A tiny bodyless service so tests can focus on headers/extensions
    /// without pulling in a real body type.
    fn layered<F, Fut>(f: F) -> RequestIdService<tower::util::ServiceFn<F>>
    where
        F: FnMut(Request<()>) -> Fut,
        Fut: Future<Output = Result<Response<()>, std::convert::Infallible>>,
    {
        RequestIdLayer.layer(tower::service_fn(f))
    }

    /// The inner service most tests want: always succeeds with an empty 200
    /// response, so tests that only care about request-id resolution/echo
    /// don't each need to write out the same closure.
    fn ok_service(
    ) -> impl Service<Request<()>, Response = Response<()>, Error = std::convert::Infallible> {
        layered(|_req| async { Ok(Response::new(())) })
    }

    /// A bodyless request with no `x-request-id` header.
    fn empty_request() -> Request<()> {
        Request::builder().body(()).unwrap()
    }

    /// A bodyless request carrying `x-request-id: id`. `id` is plain ASCII
    /// in every call site (including the deliberately-invalid ones — a
    /// space, an empty string, 200 `x`s), so it's always a valid
    /// `HeaderValue` by construction; no need for callers to build the
    /// `HeaderValue` themselves.
    fn request_with_id(id: &str) -> Request<()> {
        Request::builder()
            .header(REQUEST_ID_HEADER, HeaderValue::from_str(id).unwrap())
            .body(())
            .unwrap()
    }

    /// Pulls the echoed `x-request-id` response header out as an owned
    /// `String`, so tests assert on it without repeating the
    /// `.get(...).unwrap().to_str().unwrap()` chain.
    fn response_id(res: &Response<()>) -> String {
        res.headers()
            .get(REQUEST_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn reuses_a_reasonable_inbound_id() {
        let res = ok_service()
            .oneshot(request_with_id("client-supplied-id"))
            .await
            .unwrap();

        assert_eq!(response_id(&res), "client-supplied-id");
    }

    #[tokio::test]
    async fn absent_id_is_generated_as_32_lowercase_hex_chars() {
        let res = ok_service().oneshot(empty_request()).await.unwrap();

        let id = response_id(&res);
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(
            id,
            id.to_ascii_lowercase(),
            "generated id must be lowercase"
        );
    }

    #[tokio::test]
    async fn over_long_inbound_id_is_replaced() {
        let long = "x".repeat(200);
        let res = ok_service().oneshot(request_with_id(&long)).await.unwrap();

        assert_eq!(
            response_id(&res).len(),
            32,
            "over-long id replaced with a generated one"
        );
    }

    #[tokio::test]
    async fn non_graphic_inbound_id_is_replaced() {
        // A space is a valid `HeaderValue` byte but not `is_ascii_graphic`,
        // so it exercises the "invalid" branch without needing an
        // unconstructible control character.
        let res = ok_service()
            .oneshot(request_with_id("has space"))
            .await
            .unwrap();

        assert_eq!(
            response_id(&res).len(),
            32,
            "non-graphic id replaced with a generated one"
        );
    }

    #[tokio::test]
    async fn empty_inbound_id_is_replaced() {
        let res = ok_service().oneshot(request_with_id("")).await.unwrap();

        assert_eq!(
            response_id(&res).len(),
            32,
            "empty id replaced with a generated one"
        );
    }

    #[tokio::test]
    async fn request_id_extension_is_present_for_the_inner_service() {
        let captured: Arc<Mutex<Option<RequestId>>> = Arc::new(Mutex::new(None));
        let captured_in_service = captured.clone();
        let svc = layered(move |req: Request<()>| {
            let captured = captured_in_service.clone();
            async move {
                *captured.lock().unwrap() = req.extensions().get::<RequestId>().cloned();
                Ok(Response::new(()))
            }
        });

        svc.oneshot(request_with_id("seen-by-inner")).await.unwrap();

        assert_eq!(
            captured.lock().unwrap().as_ref(),
            Some(&RequestId("seen-by-inner".to_string()))
        );
    }

    #[tokio::test]
    async fn response_carries_the_header() {
        let res = ok_service().oneshot(empty_request()).await.unwrap();

        assert!(res.headers().get(REQUEST_ID_HEADER).is_some());
    }

    #[tokio::test]
    async fn response_header_present_on_error_status_response() {
        // "Error" here is an HTTP error *status*, not a `tower::Service`
        // `Err` — the inner service still returns `Ok(Response)`, just with
        // a 5xx status, which is the normal axum-handler shape for an error.
        // Proves the echo isn't gated on a 2xx-only "success" branch.
        let svc = layered(|_req| async {
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(())
                .unwrap())
        });

        let res = svc.oneshot(empty_request()).await.unwrap();

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(res.headers().get(REQUEST_ID_HEADER).is_some());
    }

    #[tokio::test]
    async fn works_as_a_real_axum_layer() {
        use axum::body::Body;
        use axum::routing::get;
        use axum::Router;

        let app: Router = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(RequestIdLayer);

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.headers().get(REQUEST_ID_HEADER).is_some());
    }
}
