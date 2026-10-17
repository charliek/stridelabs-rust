//! RFC 9728 protected-resource metadata, served at the origin root.
//!
//! MCP clients discover how to authorize by fetching the metadata document
//! at the **origin root**, not under the MCP endpoint: both the bare
//! well-known path and a variant suffixed with the resource's path (for
//! `https://app.example/mcp`, `/.well-known/oauth-protected-resource/mcp`).
//! Which one a client tries depends on the spec revision it implements, so
//! both answer with the same document. The `401` challenge at the MCP
//! boundary points `resource_metadata` at the suffixed one
//! ([`crate::ProtectedResource::metadata_url`]).
//!
//! This is a router of its own, rather than routes inside [`crate::router`],
//! because those paths are not under the endpoint and must not sit behind
//! its bearer check: an unauthenticated client fetching them is the whole
//! point.

use axum::body::Bytes;
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderValue;
use axum::routing::get;
use axum::Router;

use crate::resource::ProtectedResource;

/// A router serving `resource`'s metadata document at both origin-root
/// well-known paths (one, for a resource at the origin root).
///
/// Generic over the state type so it merges into any app:
/// `app.merge(metadata_router(&resource))`. `GET` and `HEAD` only; no CORS
/// headers (a browser-based client that needs them gets them from the app's
/// own CORS layer, as for any other route).
///
/// One per origin: the bare well-known path names a single resource, so
/// merging the routers of two resources on the same origin is an axum
/// overlapping-route panic at startup, not two documents.
pub fn metadata_router<S>(resource: &ProtectedResource) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    // Serialized once: the document never changes for the life of the router.
    let body = Bytes::from(
        serde_json::to_vec(&resource.metadata()).expect("the metadata document serializes"),
    );
    let mut router = Router::new();
    for path in resource.metadata_paths() {
        let body = body.clone();
        router = router.route(
            &path,
            get(move || async move {
                (
                    [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
                    body,
                )
            }),
        );
    }
    router
}

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request, StatusCode};
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;

    async fn fetch(router: Router, method: Method, path: &str) -> (StatusCode, Option<Value>) {
        let response = router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("infallible");
        let status = response.status();
        let is_json = response
            .headers()
            .get(CONTENT_TYPE)
            .is_some_and(|value| value == "application/json");
        let bytes = to_bytes(response.into_body(), 1 << 16).await.expect("body");
        let body = (is_json && !bytes.is_empty())
            .then(|| serde_json::from_slice(&bytes).expect("a JSON body"));
        (status, body)
    }

    fn parcel() -> ProtectedResource {
        ProtectedResource::new(
            "https://parcel.stridelabs.ai/mcp",
            "https://auth.stridelabs.ai",
            ["parcel:read", "parcel:write"],
        )
        .expect("canonical")
    }

    #[tokio::test]
    async fn the_document_is_served_at_both_origin_root_paths() {
        let expected = json!({
            "resource": "https://parcel.stridelabs.ai/mcp",
            "authorization_servers": ["https://auth.stridelabs.ai"],
            "scopes_supported": ["parcel:read", "parcel:write"],
            "bearer_methods_supported": ["header"],
        });

        for path in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ] {
            let (status, body) = fetch(metadata_router(&parcel()), Method::GET, path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(body, Some(expected.clone()), "{path}");
        }
    }

    #[tokio::test]
    async fn nothing_is_served_under_the_endpoint_or_on_other_methods() {
        for path in [
            "/mcp/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/other",
            "/.well-known/oauth-protected-resource/mcp/",
            "/mcp",
        ] {
            let (status, _) = fetch(metadata_router(&parcel()), Method::GET, path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        }

        let (status, _) = fetch(
            metadata_router(&parcel()),
            Method::POST,
            "/.well-known/oauth-protected-resource",
        )
        .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn head_answers_too() {
        let (status, _) = fetch(
            metadata_router(&parcel()),
            Method::HEAD,
            "/.well-known/oauth-protected-resource/mcp",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_root_resource_is_served_at_the_bare_path_only() {
        let root = ProtectedResource::new("https://mcp.stridelabs.ai", "https://auth", ["a"])
            .expect("canonical");

        let (status, body) = fetch(
            metadata_router(&root),
            Method::GET,
            "/.well-known/oauth-protected-resource",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.expect("json")["resource"], "https://mcp.stridelabs.ai");
    }

    #[tokio::test]
    async fn it_merges_into_an_app_with_its_own_state() {
        #[derive(Clone)]
        struct AppState;

        let app: Router = Router::new()
            .route("/health", get(|| async { "ok" }))
            .merge(metadata_router(&parcel()))
            .with_state(AppState);

        let (status, body) = fetch(app, Method::GET, "/.well-known/oauth-protected-resource").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_some());
    }
}
