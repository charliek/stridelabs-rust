//! Shared test-only scaffolding for the `proxy` submodules.
//!
//! `body.rs` and `relay.rs` both need to build an in-process `reqwest::Response`
//! and both need to collect an axum `Body` back into `Bytes` for assertions.
//! Kept here once rather than as near-duplicate private helpers in each file.

use axum::body::Body;
use bytes::Bytes;

/// A `reqwest::Response` built from a status/header builder and a body.
///
/// `body` accepts anything `reqwest::Body` can be built from directly
/// (`&'static [u8]`, `String`, an existing `reqwest::Body` from
/// `wrap_stream`, ...), so callers that need a plain byte body and callers
/// that need a custom stream share the same constructor.
pub(super) fn upstream_response(
    build: http::response::Builder,
    body: impl Into<reqwest::Body>,
) -> reqwest::Response {
    reqwest::Response::from(build.body(body.into()).unwrap())
}

/// Drain an axum `Body` into its bytes, for asserting on a relayed body.
pub(super) async fn collect_body(body: Body) -> Bytes {
    axum::body::to_bytes(body, usize::MAX).await.unwrap()
}
