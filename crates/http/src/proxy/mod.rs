//! Reverse-proxy primitives (feature `proxy`).
//!
//! Ported from limen's `src/http/{proxy,body,client}.rs` with **no behavior
//! change** — limen is a production reverse proxy, and these are the pieces of
//! it that are not about limen: which headers may cross a hop, how to turn a
//! client request's path into an upstream URL, how to hand a `reqwest`
//! response back to axum, how to buffer a body without letting an unbounded
//! one buffer, how to state (rather than relay) the `X-Forwarded-*` context,
//! how to build the upstream client, and how to say what went wrong upstream
//! without handing anyone the upstream's URL.
//!
//! What did change is the shape of the seams. Every one of these was private
//! to limen, and two of them reached into limen's config types; here they are
//! free functions over plain arguments ([`UpstreamClient::build`] takes a bool
//! and PEM bytes rather than a `UpstreamTlsConfig`), so a second proxy can
//! adopt them without adopting limen's configuration model.
//!
//! # What this is not
//!
//! There is no proxy *handler* here. Routing, retries, timeouts, circuit
//! breaking, shadowing and metrics are policy — they differ per service and
//! belong to the service. This module is the mechanical layer underneath all
//! of that, which is the part everyone re-derives (usually forgetting a
//! hop-by-hop header or the `Connection` token list).
//!
//! ```no_run
//! use stridelabs_http::proxy::{
//!     build_upstream_url, filter_headers, relay_response, Direction, UpstreamClient,
//! };
//! use url::Url;
//!
//! # async fn example(req_headers: http::HeaderMap) -> Result<(), Box<dyn std::error::Error>> {
//! let client = UpstreamClient::build(true, None)?;
//! let base = Url::parse("https://upstream.internal")?;
//! let url = build_upstream_url(&base, "/widgets/1", Some("verbose=1"))
//!     .ok_or("path would be rewritten")?;
//!
//! let upstream = client
//!     .inner()
//!     .get(url)
//!     .headers(filter_headers(&req_headers, Direction::Request))
//!     .send()
//!     .await?;
//!
//! let response = relay_response(upstream);
//! # let _ = response;
//! # Ok(())
//! # }
//! ```
//!
//! # Layout
//!
//! The submodules are private and everything is re-exported flat, so each item
//! has exactly one public path (`proxy::filter_headers`, not also
//! `proxy::filter::filter_headers`). The filter/relay/body/client split is how
//! this code is *written*, not a taxonomy callers should have to learn — and
//! keeping it private leaves it free to change.

mod body;
mod client;
mod filter;
mod forwarded;
mod relay;
#[cfg(test)]
mod test_support;
mod upstream;

pub use body::{buffer_or_stream, buffer_or_stream_within, buffer_request_or_stream, Buffered};
pub use client::{ClientBuildError, UpstreamClient};
pub use filter::{connection_tokens, filter_headers, request_has_body, Direction, HOP_BY_HOP};
pub use forwarded::{apply_forwarded, ForwardedPolicy, XffPolicy, XfpPolicy};
pub use relay::{build_upstream_url, relay_response, response_from_parts};
pub use upstream::{UpstreamCategory, UpstreamFailure};
