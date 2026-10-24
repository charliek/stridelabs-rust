//! A policy-free Perplexity Agent API web-search client for StrideLabs
//! services.
//!
//! One search per call, on the consumer's `reqwest::Client`:
//!
//! ```text
//! POST {base}/v1/agent
//! Authorization: Bearer <key>                      (marked sensitive)
//! Content-Type: application/json
//! {"effort":"fast","input":…,"max_output_tokens"?:…}
//!   -> 2xx {"status":"completed",
//!           "output":[{"type":"search_results","results":[{"id":1,"url":…,"title":…,…}]},
//!                     {"type":"message","content":[{"type":"output_text","text":"… [1]"}]}],
//!           "usage":{"input_tokens":…,"output_tokens":…,"total_tokens":…,
//!                    "cost":{"total_cost":…,"currency":…}}, …}
//! ```
//!
//! The answer is a faithful [`SearchAnswer`]: the text of the assistant's
//! `message` items (a message whose `role` is present and not `assistant`,
//! such as an echo of the query, contributes none), every result of every
//! `search_results` item with its citation `id` as given, the status and the
//! usage. Only a `completed` response with no unfinished `message` item is
//! an answer. [`SearchAnswer::sources`] is an optional display helper, never
//! applied implicitly; [`SearchAnswer::from_json`] runs the same parse on a
//! body the caller already has (a recorded one, a test's).
//!
//! Policy-free: the crate classifies and never retries, or logs the input,
//! the key, a body or the answer. The effort, the timeout, the bounds, what
//! to show of an answer, and what to do with each error class are the
//! caller's. It is a search client, not an Agent API SDK: no models, tools,
//! streaming or background responses.
//!
//! ```no_run
//! # async fn example(http: reqwest::Client, api_key: &str) -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::Duration;
//! use stridelabs_perplexity::{Effort, PerplexityClient, PerplexityError};
//!
//! let perplexity = PerplexityClient::builder(http, api_key)
//!     .timeout(Duration::from_secs(30))
//!     .effort(Effort::Fast)
//!     .build()?;
//! match perplexity.search("When did Paris become the capital of France?").await {
//!     Ok(answer) => {
//!         println!("{}", answer.text);
//!         for source in answer.sources(6, 200) {
//!             println!("[{}] {} ({})", source.id, source.title, source.domain);
//!         }
//!     }
//!     Err(PerplexityError::Unavailable(reason)) => println!("try again later: {reason}"),
//!     Err(error) => println!("giving up: {error}"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # The client
//!
//! [`PerplexityClient::builder`] takes the caller's `reqwest::Client`, which
//! **must not follow redirects** (`reqwest::redirect::Policy::none()`): a
//! `3xx` is an answer here ([`PerplexityError::Rejected`]), so
//! `Authorization` is never replayed at a host the configuration did not
//! name. It **must not retry** either (`.retry(reqwest::retry::never())`;
//! reqwest 0.13's default replays a request refused at the protocol level),
//! and should decode no body (`no_gzip()` and the rest: a decoder drops
//! `Content-Length`, which defeats the response pre-check) and use no proxy
//! it did not choose.
//!
//! The base URL is `https://`, or plain `http://` to a loopback IP literal,
//! the seam for a test's mock, and keeps a path prefix
//! ([`PerplexityClientBuilder::base_url`]).
//!
//! # The bounds
//!
//! Builder options, with lumen's defaults:
//!
//! | bound | default | when it is passed |
//! |---|---|---|
//! | [`PerplexityClient::timeout`] | 30 s | the whole exchange, connect to the last body byte, set on each request: [`UnavailableReason::Timeout`] |
//! | [`PerplexityClient::max_response_bytes`] | 2 MiB | refused unread when `Content-Length` says so, otherwise cut chunk by chunk while streaming, never buffered whole: [`MalformedReason::BodyTooLarge`] |
//! | [`PerplexityClient::max_input_chars`] | 2,000 | Unicode scalar values, before anything is sent: [`PerplexityError::InputTooLong`] |
//! | [`PerplexityClient::max_output_tokens`] | unset | the API's own `max_output_tokens`, sent when set; an answer it cuts short is `incomplete` |
//!
//! Zero for any of them is a [`BuildError`].
//!
//! # What a failure becomes
//!
//! | Perplexity | [`PerplexityError`] |
//! |---|---|
//! | `408`, `429`, any status of `500` or more (`600`–`999` included), a timeout (before or after the headers), a connection that could not be made or broke | [`PerplexityError::Unavailable`] |
//! | any other non-`2xx`: a `4xx`, a `3xx` not followed | [`PerplexityError::Rejected`] (`{ status, .. }`) |
//! | a `2xx` whose `status` is not `completed` (`failed`, `incomplete`, …), or with a `message` item whose own `status` is not `completed` | [`PerplexityError::Incomplete`] (`{ status, .. }`) |
//! | a `2xx` that is too large, not UTF-8, not a JSON object, without a string `status` or with more than one, or `completed` with no assistant answer text | [`PerplexityError::Malformed`] |
//! | input over the bound; nothing sent | [`PerplexityError::InputTooLong`] |
//!
//! # Nothing it handles reaches a log
//!
//! Every `Display` and `Debug` of a [`PerplexityError`] or [`BuildError`] is
//! fixed phrases, a status code, a count, a documented response status or a
//! `std::io::ErrorKind`, and its `source()` is always `None`. A transport
//! failure keeps no `reqwest::Error`: its source chain can carry what the
//! peer sent (h2 renders an HTTP/2 GOAWAY's debug data in both `Display` and
//! `Debug`), and `without_url()` strips only the URL. Never a `serde_json`
//! message, the input, the key, a body, or the response's `error` object: an
//! error body is never read, and a `2xx` body's parse errors are dropped
//! unrendered. The `Debug` of the client, its builder, a [`SearchAnswer`],
//! a [`SearchResult`], a [`Source`] and a [`Usage`] show neither the key nor
//! the text, titles, URLs or snippets (their lengths only). The crate's
//! redaction tests hold each path with canaries.
//!
//! # Feature topology
//!
//! None. The crate's `reqwest` has no features at all, so it picks no TLS
//! stack: the client a consumer hands in keeps whatever TLS that consumer
//! chose. It turns on serde_json's `raw_value` (no dependency of its own),
//! for the lenient reads that leave an unrepresentable number out.

mod client;
mod error;
mod response;

pub use client::{
    Effort, PerplexityClient, PerplexityClientBuilder, AGENT_PATH, DEFAULT_BASE_URL,
    DEFAULT_MAX_INPUT_CHARS, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_TIMEOUT,
};
pub use error::{
    BuildError, MalformedReason, PerplexityError, Phase, ResponseStatus, UnavailableReason,
};
pub use response::{SearchAnswer, SearchResult, Source, Usage};
