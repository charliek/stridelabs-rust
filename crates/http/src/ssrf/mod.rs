//! SSRF-hardened outbound fetch (feature `ssrf`).
//!
//! Any server-side path that fetches a URL a user, an LLM or an attacker
//! chose goes through [`fetch_public`]. StrideLabs services run on Cloud Run,
//! where an SSRF that reaches the metadata server (`169.254.169.254`,
//! `metadata.google.internal`) or another internal service is the primary
//! threat. Ported from Python `stridelabs.mcp.ssrf` (stridelabs-mcp 0.4.0):
//! the same steps in the same order, with the same client-safe messages, so
//! a tool ported from Python keeps its errors. Image-specific policy
//! (content-type, magic bytes, `data:` URIs) is not here; it layers on top.
//!
//! ```no_run
//! use http::HeaderValue;
//! use stridelabs_http::ssrf::{fetch_public, FetchPolicy, SsrfError};
//!
//! # async fn example(url: &str) -> Result<(), SsrfError> {
//! let policy = FetchPolicy::new("image", 10 * 1024 * 1024)
//!     .with_accept(HeaderValue::from_static("image/*"));
//! let fetched = fetch_public(url, &policy).await?;
//! println!("{} bytes, {:?}", fetched.body.len(), fetched.content_type);
//! # Ok(())
//! # }
//! ```
//!
//! # The policy, in order
//!
//! 1. **Scheme allowlist**, the caller's choice ([`AllowedSchemes`]): https
//!    only by default; a feed fetcher may allow http too, because the
//!    address policy, not the scheme, is the SSRF control.
//! 2. **Host validation up front**: no embedded credentials; the GCP metadata
//!    names (`metadata.google.internal`, its subdomains, the alias
//!    `metadata`) refused by name; an IP-literal host judged by the address
//!    policy, with no DNS.
//! 3. **DNS pinning**: the host is resolved through the policy's
//!    [`HostResolver`], **every** answer must be public, and the connection
//!    goes to one validated address — never to whatever a second lookup says
//!    (the DNS-rebinding race).
//! 4. **Redirects off by default**. A policy that allows some gets a bounded
//!    chain, and every hop is validated, resolved and pinned from scratch, so
//!    a redirect to an internal address is refused before anything connects
//!    to it.
//! 5. **Bounded download**: a streamed body with a hard byte cap
//!    (`Content-Length` is a claim, not a limit) and one wall-clock budget
//!    for the whole fetch, every hop included.
//! 6. **No content coding**: every request sends `Accept-Encoding: identity`,
//!    reqwest's decoders are switched off by name, and a response with any
//!    `Content-Encoding` other than `identity` is refused as "Could not fetch
//!    the {label} URL." — see below for why that differs from Python.
//!
//! The address policy is [`is_public_address`], written from the IANA
//! special-purpose registries; its docs carry the full table, the source,
//! the retrieval date and every judgement call.
//!
//! # The hostname invariant
//!
//! Pinning is only as good as the agreement between three names: the one the
//! policy checked, the one the connection was pinned under, and the one the
//! request actually goes to. Python gets that agreement from httpx's
//! `sni_hostname` extension; here it is structural:
//!
//! - The URL is parsed with `url` (WHATWG), which IDNA-encodes and
//!   lower-cases an http(s) host. Trailing dots are stripped, and the request
//!   URL is **rebuilt around that normalized host** — so the deny-list, the
//!   resolver, the pin, SNI, certificate verification and the `Host` header
//!   all see one string.
//! - Each hop gets a **fresh `reqwest::Client`** whose DNS resolver answers
//!   **only** that name, with the validated address, and errors for any
//!   other — there is no fallback to system DNS. A request URL that somehow
//!   named a different host fails instead of resolving it. A fresh client
//!   also means no pooled connection ever carries an earlier hop's decision.
//! - `no_proxy()`: a proxy would make the connection, and its DNS, from
//!   somewhere the pin does not reach. It also stops reqwest reading
//!   `HTTPS_PROXY`/`ALL_PROXY` from the environment.
//! - The TCP connection goes to the pinned address on the URL's port; TLS SNI
//!   and certificate verification run against the URL's host — the
//!   normalized name, not the address — through reqwest's `rustls` (the
//!   aws-lc-rs provider and the platform verifier, as `proxy` uses).
//!
//! # Compressed responses: refused, never decoded
//!
//! A deliberate difference from Python, where httpx transparently decodes
//! gzip and deflate (brotli and zstd when installed). Here nothing is ever
//! decompressed: the request asks for `identity`, and a server that encodes
//! anyway gets the generic fetch failure. Decoding would hand back bytes the
//! server did not send under the type it claimed — and, without a decoder,
//! there is no decompression bomb to bound. reqwest's own decoders are
//! disabled per client (`no_gzip()` and friends) even though this crate
//! enables none of their features, because a consumer's graph may, and Cargo
//! unifies features across it. The cost is a server that encodes even when
//! asked for `identity`: it cannot be fetched.
//!
//! # Errors
//!
//! Every failure is an [`SsrfError`] whose `Display` is safe to show a
//! client. Transport details are logged at `debug`, with
//! `reqwest::Error::without_url`, and go nowhere else.
//!
//! That covers this crate's own logging only. reqwest, hyper and hyper-util
//! log through `tracing`/`log` too, and their `DEBUG` and `TRACE` events name
//! the destination — the host, and the pinned address being connected to.
//! That is outside this crate's control: run production at `info` (or keep
//! those crates at `info` in the filter), and treat a debug-level capture of
//! a guarded fetch as carrying the address it reached.
//!
//! # Testing against it
//!
//! [`FetchPolicy::with_resolver`] is the DNS seam: inject a closure, and every
//! address-policy path can be exercised with no network at all. Proving the
//! *pinning* needs a real TLS server, which means a loopback address and a
//! private CA — exactly what the strict policy refuses. The
//! `ssrf-test-support` feature adds `LoopbackTestServer` and
//! `FetchPolicy::with_loopback_test_server`, which admit the loopback
//! addresses named one by one and trust one CA, and nothing else. There is no
//! other way to loosen a policy.
//!
//! What the gate guarantees, precisely:
//!
//! - **Without the feature**, the type, the policy field and the setter are
//!   compiled out: no code path can admit a non-public address.
//! - **With it**, a policy still admits nothing extra until code calls
//!   `with_loopback_test_server`, and then only the loopback addresses it
//!   named.
//! - **Where the feature is on is the consumer's to check.** Putting it in
//!   `[dev-dependencies]` keeps it out of an ordinary `cargo build`, but
//!   Cargo unifies dev-dependency features into the library when building
//!   with `--all-targets`, and a normal dependency anywhere else in the
//!   workspace can enable it for everyone. Guard the shipped build with a
//!   listing of its features, e.g.
//!   `cargo tree -p <service> -e normal,features -i stridelabs-http --prefix none`
//!   containing no `stridelabs-http feature "ssrf-test-support"` line.
//!
//! # Layout
//!
//! As in `proxy`, the submodules are private and everything is re-exported
//! flat, so each item has one public path.

mod address;
mod error;
mod fetch;
mod policy;
mod target;

pub use address::is_public_address;
pub use error::SsrfError;
pub use fetch::{fetch_public, Fetched};
pub use policy::{
    AllowedSchemes, FetchPolicy, HostResolver, ResolveFuture, SystemResolver, DEFAULT_TIMEOUT,
};
#[cfg(feature = "ssrf-test-support")]
pub use policy::{LoopbackTestServer, LoopbackTestServerError};
