//! Classifying an upstream (`reqwest`) failure without ever showing it to a
//! client — or to a log line that a client's own input can steer.
//!
//! # The leak this exists to close
//!
//! `reqwest::Error`'s `Display` ends with `" for url ({url})"` whenever the
//! error carries a URL, and its `Debug` prints the same URL as a field. That
//! URL is the *full* upstream URL: host, port, path, **and query string**. So
//! every one of these leaks it:
//!
//! ```text
//! tracing::error!("upstream failed: {e}");          // Display  -> leaks
//! tracing::error!(error = ?e, "upstream failed");   // Debug    -> leaks
//! AppError::BadGateway(format!("upstream: {e}"))    // to the CLIENT -> leaks
//! ```
//!
//! What is in that URL is service-specific and rarely harmless: one service's
//! is an internal provider endpoint configured via environment — exactly the
//! class of leak this redaction exists to close — slauth's carries Hydra's
//! login/consent/logout **challenge tokens** in the query, and a proxy's
//! carries the caller's own query string, which it then hands back to the
//! caller in an error body.
//!
//! [`UpstreamFailure::classify`] is the alternative: reduce the error to the
//! handful of *booleans* `reqwest` already computes, and log those. It is a
//! pure function of the error — it allocates nothing, reads no URL, and
//! cannot be made to render one.
//!
//! # Total by construction
//!
//! All four predicates can be false at once with no status attached:
//! builder-class errors (an unsupported scheme), redirect-policy errors and
//! decode errors all land there, and an all-false log line tells an operator
//! nothing. That is why the struct also carries a [`UpstreamCategory`], which
//! is total: every error gets a named category, including
//! [`UpstreamCategory::Other`] for a `reqwest` failure kind this crate does
//! not name.
//!
//! # Who this module is for
//!
//! Everyone — the classification and the log helper are wire-shape agnostic.
//! Only the *constructor* built on top of it,
//! [`AppError::bad_gateway_upstream`](crate::AppError::bad_gateway_upstream),
//! is narrow: it renders this crate's `{"error": {…}}` envelope, so a service
//! with its own envelope (slauth's `{"detail": …}`) adopts
//! `classify` + [`UpstreamFailure::log`] and keeps its own error type and
//! bodies.

use http::StatusCode;

/// The classification of an upstream failure: `reqwest`'s own predicates,
/// reduced to plain data that carries no URL, no query string and no message.
///
/// Built only by [`UpstreamFailure::classify`]. The fields keep `reqwest`'s
/// `is_*` spelling on purpose — they are exactly the predicates it exposes,
/// and exactly the field names slauth and spendwise already emit, so adopting
/// this type doesn't rename a field an operator has a query saved against.
///
/// `#[non_exhaustive]`: `reqwest` can grow a predicate (this crate deliberately
/// does not expose all of them today — see [`UpstreamCategory`]), and adding a
/// field here should not be a breaking change. Reading fields and destructuring
/// with a trailing `..` both still work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpstreamFailure {
    /// The connection was never established: DNS, TCP, or TLS handshake.
    pub is_connect: bool,
    /// Something in the chain timed out — a connect timeout *or* a response
    /// that took too long. `is_connect` tells the two apart.
    pub is_timeout: bool,
    /// `reqwest`'s umbrella "error sending request" kind. Usually true
    /// alongside `is_connect`/`is_timeout`, which are the specific answers.
    pub is_request: bool,
    /// A request- or response-body error.
    ///
    /// Narrower than it looks: a *truncated response body* read through
    /// `Response::bytes()` is a **decode** error in reqwest 0.12, not a body
    /// error, so this stays false and [`UpstreamFailure::category`] reports
    /// [`UpstreamCategory::Decode`]. Both slauth and spendwise log
    /// `is_body` at their body-read sites today and get `false` for exactly
    /// the failure they are logging; the category is what fixes that.
    pub is_body: bool,
    /// The upstream's status — `Some` **only** for an error produced by
    /// `Response::error_for_status()`.
    ///
    /// Usually `None`, and that is not a defect: a failure that reached a
    /// status at all is a response the caller already has in hand, so most
    /// call sites never build a `reqwest::Error` from one (neither slauth nor
    /// spendwise nor limen uses `error_for_status`). It is here so the field
    /// exists for the sites that do, rather than being silently dropped.
    pub status: Option<StatusCode>,
    /// The single most specific name for this failure — total, so a log line
    /// is never blank even when every predicate above is false.
    pub category: UpstreamCategory,
}

/// The one-word answer to "what went wrong upstream".
///
/// Derived from the predicates by a fixed precedence (see
/// [`UpstreamFailure::classify`]) so that a log field is stable enough to
/// group by, and total so that it is never empty.
///
/// `#[non_exhaustive]`: `reqwest`'s own set of error kinds is not frozen, and
/// a category added here for one of them must not break a `match`. Wildcard
/// arms are required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpstreamCategory {
    /// The connection was never established (DNS, TCP, TLS) — including when
    /// establishing it timed out. The upstream was unreachable.
    Connect,
    /// A connection existed; the exchange over it ran out of time.
    Timeout,
    /// `Response::error_for_status()` on a 4xx/5xx. `status` is `Some`.
    Status,
    /// A request- or response-body error.
    Body,
    /// The response body could not be decoded — including a body that ended
    /// early (`content-length` unmet, incomplete chunked message).
    Decode,
    /// The redirect policy refused to continue (a loop, or too many hops).
    Redirect,
    /// The request could not be built at all — e.g. a URL whose scheme
    /// `reqwest` will not send. Nothing left the process.
    Builder,
    /// `reqwest` reports only its umbrella "error sending request" kind, with
    /// no more specific predicate true.
    Request,
    /// A failure kind this crate does not name (today: a protocol-upgrade
    /// error), or one `reqwest` adds later. The fallback that makes the
    /// classification total.
    Other,
}

impl UpstreamCategory {
    /// A stable, lowercase name for the category — what the log field
    /// carries, so a query written against it survives a `Debug` rename.
    pub fn as_str(&self) -> &'static str {
        match self {
            UpstreamCategory::Connect => "connect",
            UpstreamCategory::Timeout => "timeout",
            UpstreamCategory::Status => "status",
            UpstreamCategory::Body => "body",
            UpstreamCategory::Decode => "decode",
            UpstreamCategory::Redirect => "redirect",
            UpstreamCategory::Builder => "builder",
            UpstreamCategory::Request => "request",
            UpstreamCategory::Other => "other",
        }
    }
}

impl std::fmt::Display for UpstreamCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl UpstreamFailure {
    /// Reduce a `reqwest::Error` to its classification.
    ///
    /// Pure: it reads only the error's own predicates. The error itself is
    /// borrowed, never stored, never formatted, and its URL is never touched
    /// — so no value produced here can carry one.
    ///
    /// # Category precedence
    ///
    /// The predicates are not mutually exclusive (a connect timeout is both
    /// `is_connect` and `is_timeout`; nearly everything that left the process
    /// is also `is_request`), so [`UpstreamFailure::category`] applies a fixed
    /// order and reports the most specific hit:
    ///
    /// `Connect` → `Timeout` → `Status` → `Body` → `Decode` → `Redirect` →
    /// `Builder` → `Request` → `Other`.
    ///
    /// `Connect` outranks `Timeout` deliberately: a connect timeout and a
    /// refused connection are the same operational fact ("could not reach the
    /// upstream"), while a `Timeout` that is *not* a connect failure means the
    /// upstream answered the handshake and then took too long — a different
    /// problem with a different fix. Both booleans are still on the struct for
    /// a caller that wants to tell a slow connect from a fast refusal.
    ///
    /// `Request` sits second-to-last because it is `reqwest`'s umbrella kind:
    /// reporting it above the specific predicates would collapse every
    /// send-side failure into one bucket.
    ///
    /// ```no_run
    /// use stridelabs_http::proxy::{UpstreamCategory, UpstreamFailure};
    ///
    /// # async fn example(client: &reqwest::Client) {
    /// if let Err(e) = client.get("https://upstream.internal/v1?key=secret").send().await {
    ///     let failure = UpstreamFailure::classify(&e);
    ///     // Log the classification — never `{e}` or `?e`, both of which
    ///     // render the URL and its query string.
    ///     failure.log("widget fetch failed");
    ///     if failure.category == UpstreamCategory::Connect {
    ///         // … circuit-breaker bookkeeping, say.
    ///     }
    /// }
    /// # }
    /// ```
    pub fn classify(err: &reqwest::Error) -> UpstreamFailure {
        let is_connect = err.is_connect();
        let is_timeout = err.is_timeout();
        let is_request = err.is_request();
        let is_body = err.is_body();
        let status = err.status();

        // Every arm is a `reqwest` predicate; the final `else` is what makes
        // this total for the kinds none of them cover (upgrade today, and
        // whatever a future version adds).
        let category = if is_connect {
            UpstreamCategory::Connect
        } else if is_timeout {
            UpstreamCategory::Timeout
        } else if status.is_some() {
            UpstreamCategory::Status
        } else if is_body {
            UpstreamCategory::Body
        } else if err.is_decode() {
            UpstreamCategory::Decode
        } else if err.is_redirect() {
            UpstreamCategory::Redirect
        } else if err.is_builder() {
            UpstreamCategory::Builder
        } else if is_request {
            UpstreamCategory::Request
        } else {
            UpstreamCategory::Other
        };

        UpstreamFailure {
            is_connect,
            is_timeout,
            is_request,
            is_body,
            status,
            category,
        }
    }

    /// Emit this classification as a `tracing` event at `ERROR`, with
    /// `message` as the event's message.
    ///
    /// Every value is a **structured field**; the message is whatever the call
    /// site passes. Nothing here formats the error, because nothing here has
    /// the error.
    ///
    /// ```text
    /// is_connect=false is_timeout=true is_request=true is_body=false category="timeout"
    /// ```
    ///
    /// `status` is emitted only when it is `Some` (tracing skips a `None`
    /// field), so the usual line carries five fields, not six.
    ///
    /// # Two things a call site still owns
    ///
    /// - **`message` must be a fixed string.** Formatting the error into it
    ///   (`&format!("{e}")`) puts the URL back, and no helper can stop that.
    ///   Pass a literal that names the call site, the way spendwise's two
    ///   sites do ("upstream chat-completions request failed" vs. "reading
    ///   upstream chat-completions response failed").
    /// - **The event's callsite metadata is this crate's**, not yours:
    ///   `target`, module path, file and line all point at
    ///   `stridelabs_http::proxy::upstream`, because that is where the macro
    ///   is expanded. A subscriber filtering by target (`RUST_LOG=my_svc=warn`)
    ///   will not match these. If per-module filtering matters more than the
    ///   convenience, emit your own event — the fields are public:
    ///
    /// ```
    /// # use stridelabs_http::proxy::UpstreamFailure;
    /// # fn example(f: UpstreamFailure) {
    /// tracing::error!(
    ///     is_connect = f.is_connect,
    ///     is_timeout = f.is_timeout,
    ///     is_request = f.is_request,
    ///     is_body = f.is_body,
    ///     status = f.status.map(|s| s.as_u16()),
    ///     category = f.category.as_str(),
    ///     "upstream request failed",
    /// );
    /// # }
    /// ```
    pub fn log(&self, message: &str) {
        tracing::error!(
            is_connect = self.is_connect,
            is_timeout = self.is_timeout,
            is_request = self.is_request,
            is_body = self.is_body,
            status = self.status.map(|s| s.as_u16()),
            category = self.category.as_str(),
            "{message}",
        );
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::response::IntoResponse as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tracing_subscriber::fmt::MakeWriter;

    use super::super::test_support::collect_body;
    use super::*;
    use crate::AppError;

    // --- the canary --------------------------------------------------------
    //
    // Every fixture below builds its error against a URL carrying these three
    // markers. Any of them appearing in a log line or a response body is the
    // leak this module exists to close, so the assertions look for the markers
    // rather than for a specific rendering.

    const CANARY_HOST: &str = "leak-canary-host.example";
    const CANARY_PATH: &str = "/leak-canary-path";
    const CANARY_QUERY: &str = "leak_token=zx9-CANARY-7q";
    const CANARY_MARKERS: &[&str] = &["leak-canary", "leak_token", "CANARY"];

    /// The client-visible body every `bad_gateway_upstream` must render,
    /// byte for byte, whatever produced it.
    const EXPECTED_BODY: &str =
        r#"{"error":{"message":"upstream request failed","type":"Bad Gateway"}}"#;

    #[track_caller]
    fn assert_no_canary(haystack: &str, what: &str) {
        for marker in CANARY_MARKERS {
            assert!(
                !haystack.contains(marker),
                "{what} leaked upstream URL material ({marker:?}): {haystack}"
            );
        }
    }

    // --- capturing tracing output -----------------------------------------

    /// A `MakeWriter` that keeps every byte the fmt subscriber writes.
    #[derive(Clone, Default)]
    struct LogSink(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log sink").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for LogSink {
        type Writer = LogSink;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run `f` with a capturing subscriber installed, and hand back what it
    /// returned along with everything it logged.
    ///
    /// A thread-local default (`with_default`), not the global one: the global
    /// subscriber can be set exactly once per process, so a global would let
    /// the first test that ran silence every other one.
    fn capturing<T>(f: impl FnOnce() -> T) -> (T, String) {
        let sink = LogSink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            // No escape codes in the captured text: the assertions are
            // substring searches over it.
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();

        let out = tracing::subscriber::with_default(subscriber, f);
        let mut sink_out = sink.clone();
        sink_out.flush().expect("flush");
        let bytes = sink.0.lock().expect("log sink").clone();
        (out, String::from_utf8(bytes).expect("utf-8 log output"))
    }

    // --- fixtures: one real `reqwest::Error` per failure class -------------

    /// What the throwaway server does after reading the request.
    enum Behavior {
        /// Accept, read, and never answer — the client's timeout fires.
        NeverRespond,
        /// A 4xx/5xx, so `error_for_status()` has something to fail on.
        Status(u16),
        /// Promise 100 bytes, send 5, hang up — the body read fails.
        TruncatedBody,
    }

    /// A one-shot HTTP/1.1 server on loopback. Raw sockets rather than
    /// `wiremock` because two of the three behaviors (never answering, an
    /// under-delivered `content-length`) are precisely the ones a well-behaved
    /// mock server will not produce.
    async fn spawn(behavior: Behavior) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");

            // Drain the request head so the client's write completes.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match sock.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }

            match behavior {
                Behavior::NeverRespond => {
                    // Hold the connection open past any test's lifetime; the
                    // client's own timeout is what ends the exchange.
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
                Behavior::Status(code) => {
                    let head = format!(
                        "HTTP/1.1 {code} \r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.shutdown().await;
                }
                Behavior::TruncatedBody => {
                    let head =
                        "HTTP/1.1 200 OK\r\ncontent-length: 100\r\nconnection: close\r\n\r\nshort";
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.shutdown().await;
                }
            }
        });

        addr
    }

    fn canary_url(addr: SocketAddr) -> String {
        format!("http://{addr}{CANARY_PATH}?{CANARY_QUERY}")
    }

    /// A port nothing is listening on: bind one, learn its number, drop it.
    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        port
    }

    /// A refused connection — retried past the port race rather than trusting
    /// it.
    ///
    /// [`closed_port`] can only report a port that *was* free: between the
    /// listener being dropped and the connect below, the OS is free to hand
    /// the same number to something else, and this test module asks it for
    /// ephemeral ports constantly (every `spawn` above takes one, and the five
    /// fixtures are built concurrently). Losing that race is not a finding
    /// about the code under test — it means the connect either succeeded or,
    /// worse, landed on the never-answering server — so take a fresh port and
    /// try again.
    async fn connect_error() -> reqwest::Error {
        const ATTEMPTS: usize = 3;

        // The timeout exists only for the lost-race case: a request that lands
        // on `Behavior::NeverRespond` would otherwise hang the suite forever.
        // It is far longer than a refusal takes, so it never fires on the
        // path this fixture is actually for — and if it does fire, the error
        // is not connect-class and is retried rather than mistaken for one.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client");

        for _ in 0..ATTEMPTS {
            let port = closed_port();
            let outcome = client
                .get(format!(
                    "http://127.0.0.1:{port}{CANARY_PATH}?{CANARY_QUERY}"
                ))
                .send()
                .await;

            match outcome {
                Err(e) if e.is_connect() => return e,
                // Something answered on that port, or answering it took the
                // whole timeout: either way the port was re-bound after
                // `closed_port` handed it over.
                _ => {}
            }
        }

        panic!(
            "no ephemeral port stayed closed across {ATTEMPTS} attempts — every one was re-bound \
             between `closed_port` and the connect, so this fixture never produced the \
             connect-class error it exists to produce"
        )
    }

    async fn timeout_error() -> reqwest::Error {
        let addr = spawn(Behavior::NeverRespond).await;
        reqwest::Client::builder()
            .timeout(Duration::from_millis(150))
            .build()
            .expect("client")
            .get(canary_url(addr))
            .send()
            .await
            .expect_err("a server that never answers must time the request out")
    }

    async fn status_error() -> reqwest::Error {
        let addr = spawn(Behavior::Status(503)).await;
        reqwest::Client::new()
            .get(canary_url(addr))
            .send()
            .await
            .expect("headers arrive")
            .error_for_status()
            .expect_err("503 must become an error")
    }

    async fn body_error() -> reqwest::Error {
        let addr = spawn(Behavior::TruncatedBody).await;
        reqwest::Client::new()
            .get(canary_url(addr))
            .send()
            .await
            .expect("headers arrive")
            .bytes()
            .await
            .expect_err("a body short of its content-length must fail")
    }

    /// The builder class: `reqwest` refuses the scheme before anything is
    /// sent, so all four predicates are false and there is no status — the
    /// input that would make an unclassified log line blank.
    async fn builder_error() -> reqwest::Error {
        reqwest::Client::new()
            .get(format!("ftp://{CANARY_HOST}{CANARY_PATH}?{CANARY_QUERY}"))
            .send()
            .await
            .expect_err("reqwest must refuse a non-http scheme")
    }

    /// Built concurrently, not one `await` after another: each fixture spins
    /// up its own throwaway server (or waits out its own 150ms timeout), and
    /// those are independent of one another — running them in sequence would
    /// only add wall-clock time to every test below without buying anything.
    async fn every_failure_class() -> Vec<(&'static str, reqwest::Error)> {
        let (connect, timeout, status, body, builder) = tokio::join!(
            connect_error(),
            timeout_error(),
            status_error(),
            body_error(),
            builder_error(),
        );
        vec![
            ("connect", connect),
            ("timeout", timeout),
            ("status", status),
            ("body", body),
            ("builder", builder),
        ]
    }

    /// Render an `AppError` the way axum would, and hand back the raw body.
    async fn body_of(err: AppError) -> String {
        let bytes = collect_body(err.into_response().into_body()).await;
        String::from_utf8(bytes.to_vec()).expect("utf-8 body")
    }

    // --- what the classification says --------------------------------------

    #[tokio::test]
    async fn each_failure_class_gets_its_category() {
        let cases = every_failure_class().await;
        let got: Vec<(&str, UpstreamCategory)> = cases
            .iter()
            .map(|(name, e)| (*name, UpstreamFailure::classify(e).category))
            .collect();

        assert_eq!(
            got,
            vec![
                ("connect", UpstreamCategory::Connect),
                ("timeout", UpstreamCategory::Timeout),
                ("status", UpstreamCategory::Status),
                // Not `Body`: reqwest 0.12 maps a `Response::bytes()` failure
                // to its *decode* kind, so `is_body()` is false for the very
                // failure both consumers log `is_body` at. See the field docs.
                ("body", UpstreamCategory::Decode),
                ("builder", UpstreamCategory::Builder),
            ]
        );
    }

    #[tokio::test]
    async fn a_builder_error_nils_every_predicate_and_still_classifies() {
        // The reason `category` exists at all: with only the four booleans and
        // the status, this error logs as five falses and says nothing.
        let failure = UpstreamFailure::classify(&builder_error().await);

        assert!(!failure.is_connect);
        assert!(!failure.is_timeout);
        assert!(!failure.is_request);
        assert!(!failure.is_body);
        assert!(failure.status.is_none());
        assert_eq!(failure.category, UpstreamCategory::Builder);
        assert_eq!(failure.category.as_str(), "builder");
    }

    #[tokio::test]
    async fn only_a_status_error_carries_a_status() {
        for (name, err) in every_failure_class().await {
            let failure = UpstreamFailure::classify(&err);
            match name {
                "status" => assert_eq!(failure.status, Some(StatusCode::SERVICE_UNAVAILABLE)),
                _ => assert!(
                    failure.status.is_none(),
                    "{name} must not carry a status — only `error_for_status` produces one"
                ),
            }
        }
    }

    #[tokio::test]
    async fn a_connect_failure_reports_connect_even_though_request_is_also_true() {
        // Precedence, pinned: `is_request` is reqwest's umbrella kind and is
        // true here too, so a naive first-match on it would bucket every
        // send-side failure identically.
        let failure = UpstreamFailure::classify(&connect_error().await);

        assert!(failure.is_connect);
        assert!(failure.is_request);
        assert_eq!(failure.category, UpstreamCategory::Connect);
    }

    // --- the leak tests ----------------------------------------------------

    #[tokio::test]
    async fn the_log_helper_never_emits_url_material() {
        for (name, err) in every_failure_class().await {
            let failure = UpstreamFailure::classify(&err);
            let ((), logs) = capturing(|| failure.log("upstream request failed"));

            assert!(
                logs.contains("upstream request failed"),
                "{name}: the event must actually have been emitted: {logs}"
            );
            assert!(
                logs.contains(&format!("category=\"{}\"", failure.category)),
                "{name}: the category must be a structured field: {logs}"
            );
            assert_no_canary(&logs, &format!("{name}: the log helper"));
            // The classification itself derives `Debug`, and a future field
            // holding the error (or its URL) would leak through every
            // `?failure` a consumer writes. Pin that it holds nothing.
            assert_no_canary(
                &format!("{failure:?}"),
                &format!("{name}: the classification's Debug"),
            );
        }
    }

    #[tokio::test]
    async fn the_errors_display_really_does_carry_the_url() {
        // The control for every assertion above and below: if reqwest stopped
        // attaching the URL, the leak tests would be vacuous and nobody would
        // notice. One of the five classes carries no URL, which is a property
        // of where reqwest builds that error rather than a promise — hence the
        // split rather than one blanket assertion.
        for (name, err) in every_failure_class().await {
            let rendered = format!("{err} / {err:?}");
            let carries = CANARY_MARKERS.iter().any(|m| rendered.contains(m));
            match name {
                // `Response::bytes()` maps its failure through
                // `reqwest::error::decode`, which attaches no URL — unlike
                // `error_for_status`, which attaches the response's.
                "body" => assert!(
                    !carries,
                    "body-read errors are not expected to carry a URL: {rendered}"
                ),
                _ => assert!(
                    carries,
                    "{name}: reqwest no longer renders the URL — the leak tests are now vacuous \
                     and this module's premise needs re-checking: {rendered}"
                ),
            }
        }
    }

    #[tokio::test]
    async fn bad_gateway_upstream_never_renders_url_material() {
        for (name, err) in every_failure_class().await {
            let (app_err, logs) = capturing(|| AppError::bad_gateway_upstream(&err));
            let body = body_of(app_err).await;

            // Absence proves nothing on its own — a capture that silently
            // stopped working would pass every assertion below. Pin that the
            // constructor's event was actually recorded first.
            assert!(
                logs.contains(AppError::UPSTREAM_FAILED_MESSAGE) && logs.contains("category="),
                "{name}: the constructor's event must actually have been captured: {logs}"
            );
            assert_no_canary(&logs, &format!("{name}: the constructor's log"));
            assert_no_canary(&body, &format!("{name}: the constructor's response body"));
        }
    }

    #[tokio::test]
    async fn bad_gateway_upstream_renders_one_fixed_body_for_every_input() {
        // The redaction contract in its strongest form: the client cannot
        // tell which upstream, which URL, or even which failure class
        // produced the response.
        for (name, err) in every_failure_class().await {
            let (app_err, _logs) = capturing(|| AppError::bad_gateway_upstream(&err));

            assert_eq!(app_err.status(), StatusCode::BAD_GATEWAY, "{name}");
            assert_eq!(body_of(app_err).await, EXPECTED_BODY, "{name}");
        }
    }

    #[tokio::test]
    async fn the_context_form_only_changes_the_log_message() {
        let err = connect_error().await;

        let (plain, plain_logs) = capturing(|| AppError::bad_gateway_upstream(&err));
        let (labelled, labelled_logs) =
            capturing(|| AppError::bad_gateway_upstream_with_context(&err, "widget fetch failed"));

        assert_eq!(body_of(plain).await, body_of(labelled).await);
        assert!(plain_logs.contains(AppError::UPSTREAM_FAILED_MESSAGE));
        assert!(labelled_logs.contains("widget fetch failed"));
        assert!(labelled_logs.contains("category=\"connect\""));
        assert_no_canary(&labelled_logs, "the context form's log");
    }

    /// Characterization, not aspiration: `AppError::BadGateway(String)` still
    /// renders its payload to the client verbatim, exactly as its own docs
    /// promise. That contract is unchanged by this module — which is *why*
    /// `bad_gateway_upstream` exists: the naive line below is the shape an
    /// upstream-calling service ships without this constructor, and it hands
    /// the caller the upstream URL and its query string.
    ///
    /// It runs both paths side by side so the difference is the test: the same
    /// error, one line that leaks it and one that cannot. If someone ever makes
    /// `BadGateway` redact, this fails and the change gets the wire-contract
    /// review it deserves.
    #[tokio::test]
    async fn the_verbatim_bad_gateway_variant_still_leaks_and_the_constructor_does_not() {
        let err = connect_error().await;

        let naive = body_of(AppError::BadGateway(format!("upstream failed: {err}"))).await;
        assert!(
            CANARY_MARKERS.iter().any(|m| naive.contains(m)),
            "the documented verbatim rendering of BadGateway(String) has changed: {naive}"
        );

        let (safe, _logs) = capturing(|| AppError::bad_gateway_upstream(&err));
        assert_eq!(body_of(safe).await, EXPECTED_BODY);
    }
}
