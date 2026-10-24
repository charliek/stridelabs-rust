//! Nothing a search handles reaches an error's `Display` or `Debug`, or a
//! result's `Debug`: not the key, not the input, not a response body (an
//! echo of the request, an `error` message, an undocumented status string),
//! not the URL or its credentials, and nothing a peer puts inside a
//! transport failure (a malformed status line, a header no parser accepts,
//! an HTTP/2 GOAWAY's debug data). Each path plants canaries and asserts
//! that none of them is in any rendering: `Display`, `{:?}`, `{:#?}`, and
//! each `source()` down the chain ([`common::renderings`]; it is what
//! anyhow's `{:#}` prints). A transport failure is also held to exactly its
//! fixed phrases ([`assert_only_fixed_phrases`]).
//!
//! The controls make each absence mean something: the mock really received
//! the key and the input, the bodies really carried the secret, a reqwest
//! error really does render its URL, and reqwest's own error for the GOAWAY
//! really does render its debug data.

mod common;

use std::error::Error as _;
use std::time::Duration;

use common::{
    answering, entry, message, never_called, raw_json, renderings, response, search_results,
    RawServer,
};
use serde_json::json;
use stridelabs_perplexity::{
    BuildError, MalformedReason, PerplexityClient, PerplexityClientBuilder, PerplexityError, Phase,
    ResponseStatus, UnavailableReason,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY_CANARY: &str = "leakcanarykey3e9f1c27";
const INPUT_CANARY: &str = "leakcanaryinput8d2b";
const BODY_CANARY: &str = "leakcanarybody5a71";
/// A path segment of the base URL, so a reqwest error that kept its URL
/// would show it.
const URL_CANARY: &str = "leakcanaryurl40c3";
/// What a peer writes inside a transport failure.
const PEER_CANARY: &str = "leakcanarypeer7e2d";

const CANARIES: [(&str, &str); 5] = [
    ("the key", KEY_CANARY),
    ("the input", INPUT_CANARY),
    ("a response body", BODY_CANARY),
    ("the URL", URL_CANARY),
    ("what the peer sent", PEER_CANARY),
];

/// A builder for a client at `base` with the key canary.
fn canary_builder(base: impl Into<String>) -> PerplexityClientBuilder {
    PerplexityClient::builder(common::http(), KEY_CANARY).base_url(base)
}

fn assert_no_canary(what: &str, rendered: &str) {
    for (name, canary) in CANARIES {
        assert!(
            !rendered.contains(canary),
            "{name} reached {what}:\n{rendered}"
        );
    }
}

/// A transport failure renders as exactly its parts, by this test's own copy
/// of the phrase tables, and has no source: if the crate ever rendered
/// anything else (a peer's text, a reqwest error), this fails.
fn assert_only_fixed_phrases(error: &PerplexityError) {
    assert!(error.source().is_none(), "{error:?} has a source");
    let PerplexityError::Unavailable(reason) = error else {
        panic!("not a transport failure: {error:?}");
    };
    let phrase = |phase: &Phase| match phase {
        Phase::Connect => "while connecting",
        Phase::Headers => "before the response headers",
        Phase::Body => "while reading the response body",
        other => panic!("a phase this test does not know: {other:?}"),
    };
    let (display, debug) = match reason {
        UnavailableReason::Timeout(phase) => (
            format!("the exchange timed out {}", phrase(phase)),
            format!("Unavailable(Timeout({phase:?}))"),
        ),
        UnavailableReason::Transport { phase, io, .. } => (
            format!(
                "the exchange failed {}{}",
                phrase(phase),
                io.map(|kind| format!("; I/O error: {kind}"))
                    .unwrap_or_default()
            ),
            format!("Unavailable(Transport {{ phase: {phase:?}, io: {io:?} }})"),
        ),
        other => panic!("not a transport reason: {other:?}"),
    };
    assert_eq!(
        error.to_string(),
        format!("Perplexity is unavailable: {display}")
    );
    assert_eq!(format!("{error:?}"), debug);
}

/// Everything the mock answers with, each carrying every canary it could
/// echo.
fn answers() -> Vec<(&'static str, ResponseTemplate)> {
    let echo = format!("{KEY_CANARY} {INPUT_CANARY} {BODY_CANARY}");
    let json_echo = json!({"error": {"message": echo, "type": echo, "code": 400}});
    let with_status = |status: &str| {
        let mut body = response(status, json!([message(&echo)]));
        body["error"] = json!({"message": echo, "code": echo});
        body["incomplete_details"] = json!({"reason": echo});
        ResponseTemplate::new(200).set_body_json(body)
    };
    vec![
        (
            "a 500 echoing the request",
            ResponseTemplate::new(500).set_body_json(&json_echo),
        ),
        (
            "a 429 echoing the request",
            ResponseTemplate::new(429).set_body_json(&json_echo),
        ),
        (
            "a 400 echoing the request",
            ResponseTemplate::new(400).set_body_json(&json_echo),
        ),
        (
            "a 302 to a canary location",
            ResponseTemplate::new(302)
                .insert_header("location", format!("http://127.0.0.1:1/{BODY_CANARY}")),
        ),
        (
            "a 200 that is not JSON",
            raw_json(200, format!("not json {echo}")),
        ),
        (
            "a 200 with trailing garbage",
            raw_json(200, format!(r#"{{"status":"completed"}} {echo}"#)),
        ),
        (
            "a 200 with no status",
            ResponseTemplate::new(200).set_body_json(&json_echo),
        ),
        (
            "a failed response echoing the request",
            with_status("failed"),
        ),
        (
            "an incomplete response echoing the request",
            with_status("incomplete"),
        ),
        (
            "a response whose status is the echo",
            with_status(BODY_CANARY),
        ),
        (
            "a message whose own status is the echo",
            ResponseTemplate::new(200).set_body_json(response(
                "completed",
                json!([{"type": "message", "role": "assistant", "status": echo,
                        "content": [{"type": "output_text", "text": echo}]}]),
            )),
        ),
        (
            "a user message echoing the request",
            ResponseTemplate::new(200).set_body_json(response(
                "completed",
                json!([{"type": "message", "role": "user",
                        "content": [{"type": "output_text", "text": echo}]}]),
            )),
        ),
        (
            "a completed response with no text",
            ResponseTemplate::new(200).set_body_json(response(
                "completed",
                json!([search_results(json!([entry(
                    1,
                    &format!("https://x.example/{echo}")
                )]))]),
            )),
        ),
        (
            "a 200 too large to read",
            raw_json(
                200,
                format!(
                    r#"{{"status":"completed","pad":"{}","x":"{echo}"}}"#,
                    " ".repeat(3 * 1024 * 1024)
                ),
            ),
        ),
        (
            "a 200 that is too slow",
            ResponseTemplate::new(200)
                .set_body_json(&json_echo)
                .set_delay(Duration::from_secs(5)),
        ),
    ]
}

#[tokio::test]
async fn no_failure_renders_the_key_the_input_a_body_or_the_url() {
    let input = format!("Tell me about {INPUT_CANARY} in Duluth.");
    for (what, answer) in answers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(answer)
            .expect(1)
            .mount(&server)
            .await;
        let perplexity = canary_builder(format!("{}/{URL_CANARY}", server.uri()))
            .timeout(Duration::from_millis(300))
            .build()
            .expect("builds");
        let error = perplexity.search(&input).await.expect_err(what);
        assert_no_canary(
            &format!("the error for {what} ({error})"),
            &renderings(&error),
        );
        if what == "a user message echoing the request" {
            assert_eq!(
                error,
                PerplexityError::Malformed(MalformedReason::MissingAnswer)
            );
        }
        if what.ends_with("status is the echo") {
            assert!(
                matches!(
                    error,
                    PerplexityError::Incomplete {
                        status: ResponseStatus::Other,
                        ..
                    }
                ),
                "{error:?}"
            );
        }

        // The control: the canaries really went out.
        let seen = &server.received_requests().await.expect("recording is on")[0];
        let authorization = seen
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(
            authorization.contains(KEY_CANARY),
            "{what}: the key was not sent"
        );
        assert!(
            String::from_utf8_lossy(&seen.body).contains(INPUT_CANARY),
            "{what}: the input was not sent"
        );
        assert!(
            seen.url.path().contains(URL_CANARY),
            "{what}: the URL was not used"
        );
    }
}

/// The transport failures keep no reqwest error at all, so no URL can reach
/// them: a refused connection and a broken one, both under a canary path.
#[tokio::test]
async fn a_transport_failure_carries_no_url() {
    let input = format!("Tell me about {INPUT_CANARY}.");
    let refused = format!("{}/{URL_CANARY}", common::refused_base_url().await);
    let broken = RawServer::start(|mut exchange| async move {
        let _ = exchange
            .send(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n{\"status")
            .await;
    })
    .await;
    for base in [refused, format!("{}/{URL_CANARY}", broken.base_url)] {
        let error = canary_builder(&base)
            .build()
            .expect("builds")
            .search(&input)
            .await
            .expect_err("nothing answers");
        assert_only_fixed_phrases(&error);
        assert_no_canary(&format!("the error for {base}"), &renderings(&error));
    }
    assert_eq!(broken.finish().await, 1);
    // The control: the reqwest error of a client that keeps the URL shows it.
    let kept = common::http()
        .post(format!("{}/{URL_CANARY}", common::refused_base_url().await))
        .send()
        .await
        .expect_err("refused");
    assert!(
        format!("{kept} {kept:?}").contains(URL_CANARY),
        "the control is blind"
    );
}

/// The refusals that send nothing, and the builder's: input over the bound
/// holding the input canary; a key holding the key canary and a byte no
/// header can carry; base URLs carrying the URL canary as credentials, in a
/// query, in a fragment, or under a scheme or host the rules refuse. Neither
/// the errors nor the builder's `Debug` render them.
#[tokio::test]
async fn a_refusal_renders_neither_the_key_the_input_nor_the_url() {
    let server = never_called().await;
    let long = format!("{INPUT_CANARY} {}", "z".repeat(2_000));
    let error = canary_builder(server.uri())
        .build()
        .expect("builds")
        .search(&long)
        .await
        .expect_err("over the bound");
    assert_no_canary("the input bound's error", &renderings(&error));
    assert!(
        matches!(error, PerplexityError::InputTooLong { .. }),
        "{error:?}"
    );

    let builder = PerplexityClient::builder(common::http(), &format!("{KEY_CANARY}\u{1}"));
    assert_no_canary("the unusable key's builder", &format!("{builder:?}"));
    let error = builder.build().expect_err("the key is unusable");
    assert_no_canary("the unusable key's error", &renderings(&error));
    assert_eq!(error, BuildError::InvalidApiKey);

    for base in [
        format!("https://user:{URL_CANARY}@api.perplexity.ai"),
        format!("https://{URL_CANARY}@api.perplexity.ai"),
        format!("http://user:{URL_CANARY}@127.0.0.1:1"),
        format!("https://api.perplexity.ai/?key={URL_CANARY}"),
        format!("https://api.perplexity.ai/#{URL_CANARY}"),
        format!("http://{URL_CANARY}.example/"),
        format!("ftp://{URL_CANARY}.example/"),
        format!("{URL_CANARY} not a url"),
    ] {
        let builder = canary_builder(&base);
        assert_no_canary(
            &format!("the builder's Debug for {base}"),
            &format!("{builder:?} {builder:#?}"),
        );
        let error = builder.build().expect_err(&base);
        assert_no_canary(&format!("the error for {base}"), &renderings(&error));
        assert!(
            matches!(error, BuildError::InvalidBaseUrl(_)),
            "{base}: {error:?}"
        );
    }
}

/// A peer that answers an HTTP/1.1 exchange with something no parser accepts,
/// carrying a canary and an echo of the whole request (the key and the input
/// in it), then closes: a malformed status line, a non-HTTP first line, a
/// header value or name no parser accepts, a bad chunk size, and a valid head
/// whose reason phrase and header carry the canary before a cut-off body.
/// Each is a transport failure that renders only its fixed phrases.
#[tokio::test]
async fn a_peer_controlled_transport_failure_renders_no_secret() {
    type Answer = fn(&str) -> String;
    let answers: [(&str, Answer); 6] = [
        ("a malformed status line", |echo| {
            format!("HTTP/1.1 2X0 {PEER_CANARY} {echo}\r\n\r\n")
        }),
        ("a non-HTTP first line", |echo| {
            format!("{PEER_CANARY} {echo}\r\n\r\n")
        }),
        ("a header value no parser accepts", |echo| {
            format!("HTTP/1.1 200 OK\r\nx-echo: {PEER_CANARY} {echo}\u{1}\r\n\r\n")
        }),
        ("a header name no parser accepts", |echo| {
            format!("HTTP/1.1 200 OK\r\n{PEER_CANARY}(){echo}: v\r\n\r\n")
        }),
        ("a bad chunk size", |echo| {
            format!(
                "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n\
                 zz{PEER_CANARY} {echo}\r\n"
            )
        }),
        (
            "a cut-off body under a canary reason phrase and header",
            |echo| {
                format!(
                    "HTTP/1.1 200 {PEER_CANARY} {echo}\r\nx-echo: {PEER_CANARY}\r\n\
                 content-length: 500\r\n\r\n{{\"status\":\"{PEER_CANARY}"
                )
            },
        ),
    ];
    let input = format!("Tell me about {INPUT_CANARY}.");
    for (what, answer) in answers {
        let server = RawServer::start(move |mut exchange| async move {
            // The request, key and input included, on one line.
            let echo = String::from_utf8_lossy(&exchange.request).replace(['\r', '\n'], " ");
            // The control, awaited through `finish` below: the peer really
            // has the key and the input to echo.
            assert!(
                echo.contains(KEY_CANARY) && echo.contains(INPUT_CANARY),
                "the request did not carry the canaries"
            );
            let _ = exchange.send(answer(&echo).as_bytes()).await;
            // Dropping the stream closes it.
        })
        .await;
        let error = canary_builder(&server.base_url)
            .build()
            .expect("builds")
            .search(&input)
            .await
            .expect_err(what);
        assert_eq!(server.connections(), 1, "{what}");
        assert_eq!(server.finish().await, 1, "{what}");
        assert_only_fixed_phrases(&error);
        assert_no_canary(
            &format!("the error for {what} ({error})"),
            &renderings(&error),
        );
    }
}

/// One HTTP/2 frame on the connection (stream 0).
fn h2_frame(kind: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("a small frame");
    let mut frame = length.to_be_bytes()[1..].to_vec();
    frame.extend_from_slice(&[kind, flags, 0, 0, 0, 0]);
    frame.extend_from_slice(payload);
    frame
}

/// An h2c peer: it reads the client's preface, sends its own SETTINGS, acks
/// the client's, waits for the request's HEADERS, and answers with a GOAWAY
/// (last stream 0, `INTERNAL_ERROR`) whose debug data is `debug`. It then
/// keeps reading (so no unread frame turns its close into a reset) until the
/// test says it is done or the client hangs up.
async fn goaway(
    stream: &mut TcpStream,
    debug: &[u8],
    mut done: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let mut preface = [0u8; 24];
    stream.read_exact(&mut preface).await?;
    stream.write_all(&h2_frame(0x4, 0, &[])).await?;
    loop {
        let mut head = [0u8; 9];
        stream.read_exact(&mut head).await?;
        let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let mut payload = vec![0u8; length];
        stream.read_exact(&mut payload).await?;
        match (head[3], head[4] & 0x1) {
            (0x4, 0) => stream.write_all(&h2_frame(0x4, 0x1, &[])).await?,
            (0x1, _) => break,
            _ => {}
        }
    }
    let mut payload = 0u32.to_be_bytes().to_vec();
    payload.extend_from_slice(&2u32.to_be_bytes());
    payload.extend_from_slice(debug);
    stream.write_all(&h2_frame(0x7, 0, &payload)).await?;
    stream.flush().await?;
    // Held open until the test is done, so the client reads the GOAWAY
    // rather than a closed socket, however the two are scheduled.
    let mut sink = [0u8; 4096];
    loop {
        tokio::select! {
            _ = done.wait_for(|done| *done) => return Ok(()),
            read = stream.read(&mut sink) => {
                if read? == 0 {
                    return Ok(());
                }
            }
        }
    }
}

/// The error chain: an HTTP/2 GOAWAY whose debug data carries a canary, the
/// key and the input, which h2 renders in both its `Display` and its
/// `Debug`. The control shows reqwest's own error for it does render the
/// canary, through `without_url()` too; the crate's error renders only its
/// fixed phrases.
#[tokio::test]
async fn an_http2_goaway_debug_payload_never_reaches_the_error() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let base = format!("http://{}", listener.local_addr().expect("its address"));
    let (finished, done) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let debug = format!("{PEER_CANARY} {KEY_CANARY} {INPUT_CANARY}");
        while let Ok((mut stream, _)) = listener.accept().await {
            let (debug, done) = (debug.clone(), done.clone());
            tokio::spawn(async move {
                let _ = goaway(&mut stream, debug.as_bytes(), done).await;
            });
        }
    });
    let bound = Duration::from_secs(10);
    let h2c = common::http_builder()
        .http2_prior_knowledge()
        .build()
        .expect("an h2c client builds");

    let raw = tokio::time::timeout(
        bound,
        h2c.post(format!("{base}/v1/agent")).body("{}").send(),
    )
    .await
    .expect("the control answers within its bound")
    .expect_err("the GOAWAY refuses the stream")
    .without_url();
    assert!(
        renderings(&raw).contains(PEER_CANARY),
        "the control is blind: {}",
        renderings(&raw)
    );

    let input = format!("Tell me about {INPUT_CANARY}.");
    let perplexity = PerplexityClient::builder(h2c, KEY_CANARY)
        .base_url(&base)
        .build()
        .expect("builds");
    let error = tokio::time::timeout(bound, perplexity.search(&input))
        .await
        .expect("the search answers within its bound")
        .expect_err("the GOAWAY refuses the stream");
    finished.send_replace(true);
    assert_only_fixed_phrases(&error);
    assert_no_canary("the GOAWAY's error", &renderings(&error));
}

/// The values a caller might log: the builder, the client, and a successful
/// answer, its results, its display rows and its usage show none of the
/// canaries. The body carried the body canary in the text, every result
/// field, the usage's currency and a field the crate ignores.
#[tokio::test]
async fn no_debug_renders_the_key_the_input_or_the_answer() {
    let mut found = entry(5, &format!("https://example.com/{BODY_CANARY}"));
    for field in ["title", "snippet", "date", "last_updated", "source"] {
        found[field] = json!(format!("{field} {BODY_CANARY}"));
    }
    let mut body = response(
        "completed",
        json!([
            search_results(json!([found])),
            message(&format!("{BODY_CANARY} [5]"))
        ]),
    );
    body["usage"]["cost"]["currency"] = json!(BODY_CANARY);
    body["debug"] = json!(BODY_CANARY);
    let server = answering(ResponseTemplate::new(200).set_body_json(body)).await;
    let input = format!("Tell me about {INPUT_CANARY}.");
    let builder = canary_builder(server.uri());
    assert_no_canary("the builder's Debug", &format!("{builder:?} {builder:#?}"));
    let perplexity = builder.build().expect("builds");
    assert_no_canary(
        "the client's Debug",
        &format!("{perplexity:?} {perplexity:#?}"),
    );

    let answer = perplexity.search(&input).await.expect("an answer");
    let sources = answer.sources(6, 200);
    // The controls: the answer, its result, its row and its usage really
    // carry the canary.
    assert!(answer.text.contains(BODY_CANARY));
    let result = &answer.results[0];
    assert!(result.url.contains(BODY_CANARY));
    assert!(result
        .title
        .as_deref()
        .is_some_and(|title| title.contains(BODY_CANARY)));
    assert!(sources[0].url.contains(BODY_CANARY) && sources[0].title.contains(BODY_CANARY));
    let usage = answer.usage.as_ref().expect("usage");
    assert_eq!(usage.currency.as_deref(), Some(BODY_CANARY));

    assert_no_canary("the answer's Debug", &format!("{answer:?} {answer:#?}"));
    assert_no_canary("a result's Debug", &format!("{result:?} {result:#?}"));
    assert_no_canary("the rows' Debug", &format!("{sources:?} {sources:#?}"));
    assert_no_canary("the usage's Debug", &format!("{usage:?} {usage:#?}"));
}
