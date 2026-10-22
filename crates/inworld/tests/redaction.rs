//! Nothing a synthesis handles reaches an error's `Display` or `Debug`, or a
//! result's `Debug`: not the key, not the text, not a response body, not the
//! URL inside a reqwest error, and nothing a peer puts inside a transport
//! failure (a malformed status line, a header no parser accepts, an HTTP/2
//! GOAWAY's debug data). Each path plants canaries and asserts that none of
//! them is in any rendering: `Display`, `{:?}`, `{:#?}`, and each `source()`
//! down the chain ([`common::renderings`]; it is what anyhow's `{:#}` prints).
//! A transport failure is also held to exactly its fixed phrases
//! ([`assert_only_fixed_phrases`]).
//!
//! The controls make each absence mean something: the mock really received
//! the key and the text, the bodies really carried the secret, and reqwest's
//! own error for the GOAWAY really does render its debug data.

mod common;

use std::error::Error as _;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use common::{mp3, renderings, RawServer, MODEL};
use serde_json::json;
use stridelabs_inworld::{
    AudioConfig, InworldClient, InworldError, SynthesisRequest, TransportStage, UnavailableReason,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY_CANARY: &str = "leakcanarykey3e9f1c27";
const TEXT_CANARY: &str = "leakcanarytext8d2b";
const BODY_CANARY: &str = "leakcanarybody5a71";
/// A path segment of the base URL, so a reqwest error that kept its URL
/// would show it.
const URL_CANARY: &str = "leakcanaryurl40c3";
/// What a peer writes inside a transport failure.
const PEER_CANARY: &str = "leakcanarypeer7e2d";

const CANARIES: [(&str, &str); 5] = [
    ("the key", KEY_CANARY),
    ("the text", TEXT_CANARY),
    ("a response body", BODY_CANARY),
    ("the URL", URL_CANARY),
    ("what the peer sent", PEER_CANARY),
];

/// A transport failure renders as exactly its parts, by this test's own copy
/// of the phrase tables, and has no source: if the crate ever rendered
/// anything else (a peer's text, a reqwest error), this fails.
fn assert_only_fixed_phrases(error: &InworldError) {
    assert!(error.source().is_none(), "{error:?} has a source");
    let InworldError::Unavailable {
        reason,
        cause: Some(cause),
    } = error
    else {
        panic!("not a transport failure: {error:?}");
    };
    let reason_phrase = match reason {
        UnavailableReason::TimedOut => "the exchange timed out",
        UnavailableReason::Connect => "the connection could not be made",
        UnavailableReason::Transport => "the exchange failed or the connection broke",
        other => panic!("not a transport reason: {other:?}"),
    };
    let stage_phrase = match cause.stage {
        TransportStage::Connect => "while connecting",
        TransportStage::Request => "while sending the request or awaiting the response",
        TransportStage::Body => "while reading the response body",
        TransportStage::Decode => "while decoding the response body",
        TransportStage::Other => "at an unclassified stage",
        other => panic!("a stage this test does not know: {other:?}"),
    };
    let ended = if cause.timed_out {
        "timed out"
    } else {
        "failed"
    };
    let io = cause
        .io
        .map(|kind| format!("; I/O error: {kind}"))
        .unwrap_or_default();
    assert_eq!(
        error.to_string(),
        format!("Inworld is unavailable: {reason_phrase} ({ended} {stage_phrase}{io})")
    );
    assert_eq!(
        format!("{error:?}"),
        format!(
            "Unavailable {{ reason: {reason:?}, cause: Some(TransportCause {{ stage: {:?}, \
             timed_out: {}, io: {:?} }}) }}",
            cause.stage, cause.timed_out, cause.io
        )
    );
}

fn assert_no_canary(what: &str, rendered: &str) {
    for (name, canary) in CANARIES {
        assert!(
            !rendered.contains(canary),
            "{name} reached {what}:\n{rendered}"
        );
    }
}

/// Everything the mock answers with, each carrying every canary it could
/// echo.
fn answers() -> Vec<(&'static str, ResponseTemplate)> {
    let echo = format!("{KEY_CANARY} {TEXT_CANARY} {BODY_CANARY}");
    let json_echo = json!({"code": 3, "message": echo, "details": [echo]});
    let raw = |status: u16, body: String| {
        ResponseTemplate::new(status).set_body_raw(body, "application/json")
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
            raw(200, format!("not json {echo}")),
        ),
        (
            "a 200 with no audioContent",
            ResponseTemplate::new(200).set_body_json(&json_echo),
        ),
        (
            "a 200 whose audioContent is not base64",
            ResponseTemplate::new(200).set_body_json(json!({"audioContent": echo})),
        ),
        (
            "a 200 whose audio is not MP3",
            ResponseTemplate::new(200)
                .set_body_json(json!({"audioContent": STANDARD.encode(echo.as_bytes())})),
        ),
        (
            "a 200 whose audioContent is a number",
            raw(
                200,
                format!(r#"{{"audioContent":12345678,"{BODY_CANARY}":1}}"#),
            ),
        ),
        (
            "a 200 with trailing garbage",
            raw(200, format!(r#"{{"audioContent":"//OQ"}} {echo}"#)),
        ),
        (
            "a 200 too large to read",
            raw(
                200,
                format!(
                    r#"{{"audioContent":"//OQ","pad":"{}","x":"{echo}"}}"#,
                    " ".repeat(5 * 1024 * 1024)
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

fn canary_request(text: &str) -> SynthesisRequest<'_> {
    SynthesisRequest::new(
        text,
        "Ashley",
        MODEL,
        AudioConfig::new("MP3").with_bit_rate(64_000),
    )
}

#[tokio::test]
async fn no_failure_renders_the_key_the_text_a_body_or_the_url() {
    let text = format!("Tell me about {TEXT_CANARY} in Duluth.");
    for (what, answer) in answers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(answer)
            .expect(1)
            .mount(&server)
            .await;
        let inworld = InworldClient::builder(common::http(), KEY_CANARY)
            .base_url(format!("{}/{URL_CANARY}", server.uri()))
            .timeout(Duration::from_millis(300))
            .build()
            .expect("builds");
        let error = inworld
            .synthesize(&canary_request(&text))
            .await
            .expect_err(what);
        assert_no_canary(
            &format!("the error for {what} ({error})"),
            &renderings(&error),
        );

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
            String::from_utf8_lossy(&seen.body).contains(TEXT_CANARY),
            "{what}: the text was not sent"
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
    let text = format!("Tell me about {TEXT_CANARY}.");
    let refused = format!("{}/{URL_CANARY}", common::refused_base_url().await);
    let broken = common::RawServer::start(|mut exchange| async move {
        let _ = exchange
            .send(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n{\"audio")
            .await;
    })
    .await;
    for base in [refused, format!("{}/{URL_CANARY}", broken.base_url)] {
        let error = InworldClient::builder(common::http(), KEY_CANARY)
            .base_url(&base)
            .build()
            .expect("builds")
            .synthesize(&canary_request(&text))
            .await
            .expect_err("nothing answers");
        assert_only_fixed_phrases(&error);
        assert_no_canary(&format!("the error for {base}"), &renderings(&error));
    }
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

/// The refusals that send nothing: an unusable key holding the key canary, and
/// text over the bound holding the text canary.
#[tokio::test]
async fn a_refusal_renders_neither_the_key_nor_the_text() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let unusable = InworldClient::builder(common::http(), &format!("{KEY_CANARY}\u{1}"))
        .base_url(server.uri())
        .build()
        .expect("builds");
    let error = unusable
        .synthesize(&canary_request("hi"))
        .await
        .expect_err("the key is unusable");
    assert!(matches!(error, InworldError::UnusableKey), "{error:?}");
    assert_no_canary("the unusable key's error", &renderings(&error));

    let long = format!("{TEXT_CANARY} {}", "z".repeat(600));
    let error = InworldClient::builder(common::http(), KEY_CANARY)
        .base_url(server.uri())
        .build()
        .expect("builds")
        .synthesize(&canary_request(&long))
        .await
        .expect_err("over the bound");
    assert!(
        matches!(error, InworldError::TextTooLong { .. }),
        "{error:?}"
    );
    assert_no_canary("the text bound's error", &renderings(&error));
}

/// A peer that answers an HTTP/1.1 exchange with something no parser accepts,
/// carrying a canary and an echo of the whole request (the key and the text
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
                 content-length: 500\r\n\r\n{{\"audioContent\":\"{PEER_CANARY}"
                )
            },
        ),
    ];
    let text = format!("Tell me about {TEXT_CANARY}.");
    for (what, answer) in answers {
        let server = RawServer::start(move |mut exchange| async move {
            // The request, key and text included, on one line.
            let echo = String::from_utf8_lossy(&exchange.request).replace(['\r', '\n'], " ");
            assert!(echo.contains(KEY_CANARY) && echo.contains(TEXT_CANARY));
            let _ = exchange.send(answer(&echo).as_bytes()).await;
            // Dropping the stream closes it.
        })
        .await;
        let error = InworldClient::builder(common::http(), KEY_CANARY)
            .base_url(&server.base_url)
            .build()
            .expect("builds")
            .synthesize(&canary_request(&text))
            .await
            .expect_err(what);
        assert_eq!(server.connections(), 1, "{what}");
        assert_only_fixed_phrases(&error);
        assert_no_canary(
            &format!("the error for {what} ({error})"),
            &renderings(&error),
        );
    }
}

/// One HTTP/2 frame.
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

/// The reviewer's vector: an HTTP/2 GOAWAY whose debug data carries a canary,
/// the key and the text, which h2 renders in both its `Display` and its
/// `Debug`. The control shows reqwest's own error for it does render the
/// canary; the crate's error renders only its fixed phrases.
#[tokio::test]
async fn an_http2_goaway_debug_payload_never_reaches_the_error() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let base = format!("http://{}", listener.local_addr().expect("its address"));
    let (finished, done) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let debug = format!("{PEER_CANARY} {KEY_CANARY} {TEXT_CANARY}");
        while let Ok((mut stream, _)) = listener.accept().await {
            let (debug, done) = (debug.clone(), done.clone());
            tokio::spawn(async move {
                let _ = goaway(&mut stream, debug.as_bytes(), done).await;
            });
        }
    });
    let bound = Duration::from_secs(10);
    let h2c = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .http2_prior_knowledge()
        .build()
        .expect("an h2c client builds");

    // The control: reqwest's error carries the debug data, through
    // `without_url()` too.
    let raw = tokio::time::timeout(
        bound,
        h2c.post(format!("{base}/tts/v1/voice")).body("{}").send(),
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

    let text = format!("Tell me about {TEXT_CANARY}.");
    let client = InworldClient::builder(h2c, KEY_CANARY)
        .base_url(&base)
        .build()
        .expect("builds");
    let error = tokio::time::timeout(bound, client.synthesize(&canary_request(&text)))
        .await
        .expect("the synthesis answers within its bound")
        .expect_err("the GOAWAY refuses the stream");
    finished.send_replace(true);
    assert_only_fixed_phrases(&error);
    assert_no_canary("the GOAWAY's error", &renderings(&error));
}

/// The values a caller might log: the client, its builder, the request and
/// a successful synthesis show none of the canaries. Its body carried the
/// body canary in a field the crate ignores, in the audio, and in
/// `usage.modelId`, which is returned as given but shown in `Debug` only as
/// its length.
#[tokio::test]
async fn no_debug_renders_the_key_the_text_the_audio_or_the_model_id() {
    let server = MockServer::start().await;
    let audio = {
        let mut audio = mp3(64);
        audio.extend_from_slice(BODY_CANARY.as_bytes());
        audio
    };
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "audioContent": STANDARD.encode(&audio),
            "usage": {"processedCharactersCount": 30, "modelId": format!("{MODEL}-{BODY_CANARY}")},
            "debug": BODY_CANARY,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let text = format!("Tell me about {TEXT_CANARY}.");
    let request = canary_request(&text);
    let builder = InworldClient::builder(common::http(), KEY_CANARY).base_url(server.uri());
    assert_no_canary("the builder's Debug", &format!("{builder:?} {builder:#?}"));
    let inworld = builder.build().expect("builds");
    assert_no_canary("the client's Debug", &format!("{inworld:?} {inworld:#?}"));
    assert_no_canary("the request's Debug", &format!("{request:?} {request:#?}"));

    let synthesis = inworld.synthesize(&request).await.expect("a synthesis");
    // The controls: the audio and the model id really carry the canary, and
    // the model id is returned as given.
    assert!(synthesis
        .audio
        .windows(BODY_CANARY.len())
        .any(|window| window == BODY_CANARY.as_bytes()));
    assert_eq!(
        synthesis.usage.model_id.as_deref(),
        Some(format!("{MODEL}-{BODY_CANARY}").as_str())
    );
    let usage = &synthesis.usage;
    assert_no_canary("the usage's Debug", &format!("{usage:?} {usage:#?}"));
    assert_no_canary(
        "the synthesis's Debug",
        &format!("{synthesis:?} {synthesis:#?}"),
    );
}
