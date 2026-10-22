//! The wire and the classification, against wiremock: the exact request
//! (method, path, headers, a body with every unset option omitted), each
//! status class, redirects never followed, the key, the client-side refusals
//! that send nothing, the MP3 check both ways, and `usage` absent and
//! present.

mod common;

use std::time::Duration;

use common::{audio_body, builder, client, mp3, request, KEY, MODEL};
use serde_json::{json, Value};
use stridelabs_inworld::{
    AudioConfig, InworldClient, InworldError, MalformedReason, Synthesis, SynthesisRequest,
    UnavailableReason, Usage,
};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

type Outcome = Result<Synthesis, InworldError>;

fn ok_with(body: impl Into<String>) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body.into(), "application/json")
}

/// A server that answers every synthesis with `template`.
async fn answering(template: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tts/v1/voice"))
        .respond_with(template)
        .mount(&server)
        .await;
    server
}

/// A server that must see no request at all (checked when dropped).
async fn never_called() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .named("nothing may be sent")
        .mount(&server)
        .await;
    server
}

fn malformed(outcome: &Outcome) -> Option<MalformedReason> {
    match outcome {
        Err(InworldError::Malformed(reason)) => Some(*reason),
        _ => None,
    }
}

fn unavailable(outcome: &Outcome) -> Option<UnavailableReason> {
    match outcome {
        Err(InworldError::Unavailable { reason, .. }) => Some(*reason),
        _ => None,
    }
}

fn rejected(outcome: &Outcome) -> Option<u16> {
    match outcome {
        Err(InworldError::Rejected(status)) => Some(*status),
        _ => None,
    }
}

/// The one request on `server`.
async fn the_request(server: &MockServer) -> wiremock::Request {
    let mut requests = server.received_requests().await.expect("recording is on");
    assert_eq!(requests.len(), 1, "exactly one request");
    requests.remove(0)
}

/// The request with nothing optional set: `POST /tts/v1/voice`, the key as
/// `Basic`, a JSON content type, and a body with every unset option omitted
/// (no `language`, no `deliveryMode`, nothing in `audioConfig` but the
/// encoding), byte for byte.
#[tokio::test]
async fn every_none_is_omitted_from_the_body() {
    let server = answering(ok_with(audio_body(&mp3(64)))).await;
    let synthesis = client(&server.uri())
        .synthesize(&request("Hello there."))
        .await
        .expect("a synthesis");
    assert_eq!(synthesis.audio.as_ref(), mp3(64).as_slice());

    let seen = the_request(&server).await;
    assert_eq!(seen.method.as_str(), "POST");
    assert_eq!(seen.url.path(), "/tts/v1/voice");
    assert_eq!(seen.url.query(), None);
    let header_of = |name: &str| {
        seen.headers
            .get(name)
            .map(|value| value.to_str().expect("ASCII").to_string())
    };
    assert_eq!(header_of("authorization"), Some(format!("Basic {KEY}")));
    assert_eq!(
        header_of("content-type").as_deref(),
        Some("application/json")
    );
    assert_eq!(
        String::from_utf8(seen.body).expect("UTF-8"),
        r#"{"text":"Hello there.","voiceId":"Ashley","modelId":"inworld-tts-2-flash","audioConfig":{"audioEncoding":"MP3"}}"#
    );
}

/// Every option set: each sent, in the pinned order, as given.
#[tokio::test]
async fn every_set_option_is_sent() {
    let server = answering(ok_with(audio_body(&mp3(64)))).await;
    let request = SynthesisRequest::new(
        "Hello there.",
        "Ashley",
        MODEL,
        AudioConfig::new("MP3")
            .with_bit_rate(64_000)
            .with_speaking_rate(1.25)
            .with_sample_rate_hertz(24_000),
    )
    .with_language("en-US")
    .with_delivery_mode("BALANCED");
    client(&server.uri())
        .synthesize(&request)
        .await
        .expect("a synthesis");
    let seen = the_request(&server).await;
    assert_eq!(
        String::from_utf8(seen.body).expect("UTF-8"),
        r#"{"text":"Hello there.","voiceId":"Ashley","modelId":"inworld-tts-2-flash","language":"en-US","deliveryMode":"BALANCED","audioConfig":{"audioEncoding":"MP3","bitRate":64000,"speakingRate":1.25,"sampleRateHertz":24000}}"#
    );
}

/// A path prefix on the base URL is kept, and a trailing slash tolerated.
#[tokio::test]
async fn a_base_url_path_prefix_is_kept() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/inworld/tts/v1/voice"))
        .respond_with(ok_with(audio_body(&mp3(16))))
        .expect(1)
        .mount(&server)
        .await;
    let inworld = client(&format!("{}/inworld/", server.uri()));
    assert_eq!(
        inworld.endpoint().as_str(),
        format!("{}/inworld/tts/v1/voice", server.uri())
    );
    inworld
        .synthesize(&request("hi"))
        .await
        .expect("a synthesis");
}

/// The key is used verbatim after trimming: surrounding whitespace never
/// reaches the header.
#[tokio::test]
async fn the_key_is_trimmed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("authorization", "Basic aWQ6c2VjcmV0"))
        .respond_with(ok_with(audio_body(&mp3(16))))
        .expect(1)
        .mount(&server)
        .await;
    InworldClient::builder(common::http(), " \t aWQ6c2VjcmV0 \r\n")
        .base_url(server.uri())
        .build()
        .expect("builds")
        .synthesize(&request("hi"))
        .await
        .expect("the trimmed key is the one sent");
}

/// A key no header can carry, or one that is empty after trimming, is
/// `UnusableKey` with nothing sent.
#[tokio::test]
async fn an_unusable_key_sends_nothing() {
    let server = never_called().await;
    for key in ["bad\u{1}key", "bad\nkey", "", "   "] {
        let inworld = InworldClient::builder(common::http(), key)
            .base_url(server.uri())
            .build()
            .expect("an unusable key is not a build error");
        let outcome = inworld.synthesize(&request("hi")).await;
        assert!(
            matches!(outcome, Err(InworldError::UnusableKey)),
            "{key:?}: {outcome:?}"
        );
    }
}

/// Text over the bound is refused before anything is sent, counted in
/// characters, not bytes: five four-byte characters are within five. The
/// control: text at the bound is sent.
#[tokio::test]
async fn text_over_the_bound_sends_nothing() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tts/v1/voice"))
        .respond_with(ok_with(audio_body(&mp3(16))))
        .expect(2)
        .mount(&server)
        .await;
    let inworld = builder(&server.uri())
        .max_text_chars(5)
        .build()
        .expect("builds");
    let outcome = inworld.synthesize(&request("123456")).await;
    assert!(
        matches!(outcome, Err(InworldError::TextTooLong { chars: 6, max: 5 })),
        "{outcome:?}"
    );
    inworld
        .synthesize(&request("12345"))
        .await
        .expect("five characters are within five");
    inworld
        .synthesize(&request("😀😀😀😀😀"))
        .await
        .expect("five characters of four bytes each are within five");

    // The default bound is 600.
    let inworld = client(&server.uri());
    let outcome = inworld.synthesize(&request(&"a".repeat(601))).await;
    assert!(
        matches!(
            outcome,
            Err(InworldError::TextTooLong {
                chars: 601,
                max: 600
            })
        ),
        "{outcome:?}"
    );
}

/// A NaN or infinite speaking rate cannot be JSON (serde_json would send
/// `null`): refused, with nothing sent.
#[tokio::test]
async fn a_non_finite_speaking_rate_sends_nothing() {
    let server = never_called().await;
    let inworld = client(&server.uri());
    for rate in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let request = SynthesisRequest::new(
            "hi",
            "Ashley",
            MODEL,
            AudioConfig::new("MP3").with_speaking_rate(rate),
        );
        let outcome = inworld.synthesize(&request).await;
        assert!(
            matches!(outcome, Err(InworldError::SpeakingRateNotFinite)),
            "{rate}: {outcome:?}"
        );
    }
}

/// `408`, `429` and every `5xx` are `Unavailable` (retryable); every other
/// non-2xx, `400` among them, is `Rejected` (not retryable). No error body
/// is read.
#[tokio::test]
async fn statuses_are_classified() {
    for status in [408, 429, 500, 502, 503, 504, 599] {
        let server = answering(
            ResponseTemplate::new(status).set_body_json(json!({"code": 8, "message": "busy"})),
        )
        .await;
        let outcome = client(&server.uri()).synthesize(&request("hi")).await;
        assert_eq!(
            unavailable(&outcome),
            Some(UnavailableReason::Status(status)),
            "{status}: {outcome:?}"
        );
        assert!(outcome.is_err_and(|error| error.is_retryable()), "{status}");
    }
    for status in [400, 401, 403, 404, 409, 413, 422, 451] {
        let server = answering(
            ResponseTemplate::new(status).set_body_json(json!({"code": 3, "message": "no"})),
        )
        .await;
        let outcome = client(&server.uri()).synthesize(&request("hi")).await;
        assert_eq!(rejected(&outcome), Some(status), "{status}: {outcome:?}");
        assert!(
            outcome.is_err_and(|error| !error.is_retryable()),
            "{status}"
        );
    }
}

/// A `3xx` is `Rejected` and never followed: the server it points at sees no
/// request, so `Authorization` never reaches it. (A `307`/`308` would replay
/// the POST and its body; a `302`/`303` would turn it into a GET.)
async fn assert_redirects_are_rejected(http: reqwest::Client) {
    let elsewhere = never_called().await;
    for status in [301, 302, 303, 307, 308] {
        let server = answering(
            ResponseTemplate::new(status)
                .insert_header("location", format!("{}/tts/v1/voice", elsewhere.uri())),
        )
        .await;
        let outcome = InworldClient::builder(http.clone(), KEY)
            .base_url(server.uri())
            .build()
            .expect("builds")
            .synthesize(&request("hi"))
            .await;
        assert_eq!(rejected(&outcome), Some(status), "{status}: {outcome:?}");
        assert_eq!(the_request(&server).await.url.path(), "/tts/v1/voice");
    }
}

#[tokio::test]
async fn a_redirect_is_rejected_and_not_followed() {
    assert_redirects_are_rejected(common::http()).await;
}

/// `client_builder()` follows no redirects either.
#[cfg(feature = "client-builder")]
#[tokio::test]
async fn client_builders_client_does_not_follow_a_redirect() {
    assert_redirects_are_rejected(
        stridelabs_inworld::client_builder()
            .build()
            .expect("client_builder() builds"),
    )
    .await;
}

/// The MP3 check, on by default: an ID3 tag or a frame sync passes; a WAV
/// header does not, unless the check is off.
#[tokio::test]
async fn the_mp3_check_passes_and_fails() {
    let mut id3 = b"ID3\x04\x00\x00\x00\x00\x00\x00".to_vec();
    id3.extend(mp3(32));
    let wav = b"RIFF\x24\x00\x00\x00WAVEfmt ".to_vec();
    for (audio, mp3_shaped) in [(id3, true), (mp3(32), true), (wav, false)] {
        let server = answering(ok_with(audio_body(&audio))).await;
        let outcome = client(&server.uri()).synthesize(&request("hi")).await;
        if mp3_shaped {
            assert_eq!(
                outcome.expect("MP3-shaped").audio.as_ref(),
                audio.as_slice()
            );
        } else {
            assert_eq!(
                malformed(&outcome),
                Some(MalformedReason::NotMp3),
                "{outcome:?}"
            );
            let unchecked = builder(&server.uri())
                .mp3_check(false)
                .build()
                .expect("builds")
                .synthesize(&request("hi"))
                .await
                .expect("with the check off, any audio is audio");
            assert_eq!(unchecked.audio.as_ref(), audio.as_slice());
        }
    }
}

/// `usage` absent: both fields `None`. Present: both read. Ill-typed: `None`,
/// and the audio still returned.
#[tokio::test]
async fn usage_is_absent_or_present() {
    let audio = mp3(64);
    let with_usage = |usage: Value| {
        let mut body: Value = serde_json::from_str(&audio_body(&audio)).expect("JSON");
        body["usage"] = usage;
        body.to_string()
    };
    for (body, expected) in [
        (audio_body(&audio), Usage::default()),
        (
            with_usage(json!({"processedCharactersCount": 12, "modelId": "inworld-tts-2-flash"})),
            {
                let mut usage = Usage::default();
                usage.processed_characters_count = Some(12);
                usage.model_id = Some("inworld-tts-2-flash".to_string());
                usage
            },
        ),
        (
            with_usage(json!({"processedCharactersCount": "12", "modelId": 7})),
            Usage::default(),
        ),
    ] {
        let server = answering(ok_with(body)).await;
        let synthesis = client(&server.uri())
            .synthesize(&request("hi"))
            .await
            .expect("a synthesis");
        assert_eq!(synthesis.usage, expected);
        assert_eq!(synthesis.audio.as_ref(), audio.as_slice());
    }
}

/// Any `2xx` is an answer to read: a `201` with audio is audio; a `204` has
/// no body, so no JSON.
#[tokio::test]
async fn any_2xx_is_read() {
    let server = answering(
        ResponseTemplate::new(201).set_body_raw(audio_body(&mp3(16)), "application/json"),
    )
    .await;
    client(&server.uri())
        .synthesize(&request("hi"))
        .await
        .expect("a 201 with audio");
    let server = answering(ResponseTemplate::new(204)).await;
    let outcome = client(&server.uri()).synthesize(&request("hi")).await;
    assert_eq!(
        malformed(&outcome),
        Some(MalformedReason::NotJsonObject),
        "{outcome:?}"
    );
}

/// A `2xx` that is not usable audio, through the wire (the full table of
/// bodies is the response module's unit tests).
#[tokio::test]
async fn a_malformed_2xx_is_malformed() {
    for (body, expected) in [
        ("<html>busy</html>", MalformedReason::NotJsonObject),
        (
            r#"{"code":3,"message":"no"}"#,
            MalformedReason::NoAudioContent,
        ),
        (
            r#"{"audioContent":"not base64!"}"#,
            MalformedReason::NotBase64,
        ),
        (r#"{"audioContent":""}"#, MalformedReason::EmptyAudio),
    ] {
        let server = answering(ok_with(body)).await;
        let outcome = client(&server.uri()).synthesize(&request("hi")).await;
        assert_eq!(malformed(&outcome), Some(expected), "{body}: {outcome:?}");
        assert!(outcome.is_err_and(|error| !error.is_retryable()), "{body}");
    }
}

/// A server that does not answer within the bound is `TimedOut`; a port
/// nothing listens on is `Connect`. Both retryable.
#[tokio::test]
async fn a_timeout_and_a_refused_connection_are_unavailable() {
    let server = answering(ok_with(audio_body(&mp3(16))).set_delay(Duration::from_secs(10))).await;
    let outcome = builder(&server.uri())
        .timeout(Duration::from_millis(300))
        .build()
        .expect("builds")
        .synthesize(&request("hi"))
        .await;
    assert_eq!(
        unavailable(&outcome),
        Some(UnavailableReason::TimedOut),
        "{outcome:?}"
    );

    let outcome = client(&common::refused_base_url().await)
        .synthesize(&request("hi"))
        .await;
    assert_eq!(
        unavailable(&outcome),
        Some(UnavailableReason::Connect),
        "{outcome:?}"
    );
    assert!(outcome.is_err_and(|error| error.is_retryable()));
}

/// The text is sent as given, quotes, newlines and non-ASCII characters
/// and all (compared as JSON values: key order is pinned above).
#[tokio::test]
async fn the_text_is_sent_as_given() {
    let server = MockServer::start().await;
    let text = "Ça va? \"Oui\" — 😀\n";
    Mock::given(method("POST"))
        .and(body_json(json!({
            "text": text,
            "voiceId": "Ashley",
            "modelId": MODEL,
            "audioConfig": {"audioEncoding": "MP3"},
        })))
        .respond_with(ok_with(audio_body(&mp3(16))))
        .expect(1)
        .mount(&server)
        .await;
    client(&server.uri())
        .synthesize(&request(text))
        .await
        .expect("a synthesis");
}
