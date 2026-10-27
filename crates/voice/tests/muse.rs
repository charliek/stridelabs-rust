//! The Muse adapter (features `muse`, `axum`, `test-support`): `MuseStt`
//! and `MuseSession` driven directly, through the `stt` traits, against
//! `muse::mock::MockMuse` on a loopback port. No Redis: one relay session
//! through the mock is `tests/muse_relay.rs`'s.
//!
//! Ported from tapper's `tests/voice_stream.rs` (`82be95f`, its mock Muse's
//! cases) and lumen's (`5b716ba`), at the adapter's own seam:
//!
//! - **the handshake** — the key, the rate's encoding and the keywords
//!   (configured ones in order; none omits the field) in the first frame,
//!   on the realtime path;
//! - **the open** — the ack opens; an error event (even with a
//!   `sessionId`), a close or a dropped connection instead is `Refused`; an
//!   unreachable Muse is `Dial` with its I/O class; the adapter applies no
//!   deadline of its own; an unconfigured provider dials nothing;
//! - **the session** — audio byte for byte; Muse's RAW frames to the core's
//!   events (never hand-built `MuseEvent`s: the serde attributes are what
//!   they pin); its close and its drop; `endStream`; the close sequence;
//! - **no starvation** — a flood of frames that yield nothing gives the
//!   relay its turn every `MAX_SILENT_FRAMES_PER_POLL`;
//! - **the connector** — the dial uses the one the app hands in: one that
//!   trusts a test certificate opens a `wss://` session, one that trusts
//!   nothing is `Dial`, class `tls`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use futures::{SinkExt as _, Stream, StreamExt as _};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use stridelabs_voice::muse::mock::{MockMuse, Seen};
use stridelabs_voice::muse::{
    handshake_body, MuseRate, MuseSession, MuseStt, END_STREAM, REALTIME_PATH,
};
use stridelabs_voice::stt::{
    AudioFormat, OpenLabel, SttError, SttEvent, SttOpenError, SttProvider as _, SttSession as _,
    MAX_SILENT_FRAMES_PER_POLL,
};
use tokio::time::{timeout, Instant};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore, ServerConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;

/// The key every test opens with. Not a secret.
const TEST_KEY: &str = "test-meta-key-s2d";

/// How long any one wait may take before the test fails.
const WAIT: Duration = Duration::from_secs(5);

const RATE_24K: AudioFormat = AudioFormat::pcm_s16le(24_000);

/// Muse at `url` with [`TEST_KEY`] and `keywords`, dialled in plain text
/// (the mock is `ws://` on loopback).
fn muse_at(url: &str, keywords: &[&str]) -> MuseStt {
    MuseStt::new(
        TEST_KEY,
        url,
        keywords.iter().map(|term| (*term).to_string()).collect(),
        Connector::Plain,
    )
}

/// Open a session at `format`, with a deadline the adapter must not apply.
async fn open(muse: &MuseStt, format: AudioFormat) -> Result<MuseSession, SttOpenError> {
    timeout(WAIT, muse.open(format, Instant::now() + WAIT))
        .await
        .expect("the open hung")
}

/// The next item the session yields.
async fn next(session: &mut MuseSession) -> Option<Result<SttEvent, SttError>> {
    timeout(WAIT, session.next())
        .await
        .expect("the session yielded nothing in 5 s")
}

/// `len` bytes of distinct-looking audio.
fn pcm(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add(u8::try_from(index % 251).expect("< 251")))
        .collect()
}

// ── The handshake and the session ────────────────────────────────────────

/// The whole session on the wire: the realtime path; the handshake (the
/// key, `PCM_24KHZ`, the keywords) as the first frame; the ack opens it;
/// audio reaches Muse byte for byte, in order; Muse's events become the
/// core's; `end_input` is `endStream`; Muse's `1000` is `Finished`; and the
/// close that follows (only a flush of the reply to Muse's close) returns.
#[tokio::test]
async fn a_session_opens_streams_and_finishes_on_the_wire() {
    let mock = MockMuse::start().await;
    let muse = muse_at(&format!("{}/base/", mock.url()), &["Fair State"]);
    assert!(muse.configured());
    let mut session = open(&muse, RATE_24K).await.expect("acked");
    let mut conn = mock.accept().await;
    assert_eq!(conn.path(), format!("/base{REALTIME_PATH}"));
    let handshake = conn.text().await;
    assert_eq!(
        handshake,
        handshake_body(TEST_KEY, MuseRate::Hz24000, &["Fair State".to_string()])
    );
    assert!(
        handshake.contains(r#""accessToken":"Bearer test-meta-key-s2d""#),
        "{handshake}"
    );
    assert!(
        handshake.contains(r#""audioEncoding":"PCM_24KHZ""#),
        "{handshake}"
    );

    let frames = [pcm(3_840, 1), pcm(3_840, 2), pcm(1_000, 3)];
    for frame in &frames {
        session
            .send_audio(bytes::Bytes::from(frame.clone()))
            .await
            .expect("written");
    }
    conn.send(r#"{"type":"speechStart","turnId":1}"#);
    conn.send(r#"{"type":"transcript","transcript":"what's the","final":false}"#);
    conn.send(r#"{"type":"speechEnd","turnId":1}"#);
    conn.send(r#"{"type":"speechComplete","turnId":1,"transcript":"What's the weather?"}"#);
    assert_eq!(next(&mut session).await, Some(Ok(SttEvent::SpeechStart)));
    assert_eq!(
        next(&mut session).await,
        Some(Ok(SttEvent::Partial("what's the".into())))
    );
    assert_eq!(next(&mut session).await, Some(Ok(SttEvent::SpeechEnd)));
    assert_eq!(
        next(&mut session).await,
        Some(Ok(SttEvent::EndOfTurn("What's the weather?".into())))
    );

    session.end_input().await.expect("written");
    let (audio, after) = conn.audio_until_other().await;
    assert_eq!(
        audio, frames,
        "the audio reaches Muse byte for byte, in order"
    );
    assert_eq!(after, Seen::Text(END_STREAM.to_string()));
    conn.close(1000);
    assert_eq!(next(&mut session).await, Some(Ok(SttEvent::Finished)));
    timeout(WAIT, session.close(true))
        .await
        .expect("a finished session's close only flushes");
}

/// The rate reaches the handshake: a 16 kHz session names `PCM_16KHZ`.
#[tokio::test]
async fn the_rate_reaches_the_handshake() {
    let mock = MockMuse::start().await;
    let muse = muse_at(&mock.url(), &[]);
    let _session = open(&muse, AudioFormat::pcm_s16le(16_000))
        .await
        .expect("acked");
    let handshake = mock.accept().await.text().await;
    assert_eq!(handshake, handshake_body(TEST_KEY, MuseRate::Hz16000, &[]));
    assert!(
        handshake.contains(r#""audioEncoding":"PCM_16KHZ""#),
        "{handshake}"
    );
}

/// Configured keywords reach the handshake, in order, and nothing else's.
#[tokio::test]
async fn configured_keywords_reach_the_handshake() {
    let mock = MockMuse::start().await;
    let keywords = ["Fair State", "tripel"];
    let muse = muse_at(&mock.url(), &keywords);
    let _session = open(&muse, RATE_24K).await.expect("acked");
    let handshake = mock.accept().await.text().await;
    assert!(
        handshake.ends_with(r#""languageBias":["English"],"keywords":["Fair State","tripel"]}"#),
        "{handshake}"
    );
    assert!(!handshake.contains("Heavy Rotation"), "{handshake}");
    assert_eq!(
        handshake,
        handshake_body(TEST_KEY, MuseRate::Hz24000, &keywords.map(str::to_string))
    );
}

/// No keywords: the handshake carries NO `keywords` field (not `[]`), and
/// the session opens and runs as any other.
#[tokio::test]
async fn empty_keywords_omit_the_field_from_the_handshake() {
    let mock = MockMuse::start().await;
    let muse = muse_at(&mock.url(), &[]);
    let mut session = open(&muse, RATE_24K).await.expect("acked");
    let mut conn = mock.accept().await;
    let handshake = conn.text().await;
    assert!(!handshake.contains("keywords"), "{handshake}");
    assert!(
        handshake.ends_with(r#""languageBias":["English"]}"#),
        "{handshake}"
    );
    session
        .send_audio(bytes::Bytes::from(pcm(4_800, 3)))
        .await
        .expect("written");
    session.end_input().await.expect("written");
    let (audio, after) = conn.audio_until_other().await;
    assert_eq!(audio, vec![pcm(4_800, 3)]);
    assert_eq!(after, Seen::Text(END_STREAM.to_string()));
}

/// Muse's RAW frames, as the session reads them: every documented event,
/// `audioProgress`, an unknown type and a frame that is not JSON (each
/// `Ignored`, one per data message), a binary frame (absorbed: nothing), a
/// final `transcript` (still a partial), `speechComplete` (the turn), and
/// `error` (the session's failure, class `an error event`).
#[tokio::test]
async fn muse_events_parse_from_raw_frames() {
    let mock = MockMuse::start().await;
    let muse = muse_at(&mock.url(), &[]);
    let mut session = open(&muse, RATE_24K).await.expect("acked");
    let conn = mock.accept().await;
    for frame in [
        r#"{"type":"speechStart","turnId":4}"#,
        r#"{"type":"audioProgress","audioMs":80}"#,
        r#"{"type":"transcript","transcript":"what's the weather","final":false}"#,
        r#"{"type":"somethingNew","x":1}"#,
        "this is not json",
    ] {
        conn.send(frame);
    }
    conn.send_binary(vec![1, 2, 3]);
    for frame in [
        r#"{"type":"transcript","transcript":"what's the weather in","final":true}"#,
        r#"{"type":"speechEnd","turnId":4}"#,
        r#"{"type":"speechComplete","turnId":4,"transcript":"What's the weather in Chicago?"}"#,
        r#"{"type":"speechComplete","turnId":5}"#,
        r#"{"type":"error","message":"the session failed"}"#,
    ] {
        conn.send(frame);
    }
    let mut items = Vec::new();
    for _ in 0..10 {
        items.push(next(&mut session).await);
    }
    assert_eq!(
        items,
        [
            Some(Ok(SttEvent::SpeechStart)),
            Some(Ok(SttEvent::Ignored)),
            Some(Ok(SttEvent::Partial("what's the weather".into()))),
            Some(Ok(SttEvent::Ignored)),
            Some(Ok(SttEvent::Ignored)),
            Some(Ok(SttEvent::Partial("what's the weather in".into()))),
            Some(Ok(SttEvent::SpeechEnd)),
            Some(Ok(SttEvent::EndOfTurn(
                "What's the weather in Chicago?".into()
            ))),
            Some(Ok(SttEvent::EndOfTurn(String::new()))),
            Some(Err(SttError::fixed("an error event"))),
        ]
    );
}

/// Muse ending the session on its own: a close of `1000` is `Finished` (the
/// relay decides whether that is done), any other close the failure
/// `closed`, and a dropped connection a failure (not `Finished`).
#[tokio::test]
async fn a_close_or_a_drop_from_muse_ends_the_session() {
    for how in ["close 1000", "close 1011", "drop"] {
        let mock = MockMuse::start().await;
        let muse = muse_at(&mock.url(), &[]);
        let mut session = open(&muse, RATE_24K).await.expect("acked");
        let conn = mock.accept().await;
        match how {
            "close 1000" => conn.close(1000),
            "close 1011" => conn.close(1011),
            _ => conn.drop_connection(),
        }
        let item = next(&mut session).await;
        match how {
            "close 1000" => assert_eq!(item, Some(Ok(SttEvent::Finished)), "{how}"),
            "close 1011" => assert_eq!(item, Some(Err(SttError::fixed("closed"))), "{how}"),
            _ => assert!(
                matches!(item, None | Some(Err(_))),
                "{how}: a drop is a failure, got {item:?}"
            ),
        }
        timeout(WAIT, session.close(false))
            .await
            .expect("an ended session's close returns");
    }
}

/// `close` on a session still open: `endStream` first unless the relay
/// already sent it, then a normal close (`1000`), and it returns once Muse
/// answered the close.
#[tokio::test]
async fn close_sends_end_stream_unless_sent_then_a_normal_close() {
    for end_sent in [false, true] {
        let mock = MockMuse::start().await;
        let muse = muse_at(&mock.url(), &[]);
        let session = open(&muse, RATE_24K).await.expect("acked");
        let mut conn = mock.accept().await;
        let _handshake = conn.text().await;
        timeout(WAIT, session.close(end_sent))
            .await
            .expect("the close returned once Muse answered it");
        if !end_sent {
            assert_eq!(conn.next().await, Seen::Text(END_STREAM.to_string()));
        }
        assert_eq!(
            conn.next().await,
            Seen::Close(Some(1000)),
            "end_sent {end_sent}"
        );
    }
}

// ── The open ─────────────────────────────────────────────────────────────

/// Every way an open fails, by its label and fixed class: Muse answering
/// the handshake with an error event (even one carrying a `sessionId`), a
/// close, or a dropped connection is `Refused`; nothing listening is `Dial`
/// with the I/O kind; an unconfigured provider (no key, a refused URL)
/// dials nothing.
#[tokio::test]
async fn each_open_failure_has_its_label_and_class() {
    let refused = |class| SttOpenError {
        label: OpenLabel::Refused,
        class: stridelabs_voice::ErrorClass::fixed(class),
    };
    let mock = MockMuse::start().await;
    let muse = muse_at(&mock.url(), &[]);
    mock.reply_to_handshake(Some(
        r#"{"type":"error","message":"bad key","sessionId":"s1"}"#,
    ));
    assert_eq!(
        open(&muse, RATE_24K).await.err(),
        Some(refused("an error event"))
    );
    let _refused = mock.accept().await;

    mock.never_ack();
    let pending = tokio::spawn({
        let muse = muse_at(&mock.url(), &[]);
        async move { open(&muse, RATE_24K).await.err() }
    });
    let mut conn = mock.accept().await;
    let _handshake = conn.text().await;
    conn.close(1000);
    assert_eq!(pending.await.expect("the task"), Some(refused("a close")));

    let pending = tokio::spawn({
        let muse = muse_at(&mock.url(), &[]);
        async move { open(&muse, RATE_24K).await.err() }
    });
    let mut conn = mock.accept().await;
    let _handshake = conn.text().await;
    conn.drop_connection();
    assert_eq!(
        pending.await.expect("the task"),
        Some(refused("the connection ended"))
    );

    let unreachable = muse_at("ws://127.0.0.1:1", &[]);
    assert_eq!(
        open(&unreachable, RATE_24K).await.err(),
        Some(SttOpenError {
            label: OpenLabel::Dial,
            class: stridelabs_voice::ErrorClass::fixed("io ConnectionRefused"),
        })
    );

    let fresh = MockMuse::start().await;
    for unconfigured in [
        MuseStt::new("", &fresh.url(), Vec::new(), Connector::Plain),
        MuseStt::new(TEST_KEY, "ws://localhost:9", Vec::new(), Connector::Plain),
    ] {
        assert!(!unconfigured.configured());
        let failed = open(&unconfigured, RATE_24K).await.expect_err("no session");
        assert_eq!(failed.label, OpenLabel::Dial);
    }
    assert!(
        !fresh.was_dialled().await,
        "an unconfigured provider dials nothing"
    );
}

/// The adapter applies NO deadline of its own (the relay's `timeout_at` is
/// the only one): with Muse never acking, an open whose deadline is already
/// past is still pending 500 ms later; dropping it (as the relay's bound
/// does) closes the connection.
#[tokio::test]
async fn the_adapter_applies_no_open_deadline_of_its_own() {
    let mock = MockMuse::start().await;
    mock.never_ack();
    let muse = muse_at(&mock.url(), &[]);
    let opening = muse.open(RATE_24K, Instant::now());
    let still = timeout(Duration::from_millis(500), opening).await;
    assert!(
        still.is_err(),
        "the adapter ended its open on its own: {:?}",
        still.map(|r| r.err())
    );
    let mut conn = mock.accept().await;
    assert!(
        conn.text().await.contains("accessToken"),
        "the handshake was sent"
    );
    assert_eq!(
        conn.next().await,
        Seen::Gone,
        "the dropped open closed its socket"
    );
}

// ── No starvation ────────────────────────────────────────────────────────

/// Counts its wakes.
#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A flood of frames that yield nothing (binary frames: Muse sends none,
/// so the adapter absorbs them) does not hold the poll: with 100 of them
/// buffered before an event, each poll absorbs at most
/// `MAX_SILENT_FRAMES_PER_POLL` (32), then wakes itself and returns
/// `Pending`, so the relay's other arms get their turn; the fourth poll
/// reaches the event.
#[tokio::test]
async fn a_muse_frame_flood_without_events_yields() {
    assert_eq!(MAX_SILENT_FRAMES_PER_POLL, 32);
    let mock = MockMuse::start().await;
    let muse = muse_at(&mock.url(), &[]);
    let mut session = open(&muse, RATE_24K).await.expect("acked");
    let conn = mock.accept().await;
    for _ in 0..100 {
        conn.send_binary(vec![0; 8]);
    }
    conn.send(r#"{"type":"speechStart"}"#);
    // Every frame is buffered on this side before the first poll.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut context = Context::from_waker(&waker);
    for round in 1..=3 {
        assert!(
            std::pin::Pin::new(&mut session)
                .poll_next(&mut context)
                .is_pending(),
            "poll {round} absorbed past the bound"
        );
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            round,
            "poll {round} woke itself"
        );
    }
    assert_eq!(
        std::pin::Pin::new(&mut session).poll_next(&mut context),
        Poll::Ready(Some(Ok(SttEvent::SpeechStart))),
        "the fourth poll absorbs the last 4 and reaches the event"
    );
}

// ── The connector ────────────────────────────────────────────────────────

/// A `wss://` stand-in for Muse on `127.0.0.1`: a throwaway CA's leaf
/// certificate for the IP, served by tokio-rustls on aws-lc-rs; it acks the
/// handshake. Returns its URL and the CA's certificate.
async fn tls_muse() -> (String, CertificateDer<'static>) {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().expect("CA key"))
        .expect("a self-signed CA");
    let ca = issuer.der().clone();
    let leaf_key = KeyPair::generate().expect("a leaf key");
    let leaf = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("leaf params")
        .signed_by(&leaf_key, &issuer)
        .expect("a signed leaf");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], key)
        .expect("a server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("the address");
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut ws) = tokio_tungstenite::accept_async(tls).await else {
                    return;
                };
                if let Some(Ok(Message::Text(_))) = ws.next().await {
                    let _ = ws.send(Message::text(r#"{"sessionId":"tls"}"#)).await;
                }
                while let Some(Ok(_)) = ws.next().await {}
            });
        }
    });
    (format!("wss://{addr}"), ca)
}

/// A client config on aws-lc-rs that trusts exactly `roots`.
fn connector(roots: &[CertificateDer<'static>]) -> Connector {
    let mut store = RootCertStore::empty();
    for root in roots {
        store.add(root.clone()).expect("a root");
    }
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_root_certificates(store)
    .with_no_client_auth();
    Connector::Rustls(Arc::new(config))
}

/// **The dial uses the injected connector**: one that trusts the test CA
/// opens a `wss://` session (the ack read through TLS); one that trusts
/// nothing fails the TLS handshake, `Dial` with class `tls`. Nothing else
/// could make that difference: the crate builds no TLS configuration of its
/// own.
#[tokio::test]
async fn the_dial_uses_the_injected_connector() {
    let (url, ca) = tls_muse().await;
    let trusting = MuseStt::new(TEST_KEY, &url, Vec::new(), connector(&[ca]));
    let session = open(&trusting, RATE_24K)
        .await
        .expect("a session through the trusting connector");
    timeout(WAIT, session.close(false)).await.expect("closed");

    let distrusting = MuseStt::new(TEST_KEY, &url, Vec::new(), connector(&[]));
    assert_eq!(
        open(&distrusting, RATE_24K).await.err(),
        Some(SttOpenError {
            label: OpenLabel::Dial,
            class: stridelabs_voice::ErrorClass::fixed("tls"),
        })
    );
}
