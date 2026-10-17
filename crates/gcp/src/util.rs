//! Crate-private helpers shared by `auth`, `storage` and `vertex`: what an
//! error may say about a failed request, how much of a body is read, and how
//! a name goes into a URL.

use std::fmt;

use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::Value;

/// How much of a Google error message an error may quote.
pub(crate) const MAX_ECHOED_MESSAGE: usize = 200;

/// The most of an error body ever read: enough for any Google error
/// envelope. The rest is left unread.
pub(crate) const MAX_ERROR_BODY: usize = 16 * 1024;

/// Everything but RFC 3986's unreserved characters (`A-Z a-z 0-9 - . _ ~`) is
/// encoded — `/` included, as `%2F`. GCS takes an object name as ONE path
/// segment (`/o/{object}`) or one query value (`name=`), so a raw `/` would
/// make `a/b.png` a different resource path, and a raw `?`, `#` or `&` would
/// end the segment or the value early. The same set as tapper's
/// `percent_encode_object_name` and parcel's `OBJECT_NAME`.
pub(crate) const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// [`COMPONENT`] with `/` kept: a public object URL, where the object name's
/// slashes are meant to read as path separators.
pub(crate) const PATH: &AsciiSet = &COMPONENT.remove(b'/');

/// `value` percent-encoded as one URL path segment or query value.
pub(crate) fn encode_component(value: &str) -> String {
    utf8_percent_encode(value, COMPONENT).to_string()
}

/// `value` percent-encoded as a URL path, its `/` kept.
pub(crate) fn encode_path(value: &str) -> String {
    utf8_percent_encode(value, PATH).to_string()
}

/// A failed request, as a fixed category — never its text.
///
/// `reqwest::Error`'s `Display` ends `for url (…)`, query string included,
/// and `without_url()` strips only that outer URL: the source chain can
/// carry another one. A redirect refused for its scheme nests a
/// `url_bad_scheme` error holding the *redirect target*, query and all, and
/// a token endpoint or emulator URL is configuration that can carry a
/// credential. So no part of the error is formatted; the category (parcel's
/// `redact()` shape) is what an operator gets.
pub(crate) fn describe_reqwest(error: reqwest::Error) -> String {
    let category = if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_redirect() {
        "redirect refused"
    } else if error.is_body() {
        "body error"
    } else if error.is_decode() {
        "decode error"
    } else if error.is_builder() {
        "invalid request"
    } else if error.is_request() {
        "request error"
    } else {
        "request failed"
    };
    category.to_owned()
}

/// A JSON parse failure as its category and position only. serde_json's
/// `Display` can quote the offending value (`invalid type: string "…"`),
/// which in a credential file is a secret and in a response can be megabytes.
pub(crate) fn json_failure(error: &serde_json::Error) -> String {
    format!(
        "{:?} error at line {} column {}",
        error.classify(),
        error.line(),
        error.column()
    )
}

/// At most `max` characters of `text`, control characters (newlines
/// included) turned into spaces so an echoed message cannot forge a log line,
/// and an ellipsis when something was cut.
pub(crate) fn truncate(text: &str, max: usize) -> String {
    let mut out: String = text
        .chars()
        .take(max)
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    if text.chars().nth(max).is_some() {
        out.push('…');
    }
    out.trim().to_owned()
}

/// Whether `text` is a machine code safe to quote: 1–64 ASCII letters,
/// digits, `_`, `.` or `-` (`invalid_grant`, `RESOURCE_EXHAUSTED`). Anything
/// else is dropped rather than quoted.
pub(crate) fn is_code(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// `: {detail}`, or nothing for an empty detail — the tail of a status
/// error's `Display`.
pub(crate) fn detail_suffix(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else {
        format!(": {detail}")
    }
}

/// ` ({status})`, or nothing — the tail of a Google status error's
/// `Display`.
pub(crate) fn status_suffix(status: &Option<String>) -> String {
    status
        .as_deref()
        .map(|status| format!(" ({status})"))
        .unwrap_or_default()
}

/// The free text of a Google API error (`error.message`): at most 200
/// characters, on one line.
///
/// **It can contain request content** — Vertex quotes parts of the prompt,
/// GCS names the object — so it is user data, not for routine logging. It
/// has no `Display`, and its `Debug` prints only its length: an error that
/// carries one can go to `error!(%e)` or `{e:?}` without it. Read it
/// deliberately, with [`SensitiveMessage::as_str`] (or the errors'
/// `sensitive_message()`), where request content may be shown.
///
/// Google writes it about the request; it does not echo credentials (the
/// bearer token travels in a header no message quotes).
#[derive(Clone, PartialEq, Eq)]
pub struct SensitiveMessage(String);

impl SensitiveMessage {
    /// The message text. May contain request content; see the type docs.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SensitiveMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SensitiveMessage(<{} chars>)", self.0.chars().count())
    }
}

/// What a Google API error body may contribute to an error, from the
/// `{"error": {"code", "message", "status", …}}` envelope every Google JSON
/// API answers with. Everything else in the envelope (`errors[]`,
/// `details[]`, debug info), everything outside it, and any body that is
/// not it, is dropped.
pub(crate) struct GoogleError {
    /// `error.status` (`RESOURCE_EXHAUSTED`, …), only if [`is_code`]. Safe
    /// for logs: a fixed enum name.
    pub(crate) status: Option<String>,
    /// `error.message`, truncated to one line. Not safe for logs.
    pub(crate) message: Option<SensitiveMessage>,
}

pub(crate) fn google_error(body: &[u8]) -> GoogleError {
    let envelope =
        serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|root| match root.get("error") {
                Some(Value::Object(error)) => Some(error.clone()),
                _ => None,
            });
    let Some(error) = envelope else {
        return GoogleError {
            status: None,
            message: None,
        };
    };
    GoogleError {
        status: error
            .get("status")
            .and_then(Value::as_str)
            .filter(|status| is_code(status))
            .map(str::to_owned),
        message: error
            .get("message")
            .and_then(Value::as_str)
            .map(|message| truncate(message, MAX_ECHOED_MESSAGE))
            .filter(|message| !message.is_empty())
            .map(SensitiveMessage),
    }
}

/// A body read up to a cap.
pub(crate) struct Limited {
    pub(crate) bytes: Vec<u8>,
    /// More followed the cap and was left unread.
    pub(crate) truncated: bool,
}

/// Read `response`'s body chunk by chunk, stopping at `cap` bytes. A body
/// that declares a longer `Content-Length` is not read at all.
pub(crate) async fn read_limited(
    mut response: reqwest::Response,
    cap: usize,
) -> Result<Limited, reqwest::Error> {
    let declared = response.content_length();
    if declared.is_some_and(|length| length > cap as u64) {
        return Ok(Limited {
            bytes: Vec::new(),
            truncated: true,
        });
    }
    let capacity = declared.map_or(0, |length| (length as usize).min(cap));
    let mut bytes = Vec::with_capacity(capacity);
    while let Some(chunk) = response.chunk().await? {
        let room = cap - bytes.len();
        if chunk.len() > room {
            bytes.extend_from_slice(&chunk[..room]);
            return Ok(Limited {
                bytes,
                truncated: true,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Limited {
        bytes,
        truncated: false,
    })
}

/// An error response's body, at most [`MAX_ERROR_BODY`] of it; empty when it
/// cannot be read. Only ever handed to a detail extractor, never quoted.
pub(crate) async fn read_error_body(response: reqwest::Response) -> Vec<u8> {
    read_limited(response, MAX_ERROR_BODY)
        .await
        .map(|limited| limited.bytes)
        .unwrap_or_default()
}

/// `raw` as `scheme://host[:port]/path`, for a `Debug` impl: the userinfo,
/// query and fragment — the parts that can hold a credential — are dropped.
/// stridelabs-auth's `redact_url`, which is crate-private there.
pub(crate) fn redact_url(raw: &str) -> String {
    reqwest::Url::parse(raw)
        .ok()
        .and_then(|url| {
            let host = url.host_str()?;
            let port = url
                .port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default();
            Some(format!("{}://{host}{port}{}", url.scheme(), url.path()))
        })
        .unwrap_or_else(|| "<unparseable URL>".to_owned())
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[test]
    fn a_component_encodes_everything_but_unreserved_characters() {
        assert_eq!(encode_component("a/b c.png"), "a%2Fb%20c.png");
        assert_eq!(encode_component("A-Z_a.z~09"), "A-Z_a.z~09");
        assert_eq!(encode_component("?#&=+%@:"), "%3F%23%26%3D%2B%25%40%3A");
        // UTF-8 bytes, uppercase hex.
        assert_eq!(encode_component("é"), "%C3%A9");
    }

    #[test]
    fn a_path_keeps_its_slashes() {
        assert_eq!(encode_path("a/b c.png"), "a/b%20c.png");
        assert_eq!(encode_path("u/2026?x#y"), "u/2026%3Fx%23y");
    }

    #[test]
    fn truncate_cuts_flattens_and_marks() {
        assert_eq!(truncate("short", 200), "short");
        assert_eq!(truncate("line one\nline two", 200), "line one line two");
        assert_eq!(truncate("abcdef", 3), "abc…");
        // Counted in characters, never split inside one.
        assert_eq!(truncate("ééé", 2), "éé…");
    }

    #[test]
    fn codes_are_short_and_plain() {
        for code in [
            "invalid_grant",
            "RESOURCE_EXHAUSTED",
            "a.b-c_1",
            &"x".repeat(64),
        ] {
            assert!(is_code(code), "{code}");
        }
        for not in [
            "",
            "has space",
            "quote\"",
            "new\nline",
            "CANARY/x",
            &"x".repeat(65),
            "é",
        ] {
            assert!(!is_code(not), "{not}");
        }
    }

    #[test]
    fn a_google_error_keeps_its_status_and_a_short_sensitive_message_only() {
        let long = "m".repeat(500);
        let body = serde_json::json!({
            "error": {
                "code": 429,
                "status": "RESOURCE_EXHAUSTED",
                "message": format!("Quota\nexceeded {long}"),
                "errors": [{"reason": "CANARY-IN-ERRORS"}],
                "details": [{"debugInfo": "CANARY-IN-DETAILS"}],
            },
            "token": "CANARY-OUTSIDE",
        });
        let error = google_error(body.to_string().as_bytes());
        assert_eq!(error.status.as_deref(), Some("RESOURCE_EXHAUSTED"));
        let message = error.message.expect("a message");
        assert!(
            message.as_str().starts_with("Quota exceeded m"),
            "{}",
            message.as_str()
        );
        assert!(message.as_str().chars().count() <= 201);
        assert!(!message.as_str().contains("CANARY"));
        assert_eq!(format!("{message:?}"), "SensitiveMessage(<201 chars>)");

        // A status that is not a plain code is dropped, the message kept.
        let body = br#"{"error":{"status":"BAD STATUS CANARY","message":"No such object"}}"#;
        let error = google_error(body);
        assert_eq!(error.status, None);
        assert_eq!(error.message.unwrap().as_str(), "No such object");
        // Not the envelope, or not JSON: nothing.
        for body in [
            &b"<html>CANARY</html>"[..],
            br#"{"message":"CANARY"}"#,
            br#"{"error":"CANARY"}"#,
        ] {
            let error = google_error(body);
            assert!(error.status.is_none() && error.message.is_none());
        }
    }

    #[test]
    fn json_failures_never_quote_the_input() {
        let error = serde_json::from_str::<u8>("\"CANARY\"").unwrap_err();
        assert!(error.to_string().contains("CANARY"), "premise");
        let rendered = json_failure(&error);
        assert!(!rendered.contains("CANARY"), "{rendered}");
        assert!(rendered.starts_with("Data error at line 1"), "{rendered}");
    }

    #[test]
    fn redact_url_drops_credentials() {
        assert_eq!(
            redact_url("http://user:SECRET@host:8080/token?key=SECRET#SECRET"),
            "http://host:8080/token"
        );
        assert_eq!(redact_url("not a url SECRET"), "<unparseable URL>");
    }

    async fn body_of(len: usize) -> reqwest::Response {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; len]))
            .mount(&server)
            .await;
        reqwest::get(server.uri()).await.unwrap()
    }

    /// A server that answers one request with `chunks` as a chunked body —
    /// no `Content-Length`, so `read_limited` cannot refuse up front and
    /// must count as it reads. wiremock always sends a length.
    async fn chunked(chunks: Vec<Vec<u8>>) -> reqwest::Response {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = socket.read(&mut buffer).await.unwrap();
                request.extend_from_slice(&buffer[..read]);
            }
            let mut response =
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    .to_vec();
            for chunk in chunks {
                response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                response.extend_from_slice(&chunk);
                response.extend_from_slice(b"\r\n");
            }
            response.extend_from_slice(b"0\r\n\r\n");
            // The client may hang up once it has read enough.
            let _ = socket.write_all(&response).await;
        });
        let response = reqwest::get(format!("http://{address}/")).await.unwrap();
        assert!(
            response.content_length().is_none(),
            "premise: no declared length"
        );
        response
    }

    #[tokio::test]
    async fn read_limited_counts_a_chunked_body_to_the_byte() {
        let bytes = |len: usize, fill: u8| vec![fill; len];
        for (name, chunks, expected_len, expected_truncated) in [
            (
                "exactly the cap, in two chunks",
                vec![bytes(512, b'a'), bytes(512, b'b')],
                1024,
                false,
            ),
            (
                "the cap plus one, split mid-chunk",
                vec![bytes(512, b'a'), bytes(513, b'b')],
                1024,
                true,
            ),
            (
                "the cap, then one more chunk",
                vec![bytes(1024, b'a'), bytes(1, b'b')],
                1024,
                true,
            ),
            (
                "one chunk over the cap",
                vec![bytes(1025, b'a')],
                1024,
                true,
            ),
            ("under the cap", vec![bytes(10, b'a')], 10, false),
        ] {
            let flat: Vec<u8> = chunks.concat();
            let limited = read_limited(chunked(chunks).await, 1024).await.unwrap();
            assert_eq!(
                (limited.bytes.len(), limited.truncated),
                (expected_len, expected_truncated),
                "{name}"
            );
            assert_eq!(
                limited.bytes,
                flat[..expected_len],
                "{name}: the prefix, intact"
            );
        }
    }

    /// A transport error's text never reaches an error: not even a nested
    /// source. reqwest nests the redirect *target* (query and all) inside a
    /// redirect error whenever the target is refused — `https_only` refusing
    /// `http`, or a consumer's redirect policy, constructed here — and
    /// `without_url()` strips only the outer URL.
    #[tokio::test]
    async fn a_nested_redirect_target_never_reaches_the_description() {
        use std::error::Error as _;

        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "http://attacker.example/next?token=CANARY"),
            )
            .mount(&server)
            .await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                let refusal = format!("refusing a redirect to {}", attempt.url());
                attempt.error(refusal)
            }))
            .build()
            .unwrap();
        let error = client.get(server.uri()).send().await.unwrap_err();

        // Premise: the URL-stripped error still carries the target in its
        // source chain, which is what the old rendering appended.
        let stripped = error.without_url();
        let mut chain = stripped.to_string();
        let mut source = stripped.source();
        while let Some(cause) = source {
            chain.push_str(&cause.to_string());
            source = cause.source();
        }
        assert!(chain.contains("CANARY"), "premise: {chain}");

        let error = client.get(server.uri()).send().await.unwrap_err();
        assert_eq!(describe_reqwest(error), "redirect refused");
    }

    #[tokio::test]
    async fn read_limited_stops_at_the_cap() {
        let exact = read_limited(body_of(1024).await, 1024).await.unwrap();
        assert_eq!((exact.bytes.len(), exact.truncated), (1024, false));

        let over = read_limited(body_of(1025).await, 1024).await.unwrap();
        assert!(over.truncated);
        assert!(over.bytes.len() <= 1024);

        let under = read_limited(body_of(10).await, 1024).await.unwrap();
        assert_eq!((under.bytes.len(), under.truncated), (10, false));
    }
}
