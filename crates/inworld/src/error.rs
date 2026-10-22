//! What a synthesis, or building a client, fails with.
//!
//! Every `Display` and `Debug` here is safe to log: fixed phrases, a status
//! code, a count, or a `std::io::ErrorKind`. No error keeps a `reqwest::Error`
//! or anything else from the exchange: a transport failure is reduced to a
//! [`TransportCause`] (where it failed, whether it timed out, and the
//! innermost I/O error kind) and the `reqwest::Error` is dropped, because its source chain
//! can carry what the peer sent (an HTTP/2 GOAWAY's debug data, rendered by
//! h2 in both `Display` and `Debug`), and `without_url()` strips only the URL.
//! So [`std::error::Error::source`] is `None` for every variant. Never a
//! `serde_json` message (it can quote the input it failed on), the text, the
//! key or a body; the crate's redaction tests hold each path to that.

use std::error::Error as _;
use std::fmt;
use std::io;

/// Why a synthesis produced no audio.
///
/// Only [`InworldError::Unavailable`] is retryable
/// ([`InworldError::is_retryable`]). Everything else is the same answer
/// however often the request is sent. Whether to retry, and how often, is the
/// caller's: a retry is a second billed synthesis.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum InworldError {
    /// Inworld answered `408`, `429` or any status of `500` or more (`5xx`
    /// and the `600`–`999` hyper also accepts), the exchange passed its
    /// timeout (before the headers or while the body was read), or the
    /// connection could not be made or broke (a body cut off before its end
    /// included).
    ///
    /// `#[non_exhaustive]`, so a field can join it: match it with `..`.
    #[error("Inworld is unavailable: {reason}{}", cause_suffix(.cause))]
    #[non_exhaustive]
    Unavailable {
        /// Which of those it was.
        reason: UnavailableReason,
        /// For a transport failure, what reqwest reported, sanitized; `None`
        /// for a status.
        cause: Option<TransportCause>,
    },
    /// Inworld answered a status that is neither a `2xx` nor retryable: any
    /// `4xx` but `408` and `429`, any `3xx` (an answer, never followed; see
    /// [`crate::InworldClient::builder`]), and any `1xx` final status. No body
    /// is read.
    ///
    /// `#[non_exhaustive]`, so a field (an RPC code, say) can join `status`
    /// without breaking a caller: match it as `Rejected { status, .. }`.
    #[error("Inworld rejected the request with HTTP {status}")]
    #[non_exhaustive]
    Rejected {
        /// The HTTP status code.
        status: u16,
    },
    /// Inworld answered a `2xx` that is not usable audio.
    #[error("Inworld answered 2xx, but {0}")]
    Malformed(MalformedReason),
    /// The API key is empty after trimming, or holds a byte no HTTP header
    /// can carry. Nothing was sent.
    #[error(
        "the Inworld API key is empty or holds a byte no HTTP header can carry; nothing was sent"
    )]
    UnusableKey,
    /// The text is longer than the client's
    /// [`crate::InworldBounds::max_text_chars`]. Nothing was sent. Carries the
    /// counts, never the text.
    #[error("the text is {chars} characters, over the bound of {max}; nothing was sent")]
    TextTooLong {
        /// The text's length, in Unicode scalar values.
        chars: usize,
        /// The bound it passed.
        max: usize,
    },
    /// The speaking rate is NaN or infinite, which JSON cannot carry
    /// (serde_json would send `null`). Nothing was sent.
    #[error("the speaking rate is not a finite number; nothing was sent")]
    SpeakingRateNotFinite,
}

impl InworldError {
    /// Whether the same request may succeed if sent again: true for
    /// [`InworldError::Unavailable`] alone (a `408` included, as lumen 001
    /// §6.3 and slaudio's Python adapter classify it).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, InworldError::Unavailable { .. })
    }
}

/// Which way Inworld was unavailable ([`InworldError::Unavailable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnavailableReason {
    /// It answered `408`, `429` or a status of `500` or more (the code). The
    /// body is not read.
    Status(u16),
    /// The exchange passed the client's timeout, before the response's
    /// headers or while its body was read.
    TimedOut,
    /// The connection could not be made.
    Connect,
    /// The exchange failed some other way: the connection broke, the body
    /// ended before its declared length, or the response could not be read.
    Transport,
}

impl fmt::Display for UnavailableReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnavailableReason::Status(status) => write!(formatter, "it answered HTTP {status}"),
            UnavailableReason::TimedOut => formatter.write_str("the exchange timed out"),
            UnavailableReason::Connect => formatter.write_str("the connection could not be made"),
            UnavailableReason::Transport => {
                formatter.write_str("the exchange failed or the connection broke")
            }
        }
    }
}

/// `" (<cause>)"` after an [`InworldError::Unavailable`]'s reason, or nothing.
fn cause_suffix(cause: &Option<TransportCause>) -> String {
    cause.map(|cause| format!(" ({cause})")).unwrap_or_default()
}

/// A transport failure, sanitized: where it happened, whether it timed out,
/// and the innermost I/O error kind, never the error itself
/// ([`InworldError::Unavailable`]'s `cause`). Its `Display` and `Debug` are
/// fixed phrases, field names and `std::io::ErrorKind`s only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TransportCause {
    /// Where in the exchange it failed ([`TransportStage`]).
    pub stage: TransportStage,
    /// reqwest's `is_timeout`: the client's timeout ended it.
    pub timed_out: bool,
    /// The kind of the innermost `std::io::Error` in the source chain, when
    /// one is there (`ConnectionRefused`, `ConnectionReset`, …). The kind
    /// only: an I/O error's message can be anything its producer wrote.
    pub io: Option<io::ErrorKind>,
}

impl TransportCause {
    /// The chain is walked at most this deep. Real chains are a handful of
    /// links; the cap only keeps a pathological one from being walked forever.
    const MAX_CHAIN: usize = 32;

    /// A failure of the send (`RequestBuilder::send`): making the connection
    /// when reqwest says so (`is_connect`), otherwise sending the request or
    /// waiting for the response's head.
    pub(crate) fn sending(error: &reqwest::Error) -> TransportCause {
        let stage = if error.is_connect() {
            TransportStage::Connect
        } else {
            TransportStage::Request
        };
        TransportCause::at(stage, error)
    }

    /// A failure of a body read (`Response::chunk`). Always
    /// [`TransportStage::Body`], whatever reqwest's predicates say: reqwest
    /// wraps every frame error of a body read in a decode error, so
    /// `is_decode` would label a stall or a cut-off body a decoding failure.
    pub(crate) fn reading_body(error: &reqwest::Error) -> TransportCause {
        TransportCause::at(TransportStage::Body, error)
    }

    /// `error`, at `stage`. Nothing of it is kept but `is_timeout` and the
    /// innermost I/O error kind.
    fn at(stage: TransportStage, error: &reqwest::Error) -> TransportCause {
        let mut io = None;
        let mut link = error.source();
        for _ in 0..TransportCause::MAX_CHAIN {
            let Some(cause) = link else { break };
            if let Some(found) = cause.downcast_ref::<io::Error>() {
                io = Some(found.kind());
            }
            link = cause.source();
        }
        TransportCause {
            stage,
            timed_out: error.is_timeout(),
            io,
        }
    }
}

impl fmt::Display for TransportCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(if self.timed_out {
            "timed out "
        } else {
            "failed "
        })?;
        formatter.write_str(self.stage.phrase())?;
        if let Some(kind) = self.io {
            // `ErrorKind`'s `Display` is std's fixed description of the kind.
            write!(formatter, "; I/O error: {kind}")?;
        }
        Ok(())
    }
}

/// Where in the exchange a transport failure happened ([`TransportCause`]),
/// by where the crate was when it failed (the send, or a body read) and,
/// within the send, reqwest's `is_connect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportStage {
    /// Making the connection: the send failed, and reqwest's `is_connect`
    /// says it was the connect.
    Connect,
    /// Sending the request or waiting for the response's head: any other
    /// failure of the send.
    Request,
    /// Reading the response body, after its head arrived: a stall (with
    /// `timed_out`), a body cut off before its end, a malformed chunk.
    Body,
}

impl TransportStage {
    /// The fixed phrase this stage renders as.
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match self {
            TransportStage::Connect => "while connecting",
            TransportStage::Request => "while sending the request or awaiting the response",
            TransportStage::Body => "while reading the response body",
        }
    }
}

impl fmt::Display for TransportStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.phrase())
    }
}

/// What was wrong with a `2xx` ([`InworldError::Malformed`]). Its `Display`
/// is a fixed phrase ([`MalformedReason::phrase`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MalformedReason {
    /// The body is over [`crate::InworldBounds::max_response_bytes`]: by its
    /// `Content-Length`, unread, or cut off while it was read.
    BodyTooLarge,
    /// The body is not a JSON object.
    NotJsonObject,
    /// The object has no `audioContent`, or it is not a string.
    NoAudioContent,
    /// `audioContent` is longer than any
    /// [`crate::InworldBounds::max_audio_bytes`] of audio encodes to, so it
    /// was refused before decoding.
    AudioContentTooLong,
    /// `audioContent` is not strict standard base64.
    NotBase64,
    /// `audioContent` decodes to no bytes.
    EmptyAudio,
    /// The audio decodes to more than
    /// [`crate::InworldBounds::max_audio_bytes`]: base64 that passed the
    /// pre-decode length check by its last quantum (up to two bytes over).
    AudioTooLarge,
    /// The MP3 check is on and the audio does not open like an MP3.
    NotMp3,
}

impl MalformedReason {
    /// The fixed phrase this reason renders as.
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match self {
            MalformedReason::BodyTooLarge => "its body is over the response bound",
            MalformedReason::NotJsonObject => "its body is not a JSON object",
            MalformedReason::NoAudioContent => "its body has no string audioContent",
            MalformedReason::AudioContentTooLong => {
                "its audioContent is longer than the audio bound allows"
            }
            MalformedReason::NotBase64 => "its audioContent is not base64",
            MalformedReason::EmptyAudio => "its audio is empty",
            MalformedReason::AudioTooLarge => "its audio is over the audio bound",
            MalformedReason::NotMp3 => "its audio is not MP3",
        }
    }
}

impl fmt::Display for MalformedReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.phrase())
    }
}

/// Why [`crate::InworldClientBuilder::build`] refused its settings.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// The base URL cannot be used; the phrase says why. Never the URL itself,
    /// which may carry userinfo.
    #[error("the Inworld base URL is not usable: {0}")]
    InvalidBaseUrl(&'static str),
    /// The timeout is zero, which would fail every synthesis at once.
    #[error("the Inworld timeout is zero")]
    ZeroTimeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_unavailable_is_retryable() {
        for reason in [
            UnavailableReason::Status(408),
            UnavailableReason::Status(429),
            UnavailableReason::Status(503),
            UnavailableReason::TimedOut,
            UnavailableReason::Connect,
            UnavailableReason::Transport,
        ] {
            let error = InworldError::Unavailable {
                reason,
                cause: None,
            };
            assert!(error.is_retryable(), "{error}");
        }
        for error in [
            InworldError::Rejected { status: 400 },
            InworldError::Rejected { status: 302 },
            InworldError::Malformed(MalformedReason::NotMp3),
            InworldError::UnusableKey,
            InworldError::TextTooLong {
                chars: 601,
                max: 600,
            },
            InworldError::SpeakingRateNotFinite,
        ] {
            assert!(!error.is_retryable(), "{error}");
        }
    }

    /// The renderings are pinned: they are what a log line carries.
    #[test]
    fn every_display_is_a_fixed_phrase_a_status_or_a_count() {
        let cases = [
            (
                InworldError::Unavailable {
                    reason: UnavailableReason::Status(503),
                    cause: None,
                },
                "Inworld is unavailable: it answered HTTP 503",
            ),
            (
                InworldError::Unavailable {
                    reason: UnavailableReason::TimedOut,
                    cause: Some(TransportCause {
                        stage: TransportStage::Body,
                        timed_out: true,
                        io: None,
                    }),
                },
                "Inworld is unavailable: the exchange timed out \
                 (timed out while reading the response body)",
            ),
            (
                InworldError::Unavailable {
                    reason: UnavailableReason::Connect,
                    cause: Some(TransportCause {
                        stage: TransportStage::Connect,
                        timed_out: false,
                        io: Some(io::ErrorKind::ConnectionRefused),
                    }),
                },
                "Inworld is unavailable: the connection could not be made \
                 (failed while connecting; I/O error: connection refused)",
            ),
            (
                InworldError::Rejected { status: 400 },
                "Inworld rejected the request with HTTP 400",
            ),
            (
                InworldError::Malformed(MalformedReason::NotBase64),
                "Inworld answered 2xx, but its audioContent is not base64",
            ),
            (
                InworldError::TextTooLong {
                    chars: 601,
                    max: 600,
                },
                "the text is 601 characters, over the bound of 600; nothing was sent",
            ),
        ];
        for (error, rendered) in cases {
            assert_eq!(error.to_string(), rendered);
            assert!(error.source().is_none(), "{error}: no error keeps a source");
        }
        assert_eq!(
            BuildError::InvalidBaseUrl("it carries userinfo").to_string(),
            "the Inworld base URL is not usable: it carries userinfo"
        );
    }
}
