//! What a search, or building a client, fails with.
//!
//! Every `Display` and `Debug` here is safe to log: fixed phrases, a status
//! code, a count, a documented response status, or a `std::io::ErrorKind`. No
//! error keeps a `reqwest::Error` or anything else from the exchange: a
//! transport failure is reduced to where it happened ([`Phase`]), whether it
//! timed out, and the innermost I/O error kind, and the `reqwest::Error` is
//! dropped, because its source chain can carry what the peer sent (an HTTP/2
//! GOAWAY's debug data, rendered by h2 in both `Display` and `Debug`), and
//! `without_url()` strips only the URL. So [`std::error::Error::source`] is
//! `None` for every variant. Never a `serde_json` message (it can quote the
//! input it failed on), the input, the key, a body, or the response's `error`
//! object; the crate's redaction tests hold each path to that.

use std::error::Error as _;
use std::fmt;
use std::io;

/// Why a search produced no answer.
///
/// Whether to search again, and how often, is the caller's: a retry is a
/// second billed search. [`PerplexityError::Unavailable`] is the one class
/// that may answer differently next time.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PerplexityError {
    /// Perplexity answered `408`, `429` or any status of `500` or more (`5xx`
    /// and the `600`–`999` hyper also accepts), the exchange passed its
    /// timeout (before the headers or while the body was read), or the
    /// connection could not be made or broke (a body cut off before its end
    /// included). No body is read.
    #[error("Perplexity is unavailable: {0}")]
    Unavailable(UnavailableReason),
    /// Perplexity answered a status that is neither a `2xx` nor
    /// [`PerplexityError::Unavailable`]'s: any `4xx` but `408` and `429`, any
    /// `3xx` (an answer, never followed; see
    /// [`crate::PerplexityClient::builder`]), and any `1xx` final status. No
    /// body is read.
    ///
    /// `#[non_exhaustive]`, so a field can join `status` without breaking a
    /// caller: match it as `Rejected { status, .. }`.
    #[error("Perplexity rejected the request with HTTP {status}")]
    #[non_exhaustive]
    Rejected {
        /// The HTTP status code.
        status: u16,
    },
    /// Perplexity answered a `2xx` whose response `status` is not
    /// `completed` (`failed`, `incomplete`, or any other), or one of whose
    /// `message` items carries a `status` of its own that is not `completed`
    /// (that status here, mapped like the response's: a non-string one is
    /// [`ResponseStatus::Other`]). Whatever text it carried is not returned,
    /// and its `error` object is never read.
    ///
    /// `#[non_exhaustive]`: match it as `Incomplete { status, .. }`.
    #[error("Perplexity's response did not complete: its status is {status}")]
    #[non_exhaustive]
    Incomplete {
        /// The response's `status`.
        status: ResponseStatus,
    },
    /// Perplexity answered a `2xx` that is not a usable response.
    #[error("Perplexity answered 2xx, but {0}")]
    Malformed(MalformedReason),
    /// The input is longer than the client's
    /// [`crate::PerplexityClient::max_input_chars`]. Nothing was sent.
    /// Carries the counts, never the input.
    #[error("the input is {chars} characters, over the bound of {max}; nothing was sent")]
    InputTooLong {
        /// The input's length, in Unicode scalar values.
        chars: usize,
        /// The bound it passed.
        max: usize,
    },
}

/// Which way Perplexity was unavailable ([`PerplexityError::Unavailable`]).
/// Its `Display` is fixed phrases, a status code and an
/// `std::io::ErrorKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnavailableReason {
    /// It answered `408`, `429` or a status of `500` or more (the code). The
    /// body is not read.
    Status(u16),
    /// The exchange passed the client's timeout, in this [`Phase`].
    Timeout(Phase),
    /// The exchange failed some other way, in this [`Phase`]: the connection
    /// was refused or broke, the response's head could not be parsed, or the
    /// body ended before its declared length.
    #[non_exhaustive]
    Transport {
        /// Where it failed.
        phase: Phase,
        /// The kind of the innermost `std::io::Error` in reqwest's source
        /// chain, when one is there (`ConnectionRefused`,
        /// `ConnectionReset`, …). The kind only: an I/O error's message can
        /// be anything its producer wrote.
        io: Option<io::ErrorKind>,
    },
}

impl UnavailableReason {
    /// The chain is walked at most this deep. Real chains are a handful of
    /// links; the cap only keeps a pathological one from being walked forever.
    const MAX_CHAIN: usize = 32;

    /// `error`, a failure in `phase`, reduced to whether it timed out and the
    /// innermost I/O error kind. Nothing else of it is kept.
    pub(crate) fn from_reqwest(phase: Phase, error: &reqwest::Error) -> UnavailableReason {
        if error.is_timeout() {
            return UnavailableReason::Timeout(phase);
        }
        let mut io = None;
        let mut link = error.source();
        for _ in 0..UnavailableReason::MAX_CHAIN {
            let Some(cause) = link else { break };
            if let Some(found) = cause.downcast_ref::<io::Error>() {
                io = Some(found.kind());
            }
            link = cause.source();
        }
        UnavailableReason::Transport { phase, io }
    }
}

impl fmt::Display for UnavailableReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnavailableReason::Status(status) => write!(formatter, "it answered HTTP {status}"),
            UnavailableReason::Timeout(phase) => {
                write!(formatter, "the exchange timed out {phase}")
            }
            UnavailableReason::Transport { phase, io } => {
                write!(formatter, "the exchange failed {phase}")?;
                if let Some(kind) = io {
                    // `ErrorKind`'s `Display` is std's fixed description of
                    // the kind.
                    write!(formatter, "; I/O error: {kind}")?;
                }
                Ok(())
            }
        }
    }
}

/// Where in the exchange a timeout or a transport failure happened, by where
/// the crate was when it failed (the send, or a body read) and, within the
/// send, reqwest's `is_connect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Phase {
    /// Making the connection: the send failed, and reqwest's `is_connect`
    /// says it was the connect (a refused connection, or the client's own
    /// connect timeout).
    Connect,
    /// Before the response's head was read: any other failure of the send
    /// (writing the request, waiting for or parsing the head, and the
    /// whole-exchange timeout ending any of them, a slow connect included).
    Headers,
    /// Reading the response body, after its head arrived: a stall, a body
    /// cut off before its end, a malformed chunk. reqwest wraps every frame
    /// error of a body read in a decode error; the crate labels it by where
    /// it was instead.
    Body,
}

impl Phase {
    /// The fixed phrase this phase renders as.
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match self {
            Phase::Connect => "while connecting",
            Phase::Headers => "before the response headers",
            Phase::Body => "while reading the response body",
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.phrase())
    }
}

/// A response's `status`, as the Agent API documents it. A string it does not
/// document is [`ResponseStatus::Other`], never kept: it is the provider's
/// text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResponseStatus {
    /// `completed`: the only status a [`crate::SearchAnswer`] is made from.
    Completed,
    /// `failed`.
    Failed,
    /// `incomplete`: generation stopped early (an output bound, say).
    Incomplete,
    /// `in_progress`.
    InProgress,
    /// `queued`.
    Queued,
    /// `cancelled`.
    Cancelled,
    /// Any other string.
    Other,
}

impl ResponseStatus {
    /// The status named `status` on the wire.
    pub(crate) fn from_wire(status: &str) -> ResponseStatus {
        match status {
            "completed" => ResponseStatus::Completed,
            "failed" => ResponseStatus::Failed,
            "incomplete" => ResponseStatus::Incomplete,
            "in_progress" => ResponseStatus::InProgress,
            "queued" => ResponseStatus::Queued,
            "cancelled" => ResponseStatus::Cancelled,
            _ => ResponseStatus::Other,
        }
    }

    /// The fixed phrase this status renders as: its wire name, or
    /// `an undocumented one` for [`ResponseStatus::Other`].
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match self {
            ResponseStatus::Completed => "completed",
            ResponseStatus::Failed => "failed",
            ResponseStatus::Incomplete => "incomplete",
            ResponseStatus::InProgress => "in_progress",
            ResponseStatus::Queued => "queued",
            ResponseStatus::Cancelled => "cancelled",
            ResponseStatus::Other => "an undocumented one",
        }
    }
}

impl fmt::Display for ResponseStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.phrase())
    }
}

/// What was wrong with a `2xx` ([`PerplexityError::Malformed`]). Its
/// `Display` is a fixed phrase ([`MalformedReason::phrase`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MalformedReason {
    /// The body is over the client's
    /// [`crate::PerplexityClient::max_response_bytes`]: by its
    /// `Content-Length`, unread, or cut off while it was read.
    BodyTooLarge,
    /// The body is not UTF-8, anywhere in it (a field the crate does not
    /// read included).
    NotUtf8,
    /// The body is not one JSON object.
    NotJson,
    /// The object has no `status`, or it is not a string.
    MissingStatus,
    /// The object has `status` more than once (an escaped spelling of the
    /// key included), whatever the values: contradictory completion
    /// evidence, so none of it is believed.
    DuplicateStatus,
    /// The status is `completed`, but no assistant `message` item carries
    /// any `output_text` (a message whose `role` is present and not
    /// `assistant` contributes none), or the text is empty or only
    /// whitespace.
    MissingAnswer,
}

impl MalformedReason {
    /// The fixed phrase this reason renders as.
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match self {
            MalformedReason::BodyTooLarge => "its body is over the response bound",
            MalformedReason::NotUtf8 => "its body is not UTF-8",
            MalformedReason::NotJson => "its body is not a JSON object",
            MalformedReason::MissingStatus => "its body has no string status",
            MalformedReason::DuplicateStatus => "its body has more than one status",
            MalformedReason::MissingAnswer => "its response has no answer text",
        }
    }
}

impl fmt::Display for MalformedReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.phrase())
    }
}

/// Why [`crate::PerplexityClientBuilder::build`] refused its settings. Never
/// the key or the URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// The base URL cannot be used; the phrase says why. Never the URL itself,
    /// which may carry userinfo.
    #[error("the Perplexity base URL is not usable: {0}")]
    InvalidBaseUrl(&'static str),
    /// The API key is empty after trimming.
    #[error("the Perplexity API key is empty")]
    EmptyApiKey,
    /// The API key holds a byte no HTTP header can carry.
    #[error("the Perplexity API key holds a byte no HTTP header can carry")]
    InvalidApiKey,
    /// The timeout is zero, which would fail every search at once.
    #[error("the Perplexity timeout is zero")]
    ZeroTimeout,
    /// `max_response_bytes` is zero, which would refuse every answer.
    #[error("the Perplexity response bound is zero")]
    ZeroMaxResponseBytes,
    /// `max_input_chars` is zero, which would refuse every input.
    #[error("the Perplexity input bound is zero")]
    ZeroMaxInputChars,
    /// `max_output_tokens` is zero; the API takes an integer of at least 1.
    #[error("the Perplexity output-token bound is zero")]
    ZeroMaxOutputTokens,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The renderings are pinned: they are what a log line carries.
    #[test]
    fn every_display_is_a_fixed_phrase_a_status_or_a_count() {
        let cases = [
            (
                PerplexityError::Unavailable(UnavailableReason::Status(503)),
                "Perplexity is unavailable: it answered HTTP 503",
            ),
            (
                PerplexityError::Unavailable(UnavailableReason::Timeout(Phase::Headers)),
                "Perplexity is unavailable: the exchange timed out before the response headers",
            ),
            (
                PerplexityError::Unavailable(UnavailableReason::Timeout(Phase::Body)),
                "Perplexity is unavailable: the exchange timed out while reading the response body",
            ),
            (
                PerplexityError::Unavailable(UnavailableReason::Transport {
                    phase: Phase::Connect,
                    io: Some(io::ErrorKind::ConnectionRefused),
                }),
                "Perplexity is unavailable: the exchange failed while connecting; \
                 I/O error: connection refused",
            ),
            (
                PerplexityError::Unavailable(UnavailableReason::Transport {
                    phase: Phase::Body,
                    io: None,
                }),
                "Perplexity is unavailable: the exchange failed while reading the response body",
            ),
            (
                PerplexityError::Rejected { status: 302 },
                "Perplexity rejected the request with HTTP 302",
            ),
            (
                PerplexityError::Incomplete {
                    status: ResponseStatus::Failed,
                },
                "Perplexity's response did not complete: its status is failed",
            ),
            (
                PerplexityError::Incomplete {
                    status: ResponseStatus::Other,
                },
                "Perplexity's response did not complete: its status is an undocumented one",
            ),
            (
                PerplexityError::Malformed(MalformedReason::MissingAnswer),
                "Perplexity answered 2xx, but its response has no answer text",
            ),
            (
                PerplexityError::InputTooLong {
                    chars: 2_001,
                    max: 2_000,
                },
                "the input is 2001 characters, over the bound of 2000; nothing was sent",
            ),
        ];
        for (error, rendered) in cases {
            assert_eq!(error.to_string(), rendered);
            assert!(error.source().is_none(), "{error}: no error keeps a source");
        }
        assert_eq!(
            BuildError::InvalidBaseUrl("it carries userinfo").to_string(),
            "the Perplexity base URL is not usable: it carries userinfo"
        );
    }

    /// Each documented status by its wire name, and anything else (a near
    /// miss in case or spelling included) as `Other`, never kept.
    #[test]
    fn response_statuses_are_the_documented_names() {
        for (wire, status) in [
            ("completed", ResponseStatus::Completed),
            ("failed", ResponseStatus::Failed),
            ("incomplete", ResponseStatus::Incomplete),
            ("in_progress", ResponseStatus::InProgress),
            ("queued", ResponseStatus::Queued),
            ("cancelled", ResponseStatus::Cancelled),
        ] {
            assert_eq!(ResponseStatus::from_wire(wire), status);
            assert_eq!(status.to_string(), wire);
        }
        for other in ["", "Completed", "COMPLETED", "complete", "canceled", "done"] {
            assert_eq!(
                ResponseStatus::from_wire(other),
                ResponseStatus::Other,
                "{other:?}"
            );
        }
    }
}
