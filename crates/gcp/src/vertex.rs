//! Vertex AI `generateContent` (feature `vertex`): typed request and
//! response, the endpoint builder, a thin client, and the inline-image
//! classifier.
//!
//! ```no_run
//! # async fn example(tokens: stridelabs_gcp::TokenProvider, http: reqwest::Client)
//! # -> Result<(), stridelabs_gcp::vertex::VertexError> {
//! use stridelabs_gcp::vertex::{
//!     first_inline_image, GenerateContentRequest, GenerationConfig, ImageOutcome, Part, VertexClient,
//! };
//!
//! let vertex = VertexClient::new(http, tokens, "my-project", "global")?;
//! let request = GenerateContentRequest::user(vec![Part::from_text("a lighthouse at dusk")])
//!     .with_generation_config(GenerationConfig::response_modalities(["IMAGE"]));
//! match first_inline_image(&vertex.generate_content("gemini-3.1-flash-image", &request).await?) {
//!     ImageOutcome::Image { bytes, .. } => { /* store it */ }
//!     ImageOutcome::Blocked { reason } => { /* tell the user the prompt was refused */ }
//!     ImageOutcome::Empty { reason } => { /* no image came back */ }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Hosts
//!
//! `location = "global"` is served from `https://aiplatform.googleapis.com`;
//! every other location from `https://{location}-aiplatform.googleapis.com`.
//! That is google-genai's rule (`_api_client.py`, the Vertex branch of
//! `BaseApiClient.__init__`), and the one a naive `{location}-` builder gets
//! wrong: `global-aiplatform.googleapis.com` does not exist, and some models
//! (`gemini-3-pro-image-preview`) are served only from `global`. The API
//! version defaults to google-genai's `v1beta1`.
//!
//! # Every URL part is validated
//!
//! The location is interpolated into the **host**, and the project, model
//! and API version into the path, so each is checked before any URL is built
//! — and before a token is fetched. A value outside its pattern is
//! [`VertexError::InvalidArgument`] and nothing is sent: a location of
//! `attacker.example/` would otherwise send the bearer token and the prompt
//! to `attacker.example`.
//!
//! | Part | Accepted |
//! |---|---|
//! | location | `global`, or `[a-z0-9]+(-[a-z0-9]+)*` (`us-central1`), at most 52 characters (so `{location}-aiplatform` stays one 63-character DNS label) |
//! | project | a project ID (`[a-z][a-z0-9-]{4,28}[a-z0-9]`), optionally domain-scoped (`example.com:my-project`), or a project number (digits) |
//! | model | `[A-Za-z0-9][A-Za-z0-9._-]*`, at most 128 characters |
//! | API version | `v[0-9]+(beta[0-9]*\|alpha[0-9]*)?` (`v1`, `v1beta1`), at most 16 characters |
//!
//! # Limits
//!
//! A response is read up to [`DEFAULT_MAX_RESPONSE_BYTES`] (64 MiB: a 10 MiB
//! image is about 13.4 MiB of base64, plus JSON) and is
//! [`VertexError::TooLarge`] past that
//! ([`VertexClient::with_max_response_bytes`]). An error body is read only as
//! far as its first 16 KiB, and only Google's `error.status` and
//! `error.message` (at most 200 characters) are kept from it.
//!
//! # Privacy
//!
//! Prompts and images are user data. The request and response types derive
//! `Debug`, and their `Debug` **includes the prompt and response text** (an
//! inline image prints as a byte count): fine in a test, not in a routine
//! log line. A [`VertexError`] is safe to log — `Display` and `Debug` carry
//! only statuses and fixed phrases — because Google's `error.message`, which
//! can quote the prompt, is held apart: [`VertexError::sensitive_message`].
//!
//! # Leniency
//!
//! The response types ignore unknown fields and treat every field as
//! optional (`null` included), so a new field or an omitted one is not a
//! decode error. `inlineData.data` is the exception: bytes that are not
//! base64 are a malformed response, and [`VertexError::Decode`].
//!
//! # 401 refresh and replay (opt-in)
//!
//! [`VertexClient::with_unauthorized_refresh`]`(true)` replays a `401` as
//! google-auth's `AuthorizedSession` does: the bearer is evicted with
//! [`TokenProvider::invalidate`], a token is taken again, and the call is
//! sent again with the **same JSON bytes** (serialized once, after the
//! first token, as before), up to
//! [`VertexClient::with_max_refresh_attempts`] times (default 2). A
//! persistent `401` costs three requests and two refreshes at the default,
//! and is then [`VertexError::Status`]. Off, a `401` is one request and that
//! error, as it always was. Only a completed `401` is replayed (it means the
//! call was not applied), never a `403`, a `5xx` or a transport failure. The
//! `401`'s body is read for at most 2 s, and everything counts against
//! [`VertexClient::with_timeout`]. On the metadata server a refresh can
//! return the same bearer, so a replay may add requests without different
//! credentials.
//!
//! What a block or an empty answer *says* to an end user, the timeout, and
//! the models are the service's business, not this module's.

use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::auth::{AccessToken, GcpAuthError, TokenProvider};
use crate::replay::{send_with_refresh, UnauthorizedRefresh};
use crate::util::{
    describe_reqwest, google_error, json_failure, read_error_body, read_limited, redact_url,
    status_suffix, SensitiveMessage,
};

/// The API version google-genai uses for Vertex.
pub const DEFAULT_API_VERSION: &str = "v1beta1";

/// The default cap on a response body.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// The longest location accepted: `{location}-aiplatform` must fit one
/// 63-character DNS label.
pub const MAX_LOCATION_LEN: usize = 63 - "-aiplatform".len();

/// The longest API version accepted.
pub const MAX_API_VERSION_LEN: usize = 16;

/// The location whose host has no `{location}-` prefix.
pub const GLOBAL_LOCATION: &str = "global";

/// Substrings of a `finishReason` (or `promptFeedback.blockReason`) that mean
/// the model refused, as opposed to answering without an image:
/// `SAFETY`/`IMAGE_SAFETY`, `PROHIBITED_CONTENT`/`IMAGE_PROHIBITED_CONTENT`,
/// `BLOCKLIST`, `RECITATION`/`IMAGE_RECITATION`, `SPII`. imgmcp's Python
/// `_BLOCK_MARKERS`.
pub const BLOCK_MARKERS: [&str; 5] = ["SAFETY", "PROHIBITED", "BLOCKLIST", "RECITATION", "SPII"];

/// Whether `reason` contains one of the [`BLOCK_MARKERS`].
pub fn is_block_reason(reason: &str) -> bool {
    BLOCK_MARKERS.iter().any(|marker| reason.contains(marker))
}

/// The `:generateContent` URL for a Google publisher `model`:
/// `https://aiplatform.googleapis.com/{api_version}/projects/{project}/locations/global/publishers/google/models/{model}:generateContent`
/// for [`GLOBAL_LOCATION`], else the same on
/// `https://{location}-aiplatform.googleapis.com`.
///
/// # Errors
///
/// [`VertexError::InvalidArgument`] for any part outside its pattern (see
/// [the module docs](self#every-url-part-is-validated)).
pub fn generate_content_url(
    project: &str,
    location: &str,
    model: &str,
    api_version: &str,
) -> Result<String, VertexError> {
    check_project(project)?;
    check_location(location)?;
    generate_content_url_at(&host(location), project, location, model, api_version)
}

/// The Vertex AI base URL for an already-validated `location`.
fn host(location: &str) -> String {
    if location == GLOBAL_LOCATION {
        "https://aiplatform.googleapis.com".to_owned()
    } else {
        format!("https://{location}-aiplatform.googleapis.com")
    }
}

/// [`generate_content_url`] on another base URL. Every part is validated
/// here too, so no path reaches a URL unchecked; once valid, each is plain
/// enough to go in as is (`example.com:my-project` keeps its `:`, as
/// google-genai sends it).
fn generate_content_url_at(
    base_url: &str,
    project: &str,
    location: &str,
    model: &str,
    api_version: &str,
) -> Result<String, VertexError> {
    check_project(project)?;
    check_location(location)?;
    check_model(model)?;
    check_api_version(api_version)?;
    Ok(format!(
        "{}/{api_version}/projects/{project}/locations/{location}/publishers/google/models/{model}:generateContent",
        base_url.trim_end_matches('/'),
    ))
}

fn invalid(what: &str, rule: &str) -> VertexError {
    VertexError::InvalidArgument(format!("{what} must be {rule}"))
}

fn check_location(location: &str) -> Result<(), VertexError> {
    // 52: `{location}-aiplatform` is one DNS label, at most 63 characters.
    let plain = location == GLOBAL_LOCATION
        || ((1..=MAX_LOCATION_LEN).contains(&location.len())
            && location.split('-').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            }));
    if plain {
        Ok(())
    } else {
        Err(invalid(
            "the location",
            "`global` or lowercase letters and digits joined by single hyphens",
        ))
    }
}

/// Google's project-ID rules (6–30 characters of `a-z`, `0-9` and `-`,
/// starting with a letter, not ending with a hyphen), optionally behind a
/// `domain:` scope; or a project number, which resource paths also accept.
fn check_project(project: &str) -> Result<(), VertexError> {
    fn is_id(id: &str) -> bool {
        let bytes = id.as_bytes();
        (6..=30).contains(&bytes.len())
            && bytes[0].is_ascii_lowercase()
            && bytes[bytes.len() - 1] != b'-'
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    }
    fn is_domain(domain: &str) -> bool {
        domain.len() <= 253
            && domain.split('.').count() >= 2
            && domain.split('.').all(|label| {
                (1..=63).contains(&label.len())
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
    }
    let number = (1..=20).contains(&project.len()) && project.bytes().all(|b| b.is_ascii_digit());
    let id = match project.split_once(':') {
        Some((domain, id)) => is_domain(domain) && is_id(id),
        None => is_id(project),
    };
    if number || id {
        Ok(())
    } else {
        Err(invalid(
            "the project",
            "a Google Cloud project ID (optionally `domain:`-scoped) or project number",
        ))
    }
}

fn check_model(model: &str) -> Result<(), VertexError> {
    let bytes = model.as_bytes();
    let plain = (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(byte));
    if plain {
        Ok(())
    } else {
        Err(invalid(
            "the model",
            "letters, digits, '.', '_' and '-', starting with a letter or digit",
        ))
    }
}

fn check_api_version(version: &str) -> Result<(), VertexError> {
    let plain = version.len() <= MAX_API_VERSION_LEN
        && (|| {
            let rest = version.strip_prefix('v')?;
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                return None;
            }
            let suffix = &rest[digits..];
            let tail = suffix
                .strip_prefix("beta")
                .or_else(|| suffix.strip_prefix("alpha"))
                .unwrap_or(suffix);
            (tail.is_empty() || (suffix != tail && tail.bytes().all(|b| b.is_ascii_digit())))
                .then_some(())
        })()
        .is_some();
    if plain {
        Ok(())
    } else {
        Err(invalid(
            "the API version",
            "like `v1`, `v1beta1` or `v1alpha`",
        ))
    }
}

/// A `generateContent` request body.
///
/// Its `Debug` includes the prompt text: user data, not for routine logs.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateContentRequest {
    /// The conversation: for a one-shot call, one `user` turn.
    pub contents: Vec<Content>,
    /// `generationConfig`, omitted when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_config: Option<GenerationConfig>,
    /// Any other top-level field (`systemInstruction`, `safetySettings`, …),
    /// sent as given.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl GenerateContentRequest {
    /// One `user` turn made of `parts` — google-genai's shape for
    /// `contents=[prompt, image]`.
    pub fn user(parts: Vec<Part>) -> GenerateContentRequest {
        GenerateContentRequest {
            contents: vec![Content {
                role: Some("user".to_owned()),
                parts,
            }],
            ..GenerateContentRequest::default()
        }
    }

    /// This request with `generationConfig` set.
    #[must_use]
    pub fn with_generation_config(mut self, config: GenerationConfig) -> GenerateContentRequest {
        self.generation_config = Some(config);
        self
    }
}

/// `generationConfig`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerationConfig {
    /// `responseModalities`, e.g. `["IMAGE"]`; omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_modalities: Vec<String>,
    /// Any other field (`imageConfig`, `candidateCount`, `temperature`, …),
    /// sent as given.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl GenerationConfig {
    /// A config asking for exactly these modalities.
    pub fn response_modalities<I, S>(modalities: I) -> GenerationConfig
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        GenerationConfig {
            response_modalities: modalities.into_iter().map(Into::into).collect(),
            extra: Map::new(),
        }
    }
}

/// One turn of a conversation. Its `Debug` includes the text of its parts.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Content {
    /// `user` or `model`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The turn's parts, in order.
    #[serde(default, deserialize_with = "nullable")]
    pub parts: Vec<Part>,
}

/// One part of a turn: text, inline bytes, or (in a response) something else
/// this crate does not model, which deserializes with every field `None`.
///
/// Its `Debug` includes `text` — in a request, the prompt. Inline bytes
/// print as a count.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Part {
    /// A text part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// An inline-bytes part (`inlineData`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_data: Option<Blob>,
    /// `true` on a part of the model's thinking rather than its answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thought: Option<bool>,
}

impl Part {
    /// `{"text": text}`.
    pub fn from_text(text: impl Into<String>) -> Part {
        Part {
            text: Some(text.into()),
            ..Part::default()
        }
    }

    /// `{"inlineData": {"mimeType": mime_type, "data": base64(data)}}`.
    pub fn from_bytes(mime_type: impl Into<String>, data: Vec<u8>) -> Part {
        Part {
            inline_data: Some(Blob {
                mime_type: Some(mime_type.into()),
                data,
            }),
            ..Part::default()
        }
    }
}

/// Inline bytes. On the wire `data` is standard base64; here it is the
/// decoded bytes. (Decoding also accepts the URL-safe alphabet and missing
/// padding.)
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Blob {
    /// The bytes' media type, e.g. `image/png`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// The decoded bytes.
    #[serde(default, with = "base64_bytes")]
    pub data: Vec<u8>,
}

impl fmt::Debug for Blob {
    /// A byte count, not megabytes of bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Blob")
            .field("mime_type", &self.mime_type)
            .field("data", &format_args!("<{} bytes>", self.data.len()))
            .finish()
    }
}

/// A `generateContent` response body. Unknown fields are ignored; every
/// field may be absent or `null`.
///
/// Its `Debug` includes the response text — the model's answer about user
/// data — so it is not for routine logs either.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateContentResponse {
    /// The answers; usually one.
    #[serde(default, deserialize_with = "nullable")]
    pub candidates: Vec<Candidate>,
    /// Present when the prompt itself was judged.
    #[serde(default)]
    pub prompt_feedback: Option<PromptFeedback>,
    /// The model version that answered.
    #[serde(default)]
    pub model_version: Option<String>,
    /// The response id, for correlating with Google's logs.
    #[serde(default)]
    pub response_id: Option<String>,
}

/// One answer.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    /// The answer's content.
    #[serde(default)]
    pub content: Option<Content>,
    /// Why generation stopped: `STOP`, `MAX_TOKENS`, `SAFETY`, `IMAGE_SAFETY`,
    /// `NO_IMAGE`, ….
    #[serde(default)]
    pub finish_reason: Option<String>,
    /// A human-readable elaboration of `finish_reason`, when Google sends one.
    #[serde(default)]
    pub finish_message: Option<String>,
}

/// The verdict on the prompt.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptFeedback {
    /// Set when the prompt was blocked: `SAFETY`, `PROHIBITED_CONTENT`,
    /// `BLOCKLIST`, `OTHER`, ….
    #[serde(default)]
    pub block_reason: Option<String>,
    /// A human-readable elaboration of `block_reason`.
    #[serde(default)]
    pub block_reason_message: Option<String>,
}

/// What an image call produced.
#[derive(Clone, PartialEq, Eq)]
pub enum ImageOutcome {
    /// The first inline image.
    Image {
        /// The decoded bytes, non-empty.
        bytes: Vec<u8>,
        /// The `mimeType` Vertex labelled them with — a claim, not a sniff.
        mime_type: Option<String>,
    },
    /// No image, and the model or the prompt filter refused.
    Blocked {
        /// The `finishReason` or `promptFeedback.blockReason` that says so.
        reason: String,
    },
    /// No image, and nothing says it was refused.
    Empty {
        /// The first candidate's `finishReason` (`STOP`, `NO_IMAGE`,
        /// `MAX_TOKENS`, …), or `None` with no candidates at all.
        reason: Option<String>,
    },
}

impl fmt::Debug for ImageOutcome {
    /// A byte count, not megabytes of bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImageOutcome::Image { bytes, mime_type } => f
                .debug_struct("Image")
                .field("bytes", &format_args!("<{} bytes>", bytes.len()))
                .field("mime_type", mime_type)
                .finish(),
            ImageOutcome::Blocked { reason } => {
                f.debug_struct("Blocked").field("reason", reason).finish()
            }
            ImageOutcome::Empty { reason } => {
                f.debug_struct("Empty").field("reason", reason).finish()
            }
        }
    }
}

/// Classify an image response:
///
/// 1. The first part, across candidates in order, with non-empty
///    `inlineData` that is not a `thought` → [`ImageOutcome::Image`].
///    (Thought parts are interim drafts, not the answer; Vertex sends them
///    only when asked to include thoughts.)
/// 2. Else a candidate whose `finishReason` contains a [`BLOCK_MARKERS`]
///    entry → [`ImageOutcome::Blocked`] with that reason.
/// 3. Else a `promptFeedback.blockReason` (other than
///    `BLOCKED_REASON_UNSPECIFIED`) → [`ImageOutcome::Blocked`]: a blocked
///    prompt is blocked whatever the reason's name.
/// 4. Else [`ImageOutcome::Empty`], with the first candidate's
///    `finishReason`.
pub fn first_inline_image(response: &GenerateContentResponse) -> ImageOutcome {
    let image = response
        .candidates
        .iter()
        .filter_map(|candidate| candidate.content.as_ref())
        .flat_map(|content| &content.parts)
        .filter(|part| part.thought != Some(true))
        .filter_map(|part| part.inline_data.as_ref())
        .find(|blob| !blob.data.is_empty());
    if let Some(blob) = image {
        return ImageOutcome::Image {
            bytes: blob.data.clone(),
            mime_type: blob.mime_type.clone(),
        };
    }

    let finish_reasons = || {
        response
            .candidates
            .iter()
            .filter_map(|candidate| candidate.finish_reason.as_deref())
    };
    if let Some(reason) = finish_reasons().find(|reason| is_block_reason(reason)) {
        return ImageOutcome::Blocked {
            reason: reason.to_owned(),
        };
    }
    let prompt_block = response
        .prompt_feedback
        .as_ref()
        .and_then(|feedback| feedback.block_reason.as_deref())
        .filter(|reason| !reason.is_empty() && *reason != "BLOCKED_REASON_UNSPECIFIED");
    if let Some(reason) = prompt_block {
        return ImageOutcome::Blocked {
            reason: reason.to_owned(),
        };
    }
    ImageOutcome::Empty {
        reason: response
            .candidates
            .first()
            .and_then(|candidate| candidate.finish_reason.clone()),
    }
}

/// Why a `generateContent` call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VertexError {
    /// A project, location, model or API version outside its pattern (see
    /// [the module docs](self#every-url-part-is-validated)). Nothing was
    /// sent and no token was fetched.
    #[error("invalid Vertex AI request: {0}")]
    InvalidArgument(String),
    /// No access token.
    #[error("Vertex AI: {0}")]
    Auth(#[from] GcpAuthError),
    /// The request did not complete: a connection failure or an unreadable
    /// body. The payload is the failure's fixed category (`timed out`,
    /// `connection failed`, …), never its text.
    #[error("Vertex AI request failed: {0}")]
    Request(String),
    /// The call outlived the client's timeout.
    #[error("Vertex AI request timed out after {0:?}")]
    Timeout(Duration),
    /// The response body is larger than the client's cap; reading stopped
    /// there.
    #[error("Vertex AI response is larger than {limit} bytes")]
    TooLarge {
        /// The cap ([`VertexClient::with_max_response_bytes`]).
        limit: usize,
    },
    /// Vertex answered non-2xx (`400` invalid argument, `429` quota, …).
    #[error("Vertex AI answered HTTP {status}{}", status_suffix(.google_status))]
    Status {
        /// The HTTP status code.
        status: u16,
        /// Google's `error.status` (`RESOURCE_EXHAUSTED`, …), when the body
        /// is Google's envelope and it is a plain code. Safe to log.
        google_status: Option<String>,
        /// Google's `error.message`: Vertex can quote the prompt in it, so
        /// it is user data and not for routine logging. Its `Debug` prints
        /// only its length.
        message: Option<SensitiveMessage>,
    },
    /// A 2xx body that is not a `generateContent` response. The payload is
    /// the parse failure's category and position, never the body.
    #[error("Vertex AI response is not a generateContent response: {0}")]
    Decode(String),
}

impl VertexError {
    /// Google's free-text `error.message` for a [`VertexError::Status`], at
    /// most 200 characters on one line.
    ///
    /// **May contain request content** — Vertex can quote the prompt —
    /// which is why neither `Display` nor `Debug` includes it. Use it where
    /// user data may be shown, not in routine logs.
    pub fn sensitive_message(&self) -> Option<&str> {
        match self {
            VertexError::Status { message, .. } => message.as_ref().map(SensitiveMessage::as_str),
            _ => None,
        }
    }
}

/// A `generateContent` client for one project and location. Cheap to clone.
#[derive(Clone)]
pub struct VertexClient {
    http: reqwest::Client,
    tokens: TokenProvider,
    project: String,
    location: String,
    api_version: String,
    base_url: Option<String>,
    timeout: Option<Duration>,
    max_response_bytes: usize,
    refresh: UnauthorizedRefresh,
}

impl fmt::Debug for VertexClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VertexClient")
            .field("project", &self.project)
            .field("location", &self.location)
            .field("api_version", &self.api_version)
            .field("base_url", &self.base_url.as_deref().map(redact_url))
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("unauthorized_refresh", &self.refresh.enabled)
            .field("max_refresh_attempts", &self.refresh.max_attempts)
            .field("tokens", &self.tokens)
            .finish_non_exhaustive()
    }
}

impl VertexClient {
    /// A client for `project` in `location`, authorizing with `tokens` (which
    /// needs [`crate::auth::CLOUD_PLATFORM_SCOPE`]). No timeout of its own
    /// until [`VertexClient::with_timeout`]: how long an image may take is the
    /// service's call.
    ///
    /// # Errors
    ///
    /// [`VertexError::InvalidArgument`] when `project` or `location` is
    /// outside its pattern (see
    /// [the module docs](self#every-url-part-is-validated)).
    pub fn new(
        http: reqwest::Client,
        tokens: TokenProvider,
        project: impl Into<String>,
        location: impl Into<String>,
    ) -> Result<VertexClient, VertexError> {
        let project = project.into();
        let location = location.into();
        check_project(&project)?;
        check_location(&location)?;
        Ok(VertexClient {
            http,
            tokens,
            project,
            location,
            api_version: DEFAULT_API_VERSION.to_owned(),
            base_url: None,
            timeout: None,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            refresh: UnauthorizedRefresh::default(),
        })
    }

    /// Send requests to `base_url` instead of the location's Vertex host — a
    /// mock in tests. The path is unchanged. A trusted test seam: unlike the
    /// location, it is not validated.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> VertexClient {
        self.base_url = Some(base_url.into());
        self
    }

    /// Use another API version ([`DEFAULT_API_VERSION`]). Validated when a
    /// URL is built ([`VertexClient::endpoint`], every call).
    #[must_use]
    pub fn with_api_version(mut self, api_version: impl Into<String>) -> VertexClient {
        self.api_version = api_version.into();
        self
    }

    /// Bound each call — token, request and body read together.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> VertexClient {
        self.timeout = Some(timeout);
        self
    }

    /// Replace the response cap ([`DEFAULT_MAX_RESPONSE_BYTES`]).
    #[must_use]
    pub fn with_max_response_bytes(mut self, limit: usize) -> VertexClient {
        self.max_response_bytes = limit;
        self
    }

    /// Refresh the token and replay the call when Vertex answers `401`
    /// (default `false`): see
    /// [the module docs](self#401-refresh-and-replay-opt-in). With it on, a
    /// call replays a `401` up to [`VertexClient::max_refresh_attempts`]
    /// times, each time after [`TokenProvider::invalidate`], with a token
    /// from [`TokenProvider::token`] and the same JSON bytes.
    #[must_use]
    pub fn with_unauthorized_refresh(mut self, enabled: bool) -> VertexClient {
        self.refresh.enabled = enabled;
        self
    }

    /// How many refresh-and-replay cycles one call may make after a `401`
    /// (default 2, google-auth's `DEFAULT_MAX_REFRESH_ATTEMPTS`): a
    /// persistent `401` costs `attempts + 1` requests and `attempts`
    /// refreshes, and `0` replays nothing. Only
    /// [`VertexClient::with_timeout`] bounds them all (there is no timeout
    /// by default). Effective only with
    /// [`VertexClient::with_unauthorized_refresh`]`(true)`; the count alone
    /// never turns it on.
    #[must_use]
    pub fn with_max_refresh_attempts(mut self, attempts: u32) -> VertexClient {
        self.refresh.max_attempts = attempts;
        self
    }

    /// Whether a `401` is refreshed and replayed
    /// ([`VertexClient::with_unauthorized_refresh`]).
    pub fn unauthorized_refresh(&self) -> bool {
        self.refresh.enabled
    }

    /// The configured refresh-and-replay count
    /// ([`VertexClient::with_max_refresh_attempts`]), whether or not
    /// [`VertexClient::unauthorized_refresh`] is on.
    pub fn max_refresh_attempts(&self) -> u32 {
        self.refresh.max_attempts
    }

    /// The `:generateContent` URL for `model`.
    ///
    /// # Errors
    ///
    /// [`VertexError::InvalidArgument`] for a model or API version outside
    /// its pattern.
    pub fn endpoint(&self, model: &str) -> Result<String, VertexError> {
        let base = self
            .base_url
            .clone()
            .unwrap_or_else(|| host(&self.location));
        generate_content_url_at(
            &base,
            &self.project,
            &self.location,
            model,
            &self.api_version,
        )
    }

    /// `POST` `request` to `model`'s `:generateContent`.
    ///
    /// # Errors
    ///
    /// [`VertexError`]; [`VertexError::InvalidArgument`] before any token
    /// or request. A blocked or image-less answer is a successful response,
    /// for [`first_inline_image`] to classify.
    pub async fn generate_content(
        &self,
        model: &str,
        request: &GenerateContentRequest,
    ) -> Result<GenerateContentResponse, VertexError> {
        let endpoint = self.endpoint(model)?;
        let call = self.call(endpoint, request);
        match self.timeout {
            Some(timeout) => tokio::time::timeout(timeout, call)
                .await
                .unwrap_or(Err(VertexError::Timeout(timeout))),
            None => call.await,
        }
    }

    /// Generic over the body only so a unit test can watch when (and how
    /// often) it is serialized.
    async fn call<T: Serialize + ?Sized>(
        &self,
        endpoint: String,
        request: &T,
    ) -> Result<GenerateContentResponse, VertexError> {
        // The token first, then the body, in v0.8.0's order (`json` encoded
        // the request when it was set on a builder that already carried the
        // token): a call that gets no token never encodes its request, an
        // image's base64 included, and its `Auth` error comes before any
        // encoding cost.
        let first = self.tokens.token().await?;
        let authorized = |token: &AccessToken| token.authorize(self.http.post(&endpoint));
        // Then the request, still before the body: a builder that cannot
        // become a request (an unparsable base URL, a quota project that is
        // not a header value) made `json` encode nothing in v0.8.0, and its
        // send reported that builder error. A throwaway build finds the same
        // error before anything is encoded.
        if let Err(error) = authorized(&first).build() {
            return Err(VertexError::Request(describe_reqwest(error)));
        }
        // What `RequestBuilder::json` sent (the same bytes and `Content-Type`,
        // after the authorization headers), serialized once so a replay
        // resends these bytes. Strings and maps only, so it cannot fail; if it
        // did, it would be the builder error `json` reported.
        let body = Bytes::from(
            serde_json::to_vec(request)
                .map_err(|_| VertexError::Request("invalid request".to_owned()))?,
        );
        let sent = send_with_refresh(
            &self.tokens,
            first,
            self.refresh,
            "generateContent",
            |token| {
                authorized(token)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body.clone())
            },
        )
        .await?;
        // Freed before the response is read, as reqwest freed `json`'s body:
        // an image request's base64 must not be held through a 64 MiB answer.
        drop(body);
        let response = sent.map_err(|error| VertexError::Request(describe_reqwest(error)))?;
        let status = response.status();
        if !status.is_success() {
            let error = google_error(&read_error_body(response).await);
            return Err(VertexError::Status {
                status: status.as_u16(),
                google_status: error.status,
                message: error.message,
            });
        }
        let body = read_limited(response, self.max_response_bytes)
            .await
            .map_err(|error| VertexError::Request(describe_reqwest(error)))?;
        if body.truncated {
            return Err(VertexError::TooLarge {
                limit: self.max_response_bytes,
            });
        }
        serde_json::from_slice(&body.bytes)
            .map_err(|error| VertexError::Decode(json_failure(&error)))
    }
}

/// `null` as the type's default, for fields Google may send as `null`.
fn nullable<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

mod base64_bytes {
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
    use base64::engine::DecodePaddingMode;
    use base64::Engine as _;
    use serde::{de, Deserialize, Deserializer, Serializer};

    const INDIFFERENT: GeneralPurposeConfig =
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
    const LENIENT_STANDARD: GeneralPurpose =
        GeneralPurpose::new(&base64::alphabet::STANDARD, INDIFFERENT);
    const LENIENT_URL_SAFE: GeneralPurpose =
        GeneralPurpose::new(&base64::alphabet::URL_SAFE, INDIFFERENT);

    pub(super) fn serialize<S: Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(data))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let Some(text) = Option::<String>::deserialize(deserializer)? else {
            return Ok(Vec::new());
        };
        LENIENT_STANDARD
            .decode(&text)
            .or_else(|_| LENIENT_URL_SAFE.decode(&text))
            .map_err(|_| de::Error::custom("`inlineData.data` is not base64"))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn global_has_no_location_prefix_and_regions_do() {
        assert_eq!(
            generate_content_url(
                "projects-413401",
                "global",
                "gemini-3-pro-image-preview",
                DEFAULT_API_VERSION
            )
            .unwrap(),
            "https://aiplatform.googleapis.com/v1beta1/projects/projects-413401/locations/global/publishers/google/models/gemini-3-pro-image-preview:generateContent"
        );
        assert_eq!(
            generate_content_url("projects-413401", "us-central1", "gemini-3.1-flash-image", "v1")
                .unwrap(),
            "https://us-central1-aiplatform.googleapis.com/v1/projects/projects-413401/locations/us-central1/publishers/google/models/gemini-3.1-flash-image:generateContent"
        );
        assert_eq!(
            host("europe-west4"),
            "https://europe-west4-aiplatform.googleapis.com"
        );
    }

    /// Hostile values for each part never reach a URL. The location is the
    /// one that matters most: it is in the host.
    const HOSTILE: &[&str] = &[
        "attacker.example/",
        "attacker.example/x?",
        "..",
        ".",
        "a/b",
        "x?y",
        "x#y",
        "%2e%2e",
        "",
        " ",
        "a b",
        "a@b",
        "a:b/c",
        "x\ny",
    ];

    #[test]
    fn every_url_part_rejects_hostile_values() {
        let ok = (
            "projects-413401",
            "global",
            "gemini-3.1-flash-image",
            "v1beta1",
        );
        let rejected = |result: Result<String, VertexError>, what: &str, value: &str| {
            assert!(
                matches!(result, Err(VertexError::InvalidArgument(_))),
                "{what} {value:?} must be rejected"
            );
        };
        for value in HOSTILE {
            rejected(
                generate_content_url(ok.0, value, ok.2, ok.3),
                "location",
                value,
            );
            rejected(
                generate_content_url(value, ok.1, ok.2, ok.3),
                "project",
                value,
            );
            rejected(
                generate_content_url(ok.0, ok.1, value, ok.3),
                "model",
                value,
            );
            rejected(
                generate_content_url(ok.0, ok.1, ok.2, value),
                "API version",
                value,
            );
        }
        // A dotted name is a legal model (it stays inside one path segment)
        // but never a location or project.
        for host in ["attacker.example", "us-central1.attacker.example"] {
            rejected(
                generate_content_url(ok.0, host, ok.2, ok.3),
                "location",
                host,
            );
            rejected(
                generate_content_url(host, ok.1, ok.2, ok.3),
                "project",
                host,
            );
        }
        for location in ["GLOBAL", "us-central1-", "-us", "us--central1", "global/"] {
            rejected(
                generate_content_url(ok.0, location, ok.2, ok.3),
                "location",
                location,
            );
        }
        for project in [
            "short",
            "Uppercase-project",
            "1starts-with-digit",
            "ends-with-hyphen-",
            "has_underscore-x",
            "example.com:short",
            "example:my-project",
            "-x.com:my-project",
            &"a".repeat(31),
        ] {
            rejected(
                generate_content_url(project, ok.1, ok.2, ok.3),
                "project",
                project,
            );
        }
        for model in [
            "-gemini",
            ".gemini",
            "gemini/../x",
            "gemini:generateContent",
            &"m".repeat(129),
        ] {
            rejected(
                generate_content_url(ok.0, ok.1, model, ok.3),
                "model",
                model,
            );
        }
        for version in ["1", "v", "vbeta", "v1beta1/..", "v1gamma", "v1-beta", "V1"] {
            rejected(
                generate_content_url(ok.0, ok.1, ok.2, version),
                "API version",
                version,
            );
        }
    }

    #[test]
    fn length_limits_sit_exactly_at_the_dns_label_and_sixteen() {
        assert_eq!(MAX_LOCATION_LEN, 52);
        assert_eq!(MAX_API_VERSION_LEN, 16);
        let url = |location: &str, version: &str| {
            generate_content_url("my-project", location, "m", version)
        };
        let at = "a".repeat(52);
        let host = url(&at, "v1").expect("52 characters is the limit");
        let label = host
            .trim_start_matches("https://")
            .split('.')
            .next()
            .unwrap()
            .to_owned();
        assert_eq!(label.len(), 63, "{label}: one full DNS label");
        assert!(matches!(
            url(&"a".repeat(53), "v1"),
            Err(VertexError::InvalidArgument(_))
        ));
        // A hyphenated location at the limit too.
        assert!(url(&format!("{}-1", "a".repeat(50)), "v1").is_ok());

        let version = format!("v1beta{}", "1".repeat(10));
        assert_eq!(version.len(), 16);
        assert!(url("global", &version).is_ok());
        assert!(matches!(
            url("global", &format!("{version}1")),
            Err(VertexError::InvalidArgument(_))
        ));
    }

    #[test]
    fn every_legal_form_is_accepted() {
        for project in [
            "projects-413401",
            "my-project",
            "example.com:my-project",
            "123456789012",
        ] {
            assert!(
                generate_content_url(project, "global", "m", "v1").is_ok(),
                "{project}"
            );
        }
        for location in ["global", "us-central1", "europe-west4", "asia-northeast1"] {
            assert!(
                generate_content_url("my-project", location, "m", "v1").is_ok(),
                "{location}"
            );
        }
        for model in [
            "gemini-3.1-flash-image",
            "gemini-2.0-flash-001",
            "Imagen_4",
            "m",
        ] {
            assert!(
                generate_content_url("my-project", "global", model, "v1").is_ok(),
                "{model}"
            );
        }
        for version in ["v1", "v1beta1", "v1beta", "v1alpha", "v2alpha3", "v10"] {
            assert!(
                generate_content_url("my-project", "global", "m", version).is_ok(),
                "{version}"
            );
        }
        // Domain-scoped projects keep their `:`, as google-genai sends them.
        assert!(
            generate_content_url("example.com:my-project", "global", "m", "v1")
                .unwrap()
                .contains("/projects/example.com:my-project/")
        );
    }

    #[test]
    fn a_text_only_request_has_one_user_turn() {
        let request = GenerateContentRequest::user(vec![Part::from_text("a cat")])
            .with_generation_config(GenerationConfig::response_modalities(["IMAGE"]));
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({
                "contents": [{"role": "user", "parts": [{"text": "a cat"}]}],
                "generationConfig": {"responseModalities": ["IMAGE"]},
            })
        );
    }

    #[test]
    fn a_text_and_image_request_carries_standard_base64() {
        let mut config = GenerationConfig::response_modalities(["TEXT", "IMAGE"]);
        config
            .extra
            .insert("imageConfig".into(), json!({"aspectRatio": "16:9"}));
        let request = GenerateContentRequest::user(vec![
            Part::from_text("make it blue"),
            // 0xfb 0xff encodes to `+/8=` — the standard alphabet, padded.
            Part::from_bytes("image/png", vec![0xfb, 0xff]),
        ])
        .with_generation_config(config);
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({
                "contents": [{"role": "user", "parts": [
                    {"text": "make it blue"},
                    {"inlineData": {"mimeType": "image/png", "data": "+/8="}},
                ]}],
                "generationConfig": {
                    "responseModalities": ["TEXT", "IMAGE"],
                    "imageConfig": {"aspectRatio": "16:9"},
                },
            })
        );
    }

    fn classify(body: Value) -> ImageOutcome {
        first_inline_image(&serde_json::from_value(body).expect("a lenient parse"))
    }

    #[test]
    fn the_classification_table() {
        let image = |data: &str| json!({"inlineData": {"mimeType": "image/png", "data": data}});
        let cases: Vec<(&str, Value, ImageOutcome)> = vec![
            (
                "an image",
                json!({"candidates": [{"content": {"role": "model", "parts": [
                    {"text": "here you go"}, image("iVBORw==")
                ]}, "finishReason": "STOP"}]}),
                ImageOutcome::Image {
                    bytes: vec![0x89, 0x50, 0x4e, 0x47],
                    mime_type: Some("image/png".into()),
                },
            ),
            (
                "an image wins over a block marker",
                json!({"candidates": [{"content": {"parts": [image("iVBORw==")]}, "finishReason": "SAFETY"}]}),
                ImageOutcome::Image {
                    bytes: vec![0x89, 0x50, 0x4e, 0x47],
                    mime_type: Some("image/png".into()),
                },
            ),
            (
                "a thought image is skipped for the answer",
                json!({"candidates": [{"content": {"parts": [
                    {"inlineData": {"data": "AAAA"}, "thought": true}, image("iVBORw==")
                ]}}]}),
                ImageOutcome::Image {
                    bytes: vec![0x89, 0x50, 0x4e, 0x47],
                    mime_type: Some("image/png".into()),
                },
            ),
            (
                "the second candidate's image",
                json!({"candidates": [
                    {"content": {"parts": [{"text": "no"}]}, "finishReason": "STOP"},
                    {"content": {"parts": [image("iVBORw==")]}},
                ]}),
                ImageOutcome::Image {
                    bytes: vec![0x89, 0x50, 0x4e, 0x47],
                    mime_type: Some("image/png".into()),
                },
            ),
            (
                "blocked by finishReason",
                json!({"candidates": [{"content": {"parts": []}, "finishReason": "IMAGE_SAFETY"}]}),
                ImageOutcome::Blocked {
                    reason: "IMAGE_SAFETY".into(),
                },
            ),
            (
                "blocked by finishReason with no content",
                json!({"candidates": [{"finishReason": "PROHIBITED_CONTENT"}]}),
                ImageOutcome::Blocked {
                    reason: "PROHIBITED_CONTENT".into(),
                },
            ),
            (
                "each marker blocks",
                json!({"candidates": [{"finishReason": "SPII"}, {"finishReason": "RECITATION"}]}),
                ImageOutcome::Blocked {
                    reason: "SPII".into(),
                },
            ),
            (
                "blocked by promptFeedback with no candidates",
                json!({"promptFeedback": {"blockReason": "BLOCKLIST", "blockReasonMessage": "no"}}),
                ImageOutcome::Blocked {
                    reason: "BLOCKLIST".into(),
                },
            ),
            (
                "a prompt block needs no marker",
                json!({"candidates": [], "promptFeedback": {"blockReason": "OTHER"}}),
                ImageOutcome::Blocked {
                    reason: "OTHER".into(),
                },
            ),
            (
                "an unspecified prompt block is not a block",
                json!({"promptFeedback": {"blockReason": "BLOCKED_REASON_UNSPECIFIED"}}),
                ImageOutcome::Empty { reason: None },
            ),
            (
                "no candidates and no reason",
                json!({}),
                ImageOutcome::Empty { reason: None },
            ),
            (
                "null candidates",
                json!({"candidates": null, "promptFeedback": null}),
                ImageOutcome::Empty { reason: None },
            ),
            (
                "no parts",
                json!({"candidates": [{"content": {"role": "model"}, "finishReason": "NO_IMAGE"}]}),
                ImageOutcome::Empty {
                    reason: Some("NO_IMAGE".into()),
                },
            ),
            (
                "null parts",
                json!({"candidates": [{"content": {"parts": null}}]}),
                ImageOutcome::Empty { reason: None },
            ),
            (
                "a benign finish reason with text only",
                json!({"candidates": [{"content": {"parts": [{"text": "I can't draw that"}]}, "finishReason": "STOP"}]}),
                ImageOutcome::Empty {
                    reason: Some("STOP".into()),
                },
            ),
            (
                "empty inline data is not an image",
                json!({"candidates": [{"content": {"parts": [{"inlineData": {"mimeType": "image/png", "data": ""}}]}, "finishReason": "MAX_TOKENS"}]}),
                ImageOutcome::Empty {
                    reason: Some("MAX_TOKENS".into()),
                },
            ),
            (
                "unknown fields and part kinds are ignored",
                json!({"candidates": [{"content": {"parts": [{"functionCall": {"name": "f"}}, image("iVBORw==")]},
                       "safetyRatings": [], "avgLogprobs": -0.1}],
                       "usageMetadata": {"totalTokenCount": 3}, "modelVersion": "m", "createTime": "t"}),
                ImageOutcome::Image {
                    bytes: vec![0x89, 0x50, 0x4e, 0x47],
                    mime_type: Some("image/png".into()),
                },
            ),
        ];
        for (name, body, expected) in cases {
            assert_eq!(classify(body), expected, "{name}");
        }
    }

    #[test]
    fn inline_data_decodes_either_alphabet_with_or_without_padding() {
        for data in ["+/8=", "+/8", "-_8=", "-_8"] {
            let part: Part = serde_json::from_value(json!({"inlineData": {"data": data}})).unwrap();
            assert_eq!(part.inline_data.unwrap().data, vec![0xfb, 0xff], "{data}");
        }
        let error =
            serde_json::from_value::<Part>(json!({"inlineData": {"data": "!!"}})).unwrap_err();
        assert!(error.to_string().contains("not base64"), "{error}");
    }

    #[test]
    fn debug_prints_byte_counts_not_bytes() {
        let part = Part::from_bytes("image/png", vec![7; 4096]);
        let rendered = format!("{part:?}");
        assert!(rendered.contains("<4096 bytes>"), "{rendered}");
        assert!(rendered.len() < 200, "{rendered}");
        let outcome = ImageOutcome::Image {
            bytes: vec![7; 4096],
            mime_type: None,
        };
        assert!(format!("{outcome:?}").contains("<4096 bytes>"));
    }

    #[test]
    fn block_markers_match_as_substrings() {
        for reason in [
            "SAFETY",
            "IMAGE_SAFETY",
            "PROHIBITED_CONTENT",
            "IMAGE_PROHIBITED_CONTENT",
            "BLOCKLIST",
            "RECITATION",
            "IMAGE_RECITATION",
            "SPII",
        ] {
            assert!(is_block_reason(reason), "{reason}");
        }
        for reason in [
            "STOP",
            "MAX_TOKENS",
            "NO_IMAGE",
            "OTHER",
            "IMAGE_OTHER",
            "FINISH_REASON_UNSPECIFIED",
            "",
        ] {
            assert!(!is_block_reason(reason), "{reason}");
        }
    }

    /// A body that counts how often it is serialized: the request JSON
    /// `generateContent` would send, written by hand.
    struct Counted(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    impl Serialize for Counted {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            json!({"contents": [{"role": "user", "parts": [{"text": "x"}]}]}).serialize(serializer)
        }
    }

    /// A metadata server answering `tokens` in order (the last repeated),
    /// a Vertex stand-in answering `statuses` in order (the last repeated),
    /// and a client on both with the refresh on.
    async fn counting_rig(
        tokens: Vec<wiremock::ResponseTemplate>,
        statuses: Vec<u16>,
    ) -> (wiremock::MockServer, VertexClient) {
        counting_rig_with(tokens, statuses, |tokens| tokens).await
    }

    /// [`counting_rig`], its token provider adjusted by `provider`.
    async fn counting_rig_with(
        tokens: Vec<wiremock::ResponseTemplate>,
        statuses: Vec<u16>,
        provider: impl FnOnce(TokenProvider) -> TokenProvider,
    ) -> (wiremock::MockServer, VertexClient) {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        let server = MockServer::start().await;
        let seen = std::sync::atomic::AtomicUsize::new(0);
        Mock::given(method("GET"))
            .and(path_regex("/token$"))
            .respond_with(move |_: &Request| {
                let n = seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokens.get(n).or(tokens.last()).cloned().unwrap()
            })
            .mount(&server)
            .await;
        let answered = std::sync::atomic::AtomicUsize::new(0);
        Mock::given(method("POST"))
            .and(path_regex(":generateContent$"))
            .respond_with(move |_: &Request| {
                let n = answered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let status = *statuses.get(n).or(statuses.last()).unwrap();
                ResponseTemplate::new(status).set_body_json(json!({}))
            })
            .mount(&server)
            .await;
        let tokens = provider(
            TokenProvider::metadata_server(reqwest::Client::new(), &[])
                .with_options(crate::auth::TokenOptions::default().metadata_base_url(server.uri())),
        );
        let vertex = VertexClient::new(reqwest::Client::new(), tokens, "test-project", "global")
            .unwrap()
            .with_base_url(server.uri())
            .with_unauthorized_refresh(true);
        (server, vertex)
    }

    fn bearer(token: &str) -> wiremock::ResponseTemplate {
        wiremock::ResponseTemplate::new(200)
            .set_body_json(json!({"access_token": token, "expires_in": 3600}))
    }

    /// v0.8.0's order: the token first. A call whose token fetch fails is
    /// `Auth` without its request ever being encoded, and sends nothing.
    #[tokio::test]
    async fn a_failed_token_fetch_never_serializes_the_request() {
        let (server, vertex) =
            counting_rig(vec![wiremock::ResponseTemplate::new(500)], vec![200]).await;
        let serialized = std::sync::Arc::default();
        let endpoint = vertex.endpoint("m").unwrap();

        let result = vertex
            .call(endpoint, &Counted(std::sync::Arc::clone(&serialized)))
            .await;

        assert!(
            matches!(
                result,
                Err(VertexError::Auth(GcpAuthError::Status { status: 500, .. }))
            ),
            "{result:?}"
        );
        assert_eq!(
            serialized.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "never encoded"
        );
        let requests = server.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .all(|request| request.method.as_str() == "GET"),
            "no POST"
        );
    }

    /// v0.8.0's order, past the token: a builder that cannot become a
    /// request poisoned `json`, which then encoded nothing. Here too: a
    /// quota project that is not a header value, or an unparsable base URL,
    /// is the same `Request("invalid request")` with nothing encoded and
    /// nothing sent.
    #[tokio::test]
    async fn a_request_that_cannot_be_built_is_never_serialized() {
        let poisoned_header = counting_rig_with(vec![bearer("t1")], vec![200], |tokens| {
            tokens.with_quota_project(Some("bad\nproject".into()))
        })
        .await;
        let (server, vertex) = counting_rig(vec![bearer("t1")], vec![200]).await;
        let poisoned_url = (server, vertex.with_base_url("not a url"));

        for (case, (server, vertex)) in [
            ("quota project", poisoned_header),
            ("base URL", poisoned_url),
        ] {
            let serialized = std::sync::Arc::default();
            let endpoint = vertex.endpoint("m").unwrap();

            let result = vertex
                .call(endpoint, &Counted(std::sync::Arc::clone(&serialized)))
                .await;

            assert!(
                matches!(&result, Err(VertexError::Request(reason)) if reason == "invalid request"),
                "{case}: {result:?}"
            );
            assert_eq!(
                serialized.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "{case}: never encoded"
            );
            let requests = server.received_requests().await.unwrap();
            assert_eq!(
                requests
                    .iter()
                    .map(|request| request.method.as_str())
                    .collect::<Vec<_>>(),
                ["GET"],
                "{case}: the token, and nothing sent"
            );
        }
    }

    /// Serialized once per call, after the first token, however many
    /// replays follow: two 401s and a 200 are three sends of one encoding.
    #[tokio::test]
    async fn a_replayed_call_serializes_its_request_once() {
        let (server, vertex) = counting_rig(
            vec![bearer("t1"), bearer("t2"), bearer("t3")],
            vec![401, 401, 200],
        )
        .await;
        let serialized = std::sync::Arc::default();
        let endpoint = vertex.endpoint("m").unwrap();

        vertex
            .call(endpoint, &Counted(std::sync::Arc::clone(&serialized)))
            .await
            .unwrap();

        assert_eq!(serialized.load(std::sync::atomic::Ordering::SeqCst), 1);
        let posts = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.method.as_str() == "POST")
            .count();
        assert_eq!(posts, 3, "three sends");
    }
}
