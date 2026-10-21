//! A small Google Cloud Storage client over the JSON API: media upload,
//! multipart upload with object metadata, media download, delete, a bucket
//! probe, and the public object URL.
//!
//! Policy-free: no object naming, no bucket from the environment, no
//! metadata of its own choosing. The service decides those. Every default is
//! v0.8.0's: [`ObjectNamePolicy::Strict`] names and one attempt per
//! operation. Both are opt-in to widen: names sent as GCS addresses them
//! ([`ObjectNamePolicy::Literal`]), and a retry of transient failures
//! ([below](self#retry-opt-in)).
//!
//! ```no_run
//! # async fn example(http: reqwest::Client) -> Result<(), Box<dyn std::error::Error>> {
//! use bytes::Bytes;
//! use stridelabs_gcp::auth::{TokenProvider, DEVSTORAGE_READ_WRITE_SCOPE};
//! use stridelabs_gcp::storage::{public_url, GcsClient};
//!
//! let tokens = TokenProvider::from_environment(http.clone(), &[DEVSTORAGE_READ_WRITE_SCOPE], None)?;
//! let gcs = GcsClient::new(http, tokens);
//! gcs.upload("my-bucket", "u/1.png", Bytes::from_static(b"\x89PNG"), "image/png").await?;
//! let url = public_url("my-bucket", "u/1.png")?; // https://storage.googleapis.com/my-bucket/u/1.png
//! # Ok(())
//! # }
//! ```
//!
//! # Names
//!
//! Every operation, and [`public_url`], checks its names before building a
//! URL, and refuses with no request sent and no token fetched:
//!
//! - **Buckets** follow GCS's naming rules: 3–222 characters of `a-z`, `0-9`,
//!   `-`, `_` and `.`, starting and ending with a letter or digit, and no
//!   `..` ([`validate_bucket_name`]; [`StorageError::InvalidBucketName`]).
//! - **Objects**, under the default [`ObjectNamePolicy::Strict`], are
//!   non-empty, neither start nor end with `/`, and have no empty, `.` or
//!   `..` segment between slashes (`u/../victim.png`, `./a`, `a//b`). Such a
//!   name is legal to GCS but becomes a *different* path the moment a client
//!   normalizes the public URL ([`StorageError::InvalidObjectName`]).
//! - **Objects under [`ObjectNamePolicy::Literal`]** go to GCS as given:
//!   GCS's own literal addressing, for a service whose existing objects
//!   carry names `Strict` refuses and must stay addressable. Uploads send
//!   every name, a download or a delete refuses only `""`, `.` and `..` (no
//!   URL path segment can carry them), and [`public_url_with`] refuses none.
//!   It is a transport policy, not validation: whatever else GCS refuses
//!   comes back as its `400`.
//!
//! On the wire the bucket and the object name are percent-encoded as **one**
//! path segment or query value: everything but RFC 3986's unreserved
//! characters is encoded, `/` included (`a/b c.png` → `a%2Fb%20c.png`). That
//! is what the JSON API requires — a raw `/` makes `/o/a/b.png` a different
//! resource. A literal `%2e%2e` is sent as `%252e%252e`, never as a dot
//! segment.
//!
//! # Upload options
//!
//! [`GcsClient::upload_with`] takes [`UploadOptions`]: a `customTime`, a
//! `cacheControl` and an `ifGenerationMatch` precondition. With none set it
//! is [`GcsClient::upload`]'s media upload, on the wire byte for byte. With
//! any set it is a **multipart** upload
//! (`POST {base}/upload/storage/v1/b/{bucket}/o?uploadType=multipart[&ifGenerationMatch=N]`,
//! `Content-Type: multipart/related; boundary=…`), the JSON API's one-request
//! way to create an object together with its metadata:
//!
//! ```text
//! --{boundary}\r\n
//! Content-Type: application/json; charset=UTF-8\r\n
//! \r\n
//! {"name":…,"contentType":…[,"customTime":…][,"cacheControl":…]}\r\n
//! --{boundary}\r\n
//! Content-Type: {content_type}\r\n
//! \r\n
//! {bytes}\r\n
//! --{boundary}--
//! ```
//!
//! — the JSON API's multipart layout. The metadata is serialized with
//! serde_json (the object name is a JSON string there, not a query value),
//! and the bytes go in unchanged. The boundary is `stridelabs-gcp-` plus 128 random bits in
//! hex, drawn again until it appears in neither part, so no content can end
//! a part early.
//!
//! Everything `upload_with` interpolates is checked first, with nothing
//! sent: the content type and the cache control must be header values that
//! need no trimming (visible ASCII, inner spaces and tabs, never CR or LF),
//! a custom time must be writable in RFC 3339 (1970 to the year 9999), and a
//! generation must not be negative ([`StorageError::InvalidArgument`]).
//!
//! A precondition that fails is GCS's 412, which is [`StorageError::Status`]
//! like any non-2xx answer: nothing retries it (a retry policy included) or
//! falls back to an upload that could overwrite.
//!
//! # Emulators
//!
//! [`GcsClient::emulator`] points the client at a fake-gcs-server or similar
//! (a `STORAGE_EMULATOR_HOST`-style base URL) and makes auth optional: with
//! no [`TokenProvider`], requests go out with no `Authorization` header
//! (parcel's rule). A client built with [`GcsClient::new`] always sends a
//! token, whatever its base URL. Either way the `reqwest::Client` must carry
//! no default credential headers, which reqwest would send to the emulator
//! too.
//!
//! # Retry (opt-in)
//!
//! [`GcsClient::with_retry`]`(`[`RetryPolicy::google_default`]`())` retries
//! an operation's transient failures on Cloud Storage's documented schedule:
//! a wait drawn uniformly under a ceiling that starts at 1 s and doubles to
//! 60 s, until the operation succeeds, fails in a way that is not transient,
//! reaches an optional attempt cap, or the next wait would end past the
//! 120 s deadline. Then that attempt's error is returned unchanged. Without
//! a policy ([`RetryPolicy::disabled`], the default) every operation is one
//! attempt, as it always was. [`crate::retry`] has the schedule and what is
//! transient (a `408`, a `429`, `500`, `502`, `503` and `504`, transport
//! failures, interrupted bodies, the same for the token; never a `404` or
//! any other status).
//!
//! - **The error strings are unchanged.** An interrupted body is still
//!   `Request { reason: "decode error" }`: only its retry class is new.
//! - **Each attempt is whole.** It takes a token and rebuilds the same
//!   request (a multipart body is built once for the operation). The
//!   client's timeout bounds each attempt instead of the operation, so the
//!   retry loop ends within the deadline plus one attempt (≤ 120 s + 60 s at
//!   the defaults). That is not a bound on the whole method: a multipart
//!   body is built before the first attempt.
//! - **An attempt cut off by the timeout** is [`StorageError::Timeout`]
//!   (v0.8.0's error there: the body read is inside the bound), transient
//!   unless that attempt had already received an error status that is not:
//!   a `412` or a `401` whose error body never arrives is not retried, a
//!   `503`'s is.
//! - **Library attempts are not wire requests.** A consumer's reqwest client
//!   can retry some protocol failures itself (reqwest 0.13 does by default)
//!   or apply its own timeout inside each attempt. Do not also configure a
//!   reqwest retry for the GCS host: the attempts multiply.
//! - **Retrying a write has two visible effects** when a response is lost
//!   after GCS applied the request: a create-only upload
//!   (`ifGenerationMatch=0`) retried after its object was written answers
//!   `412`, and a retried delete can return `Ok(false)`. A plain upload is
//!   simply written again.
//! - **A `401` is never retried.** To recover from a revoked token, evict it
//!   with [`TokenProvider::invalidate`] and replay once yourself (its docs
//!   have the snippet).
//! - Each retry logs one `debug` line: the operation, the attempt, `wait_ms`,
//!   and the status or the transport category — never a name, a message or
//!   a URL.
//!
//! # Limits and errors
//!
//! A download reads at most [`DEFAULT_MAX_DOWNLOAD_BYTES`] (32 MiB;
//! [`GcsClient::with_max_download_bytes`]) and is [`StorageError::TooLarge`]
//! past that. An error body is read only as far as its first 16 KiB.
//!
//! Every failure is a [`StorageError`] that names the operation. For a non-2xx
//! answer its `Display` and `Debug` say only the HTTP status and, from
//! Google's JSON error envelope, `error.status` when it is a plain code
//! (`PERMISSION_DENIED`). Google's free-text `error.message` names the
//! object, so it is kept apart, as a [`SensitiveMessage`] reachable only
//! through [`StorageError::sensitive_message`]. A body that is not the
//! envelope contributes nothing. No error contains a URL, and a transport
//! failure is reported as a fixed category.

use std::fmt;
use std::fmt::Write as _;
use std::future::Future;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use reqwest::StatusCode;
use serde::Serialize;

use crate::auth::{GcpAuthError, TokenProvider};
use crate::retry;
pub use crate::retry::RetryPolicy;
use crate::util::{
    describe_reqwest, encode_component, encode_path, google_error, is_transient_status,
    read_error_body, read_limited, redact_url, status_suffix, Category, Failed, SensitiveMessage,
};

/// The JSON API's base URL.
pub const DEFAULT_BASE_URL: &str = "https://storage.googleapis.com";

/// The default bound on one operation: token, request and body together.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// The default cap on a downloaded object.
pub const DEFAULT_MAX_DOWNLOAD_BYTES: usize = 32 * 1024 * 1024;

/// The public URL of `object` in `bucket`:
/// `https://storage.googleapis.com/{bucket}/{object}`, with the object's `/`
/// kept as path separators and everything else outside the unreserved set
/// percent-encoded. It resolves only if the object is publicly readable.
///
/// [`ObjectNamePolicy::Strict`]'s, always: [`public_url_with`] takes a
/// policy.
///
/// # Errors
///
/// [`StorageError::InvalidBucketName`] or [`StorageError::InvalidObjectName`]
/// (see [the module docs](self#names)).
pub fn public_url(bucket: &str, object: &str) -> Result<String, StorageError> {
    public_url_with(bucket, object, ObjectNamePolicy::Strict)
}

/// [`public_url`] under `policy`. [`ObjectNamePolicy::Strict`] is
/// [`public_url`] itself. [`ObjectNamePolicy::Literal`] refuses no object
/// name, `""` included, and writes every name as GCS addresses it:
/// `{DEFAULT_BASE_URL}/{bucket}/{name}`, the name's `/` kept and everything
/// outside RFC 3986's unreserved characters percent-encoded.
///
/// **A `Literal` URL is exact addressing, not a safe public URL.** A name
/// with an empty, `.` or `..` segment is written as it is, and a client
/// that normalizes the URL (a browser, most HTTP stacks) resolves it to a
/// *different* path — for a user-influenced name, possibly another user's
/// prefix. Use `Literal` where an existing object's URL must be exact;
/// validate names yourself if they can be hostile.
///
/// # Errors
///
/// [`StorageError::InvalidBucketName`] under either policy;
/// [`StorageError::InvalidObjectName`] under `Strict` only.
pub fn public_url_with(
    bucket: &str,
    object: &str,
    policy: ObjectNamePolicy,
) -> Result<String, StorageError> {
    validate_bucket_name(bucket)?;
    policy.check(object, Carried::Value)?;
    Ok(format!(
        "{DEFAULT_BASE_URL}/{bucket}/{}",
        encode_path(object)
    ))
}

/// GCS's bucket naming rules as every operation here applies them, before
/// anything is sent: 3–222 characters of `a-z`, `0-9`, `-`, `_` and `.`,
/// starting and ending with a letter or digit, with no `..`.
///
/// The rules only GCS itself can judge (reserved words, IP-address shapes,
/// per-label lengths) are left to GCS: a name that passes here can still be
/// refused there. A service that wants the stricter check at startup keeps
/// its own.
///
/// # Errors
///
/// [`StorageError::InvalidBucketName`], naming the rule.
pub fn validate_bucket_name(bucket: &str) -> Result<(), StorageError> {
    let invalid = |reason| Err(StorageError::InvalidBucketName { reason });
    if !(3..=222).contains(&bucket.len()) {
        return invalid("it must be 3 to 222 characters");
    }
    if !bucket
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte))
    {
        return invalid("it may contain only a-z, 0-9, '-', '_' and '.'");
    }
    let edge_ok = |byte: Option<u8>| byte.is_some_and(|byte| byte.is_ascii_alphanumeric());
    if !edge_ok(bucket.bytes().next()) || !edge_ok(bucket.bytes().last()) {
        return invalid("it must start and end with a letter or digit");
    }
    if bucket.contains("..") {
        return invalid("it must not contain '..'");
    }
    Ok(())
}

/// Which object names a [`GcsClient`] sends, and how [`public_url_with`]
/// treats them. `Strict` by default.
///
/// The difference is where a name may be one that a URL cannot carry:
///
/// | | `upload`, `upload_with` | `download`, `delete` | `public_url_with` |
/// |---|---|---|---|
/// | `Strict` | refuses a name that is empty, starts or ends with `/`, or has an empty, `.` or `..` segment | the same | the same |
/// | `Literal` | sends every name | refuses only `""`, `.` and `..` | refuses no name |
///
/// A refusal is [`StorageError::InvalidObjectName`], before a token is
/// fetched or anything is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ObjectNamePolicy {
    /// v0.8.0's rule, everywhere: a name whose public URL stays the same
    /// path when a client normalizes it (see [the module docs](self#names)).
    #[default]
    Strict,
    /// Names go to GCS as given, GCS's literal addressing: for objects
    /// whose names `Strict` refuses and that must stay addressable. A
    /// **transport policy, not validation**.
    ///
    /// - `upload` and `upload_with` send every name: there it is a query
    ///   value (`name=`) or a JSON string, which nothing normalizes.
    /// - `download` and `delete` refuse only the whole names `""`, `.` and
    ///   `..`, which no URL path segment can carry (`/o/.` is sent as `/o/`,
    ///   `/o/..` as the bucket itself). Every other name is sent.
    /// - [`public_url_with`] refuses no name.
    ///
    /// Everything else is GCS's call: CR or LF, a
    /// `.well-known/acme-challenge/` prefix, a name past GCS's length limit
    /// come back as [`StorageError::Status`] (`400`). See
    /// [`public_url_with`] for what a `Literal` public URL is not.
    Literal,
}

/// Where an object name goes.
#[derive(Clone, Copy)]
enum Carried {
    /// One URL path segment (`/o/{object}`).
    Segment,
    /// A query value (`name=`), a JSON string, or a public URL's path (a
    /// string handed back, never sent).
    Value,
}

impl ObjectNamePolicy {
    fn check(self, object: &str, carried: Carried) -> Result<(), StorageError> {
        match (self, carried) {
            (ObjectNamePolicy::Strict, _) => check_object(object),
            (ObjectNamePolicy::Literal, Carried::Segment) => {
                if matches!(object, "" | "." | "..") {
                    Err(StorageError::InvalidObjectName {
                        reason: "it is empty, '.' or '..', which a URL path segment cannot carry",
                    })
                } else {
                    Ok(())
                }
            }
            (ObjectNamePolicy::Literal, Carried::Value) => Ok(()),
        }
    }
}

/// Why a GCS operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The bucket name breaks GCS's naming rules. Nothing was sent.
    #[error("invalid GCS bucket name: {reason}")]
    InvalidBucketName {
        /// Which rule; never the name.
        reason: &'static str,
    },
    /// The object name is one the client's [`ObjectNamePolicy`] refuses:
    /// under `Strict`, empty, starting or ending with `/`, or with an empty,
    /// `.` or `..` segment; under `Literal`, `""`, `.` or `..` on a
    /// download or a delete. Nothing was sent.
    #[error("invalid GCS object name: {reason}")]
    InvalidObjectName {
        /// Which rule; never the name.
        reason: &'static str,
    },
    /// No access token.
    #[error("GCS {operation}: {source}")]
    Auth {
        /// `upload`, `download`, `delete` or `list`.
        operation: &'static str,
        /// The token provider's error.
        source: GcpAuthError,
    },
    /// The request did not complete: a connection failure or an unreadable
    /// body.
    #[error("GCS {operation} request failed: {reason}")]
    Request {
        /// `upload`, `download`, `delete` or `list`.
        operation: &'static str,
        /// The transport failure's fixed category (`timed out`,
        /// `connection failed`, …), never its text.
        reason: String,
    },
    /// The operation outlived the client's timeout (under a retry policy,
    /// its last attempt did).
    #[error("GCS {operation} timed out after {timeout:?}")]
    Timeout {
        /// `upload`, `download`, `delete` or `list`.
        operation: &'static str,
        /// The bound that elapsed.
        timeout: Duration,
    },
    /// The object is larger than the client's download cap; reading stopped
    /// there.
    #[error("GCS {operation}: the object is larger than {limit} bytes")]
    TooLarge {
        /// `download`.
        operation: &'static str,
        /// The cap ([`GcsClient::with_max_download_bytes`]).
        limit: usize,
    },
    /// GCS answered with a status the operation does not accept.
    #[error("GCS {operation} answered HTTP {status}{}", status_suffix(.google_status))]
    Status {
        /// `upload`, `download`, `delete` or `list`.
        operation: &'static str,
        /// The HTTP status code.
        status: u16,
        /// Google's `error.status` (`PERMISSION_DENIED`, …), when the body
        /// is Google's envelope and it is a plain code. Safe to log.
        google_status: Option<String>,
        /// Google's `error.message`: may name the object, so not for
        /// routine logging. Its `Debug` prints only its length.
        message: Option<SensitiveMessage>,
    },
    /// A value [`GcsClient::upload_with`] cannot send: a content type or
    /// cache control that is not a plain header value, a custom time RFC
    /// 3339 cannot write, a negative generation. Nothing was sent.
    ///
    /// (The last variant, added after the others, so that none of theirs
    /// changes its discriminant.)
    #[error("invalid GCS request argument: {reason}")]
    InvalidArgument {
        /// Which rule; never the value.
        reason: &'static str,
    },
}

impl StorageError {
    /// Google's free-text `error.message` for a [`StorageError::Status`],
    /// at most 200 characters on one line.
    ///
    /// **May contain request content** (object names), which is why neither
    /// `Display` nor `Debug` includes it. Use it where that is acceptable —
    /// a debug log behind a flag, an operator tool — not in routine logs.
    pub fn sensitive_message(&self) -> Option<&str> {
        match self {
            StorageError::Status { message, .. } => message.as_ref().map(SensitiveMessage::as_str),
            _ => None,
        }
    }
}

/// Object metadata set at creation, and a precondition, for
/// [`GcsClient::upload_with`].
///
/// `UploadOptions::default()` sets nothing, and the upload is
/// [`GcsClient::upload`]'s media upload; any option set makes it a multipart
/// upload (see [the module docs](self#upload-options)).
///
/// ```
/// use std::time::{Duration, SystemTime};
/// use stridelabs_gcp::storage::UploadOptions;
///
/// let options = UploadOptions::default()
///     .with_custom_time(SystemTime::now() - Duration::from_secs(335 * 86_400))
///     .with_if_generation_match(0) // create only: never overwrite
///     .with_cache_control("private, max-age=86400");
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct UploadOptions {
    /// The object's `customTime` (its `Custom-Time`), sent as RFC 3339 UTC
    /// at whole seconds (`YYYY-MM-DDTHH:MM:SSZ`), the fraction truncated.
    /// Lifecycle rules can count from it (`daysSinceCustomTime`).
    pub custom_time: Option<SystemTime>,
    /// The `ifGenerationMatch` precondition: the upload happens only if the
    /// object's live generation is this one, and `0` means "only if there is
    /// no live object of that name" — create, never overwrite. A mismatch is
    /// GCS's 412, [`StorageError::Status`].
    pub if_generation_match: Option<i64>,
    /// The object's `cacheControl`, which GCS serves as the `Cache-Control`
    /// of every read of it. Without one, a publicly readable object is
    /// served `public, max-age=3600`: any cache, Google's edge included, may
    /// keep it an hour, deleted or not.
    pub cache_control: Option<String>,
}

impl UploadOptions {
    /// Set [`UploadOptions::custom_time`].
    #[must_use]
    pub fn with_custom_time(mut self, time: SystemTime) -> UploadOptions {
        self.custom_time = Some(time);
        self
    }

    /// Set [`UploadOptions::if_generation_match`].
    #[must_use]
    pub fn with_if_generation_match(mut self, generation: i64) -> UploadOptions {
        self.if_generation_match = Some(generation);
        self
    }

    /// Set [`UploadOptions::cache_control`].
    #[must_use]
    pub fn with_cache_control(mut self, cache_control: impl Into<String>) -> UploadOptions {
        self.cache_control = Some(cache_control.into());
        self
    }

    /// Nothing set: the upload is a media upload.
    fn is_empty(&self) -> bool {
        let UploadOptions {
            custom_time,
            if_generation_match,
            cache_control,
        } = self;
        custom_time.is_none() && if_generation_match.is_none() && cache_control.is_none()
    }
}

/// A GCS JSON-API client. Cheap to clone; hold one in application state.
#[derive(Clone)]
pub struct GcsClient {
    http: reqwest::Client,
    tokens: Option<TokenProvider>,
    base_url: String,
    timeout: Duration,
    max_download_bytes: usize,
    names: ObjectNamePolicy,
    retry: RetryPolicy,
}

impl fmt::Debug for GcsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcsClient")
            .field("base_url", &redact_url(&self.base_url))
            .field("tokens", &self.tokens)
            .field("timeout", &self.timeout)
            .field("max_download_bytes", &self.max_download_bytes)
            .field("object_name_policy", &self.names)
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

impl GcsClient {
    /// A client for the real JSON API at [`DEFAULT_BASE_URL`], authorizing
    /// every request with `tokens`.
    pub fn new(http: reqwest::Client, tokens: TokenProvider) -> GcsClient {
        GcsClient {
            http,
            tokens: Some(tokens),
            base_url: DEFAULT_BASE_URL.to_owned(),
            timeout: DEFAULT_TIMEOUT,
            max_download_bytes: DEFAULT_MAX_DOWNLOAD_BYTES,
            names: ObjectNamePolicy::Strict,
            retry: RetryPolicy::disabled(),
        }
    }

    /// A client for an emulator at `base_url`, authorizing with `tokens` if
    /// given and sending no `Authorization` header otherwise.
    ///
    /// `base_url` takes `STORAGE_EMULATOR_HOST`'s forms: `http://host:port`,
    /// or a bare `host:port`, which means `http://host:port`. A trailing `/`
    /// is dropped.
    pub fn emulator(
        http: reqwest::Client,
        base_url: &str,
        tokens: Option<TokenProvider>,
    ) -> GcsClient {
        GcsClient {
            http,
            tokens,
            base_url: normalize_base_url(base_url),
            timeout: DEFAULT_TIMEOUT,
            max_download_bytes: DEFAULT_MAX_DOWNLOAD_BYTES,
            names: ObjectNamePolicy::Strict,
            retry: RetryPolicy::disabled(),
        }
    }

    /// This client against another base URL, still authorizing as before —
    /// for a test that wants to see the token arrive. Normalized as in
    /// [`GcsClient::emulator`].
    #[must_use]
    pub fn with_base_url(mut self, base_url: &str) -> GcsClient {
        self.base_url = normalize_base_url(base_url);
        self
    }

    /// Replace the per-operation bound ([`DEFAULT_TIMEOUT`]): the token, the
    /// request and the body read share it. With a [`GcsClient::with_retry`]
    /// policy it bounds each attempt instead (see
    /// [the module docs](self#retry-opt-in)).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> GcsClient {
        self.timeout = timeout;
        self
    }

    /// Replace the download cap ([`DEFAULT_MAX_DOWNLOAD_BYTES`]).
    #[must_use]
    pub fn with_max_download_bytes(mut self, limit: usize) -> GcsClient {
        self.max_download_bytes = limit;
        self
    }

    /// Which object names this client sends (default
    /// [`ObjectNamePolicy::Strict`]): see [`ObjectNamePolicy`].
    #[must_use]
    pub fn with_object_name_policy(mut self, policy: ObjectNamePolicy) -> GcsClient {
        self.names = policy;
        self
    }

    /// The object-name policy ([`GcsClient::with_object_name_policy`]).
    pub fn object_name_policy(&self) -> ObjectNamePolicy {
        self.names
    }

    /// Retry each operation's transient failures under `policy` (default
    /// [`RetryPolicy::disabled`], one attempt): see
    /// [the module docs](self#retry-opt-in) for what is retried, what a
    /// retried write can return, and how the bounds compose.
    #[must_use]
    pub fn with_retry(mut self, policy: RetryPolicy) -> GcsClient {
        self.retry = policy;
        self
    }

    /// The retry policy ([`GcsClient::with_retry`]).
    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry
    }

    /// The base URL requests go to.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Write `bytes` to `object` in `bucket` with a media upload
    /// (`POST {base}/upload/storage/v1/b/{bucket}/o?uploadType=media&name={object}`),
    /// replacing any object of that name.
    ///
    /// # Errors
    ///
    /// An invalid name (nothing sent); any non-2xx answer is
    /// [`StorageError::Status`].
    pub async fn upload(
        &self,
        bucket: &str,
        object: &str,
        bytes: Bytes,
        content_type: &str,
    ) -> Result<(), StorageError> {
        const OP: &str = "upload";
        validate_bucket_name(bucket)?;
        self.names.check(object, Carried::Value)?;
        let url = format!(
            "{}/upload/storage/v1/b/{}/o?uploadType=media&name={}",
            self.base_url,
            encode_component(bucket),
            encode_component(object)
        );
        let build = || {
            self.http
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(bytes.clone())
        };
        self.succeeds(OP, build).await
    }

    /// Write `bytes` to `object` in `bucket` with `options`' metadata and
    /// precondition: with none set, exactly [`GcsClient::upload`]'s media
    /// upload; otherwise one multipart upload
    /// (`POST {base}/upload/storage/v1/b/{bucket}/o?uploadType=multipart[&ifGenerationMatch=N]`)
    /// whose metadata part names the object and its content type, and the
    /// options set (see [the module docs](self#upload-options)). Without an
    /// `ifGenerationMatch`, it replaces any object of that name.
    ///
    /// The timeout, the token, the emulator base URL, the retry and the
    /// errors are [`GcsClient::upload`]'s. The multipart body is built in
    /// memory, once: one copy of `bytes`, whatever the retries.
    ///
    /// # Errors
    ///
    /// With no options set, exactly [`GcsClient::upload`]'s. Otherwise an
    /// invalid name, or [`StorageError::InvalidArgument`] for a content type,
    /// cache control, custom time or generation it cannot send — in every
    /// case before a token is fetched or anything is sent (the content type
    /// is written into the multipart body by hand, so it is checked here
    /// rather than left to reqwest as `upload` leaves it). Any non-2xx answer
    /// is [`StorageError::Status`], a failed precondition (412) included;
    /// that is never retried.
    pub async fn upload_with(
        &self,
        bucket: &str,
        object: &str,
        bytes: Bytes,
        content_type: &str,
        options: &UploadOptions,
    ) -> Result<(), StorageError> {
        const OP: &str = "upload";
        // No options: `upload` itself, so every input it accepts (and every
        // one it refuses) behaves the same here.
        if options.is_empty() {
            return self.upload(bucket, object, bytes, content_type).await;
        }
        validate_bucket_name(bucket)?;
        self.names.check(object, Carried::Value)?;
        // Interpolated into the multipart body's part header by hand, so
        // checked here (reqwest only checks real request headers).
        check_header_value(
            content_type,
            "the content type must be a header value: visible ASCII, \
             spaces and tabs only inside it",
        )?;
        let metadata = metadata_json(object, content_type, options)?;
        if options
            .if_generation_match
            .is_some_and(|generation| generation < 0)
        {
            return Err(StorageError::InvalidArgument {
                reason: "ifGenerationMatch must not be negative",
            });
        }

        // Built once, boundary and all: every attempt of this upload carries
        // these bytes.
        let (boundary, body) = multipart_body(&metadata, content_type, &bytes, random_boundary);
        let body = Bytes::from(body);
        let multipart_type = format!("multipart/related; boundary={boundary}");
        let mut url = format!(
            "{}/upload/storage/v1/b/{}/o?uploadType=multipart",
            self.base_url,
            encode_component(bucket)
        );
        if let Some(generation) = options.if_generation_match {
            // An i64 in decimal: nothing to encode.
            let _ = write!(url, "&ifGenerationMatch={generation}");
        }
        let build = || {
            self.http
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, &multipart_type)
                .body(body.clone())
        };
        self.succeeds(OP, build).await
    }

    /// Read `object` from `bucket`
    /// (`GET {base}/storage/v1/b/{bucket}/o/{object}?alt=media`): its bytes
    /// and the response's `Content-Type`, or `None` on a 404.
    ///
    /// # Errors
    ///
    /// An invalid name (nothing sent); [`StorageError::TooLarge`] past the
    /// download cap; any other non-2xx answer is [`StorageError::Status`].
    pub async fn download(
        &self,
        bucket: &str,
        object: &str,
    ) -> Result<Option<(Bytes, Option<String>)>, StorageError> {
        const OP: &str = "download";
        validate_bucket_name(bucket)?;
        self.names.check(object, Carried::Segment)?;
        let url = format!(
            "{}/storage/v1/b/{}/o/{}?alt=media",
            self.base_url,
            encode_component(bucket),
            encode_component(object)
        );
        let build = || self.http.get(&url);
        let build = &build;
        self.attempts(OP, move |received| async move {
            let response = self.send(OP, build).await?;
            let status = response.status();
            if status == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !status.is_success() {
                return Err(status_failure(OP, response, &received).await);
            }
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            // A body that stops after the headers is an interrupted
            // transfer, whatever reqwest calls it (a `decode error` for a
            // cut connection): transient.
            let body = read_limited(response, self.max_download_bytes)
                .await
                .map_err(|error| {
                    Failed::transient(StorageError::Request {
                        operation: OP,
                        reason: describe_reqwest(error),
                    })
                })?;
            if body.truncated {
                return Err(Failed::permanent(StorageError::TooLarge {
                    operation: OP,
                    limit: self.max_download_bytes,
                }));
            }
            Ok(Some((Bytes::from(body.bytes), content_type)))
        })
        .await
    }

    /// Delete `object` from `bucket` (`DELETE {base}/storage/v1/b/{bucket}/o/{object}`):
    /// `true` when it was deleted, `false` when GCS answered 404 (there was
    /// nothing to delete). Callers that only want the object gone can treat
    /// both as success.
    ///
    /// # Errors
    ///
    /// An invalid name (nothing sent); any other non-2xx answer is
    /// [`StorageError::Status`].
    pub async fn delete(&self, bucket: &str, object: &str) -> Result<bool, StorageError> {
        const OP: &str = "delete";
        validate_bucket_name(bucket)?;
        self.names.check(object, Carried::Segment)?;
        let url = format!(
            "{}/storage/v1/b/{}/o/{}",
            self.base_url,
            encode_component(bucket),
            encode_component(object)
        );
        let build = || self.http.delete(&url);
        let build = &build;
        self.attempts(OP, move |received| async move {
            let response = self.send(OP, build).await?;
            let status = response.status();
            if status == StatusCode::NOT_FOUND {
                return Ok(false);
            }
            if !status.is_success() {
                return Err(status_failure(OP, response, &received).await);
            }
            Ok(true)
        })
        .await
    }

    /// Whether `bucket` answers a one-object listing
    /// (`GET {base}/storage/v1/b/{bucket}/o?maxResults=1`): `Ok(())` on any
    /// 2xx. A startup probe, through the same timeout and retry as every
    /// operation.
    ///
    /// Point-in-time evidence only: the bucket can be deleted, or the
    /// permission revoked, a moment later. The identity needs
    /// `storage.objects.list` on the bucket. A `403` says nothing about
    /// whether the bucket exists: Google documents that it can answer for a
    /// resource that does not (the JSON API's status codes, `forbidden` and
    /// `insufficientPermissions`).
    ///
    /// # Errors
    ///
    /// [`StorageError::InvalidBucketName`] (nothing sent); any non-2xx
    /// answer, a `404` included, is [`StorageError::Status`] with operation
    /// `list`.
    pub async fn bucket_reachable(&self, bucket: &str) -> Result<(), StorageError> {
        const OP: &str = "list";
        validate_bucket_name(bucket)?;
        let url = format!(
            "{}/storage/v1/b/{}/o?maxResults=1",
            self.base_url,
            encode_component(bucket)
        );
        self.succeeds(OP, || self.http.get(&url)).await
    }

    /// An operation whose one good answer is a 2xx: `build`'s request under
    /// [`GcsClient::attempts`], any other status its error.
    async fn succeeds(
        &self,
        operation: &'static str,
        build: impl Fn() -> reqwest::RequestBuilder,
    ) -> Result<(), StorageError> {
        let build = &build;
        self.attempts(operation, move |received| async move {
            let response = self.send(operation, build).await?;
            if !response.status().is_success() {
                return Err(status_failure(operation, response, &received).await);
            }
            Ok(())
        })
        .await
    }

    /// `operation`'s attempts under the client's retry policy (one, without
    /// one), each under the client's timeout, each with the status line it
    /// received of its own (0 until a non-2xx one is in).
    async fn attempts<T, F>(
        &self,
        operation: &'static str,
        mut attempt: impl FnMut(Arc<AtomicU16>) -> F,
    ) -> Result<T, StorageError>
    where
        F: Future<Output = Result<T, Failed<StorageError>>>,
    {
        retry::run(self.retry, operation, retry::uniform, || {
            let status = Arc::new(AtomicU16::new(0));
            let work = attempt(Arc::clone(&status));
            self.bounded(operation, status, work)
        })
        .await
    }

    /// One attempt under the client's timeout. A timeout is `Timeout`, as in
    /// v0.8.0, and transient unless the attempt had already received an
    /// error status that is not: a `412` whose error body stalls past the
    /// timeout stays a `412` for the retry, whatever error reports it.
    async fn bounded<T>(
        &self,
        operation: &'static str,
        status: Arc<AtomicU16>,
        work: impl Future<Output = Result<T, Failed<StorageError>>>,
    ) -> Result<T, Failed<StorageError>> {
        match tokio::time::timeout(self.timeout, work).await {
            Ok(result) => result,
            Err(_) => {
                let received = status.load(Ordering::Acquire);
                Err(Failed {
                    error: StorageError::Timeout {
                        operation,
                        timeout: self.timeout,
                    },
                    transient: received == 0 || is_transient_status(received),
                })
            }
        }
    }

    /// Send the request `build` makes, authorized when there is a token
    /// provider: one attempt's request, with a token taken for it.
    async fn send(
        &self,
        operation: &'static str,
        build: impl Fn() -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, Failed<StorageError>> {
        let request = match &self.tokens {
            Some(tokens) => {
                let token = tokens.classified_token().await.map_err(|failed| {
                    failed.map(|source| StorageError::Auth { operation, source })
                })?;
                token.authorize(build())
            }
            None => build(),
        };
        request.send().await.map_err(|error| {
            let category = Category::of(&error);
            Failed::before_response(
                category,
                StorageError::Request {
                    operation,
                    reason: category.label().to_owned(),
                },
            )
        })
    }
}

/// A non-2xx answer as its error, transient for the retry's statuses (408,
/// 429, 500, 502, 503, 504) and for nothing else. The status is recorded in
/// `received` before the body is read, so a body that stalls past the
/// attempt's timeout leaves the attempt classified by it.
async fn status_failure(
    operation: &'static str,
    response: reqwest::Response,
    received: &AtomicU16,
) -> Failed<StorageError> {
    let status = response.status().as_u16();
    received.store(status, Ordering::Release);
    let error = google_error(&read_error_body(response).await);
    Failed::status(
        status,
        StorageError::Status {
            operation,
            status,
            google_status: error.status,
            message: error.message,
        },
    )
}

/// An object name that stays one path when its public URL is normalized.
fn check_object(object: &str) -> Result<(), StorageError> {
    let invalid = |reason| Err(StorageError::InvalidObjectName { reason });
    if object.is_empty() {
        return invalid("it is empty");
    }
    if object.starts_with('/') || object.ends_with('/') {
        return invalid("it starts or ends with '/'");
    }
    if object
        .split('/')
        .any(|segment| matches!(segment, "" | "." | ".."))
    {
        return invalid("it has an empty, '.' or '..' segment");
    }
    Ok(())
}

/// Whether `value` can go into a header line as it is: non-empty, visible
/// ASCII with spaces and tabs only inside it (nothing a parser would trim),
/// and above all no CR or LF, which would end the line and start another.
fn is_header_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    let plain = |byte: &u8| *byte == b'\t' || (0x20..=0x7e).contains(byte);
    let blank = |byte: Option<&u8>| matches!(byte, Some(b' ' | b'\t'));
    !bytes.is_empty() && bytes.iter().all(plain) && !blank(bytes.first()) && !blank(bytes.last())
}

fn check_header_value(value: &str, reason: &'static str) -> Result<(), StorageError> {
    if is_header_value(value) {
        Ok(())
    } else {
        Err(StorageError::InvalidArgument { reason })
    }
}

/// The metadata part of a multipart upload, as GCS's object resource names
/// its fields. A struct, not a `serde_json::Value`: its fields serialize in
/// this order whatever features (`preserve_order`) the graph turns on.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectMetadata<'a> {
    name: &'a str,
    content_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<&'a str>,
}

/// `object`'s metadata part, with `options`' fields checked first.
fn metadata_json(
    object: &str,
    content_type: &str,
    options: &UploadOptions,
) -> Result<Vec<u8>, StorageError> {
    let cache_control = options.cache_control.as_deref();
    if let Some(cache_control) = cache_control {
        check_header_value(
            cache_control,
            "the cache control must be a header value: visible ASCII, \
             spaces and tabs only inside it",
        )?;
    }
    let custom_time = options.custom_time.map(rfc3339).transpose()?;
    serde_json::to_vec(&ObjectMetadata {
        name: object,
        content_type,
        custom_time,
        cache_control,
    })
    // Strings and nothing else: serializing cannot fail.
    .map_err(|_| StorageError::InvalidArgument {
        reason: "the object metadata could not be serialized",
    })
}

/// The latest instant RFC 3339's four-digit year can write,
/// 9999-12-31T23:59:59Z, in Unix seconds.
const MAX_RFC3339_SECS: u64 = 253_402_300_799;

/// `time` in RFC 3339, UTC, at whole seconds (`YYYY-MM-DDTHH:MM:SSZ`), the
/// fraction truncated. Plain arithmetic rather than a date crate: this is
/// the one date the crate writes.
fn rfc3339(time: SystemTime) -> Result<String, StorageError> {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageError::InvalidArgument {
            reason: "the custom time must not be before 1970-01-01T00:00:00Z",
        })?
        .as_secs();
    if secs > MAX_RFC3339_SECS {
        return Err(StorageError::InvalidArgument {
            reason: "the custom time must be before the year 10000",
        });
    }
    let (days, seconds) = (secs / 86_400, secs % 86_400);
    let (year, month, day) = civil_from_days(days);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    ))
}

/// The proleptic Gregorian `(year, month, day)` of `days` after 1970-01-01:
/// Howard Hinnant's `civil_from_days`, for days on or after the epoch (so
/// every intermediate is unsigned). Eras are 400-year cycles of 146 097
/// days, counted from 0000-03-01 so that a leap day ends its year.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468; // days since 0000-03-01
    let era = z / 146_097;
    let day_of_era = z - era * 146_097; // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365; // [0, 399]
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100); // [0, 365]
    let month_index = (5 * day_of_year + 2) / 153; // [0, 11], from March
    let day = day_of_year - (153 * month_index + 2) / 5 + 1; // [1, 31]
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    }; // [1, 12]
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// What every boundary starts with: a fixed, recognisable token prefix.
const BOUNDARY_PREFIX: &str = "stridelabs-gcp-";

/// A candidate boundary: the prefix and 128 random bits in hex. Token
/// characters only, so the `boundary=` parameter needs no quoting, and well
/// within RFC 2046's 70.
fn random_boundary() -> String {
    format!("{BOUNDARY_PREFIX}{:032x}", rand::random::<u128>())
}

/// The `multipart/related` body for a metadata part (`metadata`, JSON) and
/// a media part (`media`, of `content_type`), and the boundary it uses: the
/// first candidate from `boundaries` that appears in neither part, headers
/// included. A candidate that does is discarded and the body built again —
/// rare enough (2^-128 per byte offset for a random one) that rebuilding
/// beats searching the media up front.
fn multipart_body(
    metadata: &[u8],
    content_type: &str,
    media: &[u8],
    mut boundaries: impl FnMut() -> String,
) -> (String, Vec<u8>) {
    const METADATA_HEADER: &[u8] = b"Content-Type: application/json; charset=UTF-8\r\n\r\n";
    loop {
        let boundary = boundaries();
        let delimiter = boundary.as_bytes();
        let mut body = Vec::with_capacity(
            metadata.len() + content_type.len() + media.len() + 3 * delimiter.len() + 96,
        );
        body.extend_from_slice(b"--");
        body.extend_from_slice(delimiter);
        body.extend_from_slice(b"\r\n");
        let first = body.len();
        body.extend_from_slice(METADATA_HEADER);
        body.extend_from_slice(metadata);
        let first_end = body.len();
        body.extend_from_slice(b"\r\n--");
        body.extend_from_slice(delimiter);
        body.extend_from_slice(b"\r\n");
        let second = body.len();
        body.extend_from_slice(b"Content-Type: ");
        body.extend_from_slice(content_type.as_bytes());
        body.extend_from_slice(b"\r\n\r\n");
        body.extend_from_slice(media);
        let second_end = body.len();
        body.extend_from_slice(b"\r\n--");
        body.extend_from_slice(delimiter);
        body.extend_from_slice(b"--");

        let finder = memchr::memmem::Finder::new(delimiter);
        if !delimiter.is_empty()
            && finder.find(&body[first..first_end]).is_none()
            && finder.find(&body[second..second_end]).is_none()
        {
            return (boundary, body);
        }
    }
}

fn normalize_base_url(base_url: &str) -> String {
    let base_url = base_url.trim().trim_end_matches('/');
    if base_url.contains("://") {
        base_url.to_owned()
    } else {
        format!("http://{base_url}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_urls_keep_slashes_and_encode_the_rest() {
        assert_eq!(
            public_url("imgmcp.stridelabs.ai", "0b0e/20261017-120000-ab12cd34.png").unwrap(),
            "https://storage.googleapis.com/imgmcp.stridelabs.ai/0b0e/20261017-120000-ab12cd34.png"
        );
        assert_eq!(
            public_url("img-bucket", "a/b c.png").unwrap(),
            "https://storage.googleapis.com/img-bucket/a/b%20c.png"
        );
        assert_eq!(
            public_url("img-bucket", "x?y#z").unwrap(),
            "https://storage.googleapis.com/img-bucket/x%3Fy%23z"
        );
        // Dots inside a segment are fine; so is a literal `%2e%2e`, which is
        // encoded as `%252e%252e` and never decodes to `..`.
        assert_eq!(
            public_url("img-bucket", "a/.hidden/b..c/%2e%2e").unwrap(),
            "https://storage.googleapis.com/img-bucket/a/.hidden/b..c/%252e%252e"
        );
    }

    #[test]
    fn object_names_that_change_under_normalization_are_refused() {
        for object in [
            "u/../victim.png",
            "./a",
            "a//b",
            "/a",
            "a/",
            "..",
            ".",
            "",
            "a/./b",
            "a/..",
        ] {
            assert!(
                matches!(
                    public_url("img-bucket", object),
                    Err(StorageError::InvalidObjectName { .. })
                ),
                "{object:?}"
            );
            assert!(check_object(object).is_err(), "{object:?}");
        }
    }

    #[test]
    fn bucket_names_follow_gcs_rules() {
        for bucket in ["img-bucket", "imgmcp.stridelabs.ai", "a_b", "123"] {
            assert!(validate_bucket_name(bucket).is_ok(), "{bucket}");
        }
        for bucket in [
            "", "ab", "..", "a..b", ".abc", "abc.", "-abc", "Upper", "a/b", "a b", "a%2Fb",
        ] {
            assert!(
                matches!(
                    public_url(bucket, "o"),
                    Err(StorageError::InvalidBucketName { .. })
                ),
                "{bucket:?}"
            );
        }
    }

    #[test]
    fn custom_times_are_rfc_3339_utc_at_whole_seconds() {
        let at = |secs: u64| rfc3339(UNIX_EPOCH + Duration::from_secs(secs)).unwrap();
        for (secs, expected) in [
            (0, "1970-01-01T00:00:00Z"),
            (68_256_000, "1972-03-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_731_196_799, "2024-11-09T23:59:59Z"),
            (1_760_000_000, "2025-10-09T08:53:20Z"),
            (4_102_444_800, "2100-01-01T00:00:00Z"),
            (MAX_RFC3339_SECS, "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(at(secs), expected, "{secs}");
        }
        // Truncated, never rounded up into the next second.
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_millis(1_760_000_000_999)).unwrap(),
            "2025-10-09T08:53:20Z"
        );
    }

    #[test]
    fn a_custom_time_rfc_3339_cannot_write_is_refused() {
        for time in [
            UNIX_EPOCH - Duration::from_secs(1),
            UNIX_EPOCH - Duration::from_nanos(1),
            UNIX_EPOCH + Duration::from_secs(MAX_RFC3339_SECS + 1),
        ] {
            assert!(
                matches!(rfc3339(time), Err(StorageError::InvalidArgument { .. })),
                "{time:?}"
            );
        }
    }

    /// The hand-written formatter against `time`'s, across the whole
    /// representable range: every day boundary in four centuries around the
    /// epoch's leap-year rules, and a spread of instants up to 9999.
    #[test]
    fn the_formatter_agrees_with_the_time_crate_everywhere() {
        use time::format_description::well_known::Rfc3339;

        let reference = |secs: u64| {
            time::OffsetDateTime::from_unix_timestamp(i64::try_from(secs).unwrap())
                .unwrap()
                .format(&Rfc3339)
                .unwrap()
        };
        let mine = |secs: u64| rfc3339(UNIX_EPOCH + Duration::from_secs(secs)).unwrap();
        // 1970 to 2370 day by day, at midnight and at the day's last second.
        for day in 0..146_097 {
            for secs in [day * 86_400, day * 86_400 + 86_399] {
                assert_eq!(mine(secs), reference(secs), "{secs}");
            }
        }
        // Up to 9999, at a stride coprime to the day length.
        let mut secs = 0;
        while secs <= MAX_RFC3339_SECS {
            assert_eq!(mine(secs), reference(secs), "{secs}");
            secs += 1_000_003_717;
        }
        assert_eq!(mine(MAX_RFC3339_SECS), reference(MAX_RFC3339_SECS));
    }

    #[test]
    fn header_values_are_plain_visible_ascii() {
        for value in [
            "image/png",
            "text/plain; charset=utf-8",
            "private, max-age=86400",
            "a\tb",
            "x",
        ] {
            assert!(is_header_value(value), "{value:?}");
        }
        for value in [
            "",
            "image/png\r\nX-Injected: 1",
            "image/png\n",
            "a\rb",
            " image/png",
            "image/png ",
            "\timage/png",
            "image/\u{e9}",
            "nul\0",
            "del\u{7f}",
        ] {
            assert!(!is_header_value(value), "{value:?}");
        }
    }

    #[test]
    fn the_multipart_body_is_crlf_framed_metadata_first() {
        let (boundary, body) = multipart_body(br#"{"name":"o"}"#, "image/png", b"\x89PNG", || {
            "B0".to_owned()
        });

        assert_eq!(boundary, "B0");
        assert_eq!(
            body,
            b"--B0\r\n\
              Content-Type: application/json; charset=UTF-8\r\n\
              \r\n\
              {\"name\":\"o\"}\r\n\
              --B0\r\n\
              Content-Type: image/png\r\n\
              \r\n\
              \x89PNG\r\n\
              --B0--"
        );
    }

    /// The boundary seam, scripted: every candidate that appears in the
    /// media, in the metadata, or in a part's header is passed over, and the
    /// first clean one is used. The negative control takes its first.
    #[test]
    fn a_boundary_found_in_either_part_is_drawn_again() {
        // The candidates drawn, and the boundary and body chosen.
        let script = |candidates: &[&str]| {
            let drawn = std::cell::Cell::new(0);
            let (boundary, body) = multipart_body(
                br#"{"name":"has-zzMETAzz-in-it"}"#,
                "image/zzheadzz",
                b"bytes with zzMEDIAzz inside",
                || {
                    let candidate = candidates[drawn.get()].to_owned();
                    drawn.set(drawn.get() + 1);
                    candidate
                },
            );
            (drawn.get(), boundary, body)
        };

        // In the media, in the metadata, in the media part's header: each
        // passed over, and the first clean candidate used.
        let (drawn, boundary, body) = script(&["zzMEDIAzz", "zzMETAzz", "zzheadzz", "fresh"]);
        assert_eq!((drawn, boundary.as_str()), (4, "fresh"));
        assert!(body.starts_with(b"--fresh\r\n"));
        assert!(body.ends_with(b"\r\n--fresh--"));
        assert_eq!(
            memchr::memmem::find_iter(&body, b"fresh").count(),
            3,
            "two delimiters and the close, nothing more"
        );
        assert_eq!(memchr::memmem::find_iter(&body, b"zzMEDIAzz").count(), 1);

        // The negative control: a clean first candidate is the only one drawn.
        let (drawn, boundary, _) = script(&["fresh", "never drawn"]);
        assert_eq!((drawn, boundary.as_str()), (1, "fresh"));
    }

    #[test]
    fn random_boundaries_are_token_characters_and_differ() {
        let (one, two) = (random_boundary(), random_boundary());
        for boundary in [&one, &two] {
            let random = boundary.strip_prefix(BOUNDARY_PREFIX).expect("the prefix");
            assert_eq!(random.len(), 32, "{boundary}");
            assert!(random
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
            assert!(boundary.len() <= 70, "RFC 2046's bound");
        }
        assert_ne!(one, two);
    }

    #[test]
    fn metadata_is_json_in_a_fixed_field_order() {
        let options = UploadOptions::default()
            .with_cache_control("private, max-age=86400")
            .with_custom_time(UNIX_EPOCH + Duration::from_secs(1_760_000_000))
            .with_if_generation_match(0);
        assert_eq!(
            String::from_utf8(metadata_json("a/\"b\"\\c/é.png", "image/png", &options).unwrap())
                .unwrap(),
            r#"{"name":"a/\"b\"\\c/é.png","contentType":"image/png","customTime":"2025-10-09T08:53:20Z","cacheControl":"private, max-age=86400"}"#
        );
        assert_eq!(
            metadata_json("o", "image/png", &UploadOptions::default()).unwrap(),
            br#"{"name":"o","contentType":"image/png"}"#
        );
        assert!(UploadOptions::default().is_empty());
        assert!(!UploadOptions::default()
            .with_if_generation_match(0)
            .is_empty());
    }

    #[test]
    fn emulator_hosts_take_both_forms() {
        assert_eq!(
            normalize_base_url("localhost:4443"),
            "http://localhost:4443"
        );
        assert_eq!(
            normalize_base_url("http://localhost:4443/"),
            "http://localhost:4443"
        );
        assert_eq!(normalize_base_url("https://gcs.test"), "https://gcs.test");
    }
}
