//! A small Google Cloud Storage client over the JSON API: media upload,
//! multipart upload with object metadata, media download, delete, and the
//! public object URL.
//!
//! Policy-free: no object naming, no bucket from the environment, no retry,
//! no metadata of its own choosing. The service decides those. The one
//! replay there is, a `401` refreshed and replayed, is off unless the
//! service turns it on ([below](self#401-refresh-and-replay-opt-in)).
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
//! URL, and refuses with no request sent:
//!
//! - **Buckets** follow GCS's naming rules: 3–222 characters of `a-z`, `0-9`,
//!   `-`, `_` and `.`, starting and ending with a letter or digit, and no
//!   `..`. ([`StorageError::InvalidBucketName`])
//! - **Objects** are non-empty, neither start nor end with `/`, and have no
//!   empty, `.` or `..` segment between slashes (`u/../victim.png`, `./a`,
//!   `a//b`). Such a name is legal to GCS but becomes a *different* path the
//!   moment a client normalizes the public URL.
//!   ([`StorageError::InvalidObjectName`])
//!
//! On the wire the bucket and the object name are percent-encoded as **one**
//! path segment or query value: everything but RFC 3986's unreserved
//! characters is encoded, `/` included (`a/b c.png` → `a%2Fb%20c.png`). That
//! is what the JSON API requires — a raw `/` makes `/o/a/b.png` a different
//! resource — and what google-cloud-storage's `_quote` and tapper's and
//! parcel's clients send.
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
//! — the layout google-resumable-media's `construct_multipart_request` (the
//! Python client's) sends. The metadata is serialized with serde_json (the
//! object name is a JSON string there, not a query value), and the bytes go
//! in unchanged. The boundary is `stridelabs-gcp-` plus 128 random bits in
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
//! like any non-2xx answer: nothing retries it or falls back to an upload
//! that could overwrite.
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
//! # 401 refresh and replay (opt-in)
//!
//! [`GcsClient::with_unauthorized_refresh`]`(true)` makes a `401` what
//! google-cloud-storage's `AuthorizedSession` makes it: the bearer is evicted
//! with [`TokenProvider::invalidate`], a token is taken again, and the
//! request is sent again, up to [`GcsClient::with_max_refresh_attempts`]
//! times (default 2). A persistent `401` costs three requests and two refreshes at the
//! default, and is then [`StorageError::Status`]. Off, a `401` is one request
//! and that error, as it always was.
//!
//! - **Only a completed `401`.** Never a `403`, a `5xx` or a transport
//!   failure: a `401` means the request was not applied (RFC 9110 section
//!   15.5.2), so replaying an upload, a delete or a create-only
//!   `ifGenerationMatch=0` upload cannot apply it twice. That reasoning does
//!   not reach a failure whose outcome is unknown.
//! - **The same request.** The URL, the headers and the body are rebuilt
//!   from what the first send used; a multipart body is built once, its
//!   boundary with it.
//! - **Inside the operation's bound.** The `401`'s body is read (at most 16
//!   KiB, and at most 2 s, after which it is dropped with its connection),
//!   then the refresh and the replay all count against the client's timeout.
//! - **The same bearer may come back.** On the metadata server a refresh
//!   re-serves the cached bearer for most of its life, so each replay can be
//!   one more metadata call and one more GCS request with the same
//!   credentials. Concurrent operations rejected on one bearer share one
//!   eviction and one refresh when the refresh mints a different bearer.
//! - With [`GcsClient::emulator`] and no provider there is no token to
//!   refresh: a no-op.
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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use reqwest::StatusCode;
use serde::Serialize;

use crate::auth::{GcpAuthError, TokenProvider};
use crate::replay::{send_with_refresh, UnauthorizedRefresh};
use crate::util::{
    describe_reqwest, encode_component, encode_path, google_error, read_error_body, read_limited,
    redact_url, status_suffix, SensitiveMessage,
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
/// # Errors
///
/// [`StorageError::InvalidBucketName`] or [`StorageError::InvalidObjectName`]
/// (see [the module docs](self#names)).
pub fn public_url(bucket: &str, object: &str) -> Result<String, StorageError> {
    check_bucket(bucket)?;
    check_object(object)?;
    Ok(format!(
        "{DEFAULT_BASE_URL}/{bucket}/{}",
        encode_path(object)
    ))
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
    /// The object name is empty, starts or ends with `/`, or has an empty,
    /// `.` or `..` segment. Nothing was sent.
    #[error("invalid GCS object name: {reason}")]
    InvalidObjectName {
        /// Which rule; never the name.
        reason: &'static str,
    },
    /// No access token.
    #[error("GCS {operation}: {source}")]
    Auth {
        /// `upload`, `download` or `delete`.
        operation: &'static str,
        /// The token provider's error.
        source: GcpAuthError,
    },
    /// The request did not complete: a connection failure or an unreadable
    /// body.
    #[error("GCS {operation} request failed: {reason}")]
    Request {
        /// `upload`, `download` or `delete`.
        operation: &'static str,
        /// The transport failure's fixed category (`timed out`,
        /// `connection failed`, …), never its text.
        reason: String,
    },
    /// The operation outlived the client's timeout.
    #[error("GCS {operation} timed out after {timeout:?}")]
    Timeout {
        /// `upload`, `download` or `delete`.
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
        /// `upload`, `download` or `delete`.
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
    refresh: UnauthorizedRefresh,
}

impl fmt::Debug for GcsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcsClient")
            .field("base_url", &redact_url(&self.base_url))
            .field("tokens", &self.tokens)
            .field("timeout", &self.timeout)
            .field("max_download_bytes", &self.max_download_bytes)
            .field("unauthorized_refresh", &self.refresh.enabled)
            .field("max_refresh_attempts", &self.refresh.max_attempts)
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
            refresh: UnauthorizedRefresh::default(),
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
            refresh: UnauthorizedRefresh::default(),
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
    /// request and the body read share it.
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

    /// Refresh the token and replay the request when GCS answers `401`
    /// (default `false`): see
    /// [the module docs](self#401-refresh-and-replay-opt-in). With it on,
    /// each operation replays a `401` up to
    /// [`GcsClient::max_refresh_attempts`] times, each time after
    /// [`TokenProvider::invalidate`], with a token from
    /// [`TokenProvider::token`]. A no-op on an emulator client built with no
    /// [`TokenProvider`].
    #[must_use]
    pub fn with_unauthorized_refresh(mut self, enabled: bool) -> GcsClient {
        self.refresh.enabled = enabled;
        self
    }

    /// How many refresh-and-replay cycles one operation may make after a
    /// `401` (default 2, google-auth's `DEFAULT_MAX_REFRESH_ATTEMPTS`): a
    /// persistent `401` costs `attempts + 1` requests and `attempts`
    /// refreshes, and `0` replays nothing. The operation's timeout bounds
    /// them all. Effective only with
    /// [`GcsClient::with_unauthorized_refresh`]`(true)`; the count alone
    /// never turns it on.
    #[must_use]
    pub fn with_max_refresh_attempts(mut self, attempts: u32) -> GcsClient {
        self.refresh.max_attempts = attempts;
        self
    }

    /// Whether a `401` is refreshed and replayed
    /// ([`GcsClient::with_unauthorized_refresh`]).
    pub fn unauthorized_refresh(&self) -> bool {
        self.refresh.enabled
    }

    /// The configured refresh-and-replay count
    /// ([`GcsClient::with_max_refresh_attempts`]), whether or not
    /// [`GcsClient::unauthorized_refresh`] is on.
    pub fn max_refresh_attempts(&self) -> u32 {
        self.refresh.max_attempts
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
        check_bucket(bucket)?;
        check_object(object)?;
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
        self.bounded(OP, async {
            let response = self.send(OP, build).await?;
            if !response.status().is_success() {
                return Err(status_error(OP, response).await);
            }
            Ok(())
        })
        .await
    }

    /// Write `bytes` to `object` in `bucket` with `options`' metadata and
    /// precondition: with none set, exactly [`GcsClient::upload`]'s media
    /// upload; otherwise one multipart upload
    /// (`POST {base}/upload/storage/v1/b/{bucket}/o?uploadType=multipart[&ifGenerationMatch=N]`)
    /// whose metadata part names the object and its content type, and the
    /// options set (see [the module docs](self#upload-options)). Without an
    /// `ifGenerationMatch`, it replaces any object of that name.
    ///
    /// The timeout, the token, the emulator base URL and the errors are
    /// [`GcsClient::upload`]'s. The multipart body is built in memory: one
    /// copy of `bytes`.
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
    /// nothing is retried.
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
        check_bucket(bucket)?;
        check_object(object)?;
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

        // Built once, boundary and all: every send of this upload (a 401's
        // replay included) carries these bytes.
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
        self.bounded(OP, async {
            let response = self.send(OP, build).await?;
            if !response.status().is_success() {
                return Err(status_error(OP, response).await);
            }
            Ok(())
        })
        .await
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
        check_bucket(bucket)?;
        check_object(object)?;
        let url = format!(
            "{}/storage/v1/b/{}/o/{}?alt=media",
            self.base_url,
            encode_component(bucket),
            encode_component(object)
        );
        let build = || self.http.get(&url);
        self.bounded(OP, async {
            let response = self.send(OP, build).await?;
            let status = response.status();
            if status == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !status.is_success() {
                return Err(status_error(OP, response).await);
            }
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            let body = read_limited(response, self.max_download_bytes)
                .await
                .map_err(|error| StorageError::Request {
                    operation: OP,
                    reason: describe_reqwest(error),
                })?;
            if body.truncated {
                return Err(StorageError::TooLarge {
                    operation: OP,
                    limit: self.max_download_bytes,
                });
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
        check_bucket(bucket)?;
        check_object(object)?;
        let url = format!(
            "{}/storage/v1/b/{}/o/{}",
            self.base_url,
            encode_component(bucket),
            encode_component(object)
        );
        let build = || self.http.delete(&url);
        self.bounded(OP, async {
            let response = self.send(OP, build).await?;
            let status = response.status();
            if status == StatusCode::NOT_FOUND {
                return Ok(false);
            }
            if !status.is_success() {
                return Err(status_error(OP, response).await);
            }
            Ok(true)
        })
        .await
    }

    /// `operation` under the client's timeout.
    async fn bounded<T>(
        &self,
        operation: &'static str,
        work: impl Future<Output = Result<T, StorageError>>,
    ) -> Result<T, StorageError> {
        tokio::time::timeout(self.timeout, work)
            .await
            .unwrap_or(Err(StorageError::Timeout {
                operation,
                timeout: self.timeout,
            }))
    }

    /// Send the request `build` makes (once per send, with the opt-in `401`
    /// refresh), authorized when there is a token provider.
    async fn send(
        &self,
        operation: &'static str,
        build: impl Fn() -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, StorageError> {
        let sent = match &self.tokens {
            Some(tokens) => {
                let auth = |source| StorageError::Auth { operation, source };
                let first = tokens.token().await.map_err(auth)?;
                send_with_refresh(tokens, first, self.refresh, operation, |token| {
                    token.authorize(build())
                })
                .await
                .map_err(auth)?
            }
            None => build().send().await,
        };
        sent.map_err(|error| StorageError::Request {
            operation,
            reason: describe_reqwest(error),
        })
    }
}

async fn status_error(operation: &'static str, response: reqwest::Response) -> StorageError {
    let status = response.status().as_u16();
    let error = google_error(&read_error_body(response).await);
    StorageError::Status {
        operation,
        status,
        google_status: error.status,
        message: error.message,
    }
}

/// GCS's bucket naming rules, minus the ones only GCS itself can judge
/// (reserved words, IP-address shapes, per-label lengths).
fn check_bucket(bucket: &str) -> Result<(), StorageError> {
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
            assert!(check_bucket(bucket).is_ok(), "{bucket}");
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
