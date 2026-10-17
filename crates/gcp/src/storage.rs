//! A small Google Cloud Storage client over the JSON API: media upload,
//! media download, delete, and the public object URL.
//!
//! Policy-free: no object naming, no bucket from the environment, no retry.
//! The service decides those.
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
use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use reqwest::StatusCode;

use crate::auth::{GcpAuthError, TokenProvider};
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
        /// The transport's reason, rendered without the URL.
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

/// A GCS JSON-API client. Cheap to clone; hold one in application state.
#[derive(Clone)]
pub struct GcsClient {
    http: reqwest::Client,
    tokens: Option<TokenProvider>,
    base_url: String,
    timeout: Duration,
    max_download_bytes: usize,
}

impl fmt::Debug for GcsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcsClient")
            .field("base_url", &redact_url(&self.base_url))
            .field("tokens", &self.tokens)
            .field("timeout", &self.timeout)
            .field("max_download_bytes", &self.max_download_bytes)
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
        let request = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(bytes);
        self.bounded(OP, async {
            let response = self.send(OP, request).await?;
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
        let request = self.http.get(url);
        self.bounded(OP, async {
            let response = self.send(OP, request).await?;
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
        let request = self.http.delete(url);
        self.bounded(OP, async {
            let response = self.send(OP, request).await?;
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

    async fn send(
        &self,
        operation: &'static str,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, StorageError> {
        let request = match &self.tokens {
            Some(tokens) => tokens
                .token()
                .await
                .map_err(|source| StorageError::Auth { operation, source })?
                .authorize(request),
            None => request,
        };
        request.send().await.map_err(|error| StorageError::Request {
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
