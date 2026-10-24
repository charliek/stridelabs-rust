//! Policy-free Google Cloud building blocks for StrideLabs services.
//!
//! - [`auth`]: a [`TokenProvider`] over an enumerated subset of Application
//!   Default Credentials (an explicit base64 key, `GOOGLE_APPLICATION_CREDENTIALS`,
//!   gcloud's well-known file, the metadata server), with a single-flight
//!   token cache and the quota project as part of the token.
//! - [`storage`]: a small GCS JSON-API client — media upload, multipart
//!   upload with object metadata ([`UploadOptions`]), media download,
//!   delete, a bucket probe — and the public object URL. v0.8.0's behaviour
//!   by default; GCS's literal object addressing
//!   ([`ObjectNamePolicy::Literal`]) and a retry ([`RetryPolicy`]) are
//!   opt-in.
//! - [`retry`]: [`RetryPolicy`], Cloud Storage's documented retry strategy
//!   (capped exponential backoff, full jitter, a deadline, an optional
//!   attempt cap).
//! - `vertex` (feature `vertex`): typed `generateContent` request and
//!   response, the endpoint builder (the `global` host included), a thin
//!   client, and the inline-image classifier.
//!
//! Wording, timeouts, models and object naming stay in the service: this
//! crate says what Google answered, never what a user should read.
//!
//! # Errors are safe to log, `Debug` included
//!
//! Upstream text is reduced when an error is built, so neither `Display` nor
//! the derived `Debug` can echo it: Google's `error.status` is one of
//! google.rpc.Code's 17 names or `other`, an OAuth `error` one of RFC 6749's
//! codes or `other`, a credential `type` google-auth does not know is
//! `other`, and a token endpoint shows only its origin
//! (`scheme://host[:port]`). Google's free-text `error.message` is held
//! apart, as a [`SensitiveMessage`].
//!
//! # No TLS of its own
//!
//! Every constructor takes the consumer's `reqwest::Client` (0.13), and the
//! crate enables no reqwest TLS feature, so the TLS stack — and the process's
//! rustls crypto provider — is the consumer's choice, as with
//! stridelabs-auth. Google's APIs are `https://`: enable a TLS feature on your
//! own reqwest (`rustls`, the aws-lc-rs provider).
//!
//! # Feature topology
//!
//! `default = []`. Feature-gated items are named in plain code spans, never
//! intra-doc links, so `cargo doc` without `--all-features` stays clean.
//!
//! | Feature | Default | Adds |
//! |---|---|---|
//! | `service-account-key` | off | `service_account` credentials: RS256 assertion signing via jsonwebtoken (`aws_lc_rs` backend) with `use_pem`, and `auth::ServiceAccountKey` (offline `validate()`, `KeyDefect`). Off, such a credential is [`GcpAuthError::Unsupported`]. |
//! | `vertex` | off | the `vertex` module. No extra dependency. |

pub mod auth;
pub mod retry;
pub mod storage;
#[cfg(feature = "vertex")]
pub mod vertex;

mod util;

pub use auth::{AccessToken, CredentialKind, CredentialSource, GcpAuthError, TokenProvider};
#[cfg(feature = "service-account-key")]
pub use auth::{KeyDefect, ServiceAccountKey};
pub use storage::{
    public_url, public_url_with, validate_bucket_name, GcsClient, ObjectNamePolicy, RetryPolicy,
    StorageError, UploadOptions,
};
pub use util::SensitiveMessage;
