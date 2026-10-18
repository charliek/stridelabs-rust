//! Policy-free Google Cloud building blocks for StrideLabs services.
//!
//! - [`auth`]: a [`TokenProvider`] over an enumerated subset of Application
//!   Default Credentials (an explicit base64 key, `GOOGLE_APPLICATION_CREDENTIALS`,
//!   gcloud's well-known file, the metadata server), with a single-flight
//!   token cache and the quota project as part of the token.
//! - [`storage`]: a small GCS JSON-API client — media upload, multipart
//!   upload with object metadata ([`UploadOptions`]), media download,
//!   delete — and the public object URL.
//! - `vertex` (feature `vertex`): typed `generateContent` request and
//!   response, the endpoint builder (the `global` host included), a thin
//!   client, and the inline-image classifier.
//!
//! Wording, timeouts, models and object naming stay in the service: this
//! crate says what Google answered, never what a user should read.
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
//! | `service-account-key` | off | `service_account` credentials: RS256 assertion signing via jsonwebtoken (`aws_lc_rs` backend) with `use_pem`. Off, such a credential is [`GcpAuthError::Unsupported`]. |
//! | `vertex` | off | the `vertex` module. No extra dependency. |

pub mod auth;
pub mod storage;
#[cfg(feature = "vertex")]
pub mod vertex;

mod util;

pub use auth::{AccessToken, CredentialKind, CredentialSource, GcpAuthError, TokenProvider};
pub use storage::{public_url, GcsClient, StorageError, UploadOptions};
pub use util::SensitiveMessage;
