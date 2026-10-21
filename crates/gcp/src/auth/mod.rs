//! Google OAuth access tokens from an enumerated subset of Application
//! Default Credentials.
//!
//! A service builds one [`TokenProvider`] at startup — synchronously, from
//! local reads only — and asks it for a token per request:
//!
//! ```no_run
//! # async fn example(http: reqwest::Client) -> Result<(), stridelabs_gcp::GcpAuthError> {
//! use stridelabs_gcp::auth::{TokenProvider, CLOUD_PLATFORM_SCOPE};
//!
//! let tokens = TokenProvider::from_environment(http.clone(), &[CLOUD_PLATFORM_SCOPE], None)?;
//! let token = tokens.token().await?;
//! let response = token.authorize(http.get("https://storage.googleapis.com/storage/v1/b/my-bucket/o"));
//! # Ok(())
//! # }
//! ```
//!
//! # The source chain
//!
//! [`TokenProvider::from_environment`] takes the first source that is
//! **configured**:
//!
//! 1. the `explicit_b64` argument — base64 credential JSON (imgmcp's
//!    `GOOGLE_CREDENTIALS_BASE64`, tapper's and parcel's `GOOGLE_CREDENTIALS`);
//! 2. the file named by `GOOGLE_APPLICATION_CREDENTIALS`;
//! 3. gcloud's well-known file, `$CLOUDSDK_CONFIG/application_default_credentials.json`
//!    or `$HOME/.config/gcloud/application_default_credentials.json` (Unix
//!    layout; Windows' `%APPDATA%` is not consulted);
//! 4. the metadata server (`Metadata-Flavor: Google`, scopes in `?scopes=`,
//!    a 3 s timeout).
//!
//! An **absent** source — a `None` argument, an unset env var, a well-known
//! file that does not exist — moves on to the next. A **configured** source
//! that is empty, unreadable, malformed or unsupported is an error from the
//! constructor: a misconfigured credential never quietly selects a different
//! identity. `Some("")` and a set-but-empty `GOOGLE_APPLICATION_CREDENTIALS`
//! are configured (google-auth tests `is None` too); a consumer that reads
//! its own env var maps an empty value to `None` itself.
//!
//! Supported file `type`s are `service_account` (an RS256 JWT-bearer
//! assertion at the key's own `token_uri`; feature `service-account-key`) and
//! `authorized_user` (a refresh-token exchange, always at Google's token
//! endpoint — a `token_uri` in the file is ignored, as google-auth ignores
//! it). Every other type is [`GcpAuthError::Unsupported`].
//!
//! # Quota project
//!
//! A file's `quota_project_id`, overridden by `GOOGLE_CLOUD_QUOTA_PROJECT`,
//! rides on every [`AccessToken`] and [`AccessToken::authorize`] sends it as
//! `x-goog-user-project`. A user credential needs one for most APIs (Vertex
//! among them). The env var applies to metadata-server credentials too, as
//! google-auth's `_apply_quota_project_id` does for compute credentials.
//!
//! # The cache
//!
//! - A token is reused until [`REFRESH_MARGIN`] (60 s) before it expires.
//! - A response with no `expires_in` field is assumed to live
//!   [`FALLBACK_LIFETIME`] (300 s). An `expires_in` that is present but
//!   `null`, zero, negative or not an integer is an error and is never
//!   cached. Lifetimes above [`MAX_LIFETIME`] are capped there.
//! - Refreshes are **single-flight, per attempt**. At most one refresh is in
//!   flight; a call that finds one waits on *that* attempt and gets exactly
//!   its outcome — a token (even one too short-lived to cache) or its error.
//!   A failure is never cached: a call that arrives after an attempt
//!   finished, with no usable token cached, starts a new attempt.
//! - The refresh runs on its own task. Cancelling a caller — the one that
//!   started it included — never cancels the refresh; the others still get
//!   its outcome, and a success is still cached. A task that panics, or that
//!   the runtime drops (even before its first poll), clears its slot: its
//!   waiters get [`GcpAuthError::RefreshAborted`] and the next call starts
//!   afresh.
//! - [`TokenProvider::invalidate`] evicts a token a Google API answered `401`
//!   to, matched by its bearer, so the next call refreshes. Callers whose
//!   rejections of one bearer overlap cost one eviction and one refresh when
//!   that refresh mints a different, cacheable bearer. A refresh already in
//!   flight when its bearer was evicted, that returns that bearer, does not
//!   cache it: its waiters get it, and the next call asks the source.
//!
//! # The consumer's client
//!
//! Every request here goes through the `reqwest::Client` you hand in. It must
//! not carry a default `Authorization` header (or any other credential in
//! `default_headers`): reqwest would send it on every request, the metadata
//! server's plain-HTTP one and an emulator's included.
//!
//! # Credential files are trusted input
//!
//! A credential file is operator-controlled configuration and is parsed as
//! such. A hostile file could do harm before any check here runs — a
//! pathological PEM could exhaust the stack inside jsonwebtoken's
//! `simple_asn1` parser — and that is an accepted risk: whoever can write the
//! file already controls the identity.
//!
//! [`TokenProvider`] is one `Arc`: clone it freely, and build it once.

mod adc;
mod error;
mod metadata;
#[cfg(feature = "service-account-key")]
mod sa;
mod user;

#[cfg(test)]
mod single_flight_tests;

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use futures::future::{BoxFuture, FutureExt, Shared};
use serde_json::Value;
use tokio::sync::oneshot;
use tracing::Instrument;

pub use adc::{
    AdcEnvironment, ProcessEnvironment, CLOUDSDK_CONFIG, GOOGLE_APPLICATION_CREDENTIALS,
    GOOGLE_CLOUD_QUOTA_PROJECT,
};
pub use error::GcpAuthError;
pub use metadata::DEFAULT_METADATA_BASE_URL;

use crate::util::{is_code, read_error_body, read_limited, redact_url, Category, Failed};

/// Full access to every Google Cloud API the identity's IAM roles allow —
/// what Vertex AI requires.
pub const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// Read and write GCS objects, and nothing else.
pub const DEVSTORAGE_READ_WRITE_SCOPE: &str =
    "https://www.googleapis.com/auth/devstorage.read_write";

/// Google's OAuth token endpoint: where every `authorized_user` credential
/// exchanges its refresh token.
pub const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// How long before expiry a cached token is replaced. A token that expires
/// mid-flight is worse than one refreshed a minute early, and `expires_in` is
/// measured on the issuer's clock.
pub const REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// The lifetime assumed when a token response has no `expires_in` field:
/// short, not eternal.
pub const FALLBACK_LIFETIME: Duration = Duration::from_secs(300);

/// The longest lifetime believed. Google issues one-hour tokens; anything
/// claiming more than a day is capped so it cannot pin a token or overflow
/// an `Instant`.
pub const MAX_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// The most of a token response read. A real one is a few hundred bytes; a
/// larger one is [`GcpAuthError::InvalidResponse`], and an error body is read
/// only as far as its first 16 KiB.
pub const MAX_TOKEN_RESPONSE: usize = 64 * 1024;

/// The metadata server's default timeout. It answers in milliseconds on an
/// instance; off one, the name does not resolve or the connection hangs, and
/// three seconds is how long that costs.
pub const DEFAULT_METADATA_TIMEOUT: Duration = Duration::from_secs(3);

/// The token endpoint's default timeout (`service_account`,
/// `authorized_user`).
pub const DEFAULT_TOKEN_TIMEOUT: Duration = Duration::from_secs(10);

/// The [`GcpAuthError::Unsupported`] message for a `service_account`
/// credential in a build without the `service-account-key` feature.
pub const SERVICE_ACCOUNT_NOT_COMPILED_IN: &str =
    "service_account key support not compiled in (enable stridelabs-gcp/service-account-key)";

/// A bearer token for Google APIs, and the quota project to bill it to.
///
/// `Debug` prints `token` as `<redacted>`: it is a live credential.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessToken {
    /// The OAuth access token.
    pub token: String,
    /// Sent as `x-goog-user-project` by [`AccessToken::authorize`] when set.
    pub quota_project: Option<String>,
}

impl fmt::Debug for AccessToken {
    /// Destructured so a new field is a decision.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let AccessToken {
            token: _,
            quota_project,
        } = self;
        f.debug_struct("AccessToken")
            .field("token", &"<redacted>")
            .field("quota_project", quota_project)
            .finish()
    }
}

impl AccessToken {
    /// `request` with `Authorization: Bearer <token>` (marked sensitive) and,
    /// when there is a quota project, `x-goog-user-project`.
    pub fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let request = request.bearer_auth(&self.token);
        match &self.quota_project {
            Some(project) => request.header("x-goog-user-project", project),
            None => request,
        }
    }
}

/// Which source a [`TokenProvider`] was built from — for a startup log line,
/// and for tests that pin the chain's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredentialSource {
    /// The `explicit_b64` argument to [`TokenProvider::from_environment`].
    ExplicitBase64,
    /// The file named by `GOOGLE_APPLICATION_CREDENTIALS`.
    ApplicationCredentials,
    /// gcloud's well-known ADC file.
    GcloudDefault,
    /// The GCE / Cloud Run metadata server.
    MetadataServer,
    /// JSON handed to one of the `from_*_json` constructors.
    Json,
}

impl fmt::Display for CredentialSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CredentialSource::ExplicitBase64 => "explicit base64 credentials",
            CredentialSource::ApplicationCredentials => GOOGLE_APPLICATION_CREDENTIALS,
            CredentialSource::GcloudDefault => "gcloud application-default credentials",
            CredentialSource::MetadataServer => "metadata server",
            CredentialSource::Json => "credentials JSON",
        })
    }
}

/// What kind of identity a [`TokenProvider`] mints tokens for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredentialKind {
    /// A `service_account` key file.
    ServiceAccount,
    /// An `authorized_user` file: a gcloud user login.
    AuthorizedUser,
    /// The metadata server's attached service account.
    MetadataServer,
}

impl fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CredentialKind::ServiceAccount => "service_account",
            CredentialKind::AuthorizedUser => "authorized_user",
            CredentialKind::MetadataServer => "metadata_server",
        })
    }
}

/// Endpoints and timeouts a [`TokenProvider`] uses — the defaults, unless a
/// test points them at a mock.
///
/// `Debug` prints the two URLs as `scheme://host[:port]/path`.
#[derive(Clone)]
pub struct TokenOptions {
    metadata_base_url: String,
    default_token_uri: String,
    metadata_timeout: Duration,
    token_timeout: Duration,
}

impl fmt::Debug for TokenOptions {
    /// Destructured so a new field is a decision.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let TokenOptions {
            metadata_base_url,
            default_token_uri,
            metadata_timeout,
            token_timeout,
        } = self;
        f.debug_struct("TokenOptions")
            .field("metadata_base_url", &redact_url(metadata_base_url))
            .field("default_token_uri", &redact_url(default_token_uri))
            .field("metadata_timeout", metadata_timeout)
            .field("token_timeout", token_timeout)
            .finish()
    }
}

impl Default for TokenOptions {
    fn default() -> TokenOptions {
        TokenOptions {
            metadata_base_url: DEFAULT_METADATA_BASE_URL.to_owned(),
            default_token_uri: DEFAULT_TOKEN_URI.to_owned(),
            metadata_timeout: DEFAULT_METADATA_TIMEOUT,
            token_timeout: DEFAULT_TOKEN_TIMEOUT,
        }
    }
}

impl TokenOptions {
    /// Replace the metadata server's base URL ([`DEFAULT_METADATA_BASE_URL`]).
    #[must_use]
    pub fn metadata_base_url(mut self, url: impl Into<String>) -> TokenOptions {
        self.metadata_base_url = url.into();
        self
    }

    /// Replace the token endpoint `authorized_user` credentials exchange at
    /// ([`DEFAULT_TOKEN_URI`]). A test seam: a credential file cannot do this.
    #[must_use]
    pub fn default_token_uri(mut self, url: impl Into<String>) -> TokenOptions {
        self.default_token_uri = url.into();
        self
    }

    /// Replace the metadata request's timeout ([`DEFAULT_METADATA_TIMEOUT`]).
    #[must_use]
    pub fn metadata_timeout(mut self, timeout: Duration) -> TokenOptions {
        self.metadata_timeout = timeout;
        self
    }

    /// Replace the token-endpoint request's timeout ([`DEFAULT_TOKEN_TIMEOUT`]).
    #[must_use]
    pub fn token_timeout(mut self, timeout: Duration) -> TokenOptions {
        self.token_timeout = timeout;
        self
    }
}

/// Where tokens come from, parsed.
#[derive(Clone)]
pub(crate) enum Source {
    #[cfg(feature = "service-account-key")]
    ServiceAccount(sa::ServiceAccountKey),
    AuthorizedUser(user::AuthorizedUser),
    Metadata,
}

impl Source {
    fn kind(&self) -> CredentialKind {
        match self {
            #[cfg(feature = "service-account-key")]
            Source::ServiceAccount(_) => CredentialKind::ServiceAccount,
            Source::AuthorizedUser(_) => CredentialKind::AuthorizedUser,
            Source::Metadata => CredentialKind::MetadataServer,
        }
    }
}

/// An access-token source with a per-attempt single-flight cache in front of
/// it (see [the module docs](self#the-cache)).
///
/// Cheap to clone (one `Arc`); clones share the cache. Build it once, at
/// startup, and keep it in application state. [`TokenProvider::token`] must
/// be called on a tokio runtime: each refresh runs on a task of its own.
///
/// The `reqwest::Client` it is built with must carry no default credential
/// headers ([the module docs](self#the-consumers-client)).
///
/// `Debug` prints the source, the kind, the scopes and the quota project —
/// and, for a service account, its `client_email` — never a key, a refresh
/// token, a client secret or a cached token.
#[derive(Clone)]
pub struct TokenProvider {
    inner: Arc<Inner>,
}

struct Inner {
    http: reqwest::Client,
    scopes: Vec<String>,
    source: Source,
    origin: CredentialSource,
    quota_project: Option<String>,
    options: TokenOptions,
    cache: Mutex<Cache>,
    /// Test seam: added to every reading of the clock, so a test can carry a
    /// cached token past its refresh deadline without waiting an hour.
    #[cfg(test)]
    clock_skew: Mutex<Duration>,
    /// Test seam: how many upcoming refreshes panic instead of fetching.
    #[cfg(test)]
    panics_left: std::sync::atomic::AtomicUsize,
}

/// One refresh attempt, as every waiter sees it: the outcome its task sends,
/// shareable, a failure with whether it was transient where it happened
/// (what `GcsClient`'s retry reads). A sender dropped unsent (a task that
/// panicked, or was dropped before or while running) resolves it to
/// [`GcpAuthError::RefreshAborted`].
type Attempt = Shared<BoxFuture<'static, Result<AccessToken, Failed<GcpAuthError>>>>;

#[derive(Default)]
struct Cache {
    token: Option<Cached>,
    /// The attempt in flight, if any. Cleared by the attempt itself when it
    /// finishes, panics or is dropped with the runtime.
    in_flight: Option<InFlight>,
    next_attempt: u64,
    /// Bumped by every [`TokenProvider::invalidate`] that evicts. An attempt
    /// records it when it starts, so its install can tell whether an
    /// eviction happened while it was in flight.
    epoch: u64,
    /// The bearer the last evicting `invalidate` dropped.
    rejected: Option<String>,
}

struct InFlight {
    id: u64,
    attempt: Attempt,
}

struct Cached {
    token: AccessToken,
    /// When the token stops being served: expiry minus [`REFRESH_MARGIN`].
    refresh_at: Instant,
}

impl Cache {
    fn fresh(&self, now: Instant) -> Option<AccessToken> {
        self.token
            .as_ref()
            .filter(|cached| now < cached.refresh_at)
            .map(|cached| cached.token.clone())
    }

    /// Drop the cached token if its bearer is `bearer`, and remember the
    /// eviction; whether it was.
    fn evict(&mut self, bearer: &str) -> bool {
        let Some(evicted) = self.token.take_if(|cached| cached.token.token == bearer) else {
            return false;
        };
        self.epoch = self.epoch.wrapping_add(1);
        self.rejected = Some(evicted.token.token);
        true
    }

    /// Cache what an attempt that started at `epoch` fetched, unless an
    /// eviction happened since it started and it returned the bearer that
    /// eviction rejected; whether it cached. (Epochs only grow, so "since" is
    /// `!=`.)
    fn install(&mut self, epoch: u64, fetched: Cached) -> bool {
        let rejected =
            epoch != self.epoch && self.rejected.as_deref() == Some(fetched.token.token.as_str());
        if !rejected {
            self.token = Some(fetched);
        }
        !rejected
    }

    /// Clear the in-flight slot if it still holds attempt `id`.
    fn finish(&mut self, id: u64) {
        if self.in_flight.as_ref().is_some_and(|slot| slot.id == id) {
            self.in_flight = None;
        }
    }
}

impl fmt::Debug for TokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = &self.inner;
        let mut debug = f.debug_struct("TokenProvider");
        debug
            .field("source", &inner.origin)
            .field("kind", &inner.source.kind())
            .field("scopes", &inner.scopes)
            .field("quota_project", &inner.quota_project);
        #[cfg(feature = "service-account-key")]
        if let Source::ServiceAccount(key) = &inner.source {
            debug.field("client_email", &key.client_email());
        }
        debug.finish_non_exhaustive()
    }
}

impl TokenProvider {
    /// The provider [`the source chain`](self#the-source-chain) selects, from
    /// the process environment and file system.
    ///
    /// Synchronous and local: env vars and file reads only. The first network
    /// call is the first [`TokenProvider::token`]. `explicit_b64` is base64
    /// credential JSON (any supported `type`). `None` means absent; `Some` of
    /// anything — empty included — is configured, so map an empty env var of
    /// your own to `None` before calling.
    ///
    /// # Errors
    ///
    /// [`GcpAuthError::InvalidCredentials`] or [`GcpAuthError::Unsupported`]
    /// for a configured source that cannot be used.
    pub fn from_environment(
        http: reqwest::Client,
        scopes: &[&str],
        explicit_b64: Option<&str>,
    ) -> Result<TokenProvider, GcpAuthError> {
        TokenProvider::from_environment_with(http, scopes, explicit_b64, &ProcessEnvironment)
    }

    /// [`TokenProvider::from_environment`] over an injected environment.
    ///
    /// # Errors
    ///
    /// As [`TokenProvider::from_environment`].
    pub fn from_environment_with(
        http: reqwest::Client,
        scopes: &[&str],
        explicit_b64: Option<&str>,
        env: &dyn AdcEnvironment,
    ) -> Result<TokenProvider, GcpAuthError> {
        let resolved = adc::resolve(explicit_b64, env)?;
        Ok(TokenProvider::assemble(
            http,
            owned(scopes),
            resolved.source,
            resolved.origin,
            resolved.quota_project,
            TokenOptions::default(),
        ))
    }

    /// From credential JSON of any supported `type` (the contents of a key
    /// file). Its `quota_project_id`, if any, is the quota project; no env
    /// var is read.
    ///
    /// # Errors
    ///
    /// [`GcpAuthError::InvalidCredentials`] or [`GcpAuthError::Unsupported`].
    pub fn from_credentials_json(
        http: reqwest::Client,
        scopes: &[&str],
        json: &[u8],
    ) -> Result<TokenProvider, GcpAuthError> {
        let parsed = adc::parse_credentials(json, "credentials JSON")?;
        Ok(TokenProvider::assemble(
            http,
            owned(scopes),
            parsed.source,
            CredentialSource::Json,
            parsed.quota_project,
            TokenOptions::default(),
        ))
    }

    /// From `service_account` key JSON.
    ///
    /// # Errors
    ///
    /// [`GcpAuthError::Unsupported`] when `json` is another `type`, or when
    /// the `service-account-key` feature is off
    /// ([`SERVICE_ACCOUNT_NOT_COMPILED_IN`]);
    /// [`GcpAuthError::InvalidCredentials`] when it does not parse.
    pub fn from_service_account_json(
        http: reqwest::Client,
        scopes: &[&str],
        json: &[u8],
    ) -> Result<TokenProvider, GcpAuthError> {
        TokenProvider::from_json_of_kind(http, scopes, json, CredentialKind::ServiceAccount)
    }

    /// From `authorized_user` JSON (what `gcloud auth application-default
    /// login` writes).
    ///
    /// # Errors
    ///
    /// [`GcpAuthError::Unsupported`] when `json` is another `type`;
    /// [`GcpAuthError::InvalidCredentials`] when it does not parse.
    pub fn from_authorized_user_json(
        http: reqwest::Client,
        scopes: &[&str],
        json: &[u8],
    ) -> Result<TokenProvider, GcpAuthError> {
        TokenProvider::from_json_of_kind(http, scopes, json, CredentialKind::AuthorizedUser)
    }

    /// The metadata server's attached service account. Infallible: nothing is
    /// read until the first [`TokenProvider::token`]. No env var is read, so
    /// no quota project; add one with [`TokenProvider::with_quota_project`].
    pub fn metadata_server(http: reqwest::Client, scopes: &[&str]) -> TokenProvider {
        TokenProvider::assemble(
            http,
            owned(scopes),
            Source::Metadata,
            CredentialSource::MetadataServer,
            None,
            TokenOptions::default(),
        )
    }

    /// This provider with other endpoints and timeouts. Meant for right after
    /// construction: the result starts with an empty cache of its own.
    #[must_use]
    pub fn with_options(self, options: TokenOptions) -> TokenProvider {
        let inner = &self.inner;
        TokenProvider::assemble(
            inner.http.clone(),
            inner.scopes.clone(),
            inner.source.clone(),
            inner.origin,
            inner.quota_project.clone(),
            options,
        )
    }

    /// This provider with another quota project (`None` removes it). Meant
    /// for right after construction: the result starts with an empty cache of
    /// its own.
    #[must_use]
    pub fn with_quota_project(self, quota_project: Option<String>) -> TokenProvider {
        let inner = &self.inner;
        TokenProvider::assemble(
            inner.http.clone(),
            inner.scopes.clone(),
            inner.source.clone(),
            inner.origin,
            quota_project,
            inner.options.clone(),
        )
    }

    /// Where this provider's credential came from.
    pub fn source(&self) -> CredentialSource {
        self.inner.origin
    }

    /// What kind of identity it mints tokens for.
    pub fn kind(&self) -> CredentialKind {
        self.inner.source.kind()
    }

    /// The quota project every token carries.
    pub fn quota_project(&self) -> Option<&str> {
        self.inner.quota_project.as_deref()
    }

    /// A usable access token: the cached one, the outcome of the refresh in
    /// flight, or the outcome of a new one.
    ///
    /// # Errors
    ///
    /// [`GcpAuthError::Request`], [`GcpAuthError::Status`],
    /// [`GcpAuthError::InvalidResponse`], [`GcpAuthError::Signing`] or
    /// [`GcpAuthError::RefreshAborted`] — the error of the attempt this call
    /// waited on. None is cached.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime, when a refresh has to start (`tokio::spawn`).
    pub async fn token(&self) -> Result<AccessToken, GcpAuthError> {
        self.classified_token().await.map_err(|failed| failed.error)
    }

    /// [`TokenProvider::token`], its failure carrying whether it was
    /// transient: decided where it happened (a token endpoint's `503`, a
    /// connection that failed, a token body cut off), for a caller that
    /// retries.
    pub(crate) async fn classified_token(&self) -> Result<AccessToken, Failed<GcpAuthError>> {
        let now = self.inner.now();
        let (attempt, start) = {
            let mut cache = self.inner.cache();
            if let Some(token) = cache.fresh(now) {
                return Ok(token);
            }
            match &cache.in_flight {
                Some(in_flight) => (in_flight.attempt.clone(), None),
                None => {
                    // Reserve the slot under the lock; spawn only after it
                    // is released (below), so nothing that runs a guard's
                    // drop — a spawn that fails, a runtime that drops the
                    // task on the spot — can do so while this thread holds
                    // the lock the guard takes.
                    let id = cache.next_attempt;
                    cache.next_attempt = id.wrapping_add(1);
                    let (sender, receiver) = oneshot::channel();
                    let attempt = receiver
                        .map(|sent| {
                            sent.unwrap_or(Err(Failed::permanent(GcpAuthError::RefreshAborted)))
                        })
                        .boxed()
                        .shared();
                    cache.in_flight = Some(InFlight {
                        id,
                        attempt: attempt.clone(),
                    });
                    (attempt, Some((id, cache.epoch, sender)))
                }
            }
        };
        if let Some((id, epoch, sender)) = start {
            // The guard exists before the task does, so even a task dropped
            // before its first poll clears the slot it reserved.
            let guard = SlotGuard {
                inner: Arc::clone(&self.inner),
                id,
                epoch,
                sender: Some(sender),
            };
            tokio::spawn(refresh(guard).instrument(tracing::Span::current()));
        }
        attempt.await
    }

    /// Forget `rejected` if it is the token the cache holds, so the next
    /// [`TokenProvider::token`] refreshes: what a caller does when a Google
    /// API answered `401` to a bearer this provider handed out, before it
    /// takes a new token and replays. Returns whether it evicted.
    ///
    /// Synchronous, and it needs no runtime: it only takes the cache's lock.
    /// It never starts, cancels or duplicates a refresh; the next `token()`
    /// does that, or joins the one in flight.
    ///
    /// - **Matched by bearer string.** Any [`AccessToken`] carrying the cached
    ///   bearer evicts it, whichever provider produced it (two
    ///   metadata-server providers with the same scopes hold the same
    ///   bearer). Any other is a no-op that returns `false`: a token already
    ///   replaced, evicted, or never cached here (a clone's `with_*`
    ///   successor has a cache of its own).
    /// - **One refresh per wave**, narrowly. Callers whose rejections of one
    ///   bearer overlap a single refresh cost one eviction and that one
    ///   refresh, and all get its token, *when* it succeeds with a different
    ///   bearer that lives longer than [`REFRESH_MARGIN`] (so it is cached).
    ///   A later caller still holding the old bearer finds the new one
    ///   cached: its `invalidate` is a no-op and its `token()` refreshes
    ///   nothing. After a **failed** refresh the next call starts another,
    ///   and the evicted token is never served again (failures are not
    ///   cached).
    /// - **No re-install.** A refresh already in flight when its bearer was
    ///   evicted, that returns that same bearer, hands it to its waiters (it
    ///   is what the source has) but does not cache it: the next `token()`
    ///   asks the source again. A refresh that *starts* after the eviction
    ///   caches whatever it gets.
    /// - **The same bearer can come back.** Google's metadata server serves
    ///   its own cached token until about five minutes before it expires, so
    ///   a refresh there returns the bearer that was just rejected. A replay
    ///   then adds requests without obtaining different credentials, though
    ///   a transient server-side rejection can still recover. Bound your
    ///   replays: never loop on `401`, and never replay a `403`.
    ///
    /// Logged at `debug` with the source and kind, never the bearer.
    ///
    /// ```no_run
    /// # async fn example(http: reqwest::Client, tokens: stridelabs_gcp::TokenProvider)
    /// # -> Result<(), Box<dyn std::error::Error>> {
    /// let url = "https://fcm.googleapis.com/v1/projects/my-project/messages:send";
    /// let token = tokens.token().await?;
    /// let mut response = token.authorize(http.post(url)).send().await?;
    /// if response.status() == reqwest::StatusCode::UNAUTHORIZED {
    ///     if tokens.invalidate(&token) {
    ///         tracing::warn!("access token rejected; evicted it");
    ///     }
    ///     // Replay once, with whatever token the cache now gives.
    ///     let token = tokens.token().await?;
    ///     response = token.authorize(http.post(url)).send().await?;
    /// }
    /// response.error_for_status()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn invalidate(&self, rejected: &AccessToken) -> bool {
        let evicted = self.inner.cache().evict(&rejected.token);
        if evicted {
            tracing::debug!(
                source = %self.inner.origin,
                kind = %self.inner.source.kind(),
                "evicted a rejected GCP access token"
            );
        }
        evicted
    }

    /// Test seam: move this provider's clock forward.
    #[cfg(test)]
    fn advance_clock(&self, by: Duration) {
        *self
            .inner
            .clock_skew
            .lock()
            .unwrap_or_else(PoisonError::into_inner) += by;
    }

    /// Test seam: make the next `count` refreshes panic.
    #[cfg(test)]
    fn panic_next_refreshes(&self, count: usize) {
        self.inner
            .panics_left
            .store(count, std::sync::atomic::Ordering::SeqCst);
    }

    /// How many calls are waiting on the attempt in flight.
    #[cfg(test)]
    fn waiters(&self) -> usize {
        let cache = self.inner.cache();
        cache
            .in_flight
            .as_ref()
            .and_then(|in_flight| in_flight.attempt.strong_count())
            // The slot's own clone is not a waiter.
            .map_or(0, |count| count.saturating_sub(1))
    }

    fn assemble(
        http: reqwest::Client,
        scopes: Vec<String>,
        source: Source,
        origin: CredentialSource,
        quota_project: Option<String>,
        options: TokenOptions,
    ) -> TokenProvider {
        TokenProvider {
            inner: Arc::new(Inner {
                http,
                scopes,
                source,
                origin,
                quota_project,
                options,
                cache: Mutex::new(Cache::default()),
                #[cfg(test)]
                clock_skew: Mutex::new(Duration::ZERO),
                #[cfg(test)]
                panics_left: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    fn from_json_of_kind(
        http: reqwest::Client,
        scopes: &[&str],
        json: &[u8],
        expected: CredentialKind,
    ) -> Result<TokenProvider, GcpAuthError> {
        let provider = TokenProvider::from_credentials_json(http, scopes, json)?;
        if provider.kind() == expected {
            Ok(provider)
        } else {
            Err(GcpAuthError::Unsupported(format!(
                "expected {expected} credentials, got {}",
                provider.kind()
            )))
        }
    }
}

/// Refresh attempt `guard.id`, on its own task: no caller's cancellation
/// reaches it.
async fn refresh(guard: SlotGuard) {
    let started = guard.inner.now();
    let result = guard.inner.fetch().await;
    guard.complete(result, started);
}

/// Attempt `id`'s claim on the in-flight slot, and the only way its outcome
/// reaches the waiters.
///
/// Created before the task is spawned and moved into it, so it is dropped
/// however the task ends — completed, panicked, or dropped by the runtime
/// before its first poll. Dropping it clears the slot (only if the slot
/// still holds attempt `id`) and *then* drops the unsent sender, so every
/// waiter sees [`GcpAuthError::RefreshAborted`] and any call after them
/// starts a fresh attempt. It is never dropped while this thread holds the
/// cache lock: [`TokenProvider::token`] spawns only after releasing it, and
/// [`SlotGuard::complete`] releases it before returning.
struct SlotGuard {
    inner: Arc<Inner>,
    id: u64,
    /// The cache's eviction epoch when this attempt reserved its slot.
    epoch: u64,
    sender: Option<oneshot::Sender<Result<AccessToken, Failed<GcpAuthError>>>>,
}

impl SlotGuard {
    /// Cache a success (per the lifetime rules, and unless it is a bearer
    /// evicted while this attempt was in flight) and clear the slot in one
    /// critical section, then hand the outcome to the waiters.
    fn complete(mut self, result: Result<Fetched, Failed<GcpAuthError>>, started: Instant) {
        let outcome = {
            let inner = &self.inner;
            let mut cache = inner.cache();
            let outcome = result.map(|fetched| {
                let token = AccessToken {
                    token: fetched.token,
                    quota_project: inner.quota_project.clone(),
                };
                let cached = Cached {
                    token: token.clone(),
                    refresh_at: started + fetched.lifetime.saturating_sub(REFRESH_MARGIN),
                };
                if !cache.install(self.epoch, cached) {
                    tracing::debug!(
                        source = %inner.origin,
                        kind = %inner.source.kind(),
                        "a refresh returned the token evicted while it ran; not cached"
                    );
                }
                tracing::debug!(
                    source = %inner.origin,
                    kind = %inner.source.kind(),
                    lifetime_secs = fetched.lifetime.as_secs(),
                    "refreshed GCP access token"
                );
                token
            });
            cache.finish(self.id);
            outcome
        };
        if let Some(sender) = self.sender.take() {
            // Every waiter may be gone; the outcome is cached either way.
            let _ = sender.send(outcome);
        }
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        // A no-op after `complete`; the cleanup after a panic or a drop.
        self.inner.cache().finish(self.id);
        drop(self.sender.take());
    }
}

impl Inner {
    /// The cache state. A std mutex: it is never held across an await, and a
    /// panic while holding it cannot leave the state half-written.
    fn cache(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The clock the cache reads.
    fn now(&self) -> Instant {
        #[cfg(test)]
        {
            Instant::now()
                + *self
                    .clock_skew
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
        }
        #[cfg(not(test))]
        {
            Instant::now()
        }
    }

    async fn fetch(&self) -> Result<Fetched, Failed<GcpAuthError>> {
        #[cfg(test)]
        if self
            .panics_left
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |left| left.checked_sub(1),
            )
            .is_ok()
        {
            panic!("injected refresh panic");
        }
        match &self.source {
            #[cfg(feature = "service-account-key")]
            Source::ServiceAccount(key) => key.fetch(&self.http, &self.scopes, &self.options).await,
            Source::AuthorizedUser(user) => user.fetch(&self.http, &self.options).await,
            Source::Metadata => metadata::fetch(&self.http, &self.scopes, &self.options).await,
        }
    }
}

fn owned(scopes: &[&str]) -> Vec<String> {
    scopes.iter().map(|scope| (*scope).to_owned()).collect()
}

/// A token and how long it lives.
pub(crate) struct Fetched {
    token: String,
    lifetime: Duration,
}

/// Send a token request and read a token out of the answer. Shared by every
/// source: they differ in the request, never in the response.
///
/// Each failure says, where it happens, whether it was transient (the class
/// `GcsClient`'s opt-in retry reads; [`TokenProvider::token`] drops it): a
/// transport failure before the response by its category, an error status
/// by the retry's status set ([`crate::retry`]), and a 2xx body that could
/// not be read always (an interrupted transfer; the only source of a
/// token-path `decode error`). An unusable 2xx body is not.
pub(crate) async fn exchange(
    request: reqwest::RequestBuilder,
    endpoint: &str,
    timeout: Duration,
) -> Result<Fetched, Failed<GcpAuthError>> {
    let endpoint = redact_url(endpoint);
    let request_failed = |category: Category| GcpAuthError::Request {
        endpoint: endpoint.clone(),
        reason: category.label().to_owned(),
    };
    // `RequestBuilder::timeout` covers the body read too.
    let response = request.timeout(timeout).send().await.map_err(|error| {
        let category = Category::of(&error);
        Failed::before_response(category, request_failed(category))
    })?;
    let status = response.status();

    if !status.is_success() {
        let body = read_error_body(response).await;
        return Err(Failed::status(
            status.as_u16(),
            GcpAuthError::Status {
                endpoint,
                status: status.as_u16(),
                detail: oauth_error_code(&body),
            },
        ));
    }

    let unusable = |reason: &str| {
        Failed::permanent(GcpAuthError::InvalidResponse {
            endpoint: endpoint.clone(),
            reason: reason.to_owned(),
        })
    };
    let body = read_limited(response, MAX_TOKEN_RESPONSE)
        .await
        .map_err(|error| Failed::transient(request_failed(Category::of(&error))))?;
    if body.truncated {
        return Err(unusable("larger than 64 KiB"));
    }
    let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(&body.bytes) else {
        return Err(unusable("not a JSON object"));
    };
    let token = match object.get("access_token") {
        Some(Value::String(token)) if !token.is_empty() => token.clone(),
        _ => return Err(unusable("no `access_token` string")),
    };
    let lifetime = lifetime(object.get("expires_in")).map_err(unusable)?;
    Ok(Fetched { token, lifetime })
}

/// `expires_in` as a lifetime: an integer (or an integer string, which
/// google-auth also accepts) of seconds, above zero. Only an **absent** field
/// is [`FALLBACK_LIFETIME`]; a `null` one is malformed. Above
/// [`MAX_LIFETIME`] is capped.
fn lifetime(expires_in: Option<&Value>) -> Result<Duration, &'static str> {
    let seconds = match expires_in {
        None => return Ok(FALLBACK_LIFETIME),
        Some(Value::Null) => return Err("`expires_in` is null"),
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_u64().map(|_| i64::MAX)),
        Some(Value::String(text)) => text.trim().parse::<i64>().ok(),
        Some(_) => None,
    };
    match seconds {
        None => Err("`expires_in` is not an integer"),
        Some(seconds) if seconds <= 0 => Err("`expires_in` is not positive"),
        Some(seconds) => {
            let seconds = u64::try_from(seconds).unwrap_or(u64::MAX);
            Ok(Duration::from_secs(seconds).min(MAX_LIFETIME))
        }
    }
}

/// The RFC 6749 §5.2 `error` code of an error body, when it is a plain code
/// ([`is_code`]); empty otherwise. `error_description` and everything else
/// are dropped: free text a server may fill with anything.
fn oauth_error_code(body: &[u8]) -> String {
    let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(body) else {
        return String::new();
    };
    match object.get("error") {
        Some(Value::String(code)) if is_code(code) => code.clone(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn lifetimes_are_positive_integers_or_the_fallback_for_an_absent_field() {
        let secs = Duration::from_secs;
        assert_eq!(lifetime(None), Ok(FALLBACK_LIFETIME));
        assert_eq!(lifetime(Some(&json!(3599))), Ok(secs(3599)));
        assert_eq!(lifetime(Some(&json!("3599"))), Ok(secs(3599)));
        assert_eq!(lifetime(Some(&json!(1))), Ok(secs(1)));
        assert_eq!(lifetime(Some(&json!(u64::MAX))), Ok(MAX_LIFETIME));
        assert_eq!(lifetime(Some(&json!(i64::MAX))), Ok(MAX_LIFETIME));
        assert_eq!(lifetime(Some(&json!(null))), Err("`expires_in` is null"));
        for bad in [json!(0), json!(-1), json!("0"), json!(i64::MIN)] {
            assert_eq!(
                lifetime(Some(&bad)),
                Err("`expires_in` is not positive"),
                "{bad}"
            );
        }
        for bad in [
            json!(3599.5),
            json!("soon"),
            json!(""),
            json!(true),
            json!([1]),
        ] {
            assert_eq!(
                lifetime(Some(&bad)),
                Err("`expires_in` is not an integer"),
                "{bad}"
            );
        }
    }

    #[test]
    fn an_oauth_error_body_is_reduced_to_a_plain_error_code() {
        assert_eq!(
            oauth_error_code(
                br#"{"error":"invalid_grant","error_description":"CANARY-DESCRIPTION","access_token":"CANARY"}"#
            ),
            "invalid_grant"
        );
        for body in [
            &b"<html>CANARY</html>"[..],
            br#"{"error":{"nested":"CANARY"}}"#,
            br#"{"error":"not a code CANARY"}"#,
            br#"{"error":"CANARY\nforged log line"}"#,
            br#"{"error_description":"CANARY"}"#,
        ] {
            assert_eq!(
                oauth_error_code(body),
                "",
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        let long = format!(r#"{{"error":"{}"}}"#, "x".repeat(65));
        assert_eq!(oauth_error_code(long.as_bytes()), "");
    }

    #[test]
    fn an_access_token_debug_never_prints_the_token() {
        let token = AccessToken {
            token: "CANARY-ACCESS-TOKEN".into(),
            quota_project: Some("billing-project".into()),
        };
        for rendered in [format!("{token:?}"), format!("{token:#?}")] {
            assert!(!rendered.contains("CANARY"), "{rendered}");
            assert!(rendered.contains("<redacted>"), "{rendered}");
            assert!(rendered.contains("billing-project"), "{rendered}");
        }
    }

    #[test]
    fn token_options_debug_redacts_its_urls() {
        let options = TokenOptions::default()
            .metadata_base_url("http://user:CANARY@metadata.test:8080/?key=CANARY")
            .default_token_uri("https://CANARY@token.test/token?secret=CANARY#CANARY");
        for rendered in [format!("{options:?}"), format!("{options:#?}")] {
            assert!(!rendered.contains("CANARY"), "{rendered}");
            assert!(rendered.contains("metadata.test:8080"), "{rendered}");
            assert!(rendered.contains("https://token.test/token"), "{rendered}");
        }
    }

    /// A token server on a raw socket that answers its one request with
    /// `response` and closes: what wiremock cannot send (a body cut short).
    async fn answering(response: &[u8]) -> String {
        let address = crate::util::test_server::answer_once(response.to_vec()).await;
        format!("http://{address}/token")
    }

    /// Where each token-exchange failure is classified, and how: the class
    /// is set where the failure happens, beside the error, and the error's
    /// text is v0.8.0's. The token path's only `decode error` is its body
    /// read, an interrupted transfer, so it is transient; the same label from
    /// anywhere else is never read back to decide anything.
    #[tokio::test]
    async fn the_token_exchange_classifies_each_failure_where_it_happens() {
        let http = reqwest::Client::builder()
            .retry(reqwest::retry::never())
            .build()
            .unwrap();
        let exchange_at = |url: String| {
            let http = http.clone();
            async move { exchange(http.get(&url), &url, Duration::from_secs(5)).await }
        };
        let request = |failed: &Failed<GcpAuthError>| match &failed.error {
            GcpAuthError::Request { reason, .. } => (reason.clone(), failed.transient),
            other => panic!("{other:?}"),
        };

        // Before any response: by category.
        let closed = crate::util::test_server::closed_port();
        let failed = exchange_at(format!("http://{closed}/token"))
            .await
            .err()
            .unwrap();
        assert_eq!(request(&failed), ("connection failed".to_owned(), true));
        let failed = exchange_at("not a url".to_owned()).await.err().unwrap();
        assert_eq!(request(&failed), ("invalid request".to_owned(), false));
        let failed = exchange_at(answering(b"").await).await.err().unwrap();
        assert_eq!(request(&failed), ("request error".to_owned(), true));

        // A 2xx body cut off after the headers: interrupted, transient.
        let failed = exchange_at(
            answering(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n{\"access_token\":").await,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(request(&failed), ("decode error".to_owned(), true));

        // An error status: by the retry's status set.
        for (response, status, transient) in [
            (&b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"[..], 503, true),
            (b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n", 429, true),
            (
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 25\r\n\r\n{\"error\":\"invalid_grant\"}",
                400,
                false,
            ),
            (b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n", 501, false),
        ] {
            let failed = exchange_at(answering(response).await).await.err().unwrap();
            assert!(
                matches!(failed.error, GcpAuthError::Status { status: s, .. } if s == status),
                "{:?}",
                failed.error
            );
            assert_eq!(failed.transient, transient, "{status}");
        }

        // A 2xx that is not a token: permanent.
        let failed =
            exchange_at(answering(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]").await)
                .await
                .err()
                .unwrap();
        assert!(matches!(failed.error, GcpAuthError::InvalidResponse { .. }));
        assert!(!failed.transient);
    }
}
