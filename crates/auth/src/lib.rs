//! The resource-server half of slauth, the StrideLabs auth service: verify the
//! RS256 access tokens that slauth (Ory Hydra) issues — or, through
//! [`Verifier::for_issuer`], another issuer's, under claim rules the consumer
//! chooses — and hash the personal access tokens a service issues for itself.
//!
//! A service that adopts this crate holds one [`Verifier`] in its
//! application state, hands it
//! a bearer token per request, and gets back a [`VerifiedIdentity`]. Mapping
//! that identity to a database row — find-or-create, linking, admin checks —
//! stays in the service: it is the part that differs everywhere.
//!
//! ```no_run
//! # async fn example() -> Result<(), stridelabs_auth::AuthError> {
//! use stridelabs_auth::{SlauthConfig, Verifier};
//!
//! let verifier = Verifier::new(
//!     SlauthConfig {
//!         issuer: "https://auth.example.com".into(),
//!         jwks_url: "https://auth.example.com/.well-known/jwks.json".into(),
//!         audience: "my-service".into(),
//!         pat_validate_url: None,
//!     },
//!     reqwest::Client::new(),
//! );
//!
//! let identity = verifier.verify_bearer("eyJhbGciOi...").await?;
//! println!("{} <{}>", identity.name, identity.email);
//! # Ok(())
//! # }
//! ```
//!
//! # What verification actually checks
//!
//! RS256 signature against a key from the issuer's JWKS (selected by the
//! token's `kid`, and only an RSA key whose `alg`, `use` and `key_ops`, where
//! present, allow RS256 signatures), `iss`, `aud`, `exp`, a non-empty `email`
//! claim, and a non-empty `sub`. Nothing else — in particular this crate does
//! not know or care what a `sub` *looks like*. That it is a Kratos identity
//! UUID is a fact about a slauth deployment, not a contract of the token
//! format; treat it as an opaque OIDC subject.
//!
//! The email and subject rules are [`VerifiedIdentity`]'s. A token minted for
//! something else — an MCP access token, say, whose audience is a resource
//! URL, whose `email` is optional and whose scopes are what matter — goes
//! through [`Verifier::verify_bearer_claims`] (or the network-free
//! [`Verifier::claims_with_jwks`]) instead: the same key selection,
//! signature, `exp`, `iss` and `aud` checks, from the same code, with the
//! claims returned as the caller's own type and their semantics left to it.
//!
//! # Another issuer's tokens: [`Verifier::for_issuer`]
//!
//! [`Verifier::new`]'s claim rules are slauth's: `aud` required, a 60 s
//! leeway, `nbf` not checked. [`Verifier::for_issuer`] takes them as a
//! [`ClaimChecks`] instead: the issuer (compared exactly), an [`Audience`]
//! (`Required`, or `NotValidated` for an issuer whose tokens carry none), the
//! leeway on `exp` and `nbf`, and whether `nbf` is checked (by default it
//! is). Everything else is [`Verifier::new`]'s, from the same code: RS256
//! only, a `kid` required, the key-fitness rules, and a [`JwksCache`] the
//! verifier builds itself from the URL it is given, with an optional TTL, so
//! a key set is never served past it. [`Verifier::claims_with_jwks_checked`]
//! is the network-free twin, and [`Verifier::claims_with_jwks`] is it with
//! slauth's rules.
//!
//! **[`Audience::NotValidated`] skips the `aud` check, and is safe only when
//! the issuer binds the audience some other way**, as WorkOS's per-client
//! `iss` does. Against an issuer shared by several services it accepts a
//! token minted for any of them.
//!
//! ```no_run
//! # async fn example(http: reqwest::Client) -> Result<(), stridelabs_auth::AuthError> {
//! use std::time::Duration;
//!
//! use stridelabs_auth::{Audience, ClaimChecks, Verifier};
//!
//! // WorkOS access tokens carry no `aud`; their `iss` names the client.
//! let client_id = "client_01H...";
//! let checks = ClaimChecks::new(
//!     format!("https://api.workos.com/user_management/{client_id}"),
//!     Audience::NotValidated,
//! )
//! .with_leeway(Duration::ZERO); // `nbf` is checked by default
//! let verifier = Verifier::for_issuer(
//!     checks,
//!     format!("https://api.workos.com/sso/jwks/{client_id}"),
//!     Some(Duration::from_secs(3600)),
//!     http,
//! );
//!
//! // No email in a WorkOS access token, so not `verify_bearer`: the
//! // consumer reads its own claims and owns their rules.
//! #[derive(serde::Deserialize)]
//! struct WorkosClaims {
//!     #[serde(default)]
//!     sub: String,
//! }
//! let claims: WorkosClaims = verifier.verify_bearer_claims("eyJhbGciOi...").await?;
//! if claims.sub.is_empty() {
//!     // reject: an empty subject would key every such token onto one user
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Two deliberate hardenings over the original implementation this crate
//! replaced, both pinned in the plan this crate was written from:
//!
//! - **An empty `sub` is rejected** ([`AuthError::MissingSubject`]). The
//!   original accepted `""` and would have keyed a user row on it.
//! - **JWKS refetches are rate-limited**: an unknown key id refetches at
//!   most once per [`MIN_REFETCH_INTERVAL`], so a stream of tokens carrying
//!   unknown key ids can't turn this service into a load generator against
//!   the issuer, and a key set is never served past its [`JWKS_TTL`]. See
//!   [`jwks`] for the full cache contract.
//!
//! # slauth PATs: [`slauth_pat`]
//!
//! [`PatValidator`] resolves a `slp_live_…` PAT to its slauth identity by
//! asking slauth (`SlauthConfig::pat_validate_url`), with the outcomes and
//! messages of stridelabs-python's `PATValidator`: a [`PatValidationError`]
//! is `Rejected` (the token, a 401) or `Unavailable` (slauth, a 503).
//! Caching the answer is the consumer's. The client it is given **must not
//! follow redirects** ([`PatValidator`]'s docs say why).
//!
//! ```no_run
//! # async fn example(config: stridelabs_auth::SlauthConfig)
//! # -> Result<(), stridelabs_auth::PatValidationError> {
//! use stridelabs_auth::{PatValidator, SLAUTH_PAT_PREFIX};
//!
//! let http = reqwest::Client::builder()
//!     .redirect(reqwest::redirect::Policy::none())
//!     .build()
//!     .expect("a client builds");
//! // `None` when the config names no validate URL.
//! let pats = PatValidator::from_config(&config, http).expect("PATs are configured");
//!
//! let bearer = "slp_live_...";
//! if bearer.starts_with(SLAUTH_PAT_PREFIX) {
//!     let identity_id = pats.validate(bearer).await?; // a `uuid::Uuid`
//!     println!("PAT for identity {identity_id}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Errors never echo the token
//!
//! [`AuthError`]'s messages are fixed strings or a classification of *why* a
//! token was rejected. No variant carries the token, a claim value, or even
//! the `kid` — all of which are attacker-supplied on exactly the requests
//! where an error is produced. See [`error`].
//!
//! # Feature topology
//!
//! `default = []`. Verification, the JWKS cache, [`slauth_pat`] and [`pat`] are
//! unconditional: they are the crate.
//!
//! Note that feature-gated items are named in plain code spans, never
//! intra-doc links: they are off by default, so a link would be an
//! unresolved-link warning on `cargo doc` without `--all-features` (which is
//! how a consumer documenting its own graph usually builds). They appear in
//! the sidebar once the matching feature is on, which is the only time they
//! exist at all.
//!
//! | Feature | Default | Adds |
//! |---|---|---|
//! | `axum` | off | `bearer_token`, via the `http` types crate |
//! | `http` | off | `From<AuthError> for stridelabs_http::AppError` |
//! | `test-support` | off | `test_support` — offline JWT minting against two committed throwaway keypairs |
//!
//! The `http` feature is named for the **stridelabs-http** crate it bridges
//! to, not for the `http` types crate that `axum` pulls in. Both names are
//! unfortunate and both are the ones a reader will look for.

pub mod config;
pub mod error;
pub mod jwks;
pub mod pat;
pub mod slauth_pat;
pub mod verify;

#[cfg(feature = "axum")]
pub mod bearer;

// The test-support module is compiled for this crate's own tests whether or
// not the feature is on, so the test suite is identical in the default and
// `--all-features` lanes. The feature only controls whether it is *public*.
#[cfg(feature = "test-support")]
pub mod test_support;
#[cfg(all(test, not(feature = "test-support")))]
mod test_support;

// Wiremock scaffolding shared by this crate's own tests. Private and
// test-only; unrelated to the public `test_support` module above.
#[cfg(test)]
mod mock_issuer;

pub use config::SlauthConfig;
pub use error::AuthError;
pub use jwks::{JwksCache, JWKS_TTL, MIN_REFETCH_INTERVAL};
// `pat::hash` is deliberately not re-exported here: a bare `hash` at a crate
// root says nothing about *what* it hashes.
pub use pat::{GeneratedToken, PatFormat, PatFormatError, MAX_PREFIX_LEN};
pub use slauth_pat::{
    is_slauth_pat, PatValidationError, PatValidator, PAT_VALIDATION_TIMEOUT, SLAUTH_PAT_PREFIX,
};
pub use verify::{Audience, ClaimChecks, Claims, VerifiedIdentity, Verifier, DEFAULT_LEEWAY};

#[cfg(feature = "axum")]
pub use bearer::bearer_token;
