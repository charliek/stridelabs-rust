//! The resource-server half of slauth: verify the RS256 access tokens that
//! slauth (Ory Hydra) issues, and hash the personal access tokens a service
//! issues for itself.
//!
//! Extracted from spendwise-rs's `auth::{slauth, token, mod}`. A service that
//! adopts this crate holds one [`Verifier`] in its application state, hands it
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
//!         issuer: "https://auth.stridelabs.ai".into(),
//!         jwks_url: "https://auth.stridelabs.ai/.well-known/jwks.json".into(),
//!         audience: "spendwise".into(),
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
//! token's `kid`), `iss`, `aud`, `exp`, a non-empty `email` claim, and a
//! non-empty `sub`. Nothing else — in particular this crate does not know or
//! care what a `sub` *looks like*. That it is a Kratos identity UUID is a fact
//! about a slauth deployment, not a contract of the token format; treat it as
//! an opaque OIDC subject.
//!
//! Two deliberate hardenings over the spendwise original, both pinned in the
//! plan this crate was written from:
//!
//! - **An empty `sub` is rejected** ([`AuthError::MissingSubject`]). The
//!   original accepted `""` and would have keyed a user row on it.
//! - **JWKS refetches are rate-limited** to one per
//!   [`MIN_REFETCH_INTERVAL`], so a stream of tokens carrying unknown key
//!   ids can't turn this service into a load generator against the issuer.
//!   See [`jwks`] for the full cache contract.
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
//! `default = []`. Verification, the JWKS cache and [`pat`] are unconditional:
//! they are the crate.
//!
//! | Feature | Default | Adds |
//! |---|---|---|
//! | `axum` | off | [`bearer_token`], via the `http` types crate |
//! | `http` | off | `From<AuthError> for stridelabs_http::AppError` |
//! | `test-support` | off | [`test_support`] — offline JWT minting against two committed throwaway keypairs |
//!
//! The `http` feature is named for the **stridelabs-http** crate it bridges
//! to, not for the `http` types crate that `axum` pulls in. Both names are
//! unfortunate and both are the ones a reader will look for.

pub mod config;
pub mod error;
pub mod jwks;
pub mod pat;
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
pub use verify::{Claims, VerifiedIdentity, Verifier};

#[cfg(feature = "axum")]
pub use bearer::bearer_token;
