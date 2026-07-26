//! The slauth settings a resource server needs.

use serde::Deserialize;

/// Everything [`crate::Verifier`] needs to know about the issuer it trusts.
///
/// `Deserialize` so a service can nest it inside its own config struct (a
/// `[slauth]` table in a YAML file, an `SLAUTH_*`-prefixed env group mapped by
/// the caller — this crate doesn't read the environment itself).
///
/// Notably absent: `client_id`. That belongs to the *browser* half of the
/// flow (the PKCE authorization request), which a resource server never
/// performs; it stays in the consuming app's config next to its redirect URI.
#[derive(Debug, Clone, Deserialize)]
pub struct SlauthConfig {
    /// Expected `iss` claim, e.g. `https://auth.stridelabs.ai`. Compared
    /// exactly — a trailing slash mismatch is a rejected token, not a
    /// near-miss.
    pub issuer: String,
    /// Where the issuer publishes its signing keys, e.g.
    /// `https://auth.stridelabs.ai/.well-known/jwks.json`.
    pub jwks_url: String,
    /// Expected `aud` claim: this service's identifier at the issuer.
    pub audience: String,
    /// slauth's personal-access-token introspection endpoint, for services
    /// that accept slauth-issued PATs in addition to JWTs.
    ///
    /// Unused by this crate today — [`crate::pat`] deals in *locally* issued
    /// tokens, which are validated against the service's own database. It
    /// lives here because it is slauth configuration and every consumer that
    /// eventually needs it would otherwise carry its own field for it.
    #[serde(default)]
    pub pat_validate_url: Option<String>,
}
