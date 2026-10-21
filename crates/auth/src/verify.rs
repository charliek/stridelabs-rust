//! Access-token verification: the thing this crate exists for.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::jwk::{
    AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::config::{redact_issuer, SlauthConfig};
use crate::error::{invalid_token, AuthError};
use crate::jwks::JwksCache;

/// The clock-skew leeway a [`ClaimChecks`] applies to `exp` (and to `nbf`,
/// when it is checked) unless [`ClaimChecks::with_leeway`] replaces it:
/// jsonwebtoken's own default, and what [`Verifier::new`] has always applied.
pub const DEFAULT_LEEWAY: Duration = Duration::from_secs(60);

/// The most leeway a [`ClaimChecks`] applies; [`ClaimChecks::with_leeway`]
/// caps a longer one here. Skew past a day is not clock skew, and
/// jsonwebtoken computes `now - leeway` and `now + leeway` in unchecked `u64`
/// seconds: an unbounded leeway panics a build with overflow checks on (a
/// debug build, so every test) and wraps in one without.
const MAX_LEEWAY: Duration = Duration::from_secs(24 * 60 * 60);

/// The `audience` of the [`SlauthConfig`] a [`Verifier::for_issuer`]
/// verifier synthesizes under [`Audience::NotValidated`]: an `aud` no issuer
/// mints. It starts with a NUL, a control character no service identifier
/// contains, so it is never empty either. A [`Verifier::new`] mistakenly
/// built from that config requires `aud` to equal it, and so accepts no
/// token a real issuer mints, where an empty audience would have accepted
/// any token with `aud: ""` under slauth's laxer time rules.
const NOT_VALIDATED_AUDIENCE: &str = "\0audience not validated";

/// Whether, and against what, a token's `aud` claim is checked.
///
/// There is deliberately no `Default`, and no conversion produces
/// [`Audience::NotValidated`]: skipping the audience check is something a
/// consumer has to spell out, in the one place a reviewer will look for it.
// `Debug` is derived and prints the `Required` value: an audience is this
// service's identifier at the issuer, configuration rather than a secret, and
// the value to compare when a token's `aud` is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Audience {
    /// `aud` must be present, and equal this value or, as an array, contain
    /// it. What [`Verifier::new`] applies, with `SlauthConfig::audience`.
    Required(String),
    /// `aud` is **not checked**: absent, present, or naming another service
    /// altogether, it passes.
    ///
    /// **Safe only when the issuer binds the audience some other way**: when
    /// the exact `iss` the [`ClaimChecks`] require can only ever be stamped
    /// on tokens minted for this service. WorkOS is the case this exists for:
    /// its access tokens carry no `aud`, and their `iss` is
    /// `https://api.workos.com/user_management/{client_id}`, so the exact
    /// issuer match pins the client. Against an issuer that serves several
    /// relying parties under one `iss` (slauth, or any shared OIDC provider)
    /// it accepts a token minted for any of them, and this service becomes a
    /// confused deputy for every other one.
    NotValidated,
}

/// The rules a token's claims are checked against once its signature has
/// verified: the issuer, the [`Audience`], the clock-skew leeway, and whether
/// `nbf` is checked.
///
/// - `exp` and `iss` are always required; `aud` only under
///   [`Audience::Required`]. A token missing one is rejected ("a required
///   claim is missing"), never let through unchecked.
/// - `iss` must equal the issuer **exactly**: a trailing-slash mismatch is a
///   rejected token, not a near miss. (Like every jsonwebtoken check, an
///   `iss` *array* that contains the issuer passes too; RFC 7519 makes `iss`
///   a single string, and only the issuer's own key can sign one.)
/// - `exp` and `nbf` are whole Unix seconds, compared with the leeway: a
///   token is expired once `exp < now - leeway`, so with no leeway it is
///   accepted through the second its `exp` names and refused from the next;
///   it is not yet valid while `nbf > now + leeway`. An absent `nbf` is fine
///   either way; a present one that is not a number is "token is malformed"
///   while `nbf` is checked.
///
/// [`ClaimChecks::new`] starts from a 60 s leeway ([`DEFAULT_LEEWAY`]) with
/// `nbf` checked. [`Verifier::new`]'s rules, kept as they have always been,
/// differ in one respect: `nbf` is not checked (see
/// [`Verifier::claim_checks`]).
///
/// `Debug` prints the issuer exactly as configured, as [`SlauthConfig`]'s
/// does: seeing it exactly is what debugging a trailing-slash mismatch
/// takes. An issuer that is a URL carrying userinfo, a query or a fragment
/// (no real `iss` does) prints as `scheme://host[:port]/path` instead, so a
/// credential pasted into one never reaches a log. The audience prints as
/// [`Audience`]'s does. The JWKS URL lives with the [`Verifier`] and is
/// redacted there.
#[derive(Clone, PartialEq, Eq)]
pub struct ClaimChecks {
    issuer: String,
    audience: Audience,
    /// Whole seconds, at most [`MAX_LEEWAY`]: exactly what is applied.
    leeway: Duration,
    validate_nbf: bool,
}

impl ClaimChecks {
    /// Rules for tokens from `issuer`, compared exactly, with `audience`'s
    /// `aud` check, a 60 s leeway ([`DEFAULT_LEEWAY`]) and `nbf` checked.
    pub fn new(issuer: impl Into<String>, audience: Audience) -> ClaimChecks {
        ClaimChecks {
            issuer: issuer.into(),
            audience,
            leeway: DEFAULT_LEEWAY,
            validate_nbf: true,
        }
    }

    /// Replace the clock-skew leeway on `exp` and `nbf` ([`DEFAULT_LEEWAY`]
    /// by default). `Duration::ZERO` for none.
    ///
    /// jsonwebtoken counts whole seconds, so a fraction is dropped (1.5 s is
    /// 1 s: never more lenient than asked), and a leeway over a day is
    /// capped at a day (skew past that is not clock skew, and jsonwebtoken's
    /// unchecked arithmetic on it would overflow). [`ClaimChecks::leeway`]
    /// returns the value applied.
    #[must_use]
    pub fn with_leeway(mut self, leeway: Duration) -> ClaimChecks {
        self.leeway = Duration::from_secs(leeway.min(MAX_LEEWAY).as_secs());
        self
    }

    /// Whether a present `nbf` is checked (on by default). An absent `nbf`
    /// is never required.
    #[must_use]
    pub fn with_nbf_validation(mut self, validate: bool) -> ClaimChecks {
        self.validate_nbf = validate;
        self
    }

    /// The `iss` a token must carry, exactly.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// How a token's `aud` is checked.
    pub fn audience(&self) -> &Audience {
        &self.audience
    }

    /// The leeway applied to `exp` and `nbf`: whole seconds, at most a day.
    pub fn leeway(&self) -> Duration {
        self.leeway
    }

    /// Whether a present `nbf` is checked.
    pub fn validates_nbf(&self) -> bool {
        self.validate_nbf
    }

    /// [`Verifier::new`]'s rules, unchanged since before `ClaimChecks`
    /// existed: `aud` required and equal to `audience`, jsonwebtoken's 60 s
    /// leeway, and `nbf` not checked.
    fn slauth(issuer: &str, audience: &str) -> ClaimChecks {
        ClaimChecks::new(issuer, Audience::Required(audience.to_owned())).with_nbf_validation(false)
    }

    /// The jsonwebtoken validation these rules come to.
    fn validation(&self) -> Validation {
        // `Validation::new(RS256)` pins the algorithm — an `alg: none` or
        // HS256 token (the classic "verify with the public key as an HMAC
        // secret" forgery) is rejected before the signature is even checked.
        // `exp` validation is on by default and stays on.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = self.leeway.as_secs();
        validation.validate_nbf = self.validate_nbf;
        // set_issuer/set_audience only validate the claims WHEN PRESENT —
        // jsonwebtoken's `Validation::new` requires only `exp`, so without
        // the required-claims lists below a token that simply omits `iss` or
        // `aud` sails through. (The original implementation this crate
        // replaced had that hole; hardening, not parity.)
        match &self.audience {
            Audience::Required(audience) => {
                validation.set_audience(&[audience]);
                validation.set_required_spec_claims(&["exp", "iss", "aud"]);
            }
            Audience::NotValidated => {
                // Off, not merely unset: with no audience configured,
                // jsonwebtoken rejects every token that carries one.
                validation.validate_aud = false;
                validation.set_required_spec_claims(&["exp", "iss"]);
            }
        }
        validation
    }
}

impl fmt::Debug for ClaimChecks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaimChecks")
            .field("issuer", &redact_issuer(&self.issuer))
            .field("audience", &self.audience)
            .field("leeway", &self.leeway)
            .field("validate_nbf", &self.validate_nbf)
            .finish()
    }
}

/// The claims this crate reads. Anything else in the token is ignored.
///
/// slauth injects `email` and `name` at the consent step, but both are
/// declared optional here so that a token which omits them fails the
/// *documented* check ([`AuthError::MissingEmail`]) rather than a
/// deserialization error — the distinction matters when reading a log.
#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    /// The OIDC subject. `default` so an absent claim arrives as `""` and is
    /// rejected by the same check as an empty one.
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// A caller whose token passed every check.
///
/// `sub` is an **opaque** stable identifier for the end user at the issuer.
/// In a slauth deployment it happens to be the Kratos identity UUID, and
/// services key their user rows on it — but that is a fact about that
/// deployment, not a promise of this type. Nothing here parses it.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub sub: String,
    /// Non-empty, guaranteed.
    pub email: String,
    /// May be empty: a display name is not something to reject a login over.
    pub name: String,
}

/// Verifies access tokens against a cached JWKS: slauth's
/// ([`Verifier::new`]), or another issuer's under rules of the consumer's
/// choosing ([`Verifier::for_issuer`]).
///
/// Cheap to clone (one `Arc`), and **meant to be cloned rather than rebuilt**:
/// the key cache lives inside, so a verifier constructed per request would
/// fetch the JWKS per request. Build one in the service's application state
/// and clone it from there.
#[derive(Debug, Clone)]
pub struct Verifier {
    inner: Arc<Inner>,
}

// `Debug` stays derived here and on `Verifier`: every URL either holds is
// inside `SlauthConfig`, `ClaimChecks` (the issuer) or `JwksCache`, whose own
// `Debug` impls redact it. `jwks::tests::debug_never_renders_url_material`
// renders a `Verifier::new` verifier, and
// `verify::tests::a_for_issuer_verifier_never_debugs_url_material` a
// `Verifier::for_issuer` one, to hold the composition to that.
#[derive(Debug)]
struct Inner {
    config: SlauthConfig,
    /// What `verify_bearer_claims` checks: derived from `config` by
    /// `Verifier::new`, the consumer's own by `Verifier::for_issuer`.
    checks: ClaimChecks,
    jwks: JwksCache,
}

impl Verifier {
    /// Build a verifier for `config`, fetching keys with `http`.
    ///
    /// The [`JwksCache`] is constructed **here**, from `config.jwks_url`,
    /// rather than being accepted as an argument. A cache pointed at one
    /// issuer and a config naming another is a hole that no amount of
    /// verification logic can close, so the two cannot be supplied
    /// separately.
    ///
    /// Its claim rules are slauth's: `iss` equal to `config.issuer`, `aud`
    /// required and equal to `config.audience`, a 60 s leeway, and `nbf` not
    /// checked ([`Verifier::claim_checks`]). The key set is cached for
    /// [`crate::JWKS_TTL`].
    pub fn new(config: SlauthConfig, http: reqwest::Client) -> Verifier {
        let jwks = JwksCache::new(config.jwks_url.clone(), http);
        let checks = ClaimChecks::slauth(&config.issuer, &config.audience);
        Verifier {
            inner: Arc::new(Inner {
                config,
                checks,
                jwks,
            }),
        }
    }

    /// Build a verifier for tokens from `checks`' issuer, under `checks`'
    /// rules, fetching that issuer's keys from `jwks_url` with `http`.
    ///
    /// For an issuer that is not slauth, or not slauth's rules: a token
    /// without an `aud` ([`Audience::NotValidated`]), a zero leeway, `nbf`
    /// checked. The signature side is [`Verifier::new`]'s, from the same
    /// code: RS256 only, a `kid` required, and only a key fit for RS256
    /// signatures under it.
    ///
    /// The [`JwksCache`] is constructed here, as [`Verifier::new`] does and
    /// for the same reason: no cache for one issuer can be paired with rules
    /// for another. It is cached for `jwks_ttl`, or [`crate::JWKS_TTL`] when
    /// `None` ([`JwksCache::with_ttl`] says what other values do), with every
    /// other bound of the cache contract ([`crate::jwks`]) at its default: a
    /// key set is never served past its TTL, is refreshed ahead of it, and a
    /// lookup once it has expired and cannot be refetched is
    /// [`AuthError::Jwks`], a 5xx at the consumer.
    ///
    /// [`Verifier::config`] on the result is synthesized from the arguments;
    /// see there.
    pub fn for_issuer(
        checks: ClaimChecks,
        jwks_url: impl Into<String>,
        jwks_ttl: Option<Duration>,
        http: reqwest::Client,
    ) -> Verifier {
        let jwks_url = jwks_url.into();
        let mut jwks = JwksCache::new(jwks_url.clone(), http);
        if let Some(ttl) = jwks_ttl {
            jwks = jwks.with_ttl(ttl);
        }
        let config = SlauthConfig {
            issuer: checks.issuer.clone(),
            jwks_url,
            audience: match &checks.audience {
                Audience::Required(audience) => audience.clone(),
                Audience::NotValidated => NOT_VALIDATED_AUDIENCE.to_owned(),
            },
            pat_validate_url: None,
        };
        Verifier {
            inner: Arc::new(Inner {
                config,
                checks,
                jwks,
            }),
        }
    }

    /// The configuration this verifier was built with.
    ///
    /// For a [`Verifier::for_issuer`] verifier, which takes no
    /// [`SlauthConfig`], one synthesized from its arguments, and
    /// **informational only**: its issuer and JWKS URL, no
    /// `pat_validate_url`, and `audience` the [`Audience::Required`] value,
    /// or under [`Audience::NotValidated`] a sentinel no issuer mints (the
    /// string `"\0audience not validated"`, which starts with a NUL
    /// character; never empty). It does not hold this verifier's rules; read
    /// [`Verifier::claim_checks`] for those.
    ///
    /// **Do not rebuild a `for_issuer` verifier with `Verifier::new(config)`.**
    /// That applies slauth's rules ([`Verifier::new`]): `aud` required, a
    /// 60 s leeway and `nbf` unchecked, not this verifier's leeway or `nbf`
    /// setting. Under [`Audience::Required`] the result can accept tokens
    /// this verifier refuses: up to 60 s past their `exp` where this one's
    /// leeway is smaller, or with an `nbf` still ahead where this one checks
    /// it. Under [`Audience::NotValidated`] the sentinel makes it refuse
    /// every token a real issuer mints, so that mistake fails closed, but it
    /// is still not this verifier. Clone the verifier instead.
    pub fn config(&self) -> &SlauthConfig {
        &self.inner.config
    }

    /// The claim rules [`Verifier::verify_bearer_claims`] applies: the
    /// [`ClaimChecks`] a [`Verifier::for_issuer`] verifier was built with, or
    /// for a [`Verifier::new`] one, slauth's (`config.issuer`, `aud` required
    /// and equal to `config.audience`, a 60 s leeway, `nbf` not checked).
    ///
    /// Handy for [`Verifier::claims_with_jwks_checked`] in a test of the
    /// consumer's own wiring.
    pub fn claim_checks(&self) -> &ClaimChecks {
        &self.inner.checks
    }

    /// Verify a bearer token's value (the part after `Bearer `).
    ///
    /// Everything [`Verifier::verify_bearer_claims`] checks, under this
    /// verifier's [`ClaimChecks`], then [`VerifiedIdentity`]'s rules: a
    /// non-empty `email` and a non-empty `sub`. Those are slauth's sign-in
    /// tokens' rules. On a [`Verifier::for_issuer`] verifier they apply
    /// as-is, so this is meaningful only for an issuer whose access tokens
    /// carry an email: WorkOS's carry none by default, and every one would be
    /// [`AuthError::MissingEmail`]. Use [`Verifier::verify_bearer_claims`]
    /// with a claims type of your own there, and check `sub` yourself.
    ///
    /// May fetch the issuer's JWKS; see [`crate::jwks`] for when.
    pub async fn verify_bearer(&self, token: &str) -> Result<VerifiedIdentity, AuthError> {
        let claims: Claims = self.verify_bearer_claims(token).await?;
        identity_from(claims)
    }

    /// Verify a bearer token's value and return its claims as `C`, with none
    /// of [`Verifier::verify_bearer`]'s identity checks.
    ///
    /// The cryptographic and spec-claim checks are the same ones, from the
    /// same code: key selection by `kid` (a token without one is
    /// [`AuthError::MissingKid`]), the RS256 signature, then this verifier's
    /// [`ClaimChecks`] ([`Verifier::claim_checks`]): for a
    /// [`Verifier::new`] verifier, `exp`, `iss` and `aud`, all three
    /// required. What is **not** checked is anything about `email` or `sub`:
    /// those are [`VerifiedIdentity`]'s contract, and a token for another
    /// purpose (an MCP access token, whose audience is a resource URL and
    /// whose email is optional) has different claim rules. The caller owns
    /// them, including rejecting an empty `sub` if its rows are keyed on it.
    ///
    /// A claims shape that doesn't deserialize into `C` is
    /// [`AuthError::InvalidToken`] ("claims are malformed"), never the serde
    /// message, which can quote the offending value.
    ///
    /// May fetch the issuer's JWKS; see [`crate::jwks`] for when.
    pub async fn verify_bearer_claims<C: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<C, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::MalformedToken)?;
        let kid = header.kid.ok_or(AuthError::MissingKid)?;

        let jwks = self.inner.jwks.jwks_for_kid(&kid).await?;

        Verifier::claims_with_jwks_checked(token, &jwks, &kid, &self.inner.checks)
    }

    /// The whole of verification, minus the network.
    ///
    /// An associated function, not a method: it takes no `self`, does no I/O,
    /// and is public so a consumer can test its own wiring — or verify a token
    /// against a key set it obtained some other way — without a
    /// [`Verifier`] or an HTTP client.
    ///
    /// Checks, in order: everything [`Verifier::claims_with_jwks`] checks,
    /// then a non-empty `email` claim and a non-empty `sub` claim.
    pub fn verify_with_jwks(
        token: &str,
        jwks: &JwkSet,
        kid: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<VerifiedIdentity, AuthError> {
        let claims: Claims = Verifier::claims_with_jwks(token, jwks, kid, issuer, audience)?;
        identity_from(claims)
    }

    /// [`Verifier::verify_bearer_claims`] minus the network, for a
    /// [`Verifier::new`] verifier: the token's claims as `C`, after every
    /// cryptographic and spec-claim check and no claim semantics beyond them.
    ///
    /// Checks, in order: the set holds a key under `kid` that is fit for RS256
    /// signatures (an RSA key whose `alg`, `use` and `key_ops`, where present,
    /// allow it); the key is usable; RS256 signature; `exp` (60 s leeway);
    /// `iss` equals `issuer`; `aud` contains `audience`. `exp`, `iss` and
    /// `aud` must be present; `nbf` is not checked. Nothing about `email` or
    /// `sub` — the caller owns those (see [`Verifier::verify_bearer_claims`]).
    ///
    /// [`Verifier::claims_with_jwks_checked`] with slauth's rules
    /// ([`Verifier::claim_checks`] on a [`Verifier::new`] verifier); the one
    /// copy of the logic is there.
    pub fn claims_with_jwks<C: DeserializeOwned>(
        token: &str,
        jwks: &JwkSet,
        kid: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<C, AuthError> {
        Verifier::claims_with_jwks_checked(token, jwks, kid, &ClaimChecks::slauth(issuer, audience))
    }

    /// The whole of claims verification minus the network, under `checks`:
    /// the token's claims as `C`, after every cryptographic check and the
    /// spec-claim rules `checks` sets, and no claim semantics beyond them.
    ///
    /// Checks, in order: the set holds a key under `kid` that is fit for RS256
    /// signatures (an RSA key whose `alg`, `use` and `key_ops`, where present,
    /// allow it); the key is usable; RS256 signature (no other algorithm,
    /// `none` and HS256 included); `exp` and, if `checks` says so, `nbf`,
    /// with its leeway; `iss` equals its issuer exactly; under
    /// [`Audience::Required`], `aud` contains the audience. `exp` and `iss`
    /// must be present, and `aud` under [`Audience::Required`]. Nothing about
    /// `email` or `sub` — the caller owns those (see
    /// [`Verifier::verify_bearer_claims`]). [`ClaimChecks`] has the details.
    ///
    /// Failures are [`AuthError::UnknownKid`] (no key fit for RS256 under
    /// `kid`), [`AuthError::Jwks`] (a fit key that cannot be used: the
    /// issuer's fault) or [`AuthError::InvalidToken`] with a fixed phrase,
    /// never text from the token.
    pub fn claims_with_jwks_checked<C: DeserializeOwned>(
        token: &str,
        jwks: &JwkSet,
        kid: &str,
        checks: &ClaimChecks,
    ) -> Result<C, AuthError> {
        // Only a key the issuer published for RS256 signatures may verify one.
        // `DecodingKey::from_jwk` ignores the JWK's `alg`, `use` and `key_ops`,
        // so without this an RSA key labelled for encryption (`use: enc`,
        // `alg: RSA-OAEP`, or a label jsonwebtoken 11 parses as
        // `UNKNOWN_ALGORITHM` where 9 rejected the whole set) would verify a
        // token naming its kid. A kid with no fit key is `UnknownKid` (401),
        // not `Jwks` (500): there is no signature-verification key by that
        // name, the same verdict as a kid missing from the set; and the kid is
        // the caller's choice, so a 500 would let anyone raise this service's
        // error rate against an issuer that publishes encryption keys
        // alongside its signing keys. Keys sharing a kid are all considered,
        // so an encryption key listed first does not hide the signing key.
        let jwk = jwks
            .keys
            .iter()
            .filter(|jwk| jwk.common.key_id.as_deref() == Some(kid))
            .find(|jwk| verifies_rs256(jwk))
            .ok_or(AuthError::UnknownKid)?;
        // A key the issuer published but we can't build a verifier from is the
        // issuer's problem, not the caller's — hence `Jwks`, which maps to a
        // 5xx, and not a 401 blaming a token that never got to be checked.
        let key = DecodingKey::from_jwk(jwk)
            .map_err(|_| AuthError::Jwks("key set contains an unusable signing key".into()))?;

        decode::<C>(token, &key, &checks.validation())
            .map(|data| data.claims)
            .map_err(|err| invalid_token(&err))
    }
}

/// [`VerifiedIdentity`]'s claim rules, applied to claims that already passed
/// every cryptographic and spec-claim check.
fn identity_from(claims: Claims) -> Result<VerifiedIdentity, AuthError> {
    // Services key their user rows on email (usually a UNIQUE NOT NULL
    // column), so a missing one must be rejected rather than collapsed to
    // "" — which would make every emailless token the same user.
    let email = claims
        .email
        .filter(|email| !email.is_empty())
        .ok_or(AuthError::MissingEmail)?;

    // Hardening over the original implementation this crate replaced,
    // which accepted `sub: ""`. An empty subject is the same
    // collapse-to-one-user failure as an empty email, one layer down.
    if claims.sub.is_empty() {
        return Err(AuthError::MissingSubject);
    }

    Ok(VerifiedIdentity {
        sub: claims.sub,
        email,
        name: claims.name.unwrap_or_default(),
    })
}

/// Whether `jwk` is an RSA key its issuer allows for RS256 signature
/// verification. An absent `alg`, `use` or `key_ops` allows it (RFC 7517 makes
/// all three optional); a present one must say RS256, say `sig`, or include
/// `verify`. Anything else, an unrecognised label included, rules the key out.
fn verifies_rs256(jwk: &Jwk) -> bool {
    let common = &jwk.common;
    matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
        && common
            .key_algorithm
            .is_none_or(|alg| alg == KeyAlgorithm::RS256)
        && common
            .public_key_use
            .as_ref()
            .is_none_or(|key_use| *key_use == PublicKeyUse::Signature)
        && common
            .key_operations
            .as_ref()
            .is_none_or(|ops| ops.contains(&KeyOperations::Verify))
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::errors::ErrorKind;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::{json, Value};
    use wiremock::{MockServer, ResponseTemplate};

    use super::*;
    use crate::mock_issuer::{
        issuer, issuer_then, jwks_body, jwks_url_of, primary_body, primary_issuer,
    };
    use crate::test_support::{TestClaims, TestKey, AUDIENCE, ISSUER, PRIMARY_KID};

    fn verify(token: &str) -> Result<VerifiedIdentity, AuthError> {
        Verifier::verify_with_jwks(
            token,
            &TestKey::primary().jwks(),
            PRIMARY_KID,
            ISSUER,
            AUDIENCE,
        )
    }

    fn claims() -> TestClaims {
        TestClaims::new(ISSUER, AUDIENCE)
    }

    #[test]
    fn a_good_token_yields_its_identity() {
        let token = TestKey::primary().mint(
            &claims()
                .subject("kratos-uuid-1")
                .email("u@example.com")
                .name("Test User")
                .build(),
        );

        let identity = verify(&token).expect("valid token");

        assert_eq!(identity.sub, "kratos-uuid-1");
        assert_eq!(identity.email, "u@example.com");
        assert_eq!(identity.name, "Test User");
    }

    #[test]
    fn a_missing_name_is_not_a_rejection() {
        let token = TestKey::primary().mint(&claims().without_name().build());

        assert_eq!(verify(&token).expect("valid token").name, "");
    }

    #[test]
    fn rejects_a_token_missing_its_issuer_or_audience() {
        // `set_issuer`/`set_audience` alone validate those claims only when
        // they are PRESENT — `set_required_spec_claims` is what makes
        // omission fatal. Regression test for a review-found hole (the
        // original implementation this crate replaced had the same gap):
        // without it, dropping `iss` or `aud` from an otherwise-valid token
        // bypassed both checks.
        for claim in ["iss", "aud"] {
            let mut claims = claims()
                .subject("kratos-uuid-1")
                .email("u@example.com")
                .build();
            claims
                .as_object_mut()
                .expect("claims build to an object")
                .remove(claim);

            let token = TestKey::primary().mint(&claims);
            let err = verify(&token).unwrap_err();

            assert!(
                matches!(err, AuthError::InvalidToken(_)),
                "token without {claim} must be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn rejects_a_malformed_token() {
        for garbage in ["", "not.a.jwt", "aaaa"] {
            let err = verify(garbage).unwrap_err();
            assert!(
                matches!(err, AuthError::InvalidToken(_)),
                "{garbage}: {err}"
            );
        }
    }

    #[test]
    fn rejects_an_unknown_kid() {
        let token = TestKey::primary().mint(&claims().build());

        let err = Verifier::verify_with_jwks(
            &token,
            &TestKey::primary().jwks(),
            "no-such-kid",
            ISSUER,
            AUDIENCE,
        )
        .unwrap_err();

        assert!(matches!(err, AuthError::UnknownKid), "{err}");
    }

    #[test]
    fn rejects_a_token_signed_by_another_key() {
        // Signed by key 2 but labelled with key 1's kid: the shape of a
        // forgery, and the reason the signature is checked against the key the
        // *set* names rather than the one the token claims.
        let token = TestKey::secondary().mint_with_kid(PRIMARY_KID, &claims().build());

        let err = verify(&token).unwrap_err();

        assert_eq!(err.to_string(), "token rejected: signature is invalid");
    }

    #[test]
    fn rejects_a_symmetric_algorithm() {
        // HS256 with the public modulus as the "secret" — the classic
        // algorithm-confusion forgery. `Validation::new(RS256)` refuses it.
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(PRIMARY_KID.to_string());
        let token = encode(
            &header,
            &claims().build(),
            &EncodingKey::from_secret(b"public key material"),
        )
        .expect("sign");

        let err = verify(&token).unwrap_err();

        assert!(matches!(err, AuthError::InvalidToken(_)), "{err}");
    }

    #[test]
    fn rejects_a_foreign_issuer() {
        let token =
            TestKey::primary().mint(&TestClaims::new("https://evil.example", AUDIENCE).build());

        let err = verify(&token).unwrap_err();

        assert_eq!(err.to_string(), "token rejected: issuer is not accepted");
    }

    #[test]
    fn rejects_another_services_audience() {
        let token = TestKey::primary().mint(&TestClaims::new(ISSUER, "some-other-app").build());

        let err = verify(&token).unwrap_err();

        assert_eq!(err.to_string(), "token rejected: audience is not accepted");
    }

    #[test]
    fn rejects_an_expired_token() {
        let token = TestKey::primary().mint(&claims().expires_in(-3600).build());

        let err = verify(&token).unwrap_err();

        assert_eq!(err.to_string(), "token rejected: token has expired");
    }

    #[test]
    fn rejects_an_empty_email() {
        let token = TestKey::primary().mint(&claims().email("").build());

        assert!(matches!(
            verify(&token).unwrap_err(),
            AuthError::MissingEmail
        ));
    }

    #[test]
    fn rejects_a_missing_email() {
        let token = TestKey::primary().mint(&claims().without_email().build());

        assert!(matches!(
            verify(&token).unwrap_err(),
            AuthError::MissingEmail
        ));
    }

    #[test]
    fn rejects_an_empty_sub() {
        let token = TestKey::primary().mint(&claims().subject("").build());

        assert!(matches!(
            verify(&token).unwrap_err(),
            AuthError::MissingSubject
        ));
    }

    #[test]
    fn rejects_a_missing_sub() {
        // No `sub` key at all, not just an empty one.
        let mut without_sub = claims().build();
        without_sub
            .as_object_mut()
            .expect("claims are an object")
            .remove("sub");
        let token = TestKey::primary().mint(&without_sub);

        assert!(matches!(
            verify(&token).unwrap_err(),
            AuthError::MissingSubject
        ));
    }

    #[test]
    fn no_error_message_contains_the_token() {
        let token = TestKey::secondary().mint_with_kid(PRIMARY_KID, &claims().build());

        let message = verify(&token).unwrap_err().to_string();

        assert!(!message.contains(&token));
        assert!(!message.contains(PRIMARY_KID));
    }

    // --- the generic claims path ---------------------------------------------

    /// A claim set some other kind of token carries: no email in sight, a
    /// space-separated `scope` string and Hydra's `scp` array.
    #[derive(Debug, serde::Deserialize)]
    struct ResourceClaims {
        sub: String,
        #[serde(default)]
        scope: Option<String>,
        #[serde(default)]
        scp: Vec<String>,
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default)]
        email: Option<String>,
    }

    fn resource_claims(token: &str) -> Result<ResourceClaims, AuthError> {
        Verifier::claims_with_jwks(
            token,
            &TestKey::primary().jwks(),
            PRIMARY_KID,
            ISSUER,
            AUDIENCE,
        )
    }

    #[test]
    fn claims_with_jwks_returns_the_callers_claim_type() {
        let token = TestKey::primary().mint(
            &claims()
                .subject("kratos-uuid-1")
                .without_email()
                .claim("scope", json!("files:read files:write"))
                .claim("scp", json!(["files:read"]))
                .claim("client_id", json!("connector-1"))
                .build(),
        );

        let claims = resource_claims(&token).expect("valid token");

        assert_eq!(claims.sub, "kratos-uuid-1");
        assert_eq!(claims.scope.as_deref(), Some("files:read files:write"));
        assert_eq!(claims.scp, ["files:read"]);
        assert_eq!(claims.client_id.as_deref(), Some("connector-1"));
        assert_eq!(claims.email, None);
    }

    #[test]
    fn claims_with_jwks_applies_no_email_or_subject_rules() {
        // Both are `verify_with_jwks` rejections; the generic path leaves
        // them to its caller.
        for spoiled in [
            claims().without_email(),
            claims().email(""),
            claims().subject(""),
        ] {
            let token = TestKey::primary().mint(&spoiled.build());

            assert!(matches!(
                verify(&token).unwrap_err(),
                AuthError::MissingEmail | AuthError::MissingSubject
            ));
            Verifier::claims_with_jwks::<Value>(
                &token,
                &TestKey::primary().jwks(),
                PRIMARY_KID,
                ISSUER,
                AUDIENCE,
            )
            .expect("the generic path checks no claim semantics");
        }
    }

    #[test]
    fn claims_with_jwks_runs_every_cryptographic_and_spec_claim_check() {
        let wrong_key = TestKey::secondary().mint_with_kid(PRIMARY_KID, &claims().build());
        let foreign_issuer =
            TestKey::primary().mint(&TestClaims::new("https://evil.example", AUDIENCE).build());
        let foreign_audience =
            TestKey::primary().mint(&TestClaims::new(ISSUER, "some-other-app").build());
        let expired = TestKey::primary().mint(&claims().expires_in(-3600).build());
        let mut without_aud = claims().build();
        without_aud
            .as_object_mut()
            .expect("claims are an object")
            .remove("aud");
        let without_aud = TestKey::primary().mint(&without_aud);

        for (token, expected) in [
            (&wrong_key, "token rejected: signature is invalid"),
            (&foreign_issuer, "token rejected: issuer is not accepted"),
            (
                &foreign_audience,
                "token rejected: audience is not accepted",
            ),
            (&expired, "token rejected: token has expired"),
            (&without_aud, "token rejected: a required claim is missing"),
        ] {
            let err = resource_claims(token).unwrap_err();
            assert_eq!(err.to_string(), expected);
        }

        let err = Verifier::claims_with_jwks::<Value>(
            &TestKey::primary().mint(&claims().build()),
            &TestKey::primary().jwks(),
            "no-such-kid",
            ISSUER,
            AUDIENCE,
        )
        .unwrap_err();
        assert!(matches!(err, AuthError::UnknownKid), "{err}");
    }

    #[test]
    fn a_claim_shape_the_caller_cannot_read_is_malformed_not_quoted() {
        // `scope` must be a string for `ResourceClaims`; the serde message
        // for this would quote the value.
        let token = TestKey::primary().mint(&claims().claim("scope", json!(["hunter2"])).build());

        let err = resource_claims(&token).unwrap_err();

        assert_eq!(err.to_string(), "token rejected: claims are malformed");
        assert!(!format!("{err:?}").contains("hunter2"));
    }

    // --- the network-facing half ------------------------------------------

    fn verifier_against(server: &MockServer) -> Verifier {
        Verifier::new(
            SlauthConfig {
                issuer: ISSUER.into(),
                jwks_url: jwks_url_of(server),
                audience: AUDIENCE.into(),
                pat_validate_url: None,
            },
            reqwest::Client::new(),
        )
    }

    #[tokio::test]
    async fn verify_bearer_fetches_the_key_set_once_for_many_tokens() {
        let server = primary_issuer(1).await;
        let verifier = verifier_against(&server);

        for i in 0..3 {
            let token = TestKey::primary().mint(&claims().subject(format!("user-{i}")).build());
            let identity = verifier.verify_bearer(&token).await.expect("valid token");
            assert_eq!(identity.sub, format!("user-{i}"));
        }
    }

    #[tokio::test]
    async fn verify_bearer_claims_fetches_once_and_skips_the_identity_rules() {
        let server = primary_issuer(1).await;
        let verifier = verifier_against(&server);

        for i in 0..2 {
            let token = TestKey::primary().mint(
                &claims()
                    .subject(format!("user-{i}"))
                    .without_email()
                    .claim("scope", json!("files:read"))
                    .build(),
            );
            let claims: ResourceClaims = verifier
                .verify_bearer_claims(&token)
                .await
                .expect("valid token");
            assert_eq!(claims.sub, format!("user-{i}"));
            assert_eq!(claims.scope.as_deref(), Some("files:read"));
        }
    }

    #[tokio::test]
    async fn verify_bearer_claims_rejects_like_verify_bearer() {
        let outage = issuer(ResponseTemplate::new(503), 1).await;
        let token = TestKey::primary().mint(&claims().build());
        let err = verifier_against(&outage)
            .verify_bearer_claims::<Value>(&token)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Jwks(_)), "{err}");

        let silent = MockServer::start().await;
        let err = verifier_against(&silent)
            .verify_bearer_claims::<Value>("not-a-jwt")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::MalformedToken), "{err}");
    }

    #[tokio::test]
    async fn verify_bearer_rejects_a_token_with_no_kid() {
        let server = MockServer::start().await;
        // No mock is mounted: reaching the issuer at all would be the bug.
        let verifier = verifier_against(&server);
        let token = encode(
            &Header::new(Algorithm::RS256),
            &claims().build(),
            &EncodingKey::from_rsa_pem(TestKey::primary().pem().as_bytes()).expect("key"),
        )
        .expect("sign");

        let err = verifier.verify_bearer(&token).await.unwrap_err();

        assert!(matches!(err, AuthError::MissingKid), "{err}");
    }

    #[tokio::test]
    async fn verify_bearer_rejects_garbage_without_fetching() {
        let server = MockServer::start().await;
        let verifier = verifier_against(&server);

        let err = verifier.verify_bearer("not-a-jwt").await.unwrap_err();

        assert!(matches!(err, AuthError::MalformedToken), "{err}");
    }

    /// The defect report's end-to-end repro, through the public entry point:
    /// warm the cache, let the key set pass its TTL, and have the issuer go
    /// down. The refetch fails, and so must the token right after it, inside
    /// the backoff that failure opened (v0.8.0 accepted it there, up to one
    /// interval past the TTL).
    #[tokio::test]
    async fn verify_bearer_refuses_a_token_once_its_key_set_expired_and_cannot_be_refetched() {
        // The issuer answers once, with its keys, and is down after that:
        // exactly one failed refetch is expected, not two.
        let server = issuer_then(primary_body(), ResponseTemplate::new(500)).await;
        // The defaults, and no lookup in the refresh window: the first lookup
        // past the TTL is the one that refetches.
        let verifier = verifier_against(&server);
        let token = TestKey::primary().mint(&claims().build());

        verifier.verify_bearer(&token).await.expect("warm cache");
        verifier
            .inner
            .jwks
            .advance_for_test(crate::JWKS_TTL + std::time::Duration::from_secs(1));

        for attempt in ["the refetch that fails", "inside the backoff it opened"] {
            let err = verifier.verify_bearer(&token).await.unwrap_err();
            assert!(matches!(err, AuthError::Jwks(_)), "{attempt}: {err}");
        }
    }

    #[tokio::test]
    async fn verify_bearer_surfaces_a_jwks_outage() {
        let server = issuer(ResponseTemplate::new(503), 1).await;
        let verifier = verifier_against(&server);
        let token = TestKey::primary().mint(&claims().build());

        let err = verifier.verify_bearer(&token).await.unwrap_err();

        assert!(matches!(err, AuthError::Jwks(_)), "{err}");
    }

    // --- the crypto backend -------------------------------------------------

    /// jsonwebtoken 10+ takes its crypto from crate features, unified across
    /// the whole graph this test is built in (the workspace's, and in a
    /// consumer, the consumer's). With exactly one of `aws_lc_rs` and
    /// `rust_crypto` on it works; with neither, or both, it still compiles
    /// cleanly and then panics at the first sign or verify. That is how the
    /// bare 9 → 11 bump passed clippy and failed only at test time. So this
    /// signs with the test-support key and verifies the token the way a
    /// service does (JWKS over HTTP into `verify_bearer`) and with a direct
    /// `jsonwebtoken::decode`. The wrong-key decode proves the backend really
    /// checks a signature rather than accepting whatever it is handed.
    #[tokio::test]
    async fn signing_and_verifying_work_on_the_one_crypto_backend() {
        let server = primary_issuer(1).await;
        let token = TestKey::primary().mint(&claims().subject("backend-check").build());

        let identity = verifier_against(&server)
            .verify_bearer(&token)
            .await
            .expect("a minted token verifies through the JWKS path");
        assert_eq!(identity.sub, "backend-check");

        let decoding_key = |key: TestKey| {
            let jwks = key.jwks();
            DecodingKey::from_jwk(jwks.find(key.kid()).expect("the key's own kid"))
                .expect("committed test JWK is a usable RSA key")
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[AUDIENCE]);

        let data = decode::<Claims>(&token, &decoding_key(TestKey::primary()), &validation)
            .expect("a minted token decodes directly");
        assert_eq!(data.claims.sub, "backend-check");

        let err = decode::<Claims>(&token, &decoding_key(TestKey::secondary()), &validation)
            .expect_err("a token must not verify under a key that did not sign it");
        assert_eq!(err.kind(), &ErrorKind::InvalidSignature);
    }

    // --- which key may verify -----------------------------------------------

    /// One key of a committed test JWKS, as JSON, to relabel.
    fn key_json(key: TestKey) -> Value {
        let set: Value = serde_json::from_str(key.jwks_json()).expect("committed JWKS");
        set["keys"][0].clone()
    }

    /// The primary key's JWK with `changes` applied (a `null` removes the
    /// member), as JWKS text, the form the cache fetches.
    fn primary_jwks_json_with(changes: Value) -> String {
        let mut key = key_json(TestKey::primary());
        let members = key.as_object_mut().expect("a JWK is an object");
        for (name, value) in changes.as_object().expect("changes are an object") {
            if value.is_null() {
                members.remove(name);
            } else {
                members.insert(name.clone(), value.clone());
            }
        }
        json!({ "keys": [key] }).to_string()
    }

    fn parse(jwks_json: &str) -> JwkSet {
        serde_json::from_str(jwks_json).expect("parses as a JWKS")
    }

    /// A good token from the primary key, checked against `jwks`.
    fn verify_against(jwks: &JwkSet) -> Result<VerifiedIdentity, AuthError> {
        let token = TestKey::primary().mint(&claims().build());
        Verifier::verify_with_jwks(&token, jwks, PRIMARY_KID, ISSUER, AUDIENCE)
    }

    #[test]
    fn a_key_labelled_for_another_algorithm_does_not_verify() {
        // The key really did sign the token; only its `alg` label is wrong.
        // `RSA-OAEP-512` is a name jsonwebtoken does not know: 9 refused the
        // whole set over it, 11 parses it as `UNKNOWN_ALGORITHM`, and
        // `DecodingKey::from_jwk` never looks at it.
        for alg in [
            "RSA-OAEP-512",
            "RSA-OAEP",
            "RSA-OAEP-256",
            "RSA1_5",
            "RS512",
            "PS256",
        ] {
            let jwks = parse(&primary_jwks_json_with(json!({ "alg": alg })));

            let err = verify_against(&jwks).unwrap_err();

            assert!(matches!(err, AuthError::UnknownKid), "alg {alg}: {err}");
        }
    }

    #[test]
    fn a_key_for_encryption_does_not_verify() {
        let jwks = parse(&primary_jwks_json_with(json!({ "use": "enc" })));

        let err = verify_against(&jwks).unwrap_err();

        assert!(matches!(err, AuthError::UnknownKid), "{err}");
    }

    #[test]
    fn a_key_whose_operations_exclude_verify_does_not_verify() {
        for ops in [json!(["encrypt", "wrapKey"]), json!(["sign"]), json!([])] {
            let jwks = parse(&primary_jwks_json_with(json!({ "key_ops": ops })));

            let err = verify_against(&jwks).unwrap_err();

            assert!(matches!(err, AuthError::UnknownKid), "key_ops {ops}: {err}");
        }
    }

    #[test]
    fn a_non_rsa_key_under_the_kid_does_not_verify() {
        // Unlabelled, so the key type is the only thing ruling each one out:
        // an EC P-256 public key (RFC 7517 appendix A.1) and a symmetric key.
        let foreign = [
            json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                "kid": PRIMARY_KID,
            }),
            json!({ "kty": "oct", "k": "cHVibGljIGtleSBtYXRlcmlhbA", "kid": PRIMARY_KID }),
        ];
        for key in foreign {
            let jwks = parse(&json!({ "keys": [key] }).to_string());

            let err = verify_against(&jwks).unwrap_err();

            assert!(matches!(err, AuthError::UnknownKid), "{key}: {err}");
        }
    }

    #[test]
    fn a_signing_key_verifies_with_or_without_its_labels() {
        for changes in [
            json!({}),
            json!({ "use": null, "alg": null }),
            json!({ "use": null, "alg": null, "key_ops": ["verify"] }),
            json!({ "key_ops": ["sign", "verify"] }),
        ] {
            let jwks = parse(&primary_jwks_json_with(changes.clone()));

            verify_against(&jwks).unwrap_or_else(|err| panic!("{changes}: {err}"));
        }
    }

    #[test]
    fn an_encryption_key_sharing_the_kid_does_not_hide_the_signing_key() {
        // A different keypair's public half, published as an encryption key
        // under the same kid and listed first.
        let mut encryption = key_json(TestKey::secondary());
        encryption["kid"] = json!(PRIMARY_KID);
        encryption["use"] = json!("enc");
        encryption["alg"] = json!("RSA-OAEP");
        let jwks =
            parse(&json!({ "keys": [encryption, key_json(TestKey::primary())] }).to_string());

        verify_against(&jwks).expect("the signing key under the kid verifies");
    }

    #[tokio::test]
    async fn verify_bearer_refuses_a_fetched_key_labelled_for_encryption() {
        // Through the fetch: jsonwebtoken 11 parses the set (9 refused it, a
        // `Jwks` outage for every token), and the key still may not verify.
        let jwks_json = primary_jwks_json_with(json!({ "alg": "RSA-OAEP-512", "use": "enc" }));
        let server = issuer(jwks_body(&jwks_json), 1).await;
        let token = TestKey::primary().mint(&claims().build());

        let err = verifier_against(&server)
            .verify_bearer(&token)
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::UnknownKid), "{err}");
    }

    // --- claim checks: `ClaimChecks` and `claims_with_jwks_checked` ---------

    /// A stand-in for a per-client issuer like WorkOS's, which binds the
    /// client, so its tokens carry no `aud`.
    const CLIENT_ISSUER: &str = "https://api.workos.test/user_management/client_01TEST";

    /// The rules lumen applies to WorkOS tokens: no `aud` check, no leeway,
    /// `nbf` checked (the default).
    fn client_checks() -> ClaimChecks {
        ClaimChecks::new(CLIENT_ISSUER, Audience::NotValidated).with_leeway(Duration::ZERO)
    }

    /// A WorkOS-shaped claim set: the client issuer, no `aud`, no email.
    fn client_claims() -> TestClaims {
        TestClaims::new(CLIENT_ISSUER, "")
            .without_audience()
            .without_email()
            .without_name()
            .subject("user_01TEST")
    }

    fn mint(claims: TestClaims) -> String {
        TestKey::primary().mint(&claims.build())
    }

    /// `claims`, minted with `claim` removed.
    fn mint_without(claims: TestClaims, claim: &str) -> String {
        let mut built = claims.build();
        let removed = built
            .as_object_mut()
            .expect("claims are an object")
            .remove(claim);
        assert!(removed.is_some(), "the claim set had a {claim} to remove");
        TestKey::primary().mint(&built)
    }

    fn checked(token: &str, checks: &ClaimChecks) -> Result<Value, AuthError> {
        Verifier::claims_with_jwks_checked(token, &TestKey::primary().jwks(), PRIMARY_KID, checks)
    }

    #[track_caller]
    fn assert_rejected(result: Result<Value, AuthError>, reason: &str, case: &str) {
        match result {
            Ok(claims) => panic!("{case}: accepted, expected \"{reason}\": {claims}"),
            Err(err) => assert_eq!(
                err.to_string(),
                format!("token rejected: {reason}"),
                "{case}"
            ),
        }
    }

    /// `claims` signed HS256 under the primary kid, with a public string as
    /// the HMAC secret: the algorithm-confusion forgery.
    fn hs256(claims: TestClaims) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(PRIMARY_KID.to_string());
        encode(
            &header,
            &claims.build(),
            &EncodingKey::from_secret(b"public key material"),
        )
        .expect("sign")
    }

    /// RFC 4648 base64url, unpadded: for assembling the header of a token
    /// jsonwebtoken cannot produce.
    fn base64url(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let bits = chunk.iter().enumerate().fold(0u32, |bits, (i, &byte)| {
                bits | (u32::from(byte) << (16 - 8 * i))
            });
            for i in 0..=chunk.len() {
                out.push(char::from(ALPHABET[((bits >> (18 - 6 * i)) & 63) as usize]));
            }
        }
        out
    }

    /// `claims` under a hand-written `header` (JSON text), with an empty
    /// signature.
    fn unsigned(header: &str, claims: TestClaims) -> String {
        let payload = serde_json::to_vec(&claims.build()).expect("claims serialize");
        format!("{}.{}.", base64url(header.as_bytes()), base64url(&payload))
    }

    /// An `alg: none` token naming the primary kid.
    fn alg_none(claims: TestClaims) -> String {
        unsigned(
            &format!(r#"{{"alg":"none","typ":"JWT","kid":"{PRIMARY_KID}"}}"#),
            claims,
        )
    }

    #[test]
    fn the_hand_assembled_header_is_one_jsonwebtoken_reads() {
        // The encoder against RFC 4648's vectors and the URL-safe alphabet.
        for (input, expected) in [
            (&b"f"[..], "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foobar", "Zm9vYmFy"),
            (&[0xfb, 0xff], "-_8"),
        ] {
            assert_eq!(base64url(input), expected);
        }
        // The control for `alg_none`: the same assembly with a real
        // algorithm parses, kid and all, so `none` is what is refused.
        let token = unsigned(
            &format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{PRIMARY_KID}"}}"#),
            client_claims(),
        );
        let header = decode_header(&token).expect("an RS256 header parses");
        assert_eq!(header.kid.as_deref(), Some(PRIMARY_KID));
        assert!(decode_header(alg_none(client_claims())).is_err());
    }

    #[test]
    fn claim_checks_default_to_a_60s_leeway_with_nbf_checked() {
        let checks = ClaimChecks::new(CLIENT_ISSUER, Audience::NotValidated);

        assert_eq!(checks.issuer(), CLIENT_ISSUER);
        assert_eq!(checks.audience(), &Audience::NotValidated);
        assert_eq!(checks.leeway(), Duration::from_secs(60));
        assert_eq!(DEFAULT_LEEWAY, Duration::from_secs(60));
        assert!(checks.validates_nbf());
        assert!(!checks.clone().with_nbf_validation(false).validates_nbf());
    }

    #[test]
    fn a_leeway_is_whole_seconds_and_at_most_a_day() {
        let with = |leeway| client_checks().with_leeway(leeway);
        assert_eq!(
            with(Duration::from_millis(1_500)).leeway(),
            Duration::from_secs(1)
        );
        assert_eq!(with(Duration::from_millis(999)).leeway(), Duration::ZERO);
        assert_eq!(
            with(Duration::from_secs(86_400)).leeway(),
            Duration::from_secs(86_400)
        );
        assert_eq!(with(Duration::MAX).leeway(), Duration::from_secs(86_400));

        // Capped, the leeway reaches jsonwebtoken's unchecked `now - leeway`
        // and `now + leeway` as a value they can hold, and means a day.
        let a_day = with(Duration::MAX);
        checked(&mint(client_claims()), &a_day).expect("a fresh token");
        checked(&mint(client_claims().expires_in(-3600)), &a_day).expect("an hour past exp");
        checked(&mint(client_claims().not_before_in(3600)), &a_day).expect("an hour before nbf");
        assert_rejected(
            checked(&mint(client_claims().expires_in(-2 * 86_400)), &a_day),
            "token has expired",
            "two days past exp",
        );
    }

    #[test]
    fn not_validated_accepts_a_token_with_or_without_an_aud() {
        for (case, claims) in [
            ("no aud", client_claims()),
            (
                "another service's aud",
                client_claims().claim("aud", json!("some-other-app")),
            ),
            (
                "an aud array",
                client_claims().claim("aud", json!(["a", "b"])),
            ),
        ] {
            let claims = checked(&mint(claims), &client_checks())
                .unwrap_or_else(|err| panic!("{case}: {err}"));
            assert_eq!(claims["sub"], json!("user_01TEST"), "{case}");
        }
    }

    #[test]
    fn required_rejects_a_missing_or_wrong_aud_and_accepts_the_right_one() {
        let checks = ClaimChecks::new(ISSUER, Audience::Required(AUDIENCE.into()));

        checked(&mint(claims()), &checks).expect("the configured audience");
        checked(
            &mint(claims().claim("aud", json!(["x", AUDIENCE]))),
            &checks,
        )
        .expect("an array containing it");
        assert_rejected(
            checked(&mint(TestClaims::new(ISSUER, "some-other-app")), &checks),
            "audience is not accepted",
            "wrong aud",
        );
        assert_rejected(
            checked(&mint(claims().without_audience()), &checks),
            "a required claim is missing",
            "missing aud",
        );
    }

    #[test]
    fn a_zero_leeway_refuses_a_token_one_second_past_its_exp() {
        assert_rejected(
            checked(&mint(client_claims().expires_in(-1)), &client_checks()),
            "token has expired",
            "exp = now - 1, leeway 0",
        );
    }

    #[test]
    fn a_60s_leeway_accepts_a_token_30s_past_its_exp_and_no_further_than_60() {
        let sixty = client_checks().with_leeway(Duration::from_secs(60));
        let token = mint(client_claims().expires_in(-30));

        checked(&token, &sixty).expect("30 s past exp, inside 60 s");
        checked(
            &token,
            &ClaimChecks::new(CLIENT_ISSUER, Audience::NotValidated),
        )
        .expect("the default leeway is the same 60 s");
        assert_rejected(
            checked(&mint(client_claims().expires_in(-90)), &sixty),
            "token has expired",
            "90 s past exp",
        );
    }

    #[test]
    fn nbf_is_checked_when_asked_and_never_required() {
        let checking = client_checks();
        let ignoring = client_checks().with_nbf_validation(false);
        let not_yet = mint(client_claims().not_before_in(30));
        let valid_since = mint(client_claims().not_before_in(-30));
        let without = mint(client_claims());
        let malformed = mint(client_claims().claim("nbf", json!("soon")));

        assert_rejected(
            checked(&not_yet, &checking),
            "token is not valid yet",
            "nbf = now + 30, leeway 0",
        );
        checked(&not_yet, &ignoring).expect("nbf not checked");
        assert_rejected(
            checked(&malformed, &checking),
            "token is malformed",
            "nbf a string",
        );
        checked(&malformed, &ignoring).expect("nbf not checked, whatever it holds");
        for checks in [&checking, &ignoring] {
            checked(&valid_since, checks).expect("nbf in the past");
            checked(&without, checks).expect("no nbf");
        }
    }

    #[test]
    fn iss_and_exp_are_required_and_iss_is_exact() {
        let other_client =
            TestClaims::new("https://api.workos.test/user_management/client_02OTHER", "")
                .without_audience();
        let trailing_slash = TestClaims::new(format!("{CLIENT_ISSUER}/"), "").without_audience();

        for (case, token, reason) in [
            (
                "missing iss",
                mint_without(client_claims(), "iss"),
                "a required claim is missing",
            ),
            (
                "missing exp",
                mint_without(client_claims(), "exp"),
                "a required claim is missing",
            ),
            (
                "another client's iss",
                mint(other_client),
                "issuer is not accepted",
            ),
            (
                "a trailing slash",
                mint(trailing_slash),
                "issuer is not accepted",
            ),
        ] {
            assert_rejected(checked(&token, &client_checks()), reason, case);
        }
    }

    /// jsonwebtoken's rule, as `ClaimChecks`' docs state it: an `iss` array
    /// passes when it holds the issuer, and only then.
    #[test]
    fn an_iss_array_passes_only_when_it_holds_the_issuer() {
        let holding = client_claims().claim("iss", json!(["https://other.test", CLIENT_ISSUER]));
        let lacking = client_claims().claim("iss", json!(["https://other.test"]));

        checked(&mint(holding), &client_checks()).expect("the array holds the issuer");
        assert_rejected(
            checked(&mint(lacking), &client_checks()),
            "issuer is not accepted",
            "the array lacks the issuer",
        );
    }

    #[test]
    fn checked_refuses_alg_none_and_hs256() {
        for (case, token) in [
            ("HS256", hs256(client_claims())),
            ("alg none", alg_none(client_claims())),
        ] {
            let err = checked(&token, &client_checks()).unwrap_err();
            assert!(matches!(err, AuthError::InvalidToken(_)), "{case}: {err}");
        }
        assert_rejected(
            checked(&hs256(client_claims()), &client_checks()),
            "algorithm is not accepted",
            "HS256",
        );
    }

    #[test]
    fn checked_shares_the_key_fitness_rules() {
        let token = mint(client_claims());

        let err = Verifier::claims_with_jwks_checked::<Value>(
            &token,
            &TestKey::primary().jwks(),
            "no-such-kid",
            &client_checks(),
        )
        .unwrap_err();
        assert!(matches!(err, AuthError::UnknownKid), "unknown kid: {err}");

        let encryption_key = parse(&primary_jwks_json_with(json!({ "use": "enc" })));
        let err = Verifier::claims_with_jwks_checked::<Value>(
            &token,
            &encryption_key,
            PRIMARY_KID,
            &client_checks(),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuthError::UnknownKid),
            "encryption key: {err}"
        );
    }

    #[test]
    fn verifier_new_keeps_slauths_rules() {
        let verifier = Verifier::new(
            SlauthConfig {
                issuer: ISSUER.into(),
                jwks_url: "http://127.0.0.1:1/jwks".into(),
                audience: AUDIENCE.into(),
                pat_validate_url: None,
            },
            reqwest::Client::new(),
        );

        assert_eq!(
            verifier.claim_checks(),
            &ClaimChecks::new(ISSUER, Audience::Required(AUDIENCE.into()))
                .with_nbf_validation(false)
        );
        assert_eq!(verifier.claim_checks().leeway(), Duration::from_secs(60));
        // Through `claims_with_jwks`, the same rules, as v0.8.0 applied them:
        // 60 s of leeway on `exp`, and `nbf` never looked at.
        for (case, token) in [
            ("30 s past exp", mint(claims().expires_in(-30))),
            ("nbf 30 s ahead", mint(claims().not_before_in(30))),
            ("nbf a string", mint(claims().claim("nbf", json!("soon")))),
        ] {
            resource_claims(&token).unwrap_or_else(|err| panic!("{case}: {err}"));
        }
    }

    // --- `Verifier::for_issuer` ---------------------------------------------

    /// What a consumer like lumen reads out of a WorkOS access token.
    #[derive(Debug, serde::Deserialize)]
    struct ClientClaims {
        sub: String,
        #[serde(default)]
        sid: Option<String>,
    }

    fn client_verifier(server: &MockServer, jwks_ttl: Option<Duration>) -> Verifier {
        Verifier::for_issuer(
            client_checks(),
            jwks_url_of(server),
            jwks_ttl,
            reqwest::Client::new(),
        )
    }

    #[test]
    fn a_for_issuer_verifiers_config_is_synthesized_and_its_rules_are_its_own() {
        let checks = client_checks();
        let verifier = Verifier::for_issuer(
            checks.clone(),
            "https://jwks.test/jwks",
            None,
            reqwest::Client::new(),
        );

        assert_eq!(verifier.claim_checks(), &checks);
        let config = verifier.config();
        assert_eq!(config.issuer, CLIENT_ISSUER);
        assert_eq!(config.jwks_url, "https://jwks.test/jwks");
        assert_eq!(config.audience, NOT_VALIDATED_AUDIENCE);
        assert!(
            config.audience.starts_with('\0'),
            "NotValidated's sentinel is no audience an issuer mints, and never empty: {:?}",
            config.audience
        );
        assert_eq!(config.pat_validate_url, None);

        let required = Verifier::for_issuer(
            ClaimChecks::new(ISSUER, Audience::Required(AUDIENCE.into())),
            "https://jwks.test/jwks",
            None,
            reqwest::Client::new(),
        );
        assert_eq!(required.config().audience, AUDIENCE);
    }

    /// `config()` on a `NotValidated` verifier, fed back into
    /// `Verifier::new`, gets slauth's rules: `aud` required, 60 s leeway,
    /// `nbf` unchecked. Had its audience been `""`, a token the original
    /// refuses (`aud: ""` with an `nbf` an hour ahead, or 30 s past `exp`)
    /// would pass the rebuilt one. With the sentinel it refuses those, and the
    /// audience-less token the original accepts too.
    #[tokio::test]
    async fn a_verifier_rebuilt_from_a_not_validated_config_accepts_no_token() {
        // One fetch for each verifier: each builds its own cache.
        let server = primary_issuer(2).await;
        let original = client_verifier(&server, None);
        let rebuilt = Verifier::new(original.config().clone(), reqwest::Client::new());

        let audience_less = mint(client_claims());
        let empty_aud = || client_claims().claim("aud", json!(""));
        let nbf_ahead = mint(empty_aud().not_before_in(3600));
        let past_exp = mint(empty_aud().expires_in(-30));

        original
            .verify_bearer_claims::<Value>(&audience_less)
            .await
            .expect("the original accepts a WorkOS-shaped token");
        for (case, token, reason) in [
            (
                "aud \"\", nbf an hour ahead",
                &nbf_ahead,
                "token is not valid yet",
            ),
            ("aud \"\", 30 s past exp", &past_exp, "token has expired"),
        ] {
            assert_rejected(original.verify_bearer_claims(token).await, reason, case);
        }

        for (case, token, reason) in [
            ("no aud", &audience_less, "a required claim is missing"),
            (
                "aud \"\", nbf an hour ahead",
                &nbf_ahead,
                "audience is not accepted",
            ),
            (
                "aud \"\", 30 s past exp",
                &past_exp,
                "audience is not accepted",
            ),
        ] {
            assert_rejected(
                rebuilt.verify_bearer_claims(token).await,
                reason,
                &format!("rebuilt, {case}"),
            );
        }
    }

    #[tokio::test]
    async fn a_for_issuer_verifier_applies_its_own_rules() {
        let server = primary_issuer(1).await;
        let verifier = client_verifier(&server, None);

        let shaped = mint(client_claims().claim("sid", json!("session_01TEST")));
        let read: ClientClaims = verifier
            .verify_bearer_claims(&shaped)
            .await
            .expect("a WorkOS-shaped token: no aud, no email");
        assert_eq!(read.sub, "user_01TEST");
        assert_eq!(read.sid.as_deref(), Some("session_01TEST"));
        verifier
            .verify_bearer_claims::<Value>(&mint(client_claims().claim("aud", json!("any"))))
            .await
            .expect("an aud is not checked either");

        // Its leeway, `nbf` and issuer rules, not slauth's.
        for (case, token, reason) in [
            (
                "a second past exp",
                mint(client_claims().expires_in(-1)),
                "token has expired",
            ),
            (
                "nbf 30 s ahead",
                mint(client_claims().not_before_in(30)),
                "token is not valid yet",
            ),
            ("slauth's issuer", mint(claims()), "issuer is not accepted"),
        ] {
            assert_rejected(verifier.verify_bearer_claims(&token).await, reason, case);
        }

        // `verify_bearer` adds `VerifiedIdentity`'s rules on top: a token
        // with no email is no identity.
        let err = verifier.verify_bearer(&shaped).await.unwrap_err();
        assert!(matches!(err, AuthError::MissingEmail), "{err}");
        let identity = verifier
            .verify_bearer(&mint(client_claims().email("u@example.com")))
            .await
            .expect("with an email it is one");
        assert_eq!(identity.sub, "user_01TEST");
    }

    #[tokio::test]
    async fn a_for_issuer_verifier_refuses_bad_headers() {
        // Only the HS256 token gets as far as the key set.
        let server = primary_issuer(1).await;
        let verifier = client_verifier(&server, None);
        let no_kid = encode(
            &Header::new(Algorithm::RS256),
            &client_claims().build(),
            &EncodingKey::from_rsa_pem(TestKey::primary().pem().as_bytes()).expect("key"),
        )
        .expect("sign");

        let err = verifier
            .verify_bearer_claims::<Value>(&no_kid)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingKid), "no kid: {err}");

        let err = verifier
            .verify_bearer_claims::<Value>(&alg_none(client_claims()))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::MalformedToken), "alg none: {err}");

        assert_rejected(
            verifier.verify_bearer_claims(&hs256(client_claims())).await,
            "algorithm is not accepted",
            "HS256",
        );

        // Inside the refetch floor of that fetch: from memory, no request,
        // and a kid no fetched set held is a suppressed refetch.
        let token = TestKey::primary().mint_with_kid("no-such-kid", &client_claims().build());
        let err = verifier
            .verify_bearer_claims::<Value>(&token)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::UnseenKid), "unseen kid: {err}");
    }

    /// The plan's C1 inheritance test: `for_issuer` builds its own
    /// [`JwksCache`], so its key set is never served past the TTL it was
    /// given. Inside the TTL the cached set verifies with the issuer down;
    /// at the TTL, to the nanosecond, it is refused (`Jwks`, a 5xx at the
    /// consumer), both by the refetch that fails and by the lookup right
    /// after it, inside the backoff that failure opened.
    #[tokio::test]
    async fn a_for_issuer_verifier_never_serves_its_key_set_past_its_ttl() {
        const TTL: Duration = Duration::from_secs(60);
        // The issuer answers once, with its keys, and is down after that:
        // exactly one failed refetch is expected, so a lookup inside the TTL
        // that dialed it would fail the test when the server drops.
        let server = issuer_then(primary_body(), ResponseTemplate::new(500)).await;
        // TTL 60 s: under three refetch floors, so no refresh-ahead, and the
        // first lookup at the TTL is the one that refetches.
        let verifier = client_verifier(&server, Some(TTL));
        let token = mint(client_claims());

        verifier
            .verify_bearer_claims::<Value>(&token)
            .await
            .expect("warm cache");
        verifier
            .inner
            .jwks
            .advance_for_test(TTL - Duration::from_nanos(1));
        verifier
            .verify_bearer_claims::<Value>(&token)
            .await
            .expect("inside the TTL, from memory");

        verifier
            .inner
            .jwks
            .advance_for_test(Duration::from_nanos(1));
        for attempt in ["the refetch that fails", "inside the backoff it opened"] {
            let err = verifier
                .verify_bearer_claims::<Value>(&token)
                .await
                .unwrap_err();
            assert!(matches!(err, AuthError::Jwks(_)), "{attempt}: {err}");
            #[cfg(feature = "http")]
            assert_eq!(
                stridelabs_http::AppError::from(err).status(),
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "{attempt}"
            );
        }
    }

    /// No TTL is [`crate::JWKS_TTL`], not anything shorter: the same 61 s
    /// that a 60 s TTL refuses at is a plain hit.
    #[tokio::test]
    async fn a_for_issuer_verifier_without_a_ttl_caches_for_the_default() {
        let server = primary_issuer(1).await;
        let verifier = client_verifier(&server, None);
        let token = mint(client_claims());

        verifier
            .verify_bearer_claims::<Value>(&token)
            .await
            .expect("warm cache");
        verifier
            .inner
            .jwks
            .advance_for_test(Duration::from_secs(61));
        verifier
            .verify_bearer_claims::<Value>(&token)
            .await
            .expect("inside the default hour, from memory");
    }

    /// `?verifier` on a `for_issuer` verifier, and `?` on each part of it that
    /// holds a URL: the issuer's and the JWKS URL's userinfo and query, and
    /// the client's default headers, never print. The issuer and the endpoint
    /// are still named, redacted, everywhere they are held. (`Audience` has no
    /// row: it prints its identifier, which is configuration, not a secret.)
    #[test]
    fn a_for_issuer_verifier_never_debugs_url_material() {
        let issuer = "https://CANARY-user:CANARY-pass@issuer.example/user_management/client_01TEST?token=CANARY-token";
        let url = "http://CANARY-user:CANARY-pass@jwks.example:8443/jwks?token=CANARY-token";
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_static("Bearer CANARY-header"),
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("a plain client builds");
        let checks = ClaimChecks::new(issuer, Audience::NotValidated).with_leeway(Duration::ZERO);
        let verifier =
            Verifier::for_issuer(checks.clone(), url, Some(Duration::from_secs(60)), client);

        let shown_issuer = r#""https://issuer.example/user_management/client_01TEST""#;
        let shown_jwks = r#""http://jwks.example:8443/jwks""#;
        // Component to composite, and every leak listed: breaking one
        // part's redaction names exactly the rows it reaches.
        let rows = [
            ("ClaimChecks", format!("{checks:?}"), 1, 0),
            (
                "the synthesized SlauthConfig",
                format!("{:?}", verifier.config()),
                1,
                1,
            ),
            ("Verifier::for_issuer", format!("{verifier:?}"), 2, 2),
        ];
        let leaks: Vec<&str> = rows
            .iter()
            .filter(|(_, rendered, _, _)| rendered.contains("CANARY"))
            .map(|(name, _, _, _)| *name)
            .collect();
        assert!(
            leaks.is_empty(),
            "Debug leaked URL or client-header material in {leaks:?}: {rows:#?}"
        );
        for (name, rendered, issuers, endpoints) in &rows {
            assert_eq!(
                rendered.matches(shown_issuer).count(),
                *issuers,
                "{name} names the issuer, redacted: {rendered}"
            );
            assert_eq!(
                rendered.matches(shown_jwks).count(),
                *endpoints,
                "{name} names the JWKS endpoint, redacted: {rendered}"
            );
        }
    }
}
