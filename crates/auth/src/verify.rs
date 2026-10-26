//! Access-token verification: the thing this crate exists for.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{
    AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse, RSAKeyParameters,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::config::{redact_issuer, SlauthConfig};
use crate::error::{invalid_token, AuthError, UnusableReason};
use crate::jwks::JwksCache;
use crate::screen::{kid_for_lookup, ScreenPolicy};

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

/// The [`AuthError::InvalidToken`] reason under
/// [`ClaimChecks::with_integer_time_claims`].
const NOT_WHOLE_SECONDS: &str = "a time claim is not a whole number of seconds";

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
    /// `aud` is checked **only when present**: absent, it passes; a string
    /// must equal this value; an array must contain it and hold nothing but
    /// strings. Any other `aud` (a number, a boolean, an object, `null`, an
    /// array holding a non-string) is refused ("audience is not accepted").
    ///
    /// For a resource server whose issuer leaves `aud` out of some tokens
    /// meant for it. **Safe only when the issuer names the audience in every
    /// token it mints for another service**: a token without `aud` is
    /// accepted from the exact `iss` the [`ClaimChecks`] require, whoever it
    /// was minted for. Hydra (slauth) stamps the audiences a client asked
    /// for, and an empty array, which this refuses, when it asked for none.
    IfPresent(String),
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
///   [`Audience::Required`] ([`Audience::IfPresent`] checks it when it is
///   there). A token missing one is rejected ("a required claim is
///   missing"), never let through unchecked.
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
/// - Under [`ClaimChecks::with_integer_time_claims`] (off by default), each
///   of `exp`, `nbf` and `iat` that is present must also be a non-negative
///   JSON integer ([`time_claims_are_whole_seconds`]).
///
/// [`ClaimChecks::new`] starts from a 60 s leeway ([`DEFAULT_LEEWAY`]) with
/// `nbf` checked and integer time claims not required. [`Verifier::new`]'s
/// rules, kept as they have always been, differ in one respect: `nbf` is not
/// checked (see [`Verifier::claim_checks`]).
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
    integer_time_claims: bool,
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
            integer_time_claims: false,
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

    /// Whether each present `exp`, `nbf` and `iat` must be a whole number of
    /// seconds: a non-negative JSON integer ([`time_claims_are_whole_seconds`]).
    /// Off by default, and on [`Verifier::new`],
    /// [`Verifier::claims_with_jwks`] and [`Verifier::verify_with_jwks`],
    /// which build their own checks.
    ///
    /// jsonwebtoken reads `exp` and `nbf` as any finite non-negative number
    /// and rounds a fraction to the nearest second, and never reads `iat`.
    /// On, a token is refused, as [`AuthError::InvalidToken`] ("a time claim
    /// is not a whole number of seconds"), whose `exp`, `nbf` or `iat` is a
    /// fraction, a whole float (`3600.0`), an exponent form (`1.8e9`), a
    /// negative number, a boolean, a string (a numeric one included) or
    /// `null`. An absent `nbf` or `iat` still passes, and `exp` stays
    /// required. A time claim jsonwebtoken already refuses keeps its own
    /// reason ("a required claim is missing" for a malformed `exp`, "token
    /// is malformed" for a malformed `nbf` while it is checked); the check
    /// runs after every other one. A payload naming `exp`, `nbf` or `iat`
    /// twice is refused ("claims are malformed"). Each claim's type is read
    /// from the payload's JSON text, never through a `serde_json::Value`
    /// ([`time_claims_are_whole_seconds`] says why).
    #[must_use]
    pub fn with_integer_time_claims(mut self, on: bool) -> ClaimChecks {
        self.integer_time_claims = on;
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

    /// Whether each present time claim must be a whole number of seconds
    /// ([`ClaimChecks::with_integer_time_claims`]).
    pub fn requires_integer_time_claims(&self) -> bool {
        self.integer_time_claims
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
            // `IfPresent` is checked by `audience_if_present` instead:
            // jsonwebtoken lets an `aud` it cannot parse (a number, an array
            // holding one) through when `aud` is not required.
            Audience::NotValidated | Audience::IfPresent(_) => {
                // Off, not merely unset: with no audience configured,
                // jsonwebtoken rejects every token that carries one.
                validation.validate_aud = false;
                validation.set_required_spec_claims(&["exp", "iss"]);
            }
        }
        validation
    }

    /// Every check on a token whose signature `key` verifies: jsonwebtoken's
    /// [`ClaimChecks::validation`], then, under [`Audience::IfPresent`],
    /// [`audience_if_present`], then, when required,
    /// [`time_claims_are_whole_seconds`].
    fn claims<C: DeserializeOwned>(&self, token: &str, key: &DecodingKey) -> Result<C, AuthError> {
        let claims = decode::<C>(token, key, &self.validation())
            .map(|data| data.claims)
            .map_err(|err| invalid_token(&err))?;
        if let Audience::IfPresent(audience) = &self.audience {
            if !audience_if_present(token, audience) {
                return Err(invalid_token(&ErrorKind::InvalidAudience.into()));
            }
        }
        if self.integer_time_claims {
            // "Insecure" only in that it checks nothing: `decode` just did.
            // Read from the payload's bytes into `TimeClaims`, never through
            // a `serde_json::Value`, which can change a value's JSON type.
            let time = jsonwebtoken::dangerous::insecure_decode_claims::<TimeClaims>(token)
                .map_err(|_| AuthError::InvalidToken("claims are malformed".into()))?;
            if !time.are_whole_seconds() {
                return Err(AuthError::InvalidToken(NOT_WHOLE_SECONDS.into()));
            }
        }
        Ok(claims)
    }
}

/// Whether each registered time claim in a token's payload (`exp`, `nbf`,
/// `iat`) is absent or a whole number of seconds: a non-negative JSON
/// integer. `payload_json` is the payload's JSON text, its second segment
/// base64url-decoded.
///
/// The rule [`ClaimChecks::with_integer_time_claims`] applies, public for a
/// verifier that reads a token's claims some other way and wants the same
/// one. A fraction (`3600.0` and `1.8e9` included), a negative number, a
/// boolean, a string, an array, an object and `null` fail; so does a payload
/// that is not a JSON object, or that names one of the three claims twice
/// (stricter than a JSON map, which keeps the last). Only the type is
/// checked: comparing `exp` and `nbf` with the clock is the verifier's job,
/// and every other claim is ignored.
///
/// **Why bytes, not a `serde_json::Value`:** a `Value` does not keep a
/// claim's JSON type. A struct of `Option`s reads `null` as absent, and with
/// serde_json's `raw_value` feature on anywhere in the graph (axum turns it
/// on), the object `{"$serde_json::private::RawValue":"0"}` becomes
/// `Value::Number(0)`, a whole number to `as_u64`. This reads each claim's
/// type as the JSON text has it.
///
/// ```
/// use stridelabs_auth::time_claims_are_whole_seconds;
///
/// assert!(time_claims_are_whole_seconds(br#"{"exp":1800000000,"iat":0}"#));
/// assert!(time_claims_are_whole_seconds(br#"{"exp":1800000000,"sub":"s"}"#));
/// assert!(!time_claims_are_whole_seconds(br#"{"exp":1800000000,"nbf":null}"#));
/// assert!(!time_claims_are_whole_seconds(br#"{"exp":3600.0}"#));
/// assert!(!time_claims_are_whole_seconds(br#"{"exp":1,"exp":2}"#));
/// ```
pub fn time_claims_are_whole_seconds(payload_json: &[u8]) -> bool {
    serde_json::from_slice::<TimeClaims>(payload_json).is_ok_and(|time| time.are_whole_seconds())
}

/// A payload's registered time claims, each as its JSON type: `None` when
/// absent. Read from a JSON object only (an array in field order, which
/// serde's derive would take, is an error), with every other member ignored
/// and a repeated time claim an error.
#[derive(Default)]
struct TimeClaims {
    exp: Option<TimeType>,
    nbf: Option<TimeType>,
    iat: Option<TimeType>,
}

impl TimeClaims {
    fn are_whole_seconds(&self) -> bool {
        [self.exp, self.nbf, self.iat]
            .into_iter()
            .all(|time| time.is_none_or(|time| time == TimeType::WholeSeconds))
    }
}

impl<'de> Deserialize<'de> for TimeClaims {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<TimeClaims, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = TimeClaims;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<TimeClaims, A::Error> {
                let mut time = TimeClaims::default();
                // An owned key: one with an escape (`"\u0065xp"`) is `exp`.
                while let Some(key) = map.next_key::<String>()? {
                    let (name, slot) = match key.as_str() {
                        "exp" => ("exp", &mut time.exp),
                        "nbf" => ("nbf", &mut time.nbf),
                        "iat" => ("iat", &mut time.iat),
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                            continue;
                        }
                    };
                    if slot.is_some() {
                        return Err(serde::de::Error::duplicate_field(name));
                    }
                    // `TimeType` itself, not `Option<TimeType>`, which would
                    // read `null` as absent.
                    *slot = Some(map.next_value::<TimeType>()?);
                }
                Ok(time)
            }
        }

        deserializer.deserialize_map(Visitor)
    }
}

/// A time claim's JSON type, read from the JSON itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeType {
    /// A non-negative integer.
    WholeSeconds,
    /// Anything else: a negative integer, a float, a boolean, a string,
    /// `null`, an array or an object. (With serde_json's
    /// `arbitrary_precision` on, which nothing here enables, an integer that
    /// fits a `u64` still arrives as one; a float or a larger integer arrives
    /// as an object and is refused, so the option still fails closed.)
    Other,
}

impl<'de> Deserialize<'de> for TimeType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<TimeType, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = TimeType;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("any JSON value")
            }

            // serde_json reports a non-negative integer here and nowhere else.
            fn visit_u64<E>(self, _: u64) -> Result<TimeType, E> {
                Ok(TimeType::WholeSeconds)
            }

            fn visit_i64<E>(self, _: i64) -> Result<TimeType, E> {
                Ok(TimeType::Other)
            }

            fn visit_f64<E>(self, _: f64) -> Result<TimeType, E> {
                Ok(TimeType::Other)
            }

            fn visit_bool<E>(self, _: bool) -> Result<TimeType, E> {
                Ok(TimeType::Other)
            }

            fn visit_str<E>(self, _: &str) -> Result<TimeType, E> {
                Ok(TimeType::Other)
            }

            fn visit_unit<E>(self) -> Result<TimeType, E> {
                Ok(TimeType::Other)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<TimeType, A::Error> {
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(TimeType::Other)
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<TimeType, A::Error> {
                while map
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(TimeType::Other)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// [`Audience::IfPresent`]'s rule, on the payload of a token jsonwebtoken has
/// just verified, read again with its own payload decoding.
fn audience_if_present(token: &str, audience: &str) -> bool {
    /// The `aud` member, `null` included: `Some(Value::Null)` is not absent.
    #[derive(Deserialize)]
    struct AudMember {
        #[serde(default, deserialize_with = "present")]
        aud: Option<serde_json::Value>,
    }

    fn present<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<serde_json::Value>, D::Error> {
        serde_json::Value::deserialize(deserializer).map(Some)
    }

    // "Insecure" only in that it checks nothing: `decode` just did.
    let member = jsonwebtoken::dangerous::insecure_decode_claims::<AudMember>(token).ok();
    match member.map(|member| member.aud) {
        None => false,
        Some(None) => true,
        Some(Some(serde_json::Value::String(aud))) => aud == audience,
        Some(Some(serde_json::Value::Array(auds))) => {
            auds.iter().all(serde_json::Value::is_string)
                && auds.iter().any(|aud| aud.as_str() == Some(audience))
        }
        Some(Some(_)) => false,
    }
}

impl fmt::Debug for ClaimChecks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaimChecks")
            .field("issuer", &redact_issuer(&self.issuer))
            .field("audience", &self.audience)
            .field("leeway", &self.leeway)
            .field("validate_nbf", &self.validate_nbf)
            .field("integer_time_claims", &self.integer_time_claims)
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
/// choosing ([`Verifier::for_issuer`], or [`Verifier::with_cache`] over a
/// cache the consumer built).
///
/// Cheap to clone (one `Arc`), and **meant to be cloned rather than rebuilt**:
/// the key cache lives inside, so a verifier constructed per request would
/// fetch the JWKS per request. Build one in the service's application state
/// and clone it from there.
#[derive(Debug, Clone)]
pub struct Verifier {
    inner: Arc<Inner>,
    /// What is checked before the key lookup: outside the `Arc`, so that
    /// [`Verifier::screen`] can set it on a verifier already built.
    screen: ScreenPolicy,
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
        Verifier::from_parts(config, checks, jwks)
    }

    fn from_parts(config: SlauthConfig, checks: ClaimChecks, jwks: JwksCache) -> Verifier {
        Verifier {
            inner: Arc::new(Inner {
                config,
                checks,
                jwks,
            }),
            screen: ScreenPolicy::default(),
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
        let mut jwks = JwksCache::new(jwks_url, http);
        if let Some(ttl) = jwks_ttl {
            jwks = jwks.with_ttl(ttl);
        }
        Verifier::with_cache(checks, jwks)
    }

    /// Build a verifier for tokens from `checks`' issuer, under `checks`'
    /// rules, with keys from `cache`: [`Verifier::for_issuer`] over a
    /// [`JwksCache`] the consumer built, so that its refetch interval, its
    /// HTTP client and its opt-in settings
    /// ([`JwksCache::report_unusable_keys`]) are the consumer's.
    ///
    /// **Pairing the cache with the rules is the caller's job here**: a cache
    /// reading one issuer's key set under `checks` for another is a hole no
    /// verification logic closes, which is why [`Verifier::new`] and
    /// [`Verifier::for_issuer`] build theirs from the URL they are given.
    /// Build the cache from the same configuration as the issuer, and hand
    /// it to one verifier: the verifier owns it from here on.
    ///
    /// [`Verifier::config`] on the result is synthesized, as for
    /// [`Verifier::for_issuer`], with the cache's JWKS URL.
    ///
    /// ```no_run
    /// # async fn example(http: reqwest::Client, token: &str)
    /// # -> Result<(), stridelabs_auth::AuthError> {
    /// use std::time::Duration;
    ///
    /// use stridelabs_auth::{Audience, ClaimChecks, JwksCache, ScreenPolicy, Verifier};
    ///
    /// let cache = JwksCache::new("https://auth.example.com/.well-known/jwks.json", http)
    ///     .with_ttl(Duration::from_secs(3600))
    ///     .report_unusable_keys(true);
    /// let checks = ClaimChecks::new(
    ///     "https://auth.example.com",
    ///     Audience::IfPresent("my-service".into()),
    /// )
    /// .with_leeway(Duration::ZERO);
    /// let verifier = Verifier::with_cache(checks, cache).screen(ScreenPolicy::Strict);
    ///
    /// let claims: serde_json::Value = verifier.verify_bearer_claims(token).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_cache(checks: ClaimChecks, cache: JwksCache) -> Verifier {
        let config = SlauthConfig {
            issuer: checks.issuer.clone(),
            jwks_url: cache.jwks_url().to_owned(),
            audience: match &checks.audience {
                Audience::Required(audience) | Audience::IfPresent(audience) => audience.clone(),
                Audience::NotValidated => NOT_VALIDATED_AUDIENCE.to_owned(),
            },
            pat_validate_url: None,
        };
        Verifier::from_parts(config, checks, cache)
    }

    /// This verifier with `policy` deciding what is checked before a token's
    /// key is looked up ([`ScreenPolicy::Basic`] by default, what every
    /// verifier has always done). [`ScreenPolicy::Strict`] refuses a
    /// malformed, oversized, `crit`-bearing or non-RS256 token, or one with
    /// an empty or oversized `kid`, before the lookup, so with no fetch and
    /// never with an outage's error ([`crate::screen`]).
    #[must_use]
    pub fn screen(mut self, policy: ScreenPolicy) -> Verifier {
        self.screen = policy;
        self
    }

    /// What this verifier checks before a key lookup ([`Verifier::screen`]).
    pub fn screen_policy(&self) -> ScreenPolicy {
        self.screen
    }

    /// The configuration this verifier was built with.
    ///
    /// For a [`Verifier::for_issuer`] or [`Verifier::with_cache`] verifier,
    /// which takes no [`SlauthConfig`], one synthesized from its arguments,
    /// and **informational only**: its issuer and JWKS URL, no
    /// `pat_validate_url`, and `audience` the [`Audience::Required`] or
    /// [`Audience::IfPresent`] value, or under [`Audience::NotValidated`] a
    /// sentinel no issuer mints (the string `"\0audience not validated"`,
    /// which starts with a NUL character; never empty). It does not hold this
    /// verifier's rules; read [`Verifier::claim_checks`] for those.
    ///
    /// **Do not rebuild a `for_issuer` verifier with `Verifier::new(config)`.**
    /// That applies slauth's rules ([`Verifier::new`]): `aud` required, a
    /// 60 s leeway and `nbf` unchecked, not this verifier's leeway or `nbf`
    /// setting. Under [`Audience::Required`] or [`Audience::IfPresent`] the
    /// result can accept tokens this verifier refuses: up to 60 s past their
    /// `exp` where this one's leeway is smaller, or with an `nbf` still ahead
    /// where this one checks it. Under [`Audience::NotValidated`] the
    /// sentinel makes it refuse every token a real issuer mints, so that
    /// mistake fails closed, but it is still not this verifier. Clone the
    /// verifier instead.
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
    /// same code: this verifier's [`ScreenPolicy`] ([`Verifier::screen`]; by
    /// default a header that parses and carries a `kid`, else
    /// [`AuthError::MalformedToken`] or [`AuthError::MissingKid`]), key
    /// selection by `kid`, the RS256 signature, then this verifier's
    /// [`ClaimChecks`] ([`Verifier::claim_checks`]): for a
    /// [`Verifier::new`] verifier, `exp`, `iss` and `aud`, all three
    /// required. Over a cache that reports unusable keys
    /// ([`JwksCache::report_unusable_keys`]), a key is selected only if it
    /// can verify RS256 (its labels, and `n` and `e` as aws-lc-rs accepts them), and a
    /// kid with no such key is [`AuthError::UnusableKey`]; otherwise the
    /// selection is [`Verifier::claims_with_jwks_checked`]'s. What is **not**
    /// checked is anything about `email` or `sub`:
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
        let kid = kid_for_lookup(token, self.screen)?;

        let jwks = self.inner.jwks.jwks_for_kid(&kid).await?;

        let key = if self.inner.jwks.reports_unusable_keys() {
            usable_key(&jwks, &kid)?
        } else {
            fit_key(&jwks, &kid)?
        };
        self.inner.checks.claims(token, &key)
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
    /// [`Audience::Required`], `aud` contains the audience, and under
    /// [`Audience::IfPresent`], a present `aud` does. `exp` and `iss` must be
    /// present, and `aud` under [`Audience::Required`]. Nothing about `email`
    /// or `sub` — the caller owns those (see
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
        let key = fit_key(jwks, kid)?;
        checks.claims(token, &key)
    }
}

/// The key under `kid` that may verify an RS256 signature, as every verifier
/// has always chosen it ([`Verifier::claims_with_jwks_checked`]).
fn fit_key(jwks: &JwkSet, kid: &str) -> Result<DecodingKey, AuthError> {
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
    // (A cache that reports unusable keys answers that case itself, once
    // per refetch floor at most: `usable_key`.)
    let jwk = keys_under(jwks, kid)
        .find(|jwk| rs256_parameters(jwk).is_ok())
        .ok_or(AuthError::UnknownKid)?;
    // A key the issuer published but we can't build a verifier from is the
    // issuer's problem, not the caller's — hence `Jwks`, which maps to a
    // 5xx, and not a 401 blaming a token that never got to be checked.
    DecodingKey::from_jwk(jwk)
        .map_err(|_| AuthError::Jwks("key set contains an unusable signing key".into()))
}

/// The first key under `kid` that can verify an RS256 signature
/// ([`first_rs256_key`]), over a cache that reports unusable keys: that cache
/// served this set because it holds one, so a kid with none is
/// [`AuthError::UnusableKey`] (the first key's reason) only defensively.
fn usable_key(jwks: &JwkSet, kid: &str) -> Result<DecodingKey, AuthError> {
    first_rs256_key(keys_under(jwks, kid))
        .map_err(|reason| reason.map_or(AuthError::UnknownKid, AuthError::UnusableKey))
}

/// The kids in `set` under which no key can verify an RS256 signature, each
/// with the first key's [`UnusableReason`]: what a cache that reports
/// unusable keys refuses ([`JwksCache::report_unusable_keys`]). Computed once
/// per fetched set, off the cache's lock.
pub(crate) fn unusable_kids(set: &JwkSet) -> HashMap<String, UnusableReason> {
    let mut by_kid: HashMap<&str, Vec<&Jwk>> = HashMap::new();
    for jwk in &set.keys {
        if let Some(kid) = jwk.common.key_id.as_deref() {
            by_kid.entry(kid).or_default().push(jwk);
        }
    }
    by_kid
        .into_iter()
        .filter_map(|(kid, keys)| Some((kid.to_owned(), first_rs256_key(keys).err()??)))
        .collect()
}

/// The keys `jwks` publishes under `kid`, in order.
fn keys_under<'a>(jwks: &'a JwkSet, kid: &'a str) -> impl Iterator<Item = &'a Jwk> {
    jwks.keys
        .iter()
        .filter(move |jwk| jwk.common.key_id.as_deref() == Some(kid))
}

/// The first of `keys` that can verify an RS256 signature ([`rs256_key`]),
/// or, when none can, the first one's reason (`None`: no keys at all).
fn first_rs256_key<'a>(
    keys: impl IntoIterator<Item = &'a Jwk>,
) -> Result<DecodingKey, Option<UnusableReason>> {
    let mut first_reason = None;
    for jwk in keys {
        match rs256_key(jwk) {
            Ok(key) => return Ok(key),
            Err(reason) => {
                first_reason.get_or_insert(reason);
            }
        }
    }
    Err(first_reason)
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

/// `jwk`'s RSA parameters, if it is an RSA key its issuer allows for RS256
/// signature verification, else why its type or a label rules that out. An
/// absent `alg`, `use` or `key_ops` allows it (RFC 7517 makes all three
/// optional); a present one must say RS256, say `sig`, or include `verify`.
/// Anything else, an unrecognised label included, rules the key out. An RSA
/// key jsonwebtoken could not parse as one, because its `n` or `e` is missing
/// or not a string, is [`UnusableReason::MalformedComponents`], not `NotRsa`.
fn rs256_parameters(jwk: &Jwk) -> Result<&RSAKeyParameters, UnusableReason> {
    let common = &jwk.common;
    let rsa = match &jwk.algorithm {
        AlgorithmParameters::RSA(rsa) => rsa,
        // jsonwebtoken's untagged catch-all: an RSA key that lacks `n` or `e`,
        // or has one that is not a string, parses as `Other`, not as a
        // failure of the whole set.
        AlgorithmParameters::Other(other)
            if other.fields.get("kty").and_then(serde_json::Value::as_str) == Some("RSA") =>
        {
            return Err(UnusableReason::MalformedComponents);
        }
        _ => return Err(UnusableReason::NotRsa),
    };
    if !common
        .key_algorithm
        .is_none_or(|alg| alg == KeyAlgorithm::RS256)
    {
        return Err(UnusableReason::Alg);
    }
    if !common
        .public_key_use
        .as_ref()
        .is_none_or(|key_use| *key_use == PublicKeyUse::Signature)
    {
        return Err(UnusableReason::Use);
    }
    if !common
        .key_operations
        .as_ref()
        .is_none_or(|ops| ops.contains(&KeyOperations::Verify))
    {
        return Err(UnusableReason::KeyOps);
    }
    Ok(rsa)
}

/// The modulus sizes the RS256 verifier accepts, in bits (aws-lc-rs's
/// `RSA_PKCS1_2048_8192_SHA256`): a key outside them can never verify.
const RS256_MODULUS_BITS: std::ops::RangeInclusive<usize> = 2048..=8192;

/// The public exponent sizes aws-lc accepts, in bits: at least 2 (so no
/// `e = 1`), at most 33 (its limit against slow verification).
const RS256_EXPONENT_BITS: std::ops::RangeInclusive<usize> = 2..=33;

/// `jwk` as an RS256 decoding key, or why it can never be one: what a cache
/// that reports unusable keys checks ([`first_rs256_key`]).
///
/// [`rs256_parameters`] first, then the components must be what the RS256
/// verifier (aws-lc-rs 1.18, on aws-lc) accepts, or verification would
/// refuse every signature as invalid, blaming the token for the key:
///
/// - `n` and `e` unpadded base64url (the decoding `DecodingKey::from_jwk`
///   runs);
/// - each non-empty with no leading zero octet: aws-lc-rs refuses any other
///   encoding of a public component (`public_component_to_bn`), and RFC 7518
///   §6.3.1 requires the minimal form;
/// - `e` odd and 2 to 33 bits long (aws-lc's
///   `is_public_component_of_rsa_key_good`), so 0, 1 and any even exponent
///   never verify;
/// - `n` 2048 to 8192 bits long ([`UnusableReason::ModulusSize`] otherwise)
///   and odd.
///
/// Everything but the size is [`UnusableReason::MalformedComponents`].
fn rs256_key(jwk: &Jwk) -> Result<DecodingKey, UnusableReason> {
    let rsa = rs256_parameters(jwk)?;
    let (Ok(modulus), Ok(exponent)) = (
        URL_SAFE_NO_PAD.decode(&rsa.n),
        URL_SAFE_NO_PAD.decode(&rsa.e),
    ) else {
        return Err(UnusableReason::MalformedComponents);
    };
    // The bit length of a minimal big-endian integer; `None` for one that is
    // empty or starts with a zero octet.
    let bits = |octets: &[u8]| match octets.first() {
        Some(&first) if first != 0 => Some(octets.len() * 8 - first.leading_zeros() as usize),
        _ => None,
    };
    let odd = |octets: &[u8]| octets.last().is_some_and(|last| last & 1 == 1);
    let (Some(modulus_bits), Some(exponent_bits)) = (bits(&modulus), bits(&exponent)) else {
        return Err(UnusableReason::MalformedComponents);
    };
    if !odd(&exponent) || !RS256_EXPONENT_BITS.contains(&exponent_bits) {
        return Err(UnusableReason::MalformedComponents);
    }
    if !RS256_MODULUS_BITS.contains(&modulus_bits) {
        return Err(UnusableReason::ModulusSize);
    }
    if !odd(&modulus) {
        return Err(UnusableReason::MalformedComponents);
    }
    Ok(DecodingKey::from_rsa_raw_components(&modulus, &exponent))
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{decode_header, encode, EncodingKey, Header};
    use serde_json::{json, Value};
    use wiremock::{MockServer, ResponseTemplate};

    use super::*;
    use crate::mock_issuer::{
        issuer, issuer_then, jwks_body, jwks_url_of, primary_body, primary_issuer, requests,
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
    /// member).
    fn primary_key_with(changes: &Value) -> Value {
        let mut key = key_json(TestKey::primary());
        let members = key.as_object_mut().expect("a JWK is an object");
        for (name, value) in changes.as_object().expect("changes are an object") {
            if value.is_null() {
                members.remove(name);
            } else {
                members.insert(name.clone(), value.clone());
            }
        }
        key
    }

    /// [`primary_key_with`] as JWKS text, the form the cache fetches.
    fn primary_jwks_json_with(changes: Value) -> String {
        json!({ "keys": [primary_key_with(&changes)] }).to_string()
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

    /// `claims` under a hand-written `header` (JSON text), with an empty
    /// signature: a token jsonwebtoken cannot produce.
    fn unsigned(header: &str, claims: TestClaims) -> String {
        let payload = serde_json::to_vec(&claims.build()).expect("claims serialize");
        format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        )
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

    // --- `Audience::IfPresent` ----------------------------------------------

    fn if_present() -> ClaimChecks {
        ClaimChecks::new(ISSUER, Audience::IfPresent(AUDIENCE.into()))
    }

    /// A good token whose `aud` is `aud`.
    fn with_aud(aud: Value) -> String {
        mint(claims().claim("aud", aud))
    }

    #[test]
    fn if_present_accepts_no_aud_its_own_or_an_array_holding_it() {
        for (case, token) in [
            ("no aud", mint(claims().without_audience())),
            ("the audience", with_aud(json!(AUDIENCE))),
            ("an array holding it", with_aud(json!(["other", AUDIENCE]))),
            ("an array of it alone", with_aud(json!([AUDIENCE]))),
        ] {
            checked(&token, &if_present()).unwrap_or_else(|err| panic!("{case}: {err}"));
        }
    }

    #[test]
    fn if_present_refuses_another_audience_and_a_malformed_aud() {
        let cases = [
            ("another audience", json!("some-other-app")),
            ("the audience and a space", json!(format!("{AUDIENCE} "))),
            ("an array without it", json!(["some-other-app"])),
            ("an empty array", json!([])),
            ("a number", json!(5)),
            ("null", json!(null)),
            ("a boolean", json!(true)),
            ("an object", json!({ "aud": AUDIENCE })),
            ("an array holding it and a number", json!([AUDIENCE, 1])),
            ("an array holding it and null", json!([AUDIENCE, null])),
            ("an array holding it nested", json!([[AUDIENCE]])),
        ];
        for (case, aud) in &cases {
            assert_rejected(
                checked(&with_aud(aud.clone()), &if_present()),
                "audience is not accepted",
                case,
            );
        }
        // The control: not checking `aud` at all, every one of these
        // verifies, so the refusal is `IfPresent`'s rule.
        let not_validated = ClaimChecks::new(ISSUER, Audience::NotValidated);
        for (case, aud) in &cases {
            checked(&with_aud(aud.clone()), &not_validated)
                .unwrap_or_else(|err| panic!("{case}, not validated: {err}"));
        }
    }

    /// `IfPresent` changes the `aud` rule alone: `exp` and `iss` are still
    /// required, `iss` still exact, and the signature still checked.
    #[test]
    fn if_present_keeps_every_other_check() {
        for (case, token, reason) in [
            (
                "no exp",
                mint_without(claims().without_audience(), "exp"),
                "a required claim is missing",
            ),
            (
                "no iss",
                mint_without(claims().without_audience(), "iss"),
                "a required claim is missing",
            ),
            (
                "another issuer",
                mint(TestClaims::new("https://evil.example", AUDIENCE)),
                "issuer is not accepted",
            ),
            (
                "expired",
                mint(claims().without_audience().expires_in(-3600)),
                "token has expired",
            ),
            (
                "another key's signature",
                TestKey::secondary().mint_with_kid(PRIMARY_KID, &claims().build()),
                "signature is invalid",
            ),
        ] {
            assert_rejected(checked(&token, &if_present()), reason, case);
        }
    }

    // --- `Verifier::with_cache` ---------------------------------------------

    #[test]
    fn a_with_cache_verifiers_config_is_synthesized_from_its_cache() {
        let cache = JwksCache::new("https://jwks.test/jwks", reqwest::Client::new());
        let verifier = Verifier::with_cache(if_present(), cache);

        assert_eq!(verifier.claim_checks(), &if_present());
        assert_eq!(verifier.screen_policy(), ScreenPolicy::Basic);
        let config = verifier.config();
        assert_eq!(config.issuer, ISSUER);
        assert_eq!(config.jwks_url, "https://jwks.test/jwks");
        assert_eq!(config.audience, AUDIENCE);
        assert_eq!(config.pat_validate_url, None);
    }

    /// The cache is the consumer's, tuning and all: with its refetch
    /// interval at zero, an unknown kid refetches on every lookup, where the
    /// cache `Verifier::for_issuer` builds would answer the second from
    /// memory (`UnseenKid`) inside its 30 s floor.
    #[tokio::test]
    async fn a_with_cache_verifier_keeps_its_caches_refetch_interval() {
        // The warm-up, then one refetch per unknown-kid lookup.
        let server = primary_issuer(3).await;
        let cache = JwksCache::new(jwks_url_of(&server), reqwest::Client::new())
            .with_min_refetch_interval(Duration::ZERO);
        let verifier = Verifier::with_cache(
            ClaimChecks::new(ISSUER, Audience::Required(AUDIENCE.into())),
            cache,
        );

        verifier
            .verify_bearer_claims::<Value>(&mint(claims()))
            .await
            .expect("warm cache");
        let forged = TestKey::primary().mint_with_kid("no-such-kid", &claims().build());
        for lookup in ["first", "second"] {
            let err = verifier
                .verify_bearer_claims::<Value>(&forged)
                .await
                .unwrap_err();
            assert!(
                matches!(err, AuthError::UnknownKid),
                "{lookup}: refetched, and the issuer's verdict: {err}"
            );
        }
    }

    /// The shape tapper adopts (plan 016 C-5): its own cache reporting
    /// unusable keys, `aud` checked if present, no leeway, the strict screen,
    /// and its claims read as JSON for its own identity rules.
    #[tokio::test]
    async fn tappers_verifier_shape_verifies_and_refuses() {
        let server = primary_issuer(1).await;
        let cache = JwksCache::new(jwks_url_of(&server), reqwest::Client::new())
            .with_ttl(Duration::from_secs(3600))
            .report_unusable_keys(true);
        let verifier = Verifier::with_cache(
            ClaimChecks::new(ISSUER, Audience::IfPresent("tapper".into()))
                .with_leeway(Duration::ZERO),
            cache,
        )
        .screen(ScreenPolicy::Strict);
        assert_eq!(verifier.screen_policy(), ScreenPolicy::Strict);
        let tapper = || TestClaims::new(ISSUER, "tapper");

        for (case, claims) in [
            ("no aud", tapper().without_audience()),
            ("aud tapper", tapper()),
            (
                "aud an array",
                tapper().claim("aud", json!(["tapper", "other"])),
            ),
        ] {
            let read: Value = verifier
                .verify_bearer_claims(&mint(claims))
                .await
                .unwrap_or_else(|err| panic!("{case}: {err}"));
            assert_eq!(read["iss"], json!(ISSUER), "{case}");
        }
        for (case, token, reason) in [
            (
                "another service's aud",
                mint(TestClaims::new(ISSUER, "other")),
                "audience is not accepted",
            ),
            (
                "a second past exp",
                mint(tapper().expires_in(-1)),
                "token has expired",
            ),
            (
                "HS256, refused by the screen",
                hs256(tapper()),
                "algorithm is not accepted",
            ),
        ] {
            assert_rejected(verifier.verify_bearer_claims(&token).await, reason, case);
        }
    }

    // --- a cache that reports unusable keys ---------------------------------

    fn reporting_verifier(server: &MockServer) -> Verifier {
        Verifier::with_cache(
            ClaimChecks::new(ISSUER, Audience::Required(AUDIENCE.into())),
            JwksCache::new(jwks_url_of(server), reqwest::Client::new()).report_unusable_keys(true),
        )
    }

    /// Each way the issuer's only key under the token's kid can be unusable,
    /// as the change that makes it so and the reason reported.
    /// `modulus` (base64url) with a zero octet in front: the same integer,
    /// not in minimal form.
    fn with_leading_zero(modulus: &str) -> String {
        let mut octets = vec![0];
        octets.extend(URL_SAFE_NO_PAD.decode(modulus).expect("base64url"));
        URL_SAFE_NO_PAD.encode(octets)
    }

    /// `modulus` (base64url) with its lowest bit cleared.
    fn made_even(modulus: &str) -> String {
        let mut octets = URL_SAFE_NO_PAD.decode(modulus).expect("base64url");
        *octets.last_mut().expect("a modulus") &= 0xFE;
        URL_SAFE_NO_PAD.encode(octets)
    }

    fn unusable_changes() -> Vec<(&'static str, Value, UnusableReason)> {
        use UnusableReason::*;
        let modulus = key_json(TestKey::primary())["n"]
            .as_str()
            .expect("the test key's n")
            .to_owned();
        vec![
            (
                "no n (parsed as `Other`)",
                json!({ "n": null }),
                MalformedComponents,
            ),
            ("no e", json!({ "e": null }), MalformedComponents),
            (
                "an n that is a number",
                json!({ "n": 65537 }),
                MalformedComponents,
            ),
            (
                "an n that is not base64url",
                json!({ "n": "not!base64url" }),
                MalformedComponents,
            ),
            (
                "a padded n",
                json!({ "n": format!("{modulus}==") }),
                MalformedComponents,
            ),
            ("an empty e", json!({ "e": "" }), MalformedComponents),
            // What aws-lc-rs refuses at verification: the key's own `n` with
            // a leading zero octet (it signed the token, so only the encoding
            // stops it), and exponents it never accepts.
            (
                "the key's n with a leading zero octet",
                json!({ "n": with_leading_zero(&modulus) }),
                MalformedComponents,
            ),
            ("e zero (`AA`)", json!({ "e": "AA" }), MalformedComponents),
            ("e one", json!({ "e": "AQ" }), MalformedComponents),
            (
                "e 65537 with a leading zero octet",
                json!({ "e": "AAEAAQ" }),
                MalformedComponents,
            ),
            ("an even e", json!({ "e": "AQAA" }), MalformedComponents),
            (
                "an e of 41 bits",
                json!({ "e": "AQAAAAAB" }),
                MalformedComponents,
            ),
            (
                "an even n",
                json!({ "n": made_even(&modulus) }),
                MalformedComponents,
            ),
            (
                "a 1024-bit modulus",
                json!({ "n": URL_SAFE_NO_PAD.encode([0xC5_u8; 128]) }),
                ModulusSize,
            ),
            ("an unknown key type", json!({ "kty": "XYZ" }), NotRsa),
            ("alg RS512", json!({ "alg": "RS512" }), Alg),
            ("use enc", json!({ "use": "enc" }), Use),
            (
                "key_ops without verify",
                json!({ "key_ops": ["encrypt"] }),
                KeyOps,
            ),
        ]
    }

    #[tokio::test]
    async fn over_a_reporting_cache_an_unusable_key_is_refused_with_its_reason() {
        let token = mint(claims());
        for (case, change, reason) in unusable_changes() {
            let server = issuer(jwks_body(&primary_jwks_json_with(change)), 1).await;

            let err = reporting_verifier(&server)
                .verify_bearer_claims::<Value>(&token)
                .await
                .unwrap_err();

            assert!(
                matches!(err, AuthError::UnusableKey(got) if got == reason),
                "{case}: expected UnusableKey({reason}), got {err}"
            );
            for rendered in [err.to_string(), format!("{err:?}")] {
                assert!(!rendered.contains(PRIMARY_KID), "{case}: {rendered}");
            }
        }
        for (case, foreign) in [
            (
                "an EC key",
                json!({ "kty": "EC", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", "kid": PRIMARY_KID }),
            ),
            (
                "a symmetric key",
                json!({ "kty": "oct", "k": "cHVibGljIGtleSBtYXRlcmlhbA", "kid": PRIMARY_KID }),
            ),
        ] {
            let server = issuer(jwks_body(&json!({ "keys": [foreign] }).to_string()), 1).await;
            let err = reporting_verifier(&server)
                .verify_bearer_claims::<Value>(&token)
                .await
                .unwrap_err();
            assert!(
                matches!(err, AuthError::UnusableKey(UnusableReason::NotRsa)),
                "{case}: {err}"
            );
        }
    }

    /// The control: over a cache that does not report them (the default),
    /// the same keys are refused as through v0.9.0, never as `UnusableKey`.
    #[tokio::test]
    async fn without_reporting_an_unusable_key_is_refused_as_before() {
        let token = mint(claims());
        for (case, change, _) in unusable_changes() {
            let server = issuer(jwks_body(&primary_jwks_json_with(change)), 1).await;

            let err = verifier_against(&server)
                .verify_bearer_claims::<Value>(&token)
                .await
                .unwrap_err();

            assert!(!matches!(err, AuthError::UnusableKey(_)), "{case}: {err}");
        }
    }

    /// Keys sharing a kid are all considered, so a key that cannot verify,
    /// listed first, does not hide the usable one behind it.
    #[tokio::test]
    async fn over_a_reporting_cache_an_unusable_key_does_not_hide_a_usable_one() {
        for (case, change, _) in unusable_changes() {
            let mut first = primary_key_with(&change);
            first["kid"] = json!(PRIMARY_KID);
            let set = json!({ "keys": [first, key_json(TestKey::primary())] }).to_string();
            let server = issuer(jwks_body(&set), 1).await;

            reporting_verifier(&server)
                .verify_bearer_claims::<Value>(&mint(claims()))
                .await
                .unwrap_or_else(|err| panic!("{case}: {err}"));
        }
    }

    #[test]
    fn unusable_kids_lists_each_kid_with_no_usable_key_and_its_first_reason() {
        let under = |kid: &str, change: Value| {
            let mut key = primary_key_with(&change);
            key["kid"] = json!(kid);
            key
        };
        let set = parse(
            &json!({ "keys": [
                under("broken", json!({ "use": "enc" })),
                under("broken", json!({ "alg": "RS512" })),
                under("fixed-later", json!({ "key_ops": ["sign"] })),
                under("fixed-later", json!({})),
                under("fine", json!({})),
                under("fine", json!({ "alg": "RS512" })),
                primary_key_with(&json!({ "kid": null, "use": "enc" })),
            ] })
            .to_string(),
        );

        assert_eq!(
            unusable_kids(&set),
            HashMap::from([("broken".to_owned(), UnusableReason::Use)])
        );
        assert!(unusable_kids(&TestKey::primary().jwks()).is_empty());
    }

    /// [`rs256_key`]'s component rules, at their edges: what aws-lc-rs
    /// accepts. Building a `DecodingKey` copies bytes and checks nothing, so
    /// the tokens through the reporting verifier above are what show a
    /// refused key never reaches verification.
    #[test]
    fn the_components_are_minimal_with_an_odd_modulus_and_a_small_odd_exponent() {
        use UnusableReason::{MalformedComponents, ModulusSize};
        let with = |n: Vec<u8>, e: Vec<u8>| {
            let key = primary_key_with(&json!({
                "n": URL_SAFE_NO_PAD.encode(n),
                "e": URL_SAFE_NO_PAD.encode(e),
            }));
            rs256_key(&serde_json::from_value(key).expect("a JWK")).map(|_| ())
        };
        // `top`, then `rest` octets of 0xFF: odd, `8 × rest` bits plus top's.
        let modulus = |top: u8, rest: usize| {
            let mut octets = vec![top];
            octets.extend(std::iter::repeat_n(0xFF, rest));
            octets
        };
        let zero_then = |octets: Vec<u8>| [vec![0], octets].concat();
        let f4 = || vec![1, 0, 1];

        for (case, n, e) in [
            ("2048 bits", modulus(0x80, 255), f4()),
            ("8192 bits", modulus(0xFF, 1023), f4()),
            ("e 3", modulus(0x80, 255), vec![3]),
            ("e of 33 bits", modulus(0x80, 255), vec![1, 0, 0, 0, 1]),
        ] {
            assert_eq!(with(n, e), Ok(()), "{case}");
        }
        let mut even = modulus(0x80, 255);
        *even.last_mut().expect("octets") = 0xFE;
        for (case, n, reason) in [
            ("2047 bits", modulus(0x7F, 255), ModulusSize),
            ("8193 bits", modulus(0x01, 1024), ModulusSize),
            (
                "2048 bits after a zero octet",
                zero_then(modulus(0x80, 255)),
                MalformedComponents,
            ),
            (
                "2047 bits after a zero octet",
                zero_then(modulus(0x7F, 255)),
                MalformedComponents,
            ),
            ("all zeros", vec![0; 256], MalformedComponents),
            ("empty", Vec::new(), MalformedComponents),
            ("even", even, MalformedComponents),
        ] {
            assert_eq!(with(n, f4()), Err(reason), "n {case}");
        }
        for (case, e) in [
            ("zero", vec![0]),
            ("one", vec![1]),
            ("even", vec![1, 0, 0]),
            ("34 bits", vec![2, 0, 0, 0, 1]),
            ("65537 after a zero octet", zero_then(f4())),
            ("empty", Vec::new()),
        ] {
            assert_eq!(
                with(modulus(0x80, 255), e),
                Err(MalformedComponents),
                "e {case}"
            );
        }
    }

    /// The review's case, end to end: a key aws-lc-rs refuses is a bad
    /// signature to the default verifier (the premise: it does reach
    /// verification there and fail, a 401) and `UnusableKey` to a reporting
    /// one, which then lets a usable key under the same kid verify.
    #[tokio::test]
    async fn a_key_aws_lc_rs_refuses_is_unusable_not_a_bad_signature() {
        let token = mint(claims());
        let modulus = key_json(TestKey::primary())["n"]
            .as_str()
            .expect("the test key's n")
            .to_owned();
        for (case, change) in [
            (
                "a leading zero octet in n",
                json!({ "n": with_leading_zero(&modulus) }),
            ),
            ("e zero", json!({ "e": "AA" })),
        ] {
            let alone = primary_jwks_json_with(change.clone());

            let server = issuer(jwks_body(&alone), 1).await;
            assert_rejected(
                verifier_against(&server).verify_bearer_claims(&token).await,
                "signature is invalid",
                &format!("{case}, default selection"),
            );

            let server = issuer(jwks_body(&alone), 1).await;
            let err = reporting_verifier(&server)
                .verify_bearer_claims::<Value>(&token)
                .await
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    AuthError::UnusableKey(UnusableReason::MalformedComponents)
                ),
                "{case}, reporting: {err}"
            );

            let pair = json!({ "keys": [primary_key_with(&change), key_json(TestKey::primary())] });
            let server = issuer(jwks_body(&pair.to_string()), 1).await;
            reporting_verifier(&server)
                .verify_bearer_claims::<Value>(&token)
                .await
                .unwrap_or_else(|err| panic!("{case}, then a usable key: {err}"));
        }
    }

    // --- report_unusable_keys set after the cache fetched -------------------

    fn required() -> ClaimChecks {
        ClaimChecks::new(ISSUER, Audience::Required(AUDIENCE.into()))
    }

    /// Reporting turned on after the cache fetched holds at once: the set
    /// fetched without it was checked like any other, so its held kid with no
    /// usable key is `UnusableKey` from memory inside the floor, and once the
    /// floor opens the recovery refetch picks up the fixed key.
    #[tokio::test]
    async fn reporting_turned_on_after_a_fetch_applies_to_the_set_held() {
        let broken = primary_jwks_json_with(json!({ "use": "enc" }));
        let server = issuer_then(jwks_body(&broken), primary_body()).await;
        let cache = JwksCache::new(jwks_url_of(&server), reqwest::Client::new());
        cache
            .jwks_for_kid(PRIMARY_KID)
            .await
            .expect("served while reporting is off");
        let verifier = Verifier::with_cache(required(), cache.report_unusable_keys(true));
        let token = mint(claims());

        let err = verifier
            .verify_bearer_claims::<Value>(&token)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AuthError::UnusableKey(UnusableReason::Use)),
            "{err}"
        );
        assert_eq!(requests(&server).await, 1, "from memory, inside the floor");

        verifier
            .inner
            .jwks
            .advance_for_test(crate::MIN_REFETCH_INTERVAL);
        verifier
            .verify_bearer_claims::<Value>(&token)
            .await
            .expect("the floor's recovery refetch finds the fixed key");
        assert_eq!(requests(&server).await, 2);
    }

    /// And turned off after the cache fetched: the set held is served for the
    /// kid again, and the default selection decides (no fit key under it:
    /// `UnknownKid`), from memory.
    #[tokio::test]
    async fn reporting_turned_off_after_a_fetch_no_longer_applies() {
        let broken = primary_jwks_json_with(json!({ "use": "enc" }));
        let server = issuer(jwks_body(&broken), 1).await;
        let cache =
            JwksCache::new(jwks_url_of(&server), reqwest::Client::new()).report_unusable_keys(true);
        let err = cache.jwks_for_kid(PRIMARY_KID).await.unwrap_err();
        assert!(
            matches!(err, AuthError::UnusableKey(UnusableReason::Use)),
            "while reporting: {err}"
        );
        let verifier = Verifier::with_cache(required(), cache.report_unusable_keys(false));

        let err = verifier
            .verify_bearer_claims::<Value>(&mint(claims()))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::UnknownKid), "{err}");
        verifier
            .inner
            .jwks
            .jwks_for_kid(PRIMARY_KID)
            .await
            .expect("the set held serves the kid");
    }

    // --- integer time claims ------------------------------------------------

    /// A registered time claim, as the integer-time-claims matrix varies it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TimeClaim {
        Exp,
        Nbf,
        Iat,
    }

    impl TimeClaim {
        const ALL: [TimeClaim; 3] = [TimeClaim::Exp, TimeClaim::Nbf, TimeClaim::Iat];

        fn name(self) -> &'static str {
            match self {
                TimeClaim::Exp => "exp",
                TimeClaim::Nbf => "nbf",
                TimeClaim::Iat => "iat",
            }
        }

        /// E: a valid value at `now`, an hour ahead for `exp`, a minute
        /// behind for `nbf`.
        fn valid(self, now: u64) -> u64 {
            match self {
                TimeClaim::Exp => now + 3600,
                TimeClaim::Nbf => now - 60,
                TimeClaim::Iat => now,
            }
        }

        /// M, for the exponent form `Me3`: a valid value too, rounded to
        /// thousands away from the clock (`exp` 1 h to about 1 h 17 min
        /// ahead, `nbf` 60 s to about 17 min behind).
        fn thousands(self, now: u64) -> u64 {
            match self {
                TimeClaim::Exp => self.valid(now).div_ceil(1000),
                TimeClaim::Nbf | TimeClaim::Iat => self.valid(now) / 1000,
            }
        }
    }

    /// The eight shapes of a time claim the matrix tries.
    #[derive(Debug, Clone, Copy)]
    enum TimeShape {
        Fraction,
        WholeFloat,
        Exponent,
        Negative,
        Bool,
        NumericString,
        String,
        Null,
    }

    impl TimeShape {
        const ALL: [TimeShape; 8] = [
            TimeShape::Fraction,
            TimeShape::WholeFloat,
            TimeShape::Exponent,
            TimeShape::Negative,
            TimeShape::Bool,
            TimeShape::NumericString,
            TimeShape::String,
            TimeShape::Null,
        ];

        /// The claim's value as JSON text.
        fn text(self, claim: TimeClaim, now: u64) -> String {
            let e = claim.valid(now);
            match self {
                TimeShape::Fraction => format!("{e}.5"),
                TimeShape::WholeFloat => format!("{e}.0"),
                TimeShape::Exponent => format!("{}e3", claim.thousands(now)),
                TimeShape::Negative => "-1".to_owned(),
                TimeShape::Bool => "true".to_owned(),
                TimeShape::NumericString => format!("\"{e}\""),
                TimeShape::String => "\"soon\"".to_owned(),
                TimeShape::Null => "null".to_owned(),
            }
        }

        /// A number serde_json reads as a float, which jsonwebtoken takes
        /// (rounded) for `exp` and `nbf`.
        fn is_float(self) -> bool {
            matches!(
                self,
                TimeShape::Fraction | TimeShape::WholeFloat | TimeShape::Exponent
            )
        }

        /// The cell's verdict with the option off, then on: `None` passes,
        /// `Some` is refused with that reason. Off, jsonwebtoken 11.1.0
        /// takes any float `exp` or `nbf`, refuses anything else as a
        /// missing `exp` or a malformed `nbf`, and never reads `iat`; on,
        /// every float and every `iat` cell is refused by the option, and
        /// jsonwebtoken's refusals come first.
        fn verdicts(self, claim: TimeClaim) -> (Option<&'static str>, Option<&'static str>) {
            match (claim, self.is_float()) {
                (TimeClaim::Iat, _) | (_, true) => (None, Some(NOT_WHOLE_SECONDS)),
                (TimeClaim::Exp, false) => (
                    Some("a required claim is missing"),
                    Some("a required claim is missing"),
                ),
                (TimeClaim::Nbf, false) => (Some("token is malformed"), Some("token is malformed")),
            }
        }
    }

    /// `payload`, JSON text, signed RS256 by the primary key under its kid
    /// exactly as written: no serializer sees it, so `Me3` and `E.0` reach
    /// the verifier as they read here.
    fn mint_raw(payload: &str) -> String {
        let header = format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{PRIMARY_KID}"}}"#);
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let key = EncodingKey::from_rsa_pem(TestKey::primary().pem().as_bytes())
            .expect("committed test key parses");
        let signature =
            jsonwebtoken::crypto::sign(input.as_bytes(), &key, Algorithm::RS256).expect("sign");
        format!("{input}.{signature}")
    }

    /// A [`client_checks`] token whose `exp`, `nbf` and `iat` are valid
    /// integers at `now`, except `claim`, which is `text` (absent for
    /// `None`). The token's own payload segment is decoded and checked to
    /// carry `claim` exactly as asked.
    fn time_token(now: u64, claim: TimeClaim, text: Option<&str>) -> String {
        let mut members = vec![
            format!(r#""iss":"{CLIENT_ISSUER}""#),
            r#""sub":"user_01TEST""#.to_owned(),
        ];
        for each in TimeClaim::ALL {
            let value = if each == claim {
                text.map(str::to_owned)
            } else {
                Some(each.valid(now).to_string())
            };
            if let Some(value) = value {
                members.push(format!(r#""{}":{value}"#, each.name()));
            }
        }
        let token = mint_raw(&format!("{{{}}}", members.join(",")));

        let segment = token.split('.').nth(1).expect("a payload segment");
        let payload =
            String::from_utf8(URL_SAFE_NO_PAD.decode(segment).expect("base64url")).expect("UTF-8");
        let member = format!(r#""{}":"#, claim.name());
        match text {
            Some(text) => assert!(
                payload.contains(&format!("{member}{text}")),
                "the signed payload carries {member}{text}: {payload}"
            ),
            None => assert!(
                !payload.contains(&member),
                "the signed payload has no {member}: {payload}"
            ),
        }
        token
    }

    /// The 24 cells (3 claims × 8 shapes) at `now`: a name, the token, and
    /// the verdicts off and on ([`TimeShape::verdicts`]).
    #[allow(clippy::type_complexity)]
    fn time_matrix(now: u64) -> Vec<(String, String, Option<&'static str>, Option<&'static str>)> {
        TimeClaim::ALL
            .into_iter()
            .flat_map(|claim| {
                TimeShape::ALL.into_iter().map(move |shape| {
                    let text = shape.text(claim, now);
                    let (off, on) = shape.verdicts(claim);
                    (
                        format!("{} {shape:?} ({text})", claim.name()),
                        time_token(now, claim, Some(&text)),
                        off,
                        on,
                    )
                })
            })
            .collect()
    }

    #[track_caller]
    fn assert_verdict(result: Result<Value, AuthError>, verdict: Option<&str>, case: &str) {
        match verdict {
            None => {
                result.unwrap_or_else(|err| panic!("{case}: refused, expected to pass: {err}"));
            }
            Some(reason) => assert_rejected(result, reason, case),
        }
    }

    fn integer_time_checks() -> ClaimChecks {
        client_checks().with_integer_time_claims(true)
    }

    #[test]
    fn integer_time_claims_are_off_by_default_and_debug_prints_them() {
        let default = ClaimChecks::new(CLIENT_ISSUER, Audience::NotValidated);
        assert!(!default.requires_integer_time_claims());
        assert!(!ClaimChecks::slauth(ISSUER, AUDIENCE).requires_integer_time_claims());
        let config = SlauthConfig {
            issuer: ISSUER.into(),
            jwks_url: "https://jwks.test/jwks".into(),
            audience: AUDIENCE.into(),
            pat_validate_url: None,
        };
        assert!(!Verifier::new(config, reqwest::Client::new())
            .claim_checks()
            .requires_integer_time_claims());

        let on = default.clone().with_integer_time_claims(true);
        assert!(on.requires_integer_time_claims());
        assert_ne!(on, default);
        assert_eq!(on.clone().with_integer_time_claims(false), default);

        assert!(
            format!("{default:?}").contains("integer_time_claims: false"),
            "{default:?}"
        );
        assert!(
            format!("{on:?}").contains("integer_time_claims: true"),
            "{on:?}"
        );
    }

    /// The design's matrix (plan 003 D2 §8): every cell off, then on.
    /// Off, every float `exp` and `nbf` passes, so each derived value is a
    /// valid time and the option is what refuses it; 14 cells change.
    #[test]
    fn the_time_claim_matrix_without_and_with_integer_time_claims() {
        let now = jsonwebtoken::get_current_timestamp();
        let matrix = time_matrix(now);
        assert_eq!(matrix.len(), 24);
        assert_eq!(
            matrix.iter().filter(|(_, _, off, on)| off != on).count(),
            14,
            "3 float cells each of exp and nbf, and all 8 of iat"
        );

        for (case, token, off, on) in &matrix {
            assert_verdict(
                checked(token, &client_checks()),
                *off,
                &format!("off, {case}"),
            );
            assert_verdict(
                checked(token, &integer_time_checks()),
                *on,
                &format!("on, {case}"),
            );
        }
    }

    #[test]
    fn integer_time_claims_pass_integers_and_absent_nbf_or_iat_and_still_require_exp() {
        let now = jsonwebtoken::get_current_timestamp();
        let integers = time_token(now, TimeClaim::Exp, Some(&(now + 3600).to_string()));
        for checks in [&client_checks(), &integer_time_checks()] {
            let claims = checked(&integers, checks).expect("integer exp, nbf and iat");
            assert_eq!(claims["exp"], json!(now + 3600));
            checked(&time_token(now, TimeClaim::Nbf, None), checks).expect("no nbf");
            checked(&time_token(now, TimeClaim::Iat, None), checks).expect("no iat");
            assert_rejected(
                checked(&time_token(now, TimeClaim::Exp, None), checks),
                "a required claim is missing",
                "no exp",
            );
        }
        // The builder's tokens are integers throughout.
        checked(
            &mint(client_claims().not_before_in(-60)),
            &integer_time_checks(),
        )
        .expect("a TestClaims token");
    }

    /// A payload that is not a JSON object never reaches the option's map
    /// read: jsonwebtoken refuses it first, with or without the option.
    #[test]
    fn a_payload_that_is_not_an_object_is_refused_before_the_option() {
        let exp = jsonwebtoken::get_current_timestamp() + 3600;
        for payload in [
            format!(r#"[{exp},null,"user_01TEST","{CLIENT_ISSUER}","aud"]"#),
            format!("{exp}"),
            r#""claims""#.to_owned(),
            "null".to_owned(),
        ] {
            let token = mint_raw(&payload);
            let off = checked(&token, &client_checks()).expect_err(&payload);
            let on = checked(&token, &integer_time_checks()).expect_err(&payload);
            assert_eq!(on.to_string(), off.to_string(), "{payload}");
            assert_ne!(
                on.to_string(),
                format!("token rejected: {NOT_WHOLE_SECONDS}"),
                "{payload}"
            );
        }
    }

    /// Both verifiers built from a consumer's `ClaimChecks` apply the
    /// option through `verify_bearer_claims`, over the whole matrix.
    #[tokio::test]
    async fn for_issuer_and_with_cache_verifiers_apply_integer_time_claims() {
        // One fetch per verifier: each holds its own cache.
        let server = primary_issuer(3).await;
        let for_issuer = |checks: ClaimChecks| {
            Verifier::for_issuer(checks, jwks_url_of(&server), None, reqwest::Client::new())
        };
        let off = for_issuer(client_checks());
        let on = for_issuer(integer_time_checks());
        let with_cache = Verifier::with_cache(
            integer_time_checks(),
            JwksCache::new(jwks_url_of(&server), reqwest::Client::new()),
        );
        assert!(!off.claim_checks().requires_integer_time_claims());
        assert!(on.claim_checks().requires_integer_time_claims());
        assert!(with_cache.claim_checks().requires_integer_time_claims());

        for (case, token, off_verdict, on_verdict) in
            time_matrix(jsonwebtoken::get_current_timestamp())
        {
            for (verifier, name, verdict) in [
                (&off, "for_issuer off", off_verdict),
                (&on, "for_issuer on", on_verdict),
                (&with_cache, "with_cache on", on_verdict),
            ] {
                assert_verdict(
                    verifier.verify_bearer_claims(&token).await,
                    verdict,
                    &format!("{name}, {case}"),
                );
            }
        }
    }

    /// `claims_with_jwks` and `verify_with_jwks` build slauth's checks
    /// themselves, so the option is never on there.
    #[test]
    fn claims_with_jwks_and_verify_with_jwks_never_require_integer_time_claims() {
        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_raw(&format!(
            r#"{{"iss":"{ISSUER}","aud":"{AUDIENCE}","sub":"s","email":"u@example.com","exp":{}.0,"iat":{now}.5}}"#,
            now + 3600
        ));

        Verifier::claims_with_jwks::<Value>(
            &token,
            &TestKey::primary().jwks(),
            PRIMARY_KID,
            ISSUER,
            AUDIENCE,
        )
        .expect("claims_with_jwks: a float exp and iat pass");
        verify(&token).expect("verify_with_jwks: a float exp and iat pass");
        // The control: the same rules with the option on refuse this token.
        assert_rejected(
            checked(
                &token,
                &ClaimChecks::slauth(ISSUER, AUDIENCE).with_integer_time_claims(true),
            ),
            NOT_WHOLE_SECONDS,
            "slauth's rules with the option on",
        );
    }

    #[test]
    fn time_claims_are_whole_seconds_reads_types_not_values() {
        let read = |text: &str| time_claims_are_whole_seconds(text.as_bytes());
        for passes in [
            r#"{}"#,
            r#"{"exp":0,"nbf":0,"iat":0}"#,
            r#"{"exp":18446744073709551615}"#,
            r#"{"exp":1,"auth_time":1.5,"other":null,"nested":{"iat":1.5}}"#,
            r#"{"\u0065xp":1}"#,
            r#"{"sub":"s","sub":"t"}"#,
        ] {
            assert!(read(passes), "{passes}");
        }
        for fails in [
            r#"{"\u0065xp":1.5}"#,
            r#"{"exp":1,"exp":2}"#,
            r#"{"iat":1,"\u0069at":2}"#,
            r#"[1]"#,
            r#"1"#,
            r#"null"#,
            r#"{"exp":1} trailing"#,
            r#"{"iat":{"$serde_json::private::RawValue":"0"}}"#,
            r#"{"iat":{"$serde_json::private::Number":"0"}}"#,
            r#"{"exp":18446744073709551616}"#,
            r#"{"exp":1e3}"#,
            r#"{"exp":1000.0}"#,
            r#"{"exp":-0}"#,
            r#"{"nbf":null}"#,
            r#"{"iat":"1"}"#,
            r#"{"iat":false}"#,
            r#"{"iat":[1]}"#,
            r#"{"iat":{"s":1}}"#,
        ] {
            assert!(!read(fails), "{fails}");
        }
    }

    /// The payload text a `serde_json::Value` misreads when serde_json's
    /// `raw_value` feature is on: an object holding the private `RawValue`
    /// token becomes the number inside it.
    fn raw_value_iat_payload(now: u64) -> String {
        format!(
            r#"{{"iss":"{CLIENT_ISSUER}","sub":"user_01TEST","exp":{},"iat":{{"$serde_json::private::RawValue":"0"}}}}"#,
            now + 3600
        )
    }

    /// The rule as first written, over a `serde_json::Value` map (tapper's
    /// `whole_seconds_or_absent`): the control the new reading must beat.
    fn value_map_rule(payload: &str) -> bool {
        let claims: serde_json::Map<String, Value> =
            serde_json::from_str(payload).expect("a JSON object");
        ["exp", "nbf", "iat"].into_iter().all(|claim| {
            claims
                .get(claim)
                .is_none_or(|value| value.as_u64().is_some())
        })
    }

    /// An object-valued `iat` is refused with the option on, in this test
    /// build, where serde_json's `raw_value` is on (axum, a dev-dependency,
    /// turns it on) and a `Value` reads that object as `0`.
    #[test]
    fn a_raw_value_object_is_not_a_whole_number_of_seconds() {
        // Not vacuous: `raw_value` is on here, so a `Value` normalises the
        // object to a number and the rule over it accepts the payload.
        assert_eq!(
            serde_json::from_str::<Value>(r#"{"$serde_json::private::RawValue":"0"}"#)
                .expect("parses"),
            json!(0),
            "serde_json's raw_value is on in this build"
        );
        let payload = raw_value_iat_payload(jsonwebtoken::get_current_timestamp());
        assert!(value_map_rule(&payload), "a Value map misreads the object");

        let token = mint_raw(&payload);
        checked(&token, &client_checks()).expect("off: jsonwebtoken never reads iat");
        let err = checked(&token, &integer_time_checks()).expect_err("on: refused");
        // The reason's literal text, not the constant.
        assert_eq!(
            err.to_string(),
            "token rejected: a time claim is not a whole number of seconds"
        );
        assert!(!time_claims_are_whole_seconds(payload.as_bytes()));
    }

    /// A time claim named twice is no claim to judge: with the option on, a
    /// repeated `iat` (which jsonwebtoken never reads) is malformed, and a
    /// repeated `exp` or `nbf` jsonwebtoken refuses itself, either way.
    #[test]
    fn a_repeated_time_claim_is_malformed() {
        let now = jsonwebtoken::get_current_timestamp();
        let exp = now + 3600;
        let iat_twice = mint_raw(&format!(
            r#"{{"iss":"{CLIENT_ISSUER}","sub":"user_01TEST","exp":{exp},"iat":{now},"iat":{now}}}"#
        ));
        checked(&iat_twice, &client_checks()).expect("off: jsonwebtoken never reads iat");
        assert_rejected(
            checked(&iat_twice, &integer_time_checks()),
            "claims are malformed",
            "iat twice, on",
        );

        for (case, payload) in [
            (
                "exp twice",
                format!(
                    r#"{{"iss":"{CLIENT_ISSUER}","sub":"user_01TEST","exp":{exp},"exp":{exp}}}"#
                ),
            ),
            (
                "nbf twice",
                format!(
                    r#"{{"iss":"{CLIENT_ISSUER}","sub":"user_01TEST","exp":{exp},"nbf":{now},"nbf":{now}}}"#
                ),
            ),
        ] {
            let token = mint_raw(&payload);
            let off = checked(&token, &client_checks()).expect_err(case);
            let on = checked(&token, &integer_time_checks()).expect_err(case);
            assert_eq!(on.to_string(), off.to_string(), "{case}");
        }
    }
}
