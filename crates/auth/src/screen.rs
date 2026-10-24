//! What a token must look like before its key is looked up.
//!
//! [`crate::Verifier::verify_bearer_claims`] (and so `verify_bearer`) reads
//! the token's `kid` and asks the [`crate::JwksCache`] for it, which may
//! fetch. A [`ScreenPolicy`] decides what is checked first. Under either
//! policy a refusal here is a verdict on the token ([`AuthError::MalformedToken`],
//! [`AuthError::MissingKid`] or [`AuthError::InvalidToken`]), made with no
//! key lookup: no fetch, and never an [`AuthError::Jwks`], an
//! [`AuthError::UnseenKid`] or an [`AuthError::UnusableKey`], whatever the
//! issuer is doing.
//!
//! Neither policy decides whether the token is good: the signature and the
//! claims are checked once a key is in hand, as before.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{decode_header, Algorithm, Header};
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;

use crate::error::AuthError;

/// The longest token [`ScreenPolicy::Strict`] looks at, in bytes: 16 KiB.
/// An access token from Hydra (slauth) is about 1–2 KiB, its RS256 signature
/// alone 342 characters; a longer one is refused before anything in it is
/// decoded.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// The longest `kid` [`ScreenPolicy::Strict`] looks up, in bytes. slauth's
/// are UUIDs (36 bytes); a longer one is refused before the lookup, so it is
/// never held, compared against a key set or logged.
pub const MAX_KID_BYTES: usize = 256;

/// What a [`crate::Verifier`] checks before it looks the token's key up
/// ([`crate::Verifier::screen`]).
///
/// `#[non_exhaustive]`: another policy can join without breaking a
/// consumer's `match`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScreenPolicy {
    /// What every verifier has always done: the header must parse (so its
    /// `alg` is one jsonwebtoken knows, `none` excluded), else
    /// [`AuthError::MalformedToken`]; and it must carry a `kid`, else
    /// [`AuthError::MissingKid`]. Anything else wrong with the token is
    /// found after the key lookup, which may fetch the issuer's set.
    #[default]
    Basic,
    /// Everything [`ScreenPolicy::Basic`] checks and more, all before the
    /// key lookup, in this order:
    ///
    /// | check | refusal |
    /// |---|---|
    /// | at most [`MAX_TOKEN_BYTES`] | [`AuthError::MalformedToken`] |
    /// | exactly three dot-separated segments, none empty | [`AuthError::MalformedToken`] |
    /// | each segment unpadded base64url (jsonwebtoken's own decoding) | [`AuthError::MalformedToken`] |
    /// | a header jsonwebtoken parses | [`AuthError::MalformedToken`] |
    /// | no `crit` header parameter, whatever its value (`[]` and `null` included) | [`AuthError::InvalidToken`] |
    /// | a payload that is UTF-8 throughout and a JSON object (its members are not read here) | [`AuthError::MalformedToken`] |
    /// | `alg` RS256 | [`AuthError::InvalidToken`] ("algorithm is not accepted") |
    /// | a `kid`, not empty | [`AuthError::MissingKid`] |
    /// | a `kid` of at most [`MAX_KID_BYTES`] | [`AuthError::InvalidToken`] |
    ///
    /// So a token that cannot verify, or that this crate would only refuse
    /// once a key was in hand (HS256, say), costs no lookup, and can neither
    /// make the cache fetch nor be answered with an outage while the issuer
    /// is down. `crit` is refused in any form because RFC 7515 §4.1.11
    /// requires a recipient to refuse a `crit` naming an extension it does
    /// not support, this crate supports none, and `[]` and `null` are not
    /// valid `crit` values either. The refusal's reason (a fixed phrase,
    /// nothing from the token) is logged at `debug`.
    Strict,
}

/// `token`'s `kid`, if `policy` lets it through to the key lookup.
pub(crate) fn kid_for_lookup(token: &str, policy: ScreenPolicy) -> Result<String, AuthError> {
    match policy {
        ScreenPolicy::Basic => {
            let header = decode_header(token).map_err(|_| AuthError::MalformedToken)?;
            header.kid.ok_or(AuthError::MissingKid)
        }
        ScreenPolicy::Strict => strict(token).map_err(|(reason, err)| {
            tracing::debug!(reason, "bearer token refused before the key lookup");
            err
        }),
    }
}

/// [`ScreenPolicy::Strict`]'s checks, in its table's order; a refusal comes
/// with its reason for the log line.
fn strict(token: &str) -> Result<String, (&'static str, AuthError)> {
    let malformed = |reason| (reason, AuthError::MalformedToken);
    let invalid = |reason: &'static str| (reason, AuthError::InvalidToken(reason.to_owned()));

    if token.len() > MAX_TOKEN_BYTES {
        return Err(malformed("over the size bound"));
    }
    let mut segments = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(malformed("not three segments"));
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(malformed("an empty segment"));
    }
    let (Ok(header_json), Ok(payload_json), Ok(_)) = (
        URL_SAFE_NO_PAD.decode(header),
        URL_SAFE_NO_PAD.decode(payload),
        URL_SAFE_NO_PAD.decode(signature),
    ) else {
        return Err(malformed("a segment that is not unpadded base64url"));
    };
    // `decode_header`'s own parse, on the bytes decoded above: jsonwebtoken
    // refuses a header whose `alg` it does not know, `none` included.
    let header: Header =
        serde_json::from_slice(&header_json).map_err(|_| malformed("not a JWT header"))?;
    // `Header::crit` cannot tell `"crit": null` from no `crit`; the member
    // can. (The header just parsed, so it is a JSON object.)
    let has_crit =
        serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&header_json)
            .map_or(true, |members| members.contains_key("crit"));
    if has_crit {
        return Err(invalid("critical header parameters are not supported"));
    }
    // UTF-8 first, and whole: skipping the members below does not validate
    // the strings it skips, and JSON text is UTF-8 (RFC 8259 §8.1).
    let Ok(payload_text) = std::str::from_utf8(&payload_json) else {
        return Err(malformed("a payload that is not UTF-8"));
    };
    if serde_json::from_str::<JsonObject>(payload_text).is_err() {
        return Err(malformed("a payload that is not a JSON object"));
    }
    if header.alg != Algorithm::RS256 {
        return Err(invalid("algorithm is not accepted"));
    }
    match header.kid {
        None => Err(("no kid", AuthError::MissingKid)),
        Some(kid) if kid.is_empty() => Err(("an empty kid", AuthError::MissingKid)),
        Some(kid) if kid.len() > MAX_KID_BYTES => Err(invalid("key id is too long")),
        Some(kid) => Ok(kid),
    }
}

/// A JSON object, its members skipped without being kept. Anything else (an
/// array, a string, a number, `null`, text that is not JSON, an object with
/// trailing bytes) fails to deserialize.
struct JsonObject;

impl<'de> Deserialize<'de> for JsonObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<JsonObject, D::Error> {
        struct ObjectVisitor;

        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = JsonObject;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<JsonObject, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(JsonObject)
            }
        }

        deserializer.deserialize_map(ObjectVisitor)
    }
}

#[cfg(test)]
mod tests;
