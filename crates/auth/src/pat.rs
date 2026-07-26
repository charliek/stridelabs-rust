//! Personal access tokens: generation, hashing, and the prefix convention.
//!
//! A raw token is `<prefix><32 alphanumeric characters>`, e.g.
//! `sw_a1b2c3d4e5f6…`. A service stores only the SHA-256 hash of the raw
//! token — the indexed secret — plus a short **display prefix**
//! (`sw_a1b2c3d4`) that lets a user tell their tokens apart in a list. The raw
//! value is shown once, at creation, and never again.
//!
//! Ported from spendwise-rs's `auth::token`, with the prefix turned into a
//! parameter: `sw_` is that service's brand, not a shared crate's.
//!
//! # What this module is not
//!
//! Storage, lookup, expiry, revocation and last-used tracking are the
//! service's — they are database concerns, and every service models them
//! differently. This module is the pure part: make a token, hash a token,
//! recognise a token's prefix.
//!
//! # On SHA-256 for a stored secret
//!
//! Deliberate, and *not* the mistake it looks like. A password needs a slow
//! KDF because it is low-entropy and human-chosen; this token's body is 32
//! random alphanumeric characters (~190 bits), so an offline attacker with the
//! hash has nothing to guess. What matters here instead is that verification
//! is a single indexed lookup on every proxied request — a bcrypt-per-request
//! design would be a self-inflicted denial of service.

use rand::distr::Alphanumeric;
use rand::Rng;
use sha2::{Digest, Sha256};

/// Length of the random body appended to the prefix.
const BODY_LEN: usize = 32;
/// How many body characters the stored display prefix keeps.
const DISPLAY_BODY_CHARS: usize = 8;
/// The upper bound on a prefix, in bytes.
pub const MAX_PREFIX_LEN: usize = 16;

/// A token prefix that has been checked, e.g. `sw_`.
///
/// Built once at startup (or as a `const`-adjacent value in a module) and
/// reused; the validation exists so a malformed prefix is a boot failure
/// rather than a run of unusable tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatFormat {
    prefix: &'static str,
}

/// Why a prefix was refused.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum PatFormatError {
    /// A prefix is what makes a token recognisable on sight (and greppable in
    /// a secret scanner); an empty one makes every token anonymous.
    #[error("token prefix must not be empty")]
    Empty,
    /// The prefix is bounded so the display prefix stays short and the token
    /// stays a token rather than a sentence.
    #[error("token prefix must be at most {MAX_PREFIX_LEN} bytes (got {len})")]
    TooLong { len: usize },
    /// Only ASCII letters, digits, `_` and `-` are allowed. Two reasons: the
    /// token is sliced by *byte* offset to build the display prefix, which is
    /// only sound for ASCII; and a token travels in an HTTP header, in URLs,
    /// and through shells, where anything else needs escaping.
    #[error("token prefix must be ASCII alphanumeric, '_' or '-' (got {ch:?})")]
    InvalidCharacter { ch: char },
}

/// A freshly minted token, in the three forms a service needs at once.
#[derive(Debug, Clone)]
pub struct GeneratedToken {
    /// The raw token. Show it to the user once; never store it.
    pub raw: String,
    /// SHA-256 hex of `raw` — the stored, indexed secret.
    pub hash: String,
    /// The non-secret display prefix, e.g. `sw_a1b2c3d4`. Safe to store in
    /// plain text and show in a token list.
    pub prefix_display: String,
}

impl PatFormat {
    /// Check a prefix.
    ///
    /// `&'static str` rather than `String`: a prefix is a compile-time
    /// property of the service, not runtime input, and taking it by static
    /// reference says so while keeping [`PatFormat`] `Copy`.
    ///
    /// ```
    /// use stridelabs_auth::PatFormat;
    ///
    /// let format = PatFormat::new("sw_").unwrap();
    /// let token = format.generate();
    ///
    /// assert!(format.has_prefix(&token.raw));
    /// assert_eq!(token.hash, stridelabs_auth::pat::hash(&token.raw));
    /// ```
    pub fn new(prefix: &'static str) -> Result<PatFormat, PatFormatError> {
        if prefix.is_empty() {
            return Err(PatFormatError::Empty);
        }
        if prefix.len() > MAX_PREFIX_LEN {
            return Err(PatFormatError::TooLong { len: prefix.len() });
        }
        if let Some(ch) = prefix
            .chars()
            .find(|ch| !(ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-'))
        {
            return Err(PatFormatError::InvalidCharacter { ch });
        }
        Ok(PatFormat { prefix })
    }

    /// The prefix itself.
    pub fn prefix(&self) -> &'static str {
        self.prefix
    }

    /// Mint a token: prefix + 32 random alphanumeric characters.
    pub fn generate(&self) -> GeneratedToken {
        let body: String = rand::rng()
            .sample_iter(Alphanumeric)
            .take(BODY_LEN)
            .map(char::from)
            .collect();
        let raw = format!("{}{body}", self.prefix);
        let hash = hash(&raw);
        // Byte slice, sound because `new` rejected any non-ASCII prefix and
        // the body is alphanumeric by construction.
        let prefix_display = raw[..self.prefix.len() + DISPLAY_BODY_CHARS].to_string();

        GeneratedToken {
            raw,
            hash,
            prefix_display,
        }
    }

    /// Does `raw` start with this prefix?
    ///
    /// **A `starts_with` and nothing more** — deliberately, and matching what
    /// spendwise checks inline today. It is a cheap "this looks like one of
    /// ours" filter that lets a service skip a database round-trip for a
    /// bearer token that is obviously a JWT instead. It validates neither the
    /// length nor the alphabet of what follows, and a `true` here says
    /// nothing about whether the token exists or is valid — that answer only
    /// comes from looking up [`hash`].
    pub fn has_prefix(&self, raw: &str) -> bool {
        raw.starts_with(self.prefix)
    }
}

/// SHA-256 of a raw token, lowercase hex.
///
/// The stored form. A free function rather than a method because hashing has
/// nothing to do with the prefix: a service verifying an incoming token hashes
/// it the same way whoever issued it did.
pub fn hash(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    // `{:x}` on the digest is byte-identical to `hex::encode` and saves the
    // crate a dependency for its single use.
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format() -> PatFormat {
        PatFormat::new("sw_").expect("valid prefix")
    }

    #[test]
    fn accepts_the_prefixes_services_actually_use() {
        for prefix in ["sw_", "slauth-", "a", "AB_cd-12", "0123456789abcdef"] {
            assert!(PatFormat::new(prefix).is_ok(), "{prefix}");
        }
    }

    #[test]
    fn rejects_an_empty_prefix() {
        assert_eq!(PatFormat::new("").unwrap_err(), PatFormatError::Empty);
    }

    #[test]
    fn rejects_an_overlong_prefix() {
        // 17 bytes, one over the bound.
        let err = PatFormat::new("0123456789abcdefg").unwrap_err();

        assert_eq!(err, PatFormatError::TooLong { len: 17 });
    }

    #[test]
    fn rejects_a_non_ascii_prefix() {
        // Also under the byte bound but not the character bound, which is the
        // slicing hazard the ASCII rule exists for.
        let err = PatFormat::new("swé_").unwrap_err();

        assert_eq!(err, PatFormatError::InvalidCharacter { ch: 'é' });
    }

    #[test]
    fn rejects_punctuation_in_a_prefix() {
        for prefix in ["sw.", "sw ", "sw/", "sw:"] {
            assert!(
                matches!(
                    PatFormat::new(prefix),
                    Err(PatFormatError::InvalidCharacter { .. })
                ),
                "{prefix:?} must be refused"
            );
        }
    }

    #[test]
    fn a_generated_token_round_trips() {
        let format = format();

        let token = format.generate();

        assert!(format.has_prefix(&token.raw));
        assert_eq!(token.raw.len(), "sw_".len() + BODY_LEN);
        assert!(
            token.raw["sw_".len()..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric()),
            "body must be alphanumeric: {}",
            token.raw
        );
        assert_eq!(token.hash, hash(&token.raw));
        assert_eq!(token.hash.len(), 64);
    }

    #[test]
    fn the_display_prefix_is_the_prefix_plus_eight_characters() {
        let token = format().generate();

        assert_eq!(token.prefix_display.len(), "sw_".len() + DISPLAY_BODY_CHARS);
        assert!(token.raw.starts_with(&token.prefix_display));
        assert!(token.prefix_display.starts_with("sw_"));
    }

    #[test]
    fn tokens_are_unique() {
        let a = format().generate();
        let b = format().generate();

        assert_ne!(a.raw, b.raw);
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn hashing_is_deterministic_and_specific() {
        assert_eq!(hash("sw_abc"), hash("sw_abc"));
        assert_ne!(hash("sw_abc"), hash("sw_abd"));
        // A known vector, so a future "optimisation" of the hash function is a
        // failing test rather than every stored token silently invalidated.
        assert_eq!(
            hash("sw_abc"),
            "47b92df3e0bab4ab2a01ba562471014c1017b394e0b1858d97a504474103183d"
        );
    }

    #[test]
    fn has_prefix_does_not_validate_the_body() {
        let format = format();

        // Documented behavior: a bare prefix passes the filter. The lookup by
        // hash is what actually decides.
        assert!(format.has_prefix("sw_"));
        assert!(format.has_prefix("sw_not-alphanumeric!!"));
        assert!(!format.has_prefix("eyJhbGciOiJSUzI1NiJ9.e30."));
        assert!(!format.has_prefix(" sw_abc"));
    }
}
