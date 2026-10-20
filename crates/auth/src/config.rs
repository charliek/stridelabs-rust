//! The slauth settings a resource server needs.

use std::borrow::Cow;
use std::fmt;

use serde::Deserialize;

/// Everything [`crate::Verifier`] needs to know about the issuer it trusts.
///
/// `Deserialize` so a service can nest it inside its own config struct (a
/// `[slauth]` table in a YAML file, an `SLAUTH_*`-prefixed env group mapped by
/// the caller — this crate doesn't read the environment itself).
///
/// `Debug` prints the two endpoint URLs without their userinfo, query or
/// fragment (`scheme://host[:port]/path`): a URL is configuration, and
/// configuration can carry a credential that a `tracing::info!(?config)`
/// would otherwise put in the logs. The issuer prints exactly as configured,
/// which is what debugging a trailing-slash mismatch takes, unless it is a
/// URL carrying one of those parts (no real `iss` does): then it prints as
/// the endpoints do.
///
/// Notably absent: `client_id`. That belongs to the *browser* half of the
/// flow (the PKCE authorization request), which a resource server never
/// performs; it stays in the consuming app's config next to its redirect URI.
#[derive(Clone, Deserialize)]
pub struct SlauthConfig {
    /// Expected `iss` claim, e.g. `https://auth.example.com`. Compared
    /// exactly — a trailing slash mismatch is a rejected token, not a
    /// near-miss.
    pub issuer: String,
    /// Where the issuer publishes its signing keys, e.g.
    /// `https://auth.example.com/.well-known/jwks.json`.
    pub jwks_url: String,
    /// Expected `aud` claim: this service's identifier at the issuer.
    pub audience: String,
    /// slauth's personal-access-token introspection endpoint, for services
    /// that accept slauth-issued PATs in addition to JWTs (e.g.
    /// `https://auth.example.com/api/v1/pat/validate`).
    ///
    /// Read by [`crate::PatValidator::from_config`]; `None` (or empty) means
    /// the service takes no slauth PATs. [`crate::Verifier`] never reads it,
    /// and [`crate::pat`] is unrelated: it deals in *locally* issued tokens,
    /// validated against the service's own database.
    #[serde(default)]
    pub pat_validate_url: Option<String>,
}

impl fmt::Debug for SlauthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlauthConfig")
            .field("issuer", &redact_issuer(&self.issuer))
            .field("jwks_url", &redact_url(&self.jwks_url))
            .field("audience", &self.audience)
            .field(
                "pat_validate_url",
                &self.pat_validate_url.as_deref().map(redact_url),
            )
            .finish()
    }
}

/// `raw` as `scheme://host[:port]/path`, for a `Debug` impl: the userinfo,
/// query and fragment — the parts that can hold a credential — are dropped.
///
/// Parsed with the same parser reqwest fetches with (`reqwest::Url` is
/// `url::Url`), so the host shown is the host requested. A string that does
/// not parse to a URL with a host renders as a fixed placeholder instead:
/// where its credential would start is exactly what cannot be known.
pub(crate) fn redact_url(raw: &str) -> String {
    reqwest::Url::parse(raw)
        .ok()
        .and_then(|url| {
            let host = url.host_str()?;
            let port = url
                .port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default();
            Some(format!("{}://{host}{port}{}", url.scheme(), url.path()))
        })
        .unwrap_or_else(|| "<unparseable URL>".to_owned())
}

/// An issuer (an `iss` value) for a `Debug` impl: exactly as configured,
/// unless it parses as a URL with a host and carries userinfo, a query or a
/// fragment, which is then rendered as [`redact_url`] renders an endpoint.
///
/// Not [`redact_url`] outright: an issuer is compared exactly, and the
/// parser's normalisation would hide the mismatch someone is reading the
/// `Debug` to find (`https://auth.example.com` renders as
/// `https://auth.example.com/`, the very trailing slash in question). No
/// real `iss` carries a credential, so the exact form is what prints in
/// practice; one that does gives up its exactness to keep the credential
/// out of the logs. Anything else (a plain-string issuer, or a URL with no
/// host to redact around) prints as-is.
pub(crate) fn redact_issuer(issuer: &str) -> Cow<'_, str> {
    match reqwest::Url::parse(issuer) {
        Ok(url)
            if url.host_str().is_some()
                && (!url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()) =>
        {
            Cow::Owned(redact_url(issuer))
        }
        _ => Cow::Borrowed(issuer),
    }
}

#[cfg(test)]
mod tests {
    use super::{redact_issuer, redact_url};

    #[test]
    fn redact_url_keeps_scheme_host_port_and_path_only() {
        for (input, expected) in [
            (
                "https://auth.example.com/.well-known/jwks.json",
                "https://auth.example.com/.well-known/jwks.json",
            ),
            (
                "http://user:SECRET@auth.example.com:8443/jwks?token=SECRET#SECRET",
                "http://auth.example.com:8443/jwks",
            ),
            (
                "https://SECRET@auth.example.com/jwks",
                "https://auth.example.com/jwks",
            ),
            (
                "https://auth.example.com/jwks?token=SECRET",
                "https://auth.example.com/jwks",
            ),
            (
                "https://auth.example.com/jwks#SECRET",
                "https://auth.example.com/jwks",
            ),
            // An `@` in the password: the authority ends at the LAST one.
            (
                "https://u:SE@CRET@auth.example.com/jwks",
                "https://auth.example.com/jwks",
            ),
            (
                "http://[::1]:8080/jwks?token=SECRET",
                "http://[::1]:8080/jwks",
            ),
            // The parser's normalisation shows through: a default port is
            // dropped and an empty path is `/`.
            (
                "https://auth.example.com:443?token=SECRET",
                "https://auth.example.com/",
            ),
        ] {
            assert_eq!(redact_url(input), expected, "{input}");
        }
    }

    #[test]
    fn an_unparseable_url_renders_nothing_of_itself() {
        for input in [
            "",
            "not a url?token=SECRET",
            "auth.example.com/jwks?token=SECRET",
            "http://user:SECRET@[::1/jwks?token=SECRET",
            "http://user:SECRET@auth example.com/jwks",
            // Parses, but has no host to show.
            "mailto:user:SECRET@auth.example.com?token=SECRET",
        ] {
            let rendered = redact_url(input);
            assert_eq!(rendered, "<unparseable URL>", "{input}");
        }
    }

    #[test]
    fn an_issuer_prints_exactly_unless_it_carries_url_credentials() {
        for (input, expected) in [
            // Exact: no slash added, none taken away, nothing normalised.
            ("https://auth.example.com", "https://auth.example.com"),
            ("https://auth.example.com/", "https://auth.example.com/"),
            (
                "HTTPS://Auth.Example.com:443",
                "HTTPS://Auth.Example.com:443",
            ),
            (
                "https://api.workos.com/user_management/client_01",
                "https://api.workos.com/user_management/client_01",
            ),
            // Not a URL with a host: there is nothing to redact around.
            ("slauth", "slauth"),
            ("", ""),
            // A credential-bearing part drops, as an endpoint's does.
            (
                "https://user:SECRET@auth.example.com/tenant?token=SECRET#SECRET",
                "https://auth.example.com/tenant",
            ),
            (
                "https://:SECRET@auth.example.com/",
                "https://auth.example.com/",
            ),
            (
                "https://auth.example.com?token=SECRET",
                "https://auth.example.com/",
            ),
            (
                "https://auth.example.com/#SECRET",
                "https://auth.example.com/",
            ),
        ] {
            assert_eq!(redact_issuer(input), expected, "{input}");
        }
    }
}
