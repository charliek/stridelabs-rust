//! The protected resource: an MCP endpoint's canonical URL and everything
//! derived from it.
//!
//! One string has to be identical in four places: the `aud` slauth stamps on
//! the access tokens it mints for the endpoint, the audience this crate's
//! verifier demands, the `resource` member of the RFC 9728 metadata document,
//! and the URL a client was configured with (it compares the document's
//! `resource` with that URL before trusting it). A [`ProtectedResource`] is
//! that string, validated once, plus what follows from it: the metadata
//! document, the metadata URL a `401` challenge points at, the route the
//! endpoint is served on, and the `Host` the transport accepts.
//!
//! # The canonical URL rule
//!
//! The rule is slauth's own (`normalize_mcp_resource`, the RFC 8707
//! `resource` → token `aud` translation), because slauth compares verbatim
//! and mints exactly the string it canonicalized to:
//!
//! - `https` only. Local development is real https too (a dev host such as
//!   `https://parcel.local.stridelabs.ai/mcp` behind a TLS-terminating proxy),
//!   so there is no `http` or loopback carve-out. A test that serves over
//!   plain http on `127.0.0.1` still names an `https` resource: the URL is an
//!   identifier, and the `Host` check is configured separately
//!   ([`crate::server_config`]'s extra hosts).
//! - Lowercase scheme and host; path case is preserved (RFC 3986: only the
//!   scheme and host are case-insensitive).
//! - No trailing slash, and no port unless it is not the default (`:443` is
//!   dropped; any other port is kept, as slauth keeps it).
//! - No query, fragment or userinfo; no percent-escapes, backslashes or
//!   non-ASCII characters; no empty, `.` or `..` path segments.
//!
//! slauth *normalizes* input that is merely non-canonical (`HTTPS://Host/mcp/`
//! becomes `https://host/mcp`). This crate **rejects** it instead, naming the
//! canonical form in [`ResourceError::NotCanonical`]: the configured string is
//! then the token audience byte for byte, rather than a value that becomes
//! one after a rewrite nobody sees.
//!
//! Two restrictions go beyond slauth's, both for strings slauth would accept
//! but no deployment uses: the host must be a DNS-style name (ASCII letters,
//! digits, `-`, `.`, `_`) or a bracketed IPv6 literal, and each path segment
//! may use only RFC 3986's unreserved characters (letters, digits, `-`, `.`,
//! `_`, `~`). The path also becomes an axum route (where `{`, `}` and `*`
//! mean something) and is quoted into a `WWW-Authenticate` header, so a
//! character outside that set is refused rather than escaped.

use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};
use stridelabs_auth::{Audience, ClaimChecks};

/// Where RFC 9728 puts protected-resource metadata, at the origin root.
pub const METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

/// Why a [`ProtectedResource`] could not be built.
///
/// No variant echoes the URL it was given: configuration can carry a
/// credential (a userinfo or a query token is exactly what the rule rejects),
/// and these errors end up in startup logs. [`ResourceError::NotCanonical`]
/// carries the *canonical* form instead, which by construction has neither.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ResourceError {
    /// The URL is valid but not in canonical form; `canonical` is the string
    /// to configure instead (it is the token audience slauth mints).
    #[error("MCP resource URL is not canonical; configure {canonical:?} instead")]
    NotCanonical {
        /// The canonical form of the URL that was given.
        canonical: String,
    },
    /// The URL breaks the canonical URL rule in a way no rewrite can fix.
    /// `reason` is a fixed phrase.
    #[error("MCP resource URL is invalid: it {reason}")]
    InvalidUrl {
        /// Which rule the URL breaks.
        reason: &'static str,
    },
    /// The authorization server's issuer is empty.
    #[error("the authorization server issuer must not be empty")]
    EmptyIssuer,
    /// A scope is not an RFC 6749 §3.3 scope token (non-empty; printable
    /// ASCII other than space, `"` and `\`). Scopes are configuration, not
    /// caller input, so the offending value is shown.
    #[error("{scope:?} is not a valid OAuth scope token")]
    InvalidScope {
        /// The offending scope.
        scope: String,
    },
}

/// An MCP endpoint as an OAuth 2.0 protected resource: its canonical URL,
/// the authorization server that issues tokens for it, and its scopes.
///
/// Build it once at startup and hand it (or a clone) to
/// [`crate::metadata_router`], [`crate::McpVerifier::new`] and
/// [`crate::server_config`]: every string those derive — the metadata
/// document, the challenge's `resource_metadata` URL, the verifier's
/// audience, the route, the allowed `Host` — comes from this one value.
///
/// ```
/// use stridelabs_mcp::ProtectedResource;
///
/// let resource = ProtectedResource::new(
///     "https://parcel.stridelabs.ai/mcp",
///     "https://auth.stridelabs.ai",
///     ["parcel:read", "parcel:write"],
/// )?;
///
/// assert_eq!(
///     resource.metadata_url(),
///     "https://parcel.stridelabs.ai/.well-known/oauth-protected-resource/mcp",
/// );
/// assert_eq!(resource.endpoint_path(), "/mcp");
/// assert_eq!(resource.scope_hint(), "parcel:read parcel:write");
/// # Ok::<(), stridelabs_mcp::ResourceError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedResource {
    url: String,
    host: String,
    /// `""` for a resource at the origin root, else `/seg[/seg…]`.
    path: String,
    metadata_url: String,
    issuer: String,
    scopes_supported: Vec<String>,
    scope_hint: String,
}

impl ProtectedResource {
    /// Validate `resource_url` (see the [module docs](self) for the rule) and
    /// build the resource. `issuer` is the authorization server (slauth's
    /// issuer, exactly as it appears in tokens' `iss`); `scopes_supported`
    /// are the scopes the endpoint understands, in the order the metadata
    /// document lists them. The scope hint defaults to them joined by
    /// spaces; see [`ProtectedResource::with_scope_hint`].
    pub fn new<I, S>(
        resource_url: &str,
        issuer: impl Into<String>,
        scopes_supported: I,
    ) -> Result<ProtectedResource, ResourceError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let parts = canonical_parts(resource_url)?;
        let canonical = parts.url();
        if canonical != resource_url {
            return Err(ResourceError::NotCanonical { canonical });
        }

        let issuer = issuer.into();
        if issuer.is_empty() {
            return Err(ResourceError::EmptyIssuer);
        }
        let scopes_supported: Vec<String> = scopes_supported.into_iter().map(Into::into).collect();
        for scope in &scopes_supported {
            check_scope_token(scope)?;
        }

        let metadata_url = format!("{}{METADATA_PATH}{}", parts.origin(), parts.path);
        Ok(ProtectedResource {
            url: canonical,
            host: parts.host,
            path: parts.path,
            metadata_url,
            issuer,
            scope_hint: scopes_supported.join(" "),
            scopes_supported,
        })
    }

    /// Replace the `scope` advertised in `401` challenges — the scopes a
    /// client should request when it (re)authorizes, which may be fewer than
    /// [`ProtectedResource::scopes_supported`] (a connector's scope ceiling,
    /// say). Space-separated scope tokens; an empty hint omits the `scope`
    /// parameter from challenges altogether.
    pub fn with_scope_hint(
        mut self,
        scope_hint: impl Into<String>,
    ) -> Result<ProtectedResource, ResourceError> {
        let scope_hint = scope_hint.into();
        for scope in scope_hint.split(' ').filter(|scope| !scope.is_empty()) {
            check_scope_token(scope)?;
        }
        // Normalised to single spaces: the hint is quoted into a header.
        self.scope_hint = scope_hint.split_whitespace().collect::<Vec<_>>().join(" ");
        Ok(self)
    }

    /// The canonical resource URL: the token audience, and the metadata
    /// document's `resource`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The authorization server's issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Claim rules for tokens minted for this resource, to adjust and hand to
    /// [`crate::McpVerifier::with_cache`]: the issuer, exactly, and `aud`
    /// required and equal to the resource URL, with
    /// [`ClaimChecks::new`]'s defaults otherwise (a 60 s leeway, `nbf`
    /// checked).
    pub fn claim_checks(&self) -> ClaimChecks {
        ClaimChecks::new(&self.issuer, Audience::Required(self.url.clone()))
    }

    /// The scopes the metadata document lists.
    pub fn scopes_supported(&self) -> &[String] {
        &self.scopes_supported
    }

    /// The `scope` value of `401` challenges (empty: no `scope` parameter).
    pub fn scope_hint(&self) -> &str {
        &self.scope_hint
    }

    /// The resource's host as it appears in the URL (a bracketed literal for
    /// IPv6): the `Host` [`crate::server_config`] allows, on any port.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The path the MCP endpoint is served on: the URL's path, or `/` for a
    /// resource at the origin root.
    pub fn endpoint_path(&self) -> &str {
        if self.path.is_empty() {
            "/"
        } else {
            &self.path
        }
    }

    /// Where a `401` challenge's `resource_metadata` points: the origin, the
    /// RFC 9728 well-known path, then the resource's path, e.g.
    /// `https://parcel.stridelabs.ai/.well-known/oauth-protected-resource/mcp`.
    pub fn metadata_url(&self) -> &str {
        &self.metadata_url
    }

    /// The origin-relative paths the metadata document is served at: the
    /// bare well-known path, and (for a resource with a path) the variant
    /// suffixed with it. Clients try either, depending on spec revision.
    pub fn metadata_paths(&self) -> Vec<String> {
        let mut paths = vec![METADATA_PATH.to_owned()];
        if !self.path.is_empty() {
            paths.push(format!("{METADATA_PATH}{}", self.path));
        }
        paths
    }

    /// The RFC 9728 protected-resource metadata document.
    pub fn metadata(&self) -> ResourceMetadata {
        ResourceMetadata {
            resource: self.url.clone(),
            authorization_servers: vec![self.issuer.clone()],
            scopes_supported: self.scopes_supported.clone(),
            bearer_methods_supported: vec!["header".to_owned()],
        }
    }
}

/// An RFC 9728 OAuth 2.0 Protected Resource Metadata document, as
/// [`crate::metadata_router`] serves it.
///
/// `bearer_methods_supported` is always `["header"]`: the boundary reads the
/// `Authorization` header and nothing else (no form-body or query tokens,
/// RFC 6750 §2.2–2.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResourceMetadata {
    /// The canonical resource URL.
    pub resource: String,
    /// The issuer that mints tokens for it.
    pub authorization_servers: Vec<String>,
    /// The scopes it understands.
    pub scopes_supported: Vec<String>,
    /// How a token may be presented.
    pub bearer_methods_supported: Vec<String>,
}

/// A URL taken apart by the canonical rule, every part already canonical.
struct CanonicalParts {
    /// Lowercase; IPv6 literals keep their brackets.
    host: String,
    /// `None` for the default port (dropped).
    port: Option<u16>,
    /// `""` or `/seg[/seg…]`, trailing slashes removed.
    path: String,
}

impl CanonicalParts {
    fn origin(&self) -> String {
        match self.port {
            Some(port) => format!("https://{}:{port}", self.host),
            None => format!("https://{}", self.host),
        }
    }

    fn url(&self) -> String {
        format!("{}{}", self.origin(), self.path)
    }
}

fn invalid(reason: &'static str) -> ResourceError {
    ResourceError::InvalidUrl { reason }
}

/// The canonical parts of `url`, or why it has none. The checks, and their
/// order, follow slauth's `normalize_mcp_resource`.
fn canonical_parts(url: &str) -> Result<CanonicalParts, ResourceError> {
    if !url.is_ascii() {
        return Err(invalid("must be ASCII"));
    }
    if url.contains('%') {
        return Err(invalid("must not contain percent-escapes"));
    }
    if url.contains('\\') {
        return Err(invalid("must not contain a backslash"));
    }
    // slauth's Python twin silently strips some of these (`urlsplit` drops
    // tabs and newlines); a resource identifier containing any is refused.
    if url.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(invalid("must not contain whitespace or control characters"));
    }

    let (scheme, rest) = url.split_once(':').ok_or(invalid("must be an https URL"))?;
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(invalid("must be an https URL"));
    }
    if rest.contains('?') || rest.contains('#') {
        return Err(invalid("must not contain a query or fragment"));
    }
    let rest = rest.strip_prefix("//").ok_or(invalid("has no host"))?;
    let (authority, path) = match rest.find('/') {
        Some(slash) => rest.split_at(slash),
        None => (rest, ""),
    };
    if authority.contains('@') {
        return Err(invalid("must not contain userinfo"));
    }

    let (host, port) = split_host_port(authority)?;
    let port = match port {
        // `host:` with nothing after the colon has no port (slauth agrees).
        None | Some("") => None,
        Some(digits) => {
            if !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("has an invalid port"));
            }
            match digits.parse::<u16>() {
                Ok(443) => None,
                Ok(port) => Some(port),
                Err(_) => return Err(invalid("has an invalid port")),
            }
        }
    };

    let path = path.trim_end_matches('/');
    if !path.is_empty() {
        // `path` starts with `/`; skipping it keeps a bare "/mcp" from
        // yielding a phantom empty first segment.
        for segment in path[1..].split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(invalid("has an empty or dot path segment"));
            }
            if !segment.bytes().all(is_unreserved) {
                return Err(invalid(
                    "has a path character outside letters, digits, '-', '.', '_' and '~'",
                ));
            }
        }
    }

    Ok(CanonicalParts {
        host,
        port,
        path: path.to_owned(),
    })
}

/// Split an authority into a validated, lowercased host and its raw port.
fn split_host_port(authority: &str) -> Result<(String, Option<&str>), ResourceError> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (literal, after) = bracketed
            .split_once(']')
            .ok_or(invalid("has an invalid IPv6 host"))?;
        if literal.parse::<Ipv6Addr>().is_err() {
            return Err(invalid("has an invalid IPv6 host"));
        }
        let port = match after {
            "" => None,
            _ => Some(
                after
                    .strip_prefix(':')
                    .ok_or(invalid("has an invalid port"))?,
            ),
        };
        return Ok((format!("[{}]", literal.to_ascii_lowercase()), port));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty() {
        return Err(invalid("has no host"));
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
    {
        return Err(invalid("has an invalid host"));
    }
    Ok((host.to_ascii_lowercase(), port))
}

/// RFC 3986 `unreserved`.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// RFC 6749 §3.3: `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )`.
fn check_scope_token(scope: &str) -> Result<(), ResourceError> {
    let valid = !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b));
    if valid {
        Ok(())
    } else {
        Err(ResourceError::InvalidScope {
            scope: scope.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://auth.stridelabs.ai";

    fn resource(url: &str) -> Result<ProtectedResource, ResourceError> {
        ProtectedResource::new(url, ISSUER, ["files:read", "files:write"])
    }

    #[test]
    fn canonical_urls_are_accepted_unchanged() {
        for url in [
            "https://parcel.stridelabs.ai/mcp",
            "https://parcel.local.stridelabs.ai/mcp",
            "https://audio.stridelabs.ai/MCP",
            "https://audio.stridelabs.ai:8443/mcp",
            "https://audio.stridelabs.ai/v1/mcp",
            "https://audio.stridelabs.ai/m_c-p.v~1",
            "https://audio.stridelabs.ai",
            "https://xn--udio-8cd.stridelabs.ai/mcp",
            "https://[::1]/mcp",
            "https://[2001:db8::1]:8443/mcp",
        ] {
            let resource = resource(url).unwrap_or_else(|err| panic!("{url}: {err}"));
            assert_eq!(resource.url(), url);
        }
    }

    #[test]
    fn non_canonical_urls_are_rejected_naming_the_canonical_form() {
        for (url, canonical) in [
            (
                "https://parcel.stridelabs.ai/mcp/",
                "https://parcel.stridelabs.ai/mcp",
            ),
            (
                "https://parcel.stridelabs.ai/mcp//",
                "https://parcel.stridelabs.ai/mcp",
            ),
            (
                "HTTPS://Parcel.STRIDELABS.ai/MCP",
                "https://parcel.stridelabs.ai/MCP",
            ),
            (
                "https://parcel.stridelabs.ai:443/mcp",
                "https://parcel.stridelabs.ai/mcp",
            ),
            (
                "https://parcel.stridelabs.ai:/mcp",
                "https://parcel.stridelabs.ai/mcp",
            ),
            (
                "https://parcel.stridelabs.ai/",
                "https://parcel.stridelabs.ai",
            ),
            ("https://[::ABCD]/mcp", "https://[::abcd]/mcp"),
        ] {
            assert_eq!(
                resource(url),
                Err(ResourceError::NotCanonical {
                    canonical: canonical.to_owned()
                }),
                "{url}"
            );
        }
    }

    #[test]
    fn urls_no_rewrite_can_fix_are_invalid() {
        for (url, reason) in [
            ("http://parcel.stridelabs.ai/mcp", "must be an https URL"),
            ("http://127.0.0.1:8080/mcp", "must be an https URL"),
            ("parcel.stridelabs.ai/mcp", "must be an https URL"),
            ("", "must be an https URL"),
            ("https:parcel.stridelabs.ai/mcp", "has no host"),
            ("https:///mcp", "has no host"),
            ("https://:8443/mcp", "has no host"),
            (
                "https://parcel.stridelabs.ai/mcp?x=1",
                "must not contain a query or fragment",
            ),
            (
                "https://parcel.stridelabs.ai/mcp?",
                "must not contain a query or fragment",
            ),
            (
                "https://parcel.stridelabs.ai/mcp#frag",
                "must not contain a query or fragment",
            ),
            (
                "https://user@parcel.stridelabs.ai/mcp",
                "must not contain userinfo",
            ),
            (
                "https://user:secret@parcel.stridelabs.ai/mcp",
                "must not contain userinfo",
            ),
            (
                "https://parcel.stridelabs.ai:notaport/mcp",
                "has an invalid port",
            ),
            (
                "https://parcel.stridelabs.ai:99999/mcp",
                "has an invalid port",
            ),
            (
                "https://parcel.stridelabs.ai:+80/mcp",
                "has an invalid port",
            ),
            (
                "https://parcel.stridelabs.ai/mc%70",
                "must not contain percent-escapes",
            ),
            (
                "https://parcel.stridelabs.ai/%2e%2e/mcp",
                "must not contain percent-escapes",
            ),
            (
                "https://parcel.stridelabs.ai/mcp\\x",
                "must not contain a backslash",
            ),
            (
                "https:\\\\parcel.stridelabs.ai/mcp",
                "must not contain a backslash",
            ),
            ("https://parcel.stridelabs.ai/mcp/café", "must be ASCII"),
            // A leading Cyrillic "а": a confusable host.
            ("https://\u{0430}udio.stridelabs.ai/mcp", "must be ASCII"),
            (
                "https://parcel.stridelabs.ai/mcp x",
                "must not contain whitespace or control characters",
            ),
            (
                " https://parcel.stridelabs.ai/mcp",
                "must not contain whitespace or control characters",
            ),
            (
                "https://parcel.stridelabs.ai/mcp\n",
                "must not contain whitespace or control characters",
            ),
            (
                "https://parcel.stridelabs.ai//mcp",
                "has an empty or dot path segment",
            ),
            (
                "https://parcel.stridelabs.ai/mcp//x",
                "has an empty or dot path segment",
            ),
            (
                "https://parcel.stridelabs.ai/./mcp",
                "has an empty or dot path segment",
            ),
            (
                "https://parcel.stridelabs.ai/../mcp",
                "has an empty or dot path segment",
            ),
            (
                "https://parcel.stridelabs.ai/mcp/..",
                "has an empty or dot path segment",
            ),
            ("https://[localhost]/mcp", "has an invalid IPv6 host"),
            ("https://[::1/mcp", "has an invalid IPv6 host"),
            ("https://[::1]x/mcp", "has an invalid port"),
            ("https://parcel!stridelabs.ai/mcp", "has an invalid host"),
            (
                "https://parcel.stridelabs.ai/{id}",
                "has a path character outside letters, digits, '-', '.', '_' and '~'",
            ),
            (
                "https://parcel.stridelabs.ai/mc\"p",
                "has a path character outside letters, digits, '-', '.', '_' and '~'",
            ),
        ] {
            assert_eq!(
                resource(url),
                Err(ResourceError::InvalidUrl { reason }),
                "{url:?}"
            );
        }
    }

    #[test]
    fn no_error_echoes_the_url_it_was_given() {
        for url in [
            "https://user:SECRET@parcel.stridelabs.ai/mcp",
            "https://parcel.stridelabs.ai/mcp?token=SECRET",
            "http://parcel.stridelabs.ai/SECRET",
        ] {
            let err = resource(url).unwrap_err();
            assert!(!err.to_string().contains("SECRET"), "{err}");
            assert!(!format!("{err:?}").contains("SECRET"), "{err:?}");
        }
    }

    #[test]
    fn everything_derives_from_the_one_url() {
        let resource = resource("https://parcel.stridelabs.ai/mcp").expect("canonical");

        assert_eq!(resource.host(), "parcel.stridelabs.ai");
        assert_eq!(resource.endpoint_path(), "/mcp");
        assert_eq!(
            resource.metadata_url(),
            "https://parcel.stridelabs.ai/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            resource.metadata_paths(),
            [
                "/.well-known/oauth-protected-resource",
                "/.well-known/oauth-protected-resource/mcp",
            ]
        );
        assert_eq!(
            resource.metadata(),
            ResourceMetadata {
                resource: "https://parcel.stridelabs.ai/mcp".into(),
                authorization_servers: vec![ISSUER.into()],
                scopes_supported: vec!["files:read".into(), "files:write".into()],
                bearer_methods_supported: vec!["header".into()],
            }
        );
    }

    #[test]
    fn a_port_and_a_nested_path_carry_into_the_metadata_url() {
        let resource = resource("https://[::1]:8443/v1/mcp").expect("canonical");

        assert_eq!(resource.host(), "[::1]");
        assert_eq!(resource.endpoint_path(), "/v1/mcp");
        assert_eq!(
            resource.metadata_url(),
            "https://[::1]:8443/.well-known/oauth-protected-resource/v1/mcp"
        );
    }

    #[test]
    fn a_resource_at_the_origin_root_has_one_metadata_path() {
        let resource = resource("https://mcp.stridelabs.ai").expect("canonical");

        assert_eq!(resource.endpoint_path(), "/");
        assert_eq!(
            resource.metadata_url(),
            "https://mcp.stridelabs.ai/.well-known/oauth-protected-resource"
        );
        assert_eq!(
            resource.metadata_paths(),
            ["/.well-known/oauth-protected-resource"]
        );
    }

    #[test]
    fn the_scope_hint_defaults_to_the_supported_scopes_and_can_be_narrowed() {
        let resource = resource("https://parcel.stridelabs.ai/mcp").expect("canonical");
        assert_eq!(resource.scope_hint(), "files:read files:write");

        let narrowed = resource
            .clone()
            .with_scope_hint("  files:read   offline_access ")
            .expect("valid scope tokens");
        assert_eq!(narrowed.scope_hint(), "files:read offline_access");
        // The document still lists every supported scope.
        assert_eq!(narrowed.scopes_supported(), ["files:read", "files:write"]);

        let silent = resource
            .with_scope_hint("")
            .expect("an empty hint is allowed");
        assert_eq!(silent.scope_hint(), "");
    }

    #[test]
    fn scopes_must_be_scope_tokens() {
        for bad in ["", "has space", "quo\"te", "back\\slash", "tab\t"] {
            assert_eq!(
                ProtectedResource::new("https://p.stridelabs.ai/mcp", ISSUER, [bad]),
                Err(ResourceError::InvalidScope { scope: bad.into() }),
                "{bad:?}"
            );
        }
        let resource = resource("https://p.stridelabs.ai/mcp").expect("canonical");
        assert_eq!(
            resource.with_scope_hint("ok \"bad\""),
            Err(ResourceError::InvalidScope {
                scope: "\"bad\"".into()
            })
        );
    }

    #[test]
    fn an_empty_issuer_is_refused() {
        assert_eq!(
            ProtectedResource::new("https://p.stridelabs.ai/mcp", "", ["a"]),
            Err(ResourceError::EmptyIssuer)
        );
    }

    #[test]
    fn no_scopes_at_all_is_an_auth_only_resource() {
        let resource =
            ProtectedResource::new("https://p.stridelabs.ai/mcp", ISSUER, Vec::<String>::new())
                .expect("no scopes is allowed");

        assert_eq!(resource.scope_hint(), "");
        assert!(resource.metadata().scopes_supported.is_empty());
    }
}
