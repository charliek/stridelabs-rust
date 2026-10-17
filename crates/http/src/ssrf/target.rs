//! URL validation and normalization: what a URL is allowed to name, and the
//! one normalized host string every later step uses.

use std::net::IpAddr;

use url::{Host, Url};

use super::error::SsrfError;
use super::policy::FetchPolicy;

/// GCP metadata-server names, denied up front ("metadata" is the short alias
/// GCP's resolvers answer for the same host). The address policy refuses the
/// metadata IP too; the names fail fast, with their own message, and also
/// cover a resolver that answers them with something else.
const DENIED_HOSTS: [&str; 2] = ["metadata.google.internal", "metadata"];
const DENIED_SUFFIX: &str = ".metadata.google.internal";

/// A validated fetch target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Target {
    /// The URL the request is sent to, rebuilt around the normalized host.
    pub(super) url: Url,
    pub(super) host: TargetHost,
    /// The URL's port, or its scheme's default.
    pub(super) port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TargetHost {
    /// A host name: IDNA-encoded (punycode), lower-cased, trailing dots
    /// removed. The string the deny-list judged, the resolver is asked for,
    /// the connection is pinned under, and `url`'s host are all this one.
    Name(String),
    /// An IP-literal host, already judged by the address policy.
    Ip(IpAddr),
}

/// Parse `source` and enforce the scheme and host policy, in Python's order:
/// parse → scheme → credentials → host (empty, metadata names) → IP literal.
pub(super) fn validate(source: &str, policy: &FetchPolicy) -> Result<Target, SsrfError> {
    let mut url = match Url::parse(source) {
        Ok(url) => url,
        // No scheme at all. Python parses this as a relative URL whose empty
        // scheme then fails the allowlist, so it gets the scheme message.
        Err(url::ParseError::RelativeUrlWithoutBase) => return Err(policy.scheme_rejection()),
        Err(_) => return Err(SsrfError::InvalidUrl),
    };
    if !policy.schemes.allows(url.scheme()) {
        return Err(policy.scheme_rejection());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(SsrfError::EmbeddedCredentials);
    }

    let host = match url.host() {
        Some(Host::Ipv4(ip)) => TargetHost::Ip(ip.into()),
        Some(Host::Ipv6(ip)) => TargetHost::Ip(ip.into()),
        // `url` has already applied IDNA (UTS #46: case folding, width
        // mapping, punycode) to an http(s) host, so this is the canonical
        // ASCII form. What is left is the trailing dot: `example.com.` is the
        // same host spelled as an absolute name, and must not slip past the
        // name checks below. Python strips every trailing dot; so does this.
        Some(Host::Domain(domain)) => TargetHost::Name(domain.trim_end_matches('.').to_owned()),
        None => return Err(SsrfError::InvalidUrl),
    };

    if let TargetHost::Name(name) = &host {
        if name.is_empty() {
            return Err(SsrfError::InvalidUrl);
        }
        if DENIED_HOSTS.contains(&name.as_str()) || name.ends_with(DENIED_SUFFIX) {
            return Err(SsrfError::HostNotAllowed);
        }
        // Rebuild the request URL around the normalized name, and prove the
        // rebuild took: from here on the name that was checked is the name
        // that is resolved, pinned and requested — reqwest asks the pinned
        // resolver for exactly `url`'s host, and that resolver answers
        // nothing else.
        if url.set_host(Some(name)).is_err()
            || !matches!(url.host(), Some(Host::Domain(rebuilt)) if rebuilt == name)
        {
            return Err(SsrfError::InvalidUrl);
        }
    }

    if let TargetHost::Ip(ip) = host {
        if !policy.permits(ip) {
            return Err(SsrfError::NonPublicHost);
        }
    }

    let port = url.port_or_known_default().ok_or(SsrfError::InvalidUrl)?;
    Ok(Target { url, host, port })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssrf::AllowedSchemes;

    fn strict() -> FetchPolicy {
        FetchPolicy::new("image", 1024)
    }

    fn reject(url: &str) -> String {
        validate(url, &strict())
            .expect_err("must be rejected")
            .to_string()
    }

    fn accept(url: &str) -> Target {
        validate(url, &strict()).unwrap_or_else(|e| panic!("{url} rejected: {e}"))
    }

    fn name(target: &Target) -> &str {
        match &target.host {
            TargetHost::Name(name) => name,
            TargetHost::Ip(ip) => panic!("expected a name, got {ip}"),
        }
    }

    #[test]
    fn only_allowed_schemes_pass() {
        let scheme = "Only https:// URLs are allowed.";
        for url in [
            "http://example.com/a.png",
            "ftp://example.com/a.png",
            "file:///etc/passwd",
            "gopher://example.com/",
            "data:image/png;base64,AAAA",
            // No scheme at all: Python's relative-URL parse fails the
            // allowlist too, so the message is the scheme one.
            "not a url at all",
            "//example.com/a.png",
        ] {
            assert_eq!(reject(url), scheme, "{url}");
        }
        let custom = strict().with_scheme_error("Only https:// image URLs are allowed.");
        assert_eq!(
            validate("http://example.com/", &custom)
                .unwrap_err()
                .to_string(),
            "Only https:// image URLs are allowed."
        );
        let feeds = strict().with_allowed_schemes(AllowedSchemes::HttpAndHttps);
        assert!(validate("http://example.com/rss.xml", &feeds).is_ok());
        assert_eq!(
            validate("ftp://example.com/", &feeds)
                .unwrap_err()
                .to_string(),
            "Only http://, https:// URLs are allowed."
        );
    }

    #[test]
    fn unparseable_urls_are_invalid() {
        for url in [
            "https://",
            "https://exa mple.com/",
            "https://[::1/",
            "https://example.com:99999/",
            "https://./a.png",
            "https://.../a.png",
        ] {
            assert_eq!(reject(url), "Invalid URL.", "{url}");
        }
    }

    #[test]
    fn embedded_credentials_are_rejected() {
        let message = "URLs with embedded credentials are not allowed.";
        for url in [
            "https://user:pass@example.com/a.png",
            "https://user@example.com/a.png",
            "https://:pass@example.com/a.png",
        ] {
            assert_eq!(reject(url), message, "{url}");
        }
    }

    #[test]
    fn metadata_host_names_are_rejected_in_every_spelling() {
        for url in [
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://metadata.google.internal./a.png",
            "https://metadata.google.internal../a.png",
            "https://foo.metadata.google.internal/a.png",
            "https://foo.metadata.google.internal./a.png",
            "https://metadata/computeMetadata/v1/",
            "https://metadata./a",
            "https://METADATA.Google.Internal/a",
            // Full-width letters: IDNA maps them to ASCII before the check.
            "https://\u{ff4d}\u{ff45}\u{ff54}\u{ff41}\u{ff44}\u{ff41}\u{ff54}\u{ff41}/a",
        ] {
            assert_eq!(reject(url), "That host is not allowed.", "{url}");
        }
        // A suffix match is a label match, not a substring one.
        assert!(validate(
            "https://notmetadata.google.internal.example.com/",
            &strict()
        )
        .is_ok());
        assert!(validate("https://metadata.example.com/", &strict()).is_ok());
    }

    /// Python's `TestLiteralIpPolicy`, all nineteen, with its message.
    #[test]
    fn pythons_nineteen_literal_hosts_are_rejected() {
        for host in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.0.10",
            "0.0.0.0",
            "224.0.0.1",
            "240.0.0.1",
            "100.64.0.1",
            "[::1]",
            "[fc00::1]",
            "[fd12:3456::1]",
            "[fe80::1]",
            "[ff02::1]",
            "[::]",
            "[::ffff:127.0.0.1]",
            "[::ffff:169.254.169.254]",
            "[::ffff:10.0.0.1]",
        ] {
            assert_eq!(
                reject(&format!("https://{host}/a.png")),
                "URL host is not a public address.",
                "{host}"
            );
        }
    }

    /// The WHATWG IPv4 parser reads these as `127.0.0.1`; they are literals,
    /// not names, and never reach a resolver that might answer otherwise.
    #[test]
    fn alternative_ipv4_spellings_are_judged_as_the_address_they_are() {
        for host in ["0x7f.1", "2130706433", "127.1", "0177.0.0.1", "127.0.0.1."] {
            assert_eq!(
                reject(&format!("https://{host}/a.png")),
                "URL host is not a public address.",
                "{host}"
            );
        }
    }

    #[test]
    fn a_public_literal_passes_and_skips_dns() {
        let v4 = accept("https://93.184.216.34/a.png");
        assert_eq!(v4.host, TargetHost::Ip("93.184.216.34".parse().unwrap()));
        assert_eq!(v4.port, 443);
        let v6 = accept("https://[2606:2800:220:1:248:1893:25c8:1946]:8443/a.png");
        assert_eq!(
            v6.host,
            TargetHost::Ip("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap())
        );
        assert_eq!(v6.port, 8443);
    }

    /// The hostname invariant: one normalized string, and the request URL
    /// is rebuilt around it.
    #[test]
    fn the_host_is_normalized_and_the_url_rebuilt_around_it() {
        let dotted = accept("https://images.example.com./a.png?x=1");
        assert_eq!(name(&dotted), "images.example.com");
        assert_eq!(dotted.url.as_str(), "https://images.example.com/a.png?x=1");

        let shouty = accept("https://IMAGES.Example.COM../a.png");
        assert_eq!(name(&shouty), "images.example.com");
        assert_eq!(shouty.url.as_str(), "https://images.example.com/a.png");

        let idna = accept("https://B\u{dc}CHER.example./a.png");
        assert_eq!(name(&idna), "xn--bcher-kva.example");
        assert_eq!(idna.url.as_str(), "https://xn--bcher-kva.example/a.png");

        let ported = accept("https://images.example.com.:8443/a.png");
        assert_eq!(name(&ported), "images.example.com");
        assert_eq!(ported.port, 8443);
        assert_eq!(ported.url.as_str(), "https://images.example.com:8443/a.png");
    }

    #[test]
    fn the_port_defaults_by_scheme() {
        assert_eq!(accept("https://images.example.com/").port, 443);
        let feeds = strict().with_allowed_schemes(AllowedSchemes::HttpAndHttps);
        assert_eq!(
            validate("http://feeds.example.com/", &feeds).unwrap().port,
            80
        );
        // An explicit default port is the same port.
        assert_eq!(accept("https://images.example.com:443/").port, 443);
    }
}
