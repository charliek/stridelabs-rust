//! A URL rendered without its credentials (feature `redact-url`).
//!
//! A service names URLs on purpose — an upstream in a log field, an endpoint
//! in a config struct's `Debug` — and a URL is configuration, which can carry
//! a credential that a `tracing::info!(?config)` would put in the logs.
//! stridelabs-auth renders `SlauthConfig`'s endpoints by this same rule with
//! a crate-private copy: it depends on this crate only behind its `http`
//! feature, so it can't call this one unconditionally.

/// `raw` as `scheme://host[:port]/path`, for a log line or a `Debug` impl:
/// the userinfo, query and fragment — where a URL carries a credential
/// (`user:pass@`, `?token=…`) — are dropped.
///
/// Parsed with `url::Url`, the parser reqwest requests with (`reqwest::Url`
/// is that type), so the host shown is the host a client dials, normalised
/// the way the client sees it: scheme and host lowercased, an
/// internationalised host in its punycode form, the scheme's default port
/// left out, and a special scheme's (`http`, `https`, `ws`, `wss`) empty
/// path shown as `/`. A string that does not parse to a URL with a host
/// renders as the fixed placeholder `<unparseable URL>`: where its credential
/// would start is exactly what cannot be known.
///
/// The path is kept as parsed: this cannot tell a credential in the path
/// (`/hooks/SECRET`) from a route, so such a URL needs a rule of its own.
///
/// ```
/// use stridelabs_http::redact_url;
///
/// assert_eq!(
///     redact_url("https://user:SECRET@api.example.com:8443/v1/feed?token=SECRET#top"),
///     "https://api.example.com:8443/v1/feed",
/// );
/// assert_eq!(redact_url("api.example.com/v1/feed?token=SECRET"), "<unparseable URL>");
/// ```
#[must_use]
pub fn redact_url(raw: &str) -> String {
    url::Url::parse(raw)
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

#[cfg(test)]
mod tests {
    use super::redact_url;

    /// stridelabs-auth's `config::redact_url` table, row for row: a consumer
    /// swapping a copy of that function for this one sees no output change.
    #[test]
    fn keeps_scheme_host_port_and_path_only() {
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

    /// stridelabs-auth's unparseable table, row for row.
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
            assert_eq!(redact_url(input), "<unparseable URL>", "{input}");
        }
    }

    /// Beyond the ported tables: the userinfo and IPv6 shapes a hand-rolled
    /// split would get wrong, the parser's normalisation, and the non-`http`
    /// schemes a service's own configuration names.
    #[test]
    fn redacts_every_url_shape_a_service_configures() {
        for (input, expected) in [
            // Percent-encoded userinfo, including an encoded `@`, `:`, `/`,
            // `?` and `#`: all of it is userinfo, none of it is rendered.
            (
                "https://alice%40example.com:p%40ss%3Aw%2Fo%3Fr%23d@auth.example.com/jwks",
                "https://auth.example.com/jwks",
            ),
            // IPv6 with a credential and a port; the address is shown in
            // its canonical (compressed, lowercase) form.
            (
                "https://user:SECRET@[2001:DB8:0:0:0:0:0:1]:8443/jwks?token=SECRET",
                "https://[2001:db8::1]:8443/jwks",
            ),
            // IPv6 on the scheme's default port.
            ("https://[::1]:443/jwks", "https://[::1]/jwks"),
            // Scheme and host are case-folded; the path is not.
            (
                "HTTPS://Auth.Example.COM/JWKS?token=SECRET",
                "https://auth.example.com/JWKS",
            ),
            // An internationalised host, as the punycode a client resolves.
            (
                "https://bücher.example/feed?token=SECRET",
                "https://xn--bcher-kva.example/feed",
            ),
            (
                "wss://api.example.com/v1/realtime?key=SECRET",
                "wss://api.example.com/v1/realtime",
            ),
            // Non-special schemes keep a non-default port as written, and an
            // empty path stays empty.
            (
                "postgres://app:SECRET@db.internal:5432/app?sslmode=require&password=SECRET",
                "postgres://db.internal:5432/app",
            ),
            (
                "rediss://default:SECRET@eu1-example.upstash.io:6379",
                "rediss://eu1-example.upstash.io:6379",
            ),
        ] {
            assert_eq!(redact_url(input), expected, "{input}");
        }
        for input in [
            // A relative reference has no base to resolve against.
            "//user:SECRET@auth.example.com/jwks",
            "/jwks?token=SECRET",
            // Parse, but have no host to show.
            "file:///home/user/SECRET",
            "data:text/plain,SECRET",
        ] {
            assert_eq!(redact_url(input), "<unparseable URL>", "{input}");
        }
    }
}
