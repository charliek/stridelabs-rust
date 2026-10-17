//! Credential redaction for the connection strings `require_postgres` and
//! `require_redis` put in their panic messages — which test runners happily
//! print to CI logs.

/// What a well-formed connection URL of one kind looks like, and the env var
/// it came from (named in the placeholder for one that is not).
pub(crate) struct UrlShape {
    /// The variable the URL is read from, e.g. `DATABASE_URL`.
    pub(crate) env_var: &'static str,
    /// The schemes a URL of this kind may have, e.g. `postgres`.
    pub(crate) schemes: &'static [&'static str],
}

/// Query keys whose values are shown as they are. Every other value is
/// masked: a credential can hide under any key (`password`, `pass`, a token),
/// so only keys known to hold none are trusted with a value.
const VISIBLE_QUERY_KEYS: &[&str] = &["sslmode", "protocol", "db"];

/// Mask the credentials in a connection URL so a panic message never carries
/// one — or render an opaque placeholder when the URL is not shaped so that
/// its credentials can be found.
///
/// The URL is rendered only when it parses with the expected structure:
/// one of `shape`'s schemes, a host, and nothing credential-shaped (an `@` or
/// a `:`) in its path or fragment. Its userinfo password is replaced with
/// `***`, and every query value except [`VISIBLE_QUERY_KEYS`]' is masked.
/// Anything else — a typo'd URL above all, such as
/// `rediss:/default:secret@host` (one slash short, it parses as a generic
/// URL whose PATH holds the credentials) — is reported as
/// `<a {env_var} that is not a well-formed URL (not shown)>` rather than
/// echoed.
pub(crate) fn redact_password(url: &str, shape: &UrlShape) -> String {
    redact(url, shape).unwrap_or_else(|| {
        format!(
            "<a {} that is not a well-formed URL (not shown)>",
            shape.env_var
        )
    })
}

fn redact(url: &str, shape: &UrlShape) -> Option<String> {
    let mut parsed = url::Url::parse(url).ok()?;
    if !shape.schemes.contains(&parsed.scheme()) {
        return None;
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return None;
    }
    let credential_shaped = |text: &str| text.contains('@') || text.contains(':');
    if credential_shaped(parsed.path()) || parsed.fragment().is_some_and(credential_shaped) {
        return None;
    }
    if parsed.password().is_some() {
        // `set_password` fails only for URLs that cannot have a password
        // (no host); this one has a host.
        parsed.set_password(Some("***")).ok()?;
    }
    if parsed.query().is_some() {
        let pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(key, value)| {
                let visible = VISIBLE_QUERY_KEYS
                    .iter()
                    .any(|shown| key.eq_ignore_ascii_case(shown));
                let value = if visible {
                    value.into_owned()
                } else {
                    "***".to_string()
                };
                (key.into_owned(), value)
            })
            .collect();
        parsed.query_pairs_mut().clear().extend_pairs(pairs);
    }
    Some(parsed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const POSTGRES: UrlShape = UrlShape {
        env_var: "DATABASE_URL",
        schemes: &["postgres", "postgresql"],
    };
    const REDIS: UrlShape = UrlShape {
        env_var: "REDIS_URL",
        schemes: &["redis", "rediss"],
    };

    #[test]
    fn redact_password_masks_only_the_password() {
        let redacted = redact_password(
            "postgres://postgres:hunter2@localhost:5438/stridelabs_test",
            &POSTGRES,
        );

        assert!(!redacted.contains("hunter2"), "{redacted}");
        assert!(redacted.contains("postgres://postgres:***@"), "{redacted}");
        assert!(redacted.contains("localhost:5438"), "{redacted}");
        assert!(redacted.contains("stridelabs_test"), "{redacted}");
    }

    #[test]
    fn redact_password_is_a_no_op_without_one() {
        assert_eq!(
            redact_password(
                "postgres://postgres@localhost:5438/stridelabs_test",
                &POSTGRES
            ),
            "postgres://postgres@localhost:5438/stridelabs_test"
        );
        assert_eq!(
            redact_password("redis://localhost:6390/0", &REDIS),
            "redis://localhost:6390/0"
        );
    }

    #[test]
    fn redact_password_on_unparsable_input_stays_opaque() {
        let redacted = redact_password("not a url", &REDIS);
        assert!(!redacted.contains("not a url"));
        assert_eq!(
            redacted,
            "<a REDIS_URL that is not a well-formed URL (not shown)>"
        );
    }

    #[test]
    fn redact_password_masks_query_parameter_credentials_too() {
        // sqlx also accepts `?password=...`, which `Url::password()` never
        // sees — regression for a review-found leak where this shape sailed
        // through the authority-only mask. Any key not known to be harmless
        // is masked the same way.
        for url in [
            "postgres://user@localhost:5438/db?password=hunter2",
            "postgres://user@localhost:5438/db?PASSWORD=hunter2&sslmode=disable",
            "postgres://user@localhost:5438/db?options=-c%20password%3Dhunter2",
            "redis://localhost:6390/0?pass=hunter2",
            "redis://localhost:6390/0?token=hunter2&protocol=resp3",
        ] {
            let shape = if url.starts_with("redis") {
                &REDIS
            } else {
                &POSTGRES
            };
            let redacted = redact_password(url, shape);
            assert!(!redacted.contains("hunter2"), "{redacted}");
            assert!(redacted.contains("***"), "{redacted}");
        }
        // The keys known to hold no credential keep their values.
        let redacted = redact_password(
            "postgres://user@localhost:5438/db?PASSWORD=hunter2&sslmode=disable",
            &POSTGRES,
        );
        assert!(redacted.contains("sslmode=disable"), "{redacted}");
    }

    #[test]
    fn redact_password_masks_a_redis_userinfo_password() {
        for url in [
            "redis://:hunter2@localhost:6390/0",
            "rediss://default:hunter2@example.upstash.io:6379",
        ] {
            let redacted = redact_password(url, &REDIS);
            assert!(!redacted.contains("hunter2"), "{redacted}");
            assert!(redacted.contains(":***@"), "{redacted}");
        }
    }

    /// A URL that parses, but not with the expected structure, may hold its
    /// credentials somewhere the userinfo/query masks never look — so it is
    /// not rendered at all.
    #[test]
    fn a_url_without_the_expected_structure_is_never_rendered() {
        for (url, shape) in [
            // One slash short: a generic URL whose PATH is the credentials.
            ("rediss:/default:hunter2@example.upstash.io:6379", &REDIS),
            ("rediss:default:hunter2@example.upstash.io:6379", &REDIS),
            ("postgres:/postgres:hunter2@localhost:5438/db", &POSTGRES),
            // No host: the credentials end up in the path.
            ("redis:///:hunter2@localhost:6390", &REDIS),
            // Credential-shaped text in the path or fragment.
            ("redis://localhost:6390/:hunter2@localhost", &REDIS),
            ("redis://localhost:6390/0#default:hunter2", &REDIS),
            // Not the expected scheme at all.
            ("http://user:hunter2@localhost:6390/0", &REDIS),
            ("redis+unix:///tmp/redis.sock?pass=hunter2", &REDIS),
            ("mysql://root:hunter2@localhost/db", &POSTGRES),
        ] {
            let redacted = redact_password(url, shape);
            assert!(!redacted.contains("hunter2"), "{url}: {redacted}");
            assert_eq!(
                redacted,
                format!(
                    "<a {} that is not a well-formed URL (not shown)>",
                    shape.env_var
                ),
                "{url}"
            );
        }
    }
}
