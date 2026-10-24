//! [`neon_pooler`]: whether a connection reaches Neon's pooled endpoint, and
//! [`neon_pooler_url`]: whether a URL names it anywhere.
//!
//! A transaction pooler (Neon's `-pooler` endpoint, PgBouncer in transaction
//! mode) hands each transaction a different server session, so anything
//! session-scoped (a session-level advisory lock, which a migration runner
//! holds; `SET`; `LISTEN`; a prepared statement) is neither held nor released
//! where the client thinks. Detection is here; whether to refuse is the
//! consumer's call (tapper's and lumen's migrate commands refuse, their
//! servers do not).

use std::fmt;

use percent_encoding::percent_decode_str;
use sqlx::postgres::PgConnectOptions;
use url::Url;

use crate::connect::{pg_split_opts, split_options};

/// How a connection reaches Neon's pooled endpoint. Its text (`Display` and
/// `Debug`) holds a host label or an endpoint id, both of which are letters,
/// digits and `-` only, or a fixed placeholder: never anything else from the
/// URL or the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PoolerRef {
    /// The host has a label ending in `-pooler` (Neon routes by the TLS SNI
    /// name, whose first label names the endpoint): the label, lowercased.
    Host(String),
    /// The startup options select an endpoint whose id ends in `-pooler`
    /// (Neon's routing when there is no usable SNI, e.g. an IP address): the
    /// id, lowercased, or `<an endpoint id that is not printed>` when it is
    /// not letters, digits and `-`.
    Endpoint(String),
}

impl fmt::Display for PoolerRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolerRef::Host(label) => write!(f, "the pooler host `{label}` (a `-pooler` label)"),
            PoolerRef::Endpoint(endpoint) => write!(
                f,
                "the pooled Neon endpoint `{endpoint}`, selected by the startup options \
                 (`options=` or PGOPTIONS)"
            ),
        }
    }
}

/// Whether `options` reach Neon's pooled endpoint, either way Neon routes a
/// connection to it:
///
/// - **the host** sqlx will dial (after `?host=`/`?hostaddr=` and the
///   `PGHOST`/`PGHOSTADDR` fallback) has a `-pooler` label, as is or
///   percent-decoded ([`neon_pooler_host`]);
/// - **the startup options** sqlx will send (`PGOPTIONS` plus every
///   `options=`) select a `-pooler` endpoint: a token `endpoint=<id>-pooler`
///   or `project=<id>-pooler`, case-insensitively, also after a `-c` or `--`
///   prefix (sqlx renders `options[k]=v` as `-c k=v`), read both as Neon's
///   proxy splits the options (Rust's `is_ascii_whitespace`) and as
///   PostgreSQL's `pg_split_opts` does (C's `isspace`, the vertical tab
///   included). The two readings differ only around a
///   vertical tab; reading both cannot miss what Neon routes on, whichever
///   way a future proxy splits. This is deliberately broader than Neon's own
///   parser (which takes an endpoint only from a lone such token): ANY token
///   naming a `-pooler` endpoint counts. Only `endpoint=`/`project=` values
///   are endpoint ids: `-c application_name=app-pooler` selects nothing.
///
/// Detection only: refusing is the caller's decision. A caller that wants to
/// refuse an ambiguous URL as well (a pooler named in the URL's authority
/// but redirected elsewhere by `?host=`, which sqlx would never dial) uses
/// [`neon_pooler_url`].
///
/// ```
/// use stridelabs_postgres::{connect_options, neon_pooler, PoolerRef};
///
/// let pooled = connect_options(
///     "postgres://app:secret@ep-cool-name-123456-pooler.us-east-2.aws.neon.tech/app",
/// )?;
/// assert_eq!(
///     neon_pooler(&pooled),
///     Some(PoolerRef::Host("ep-cool-name-123456-pooler".into()))
/// );
///
/// let direct = connect_options("postgres://app:secret@ep-cool-name-123456.us-east-2.aws.neon.tech/app")?;
/// assert_eq!(neon_pooler(&direct), None);
/// # Ok::<(), stridelabs_postgres::UrlRefusal>(())
/// ```
pub fn neon_pooler(options: &PgConnectOptions) -> Option<PoolerRef> {
    neon_pooler_host(options.get_host()).or_else(|| options.get_options().and_then(pooler_endpoint))
}

/// [`neon_pooler`], plus every host the URL names that sqlx will NOT dial:
/// whether `url` reaches Neon's pooled endpoint, or names it anywhere a
/// reader could take it to.
///
/// sqlx (like libpq) dials the last `?host=` or `?hostaddr=` instead of the
/// URL's authority, so `ep-x-pooler.example.com/db?host=127.0.0.1` dials
/// `127.0.0.1` and [`neon_pooler`] finds nothing. Such a URL is ambiguous:
/// whoever wrote it may have meant the pooler, and the next edit (dropping
/// the parameter) reaches it. So this also reads, through
/// [`neon_pooler_host`], the URL's authority (as is and percent-decoded) and
/// every `host` query value, dialled or not. (`hostaddr` values need no
/// reading: [`connect_options`](crate::connect_options) accepts only an IP
/// address there, which has no label.) A host is reported before an
/// endpoint, and the dialled host before the others.
///
/// `options` must be what [`connect_options`](crate::connect_options)
/// returned for this `url`: the dialled host and the startup options come
/// from it (`PGHOST` and `PGOPTIONS` included), so the URL is checked and
/// parsed once, by the call that also hands back what to connect with. (A
/// `url` that does not parse adds nothing to what `options` show; one that
/// `connect_options` accepted always parses.) The refusal a migration runner
/// needs is then:
///
/// ```
/// use stridelabs_postgres::{connect_options, neon_pooler_url, PoolerRef, UrlRefusal};
///
/// # #[derive(Debug)]
/// # enum Error { InvalidDatabaseUrl(UrlRefusal), Pooler(PoolerRef) }
/// fn direct_connect_options(url: &str) -> Result<sqlx::postgres::PgConnectOptions, Error> {
///     let options = connect_options(url).map_err(Error::InvalidDatabaseUrl)?;
///     match neon_pooler_url(url, &options) {
///         Some(pooler) => Err(Error::Pooler(pooler)),
///         None => Ok(options),
///     }
/// }
///
/// let ambiguous = "postgres://app:secret@ep-x-pooler.example.com/app?host=127.0.0.1";
/// assert!(matches!(
///     direct_connect_options(ambiguous),
///     Err(Error::Pooler(PoolerRef::Host(label))) if label == "ep-x-pooler"
/// ));
/// assert!(direct_connect_options("postgres://app:secret@ep-x.example.com/app").is_ok());
/// ```
pub fn neon_pooler_url(url: &str, options: &PgConnectOptions) -> Option<PoolerRef> {
    let parsed = Url::parse(url).ok();
    let authority = parsed.as_ref().and_then(Url::host_str).map(str::to_owned);
    let redirects = parsed.iter().flat_map(|parsed| {
        parsed
            .query_pairs()
            .filter(|(key, _)| key == "host")
            .map(|(_, value)| value.into_owned())
    });
    neon_pooler_host(options.get_host())
        .or_else(|| {
            authority
                .into_iter()
                .chain(redirects)
                .find_map(|host| neon_pooler_host(&host))
        })
        .or_else(|| options.get_options().and_then(pooler_endpoint))
}

/// Whether `host` (a host name, a comma-separated host list, or anything
/// else naming one) has a label ending in `-pooler`, case-insensitively, as
/// is or percent-decoded. A label is a maximal run of ASCII letters, digits
/// and `-`; `pooler.example.com` and `my-pooler-db.example.com` have none.
pub fn neon_pooler_host(host: &str) -> Option<PoolerRef> {
    pooler_label(host)
        .or_else(|| pooler_label(&percent_decode_str(host).decode_utf8_lossy()))
        .map(PoolerRef::Host)
}

fn pooler_label(value: &str) -> Option<String> {
    value
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .map(str::to_ascii_lowercase)
        .find(|label| label.ends_with("-pooler"))
}

/// The pooled endpoint the startup `options` select, if they select one
/// (see [`neon_pooler`]).
///
/// Neon's proxy keeps the escapes in its tokens; they are read unescaped
/// here, which matches wherever the raw token would: unescaping only drops
/// backslashes, and a raw match has none in its `-c`/`--` prefix, its
/// `endpoint=`/`project=` key or its final `-pooler`.
fn pooler_endpoint(options: &str) -> Option<PoolerRef> {
    let neon = split_options(options, |c| c.is_ascii_whitespace());
    for form in neon.into_iter().chain(pg_split_opts(options)) {
        let form = form.to_ascii_lowercase();
        let setting = form
            .strip_prefix("-c")
            .or_else(|| form.strip_prefix("--"))
            .unwrap_or(&form);
        for key in ["endpoint=", "project="] {
            if let Some(endpoint) = setting.strip_prefix(key) {
                if endpoint.ends_with("-pooler") {
                    return Some(PoolerRef::Endpoint(printable_endpoint(endpoint)));
                }
            }
        }
    }
    None
}

/// An endpoint id for a message: Neon's ids are letters, digits and `-`;
/// anything else is not printed.
fn printable_endpoint(endpoint: &str) -> String {
    if endpoint.len() <= 63
        && endpoint
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        endpoint.to_owned()
    } else {
        "<an endpoint id that is not printed>".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect_options;

    fn detected(url: &str) -> Option<PoolerRef> {
        let options = connect_options(url).unwrap_or_else(|refusal| panic!("{url}: {refusal}"));
        neon_pooler(&options)
    }

    fn host(label: &str) -> Option<PoolerRef> {
        Some(PoolerRef::Host(label.to_owned()))
    }

    fn endpoint(id: &str) -> Option<PoolerRef> {
        Some(PoolerRef::Endpoint(id.to_owned()))
    }

    /// Neon's pooled endpoint, in every host spelling that still reaches it:
    /// any case, a bare label, a percent-escaped `-`, `?host=` (which sqlx
    /// dials instead of the authority).
    #[test]
    fn a_pooler_host_is_detected() {
        for (url, label) in [
            (
                "postgres://u:p@ep-cool-name-123456-pooler.us-east-2.aws.neon.tech/neondb\
                 ?sslmode=require",
                "ep-cool-name-123456-pooler",
            ),
            (
                "postgresql://u:p@EP-X-POOLER.example.com:5432/db",
                "ep-x-pooler",
            ),
            ("postgres://u:p@db-pooler/db", "db-pooler"),
            ("postgres://u:p@ep-x%2Dpooler.example.com/db", "ep-x-pooler"),
            (
                "postgres://u:p@ep-x.example.com/db?host=ep-x-pooler.example.com",
                "ep-x-pooler",
            ),
        ] {
            assert_eq!(detected(url), host(label), "{url}");
        }
    }

    /// The direct endpoint, local hosts, and names that merely contain
    /// "pooler" without being a `-pooler` label are not a pooler; nor is a
    /// pooler authority that `?host=` sends elsewhere (sqlx never dials it:
    /// refusing that ambiguity is the caller's, through `neon_pooler_host`).
    #[test]
    fn a_direct_host_is_not_a_pooler() {
        for url in [
            "postgres://u:p@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb?sslmode=require",
            "postgres://dev:dev@localhost:5432/app",
            "postgresql://dev:dev@127.0.0.1/app",
            "postgres://u:p@pooler.example.com/db",
            "postgres://u:p@my-pooler-db.example.com/db",
            "postgres://u:p@ep-x.example.com/pooler-db",
            "postgres://u:p@ep-x-pooler.example.com/db?host=127.0.0.1",
            "postgres://u:p@ep-x-pooler.example.com/db?hostaddr=127.0.0.1",
        ] {
            assert_eq!(detected(url), None, "{url}");
        }
        assert_eq!(
            neon_pooler_host("ep-x-pooler.example.com"),
            host("ep-x-pooler")
        );
        assert_eq!(
            neon_pooler_host("a.example.com,ep-y-pooler.example.com"),
            host("ep-y-pooler")
        );
        assert_eq!(neon_pooler_host("ep-x.example.com"), None);
    }

    /// Neon routes by an `endpoint=` (or the deprecated `project=`) token in
    /// the startup options when the host gives it no SNI name (an IP). Every
    /// encoding of one that names a `-pooler` endpoint is detected: the
    /// options sqlx will send are read after its own decoding and joining
    /// (several `options=` are appended), split on unescaped whitespace, raw
    /// and unescaped, case-insensitively, also after `-c`/`--`.
    #[test]
    fn a_pooler_endpoint_in_the_startup_options_is_detected() {
        for options in [
            "endpoint%3Dep-x-pooler",
            "project%3Dep-x-pooler",
            "-c%20endpoint%3Dep-x-pooler",
            "-cendpoint%3Dep-x-pooler",
            "--endpoint%3Dep-x-pooler",
            "ENDPOINT%3DEP-X-POOLER",
            "-c%20application_name%3Dsvc%09endpoint%3Dep-x-pooler",
            "endpoint%3Dep%5C-x-pooler",
            "-c%20application_name%3Dsvc&options=endpoint%3Dep-x-pooler",
        ] {
            let url = format!("postgres://u:p@203.0.113.7/db?options={options}");
            assert_eq!(detected(&url), endpoint("ep-x-pooler"), "{url}");
        }
    }

    /// Options that select no pooled endpoint: an endpoint without the
    /// suffix, a setting whose VALUE ends in `-pooler`, and an escaped space
    /// that keeps `endpoint=…` inside another setting's value.
    #[test]
    fn options_that_select_no_pooled_endpoint_are_not_a_pooler() {
        for options in [
            "-c%20application_name%3Dsvc-pooler",
            "endpoint%3Dep-x",
            "-c%20statement_timeout%3Dep-x-pooler",
        ] {
            let url = format!("postgres://u:p@ep-x.example.com/db?options={options}");
            assert_eq!(detected(&url), None, "{url}");
        }
        assert_eq!(
            pooler_endpoint(r"-c application_name=a\ endpoint=ep-x-pooler"),
            None
        );
    }

    /// `PGOPTIONS` reaches the same field the URL's `options=` appends to;
    /// sqlx's own setter stands in for the variable (a test never sets one).
    #[test]
    fn a_pooler_endpoint_from_pgoptions_is_detected() {
        let options = PgConnectOptions::new_without_pgpass()
            .host("203.0.113.7")
            .options([("endpoint", "ep-x-pooler")]);
        assert_eq!(neon_pooler(&options), endpoint("ep-x-pooler"));
        let options = PgConnectOptions::new_without_pgpass()
            .host("203.0.113.7")
            .options([("endpoint", "ep-x")]);
        assert_eq!(neon_pooler(&options), None);
    }

    /// The options are read BOTH ways, on Neon's spaces and on PostgreSQL's.
    /// Each case below is found by exactly one of them, so dropping either
    /// reading fails this test.
    #[test]
    fn the_endpoint_reader_reads_both_tokenisers() {
        // PostgreSQL's reading only: two tokens around the vertical tab, one
        // to Neon's.
        assert_eq!(
            split_options("-capplication_name=x\x0Bendpoint=ep-x-pooler", |c| {
                c.is_ascii_whitespace()
            })
            .len(),
            1,
            "the premise: one token to Neon's reading"
        );
        assert_eq!(
            pooler_endpoint("-capplication_name=x\x0Bendpoint=ep-x-pooler"),
            endpoint("ep-x-pooler")
        );
        // Neon's reading only: an id that ends `-pooler` across the vertical
        // tab, which PostgreSQL splits into `endpoint=ep-x` and `-pooler`.
        assert_eq!(
            pg_split_opts("endpoint=ep-x\x0B-pooler"),
            ["endpoint=ep-x", "-pooler"],
            "the premise: two tokens to PostgreSQL's reading"
        );
        assert_eq!(
            pooler_endpoint("endpoint=ep-x\x0B-pooler"),
            endpoint("<an endpoint id that is not printed>")
        );
        assert_eq!(
            detected(
                "postgres://u:p@203.0.113.7/db?options=-capplication_name%3Dx%0Bendpoint%3Dep-x-pooler"
            ),
            endpoint("ep-x-pooler")
        );
    }

    /// `neon_pooler_url(url, &connect_options(url))`.
    fn detected_in_url(url: &str) -> Option<PoolerRef> {
        let options = connect_options(url).unwrap_or_else(|refusal| panic!("{url}: {refusal}"));
        neon_pooler_url(url, &options)
    }

    /// An ambiguous URL names a pooler where sqlx will not dial it: in the
    /// authority (as is, or percent-encoded) while `?host=`/`?hostaddr=`
    /// redirects the connection, or in a `host` value a later `host` or
    /// `hostaddr` overrides. tapper's and lumen's migrate refusal cases, with
    /// the control on each: `neon_pooler` (the dialled host only) finds
    /// nothing. A `hostaddr` cannot name one: it must be an IP address.
    #[test]
    fn a_pooler_named_anywhere_in_the_url_is_detected() {
        for (url, label) in [
            (
                "postgres://u:p@ep-x-pooler.example.com/db?host=127.0.0.1",
                "ep-x-pooler",
            ),
            (
                "postgres://u:p@ep-x-pooler.example.com/db?hostaddr=127.0.0.1",
                "ep-x-pooler",
            ),
            (
                "postgres://u:p@EP-X%2DPOOLER.example.com/db?host=127.0.0.1",
                "ep-x-pooler",
            ),
            (
                "postgres://u:p@ep-x.example.com/db?host=ep-y-pooler.example.com&host=127.0.0.1",
                "ep-y-pooler",
            ),
            (
                "postgres://u:p@ep-x.example.com/db?host=ep-y-pooler.example.com&hostaddr=127.0.0.1",
                "ep-y-pooler",
            ),
        ] {
            assert_eq!(detected_in_url(url), host(label), "{url}");
            assert_eq!(detected(url), None, "the control: sqlx dials no pooler: {url}");
        }
        assert_eq!(
            connect_options("postgres://u:p@ep-x.example.com/db?hostaddr=ep-y-pooler.example.com")
                .err(),
            Some(crate::UrlRefusal::InvalidValue("hostaddr"))
        );
    }

    /// Everything `neon_pooler` finds, `neon_pooler_url` finds too (the
    /// dialled host, then the startup options), and the dialled host is the
    /// one reported when the URL names two poolers.
    #[test]
    fn neon_pooler_url_finds_what_neon_pooler_finds() {
        for (url, found) in [
            (
                "postgres://u:p@ep-cool-name-123456-pooler.us-east-2.aws.neon.tech/neondb\
                 ?sslmode=require",
                host("ep-cool-name-123456-pooler"),
            ),
            (
                "postgresql://u:p@EP-X-POOLER.example.com:5432/db",
                host("ep-x-pooler"),
            ),
            ("postgres://u:p@db-pooler/db", host("db-pooler")),
            (
                "postgres://u:p@ep-x%2Dpooler.example.com/db",
                host("ep-x-pooler"),
            ),
            (
                "postgres://u:p@ep-x.example.com/db?host=ep-x-pooler.example.com",
                host("ep-x-pooler"),
            ),
            (
                "postgres://u:p@ep-a-pooler.example.com/db?host=ep-b-pooler.example.com",
                host("ep-b-pooler"),
            ),
            (
                "postgres://u:p@203.0.113.7/db?options=endpoint%3Dep-x-pooler",
                endpoint("ep-x-pooler"),
            ),
            (
                "postgres://u:p@203.0.113.7/db?options=-c%20application_name%3Dsvc\
                 &options=endpoint%3Dep-x-pooler",
                endpoint("ep-x-pooler"),
            ),
        ] {
            assert_eq!(detected_in_url(url), found, "{url}");
        }
    }

    /// The direct endpoint, local hosts, names that merely contain "pooler",
    /// and a direct authority redirected to another direct host name no
    /// pooler anywhere; neither does an endpoint without the suffix.
    #[test]
    fn a_url_that_names_no_pooler_is_not_one() {
        for url in [
            "postgres://u:p@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb?sslmode=require",
            "postgres://dev:dev@localhost:5432/app",
            "postgresql://dev:dev@127.0.0.1/app",
            "postgres://u:p@pooler.example.com/db",
            "postgres://u:p@my-pooler-db.example.com/db",
            "postgres://u:p@ep-x.example.com/pooler-db",
            "postgres://u:p@ep-x.example.com/db?host=127.0.0.1&hostaddr=192.0.2.7",
            "postgres://u:p@ep-x.example.com/db?options=endpoint%3Dep-x\
             &application_name=svc-pooler",
        ] {
            assert_eq!(detected_in_url(url), None, "{url}");
        }
        // A URL that does not parse adds nothing to what the options show.
        let options = connect_options("postgres://u:p@ep-x.example.com/db").expect("a URL");
        assert_eq!(neon_pooler_url("not a url ep-y-pooler", &options), None);
    }

    /// The text names the label or the id, never the URL or its password;
    /// an id that is not label-shaped is detected but not printed.
    #[test]
    fn the_text_carries_only_a_label_or_an_id() {
        let found = detected("postgres://u:hunter2-canary@ep-x-pooler.example.com/db")
            .expect("a pooler host");
        for text in [found.to_string(), format!("{found:?}")] {
            assert!(text.contains("ep-x-pooler"), "{text}");
            assert!(!text.contains("hunter2-canary"), "{text}");
        }
        assert_eq!(
            pooler_endpoint("endpoint=secret$stuff-pooler"),
            endpoint("<an endpoint id that is not printed>")
        );
    }
}
