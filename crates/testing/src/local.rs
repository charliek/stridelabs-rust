//! A test URL from the environment, on this machine only.
//!
//! A suite that writes to a server (creates databases, seeds counters,
//! deletes keys) must never be pointed at a shared or remote one by a
//! variable left over in a shell. [`require_local_url`] reads the suite's
//! own variable, and **panics** unless it is set to a URL whose host is
//! loopback, before anything connects. Modelled on tapper-rs's
//! `tests/test_redis` reader and slaudio's harness guards.

use std::net::IpAddr;

/// The URL in `var`, which must be set and name a server on this machine,
/// or a panic saying what to fix.
///
/// The URL's host must be `localhost` (any case), a loopback IP address
/// (`127.0.0.0/8`, `::1`, bracketed or not, or an IPv4-mapped `127.x`), and
/// so must every `host` or `hostaddr` query parameter (libpq and sqlx dial
/// those instead of the URL's authority). A URL with no host (a Unix socket,
/// `postgres:///db`) is refused too: the rule is about the host a test
/// dials. Nothing else is checked: pair it with the probe of the server
/// kind (`require_postgres_at`, feature `postgres`) or, for Redis, use
/// `require_local_redis_url` (feature `redis`), which also rules on the
/// database number.
///
/// Unset and empty are both "not set": that is how a variable someone left
/// unfilled arrives from compose or CI. There is no default to fall back to,
/// on purpose: a default is the dev stack's server.
///
/// # Panics
///
/// When `var` is unset or empty, is not a URL, names no host, or names a
/// host (in the authority or a `host`/`hostaddr` parameter) that is not
/// loopback. The message names the variable, the problem and the fix; it
/// never shows the value, which can carry a password.
///
/// ```no_run
/// // e.g. `export MYAPP_TEST_DATABASE_URL=postgres://dev:dev@localhost:5432/myapp_test`
/// let url = stridelabs_testing::require_local_url("MYAPP_TEST_DATABASE_URL");
/// # let _ = url;
/// ```
pub fn require_local_url(var: &str) -> String {
    require_local_url_from(var, |name| std::env::var(name).ok())
}

/// The env-injectable seam behind [`require_local_url`], so unit tests reach
/// every refusal without mutating the environment.
fn require_local_url_from(var: &str, get: impl Fn(&str) -> Option<String>) -> String {
    checked_local_url(var, get(var).as_deref()).unwrap_or_else(|refusal| panic!("{refusal}"))
}

/// `value` (the variable's, if set) as a local test URL, or the refusal
/// message [`require_local_url`] panics with.
pub(crate) fn checked_local_url(var: &str, value: Option<&str>) -> Result<String, String> {
    let refuse = |problem: &str| Err(refusal(var, problem));
    let Some(raw) = value.filter(|value| !value.is_empty()) else {
        return refuse("is not set");
    };
    let Ok(url) = url::Url::parse(raw) else {
        return refuse("is not a URL");
    };
    match url.host_str() {
        None | Some("") => return refuse("names no host (a Unix socket counts as none)"),
        Some(host) if !is_loopback(host) => {
            return refuse("names a host that is not loopback");
        }
        Some(_) => {}
    }
    let redirected = url
        .query_pairs()
        .any(|(key, value)| matches!(&*key, "host" | "hostaddr") && !is_loopback(&value));
    if redirected {
        return refuse(
            "has a `host` or `hostaddr` query parameter that is not loopback (a client dials \
             it instead of the URL's host)",
        );
    }
    Ok(raw.to_owned())
}

/// The message every refusal is: the variable, the problem, the fix.
pub(crate) fn refusal(var: &str, problem: &str) -> String {
    format!(
        "\n{var} {problem}.\n\n\
         stridelabs-testing never skips a test for a missing server, and never lets a suite \
         write to a server on another machine: set {var} to a URL whose host is this machine \
         (`localhost`, `127.0.0.1` or `::1`), such as the server `docker compose up -d` starts. \
         The value is not shown: a URL can carry a password.\n"
    )
}

/// `localhost` (any case), or a loopback IP address, bracketed or not.
fn is_loopback(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<IpAddr>()
            .is_ok_and(|address| address.to_canonical().is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lookup;

    const VAR: &str = "STRIDELABS_TESTING_LOCAL_URL";

    fn refused(value: &str) -> String {
        checked_local_url(VAR, Some(value)).expect_err(value)
    }

    /// Loopback hosts pass, in each spelling, for Postgres and Redis URLs
    /// alike, and come back as they were given.
    #[test]
    fn a_loopback_url_is_returned_as_given() {
        for url in [
            "postgres://dev:hunter2@localhost:5432/app_test",
            "postgres://dev:dev@LocalHost/app_test",
            "postgresql://dev:dev@127.0.0.1:5438/x",
            "postgres://dev:dev@127.0.0.2/x",
            "postgres://dev:dev@[::1]:5432/x",
            "postgres://dev:dev@[::ffff:127.0.0.1]:5432/x",
            "postgres://dev:dev@localhost/x?host=127.0.0.1&sslmode=disable",
            "redis://localhost:6390/1",
            "redis://:hunter2@127.0.0.1:6379/0",
        ] {
            assert_eq!(checked_local_url(VAR, Some(url)).as_deref(), Ok(url));
        }
        assert_eq!(
            require_local_url_from(VAR, lookup(&[(VAR, "redis://localhost:6390/1")])),
            "redis://localhost:6390/1"
        );
    }

    /// Any other host is refused, before anything connects: a remote name
    /// or address, a name that only starts like `localhost`, a host
    /// redirected by `host=`/`hostaddr=`, and no host at all. The message
    /// never shows the value.
    #[test]
    fn a_host_that_is_not_loopback_is_refused_without_showing_it() {
        for (url, problem) in [
            (
                "postgres://u:hunter2@db.example.com/app",
                "names a host that is not loopback",
            ),
            (
                "postgres://u:hunter2@192.0.2.1:5432/app",
                "names a host that is not loopback",
            ),
            (
                "postgres://u:hunter2@localhost.example.com/app",
                "names a host that is not loopback",
            ),
            (
                "postgres://u:hunter2@localhost./app",
                "names a host that is not loopback",
            ),
            (
                "postgres://u:hunter2@0.0.0.0/app",
                "names a host that is not loopback",
            ),
            (
                "postgres://u:hunter2@%6Cocalhost/app",
                "names a host that is not loopback",
            ),
            (
                "redis://:hunter2@10.0.0.5:6379/1",
                "names a host that is not loopback",
            ),
            (
                "postgres://u:hunter2@localhost/app?host=db.example.com",
                "has a `host` or `hostaddr` query parameter that is not loopback",
            ),
            (
                "postgres://u:hunter2@localhost/app?hostaddr=192.0.2.1",
                "has a `host` or `hostaddr` query parameter that is not loopback",
            ),
            (
                "postgres://u:hunter2@localhost/app?host=%2Fvar%2Frun%2Fpostgresql",
                "has a `host` or `hostaddr` query parameter that is not loopback",
            ),
            ("postgres:///app?password=hunter2", "names no host"),
            ("redis+unix:///tmp/redis.sock?pass=hunter2", "names no host"),
            ("localhost:5432", "names no host"),
            ("not a url hunter2", "is not a URL"),
        ] {
            let message = refused(url);
            assert!(
                message.contains(&format!("{VAR} {problem}")),
                "{url}: {message}"
            );
            assert!(!message.contains("hunter2"), "{url}: {message}");
        }
    }

    /// Unset and empty are both "not set": no default is ever dialled.
    #[test]
    fn an_unset_or_empty_variable_is_refused() {
        for value in [None, Some("")] {
            let message = checked_local_url(VAR, value).expect_err("must be refused");
            assert!(message.contains(&format!("{VAR} is not set.")), "{message}");
            assert!(message.contains("docker compose up -d"), "{message}");
        }
    }

    /// The public entry point panics with the refusal, read through the
    /// lookup it is handed.
    #[test]
    #[should_panic(expected = "STRIDELABS_TESTING_LOCAL_URL names a host that is not loopback")]
    fn require_local_url_panics_with_the_refusal() {
        let _ = require_local_url_from(VAR, lookup(&[(VAR, "postgres://db.example.com/app")]));
    }
}
