//! [`error_summary`]: a `sqlx::Error` rendered without anything a server, a
//! peer or the URL put into it.

use std::fmt;

/// Render `error` as its SQLSTATE and a fixed description (a database
/// error), or a fixed class name (anything else). Never the message text.
///
/// PostgreSQL's error messages echo what they reject: a setting's value from
/// the startup `options` (`-c statement_timeout=<value>`), the user name in
/// `password authentication failed for user "…"`, a row's values in a unique
/// violation. sqlx's `Display` passes them through, and so do its `Io`,
/// `Tls`, `Protocol` and `Configuration` payloads. Make this the one way a
/// `sqlx::Error` is rendered: every log line, and every `Display` (and
/// hand-written `Debug`) of an error type that wraps one.
///
/// ```
/// let error = sqlx::Error::Protocol("unexpected message carrying hunter2".into());
/// let summary = stridelabs_postgres::error_summary(&error).to_string();
/// assert_eq!(summary, "protocol error");
/// ```
pub fn error_summary(error: &sqlx::Error) -> ErrorSummary<'_> {
    ErrorSummary(error)
}

/// See [`error_summary`]. Its `Debug` is its `Display`, so `?summary` is as
/// safe as `%summary`.
pub struct ErrorSummary<'a>(&'a sqlx::Error);

impl fmt::Display for ErrorSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            sqlx::Error::Database(database) => {
                let code = database.code().filter(|code| {
                    code.len() == 5
                        && code
                            .chars()
                            .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
                });
                match code {
                    Some(code) => write!(
                        f,
                        "database error SQLSTATE {code} ({})",
                        sqlstate_description(&code)
                    ),
                    None => write!(f, "database error (no SQLSTATE)"),
                }
            }
            sqlx::Error::Io(io) => write!(f, "I/O error ({:?})", io.kind()),
            sqlx::Error::Tls(_) => write!(f, "TLS error"),
            sqlx::Error::Protocol(_) => write!(f, "protocol error"),
            sqlx::Error::Configuration(_) => write!(f, "configuration error"),
            sqlx::Error::PoolTimedOut => write!(f, "timed out waiting for a pool connection"),
            sqlx::Error::PoolClosed => write!(f, "the pool is closed"),
            sqlx::Error::WorkerCrashed => write!(f, "the connection worker crashed"),
            sqlx::Error::RowNotFound => write!(f, "no row returned"),
            sqlx::Error::ColumnDecode { .. }
            | sqlx::Error::Decode(_)
            | sqlx::Error::ColumnNotFound(_)
            | sqlx::Error::ColumnIndexOutOfBounds { .. }
            | sqlx::Error::TypeNotFound { .. } => write!(f, "result decoding error"),
            sqlx::Error::Encode(_) => write!(f, "argument encoding error"),
            // `Migrate` (sqlx's `migrate` feature, which this crate does not
            // turn on, so it cannot be named here) lands here too.
            _ => write!(f, "database client error"),
        }
    }
}

impl fmt::Debug for ErrorSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A fixed description of a SQLSTATE: the specific condition for the codes a
/// service is likely to meet, else its class (PostgreSQL's Appendix A).
fn sqlstate_description(code: &str) -> &'static str {
    match code {
        "28P01" => "invalid password",
        "28000" => "invalid authorization specification",
        "3D000" => "database does not exist",
        "3F000" => "schema does not exist",
        "22023" => "invalid parameter value",
        "42704" => "undefined object",
        "42P01" => "undefined table",
        "42703" => "undefined column",
        "42601" => "syntax error",
        "42501" => "insufficient privilege",
        "42P07" => "duplicate table",
        "42710" => "duplicate object",
        "23505" => "unique violation",
        "23503" => "foreign key violation",
        "23502" => "not-null violation",
        "23514" => "check violation",
        "25P02" => "in failed transaction",
        "40001" => "serialization failure",
        "40P01" => "deadlock detected",
        "53300" => "too many connections",
        "55P03" => "lock not available",
        "57014" => "query canceled",
        "57P01" => "admin shutdown",
        "57P03" => "cannot connect now",
        "08001" => "unable to connect",
        "08006" => "connection failure",
        "08P01" => "protocol violation",
        "0A000" => "feature not supported",
        _ => match &code[..2] {
            "08" => "connection exception",
            "0A" => "feature not supported",
            "22" => "data exception",
            "23" => "integrity constraint violation",
            "25" => "invalid transaction state",
            "28" => "invalid authorization specification",
            "3D" => "invalid catalog name",
            "3F" => "invalid schema name",
            "40" => "transaction rollback",
            "42" => "syntax error or access rule violation",
            "53" => "insufficient resources",
            "54" => "program limit exceeded",
            "55" => "object not in prerequisite state",
            "57" => "operator intervention",
            "58" => "system error",
            "XX" => "internal error",
            _ => "other",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "db-error-canary";

    /// Error classes that are not database errors render as fixed names,
    /// whatever their payload carries, in `Display` and `Debug` alike.
    /// (Database errors, whose messages echo what the server rejected, are
    /// driven against a real server in `tests/live.rs`.)
    #[test]
    fn an_error_summary_never_carries_the_error_text() {
        let cases: Vec<(sqlx::Error, &str)> = vec![
            (
                sqlx::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    CANARY,
                )),
                "I/O error (ConnectionRefused)",
            ),
            (sqlx::Error::Protocol(CANARY.to_owned()), "protocol error"),
            (sqlx::Error::Tls(CANARY.into()), "TLS error"),
            (
                sqlx::Error::Configuration(CANARY.into()),
                "configuration error",
            ),
            (
                sqlx::Error::ColumnNotFound(CANARY.to_owned()),
                "result decoding error",
            ),
            (sqlx::Error::Decode(CANARY.into()), "result decoding error"),
            (
                sqlx::Error::Encode(CANARY.into()),
                "argument encoding error",
            ),
            (
                sqlx::Error::InvalidArgument(CANARY.to_owned()),
                "database client error",
            ),
            (
                sqlx::Error::TypeNotFound {
                    type_name: CANARY.to_owned(),
                },
                "result decoding error",
            ),
        ];
        for (error, expected) in cases {
            assert!(
                error.to_string().contains(CANARY),
                "premise: sqlx's text carries it"
            );
            let summary = error_summary(&error);
            assert_eq!(summary.to_string(), expected);
            assert_eq!(format!("{summary:?}"), expected);
        }
        for (error, expected) in [
            (
                sqlx::Error::PoolTimedOut,
                "timed out waiting for a pool connection",
            ),
            (sqlx::Error::PoolClosed, "the pool is closed"),
            (sqlx::Error::WorkerCrashed, "the connection worker crashed"),
            (sqlx::Error::RowNotFound, "no row returned"),
        ] {
            assert_eq!(error_summary(&error).to_string(), expected);
        }
    }

    /// A database error whose code and message a test chooses, as a server
    /// (or a peer pretending to be one) would send them.
    #[derive(Debug)]
    struct ServerError {
        code: &'static str,
    }

    impl fmt::Display for ServerError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "duplicate key value violates unique constraint: {CANARY}"
            )
        }
    }

    impl std::error::Error for ServerError {}

    impl sqlx::error::DatabaseError for ServerError {
        fn message(&self) -> &str {
            CANARY
        }

        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some(self.code.into())
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    /// A database error is its SQLSTATE and a fixed description, never the
    /// server's message; a code that is not SQLSTATE-shaped (five ASCII
    /// digits or capitals) is not printed either, since a peer chose it.
    #[test]
    fn a_database_error_is_its_sqlstate_never_its_message() {
        for (code, expected) in [
            ("23505", "database error SQLSTATE 23505 (unique violation)"),
            ("22P02", "database error SQLSTATE 22P02 (data exception)"),
            ("db-error-canary", "database error (no SQLSTATE)"),
            ("2350a", "database error (no SQLSTATE)"),
            ("2350", "database error (no SQLSTATE)"),
        ] {
            let error = sqlx::Error::Database(Box::new(ServerError { code }));
            assert!(error.to_string().contains(CANARY), "premise: {code}");
            let summary = error_summary(&error).to_string();
            assert_eq!(summary, expected, "{code}");
            assert!(!summary.contains(CANARY), "{code}: {summary}");
        }
    }

    #[test]
    fn a_sqlstate_is_described_by_code_then_by_class() {
        assert_eq!(sqlstate_description("28P01"), "invalid password");
        assert_eq!(sqlstate_description("22023"), "invalid parameter value");
        assert_eq!(sqlstate_description("3D000"), "database does not exist");
        assert_eq!(sqlstate_description("22P02"), "data exception");
        assert_eq!(sqlstate_description("40P01"), "deadlock detected");
        assert_eq!(sqlstate_description("40003"), "transaction rollback");
        assert_eq!(sqlstate_description("ZZ999"), "other");
    }
}
