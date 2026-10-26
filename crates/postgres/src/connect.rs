//! [`connect_options`]: a `DATABASE_URL` checked before sqlx parses it, and
//! the startup `options` tokeniser ([`split_options`]; [`pg_split_opts`] is
//! the server's reading).

use std::net::IpAddr;

use sqlx::postgres::PgConnectOptions;
use sqlx::ConnectOptions as _;
use url::Url;

/// The query parameters a `DATABASE_URL` may carry and sqlx applies: libpq's
/// spellings of the connection settings sqlx honours. sqlx's own aliases
/// (`ssl-mode`, `ssl-ca`, …), `statement-cache-capacity` and the
/// `options[…]` form are left out: no StrideLabs app uses them, and one
/// spelling per setting keeps the list reviewable.
///
/// **Why an allow-list.** sqlx's URL parser logs every parameter it does not
/// recognise WITH its value (`warn!(%key, %value, "ignoring unrecognized
/// connect parameter")`), and its errors quote a bad value (`unknown value
/// "…" for ssl_mode`). A credential pasted into the wrong parameter would
/// reach the log or stderr. [`connect_options`] refuses anything not on this
/// list or [`IGNORED_URL_PARAMETERS`], and checks the values sqlx would
/// quote, BEFORE sqlx sees the URL.
///
/// **Neon's URLs.** The connection string Neon hands out carries
/// `sslmode=require` and `channel_binding=require`, and may carry
/// `options=endpoint%3D<id>` for a client without SNI. `sslmode` and
/// `options` are on this list; `channel_binding` is refused by name (sqlx 0.9
/// cannot do channel binding, so a `require` would be silently unenforced):
/// remove it before calling [`connect_options`], as tapper's and lumen's
/// URL normalisers do.
pub const SUPPORTED_URL_PARAMETERS: [&str; 12] = [
    "sslmode",
    "sslrootcert",
    "sslcert",
    "sslkey",
    "host",
    "hostaddr",
    "port",
    "dbname",
    "user",
    "password",
    "application_name",
    "options",
];

/// The six `sslmode` values (sqlx compares them case-insensitively).
const SSL_MODES: [&str; 6] = [
    "disable",
    "allow",
    "prefer",
    "require",
    "verify-ca",
    "verify-full",
];

/// libpq parameters that hosted-Postgres docs commonly put in a connection
/// string and that sqlx 0.9 has no equivalent for. They are ACCEPTED (their
/// values validated) and NOT passed on to sqlx, which would log them (with
/// their values) as unrecognised and ignore them; so their effect is still
/// nothing:
/// - `connect_timeout` (seconds, a non-negative integer): sqlx has no
///   per-connection connect timeout; a pool's connections are bounded by its
///   acquire timeout ([`PoolSettings`](crate::PoolSettings)).
/// - `keepalives` (0 or 1), `keepalives_idle`, `keepalives_interval`,
///   `keepalives_count` (non-negative integers): TCP keepalive tuning, which
///   sqlx 0.9 cannot apply. Dropping them leaves the OS defaults, and sqlx
///   sets no keepalive itself: it opens a plain Tokio `TcpStream` and offers
///   no hook on the socket (`sqlx-core/src/net/socket/mod.rs`,
///   `connect_tcp`). So TCP never notices a peer that keeps the connection
///   open and goes silent, and a statement waiting on one waits unbounded
///   unless something above it has a timeout. (Under the `guard` feature,
///   `GuardedPool` bounds a `BEGIN`, its `SET LOCAL` and the release probes
///   after one; the crate README lists what stays unbounded.)
/// - `target_session_attrs`, only `any` or `read-write`: sqlx dials one host,
///   which satisfies `any`, and a `read-write` demand on a replica still fails
///   loudly at the first write. The other values (`read-only`, `primary`,
///   `standby`, `prefer-standby`) ask for a choice sqlx cannot make, so they
///   are refused rather than silently dropped.
pub const IGNORED_URL_PARAMETERS: [&str; 6] = [
    "connect_timeout",
    "keepalives",
    "keepalives_idle",
    "keepalives_interval",
    "keepalives_count",
    "target_session_attrs",
];

/// Parameter names this crate recognises but does not support: sqlx's
/// aliases and libpq settings sqlx cannot honour. Only these unsupported
/// names are ever printed, and from THIS list, never from the URL: any other
/// name is reported as "not printed", because an unknown name can be a pasted
/// credential as easily as a typo.
const KNOWN_UNSUPPORTED_PARAMETERS: [&str; 24] = [
    "ssl-mode",
    "ssl-root-cert",
    "ssl-ca",
    "ssl-cert",
    "ssl-key",
    "statement-cache-capacity",
    "channel_binding",
    "tcp_user_timeout",
    "gssencmode",
    "gsslib",
    "krbsrvname",
    "sslnegotiation",
    "sslcrl",
    "sslcrldir",
    "sslsni",
    "sslpassword",
    "sslcompression",
    "ssl_min_protocol_version",
    "ssl_max_protocol_version",
    "requirepeer",
    "require_auth",
    "service",
    "passfile",
    "load_balance_hosts",
];

/// How sqlx's `options[<setting>]=` form is named in a refusal (the setting
/// itself is not printed).
const OPTIONS_MAP_FORM: &str = "options[…]";

/// Why [`connect_options`] refused a URL. Its `Display` never contains
/// anything taken from the URL or the environment: every name it prints
/// comes from this crate's own lists.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UrlRefusal {
    /// Not a URL at all; carries the `url` crate's fixed reason text (its
    /// `ParseError` variants never quote the input).
    #[error("not a URL ({0})")]
    NotAUrl(String),
    /// A scheme other than `postgres` or `postgresql`.
    #[error("the scheme must be postgres:// or postgresql://")]
    Scheme,
    /// Query parameters that are neither supported nor ignored: the ones
    /// this crate recognises, by name, and how many others there were.
    #[error(
        "unsupported query parameters: {}; supported: {}; accepted and ignored: {}",
        unsupported_list(named, *unnamed),
        SUPPORTED_URL_PARAMETERS.join(", "),
        IGNORED_URL_PARAMETERS.join(", ")
    )]
    UnsupportedParameters {
        /// The recognised names, each once, in the order they appear.
        named: Vec<&'static str>,
        /// How many parameters had a name this crate does not recognise.
        unnamed: usize,
    },
    /// A supported or ignored parameter with a value sqlx would refuse (and
    /// quote), or one sqlx cannot honour.
    #[error("{}", invalid_value(.0))]
    InvalidValue(&'static str),
    /// sqlx refused the URL for another reason; its text is withheld because
    /// it can quote the URL.
    #[error("sqlx could not parse it (its reason is withheld because it can quote the URL)")]
    Unparseable,
    /// The startup options sqlx would send (`PGOPTIONS`, then every
    /// `options=`) set `search_path`; the value is not printed.
    #[error(
        "its startup options (`options=` or PGOPTIONS) set `search_path`, which is refused: it \
         points every query on the connection (migrations included) at a schema the connection \
         string chose rather than the application; remove that setting"
    )]
    SearchPath,
    /// A NUL byte (percent-decoded) in the named field: the user, password,
    /// database, host, any query parameter's value, or what sqlx takes from
    /// the environment for them; the value is not printed.
    #[error(
        "a NUL byte (`%00`, decoded) in `{0}` (from the URL, or the environment variable sqlx \
         reads for it), which is refused: sqlx copies it into the startup packet, where it ends \
         the field and the rest is read as further startup parameters (a `search_path` among \
         them); the value is not printed"
    )]
    NulByte(&'static str),
}

fn unsupported_list(named: &[&'static str], unnamed: usize) -> String {
    let mut parts: Vec<String> = named.iter().map(|name| format!("`{name}`")).collect();
    match unnamed {
        0 => {}
        1 => parts.push("an unsupported query parameter (name not printed)".into()),
        n => parts.push(format!(
            "{n} unsupported query parameters (names not printed)"
        )),
    }
    parts.join(", ")
}

fn invalid_value(name: &str) -> String {
    match name {
        "sslmode" => format!("invalid `sslmode` value (one of {})", SSL_MODES.join(", ")),
        "port" => "invalid `port` value (a number from 0 to 65535)".to_owned(),
        "hostaddr" => "invalid `hostaddr` value (an IP address)".to_owned(),
        "keepalives" => "invalid `keepalives` value (0 or 1)".to_owned(),
        "target_session_attrs" => "unsupported `target_session_attrs` value (sqlx connects to \
                                   one host: only `any` or `read-write`)"
            .to_owned(),
        name => {
            format!("invalid `{name}` value (a non-negative whole number of seconds or probes)")
        }
    }
}

/// The libpq variable sqlx takes a default password from
/// (`PgConnectOptions::new_without_pgpass`).
const PGPASSWORD_VAR: &str = "PGPASSWORD";

/// The `PG*` variables sqlx reads into a startup or authentication field,
/// each with the field a refusal names.
const ENVIRONMENT_FIELDS: [(&str, &str); 7] = [
    ("PGUSER", "user"),
    ("PGDATABASE", "dbname"),
    ("PGAPPNAME", "application_name"),
    ("PGOPTIONS", "options"),
    ("PGHOST", "host"),
    ("PGHOSTADDR", "host"),
    (PGPASSWORD_VAR, "password"),
];

/// Validate `database_url` and parse it into sqlx's options, refusing
/// anything sqlx would log or quote a value of (see
/// [`SUPPORTED_URL_PARAMETERS`], [`IGNORED_URL_PARAMETERS`]). Make it the ONE
/// place a `DATABASE_URL` reaches sqlx: build the pool from what it returns
/// ([`lazy_pool`](crate::lazy_pool)), never from the URL string.
///
/// The URL must already be in sqlx's spelling: `postgres://` or
/// `postgresql://` (a SQLAlchemy `+asyncpg` scheme is refused), and no
/// `channel_binding` (see [`SUPPORTED_URL_PARAMETERS`]).
///
/// **The password file is never read.** sqlx falls back to `PGPASSFILE` (or
/// `~/.pgpass`) when neither the URL nor `PGPASSWORD` supplies a password,
/// and it logs a malformed line of that file VERBATIM at WARN, password and
/// all, before any connection or error path the caller controls. So when
/// nothing supplies one, sqlx is handed an explicitly EMPTY password
/// (`password=`), which is exactly what it would send for no password at all,
/// and the file is never opened. A password-less URL therefore connects only
/// where the server asks for none (trust, peer); put the password in the URL
/// or `PGPASSWORD`.
///
/// **No `search_path`.** Startup options that set `search_path` (read as the
/// server reads them: `PGOPTIONS` followed by every `options=`, which sqlx
/// joins with a space) are refused ([`UrlRefusal::SearchPath`], value not
/// printed), in every spelling the server honours (`-c`, `--`, any case, `-`
/// for `_`, escapes, any of PostgreSQL's six spaces, the vertical tab
/// included). A setting whose name merely contains the words
/// (`myapp.search_path_hint`) passes: names are compared exactly.
///
/// **No NUL byte.** sqlx writes each startup parameter as its bytes plus one
/// NUL, copying an embedded NUL as is, and PostgreSQL reads the packet's
/// name/value pairs with `strlen`, taking any name it does not know as a
/// setting. So `application_name=x%00search_path%00y` would send
/// `search_path=y` as a parameter of its own, past every check of the
/// `options`. A NUL in anything that reaches the startup packet or
/// authentication is refused ([`UrlRefusal::NulByte`], naming the field):
/// every query parameter's value; the URL's user, password, database and
/// host, decoded as sqlx decodes them; the values sqlx will actually use,
/// which include its `PG*` environment defaults; and `PGUSER`, `PGDATABASE`,
/// `PGAPPNAME`, `PGOPTIONS`, `PGHOST`, `PGHOSTADDR` and `PGPASSWORD`
/// themselves. (A real process environment cannot hold a NUL, each entry
/// being a C string; they are checked for completeness.)
///
/// **Never log what it returns**: sqlx's derived `Debug` of
/// `PgConnectOptions` prints the password.
///
/// # Errors
///
/// [`UrlRefusal`], whose text names a parameter or field from this crate's
/// own lists and never a value.
///
/// ```
/// use stridelabs_postgres::{connect_options, UrlRefusal};
///
/// let options = connect_options("postgres://app:secret@db.example.com/app?sslmode=require")?;
/// assert_eq!(options.get_host(), "db.example.com");
///
/// // A credential pasted into a parameter nobody recognises is not printed.
/// let refusal = connect_options("postgres://app@db.example.com/app?token=hunter2").unwrap_err();
/// assert!(!refusal.to_string().contains("hunter2"));
/// # Ok::<(), UrlRefusal>(())
/// ```
pub fn connect_options(database_url: &str) -> Result<PgConnectOptions, UrlRefusal> {
    connect_options_with_env(database_url, |name| std::env::var(name).ok())
}

/// [`connect_options`] with the `PG*` variables it CHECKS read through
/// `env`, so tests reach every environment refusal without `set_var`.
///
/// Deliberately private, and deliberately not used for whether the URL
/// supplies a password: sqlx reads the real environment itself
/// (`new_without_pgpass`), so that decision must too. A lookup that claimed a
/// `PGPASSWORD` the process does not have would leave sqlx to read the
/// password file. What sqlx takes from the real environment is checked on
/// the parsed options ([`refuse_unsafe_startup`]).
fn connect_options_with_env(
    database_url: &str,
    env: impl Fn(&str) -> Option<String>,
) -> Result<PgConnectOptions, UrlRefusal> {
    let parsed =
        Url::parse(database_url).map_err(|failure| UrlRefusal::NotAUrl(failure.to_string()))?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql") {
        return Err(UrlRefusal::Scheme);
    }

    // Every unsupported parameter first, so the refusal counts them all.
    let mut named = Vec::new();
    let mut unnamed = 0;
    for (key, _) in parsed.query_pairs() {
        if SUPPORTED_URL_PARAMETERS.contains(&&*key) || IGNORED_URL_PARAMETERS.contains(&&*key) {
            continue;
        }
        match KNOWN_UNSUPPORTED_PARAMETERS
            .iter()
            .find(|name| **name == key)
        {
            Some(name) if !named.contains(name) => named.push(*name),
            Some(_) => {}
            None if key.starts_with("options[") => {
                if !named.contains(&OPTIONS_MAP_FORM) {
                    named.push(OPTIONS_MAP_FORM);
                }
            }
            None => unnamed += 1,
        }
    }
    if !named.is_empty() || unnamed > 0 {
        return Err(UrlRefusal::UnsupportedParameters { named, unnamed });
    }

    for (key, value) in parsed.query_pairs() {
        let name = SUPPORTED_URL_PARAMETERS
            .iter()
            .chain(IGNORED_URL_PARAMETERS.iter())
            .find(|name| **name == key)
            .copied()
            .unwrap_or_default();
        if value.contains('\0') {
            return Err(UrlRefusal::NulByte(name));
        }
        let whole_number = || value.parse::<u32>().is_ok();
        let valid = match name {
            "sslmode" => SSL_MODES.contains(&value.to_ascii_lowercase().as_str()),
            "port" => value.parse::<u16>().is_ok(),
            "hostaddr" => value.parse::<IpAddr>().is_ok(),
            "connect_timeout" | "keepalives_idle" | "keepalives_interval" | "keepalives_count" => {
                whole_number()
            }
            "keepalives" => matches!(&*value, "0" | "1"),
            "target_session_attrs" => matches!(&*value, "any" | "read-write"),
            _ => true,
        };
        if !valid {
            return Err(UrlRefusal::InvalidValue(name));
        }
    }
    // The URL's own parts, percent-decoded as sqlx decodes them.
    for (field, part) in [
        ("user", parsed.username()),
        ("password", parsed.password().unwrap_or_default()),
        ("dbname", parsed.path()),
        ("host", parsed.host_str().unwrap_or_default()),
    ] {
        if decodes_to_nul(part) {
            return Err(UrlRefusal::NulByte(field));
        }
    }
    refuse_unsafe_environment(&env)?;

    let for_sqlx = url_for_sqlx(&parsed, !supplies_password(&parsed));
    let options =
        PgConnectOptions::from_url(&for_sqlx).map_err(|_withheld| UrlRefusal::Unparseable)?;
    refuse_unsafe_startup(&options)?;
    Ok(options)
}

/// A NUL in any `PG*` variable sqlx reads into a startup or authentication
/// field ([`ENVIRONMENT_FIELDS`]), or a `search_path` in `PGOPTIONS` (which
/// sqlx always sends: a URL's `options=` is appended to it, never replaces
/// it), as `env` reports them.
fn refuse_unsafe_environment(env: &impl Fn(&str) -> Option<String>) -> Result<(), UrlRefusal> {
    for (variable, field) in ENVIRONMENT_FIELDS {
        if env(variable).is_some_and(|value| value.contains('\0')) {
            return Err(UrlRefusal::NulByte(field));
        }
    }
    if env("PGOPTIONS").is_some_and(|options| sets_search_path(&options)) {
        return Err(UrlRefusal::SearchPath);
    }
    Ok(())
}

/// The checks [`connect_options`] runs on what sqlx WILL send, once it has
/// applied the URL over its `PG*` environment defaults (read from the real
/// environment): a NUL in the user, the database, `application_name`, the
/// startup `options` or the host (name or socket), and a `search_path` in the
/// startup options. Split out so every field has a test of its own, driven
/// through sqlx's own setters.
fn refuse_unsafe_startup(options: &PgConnectOptions) -> Result<(), UrlRefusal> {
    for (field, value) in [
        ("user", Some(options.get_username())),
        ("dbname", options.get_database()),
        ("application_name", options.get_application_name()),
        ("options", options.get_options()),
        ("host", Some(options.get_host())),
    ] {
        if value.is_some_and(|value| value.contains('\0')) {
            return Err(UrlRefusal::NulByte(field));
        }
    }
    if options
        .get_socket()
        .is_some_and(|socket| socket.as_os_str().as_encoded_bytes().contains(&0))
    {
        return Err(UrlRefusal::NulByte("host"));
    }
    if options.get_options().is_some_and(sets_search_path) {
        return Err(UrlRefusal::SearchPath);
    }
    Ok(())
}

/// Does `text`, percent-decoded, hold a NUL byte? Percent-decoding yields a
/// NUL exactly where `%00` appears (a `%` is never one of an earlier
/// escape's hex digits); a literal NUL counts too (the `url` crate encodes
/// one, but this does not rely on it).
fn decodes_to_nul(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.contains(&0) || bytes.windows(3).any(|window| window == b"%00")
}

/// Whether sqlx will find a password for `url` WITHOUT its password file:
/// exactly the three places it looks first, in its own terms (`PGPASSWORD`
/// read with `std::env::var` from the real environment, the URL's userinfo,
/// a `password=` parameter).
fn supplies_password(url: &Url) -> bool {
    std::env::var(PGPASSWORD_VAR).is_ok()
        || url.password().is_some()
        || url.query_pairs().any(|(key, _)| key == "password")
}

/// The URL sqlx is handed: `parsed` without the [`IGNORED_URL_PARAMETERS`]
/// (the rest re-encoded in order; sqlx decodes the query the same way either
/// way), and with an empty `password=` appended when `empty_password`, so
/// sqlx never reads a password file for it (see [`connect_options`]).
fn url_for_sqlx(parsed: &Url, empty_password: bool) -> Url {
    let mut pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(key, _)| !IGNORED_URL_PARAMETERS.contains(&&**key))
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    if empty_password {
        pairs.push(("password".to_owned(), String::new()));
    }
    let mut url = parsed.clone();
    url.set_query(None);
    if !pairs.is_empty() {
        url.query_pairs_mut().extend_pairs(pairs);
    }
    url
}

/// The startup `options` split into tokens, with their escapes applied: a
/// token ends at the first `is_space` character not escaped by a backslash;
/// runs of spaces (leading and trailing included) separate and are dropped;
/// a backslash that is not itself escaped is dropped and escapes the next
/// character, which is kept whatever it is (so a lone `\` is a token of its
/// own, empty). That is PostgreSQL's `pg_split_opts`
/// (`src/backend/utils/init/postinit.c` at `REL_16_STABLE`, lines 504-544)
/// over any set of spaces: [`pg_split_opts`] gives it the server's, and the
/// pooler check also gives it Neon's proxy's (`pooler::pooler_endpoint`).
pub(crate) fn split_options(options: &str, is_space: fn(char) -> bool) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token: Option<String> = None;
    let mut escaped = false;
    for c in options.chars() {
        if is_space(c) && !escaped {
            tokens.extend(token.take());
            continue;
        }
        let current = token.get_or_insert_with(String::new);
        if c == '\\' && !escaped {
            escaped = true;
        } else {
            escaped = false;
            current.push(c);
        }
    }
    tokens.extend(token);
    tokens
}

/// The bytes PostgreSQL's `pg_split_opts` splits the startup options on: C's
/// `isspace` in the C locale (space, `\t`, `\n`, `\v`, `\f`, `\r`). Rust's
/// `is_ascii_whitespace` (Neon's proxy's set) leaves out the vertical tab
/// (`\v`, `\x0B`).
fn is_pg_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0B' | '\x0C' | '\r')
}

/// The startup `options` as the PostgreSQL server splits them into the
/// switches it applies: [`split_options`] on C's six spaces, the tokens
/// exactly as the server's `argv`.
pub(crate) fn pg_split_opts(options: &str) -> Vec<String> {
    split_options(options, is_pg_space)
}

/// Do the startup `options` set `search_path`, in any spelling the server
/// would honour?
///
/// The server splits the options with [`pg_split_opts`] (on all six of C's
/// spaces, the vertical tab included) and reads the tokens with `getopt` and
/// the option string `"B:bC:c:D:d:EeFf:h:ijk:lN:nOPp:r:S:sTt:v:W:-:"`
/// (`process_postgres_switches`, `src/backend/tcop/postgres.c` at
/// `REL_16_STABLE`). Only `-c` and `--` set a setting, and both hand their
/// argument (the rest of the token, else the next token) to `ParseLongOption`
/// (`src/backend/utils/misc/guc.c`): the NAME is the part before the first
/// `=`, with every `-` read as `_`, and it is looked up
/// ASCII-case-insensitively (`guc_name_compare`). So: `-c search_path=x`,
/// `-csearch_path=x`, `--search_path=x`, `--search-path=x`,
/// `-c SEARCH_PATH=x`, `-Ec search_path=x` (`c` after other flag letters).
///
/// Each token is read as that NAME and compared EXACTLY to `search_path`
/// (normalised as the server normalises it), so a custom setting that merely
/// contains the words (`myapp.search_path_hint`, or a dotted
/// `myapp.search_path`) is not refused, and neither is a value
/// (`-c application_name=search_path`). It is broader than `getopt` only
/// where the server would refuse the connection or set nothing anyway: a
/// switch token's setting starts at its first `c` or `-` whatever letters
/// precede it, and a token that is no switch is read as a setting too (it is
/// the argument when a `-c` ended the token before it).
fn sets_search_path(options: &str) -> bool {
    pg_split_opts(options).iter().any(|token| {
        let setting = match token.strip_prefix('-') {
            Some(switches) => match switches.find(['c', '-']) {
                // Both are one byte: the slice starts on a char boundary.
                Some(at) => &switches[at + 1..],
                None => return false,
            },
            None => token.as_str(),
        };
        let name = setting.split('=').next().unwrap_or_default();
        name.replace('-', "_").eq_ignore_ascii_case("search_path")
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const CANARY: &str = "db-url-canary";

    fn refusal(url: &str) -> UrlRefusal {
        match connect_options(url) {
            Err(refusal) => refusal,
            Ok(_) => panic!("{url} must be refused"),
        }
    }

    /// A fake environment for `connect_options_with_env`: the pairs given,
    /// nothing else.
    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: HashMap<&str, &str> = pairs.iter().copied().collect();
        move |name| map.get(name).map(|value| (*value).to_owned())
    }

    /// Every supported parameter, with a value sqlx accepts, passes; the
    /// options come back as the URL describes them.
    #[test]
    fn every_supported_parameter_is_accepted() {
        let options = connect_options(
            "postgres://u:p@db.example.com:6543/app?sslmode=VERIFY-FULL&sslrootcert=/ca.pem\
             &sslcert=/c.pem&sslkey=/k.pem&host=db2.example.com&hostaddr=192.0.2.7&port=5433\
             &dbname=other&user=v&password=w&application_name=svc&options=-c%20a%3Db",
        )
        .unwrap_or_else(|refusal| panic!("refused: {refusal}"));
        assert_eq!(options.get_host(), "192.0.2.7");
        assert_eq!(options.get_port(), 5433);
        assert_eq!(options.get_database(), Some("other"));
        assert_eq!(options.get_username(), "v");
        assert_eq!(options.get_application_name(), Some("svc"));
        assert_eq!(options.get_options(), Some("-c a=b"));
        for mode in SSL_MODES {
            connect_options(&format!("postgres://u:p@h/db?sslmode={mode}"))
                .unwrap_or_else(|refusal| panic!("sslmode={mode} refused: {refusal}"));
        }
        connect_options("postgresql://u:p@h/db").expect("no parameters at all");
    }

    /// The connection strings Neon hands out, `channel_binding` removed (as
    /// a consumer's normaliser removes it), are usable: `sslmode` and
    /// `options=endpoint%3D…` are on the list. With `channel_binding` still
    /// in it, the URL is refused by that name (the control).
    #[test]
    fn a_neon_connection_string_without_channel_binding_is_accepted() {
        for url in [
            "postgresql://u:p@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb?sslmode=require",
            "postgresql://u:p@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb\
             ?sslmode=require&options=endpoint%3Dep-cool-name-123456",
        ] {
            let options =
                connect_options(url).unwrap_or_else(|refusal| panic!("{url} refused: {refusal}"));
            assert!(
                matches!(options.get_ssl_mode(), sqlx::postgres::PgSslMode::Require),
                "{url}"
            );
            assert_eq!(options.get_database(), Some("neondb"), "{url}");
        }
        assert_eq!(
            refusal(
                "postgresql://u:p@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb\
                 ?sslmode=require&channel_binding=require"
            ),
            UrlRefusal::UnsupportedParameters {
                named: vec!["channel_binding"],
                unnamed: 0
            }
        );
    }

    /// A URL that supplies its own password is handed to sqlx as it is; one
    /// that does not gets an explicit empty `password=`, so sqlx never opens
    /// a password file. Only the URL-supplied cases are pinned here:
    /// `PGPASSWORD` is the test process's own environment.
    #[test]
    fn a_url_without_a_password_is_given_an_empty_one() {
        for url in [
            "postgres://u:secret@h/db",
            "postgres://u@h/db?password=secret",
            "postgres://u@h/db?password=",
        ] {
            let parsed = Url::parse(url).expect("a URL");
            assert!(supplies_password(&parsed), "{url}");
        }
        for (url, for_sqlx) in [
            ("postgres://u@h/db", "postgres://u@h/db?password="),
            (
                "postgres://u@h/db?sslmode=require",
                "postgres://u@h/db?sslmode=require&password=",
            ),
        ] {
            let parsed = Url::parse(url).expect("a URL");
            assert_eq!(url_for_sqlx(&parsed, true).as_str(), for_sqlx);
            // The control: nothing appended when a password is supplied.
            assert_eq!(url_for_sqlx(&parsed, false).as_str(), url);
        }
        connect_options("postgres://u@h/db?sslmode=require")
            .unwrap_or_else(|refusal| panic!("a password-less URL is still usable: {refusal}"));
    }

    /// A parameter this crate RECOGNISES but does not support (sqlx's aliases
    /// and forms, libpq settings sqlx cannot honour) is refused by name, the
    /// name taken from the crate's own list, and never with its value.
    #[test]
    fn a_known_unsupported_parameter_is_refused_by_name_without_its_value() {
        for (query, name) in [
            ("ssl-mode", "ssl-mode"),
            ("statement-cache-capacity", "statement-cache-capacity"),
            ("options[endpoint]", "options[…]"),
            ("channel_binding", "channel_binding"),
            ("tcp_user_timeout", "tcp_user_timeout"),
            ("passfile", "passfile"),
        ] {
            let refusal = refusal(&format!("postgres://u:p@h/db?{query}={CANARY}"));
            assert_eq!(
                refusal,
                UrlRefusal::UnsupportedParameters {
                    named: vec![name],
                    unnamed: 0
                }
            );
            let text = refusal.to_string();
            assert!(text.contains(&format!("`{name}`")), "{text}");
            assert!(!text.contains(CANARY), "{text}");
        }
    }

    /// A parameter name this crate does not recognise is never printed (it
    /// may be a pasted credential), whether it is spelled plainly or
    /// percent-encoded; the refusal says how many there were.
    #[test]
    fn an_unrecognised_parameter_name_is_never_printed() {
        for query in [
            "secret-token-abc=1",
            "%73ecret-token-abc=1",
            "token=db-url-canary",
        ] {
            let refusal = refusal(&format!("postgres://u:p@h/db?{query}"));
            assert_eq!(
                refusal,
                UrlRefusal::UnsupportedParameters {
                    named: vec![],
                    unnamed: 1
                },
                "{query}"
            );
            let text = refusal.to_string();
            for secret in ["ecret-token-abc", "token=", CANARY] {
                assert!(!text.contains(secret), "{query}: {text}");
            }
            assert!(
                text.starts_with(
                    "unsupported query parameters: an unsupported query parameter (name not printed);"
                ),
                "{text}"
            );
        }
        // Every unsupported parameter is counted; known ones are still named.
        let refusal =
            refusal("postgres://u:p@h/db?secret-a=1&ssl-mode=x&secret-b=2&sslmode=require");
        assert_eq!(
            refusal,
            UrlRefusal::UnsupportedParameters {
                named: vec!["ssl-mode"],
                unnamed: 2
            }
        );
        let text = refusal.to_string();
        assert!(
            text.contains("`ssl-mode`, 2 unsupported query parameters (names not printed)"),
            "{text}"
        );
        assert!(!text.contains("secret"), "{text}");
    }

    /// `connect_timeout`, the `keepalives*` settings and an `any`/`read-write`
    /// `target_session_attrs` are accepted, validated, and NOT handed to sqlx
    /// (which would log them, values included, as unrecognised).
    #[test]
    fn the_ignored_libpq_parameters_are_accepted_and_not_passed_to_sqlx() {
        let options = connect_options("postgres://u:p@h/db?sslmode=require&connect_timeout=10")
            .unwrap_or_else(|refusal| panic!("refused: {refusal}"));
        assert!(matches!(
            options.get_ssl_mode(),
            sqlx::postgres::PgSslMode::Require
        ));
        connect_options(
            "postgres://u:p@h/db?connect_timeout=0&keepalives=1&keepalives_idle=30\
             &keepalives_interval=10&keepalives_count=3&target_session_attrs=read-write",
        )
        .unwrap_or_else(|refusal| panic!("refused: {refusal}"));
        connect_options("postgres://u:p@h/db?target_session_attrs=any")
            .unwrap_or_else(|refusal| panic!("refused: {refusal}"));

        let url = Url::parse(
            "postgres://u:p@h/db?sslmode=require&connect_timeout=10&options=-c%20a%3Db%2Bc\
             &keepalives=1&application_name=x%20y",
        )
        .expect("parses");
        let kept: Vec<(String, String)> = url_for_sqlx(&url, false)
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        assert_eq!(
            kept,
            [
                ("sslmode", "require"),
                ("options", "-c a=b+c"),
                ("application_name", "x y"),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
        );
    }

    /// Their values are checked, and a refusal never quotes one.
    #[test]
    fn an_ignored_parameter_with_a_bad_value_is_refused_without_quoting_it() {
        for (query, expected) in [
            (
                "connect_timeout=db-url-canary",
                "invalid `connect_timeout` value (a non-negative whole number of seconds or probes)",
            ),
            (
                "connect_timeout=-5",
                "invalid `connect_timeout` value (a non-negative whole number of seconds or probes)",
            ),
            ("keepalives=db-url-canary", "invalid `keepalives` value (0 or 1)"),
            ("keepalives=2", "invalid `keepalives` value (0 or 1)"),
            (
                "keepalives_count=db-url-canary",
                "invalid `keepalives_count` value (a non-negative whole number of seconds or probes)",
            ),
            (
                "target_session_attrs=read-only",
                "unsupported `target_session_attrs` value (sqlx connects to one host: only \
                 `any` or `read-write`)",
            ),
        ] {
            assert_eq!(
                refusal(&format!("postgres://u:p@h/db?{query}")).to_string(),
                expected,
                "{query}"
            );
        }
    }

    /// The values sqlx would quote in its error are checked first, and the
    /// refusal is a fixed text; a good value of each passes (the control).
    #[test]
    fn a_value_sqlx_would_quote_is_refused_without_quoting_it() {
        for (name, expected, good) in [
            (
                "sslmode",
                "invalid `sslmode` value (one of disable, allow, prefer, require, verify-ca, \
                 verify-full)",
                "require",
            ),
            (
                "port",
                "invalid `port` value (a number from 0 to 65535)",
                "5432",
            ),
            (
                "hostaddr",
                "invalid `hostaddr` value (an IP address)",
                "192.0.2.7",
            ),
        ] {
            let refusal = refusal(&format!("postgres://u:p@h/db?{name}={CANARY}"));
            assert_eq!(refusal, UrlRefusal::InvalidValue(name));
            assert_eq!(refusal.to_string(), expected);
            connect_options(&format!("postgres://u:p@h/db?{name}={good}"))
                .unwrap_or_else(|refusal| panic!("{name}={good}: {refusal}"));
        }
    }

    /// Whatever else sqlx refuses (here: a username that is not UTF-8 once
    /// percent-decoded) is reported without sqlx's own text.
    #[test]
    fn any_other_sqlx_refusal_is_a_fixed_text() {
        let refusal = refusal(&format!("postgres://u%FF:{CANARY}@h/db"));
        assert_eq!(refusal, UrlRefusal::Unparseable);
        assert_eq!(
            refusal.to_string(),
            "sqlx could not parse it (its reason is withheld because it can quote the URL)"
        );
        connect_options(&format!("postgres://u%41:{CANARY}@h/db")).expect("a decodable user");
    }

    #[test]
    fn not_a_postgres_url_is_refused_without_quoting_it() {
        for url in [
            format!("mysql://u:{CANARY}@h/db"),
            format!("not a url {CANARY}"),
            format!("postgres://u:{CANARY}@h:notaport/db"),
            format!("postgresql+asyncpg://u:{CANARY}@h/db"),
        ] {
            let text = refusal(&url).to_string();
            assert!(!text.contains(CANARY), "{url}: {text}");
        }
        assert_eq!(refusal("mysql://h/db"), UrlRefusal::Scheme);
        assert_eq!(
            UrlRefusal::Scheme.to_string(),
            "the scheme must be postgres:// or postgresql://"
        );
        assert!(matches!(
            refusal("not a url"),
            UrlRefusal::NotAUrl(reason) if reason == "relative URL without a base"
        ));
    }

    const SCHEMA_CANARY: &str = "schema_canary_5d2b";

    /// `search_path` in the startup options is refused in every spelling the
    /// server would honour (percent-encoded in the URL, `-c` apart or
    /// attached, `--`, after other flag letters, any case, `-` for `_`,
    /// backslash-escaped, in a second `options=`, after another setting,
    /// separated from it by any of PostgreSQL's six spaces, the vertical tab,
    /// form feed and carriage return included), naming the setting and never
    /// its value. (lumen-rs `8078431`'s table, as tapper-rs ported it.)
    #[test]
    fn a_search_path_in_the_startup_options_is_refused_in_every_spelling() {
        for options in [
            // One token to `is_ascii_whitespace`, two settings to PostgreSQL.
            "-capplication_name%3Dsvc%0B-csearch_path%3D{}",
            "-capplication_name%3Dsvc%0C-csearch_path%3D{}",
            "-capplication_name%3Dsvc%0D-csearch_path%3D{}",
            "-capplication_name%3Dsvc%0A-csearch_path%3D{}",
            "-c%0Bsearch_path%3D{}",
            "%0B%0C-c%0D%0Asearch_path%3D{}",
            "-E-search_path%3D{}",
            "-c%20search_path%3D{}",
            "-c+search_path%3D{}",
            "-csearch_path%3D{}",
            "--search_path%3D{}",
            "--search-path%3D{}",
            "-c%20search-path%3D{}",
            "-c%20SEARCH_PATH%3D{}",
            "-c%20Search_Path%3D{}",
            "%2Dc%20search%5Fpath%3D{}",
            "-c%20search%5C_path%3D{}",
            "-c%20search_path%5C%3D{}",
            "-Ec%20search_path%3D{}",
            "-Ecsearch_path%3D{}",
            "-c%20application_name%3Dsvc%09-c%20search_path%3D{}",
            // A repeated `options`: sqlx joins them with a space.
            "-c%20application_name%3Dsvc&options=-c%20search_path%3D{}",
            "-c%20search_path%3D",
            "-c%20search_path",
        ] {
            let url = format!(
                "postgres://u:p@h/db?options={}",
                options.replace("{}", SCHEMA_CANARY)
            );
            let refusal = refusal(&url);
            assert_eq!(refusal, UrlRefusal::SearchPath, "{url}");
            let text = refusal.to_string();
            assert!(text.contains("set `search_path`"), "{text}");
            assert!(!text.contains(SCHEMA_CANARY), "{text}");
        }
    }

    /// Other settings pass, and so do settings whose name merely CONTAINS
    /// `search_path` (a custom `myapp.search_path_hint` is legal; a dotted
    /// custom name is never `search_path`) and `search_path` as a VALUE: only
    /// a setting's name is read, and compared exactly.
    #[test]
    fn startup_options_that_do_not_set_search_path_are_accepted() {
        for options in [
            "-cmyapp.search_path_hint%3Danything",
            "-c%20myapp.search_path_hint%3Danything",
            "--myapp.search-path-hint%3Danything",
            "-cmyapp.search_path%3Dx",
            "-c%20search_path_hint%3Dx",
            "-c%20statement_timeout%3D5s",
            "-cstatement_timeout%3D5s",
            "--statement-timeout%3D5s",
            "-c%20application_name%3Dsearch_path",
            // A backslash-escaped vertical tab joins the two into one value.
            "-c%20application_name%3Dsvc%5C%0B-csearch_path%3Dx",
            "endpoint%3Dep-x",
        ] {
            let url = format!("postgres://u:p@h/db?options={options}");
            let options =
                connect_options(&url).unwrap_or_else(|refusal| panic!("{url}: {refusal}"));
            assert!(options.get_options().is_some(), "{url}");
        }
        assert!(!sets_search_path(""));
    }

    /// A NUL byte (`%00`) in anything sqlx copies into the startup packet or
    /// the password message is refused, naming the field, never the value.
    /// The first two would each send `search_path=other` to PostgreSQL as a
    /// startup parameter of its own. Then a NUL in the user, password and
    /// database (the URL's own parts and their query parameters), the host,
    /// and other parameters' values. One row per field.
    #[test]
    fn a_nul_byte_in_any_url_field_is_refused() {
        for (url, field) in [
            (
                "postgres://u:p@h/db?options=-capplication_name%3Dsvc%00search_path%00other",
                "options",
            ),
            (
                "postgres://u:p@h/db?application_name=svc%00search_path%00other",
                "application_name",
            ),
            ("postgres://svc%00search_path%00nul-canary:p@h/db", "user"),
            (
                "postgres://u:p@h/db?user=svc%00search_path%00nul-canary",
                "user",
            ),
            ("postgres://u:pw%00nul-canary@h/db", "password"),
            ("postgres://u@h/db?password=pw%00nul-canary", "password"),
            ("postgres://u:p@h/db%00search_path%00nul-canary", "dbname"),
            (
                "postgres://u:p@h/db?dbname=db%00search_path%00nul-canary",
                "dbname",
            ),
            ("postgres://u:p@h%00nul-canary/db", "host"),
            ("postgres://u:p@h/db?host=h%00nul-canary", "host"),
            ("postgres://u:p@h/db?hostaddr=%00nul-canary", "hostaddr"),
            (
                "postgres://u:p@h/db?sslrootcert=%2Fca%00nul-canary.pem",
                "sslrootcert",
            ),
            ("postgres://u:p@h/db?sslmode=require%00", "sslmode"),
            ("postgres://u:p@h/db?port=5432%00", "port"),
            (
                "postgres://u:p@h/db?connect_timeout=5%00",
                "connect_timeout",
            ),
        ] {
            let refusal = refusal(url);
            assert_eq!(refusal, UrlRefusal::NulByte(field), "{url}");
            let text = refusal.to_string();
            assert!(text.contains(&format!("in `{field}`")), "{text}");
            assert!(!text.contains("nul-canary"), "{text}");
        }
        // A literal `%00` (sent as `%2500`) is text, not a NUL: accepted.
        let options = connect_options("postgres://u:p@h/db?application_name=svc%2500x")
            .unwrap_or_else(|refusal| panic!("{refusal}"));
        assert_eq!(options.get_application_name(), Some("svc%00x"));
        assert!(decodes_to_nul("%%00") && !decodes_to_nul("%2500") && !decodes_to_nul("a%0"));
    }

    /// The `PG*` variables sqlx reads into a startup or authentication field,
    /// one per variable, through the lookup seam (a real environment cannot
    /// hold a NUL, and a test must not `set_var`): each is refused naming its
    /// field, before sqlx parses anything; a `search_path` in `PGOPTIONS` is
    /// refused too, even when the URL brings `options=` of its own (sqlx
    /// appends those). The controls: the same variables without the NUL or
    /// the setting pass.
    #[test]
    fn a_nul_byte_or_search_path_from_the_environment_is_refused() {
        let url = "postgres://u:p@h/db";
        for (variable, field) in ENVIRONMENT_FIELDS {
            let refused =
                connect_options_with_env(url, env(&[(variable, "x\0search_path\0nul-canary")]))
                    .expect_err("a NUL must be refused");
            assert_eq!(refused, UrlRefusal::NulByte(field), "{variable}");
            assert!(!refused.to_string().contains("nul-canary"), "{variable}");
            connect_options_with_env(url, env(&[(variable, "plain")]))
                .unwrap_or_else(|refusal| panic!("{variable}=plain: {refusal}"));
        }
        for url in [
            "postgres://u:p@h/db",
            "postgres://u:p@h/db?options=-c%20statement_timeout%3D5s",
        ] {
            assert_eq!(
                connect_options_with_env(
                    url,
                    env(&[("PGOPTIONS", "-c search_path=schema_canary")])
                )
                .expect_err("PGOPTIONS' search_path must be refused"),
                UrlRefusal::SearchPath,
                "{url}"
            );
            connect_options_with_env(url, env(&[("PGOPTIONS", "-c statement_timeout=5s")]))
                .unwrap_or_else(|refusal| panic!("{url}: {refusal}"));
        }
    }

    /// The fields sqlx fills from the REAL environment, checked on what it
    /// parsed, one per field, set through sqlx's own setters: the user, the
    /// database, `application_name`, the startup options, the host (a name
    /// or a socket directory), and a `search_path` in the options. Each is
    /// refused naming its field; the control passes.
    #[test]
    fn a_nul_byte_in_what_sqlx_will_send_is_refused() {
        let base = || {
            PgConnectOptions::new_without_pgpass()
                .host("h")
                .username("u")
                .database("db")
                .application_name("svc")
        };
        for (source, options, field) in [
            ("PGUSER", base().username("u\0nul-canary"), "user"),
            ("PGDATABASE", base().database("db\0nul-canary"), "dbname"),
            (
                "PGAPPNAME",
                base().application_name("svc\0search_path\0x"),
                "application_name",
            ),
            (
                "PGOPTIONS",
                base().options([("statement_timeout", "5s\0nul-canary")]),
                "options",
            ),
            ("PGHOST", base().host("h\0nul-canary"), "host"),
            (
                "PGHOST (a socket)",
                base().socket("/tmp\0nul-canary"),
                "host",
            ),
        ] {
            assert_eq!(
                refuse_unsafe_startup(&options),
                Err(UrlRefusal::NulByte(field)),
                "{source}"
            );
        }
        assert_eq!(refuse_unsafe_startup(&base()), Ok(()));
        assert_eq!(
            refuse_unsafe_startup(&base().options([("search_path", "x")])),
            Err(UrlRefusal::SearchPath)
        );
        assert_eq!(
            refuse_unsafe_startup(&base().options([("statement_timeout", "5s")])),
            Ok(())
        );
    }

    /// The child's marker for [`the_password_file_is_never_read`].
    const PGPASS_CHILD: &str = "STRIDELABS_POSTGRES_PGPASS_CHILD";

    /// No password file is ever read: with `PGPASSFILE` naming a file whose
    /// first line is malformed (sqlx logs such a line verbatim) and whose
    /// second hands every connection a password, sqlx's own parser logs the
    /// one and uses the other (the premise), and `connect_options` does
    /// neither. The environment is set on a child process alone (this test,
    /// re-run), never on this one.
    #[test]
    fn the_password_file_is_never_read() {
        if std::env::var(PGPASS_CHILD).is_ok() {
            return password_file_child();
        }
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let path = std::env::temp_dir().join(format!(
            "stridelabs-postgres-pgpass-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create the password file");
        // A line with no `:` at all is malformed before any field is
        // compared, whatever the connection. The password is alphanumeric
        // because `to_url_lossy` percent-encodes everything else.
        file.write_all(b"pgpass-line-canary\n*:*:*:*:pgpasspasswordcanary\n")
            .expect("write the password file");
        drop(file);

        let test = "connect::tests::the_password_file_is_never_read";
        let output = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(PGPASS_CHILD, "1")
            .env("PGPASSFILE", &path)
            .env_remove(PGPASSWORD_VAR)
            .output()
            .expect("run the child");
        let _ = std::fs::remove_file(&path);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "the child failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("1 passed"),
            "the child ran no test:\n{stdout}"
        );
    }

    /// The child half of [`the_password_file_is_never_read`].
    fn password_file_child() {
        use std::str::FromStr as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        const URL: &str = "postgres://u@h/db";
        let logged = |parse: &dyn Fn() -> String| {
            let recorded = crate::recorded::Recorded::default();
            let subscriber = tracing_subscriber::registry().with(recorded.clone());
            let rendered = tracing::subscriber::with_default(subscriber, parse);
            (rendered, recorded.events())
        };

        let (sqlx, sqlx_log) = logged(&|| {
            PgConnectOptions::from_str(URL)
                .expect("sqlx parses it")
                .to_url_lossy()
                .to_string()
        });
        assert!(sqlx.contains("pgpasspasswordcanary"), "premise: {sqlx}");
        assert!(
            format!("{sqlx_log:?}").contains("pgpass-line-canary"),
            "premise: {sqlx_log:?}"
        );

        let (ours, our_log) = logged(&|| {
            connect_options(URL)
                .expect("a password-less URL is usable")
                .to_url_lossy()
                .to_string()
        });
        assert!(!ours.contains("pgpasspasswordcanary"), "{ours}");
        assert!(our_log.is_empty(), "{our_log:?}");
    }

    /// `pg_split_opts`, step for step: the six C spaces split, leading and
    /// repeated ones are skipped, a backslash escapes the next character
    /// (a space or another backslash) and is dropped, a trailing one is
    /// dropped too. On Neon's spaces the vertical tab stays inside a token.
    #[test]
    fn the_options_split_as_postgresql_and_neon_split_them() {
        assert_eq!(
            pg_split_opts(" \t-c\x0Ba=b\x0C\r\n--c=d "),
            ["-c", "a=b", "--c=d"]
        );
        assert_eq!(pg_split_opts(r"a\ b c\\d e\"), ["a b", r"c\d", "e"]);
        assert_eq!(pg_split_opts("a\\\x0Bb"), ["a\x0Bb"]);
        assert_eq!(pg_split_opts(r"\"), [""]);
        assert!(pg_split_opts(" \x0B ").is_empty());
        assert_eq!(
            split_options("a\x0Bb c\\-d", |c| c.is_ascii_whitespace()),
            ["a\x0Bb", "c-d"]
        );
    }
}
