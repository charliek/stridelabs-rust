//! Offline MCP access tokens for consumers' tests, and the committed
//! `tools/list` freshness check (feature `test-support`).
//!
//! Tokens are signed with stridelabs-auth's committed **throwaway** test
//! keypair (see `stridelabs_auth::test_support`), shaped as slauth mints
//! them for an MCP connector: `iss` = the resource's issuer, `aud` = the
//! canonical resource URL, `scope` = a space-separated scope string.
//!
//! A consumer's end-to-end test serves the matching key set and points its
//! [`crate::McpVerifier`] at it:
//!
//! ```
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use stridelabs_mcp::test_support::{access_token, jwks_json};
//! use stridelabs_mcp::{McpVerifier, ProtectedResource};
//! use wiremock::matchers::{method, path};
//! use wiremock::{Mock, MockServer, ResponseTemplate};
//!
//! let resource = ProtectedResource::new(
//!     "https://parcel.stridelabs.ai/mcp",
//!     "https://auth.test.stridelabs.ai",
//!     ["parcel:read", "parcel:write"],
//! )?;
//! let jwks = MockServer::start().await;
//! Mock::given(method("GET"))
//!     .and(path("/jwks"))
//!     .respond_with(ResponseTemplate::new(200).set_body_raw(jwks_json(), "application/json"))
//!     .mount(&jwks)
//!     .await;
//! let verifier = McpVerifier::new(&resource, format!("{}/jwks", jwks.uri()), reqwest::Client::new());
//!
//! let token = access_token(&resource)
//!     .subject("user-1")
//!     .scopes(["parcel:read"])
//!     .mint();
//! let principal = verifier.verify(&token).await?;
//! assert_eq!(principal.subject, "user-1");
//! # Ok(())
//! # }
//! ```
//!
//! (`stridelabs_testing::serve_json(200, serde_json::from_str(jwks_json())?)`
//! is the same mock in one line; it answers every path.) Over HTTP, send the
//! token as `Authorization: Bearer {token}`. The server under test must also
//! accept the test's `Host`: pass `"127.0.0.1"` (or `"localhost"`) as an
//! extra host to [`crate::server_config`] when it listens on loopback. The
//! resource URL itself stays `https`: it is an identifier, never dialled.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use stridelabs_auth::test_support::{TestClaims, TestKey};

use crate::resource::ProtectedResource;

/// The public half of the key [`AccessToken::mint`] signs with, as JWKS JSON
/// text: the body a mock JWKS endpoint serves.
pub fn jwks_json() -> &'static str {
    TestKey::primary().jwks_json()
}

/// A token for `resource` that its [`crate::McpVerifier`] accepts (given the
/// test JWKS): subject `test-subject`, every one of the resource's
/// `scopes_supported`, an email and a name, one hour of validity. Each setter
/// moves it one step from that.
pub fn access_token(resource: &ProtectedResource) -> AccessToken {
    AccessToken {
        claims: TestClaims::new(resource.issuer(), resource.url()),
        scopes: Some(resource.scopes_supported().to_vec()),
        key: TestKey::primary(),
    }
}

/// A token being built; see [`access_token`].
#[derive(Debug, Clone)]
pub struct AccessToken {
    claims: TestClaims,
    /// `None`: no `scope` claim at all.
    scopes: Option<Vec<String>>,
    key: TestKey,
}

impl AccessToken {
    /// Set `sub` (`""` for the empty-subject rejection).
    pub fn subject(mut self, sub: impl Into<String>) -> AccessToken {
        self.claims = self.claims.subject(sub);
        self
    }

    /// Set the `scope` claim to `scopes`, space-separated.
    pub fn scopes<I, S>(mut self, scopes: I) -> AccessToken
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = Some(scopes.into_iter().map(Into::into).collect());
        self
    }

    /// Omit the `scope` claim (for a token that carries Hydra's `scp`
    /// instead, set with [`AccessToken::claim`]).
    pub fn without_scope(mut self) -> AccessToken {
        self.scopes = None;
        self
    }

    /// Set `client_id`.
    pub fn client_id(self, client_id: impl Into<String>) -> AccessToken {
        self.claim("client_id", json!(client_id.into()))
    }

    /// Set `email`.
    pub fn email(mut self, email: impl Into<String>) -> AccessToken {
        self.claims = self.claims.email(email);
        self
    }

    /// Omit `email` (MCP tokens need not carry one).
    pub fn without_email(mut self) -> AccessToken {
        self.claims = self.claims.without_email();
        self
    }

    /// Seconds until `exp`; negative for an expired token.
    pub fn expires_in(mut self, secs: i64) -> AccessToken {
        self.claims = self.claims.expires_in(secs);
        self
    }

    /// Any other claim, applied last (so `.claim("aud", …)` mints a token
    /// for another audience).
    pub fn claim(mut self, name: impl Into<String>, value: Value) -> AccessToken {
        self.claims = self.claims.claim(name, value);
        self
    }

    /// Sign with stridelabs-auth's *secondary* test key instead, under the
    /// primary key's `kid`: a forged signature the verifier must refuse.
    pub fn signed_by_untrusted_key(mut self) -> AccessToken {
        self.key = TestKey::secondary();
        self
    }

    /// The signed JWT (without the `Bearer ` prefix).
    pub fn mint(&self) -> String {
        let mut claims = self.claims.build();
        if let (Some(scopes), Some(object)) = (&self.scopes, claims.as_object_mut()) {
            // An explicit `.claim("scope", …)` wins over the scope list.
            object
                .entry("scope")
                .or_insert_with(|| json!(scopes.join(" ")));
        }
        self.key.mint_with_kid(TestKey::primary().kid(), &claims)
    }
}

/// Why a committed `tools/list` file failed its freshness check. `Display`
/// is the whole report, ending with the command that regenerates the file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ToolsFreshnessError {
    /// The committed file could not be read (missing, unreadable, not UTF-8).
    #[error(
        "could not read the committed MCP tool list at {}: {source}\nregenerate it with: {regenerate_command}",
        .path.display()
    )]
    Read {
        /// The file that was checked.
        path: PathBuf,
        /// The command that regenerates it.
        regenerate_command: String,
        /// Why it could not be read.
        source: std::io::Error,
    },
    /// The committed file differs from the fresh export.
    #[error(
        "{} is stale: it does not match the tools this build serves.\n{detail}\nregenerate it with: {regenerate_command}",
        .path.display()
    )]
    Stale {
        /// The file that was checked.
        path: PathBuf,
        /// The command that regenerates it.
        regenerate_command: String,
        /// Where the two first differ, or which invisible difference it is
        /// (CRLF line endings, a missing or doubled trailing newline).
        detail: String,
    },
}

/// Check that the committed file at `path` is byte-identical to `fresh_json`
/// — the service's [`canonical_tools_json`](crate::canonical_tools_json) —
/// the MCP counterpart of `stridelabs_http::openapi::check_committed_spec`.
///
/// Line endings are not normalized: a CRLF checkout is reported by name,
/// with the `.gitattributes` line that fixes it (`mcp-tools.json text
/// eol=lf`), rather than passing locally and failing for the next person.
pub fn check_committed_tools(
    path: impl AsRef<Path>,
    fresh_json: &str,
    regenerate_command: &str,
) -> Result<(), ToolsFreshnessError> {
    let path = path.as_ref();
    let committed = std::fs::read_to_string(path).map_err(|source| ToolsFreshnessError::Read {
        path: path.to_path_buf(),
        regenerate_command: regenerate_command.to_owned(),
        source,
    })?;
    if committed == fresh_json {
        return Ok(());
    }
    Err(ToolsFreshnessError::Stale {
        path: path.to_path_buf(),
        regenerate_command: regenerate_command.to_owned(),
        detail: describe_difference(path, &committed, fresh_json),
    })
}

/// [`check_committed_tools`], panicking with the report: the one-line test.
///
/// ```no_run
/// # fn tools() -> Vec<rmcp::model::Tool> { vec![] }
/// #[test]
/// fn the_committed_tool_list_is_fresh() {
///     stridelabs_mcp::test_support::assert_committed_tools_are_fresh(
///         concat!(env!("CARGO_MANIFEST_DIR"), "/mcp-tools.json"),
///         &stridelabs_mcp::canonical_tools_json(&tools()),
///         "cargo run -- tools > mcp-tools.json",
///     );
/// }
/// ```
#[track_caller]
pub fn assert_committed_tools_are_fresh(
    path: impl AsRef<Path>,
    fresh_json: &str,
    regenerate_command: &str,
) {
    if let Err(error) = check_committed_tools(path, fresh_json, regenerate_command) {
        panic!("{error}");
    }
}

fn describe_difference(path: &Path, committed: &str, fresh: &str) -> String {
    if committed.contains('\r') {
        let file = path.file_name().map_or_else(
            || path.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        );
        return format!(
            "the committed file has CRLF line endings; the export always writes LF. \
             Pin it to LF and re-check it out:\n    echo '{file} text eol=lf' >> .gitattributes"
        );
    }
    if committed.trim_end_matches('\n') == fresh.trim_end_matches('\n') {
        return if committed.ends_with('\n') {
            "the content matches but the committed file has more than one trailing newline".into()
        } else {
            "the content matches but the committed file has no trailing newline".into()
        };
    }
    let committed_lines: Vec<&str> = committed.lines().collect();
    let fresh_lines: Vec<&str> = fresh.lines().collect();
    for (number, (old, new)) in committed_lines.iter().zip(&fresh_lines).enumerate() {
        if old != new {
            return format!(
                "first difference at line {}:\n  committed: {old}\n  exported:  {new}",
                number + 1
            );
        }
    }
    if committed_lines.len() < fresh_lines.len() {
        format!(
            "the committed file ends at line {}; the export continues with: {}",
            committed_lines.len(),
            fresh_lines[committed_lines.len()]
        )
    } else {
        format!(
            "the export ends at line {}; the committed file continues with: {}",
            fresh_lines.len(),
            committed_lines[fresh_lines.len()]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthMethod, McpVerifier, VerifyError};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn resource() -> ProtectedResource {
        ProtectedResource::new(
            "https://parcel.stridelabs.ai/mcp",
            "https://auth.test.stridelabs.ai",
            ["parcel:read", "parcel:write"],
        )
        .expect("canonical")
    }

    async fn verifier() -> (MockServer, McpVerifier) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(jwks_json(), "application/json"))
            .mount(&server)
            .await;
        let verifier = McpVerifier::new(
            &resource(),
            format!("{}/jwks", server.uri()),
            reqwest::Client::new(),
        );
        (server, verifier)
    }

    #[tokio::test]
    async fn a_default_token_verifies_with_every_supported_scope() {
        let (_server, verifier) = verifier().await;

        let principal = verifier
            .verify(&access_token(&resource()).mint())
            .await
            .expect("valid");

        assert_eq!(principal.subject, "test-subject");
        assert_eq!(principal.auth_method, AuthMethod::Jwt);
        assert!(principal.has_scope("parcel:read") && principal.has_scope("parcel:write"));
    }

    #[tokio::test]
    async fn each_setter_shapes_the_token() {
        let (_server, verifier) = verifier().await;
        let token = access_token(&resource())
            .subject("user-9")
            .scopes(["parcel:read"])
            .client_id("connector-1")
            .without_email()
            .mint();

        let principal = verifier.verify(&token).await.expect("valid");

        assert_eq!(principal.subject, "user-9");
        assert_eq!(principal.scopes.iter().collect::<Vec<_>>(), ["parcel:read"]);
        assert_eq!(principal.client_id.as_deref(), Some("connector-1"));
        assert_eq!(principal.email, None);

        let emailed = access_token(&resource()).email("u@example.com").mint();
        let principal = verifier.verify(&emailed).await.expect("valid");
        assert_eq!(principal.email.as_deref(), Some("u@example.com"));

        let scp_only = access_token(&resource())
            .without_scope()
            .claim("scp", json!(["parcel:write"]))
            .mint();
        let principal = verifier.verify(&scp_only).await.expect("valid");
        assert_eq!(
            principal.scopes.iter().collect::<Vec<_>>(),
            ["parcel:write"]
        );

        let explicit = access_token(&resource())
            .claim("scope", json!("offline_access"))
            .mint();
        let principal = verifier.verify(&explicit).await.expect("valid");
        assert_eq!(
            principal.scopes.iter().collect::<Vec<_>>(),
            ["offline_access"]
        );
    }

    #[tokio::test]
    async fn the_rejection_shapes_are_rejected() {
        let (_server, verifier) = verifier().await;

        for (token, reason) in [
            (
                access_token(&resource()).expires_in(-3600).mint(),
                "token rejected: token has expired",
            ),
            (
                access_token(&resource()).signed_by_untrusted_key().mint(),
                "token rejected: signature is invalid",
            ),
            (
                access_token(&resource())
                    .claim("aud", json!("parcel-rest-api"))
                    .mint(),
                "token rejected: audience is not accepted",
            ),
            (
                access_token(&resource()).subject("").mint(),
                "token is missing a subject claim",
            ),
        ] {
            assert_eq!(
                verifier.verify(&token).await,
                Err(VerifyError::invalid(reason))
            );
        }
    }

    // --- the tools freshness check -----------------------------------------

    const REGEN: &str = "cargo run -- tools > mcp-tools.json";
    const FRESH: &str = "{\n  \"tools\": [\n    {\n      \"name\": \"ping\"\n    }\n  ]\n}\n";

    fn committed(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("a temp file");
        std::fs::write(file.path(), contents).expect("written");
        file
    }

    fn report(contents: &str) -> String {
        let file = committed(contents);
        check_committed_tools(file.path(), FRESH, REGEN)
            .expect_err("stale")
            .to_string()
    }

    #[test]
    fn a_fresh_file_passes() {
        let file = committed(FRESH);
        check_committed_tools(file.path(), FRESH, REGEN).expect("fresh");
        assert_committed_tools_are_fresh(file.path(), FRESH, REGEN);
    }

    #[test]
    fn a_stale_file_names_the_first_difference_and_the_command() {
        let report = report(&FRESH.replace("ping", "pong"));

        assert!(report.contains("is stale"), "{report}");
        assert!(report.contains("first difference at line 4"), "{report}");
        assert!(
            report.contains("committed:       \"name\": \"pong\""),
            "{report}"
        );
        assert!(
            report.ends_with(&format!("regenerate it with: {REGEN}")),
            "{report}"
        );
    }

    #[test]
    fn a_shorter_or_longer_file_says_where_it_ends() {
        let shorter = report("{\n  \"tools\": [\n");
        assert!(
            shorter.contains("the committed file ends at line 2"),
            "{shorter}"
        );
        let longer = report(&format!("{FRESH}extra\n"));
        assert!(longer.contains("the export ends at line 7"), "{longer}");
    }

    #[test]
    fn invisible_differences_are_called_out_by_name() {
        let crlf = report(&FRESH.replace('\n', "\r\n"));
        assert!(crlf.contains("CRLF"), "{crlf}");
        assert!(crlf.contains("text eol=lf"), "{crlf}");

        let bare = report(FRESH.trim_end());
        assert!(bare.contains("no trailing newline"), "{bare}");

        let doubled = report(&format!("{FRESH}\n"));
        assert!(
            doubled.contains("more than one trailing newline"),
            "{doubled}"
        );
    }

    #[test]
    fn a_missing_file_names_the_command() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let error = check_committed_tools(dir.path().join("mcp-tools.json"), FRESH, REGEN)
            .expect_err("missing");

        assert!(
            matches!(error, ToolsFreshnessError::Read { .. }),
            "{error:?}"
        );
        assert!(error.to_string().contains(REGEN), "{error}");
    }

    #[test]
    #[should_panic(expected = "regenerate it with: cargo run -- tools > mcp-tools.json")]
    fn the_assertion_panics_with_the_report() {
        let file = committed("{}\n");
        assert_committed_tools_are_fresh(file.path(), FRESH, REGEN);
    }
}
