//! The authenticated caller of an MCP tool, and per-tool scope enforcement.
//!
//! [`crate::McpAuthLayer`] verifies the bearer token and inserts a
//! [`Principal`] into the request's extensions; [`crate::principal()`] reads it
//! back inside a tool, and [`Principal::check_scopes`] is the per-tool
//! authorization check. Authentication happens once, at the HTTP boundary;
//! authorization is per tool, because tools need different scopes (and a
//! `ping` needs none).

use std::collections::BTreeSet;
use std::fmt;

/// How a [`Principal`] authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthMethod {
    /// An RS256 JWT from the authorization server, audience = the resource.
    Jwt,
    /// A credential the app verified itself, through a
    /// [`crate::CredentialVerifier`] (slauth personal access tokens, the
    /// app's own API tokens, …).
    Token,
}

impl AuthMethod {
    /// `"jwt"` or `"token"`: the audit log's `auth_method`.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethod::Jwt => "jwt",
            AuthMethod::Token => "token",
        }
    }
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The authenticated caller of an MCP request.
///
/// `subject` is the issuer's opaque user identifier (slauth's Kratos
/// identity UUID for a JWT; whatever the app's [`crate::CredentialVerifier`]
/// says for a token). `email`, `name` and `client_id` are present when the
/// credential carried them; MCP tokens need not carry an email, so nothing
/// here may be keyed on one being there.
///
/// `#[non_exhaustive]` so a field can join without a breaking change: read
/// the fields directly, and build one (in a [`crate::CredentialVerifier`])
/// with [`Principal::new`] and the `with_*` setters.
///
/// `Debug` shows whether `email` and `name` are present, never their values:
/// a `tracing::debug!(?principal)` must not put personal data in the logs.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Principal {
    /// The issuer's identifier for the user. Never empty.
    pub subject: String,
    /// The scopes the credential grants.
    pub scopes: BTreeSet<String>,
    /// How the credential was verified.
    pub auth_method: AuthMethod,
    /// The user's email, if the credential carried one.
    pub email: Option<String>,
    /// The user's display name, if the credential carried one.
    pub name: Option<String>,
    /// The OAuth client the credential was issued to, if known.
    pub client_id: Option<String>,
}

impl Principal {
    /// A principal for `subject` holding `scopes`.
    pub fn new<I, S>(subject: impl Into<String>, scopes: I, auth_method: AuthMethod) -> Principal
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Principal {
            subject: subject.into(),
            scopes: scopes.into_iter().map(Into::into).collect(),
            auth_method,
            email: None,
            name: None,
            client_id: None,
        }
    }

    /// Set `email`.
    pub fn with_email(mut self, email: impl Into<String>) -> Principal {
        self.email = Some(email.into());
        self
    }

    /// Set `name`.
    pub fn with_name(mut self, name: impl Into<String>) -> Principal {
        self.name = Some(name.into());
        self
    }

    /// Set `client_id`.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Principal {
        self.client_id = Some(client_id.into());
        self
    }

    /// Whether the credential grants `scope`.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }

    /// `Err` naming the missing scopes unless the credential grants every one
    /// of `required`.
    ///
    /// The message (see [`ScopeError`]) is meant for the model and the user:
    /// what is missing, what was granted, and that reconnecting with the
    /// scopes fixes it.
    pub fn check_scopes<I, S>(&self, required: I) -> Result<(), ScopeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let missing: BTreeSet<String> = required
            .into_iter()
            .filter(|scope| !self.scopes.contains(scope.as_ref()))
            .map(|scope| scope.as_ref().to_owned())
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(ScopeError {
                missing: missing.into_iter().collect(),
                granted: self.scopes.iter().cloned().collect(),
            })
        }
    }
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let presence = |value: &Option<String>| value.as_ref().map(|_| "<redacted>");
        f.debug_struct("Principal")
            .field("subject", &self.subject)
            .field("scopes", &self.scopes)
            .field("auth_method", &self.auth_method)
            .field("email", &presence(&self.email))
            .field("name", &presence(&self.name))
            .field("client_id", &self.client_id)
            .finish()
    }
}

/// The principal lacks a scope a tool requires.
///
/// Its message reaches the client unchanged (a tool error, visible to the
/// model) — it names only scopes, which the credential's holder already
/// knows — and the tool boundary records the call as `denied`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "Missing required scope(s): {}. This credential grants: {}. \
     Reconnect with the required scopes to use this tool.",
    .missing.join(", "),
    granted_list(.granted)
)]
pub struct ScopeError {
    missing: Vec<String>,
    granted: Vec<String>,
}

impl ScopeError {
    /// The required scopes the credential does not grant, sorted.
    pub fn missing(&self) -> &[String] {
        &self.missing
    }

    /// The scopes the credential does grant, sorted.
    pub fn granted(&self) -> &[String] {
        &self.granted
    }
}

fn granted_list(granted: &[String]) -> String {
    if granted.is_empty() {
        "none".to_owned()
    } else {
        granted.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(scopes: &[&str]) -> Principal {
        Principal::new("user-1", scopes.iter().copied(), AuthMethod::Jwt)
    }

    #[test]
    fn granted_scopes_pass() {
        let principal = principal(&["parcel:read", "parcel:write"]);

        principal.check_scopes(["parcel:read"]).expect("granted");
        principal
            .check_scopes(["parcel:write", "parcel:read"])
            .expect("granted");
        principal
            .check_scopes(Vec::<String>::new())
            .expect("nothing required");
        assert!(principal.has_scope("parcel:read"));
        assert!(!principal.has_scope("parcel:admin"));
    }

    #[test]
    fn the_message_matches_the_python_boundary() {
        let err = principal(&["parcel:write", "parcel:read"])
            .check_scopes(["parcel:read", "parcel:admin", "audio:generate"])
            .unwrap_err();

        assert_eq!(err.missing(), ["audio:generate", "parcel:admin"]);
        assert_eq!(err.granted(), ["parcel:read", "parcel:write"]);
        assert_eq!(
            err.to_string(),
            "Missing required scope(s): audio:generate, parcel:admin. \
             This credential grants: parcel:read, parcel:write. \
             Reconnect with the required scopes to use this tool."
        );
    }

    #[test]
    fn a_scopeless_credential_grants_none() {
        let err = principal(&[]).check_scopes(["parcel:read"]).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Missing required scope(s): parcel:read. This credential grants: none. \
             Reconnect with the required scopes to use this tool."
        );
    }

    #[test]
    fn debug_never_shows_email_or_name() {
        let principal = principal(&["a"])
            .with_email("someone@example.com")
            .with_name("Some One")
            .with_client_id("connector-1");

        let debug = format!("{principal:?}");

        assert!(!debug.contains("someone@example.com"), "{debug}");
        assert!(!debug.contains("Some One"), "{debug}");
        assert!(debug.contains("user-1"), "{debug}");
        assert!(debug.contains("connector-1"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    #[test]
    fn auth_methods_render_for_the_audit_log() {
        assert_eq!(AuthMethod::Jwt.to_string(), "jwt");
        assert_eq!(AuthMethod::Token.as_str(), "token");
    }
}
