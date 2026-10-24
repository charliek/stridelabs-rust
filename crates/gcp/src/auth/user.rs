//! `authorized_user` credentials: a gcloud user login (`gcloud auth
//! application-default login`), exchanged with its refresh token.
//!
//! **Unscoped:** the exchange sends no `scope`, so a token carries every
//! scope the login was granted, whatever the provider asked for (see the
//! `auth` module docs). Deliberate, and documented rather than changed:
//! imgmcp's local development runs on it.

use std::fmt;

use super::adc::Fields;
use super::error::GcpAuthError;
use super::{exchange, Fetched, TokenOptions};
use crate::util::Failed;

/// An `authorized_user` credential file, parsed. All three fields are
/// required; `client_secret` and `refresh_token` are secrets.
///
/// A `token_uri` in the file is **ignored**, as google-auth ignores it for
/// user credentials: the refresh token and client secret always go to
/// Google's token endpoint ([`super::DEFAULT_TOKEN_URI`], replaceable only
/// through [`TokenOptions::default_token_uri`]). A file that could name its
/// own endpoint could hand those secrets to anyone who can write the file.
#[derive(Clone)]
pub(crate) struct AuthorizedUser {
    client_id: String,
    client_secret: String,
    refresh_token: String,
}

impl fmt::Debug for AuthorizedUser {
    /// Nothing: the client id is public in OAuth terms, but nothing here
    /// needs it in a log either, and the other two are secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedUser").finish_non_exhaustive()
    }
}

impl AuthorizedUser {
    pub(crate) fn parse(fields: &Fields<'_>) -> Result<AuthorizedUser, GcpAuthError> {
        Ok(AuthorizedUser {
            client_id: fields.required("client_id")?,
            client_secret: fields.required("client_secret")?,
            refresh_token: fields.required("refresh_token")?,
        })
    }

    /// The refresh-token grant (RFC 6749 §6). No `scope` parameter: a user
    /// credential's scopes were fixed at login, and google-auth sends none
    /// for ADC either. So the token is NOT limited to the provider's
    /// scopes.
    pub(crate) async fn fetch(
        &self,
        http: &reqwest::Client,
        options: &TokenOptions,
    ) -> Result<Fetched, Failed<GcpAuthError>> {
        let token_uri = &options.default_token_uri;
        let request = http.post(token_uri).form(&[
            ("grant_type", "refresh_token"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("refresh_token", self.refresh_token.as_str()),
        ]);
        exchange(request, token_uri, options.token_timeout).await
    }
}
