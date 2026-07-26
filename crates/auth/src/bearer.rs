//! `Authorization: Bearer …` extraction (feature `axum`).

use http::header::AUTHORIZATION;
use http::request::Parts;

use crate::error::AuthError;

/// The token from a request's `Authorization: Bearer …` header.
///
/// The scheme is matched **case-insensitively** (RFC 7235 §2.1: the scheme is
/// a case-insensitive token) while the credential is returned verbatim apart
/// from surrounding whitespace — its case is never touched, because a JWT's
/// base64url is case-sensitive and lowercasing one silently invalidates every
/// signature.
///
/// Borrowed from `parts`, so extracting costs no allocation on the hot path.
///
/// Every way of not having a token — no header, a non-UTF-8 header, a
/// different scheme, no scheme at all, an empty credential — is the same
/// [`AuthError::MissingToken`]. They are one condition from the caller's point
/// of view ("this request is not presenting a bearer token"), and
/// distinguishing them in a response would only tell a prober which shapes get
/// further into the handler.
///
/// ```
/// use stridelabs_auth::bearer_token;
///
/// let request = http::Request::builder()
///     .header("authorization", "bearer eyJhbGciOi...")
///     .body(())
///     .unwrap();
/// let (parts, _) = request.into_parts();
///
/// assert_eq!(bearer_token(&parts).unwrap(), "eyJhbGciOi...");
/// ```
pub fn bearer_token(parts: &Parts) -> Result<&str, AuthError> {
    let header = parts
        .headers
        .get(AUTHORIZATION)
        .ok_or(AuthError::MissingToken)?
        .to_str()
        .map_err(|_| AuthError::MissingToken)?;

    let (scheme, credential) = header.split_once(' ').ok_or(AuthError::MissingToken)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(AuthError::MissingToken);
    }

    let token = credential.trim();
    if token.is_empty() {
        return Err(AuthError::MissingToken);
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts_with(header: Option<&str>) -> Parts {
        let mut request = http::Request::builder();
        if let Some(value) = header {
            request = request.header(AUTHORIZATION, value);
        }
        request.body(()).expect("request").into_parts().0
    }

    #[test]
    fn extracts_a_bearer_token() {
        let parts = parts_with(Some("Bearer abc.def.ghi"));

        assert_eq!(bearer_token(&parts).unwrap(), "abc.def.ghi");
    }

    #[test]
    fn the_scheme_is_case_insensitive_and_the_token_is_not() {
        for scheme in ["Bearer", "bearer", "BEARER", "BeArEr"] {
            let parts = parts_with(Some(&format!("{scheme} AbC")));

            assert_eq!(bearer_token(&parts).unwrap(), "AbC", "{scheme}");
        }
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        let parts = parts_with(Some("Bearer   abc  "));

        assert_eq!(bearer_token(&parts).unwrap(), "abc");
    }

    #[test]
    fn a_missing_header_has_no_token() {
        let parts = parts_with(None);

        assert!(matches!(
            bearer_token(&parts).unwrap_err(),
            AuthError::MissingToken
        ));
    }

    #[test]
    fn another_scheme_has_no_token() {
        for header in ["Basic dXNlcjpwYXNz", "Digest abc", "bearerish abc"] {
            assert!(
                matches!(
                    bearer_token(&parts_with(Some(header))).unwrap_err(),
                    AuthError::MissingToken
                ),
                "{header}"
            );
        }
    }

    #[test]
    fn a_schemeless_or_empty_credential_has_no_token() {
        for header in ["abc.def.ghi", "Bearer", "Bearer ", "Bearer    "] {
            assert!(
                matches!(
                    bearer_token(&parts_with(Some(header))).unwrap_err(),
                    AuthError::MissingToken
                ),
                "{header:?}"
            );
        }
    }
}
