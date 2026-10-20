//! The opt-in `401` refresh-and-replay that [`crate::storage::GcsClient`]
//! and `VertexClient` share: google-auth's `AuthorizedSession` loop
//! (`requests.py:558-560`, `DEFAULT_MAX_REFRESH_ATTEMPTS = 2`), on
//! [`TokenProvider::invalidate`].

use std::time::Duration;

use reqwest::StatusCode;

use crate::auth::{AccessToken, GcpAuthError, TokenProvider};
use crate::util::{read_error_body, Failed, Heard};

/// The default number of refresh-and-replay cycles one attempt may make,
/// google-auth's `DEFAULT_MAX_REFRESH_ATTEMPTS`
/// (`google/auth/transport/__init__.py:46`).
const DEFAULT_MAX_REFRESH_ATTEMPTS: u32 = 2;

/// How long a `401`'s body may take to read before the replay. Past it the
/// response is dropped, and its connection with it, so a server that
/// trickles a rejection cannot spend the operation's budget.
const UNAUTHORIZED_BODY_TIMEOUT: Duration = Duration::from_secs(2);

/// A client's `401` refresh setting: off by default, and the count applies
/// only when it is on.
#[derive(Clone, Copy)]
pub(crate) struct UnauthorizedRefresh {
    pub(crate) enabled: bool,
    pub(crate) max_attempts: u32,
}

impl Default for UnauthorizedRefresh {
    fn default() -> UnauthorizedRefresh {
        UnauthorizedRefresh {
            enabled: false,
            max_attempts: DEFAULT_MAX_REFRESH_ATTEMPTS,
        }
    }
}

/// One attempt: send the request `build` makes with `first`, the token the
/// caller took from `tokens` for it, and, while the answer is a completed
/// `401` and `refresh` allows another refresh, drop its body (under the
/// error-body cap and [`UNAUTHORIZED_BODY_TIMEOUT`]),
/// [`TokenProvider::invalidate`] the bearer it carried, take a token again
/// and resend the request rebuilt.
///
/// The budget is this call's: one library attempt's. Without a retry policy
/// an operation is one attempt; under `GcsClient`'s retry each attempt
/// calls this afresh, with a full budget, and the response it returns (a
/// `401` replayed into a `503` included) is the one the retry classifies.
///
/// The caller takes the first token so that it can prepare what `build`
/// needs only once there is one, in v0.8.0's order: a call that gets no
/// token costs no body (Vertex's JSON, an image's base64 included).
///
/// The outer error is the provider's (no token, so nothing more was sent),
/// with whether it was transient; the inner one the transport's. Whatever
/// response comes back otherwise is the attempt's answer, for the caller to
/// classify: a `403`, a `401` past the budget, any other status. A
/// transport failure is never replayed: the request may have been applied.
/// A persistent `401` costs `max_attempts + 1` requests and `max_attempts`
/// invalidations; `0`, or `refresh` off, sends once.
///
/// `build` is called once per send, so a body it clones must be cheap to
/// clone (`Bytes`) and identical each time.
///
/// `heard` follows along, for a caller whose own timeout may cut the
/// attempt off: a `401` about to be drained is the attempt's answer until
/// its replay goes out (so an attempt cut off while draining or refreshing
/// it is classified as that `401`, never retried), and each refresh's token
/// endpoint status line is registered as it is waited on.
pub(crate) async fn send_with_refresh(
    tokens: &TokenProvider,
    first: AccessToken,
    refresh: UnauthorizedRefresh,
    operation: &'static str,
    heard: &Heard,
    build: impl Fn(&AccessToken) -> reqwest::RequestBuilder,
) -> Result<reqwest::Result<reqwest::Response>, Failed<GcpAuthError>> {
    let budget = if refresh.enabled {
        refresh.max_attempts
    } else {
        0
    };
    let mut token = first;
    let mut used = 0;
    loop {
        heard.resending();
        let response = match build(&token).send().await {
            Ok(response) if response.status() == StatusCode::UNAUTHORIZED && used < budget => {
                response
            }
            sent => return Ok(sent),
        };
        heard.status(StatusCode::UNAUTHORIZED.as_u16());
        used += 1;
        // Read so the connection can be reused; on a timeout the response is
        // dropped unread, which closes it. What it said is never used.
        let _ = tokio::time::timeout(UNAUTHORIZED_BODY_TIMEOUT, read_error_body(response)).await;
        let evicted = tokens.invalidate(&token);
        tracing::debug!(
            operation,
            refresh = used,
            evicted,
            "a request was answered 401; replaying it with a refreshed token"
        );
        token = tokens.classified_token(Some(heard)).await?;
    }
}
