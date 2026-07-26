//! The upstream HTTP client: TLS trust, connection pooling, redirect policy.
//!
//! One pooled client serves every upstream call. Per-request timeouts are
//! deliberately *not* set here — they are a per-route policy, so they belong at
//! the call site (`client.inner().get(url).timeout(..)`), not baked into a
//! client shared by every route.

use reqwest::Client;
use thiserror::Error;

/// Failure building the upstream client.
#[derive(Debug, Error)]
pub enum ClientBuildError {
    /// reqwest could not construct the client.
    #[error("failed to build upstream HTTP client: {0}")]
    Build(#[from] reqwest::Error),
    /// The supplied CA bundle was not valid PEM.
    ///
    /// Reading the bundle is the caller's problem — [`UpstreamClient::build`]
    /// takes bytes, so where they came from (a file, a secret manager, a
    /// baked-in constant) and how that read failed stays in the caller's own
    /// error type instead of being guessed at here.
    ///
    /// This is specifically a *PEM decoding* failure. A well-formed PEM whose
    /// DER the trust store then rejects surfaces as [`ClientBuildError::Build`]
    /// — reqwest applies that check while assembling the client, and there is
    /// no honest way to attribute it back to the bundle from out here.
    #[error("invalid CA bundle: {source}")]
    CaParse {
        /// The underlying parse error.
        source: reqwest::Error,
    },
}

/// A pooled HTTP client for upstream calls.
#[derive(Clone, Debug)]
pub struct UpstreamClient {
    client: Client,
}

impl UpstreamClient {
    /// Build the client.
    ///
    /// - `verify_certificates` — when `false`, invalid certificates are
    ///   accepted. That is a development affordance for self-signed upstreams;
    ///   it disables the guarantee TLS exists to provide, so it should be
    ///   reachable only from a config value an operator had to set on purpose.
    /// - `ca_bundle_pem` — an extra root certificate to trust, as PEM bytes,
    ///   *in addition* to the built-in roots. This is the right answer for a
    ///   private CA, and the reason `verify_certificates: false` should be
    ///   rare.
    ///
    /// The client **never follows redirects** (`redirect::Policy::none()`).
    /// A proxy relays a 3xx to the client and lets the client decide; chasing
    /// it would mean returning the client a response from a URL it never
    /// asked for, resolved against the proxy's network position rather than
    /// the client's.
    ///
    /// `tcp_nodelay` is on: proxied traffic is overwhelmingly small
    /// request/response pairs, where Nagle's algorithm only adds latency.
    pub fn build(
        verify_certificates: bool,
        ca_bundle_pem: Option<&[u8]>,
    ) -> Result<Self, ClientBuildError> {
        let mut builder = Client::builder()
            // A proxy relays redirects to the client; it must not follow them.
            .redirect(reqwest::redirect::Policy::none())
            .tcp_nodelay(true);

        if !verify_certificates {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(pem) = ca_bundle_pem {
            // `Certificate::from_pem` would be the obvious call, but under
            // rustls it is lazy: it stores the bytes and parses them inside
            // `build()`, so a malformed bundle comes back as an
            // indistinguishable `Build` error. `from_pem_bundle` runs the same
            // parser eagerly, over the same "every certificate in the file"
            // semantics rustls applies at build time — so the trust anchors
            // that end up in the store are identical, and the failure is
            // attributable.
            let certs = reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|source| ClientBuildError::CaParse { source })?;
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }

        Ok(Self {
            client: builder.build()?,
        })
    }

    /// The underlying reqwest client (for issuing requests).
    pub fn inner(&self) -> &Client {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[test]
    fn builds_with_defaults() {
        assert!(UpstreamClient::build(true, None).is_ok());
    }

    #[test]
    fn builds_with_verification_disabled() {
        assert!(UpstreamClient::build(false, None).is_ok());
    }

    #[test]
    fn an_invalid_ca_bundle_is_rejected() {
        let err = UpstreamClient::build(true, Some(b"-----BEGIN CERTIFICATE-----\nnope\n"))
            .expect_err("garbage PEM must not build a client");

        assert!(
            matches!(err, ClientBuildError::CaParse { .. }),
            "expected CaParse, got {err:?}"
        );
    }

    #[tokio::test]
    async fn redirects_are_relayed_not_followed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/redirect"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/target"))
            .mount(&server)
            .await;
        // Present so that "did it follow?" is answerable from the response
        // itself, not only from the request log.
        Mock::given(method("GET"))
            .and(path("/target"))
            .respond_with(ResponseTemplate::new(200).set_body_string("followed"))
            .mount(&server)
            .await;

        let client = UpstreamClient::build(true, None).unwrap();
        let res = client
            .inner()
            .get(format!("{}/redirect", server.uri()))
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 302, "the 3xx belongs to the client");
        assert_eq!(res.headers().get("location").unwrap(), "/target");
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "the proxy must not have fetched the redirect target itself"
        );
    }
}
