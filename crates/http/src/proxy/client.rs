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
    /// - `ca_bundle_pem` — extra root certificates to trust, as PEM bytes,
    ///   *in addition* to the operating system's trust store (reqwest 0.13
    ///   verifies through `rustls-platform-verifier` and bundles no roots of
    ///   its own). This is the right answer for a private CA, and the reason
    ///   `verify_certificates: false` should be rare.
    ///
    /// On Linux the trust store is the system CA bundle (`SSL_CERT_FILE` /
    /// `SSL_CERT_DIR` override where it is read from). With no bundle there
    /// and no `ca_bundle_pem`, verification has no roots at all and this
    /// fails with [`ClientBuildError::Build`] — an image that calls it needs
    /// `ca-certificates`.
    ///
    /// The client **never follows redirects** (`redirect::Policy::none()`).
    /// A proxy relays a 3xx to the client and lets the client decide; chasing
    /// it would mean returning the client a response from a URL it never
    /// asked for, resolved against the proxy's network position rather than
    /// the client's.
    ///
    /// The client **never decodes a body** either: reqwest's gzip, brotli,
    /// zstd and deflate decoding are each switched off, so a coded response
    /// is relayed byte for byte under its own `Content-Encoding`, and no
    /// request asks for a coding the client did not. They are off by
    /// default only while no crate in the build turns on reqwest's feature
    /// of the same name, and a feature turned on anywhere in a consumer's
    /// graph is on for every client in it.
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
            // Nor decode what it relays, whatever features the graph unifies.
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .tcp_nodelay(true);

        if !verify_certificates {
            builder = builder.tls_danger_accept_invalid_certs(true);
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
            // Merged with the platform's roots, not instead of them
            // (`tls_certs_only` would be the replacing form).
            builder = builder.tls_certs_merge(certs);
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

    /// What [`GZIPPED`] decodes to.
    const PLAIN: &[u8] = b"relayed as sent, never decoded\n";

    /// [`PLAIN`], gzip-coded.
    const GZIPPED: &[u8] =
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03\x2b\x4a\xcd\x49\xac\x4c\x4d\x51\x48\x2c\
          \x56\x28\x4e\xcd\x2b\xd1\x51\xc8\x4b\x2d\x4b\x2d\x52\x48\x49\x4d\xce\x4f\x49\x4d\
          \xe1\x02\x00\xd6\x98\xa9\x31\x1f\x00\x00\x00";

    /// An upstream serving [`GZIPPED`] at `/gzip`, labelled as gzip.
    async fn gzip_upstream() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/gzip"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_raw(GZIPPED.to_vec(), "text/plain"),
            )
            .mount(&server)
            .await;
        server
    }

    /// What makes the relay test below mean something: this crate's test
    /// build turns on reqwest's gzip decoder (a dev-dependency), as any
    /// crate in a consumer's graph can, so a plain client asks for gzip and
    /// decodes the fixture to [`PLAIN`], dropping its `Content-Encoding`.
    /// If the dev-dependency goes, this fails first.
    #[tokio::test]
    async fn a_plain_client_in_this_build_decodes_gzip() {
        let server = gzip_upstream().await;
        let res = reqwest::Client::new()
            .get(format!("{}/gzip", server.uri()))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.headers().get("content-encoding"),
            None,
            "a decoding client drops the coding"
        );
        assert_eq!(
            res.bytes().await.unwrap().as_ref(),
            PLAIN,
            "decoded (reqwest's `gzip` decoder is not in this test build)"
        );
        let requests = server.received_requests().await.unwrap();
        let accepted = requests[0]
            .headers
            .get("accept-encoding")
            .and_then(|value| value.to_str().ok());
        assert!(
            accepted.is_some_and(|value| value.contains("gzip")),
            "a decoding client asks for gzip: {accepted:?}"
        );
    }

    /// A proxy relays bytes. In the same build, where a plain client decodes
    /// (above), a gzip-coded upstream body comes back through
    /// `UpstreamClient` exactly as sent, under its `Content-Encoding`, and the
    /// request asks for no coding: what `build`'s `no_*` calls hold. (gzip
    /// stands for all four: reqwest switches each decoder the same way.)
    #[tokio::test]
    async fn a_coded_upstream_body_is_relayed_byte_for_byte() {
        let server = gzip_upstream().await;
        let res = UpstreamClient::build(true, None)
            .unwrap()
            .inner()
            .get(format!("{}/gzip", server.uri()))
            .send()
            .await
            .unwrap();
        let encoding = res.headers().get("content-encoding").cloned();
        assert_eq!(
            res.bytes().await.unwrap().as_ref(),
            GZIPPED,
            "relayed byte for byte"
        );
        assert_eq!(
            encoding.as_ref().map(|value| value.as_bytes()),
            Some(&b"gzip"[..]),
            "the coding is the client's to undo"
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests[0].headers.get("accept-encoding"),
            None,
            "the proxy asked for a coding"
        );
    }
}
