//! Shared scaffolding for the integration tests: a fake environment, the
//! credential fixtures, and token-endpoint responders.
//!
//! Every key here is throwaway: the `service_account` fixtures sign with
//! stridelabs-auth's committed test keypair (`crates/auth/testdata`, never
//! trusted anywhere), and every secret-shaped string is a `CANARY` that the
//! redaction tests look for.

// Each test binary uses a different subset.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use stridelabs_gcp::auth::{AdcEnvironment, TokenOptions, TokenProvider};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const CLIENT_SECRET: &str = "CANARY-CLIENT-SECRET";
pub const REFRESH_TOKEN: &str = "CANARY-REFRESH-TOKEN";
pub const ACCESS_TOKEN: &str = "CANARY-ACCESS-TOKEN";
pub const CLIENT_EMAIL: &str = "imgmcp-test@test-project.iam.gserviceaccount.com";

/// The committed throwaway PKCS#1 key (`BEGIN RSA PRIVATE KEY`).
pub const TEST_KEY_PEM: &str = include_str!("../../../auth/testdata/test_signing_key.pem");
/// Its public half.
pub const TEST_JWKS: &str = include_str!("../../../auth/testdata/test_jwks.json");

/// An [`AdcEnvironment`] made of maps. A file maps to its bytes or to the
/// `io::ErrorKind` reading it fails with; an unmapped path is `NotFound`.
#[derive(Default)]
pub struct FakeEnv {
    vars: HashMap<String, String>,
    files: HashMap<PathBuf, Result<Vec<u8>, io::ErrorKind>>,
}

impl FakeEnv {
    pub fn new() -> FakeEnv {
        FakeEnv::default()
    }

    pub fn var(mut self, name: &str, value: &str) -> FakeEnv {
        self.vars.insert(name.to_owned(), value.to_owned());
        self
    }

    pub fn file(mut self, path: &str, contents: impl Into<Vec<u8>>) -> FakeEnv {
        self.files.insert(PathBuf::from(path), Ok(contents.into()));
        self
    }

    pub fn unreadable(mut self, path: &str, kind: io::ErrorKind) -> FakeEnv {
        self.files.insert(PathBuf::from(path), Err(kind));
        self
    }
}

impl AdcEnvironment for FakeEnv {
    fn var(&self, name: &str) -> Option<String> {
        self.vars.get(name).cloned()
    }

    fn read_file(&self, path: &Path) -> io::Result<Vec<u8>> {
        match self.files.get(path) {
            Some(Ok(bytes)) => Ok(bytes.clone()),
            Some(Err(kind)) => Err(io::Error::from(*kind)),
            None => Err(io::Error::from(io::ErrorKind::NotFound)),
        }
    }
}

/// gcloud's well-known file for `HOME=/home/test`.
pub const HOME: &str = "/home/test";
pub const WELL_KNOWN: &str = "/home/test/.config/gcloud/application_default_credentials.json";

pub fn b64(text: &str) -> String {
    STANDARD.encode(text)
}

/// `authorized_user` JSON with the canary secrets.
pub fn authorized_user() -> Value {
    authorized_user_with(REFRESH_TOKEN)
}

/// `authorized_user` JSON whose refresh token is `refresh_token` — how a
/// test tells which of several user credentials reached the endpoint.
pub fn authorized_user_with(refresh_token: &str) -> Value {
    json!({
        "type": "authorized_user",
        "client_id": "test-client.apps.googleusercontent.com",
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
    })
}

/// `service_account` JSON over the committed test key, exchanging at
/// `token_uri`.
pub fn service_account(token_uri: &str) -> Value {
    service_account_with_key(token_uri, TEST_KEY_PEM)
}

pub fn service_account_with_key(token_uri: &str, private_key: &str) -> Value {
    json!({
        "type": "service_account",
        "project_id": "test-project",
        "private_key_id": "test-key-id",
        "private_key": private_key,
        "client_email": CLIENT_EMAIL,
        "client_id": "1234567890",
        "token_uri": token_uri,
    })
}

/// A credential of an arbitrary `type`, otherwise plausible.
pub fn of_type(kind: &str) -> Value {
    let mut value = authorized_user();
    value["type"] = json!(kind);
    value
}

/// A token endpoint's success body, `expires_in` included as given (`null`
/// included).
pub fn token_body(token: &str, expires_in: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }))
}

/// A token endpoint's success body with no `expires_in` field at all.
pub fn token_body_without_expiry(token: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({"access_token": token, "token_type": "Bearer"}))
}

/// The route [`routed`] sends `authorized_user` exchanges to.
pub const USER_TOKEN_PATH: &str = "/token";

/// `provider` with its user-token endpoint at `{server}/token` and its
/// metadata server at `server`.
pub fn routed(provider: TokenProvider, server: &MockServer) -> TokenProvider {
    provider.with_options(
        TokenOptions::default()
            .default_token_uri(format!("{}{USER_TOKEN_PATH}", server.uri()))
            .metadata_base_url(server.uri())
            .metadata_timeout(Duration::from_secs(2)),
    )
}

/// A metadata-server provider against `server`, with a short timeout.
pub fn metadata_provider(server: &MockServer, scopes: &[&str]) -> TokenProvider {
    routed(
        TokenProvider::metadata_server(reqwest::Client::new(), scopes),
        server,
    )
}

pub const METADATA_TOKEN_PATH: &str = "/computeMetadata/v1/instance/service-accounts/default/token";

/// Mount a metadata server on `server` that answers `token` for an hour.
pub async fn mount_metadata_token(server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path(METADATA_TOKEN_PATH))
        .respond_with(token_body(token, json!(3600)))
        .mount(server)
        .await;
}

/// The form body of a received request, as a map.
pub fn form(body: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}
