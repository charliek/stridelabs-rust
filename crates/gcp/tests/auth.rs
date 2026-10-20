//! The ADC chain, the token sources, the cache and the redaction rule, against
//! wiremock and an injected environment. Nothing here reads the process
//! environment, touches the file system, or calls Google.
//!
//! The single-flight tests live in `src/auth/single_flight_tests.rs`: they
//! count the waiters on an attempt, which only the crate itself can see.

mod common;

use std::io;
use std::time::{Duration, Instant};

use common::*;
use serde_json::{json, Value};
use stridelabs_gcp::auth::{
    AccessToken, CredentialKind, CredentialSource, GcpAuthError, TokenOptions, TokenProvider,
    DEFAULT_METADATA_TIMEOUT, DEFAULT_TOKEN_TIMEOUT, GOOGLE_APPLICATION_CREDENTIALS,
    GOOGLE_CLOUD_QUOTA_PROJECT, MAX_TOKEN_RESPONSE, REFRESH_MARGIN,
};
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/devstorage.read_write",
];

fn http() -> reqwest::Client {
    reqwest::Client::new()
}

fn from_env(explicit: Option<&str>, env: &FakeEnv) -> Result<TokenProvider, GcpAuthError> {
    TokenProvider::from_environment_with(http(), SCOPES, explicit, env)
}

fn user_provider(json: &Value) -> TokenProvider {
    TokenProvider::from_authorized_user_json(http(), SCOPES, json.to_string().as_bytes()).unwrap()
}

/// A file path an env var can name.
const KEY_FILE: &str = "/etc/keys/key.json";

/// Every file source configured and valid, each with its own refresh token,
/// so the one picked is visible in the exchange that arrives.
fn every_source() -> FakeEnv {
    FakeEnv::new()
        .var(GOOGLE_APPLICATION_CREDENTIALS, KEY_FILE)
        .file(KEY_FILE, authorized_user_with("gac-rt").to_string())
        .var("HOME", HOME)
        .file(
            WELL_KNOWN,
            authorized_user_with("well-known-rt").to_string(),
        )
}

/// Answer the user-token exchange for `refresh_token` with `token`.
async fn mount_user_token(server: &MockServer, refresh_token: &str, token: &str) {
    Mock::given(method("POST"))
        .and(path(USER_TOKEN_PATH))
        .and(body_string_contains(format!(
            "refresh_token={refresh_token}"
        )))
        .respond_with(token_body(token, json!(3600)))
        .mount(server)
        .await;
}

// ---- source order ---------------------------------------------------------

#[tokio::test]
async fn the_explicit_base64_credential_beats_every_other_source() {
    let server = MockServer::start().await;
    mount_user_token(&server, "explicit-rt", "explicit-token").await;
    let explicit = b64(&authorized_user_with("explicit-rt").to_string());

    let provider = from_env(Some(&explicit), &every_source()).expect("explicit parses");

    assert_eq!(provider.source(), CredentialSource::ExplicitBase64);
    assert_eq!(provider.kind(), CredentialKind::AuthorizedUser);
    let provider = routed(provider, &server);
    assert_eq!(provider.token().await.unwrap().token, "explicit-token");
}

#[tokio::test]
async fn google_application_credentials_beats_the_well_known_file() {
    let server = MockServer::start().await;
    mount_user_token(&server, "gac-rt", "gac-token").await;

    let provider = from_env(None, &every_source()).expect("the env file parses");

    assert_eq!(provider.source(), CredentialSource::ApplicationCredentials);
    let provider = routed(provider, &server);
    assert_eq!(provider.token().await.unwrap().token, "gac-token");
}

#[tokio::test]
async fn the_well_known_file_beats_the_metadata_server() {
    let server = MockServer::start().await;
    mount_user_token(&server, "well-known-rt", "well-known-token").await;
    mount_metadata_token(&server, "metadata-token").await;
    let env = FakeEnv::new().var("HOME", HOME).file(
        WELL_KNOWN,
        authorized_user_with("well-known-rt").to_string(),
    );

    let provider = from_env(None, &env).expect("the well-known file parses");

    assert_eq!(provider.source(), CredentialSource::GcloudDefault);
    let provider = routed(provider, &server);
    assert_eq!(provider.token().await.unwrap().token, "well-known-token");
}

#[tokio::test]
async fn cloudsdk_config_moves_the_well_known_file() {
    let env = FakeEnv::new()
        .var("HOME", HOME)
        .var("CLOUDSDK_CONFIG", "/opt/gcloud")
        .file(
            "/opt/gcloud/application_default_credentials.json",
            authorized_user().to_string(),
        );

    let provider = from_env(None, &env).expect("the moved file parses");

    assert_eq!(provider.source(), CredentialSource::GcloudDefault);
}

#[tokio::test]
async fn with_every_source_absent_the_metadata_server_is_used() {
    let server = MockServer::start().await;
    mount_metadata_token(&server, "metadata-token").await;
    // Unset, or a well-known file that does not exist. The directory
    // variables count as unset when blank; the credential sources do not (see
    // the configured-but-broken table).
    for env in [
        FakeEnv::new(),
        FakeEnv::new().var("HOME", HOME),
        FakeEnv::new().var("HOME", "").var("CLOUDSDK_CONFIG", " "),
    ] {
        let provider = from_env(None, &env).expect("nothing configured is not an error");
        assert_eq!(provider.source(), CredentialSource::MetadataServer);
        assert_eq!(provider.kind(), CredentialKind::MetadataServer);
        let provider = routed(provider, &server);
        assert_eq!(provider.token().await.unwrap().token, "metadata-token");
    }
}

#[test]
fn construction_is_synchronous_and_makes_no_request() {
    // A token endpoint nothing listens on: construction must not care.
    let env = FakeEnv::new()
        .var(GOOGLE_APPLICATION_CREDENTIALS, KEY_FILE)
        .file(KEY_FILE, authorized_user().to_string());
    let provider = from_env(None, &env).expect("no network needed");
    assert_eq!(provider.source(), CredentialSource::ApplicationCredentials);
    assert_eq!(
        TokenProvider::metadata_server(http(), SCOPES).source(),
        CredentialSource::MetadataServer
    );
}

// ---- unsupported types ----------------------------------------------------

#[test]
fn every_other_credential_type_is_unsupported_from_every_source() {
    for kind in [
        "external_account",
        "impersonated_service_account",
        "external_account_authorized_user",
        "gdch_service_account",
        "made_up",
    ] {
        let json = of_type(kind).to_string();
        let attempts = [
            from_env(Some(&b64(&json)), &FakeEnv::new()),
            from_env(
                None,
                &FakeEnv::new()
                    .var(GOOGLE_APPLICATION_CREDENTIALS, KEY_FILE)
                    .file(KEY_FILE, json.clone()),
            ),
            from_env(
                None,
                &FakeEnv::new()
                    .var("HOME", HOME)
                    .file(WELL_KNOWN, json.clone()),
            ),
            TokenProvider::from_credentials_json(http(), SCOPES, json.as_bytes()),
        ];
        for result in attempts {
            match result {
                Err(GcpAuthError::Unsupported(message)) => {
                    assert!(message.contains(kind), "{message:?} names {kind}")
                }
                other => panic!("{kind} must be Unsupported, got {other:?}"),
            }
        }
    }
}

#[test]
fn a_hostile_type_is_not_quoted() {
    for kind in [
        "CANARY-Type",
        "has space CANARY",
        "external_account\nCANARY forged line",
        "canary\"quote",
        &format!("canary{}", "_".repeat(64)),
    ] {
        match TokenProvider::from_credentials_json(
            http(),
            SCOPES,
            of_type(kind).to_string().as_bytes(),
        ) {
            Err(error @ GcpAuthError::Unsupported(_)) => {
                let rendered = format!("{error} {error:?}");
                assert!(!rendered.to_lowercase().contains("canary"), "{rendered}");
                assert!(rendered.contains("<unrecognized>"), "{rendered}");
            }
            other => panic!("{kind:?} must be Unsupported, got {other:?}"),
        }
    }
}

#[cfg(not(feature = "service-account-key"))]
#[test]
fn a_service_account_key_without_the_feature_is_unsupported() {
    let json = service_account("http://127.0.0.1:1/token").to_string();
    let attempts = [
        from_env(Some(&b64(&json)), &FakeEnv::new()),
        from_env(
            None,
            &FakeEnv::new()
                .var(GOOGLE_APPLICATION_CREDENTIALS, KEY_FILE)
                .file(KEY_FILE, json.clone()),
        ),
        TokenProvider::from_service_account_json(http(), SCOPES, json.as_bytes()),
    ];
    for result in attempts {
        match result {
            Err(GcpAuthError::Unsupported(message)) => assert_eq!(
                message,
                stridelabs_gcp::auth::SERVICE_ACCOUNT_NOT_COMPILED_IN
            ),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}

#[test]
fn a_typed_constructor_rejects_the_other_type() {
    let user = authorized_user().to_string();
    assert!(matches!(
        TokenProvider::from_service_account_json(http(), SCOPES, user.as_bytes()),
        Err(GcpAuthError::Unsupported(_))
    ));
    assert_eq!(
        TokenProvider::from_authorized_user_json(http(), SCOPES, user.as_bytes())
            .unwrap()
            .source(),
        CredentialSource::Json
    );
}

// ---- configured but broken ------------------------------------------------

/// Each case configures exactly one broken source above a valid one (a
/// well-known file, and the metadata server below everything). The
/// constructor must fail — never pick the valid source underneath.
#[test]
fn a_configured_but_broken_source_fails_instead_of_falling_through() {
    let valid_below = || {
        FakeEnv::new()
            .var("HOME", HOME)
            .file(WELL_KNOWN, authorized_user().to_string())
    };
    let gac = |contents: &str| {
        valid_below()
            .var(GOOGLE_APPLICATION_CREDENTIALS, KEY_FILE)
            .file(KEY_FILE, contents.to_owned())
    };
    let mut no_refresh_token = authorized_user();
    no_refresh_token
        .as_object_mut()
        .unwrap()
        .remove("refresh_token");
    let mut mistyped = authorized_user();
    mistyped["client_secret"] = json!(42);
    let mut no_type = authorized_user();
    no_type.as_object_mut().unwrap().remove("type");

    let cases: Vec<(&str, Option<String>, FakeEnv, &str)> = vec![
        (
            "explicit: empty",
            Some(String::new()),
            valid_below(),
            "explicit",
        ),
        (
            "explicit: blank",
            Some("  \n".into()),
            valid_below(),
            "explicit",
        ),
        (
            "explicit: not base64",
            Some("!!!not base64!!!".into()),
            valid_below(),
            "explicit",
        ),
        (
            "explicit: not JSON",
            Some(b64("{nope")),
            valid_below(),
            "explicit",
        ),
        (
            "explicit: not an object",
            Some(b64("[1, 2]")),
            valid_below(),
            "explicit",
        ),
        (
            "explicit: no type",
            Some(b64(&no_type.to_string())),
            valid_below(),
            "explicit",
        ),
        (
            "explicit: missing field",
            Some(b64(&no_refresh_token.to_string())),
            valid_below(),
            "explicit",
        ),
        (
            "explicit: mistyped field",
            Some(b64(&mistyped.to_string())),
            valid_below(),
            "explicit",
        ),
        (
            "env var: set but empty",
            None,
            valid_below().var(GOOGLE_APPLICATION_CREDENTIALS, ""),
            GOOGLE_APPLICATION_CREDENTIALS,
        ),
        (
            "env var: set but blank",
            None,
            valid_below().var(GOOGLE_APPLICATION_CREDENTIALS, "  "),
            GOOGLE_APPLICATION_CREDENTIALS,
        ),
        (
            "env file: missing",
            None,
            valid_below().var(GOOGLE_APPLICATION_CREDENTIALS, "/nowhere/key.json"),
            GOOGLE_APPLICATION_CREDENTIALS,
        ),
        (
            "env file: unreadable",
            None,
            valid_below()
                .var(GOOGLE_APPLICATION_CREDENTIALS, KEY_FILE)
                .unreadable(KEY_FILE, io::ErrorKind::PermissionDenied),
            GOOGLE_APPLICATION_CREDENTIALS,
        ),
        (
            "env file: not JSON",
            None,
            gac("not json"),
            GOOGLE_APPLICATION_CREDENTIALS,
        ),
        (
            "env file: empty",
            None,
            gac(""),
            GOOGLE_APPLICATION_CREDENTIALS,
        ),
        (
            "env file: missing field",
            None,
            gac(&no_refresh_token.to_string()),
            GOOGLE_APPLICATION_CREDENTIALS,
        ),
        (
            "well-known file: not JSON",
            None,
            FakeEnv::new().var("HOME", HOME).file(WELL_KNOWN, "{"),
            "gcloud ADC file",
        ),
        (
            "well-known file: unreadable",
            None,
            FakeEnv::new()
                .var("HOME", HOME)
                .unreadable(WELL_KNOWN, io::ErrorKind::PermissionDenied),
            "gcloud ADC file",
        ),
    ];

    for (name, explicit, env, origin) in cases {
        match from_env(explicit.as_deref(), &env) {
            Err(GcpAuthError::InvalidCredentials {
                origin: got,
                reason,
            }) => {
                assert!(
                    got.contains(origin),
                    "{name}: origin {got:?} names {origin:?}"
                );
                assert!(!reason.is_empty(), "{name}");
            }
            other => panic!("{name}: expected InvalidCredentials, got {other:?}"),
        }
    }
}

#[test]
fn a_configured_but_unsupported_source_fails_instead_of_falling_through() {
    let env = FakeEnv::new()
        .var(GOOGLE_APPLICATION_CREDENTIALS, KEY_FILE)
        .file(KEY_FILE, of_type("external_account").to_string())
        .var("HOME", HOME)
        .file(WELL_KNOWN, authorized_user().to_string());
    assert!(matches!(
        from_env(None, &env),
        Err(GcpAuthError::Unsupported(_))
    ));
}

// ---- service_account ------------------------------------------------------

#[cfg(feature = "service-account-key")]
mod service_account {
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    use super::*;

    #[derive(serde::Deserialize)]
    struct Assertion {
        iss: String,
        scope: String,
        aud: String,
        iat: i64,
        exp: i64,
    }

    /// Exchange `private_key`'s assertion at a mock and check what arrived:
    /// the grant, and an RS256 signature that verifies against the committed
    /// key's public half, with the expected claims.
    async fn exchange_and_verify(private_key: &str) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(token_body("sa-token", json!(3600)))
            .expect(1)
            .mount(&server)
            .await;
        let token_uri = format!("{}/token", server.uri());
        let json = service_account_with_key(&token_uri, private_key).to_string();

        let provider = from_env(Some(&b64(&json)), &FakeEnv::new()).expect("the key parses");
        assert_eq!(provider.kind(), CredentialKind::ServiceAccount);
        assert_eq!(provider.token().await.unwrap().token, "sa-token");

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method.as_str(), "POST");
        assert_eq!(
            request.headers.get("content-type").unwrap(),
            "application/x-www-form-urlencoded"
        );
        let form = form(&request.body);
        assert_eq!(
            form["grant_type"],
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        );
        assert_eq!(form.len(), 2, "grant_type and assertion only: {form:?}");

        let assertion = &form["assertion"];
        let header = decode_header(assertion).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(header.kid.as_deref(), Some("test-key-id"));
        let jwks: JwkSet = serde_json::from_str(TEST_JWKS).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&token_uri]);
        validation.set_issuer(&[CLIENT_EMAIL]);
        let claims = decode::<Assertion>(
            assertion,
            &DecodingKey::from_jwk(&jwks.keys[0]).unwrap(),
            &validation,
        )
        .expect("the assertion verifies")
        .claims;

        assert_eq!(claims.iss, CLIENT_EMAIL);
        assert_eq!(claims.aud, token_uri);
        assert_eq!(claims.scope, SCOPES.join(" "));
        assert_eq!(claims.exp - claims.iat, 3600);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!((claims.iat - now).abs() < 60, "iat is now");
        server.verify().await;
    }

    #[tokio::test]
    async fn a_pkcs1_key_signs_a_verifiable_assertion() {
        exchange_and_verify(TEST_KEY_PEM).await;
    }

    /// Google mints PKCS#8 (`BEGIN PRIVATE KEY`); the committed test key is
    /// PKCS#1. Wrapping the same key in a PKCS#8 envelope here proves the
    /// format that ships without committing a second key.
    #[tokio::test]
    async fn a_pkcs8_key_signs_a_verifiable_assertion() {
        let pkcs8 = pkcs8(TEST_KEY_PEM);
        assert!(pkcs8.starts_with("-----BEGIN PRIVATE KEY-----"));
        exchange_and_verify(&pkcs8).await;
    }

    #[test]
    fn a_broken_service_account_key_is_invalid() {
        let mut no_email = service_account("http://127.0.0.1:1/token");
        no_email.as_object_mut().unwrap().remove("client_email");
        let mut no_token_uri = service_account("http://127.0.0.1:1/token");
        no_token_uri.as_object_mut().unwrap().remove("token_uri");
        let bad_pem = service_account_with_key(
            "http://127.0.0.1:1/token",
            "-----BEGIN PRIVATE KEY-----\nCANARYKEYMATERIAL\n-----END PRIVATE KEY-----\n",
        );
        for (name, json) in [
            ("no email", no_email),
            ("no token_uri", no_token_uri),
            ("bad pem", bad_pem),
        ] {
            match TokenProvider::from_service_account_json(
                http(),
                SCOPES,
                json.to_string().as_bytes(),
            ) {
                Err(error @ GcpAuthError::InvalidCredentials { .. }) => {
                    let rendered = format!("{error} {error:?}");
                    assert!(!rendered.contains("CANARY"), "{name}: {rendered}");
                }
                other => panic!("{name}: expected InvalidCredentials, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_service_account_provider_debug_shows_no_key() {
        let json = service_account("http://127.0.0.1:1/token?key=CANARY").to_string();
        let provider =
            TokenProvider::from_service_account_json(http(), SCOPES, json.as_bytes()).unwrap();
        let rendered = format!("{provider:?} {provider:#?}");
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
        assert!(!rendered.contains("CANARY"), "{rendered}");
        assert!(rendered.contains(CLIENT_EMAIL), "{rendered}");
    }

    /// PKCS#1 PEM → PKCS#8 PEM: `SEQUENCE { INTEGER 0, AlgorithmIdentifier
    /// { rsaEncryption, NULL }, OCTET STRING <PKCS#1 DER> }`.
    fn pkcs8(pkcs1_pem: &str) -> String {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        fn der_len(len: usize) -> Vec<u8> {
            match len {
                0..=0x7f => vec![len as u8],
                0x80..=0xff => vec![0x81, len as u8],
                _ => vec![0x82, (len >> 8) as u8, len as u8],
            }
        }
        fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            out.extend(der_len(content.len()));
            out.extend_from_slice(content);
            out
        }

        let body: String = pkcs1_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let pkcs1 = STANDARD.decode(body).unwrap();
        let rsa_encryption = [
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00,
        ];
        let mut info = vec![0x02, 0x01, 0x00];
        info.extend_from_slice(&rsa_encryption);
        info.extend(tlv(0x04, &pkcs1));
        let der = tlv(0x30, &info);

        let encoded = STANDARD.encode(der);
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        pem
    }
}

// ---- authorized_user ------------------------------------------------------

#[tokio::test]
async fn the_authorized_user_refresh_form() {
    let server = MockServer::start().await;
    mount_user_token(&server, REFRESH_TOKEN, "user-token").await;

    let provider = routed(user_provider(&authorized_user()), &server);
    assert_eq!(provider.token().await.unwrap().token, "user-token");

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method.as_str(), "POST");
    let form = form(&requests[0].body);
    assert_eq!(
        form.len(),
        4,
        "exactly the four refresh fields, no scope: {form:?}"
    );
    assert_eq!(form["grant_type"], "refresh_token");
    assert_eq!(form["client_id"], "test-client.apps.googleusercontent.com");
    assert_eq!(form["client_secret"], CLIENT_SECRET);
    assert_eq!(form["refresh_token"], REFRESH_TOKEN);
}

/// google-auth ignores a user credential's `token_uri`; so does this. A
/// file that names its own endpoint does not get the secrets sent there.
#[tokio::test]
async fn an_authorized_user_files_token_uri_is_never_contacted() {
    let hostile = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(token_body("stolen", json!(3600)))
        .expect(0)
        .mount(&hostile)
        .await;
    let google = MockServer::start().await;
    mount_user_token(&google, REFRESH_TOKEN, "from-google").await;
    let mut json = authorized_user();
    json["token_uri"] = json!(format!("{}/steal", hostile.uri()));

    for provider in [
        user_provider(&json),
        from_env(Some(&b64(&json.to_string())), &FakeEnv::new()).unwrap(),
    ] {
        let provider = routed(provider, &google);
        assert_eq!(provider.token().await.unwrap().token, "from-google");
    }
    hostile.verify().await;
}

// ---- metadata server ------------------------------------------------------

#[tokio::test]
async fn the_metadata_request_names_its_flavor_and_scopes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(METADATA_TOKEN_PATH))
        .and(header("Metadata-Flavor", "Google"))
        .and(query_param("scopes", SCOPES.join(",")))
        .respond_with(token_body("metadata-token", json!(3599)))
        .expect(1)
        .mount(&server)
        .await;

    let token = metadata_provider(&server, SCOPES).token().await.unwrap();
    assert_eq!(token.token, "metadata-token");
    assert_eq!(token.quota_project, None);

    let requests = server.received_requests().await.unwrap();
    assert!(requests[0].headers.get("authorization").is_none());
    server.verify().await;
}

#[tokio::test]
async fn a_hanging_metadata_server_times_out() {
    assert_eq!(DEFAULT_METADATA_TIMEOUT, Duration::from_secs(3));
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(METADATA_TOKEN_PATH))
        .respond_with(token_body("late", json!(3600)).set_delay(Duration::from_secs(10)))
        .mount(&server)
        .await;
    let provider = TokenProvider::metadata_server(http(), SCOPES).with_options(
        TokenOptions::default()
            .metadata_base_url(server.uri())
            .metadata_timeout(Duration::from_millis(200)),
    );

    let started = Instant::now();
    let error = provider
        .token()
        .await
        .expect_err("the server never answers in time");

    assert!(
        started.elapsed() < Duration::from_secs(3),
        "bounded by the timeout"
    );
    match error {
        GcpAuthError::Request { reason, endpoint } => {
            assert_eq!(reason, "timed out");
            assert!(endpoint.contains(METADATA_TOKEN_PATH), "{endpoint}");
        }
        other => panic!("expected a Request error, got {other:?}"),
    }
}

/// `token_timeout` bounds the whole token-endpoint exchange (here an
/// `authorized_user` refresh), as `metadata_timeout` bounds the metadata
/// request above.
#[tokio::test]
async fn a_hanging_token_endpoint_times_out_at_the_token_timeout() {
    assert_eq!(DEFAULT_TOKEN_TIMEOUT, Duration::from_secs(10));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(USER_TOKEN_PATH))
        .respond_with(token_body("late", json!(3600)).set_delay(Duration::from_secs(10)))
        .mount(&server)
        .await;
    let provider = user_provider(&authorized_user()).with_options(
        TokenOptions::default()
            .default_token_uri(format!("{}{USER_TOKEN_PATH}", server.uri()))
            .token_timeout(Duration::from_millis(200)),
    );

    let started = Instant::now();
    let error = provider.token().await.expect_err("never answers in time");

    assert!(started.elapsed() < Duration::from_secs(3), "bounded");
    match error {
        GcpAuthError::Request { reason, endpoint } => {
            assert_eq!(reason, "timed out");
            assert!(endpoint.contains(USER_TOKEN_PATH), "{endpoint}");
        }
        other => panic!("expected Request, got {other:?}"),
    }
}

/// An error status whose body stalls is still cut off at `token_timeout`,
/// but reports that status, not `Request { "timed out" }`: the error body is
/// read only to find an OAuth code, and an unreadable one has none.
#[tokio::test]
async fn a_token_error_whose_body_stalls_is_its_status_at_the_token_timeout() {
    let raw = RawServer::start(|_, _| {
        RawReply::Stall(
            b"HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{\"error\":\"invalid_gr"
                .to_vec(),
        )
    })
    .await;
    let provider = user_provider(&authorized_user()).with_options(
        TokenOptions::default()
            .default_token_uri(format!("{}{USER_TOKEN_PATH}", raw.base_url))
            .token_timeout(Duration::from_millis(300)),
    );

    let started = Instant::now();
    let error = provider.token().await.expect_err("a 400");
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_millis(300),
        "the body was waited on: {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(3), "bounded: {elapsed:?}");
    match error {
        GcpAuthError::Status { status, detail, .. } => {
            assert_eq!((status, detail.as_str()), (400, ""));
        }
        other => panic!("expected Status, got {other:?}"),
    }
    assert_eq!(raw.requests().len(), 1);
}

// ---- the cache ------------------------------------------------------------

/// `invalidate`'s exported shape, pinned: a synchronous method on a shared
/// provider, taking the rejected token by reference and saying whether it
/// evicted. Callable with no runtime at all.
#[test]
fn invalidate_is_a_synchronous_eviction_by_token() {
    let invalidate: fn(&TokenProvider, &AccessToken) -> bool = TokenProvider::invalidate;
    let provider = TokenProvider::metadata_server(http(), SCOPES);
    let never_issued = AccessToken {
        token: "never-issued".into(),
        quota_project: None,
    };
    assert!(!invalidate(&provider, &never_issued), "nothing cached");
}

/// Through the public API: an evicted token is refreshed on the next call,
/// and a clone shares the eviction (one cache).
#[tokio::test]
async fn an_invalidated_token_is_refreshed_on_the_next_call() {
    let server = token_server(bearers(&["t1", "t2"])).await;
    let provider = exact_provider(&server);
    let clone = provider.clone();
    let first = provider.token().await.unwrap();
    assert_eq!(first.token, "t1");

    assert!(clone.invalidate(&first), "evicted through a clone");
    assert!(!provider.invalidate(&first), "and gone for the original");
    assert_eq!(provider.token().await.unwrap().token, "t2");
    assert_eq!(clone.token().await.unwrap().token, "t2");
    assert_eq!(request_count(&server).await, 2);
}

/// A metadata server that answers `response`, expecting `requests` calls.
async fn lifetime_server(response: ResponseTemplate, requests: u64) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(METADATA_TOKEN_PATH))
        .respond_with(response)
        .expect(requests)
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn a_token_is_reused_until_the_refresh_margin() {
    assert_eq!(REFRESH_MARGIN, Duration::from_secs(60));
    // 65 s of life is five seconds outside the margin: served from memory.
    // 60 s is inside it: every call refreshes. An absent expires_in is the
    // 300 s fallback: cached.
    for (name, response, requests) in [
        ("3600", token_body("token", json!(3600)), 1),
        ("65", token_body("token", json!(65)), 1),
        ("absent", token_body_without_expiry("token"), 1),
        ("60", token_body("token", json!(60)), 3),
        ("1", token_body("token", json!(1)), 3),
    ] {
        let server = lifetime_server(response, requests).await;
        let provider = metadata_provider(&server, SCOPES);
        for _ in 0..3 {
            assert_eq!(provider.token().await.unwrap().token, "token", "{name}");
        }
        server.verify().await;
    }
}

#[tokio::test]
async fn clones_share_one_cache() {
    let server = lifetime_server(token_body("token", json!(3600)), 1).await;
    let provider = metadata_provider(&server, SCOPES);
    let clone = provider.clone();
    provider.token().await.unwrap();
    clone.token().await.unwrap();
    server.verify().await;
}

#[tokio::test]
async fn an_unusable_lifetime_is_an_error_and_never_cached() {
    // `null` is not "absent": only a missing field gets the fallback.
    for expires_in in [
        json!(null),
        json!(0),
        json!(-30),
        json!("soon"),
        json!(12.5),
        json!({"s": 1}),
    ] {
        let server = lifetime_server(token_body("token", expires_in.clone()), 2).await;
        let provider = metadata_provider(&server, SCOPES);
        for _ in 0..2 {
            match provider.token().await {
                Err(GcpAuthError::InvalidResponse { reason, .. }) => {
                    assert!(reason.contains("expires_in"), "{expires_in}: {reason}")
                }
                other => panic!("{expires_in}: expected InvalidResponse, got {other:?}"),
            }
        }
        server.verify().await;
    }
}

#[tokio::test]
async fn a_refresh_failure_is_not_cached() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(METADATA_TOKEN_PATH))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(METADATA_TOKEN_PATH))
        .respond_with(token_body("second-try", json!(3600)))
        .expect(1)
        .mount(&server)
        .await;
    let provider = metadata_provider(&server, SCOPES);

    assert!(matches!(
        provider.token().await,
        Err(GcpAuthError::Status { status: 503, .. })
    ));
    assert_eq!(provider.token().await.unwrap().token, "second-try");
    assert_eq!(
        provider.token().await.unwrap().token,
        "second-try",
        "now cached"
    );
    server.verify().await;
}

// ---- bounded reads --------------------------------------------------------

#[tokio::test]
async fn a_token_response_over_64_kib_is_refused() {
    assert_eq!(MAX_TOKEN_RESPONSE, 64 * 1024);
    let padded = |len: usize| {
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "token",
            "expires_in": 3600,
            "padding": "x".repeat(len),
        }))
    };
    let server = lifetime_server(padded(MAX_TOKEN_RESPONSE), 1).await;
    match metadata_provider(&server, SCOPES).token().await {
        Err(GcpAuthError::InvalidResponse { reason, .. }) => {
            assert!(reason.contains("64 KiB"), "{reason}")
        }
        other => panic!("expected InvalidResponse, got {other:?}"),
    }

    // Just under the cap is fine.
    let server = lifetime_server(padded(MAX_TOKEN_RESPONSE - 100), 1).await;
    assert_eq!(
        metadata_provider(&server, SCOPES)
            .token()
            .await
            .unwrap()
            .token,
        "token"
    );
}

#[tokio::test]
async fn an_error_body_is_read_no_further_than_16_kib() {
    let error_body = |padding: usize| {
        ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "padding": "x".repeat(padding),
        }))
    };
    // Small: the code survives. Past the cap: the body is not read, so
    // nothing of it survives and only the status is reported.
    for (padding, detail) in [(100, "invalid_grant"), (17 * 1024, "")] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(error_body(padding))
            .mount(&server)
            .await;
        match routed(user_provider(&authorized_user()), &server)
            .token()
            .await
        {
            Err(GcpAuthError::Status {
                status: 400,
                detail: got,
                ..
            }) => assert_eq!(got, detail, "padding {padding}"),
            other => panic!("expected Status, got {other:?}"),
        }
    }
}

// ---- quota project --------------------------------------------------------

/// Where `authorize` sends a request, and what arrives.
async fn authorized_headers(token: &AccessToken) -> (Option<String>, Option<String>) {
    let api = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&api)
        .await;
    token
        .authorize(http().get(format!("{}/api", api.uri())))
        .send()
        .await
        .unwrap();
    let requests = api.received_requests().await.unwrap();
    let header = |name: &str| {
        requests[0]
            .headers
            .get(name)
            .map(|value| value.to_str().unwrap().to_owned())
    };
    (header("authorization"), header("x-goog-user-project"))
}

#[tokio::test]
async fn the_file_quota_project_is_sent() {
    let server = MockServer::start().await;
    mount_user_token(&server, REFRESH_TOKEN, "user-token").await;
    let mut json = authorized_user();
    json["quota_project_id"] = json!("file-project");
    let env = FakeEnv::new()
        .var(GOOGLE_APPLICATION_CREDENTIALS, KEY_FILE)
        .file(KEY_FILE, json.to_string());

    let provider = routed(from_env(None, &env).unwrap(), &server);
    assert_eq!(provider.quota_project(), Some("file-project"));
    let token = provider.token().await.unwrap();

    assert_eq!(
        authorized_headers(&token).await,
        (
            Some("Bearer user-token".into()),
            Some("file-project".into())
        )
    );
}

#[tokio::test]
async fn the_env_var_overrides_the_file_quota_project() {
    let server = MockServer::start().await;
    mount_user_token(&server, REFRESH_TOKEN, "user-token").await;
    let mut json = authorized_user();
    json["quota_project_id"] = json!("file-project");
    for (env, explicit) in [
        (
            FakeEnv::new()
                .var(GOOGLE_APPLICATION_CREDENTIALS, KEY_FILE)
                .file(KEY_FILE, json.to_string()),
            None,
        ),
        (FakeEnv::new(), Some(b64(&json.to_string()))),
    ] {
        let env = env.var(GOOGLE_CLOUD_QUOTA_PROJECT, "env-project");
        let provider = routed(from_env(explicit.as_deref(), &env).unwrap(), &server);
        let token = provider.token().await.unwrap();
        assert_eq!(
            authorized_headers(&token).await,
            (Some("Bearer user-token".into()), Some("env-project".into()))
        );
    }
}

/// As google-auth's `_apply_quota_project_id` does for compute credentials,
/// the env var applies to metadata-server tokens; without it they carry none.
#[tokio::test]
async fn metadata_tokens_take_the_env_quota_project_only() {
    let server = MockServer::start().await;
    mount_metadata_token(&server, "metadata-token").await;
    for (env, expected) in [
        (
            FakeEnv::new().var(GOOGLE_CLOUD_QUOTA_PROJECT, "env-project"),
            Some("env-project"),
        ),
        (FakeEnv::new().var(GOOGLE_CLOUD_QUOTA_PROJECT, ""), None),
        (FakeEnv::new(), None),
    ] {
        let provider = routed(from_env(None, &env).unwrap(), &server);
        assert_eq!(provider.source(), CredentialSource::MetadataServer);
        assert_eq!(provider.quota_project(), expected);
        let token = provider.token().await.unwrap();
        assert_eq!(
            authorized_headers(&token).await,
            (
                Some("Bearer metadata-token".into()),
                expected.map(str::to_owned)
            )
        );
    }
}

// ---- redaction ------------------------------------------------------------

/// A transport error is a fixed category. reqwest nests a refused redirect's
/// target URL (query and all) inside the error it returns — `https_only`
/// refusing `http` does, and so does a consumer's redirect policy, used here
/// to build that error deterministically — and none of it may come out.
#[tokio::test]
async fn a_refused_redirect_never_leaks_its_target() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", "http://attacker.example/steal?token=CANARY"),
        )
        .mount(&server)
        .await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let refusal = format!("refusing {}", attempt.url());
            attempt.error(refusal)
        }))
        .build()
        .unwrap();
    let provider = TokenProvider::from_authorized_user_json(
        client,
        SCOPES,
        authorized_user().to_string().as_bytes(),
    )
    .unwrap()
    .with_options(
        TokenOptions::default().default_token_uri(format!("{}/token?key=CANARY", server.uri())),
    );

    let error = provider.token().await.unwrap_err();
    match &error {
        GcpAuthError::Request { reason, .. } => assert_eq!(reason, "redirect refused"),
        other => panic!("expected Request, got {other:?}"),
    }
    let rendered = format!("{error} | {error:?}");
    assert!(!rendered.contains("CANARY"), "{rendered}");
    assert!(!rendered.contains("attacker"), "{rendered}");
}

const CANARIES: &[&str] = &[CLIENT_SECRET, REFRESH_TOKEN, ACCESS_TOKEN, "CANARY"];

fn assert_clean(what: &str, rendered: &str) {
    for canary in CANARIES {
        assert!(
            !rendered.contains(canary),
            "{what} leaks {canary}: {rendered}"
        );
    }
}

fn assert_error_clean(what: &str, error: &GcpAuthError) {
    assert_clean(what, &format!("{error} | {error:?} | {error:#?}"));
}

#[tokio::test]
async fn no_secret_reaches_an_error_or_a_debug() {
    let server = MockServer::start().await;
    // A failing token endpoint that echoes everything it was sent into the
    // free-text field, and then some.
    Mock::given(method("POST"))
        .and(path("/rejecting"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": format!("Bad Request for {REFRESH_TOKEN} CANARY-DESCRIPTION"),
            "refresh_token": REFRESH_TOKEN,
            "client_secret": CLIENT_SECRET,
            "access_token": ACCESS_TOKEN,
        })))
        .mount(&server)
        .await;
    // One whose `error` is not a plain code.
    Mock::given(method("POST"))
        .and(path("/hostile-code"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": format!("invalid {REFRESH_TOKEN}"),
        })))
        .mount(&server)
        .await;
    // A 2xx whose token is unusable.
    Mock::given(method("POST"))
        .and(path("/unusable"))
        .respond_with(token_body(ACCESS_TOKEN, json!("never")))
        .mount(&server)
        .await;
    // A 2xx that is not JSON at all.
    Mock::given(method("POST"))
        .and(path("/garbage"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("token={ACCESS_TOKEN}")))
        .mount(&server)
        .await;
    // A working one, so a cached token exists for the Debug check.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(token_body(ACCESS_TOKEN, json!(3600)))
        .mount(&server)
        .await;

    let user_at = |route: &str| {
        user_provider(&authorized_user()).with_options(
            TokenOptions::default().default_token_uri(format!("{}{route}", server.uri())),
        )
    };

    let rejected = user_at("/rejecting").token().await.unwrap_err();
    assert!(matches!(rejected, GcpAuthError::Status { status: 400, .. }));
    assert_error_clean("a rejected refresh", &rejected);
    assert!(
        rejected
            .to_string()
            .ends_with("answered HTTP 400: invalid_grant"),
        "only the code survives: {rejected}"
    );

    let hostile = user_at("/hostile-code").token().await.unwrap_err();
    assert_error_clean("a hostile error code", &hostile);
    assert!(
        hostile.to_string().ends_with("answered HTTP 400"),
        "{hostile}"
    );

    let unusable = user_at("/unusable").token().await.unwrap_err();
    assert!(matches!(unusable, GcpAuthError::InvalidResponse { .. }));
    assert_error_clean("an unusable token response", &unusable);

    let garbage = user_at("/garbage").token().await.unwrap_err();
    assert!(matches!(garbage, GcpAuthError::InvalidResponse { .. }));
    assert_error_clean("a non-JSON token response", &garbage);

    // A token URI whose query and userinfo carry a credential, unreachable.
    let unreachable = user_provider(&authorized_user())
        .with_options(
            TokenOptions::default()
                .default_token_uri("http://user:CANARY@127.0.0.1:1/token?key=CANARY"),
        )
        .token()
        .await
        .unwrap_err();
    assert!(matches!(unreachable, GcpAuthError::Request { .. }));
    assert_error_clean("an unreachable token endpoint", &unreachable);

    // Credentials that fail to parse, with secrets inside.
    let truncated = format!(r#"{{"type":"authorized_user","refresh_token":"{REFRESH_TOKEN}""#);
    let mistyped = json!({
        "type": "authorized_user",
        "client_id": "x",
        "client_secret": {"nested": CLIENT_SECRET},
        "refresh_token": REFRESH_TOKEN,
    })
    .to_string();
    let wrong_scalar = format!(
        r#"{{"type":"authorized_user","client_id":"x","client_secret":"s","refresh_token":["{REFRESH_TOKEN}"]}}"#
    );
    for (name, explicit) in [
        ("truncated JSON", b64(&truncated)),
        ("a mistyped secret", b64(&mistyped)),
        ("a secret of the wrong type", b64(&wrong_scalar)),
        ("bad base64 around a secret", format!("{REFRESH_TOKEN}!!")),
    ] {
        let error = from_env(Some(&explicit), &FakeEnv::new()).unwrap_err();
        assert!(
            matches!(error, GcpAuthError::InvalidCredentials { .. }),
            "{name}: {error:?}"
        );
        assert_error_clean(name, &error);
    }

    // A provider holding a cached token prints none of it, nor its options'
    // credentialed URLs.
    let working = user_at("/token");
    assert_eq!(working.token().await.unwrap().token, ACCESS_TOKEN);
    assert_clean("a provider's Debug", &format!("{working:?} {working:#?}"));
    let token = working.token().await.unwrap();
    assert_clean("an AccessToken's Debug", &format!("{token:?} {token:#?}"));
    let options = TokenOptions::default()
        .default_token_uri("https://user:CANARY@oauth.test/token?key=CANARY")
        .metadata_base_url("http://CANARY@metadata.test/?CANARY");
    assert_clean("TokenOptions' Debug", &format!("{options:?} {options:#?}"));
}
