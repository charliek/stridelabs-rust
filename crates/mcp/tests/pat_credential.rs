//! `SlauthPatCredential` against a wiremock slauth: every outcome of the
//! validation, the ceiling, and the cache's fail-through rules with an
//! in-memory `PatCache` that can be told to fail, hang or hold garbage. Then
//! the credential end to end, behind the auth layer, over a socket.

mod support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{CallToolResult, ServerCapabilities, ServerConfig};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler};
use serde_json::json;
use stridelabs_auth::{PatValidator, SLAUTH_PAT_PREFIX};
use stridelabs_mcp::{
    pat_cache_key, AuthMethod, CachedPat, CredentialVerifier, McpAuthLayer, PatCache,
    PatCacheError, PatCacheFuture, Principal, SlauthPatCredential, ToolCall, VerifyError,
    AUTH_LOG_TARGET, PAT_CACHE_TIMEOUT, PAT_CACHE_TTL,
};
use support::*;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const IDENTITY: &str = "6f1c1b7e-2d4f-4c55-9a51-0d7e2b1f3a10";

fn pat(fill: char) -> String {
    format!("{SLAUTH_PAT_PREFIX}{}", fill.to_string().repeat(43))
}

/// slauth's validate endpoint: one token per answer.
async fn slauth() -> MockServer {
    let server = MockServer::start().await;
    let answer = |token: &str, response: ResponseTemplate| {
        Mock::given(method("POST"))
            .and(path("/api/v1/pat/validate"))
            .and(header("authorization", format!("Bearer {token}").as_str()))
            .respond_with(response)
    };
    for (fill, response) in [
        (
            'g',
            ResponseTemplate::new(200)
                .set_body_json(json!({"valid": true, "identity_id": IDENTITY, "reason": null})),
        ),
        (
            'r',
            ResponseTemplate::new(200)
                .set_body_json(json!({"valid": false, "identity_id": null, "reason": "revoked"})),
        ),
        ('u', ResponseTemplate::new(401)),
        ('d', ResponseTemplate::new(500)),
        (
            's',
            ResponseTemplate::new(200)
                .set_body_json(json!({"valid": true, "identity_id": IDENTITY}))
                .set_delay(Duration::from_secs(5)),
        ),
    ] {
        answer(&pat(fill), response).mount(&server).await;
    }
    server
}

fn validator(slauth: &MockServer) -> PatValidator {
    PatValidator::new(
        format!("{}/api/v1/pat/validate", slauth.uri()),
        reqwest::Client::new(),
    )
    .with_timeout(Duration::from_millis(300))
}

fn credential(slauth: &MockServer) -> SlauthPatCredential {
    SlauthPatCredential::new(validator(slauth), ["notes:read", "notes:write"])
}

async fn validations(slauth: &MockServer) -> usize {
    slauth.received_requests().await.expect("recording").len()
}

fn granted(principal: &Principal) -> Vec<&str> {
    principal.scopes.iter().map(String::as_str).collect()
}

// --- an in-memory cache with failure switches ---------------------------------

/// Where the cache tests' clock starts (Unix seconds).
const NOW: u64 = 1_760_000_000;

#[derive(Clone, Default)]
struct TestCache(Arc<CacheState>);

/// An in-memory `PatCache` that behaves like Redis where it matters here: an
/// entry is dropped `ttl` after it was stored (by the test's clock), and the
/// switches make it fail, hang, hold garbage, or run a write late.
#[derive(Default)]
struct CacheState {
    /// The test's clock, which the credential under test reads too.
    now: Arc<AtomicU64>,
    /// Entries and when the store drops them (its housekeeping TTL).
    entries: Mutex<HashMap<String, (CachedPat, u64)>>,
    gets: AtomicUsize,
    sets: Mutex<Vec<(String, CachedPat, Duration)>>,
    fail_get: AtomicBool,
    fail_set: AtomicBool,
    hang_get: AtomicBool,
    hang_set: AtomicBool,
    /// `get` finds a value that is not an entry.
    malformed: AtomicBool,
    /// `set` never answers, but its write lands when `land` is notified:
    /// a `SET` the server runs after the client gave up on it.
    late_set: AtomicBool,
    land: tokio::sync::Notify,
}

impl TestCache {
    fn new() -> TestCache {
        let cache = TestCache::default();
        cache.set_now(NOW);
        cache
    }

    fn with(switch: impl FnOnce(&CacheState) -> &AtomicBool) -> TestCache {
        let cache = TestCache::new();
        switch(&cache.0).store(true, Ordering::SeqCst);
        cache
    }

    fn set_now(&self, now: u64) {
        self.0.now.store(now, Ordering::SeqCst);
    }

    /// The test clock, for `SlauthPatCredential::with_clock`.
    fn clock(
        &self,
    ) -> impl Fn() -> u64 + Send + Sync + std::panic::UnwindSafe + std::panic::RefUnwindSafe {
        let now = Arc::clone(&self.0.now);
        move || now.load(Ordering::SeqCst)
    }

    /// Plant `entry` as if a write had stored it now, for `ttl_secs`.
    fn put(&self, key: &str, entry: CachedPat, ttl_secs: u64) {
        let until = self.0.now.load(Ordering::SeqCst) + ttl_secs;
        self.0
            .entries
            .lock()
            .unwrap()
            .insert(key.to_owned(), (entry, until));
    }

    fn stored(&self, key: &str) -> Option<CachedPat> {
        self.0
            .entries
            .lock()
            .unwrap()
            .get(key)
            .map(|(entry, _)| *entry)
    }

    fn gets(&self) -> usize {
        self.0.gets.load(Ordering::SeqCst)
    }

    fn sets(&self) -> Vec<(String, CachedPat, Duration)> {
        self.0.sets.lock().unwrap().clone()
    }
}

impl PatCache for TestCache {
    fn get<'a>(&'a self, key: &'a str) -> PatCacheFuture<'a, Option<CachedPat>> {
        Box::pin(async move {
            let state = &self.0;
            state.gets.fetch_add(1, Ordering::SeqCst);
            if state.hang_get.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if state.fail_get.load(Ordering::SeqCst) {
                return Err(PatCacheError::new("connection refused"));
            }
            if state.malformed.load(Ordering::SeqCst) {
                return Err(PatCacheError::new("the cached value is malformed"));
            }
            let now = state.now.load(Ordering::SeqCst);
            Ok(state
                .entries
                .lock()
                .unwrap()
                .get(key)
                .filter(|(_, until)| now < *until)
                .map(|(entry, _)| *entry))
        })
    }

    fn set<'a>(&'a self, key: &'a str, entry: CachedPat, ttl: Duration) -> PatCacheFuture<'a, ()> {
        Box::pin(async move {
            let state = &self.0;
            state
                .sets
                .lock()
                .unwrap()
                .push((key.to_owned(), entry, ttl));
            if state.late_set.load(Ordering::SeqCst) {
                let (cache, key) = (self.clone(), key.to_owned());
                tokio::spawn(async move {
                    cache.0.land.notified().await;
                    cache.put(&key, entry, ttl.as_secs());
                });
                std::future::pending::<()>().await;
            }
            if state.hang_set.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if state.fail_set.load(Ordering::SeqCst) {
                return Err(PatCacheError::new("connection reset"));
            }
            self.put(key, entry, ttl.as_secs());
            Ok(())
        })
    }
}

/// A credential with `cache`, on the cache's clock.
fn cached(slauth: &MockServer, cache: &TestCache) -> SlauthPatCredential {
    credential(slauth)
        .with_cache(cache.clone())
        .with_clock(cache.clock())
}

// --- the validation's outcomes ----------------------------------------------------

#[tokio::test]
async fn a_valid_pat_is_its_identity_with_exactly_the_ceiling() {
    let slauth = slauth().await;

    let principal = credential(&slauth).verify(&pat('g')).await.expect("valid");

    assert_eq!(principal.subject, IDENTITY);
    assert_eq!(granted(&principal), ["notes:read", "notes:write"]);
    assert_eq!(principal.auth_method, AuthMethod::Token);
    assert_eq!(principal.email, None);
    assert_eq!(principal.name, None);
    assert_eq!(principal.client_id, None);
}

#[tokio::test]
async fn every_validation_outcome_maps_to_invalid_or_unavailable() {
    let slauth = slauth().await;
    let credential = credential(&slauth);
    let refused = SlauthPatCredential::new(
        PatValidator::new(
            "http://127.0.0.1:1/api/v1/pat/validate",
            reqwest::Client::new(),
        ),
        ["notes:read"],
    );

    for (case, outcome, expected) in [
        (
            "unknown (401)",
            credential.verify(&pat('u')).await,
            VerifyError::invalid("Invalid or expired PAT"),
        ),
        (
            "revoked",
            credential.verify(&pat('r')).await,
            VerifyError::invalid("revoked"),
        ),
        (
            "malformed",
            credential.verify("slp_live_short").await,
            VerifyError::invalid("Invalid PAT format"),
        ),
        (
            "slauth erroring",
            credential.verify(&pat('d')).await,
            VerifyError::unavailable("Authentication service error"),
        ),
        (
            "slauth slow",
            credential.verify(&pat('s')).await,
            VerifyError::unavailable("Authentication service timeout"),
        ),
        (
            "slauth unreachable",
            refused.verify(&pat('g')).await,
            VerifyError::unavailable("Authentication service unavailable"),
        ),
    ] {
        assert_eq!(outcome, Err(expected), "{case}");
    }
    // The malformed token never reached slauth: four of the five calls did.
    assert_eq!(validations(&slauth).await, 4);
}

#[tokio::test]
async fn behind_the_verifier_a_pat_is_a_token_principal() {
    let slauth = slauth().await;
    let jwks = good_jwks().await;
    let verifier = verifier(&jwks).with_credential(SLAUTH_PAT_PREFIX, credential(&slauth));

    let principal = verifier.verify(&pat('g')).await.expect("valid");

    assert_eq!(principal.subject, IDENTITY);
    assert_eq!(principal.auth_method, AuthMethod::Token);
    assert!(
        jwks.received_requests()
            .await
            .expect("recording")
            .is_empty(),
        "a PAT never reaches the JWT path"
    );
}

// --- the cache --------------------------------------------------------------------

#[tokio::test]
async fn a_hit_skips_slauth_and_the_key_is_the_digest() {
    let slauth = slauth().await;
    let cache = TestCache::new();
    let credential = cached(&slauth, &cache);

    for _ in 0..3 {
        let principal = credential.verify(&pat('g')).await.expect("valid");
        assert_eq!(principal.subject, IDENTITY);
        assert_eq!(granted(&principal), ["notes:read", "notes:write"]);
    }

    assert_eq!(
        validations(&slauth).await,
        1,
        "one validation for three calls"
    );
    assert_eq!(cache.gets(), 3);
    let identity = Uuid::parse_str(IDENTITY).unwrap();
    // One write, at the miss, stamped with the validation's start plus the
    // TTL: a hit writes nothing, so it cannot extend anything.
    assert_eq!(
        cache.sets(),
        [(
            pat_cache_key(&pat('g')),
            CachedPat::new(identity, NOW + 120),
            PAT_CACHE_TTL
        )]
    );
    let (key, _, _) = &cache.sets()[0];
    assert_eq!(key.len(), 32);
    assert!(key
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert!(!key.contains("ggg"), "never the token");
}

#[tokio::test]
async fn the_ttl_can_be_shortened() {
    let slauth = slauth().await;
    let cache = TestCache::new();
    let credential = cached(&slauth, &cache).with_cache_ttl(Duration::from_secs(30));

    credential.verify(&pat('g')).await.expect("valid");

    assert_eq!(cache.sets()[0].1.expires_at, NOW + 30);
    assert_eq!(cache.sets()[0].2, Duration::from_secs(30));
}

#[tokio::test]
async fn an_entry_past_its_expiry_is_a_miss_and_is_replaced() {
    let identity = Uuid::parse_str(IDENTITY).unwrap();
    let key = pat_cache_key(&pat('g'));
    for (expires_at, hit) in [(NOW - 1, false), (NOW, false), (NOW + 1, true)] {
        let slauth = slauth().await;
        let cache = TestCache::new();
        // The store still holds it (its own TTL has a minute to run).
        cache.put(&key, CachedPat::new(identity, expires_at), 60);

        cached(&slauth, &cache)
            .verify(&pat('g'))
            .await
            .expect("valid");

        let validated = usize::from(!hit);
        assert_eq!(validations(&slauth).await, validated, "expiry {expires_at}");
        if hit {
            assert!(cache.sets().is_empty(), "a hit writes nothing");
        } else {
            assert_eq!(
                cache.stored(&key),
                Some(CachedPat::new(identity, NOW + 120)),
                "replaced by a fresh validation's entry"
            );
        }
    }
}

#[tokio::test]
async fn a_late_write_cannot_extend_validity_past_validation_plus_ttl() {
    // A SET that Redis runs after the credential abandoned it (the 250 ms
    // bound): it lands 100 s later, so the store keeps it until NOW + 220.
    // Validity must still end at the validation's NOW + 120.
    let slauth = slauth().await;
    let cache = TestCache::with(|state| &state.late_set);
    let credential = cached(&slauth, &cache);
    let key = pat_cache_key(&pat('g'));

    credential
        .verify(&pat('g'))
        .await
        .expect("validated at NOW");
    cache.set_now(NOW + 100);
    cache.0.land.notify_one();
    for _ in 0..1_000 {
        if cache.stored(&key).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(cache.stored(&key).is_some(), "the late write landed");

    cache.set_now(NOW + 119);
    credential.verify(&pat('g')).await.expect("a hit");
    assert_eq!(validations(&slauth).await, 1, "still valid at NOW + 119");

    cache.set_now(NOW + 150);
    credential.verify(&pat('g')).await.expect("validated again");
    assert_eq!(
        validations(&slauth).await,
        2,
        "the store still holds it at NOW + 150, but it expired at NOW + 120"
    );
}

#[tokio::test]
async fn rejections_and_outages_are_never_cached() {
    let slauth = slauth().await;
    let cache = TestCache::new();
    let credential = cached(&slauth, &cache);

    for token in [pat('r'), pat('r'), pat('d'), pat('d')] {
        assert!(credential.verify(&token).await.is_err());
    }

    assert_eq!(validations(&slauth).await, 4);
    assert!(cache.sets().is_empty());
}

#[tokio::test]
async fn the_ceiling_is_applied_fresh_on_a_hit() {
    let slauth = slauth().await;
    let cache = TestCache::new();
    let narrow = SlauthPatCredential::new(validator(&slauth), ["notes:read"])
        .with_cache(cache.clone())
        .with_clock(cache.clock());
    let wide = cached(&slauth, &cache);

    let first = narrow.verify(&pat('g')).await.expect("valid");
    let second = wide.verify(&pat('g')).await.expect("valid");

    assert_eq!(granted(&first), ["notes:read"]);
    assert_eq!(
        granted(&second),
        ["notes:read", "notes:write"],
        "the cache holds no scopes"
    );
    assert_eq!(validations(&slauth).await, 1, "the second was a hit");
}

#[tokio::test]
async fn a_malformed_cached_value_falls_through_to_slauth() {
    let slauth = slauth().await;
    let cache = TestCache::with(|state| &state.malformed);
    let credential = cached(&slauth, &cache);

    let principal = credential.verify(&pat('g')).await.expect("valid");

    assert_eq!(principal.subject, IDENTITY);
    assert_eq!(validations(&slauth).await, 1);
    assert!(
        cache.sets().is_empty(),
        "nothing is written after a failed read"
    );
}

#[tokio::test]
async fn a_cache_read_failure_falls_through_to_each_slauth_outcome() {
    let (capture, _guard) = Capture::install();
    let slauth = slauth().await;
    let cache = TestCache::with(|state| &state.fail_get);
    let credential = cached(&slauth, &cache);

    assert_eq!(
        credential.verify(&pat('g')).await.map(|p| p.subject),
        Ok(IDENTITY.to_owned())
    );
    assert_eq!(
        credential.verify(&pat('r')).await,
        Err(VerifyError::invalid("revoked"))
    );
    assert_eq!(
        credential.verify(&pat('d')).await,
        Err(VerifyError::unavailable("Authentication service error"))
    );

    assert_eq!(validations(&slauth).await, 3);
    assert!(cache.sets().is_empty());
    let warnings = capture.take(AUTH_LOG_TARGET);
    assert_eq!(warnings.len(), 3, "{warnings:?}");
    assert!(warnings
        .iter()
        .all(|line| line.level == tracing::Level::WARN));
    assert!(
        !capture.everything().contains("ggg"),
        "no token in the logs"
    );
}

#[tokio::test]
async fn a_cache_write_failure_still_succeeds_without_a_second_validation() {
    let (capture, _guard) = Capture::install();
    let slauth = slauth().await;
    let cache = TestCache::with(|state| &state.fail_set);
    let credential = cached(&slauth, &cache);

    let principal = credential.verify(&pat('g')).await.expect("valid");

    assert_eq!(principal.subject, IDENTITY);
    assert_eq!(validations(&slauth).await, 1);
    assert_eq!(cache.sets().len(), 1, "the write was tried once");
    assert_eq!(capture.take(AUTH_LOG_TARGET).len(), 1);
}

#[tokio::test]
async fn a_cache_that_hangs_is_skipped_after_the_bound() {
    for switch in [
        (|state: &CacheState| &state.hang_get) as fn(&CacheState) -> &AtomicBool,
        |state: &CacheState| &state.hang_set,
    ] {
        let slauth = slauth().await;
        let cache = TestCache::with(switch);
        let credential = cached(&slauth, &cache);

        // The cache never answers, so an unbounded operation would never
        // return: the 10 s outer limit only has to tell "bounded" from
        // "hangs", and leaves a stalled scheduler plenty of room.
        let started = Instant::now();
        let principal = tokio::time::timeout(Duration::from_secs(10), credential.verify(&pat('g')))
            .await
            .expect("the cache operation is bounded")
            .expect("valid");
        let took = started.elapsed();

        assert_eq!(principal.subject, IDENTITY);
        assert_eq!(validations(&slauth).await, 1);
        assert!(took >= PAT_CACHE_TIMEOUT, "waited the bound out: {took:?}");
    }
}

#[tokio::test]
async fn a_token_not_shaped_like_a_pat_skips_the_cache() {
    let slauth = slauth().await;
    let cache = TestCache::new();
    let credential = cached(&slauth, &cache);

    assert_eq!(
        credential.verify("slp_live_short").await,
        Err(VerifyError::invalid("Invalid PAT format"))
    );
    assert_eq!(cache.gets(), 0);
    assert_eq!(validations(&slauth).await, 0);
}

// --- end to end -------------------------------------------------------------------

struct Whoami {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl Whoami {
    #[tool(description = "Who is calling.")]
    async fn whoami(&self, ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
        ToolCall::new("whoami")
            .scopes(["notes:read"])
            .run(&ctx, |principal| async move {
                Ok(CallToolResult::structured(json!({
                    "sub": principal.subject,
                    "scopes": principal.scopes,
                    "auth_method": principal.auth_method.as_str(),
                })))
            })
            .await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Whoami {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

#[tokio::test]
async fn pats_work_end_to_end_and_refusals_keep_their_status() {
    let (capture, _guard) = Capture::install();
    let slauth = slauth().await;
    let jwks = good_jwks().await;
    let verifier = verifier(&jwks).with_credential(
        SLAUTH_PAT_PREFIX,
        credential(&slauth).with_cache(TestCache::new()),
    );
    let base = serve(stridelabs_mcp::router(
        McpAuthLayer::new(verifier),
        stridelabs_mcp::server_config(&resource(), ["127.0.0.1"]),
        || {
            Ok(Whoami {
                tool_router: Whoami::tool_router(),
            })
        },
    ))
    .await;

    let answer = call(&base, &format!("Bearer {}", pat('g')), "whoami").await;
    assert_eq!(
        answer["result"]["structuredContent"],
        json!({"sub": IDENTITY, "scopes": ["notes:read", "notes:write"], "auth_method": "token"})
    );
    let line = capture.one_audit_line();
    assert_eq!(line.field("auth_method"), Some("token"));
    assert_eq!(line.field("sub"), Some(IDENTITY));

    for (fill, status) in [
        ('r', StatusCode::UNAUTHORIZED),
        ('u', StatusCode::UNAUTHORIZED),
        ('d', StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let response = post(
            &base,
            &[("authorization", &format!("Bearer {}", pat(fill)))],
            &tools_call("whoami", json!({})),
        )
        .await;
        assert_eq!(response.status(), status, "{fill}");
        let error = if status == StatusCode::UNAUTHORIZED {
            "invalid_token"
        } else {
            "temporarily_unavailable"
        };
        let body: serde_json::Value = response.json().await.expect("a JSON body");
        assert_eq!(body["error"], error, "{fill}");
    }
}
