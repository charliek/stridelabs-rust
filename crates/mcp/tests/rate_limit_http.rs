//! `ToolCall::rate_limit` end to end over a socket: where the check sits
//! (after the scopes, before the body, inside the deadline, the
//! cancellation and the panic capture), what a refusal looks like on the
//! wire and in the audit line, and that the limiter's state is shared by the
//! per-request handler instances of a stateless server.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler};
use serde_json::json;
use stridelabs_mcp::{
    LimitFuture, McpAuthLayer, MemoryLimiter, RateClass, RateLimit, RateLimiter, ToolCall,
    AUDIT_TARGET,
};
use support::*;
use tokio::sync::Notify;

const GENERATE: RateClass = RateClass("generate");
const FREE: RateClass = RateClass("free");
/// Limited per minute and per day.
const DAILY: RateClass = RateClass("daily");

/// 1_000_040 is 20 s into its minute: every refusal here says "Retry in 40".
/// It is also 49 640 s into its UTC day: 36 760 s are left, 10 h 13 min
/// rounded up.
const NOW: u64 = 1_000_040;

// --- limiters ---------------------------------------------------------------

/// A `MemoryLimiter` that records every check it is asked for.
struct Recording {
    inner: MemoryLimiter,
    checks: Mutex<Vec<(String, RateClass)>>,
}

impl RateLimiter for Recording {
    fn check<'a>(&'a self, subject: &'a str, class: RateClass) -> LimitFuture<'a> {
        self.checks
            .lock()
            .unwrap()
            .push((subject.to_owned(), class));
        self.inner.check(subject, class)
    }
}

impl Recording {
    fn checks(&self) -> Vec<(String, RateClass)> {
        self.checks.lock().unwrap().clone()
    }
}

/// Never answers; says when it has been entered.
struct Hanging {
    entered: Arc<Notify>,
}

impl RateLimiter for Hanging {
    fn check<'a>(&'a self, _: &'a str, _: RateClass) -> LimitFuture<'a> {
        Box::pin(async move {
            self.entered.notify_one();
            std::future::pending().await
        })
    }
}

/// Panics, either while building its future (`at_call`) or while it is
/// polled.
struct Panicking {
    at_call: bool,
}

impl RateLimiter for Panicking {
    fn check<'a>(&'a self, _: &'a str, _: RateClass) -> LimitFuture<'a> {
        if self.at_call && std::hint::black_box(true) {
            panic!("a limiter bug, before its future exists");
        }
        Box::pin(async {
            if std::hint::black_box(true) {
                panic!("a limiter bug, while polled");
            }
            Ok(())
        })
    }
}

// --- the server under test --------------------------------------------------

#[derive(Clone)]
struct Limiters {
    recording: Arc<Recording>,
    hanging: Arc<Hanging>,
    panic_at_call: Arc<Panicking>,
    panic_when_polled: Arc<Panicking>,
    /// Bodies that ran, so a test can tell a refusal stopped one.
    bodies: Arc<AtomicUsize>,
}

impl Limiters {
    fn new() -> Limiters {
        Limiters {
            recording: Arc::new(Recording {
                inner: MemoryLimiter::from_limits([
                    RateLimit::per_minute(RateClass::READ, 3),
                    RateLimit::per_minute(RateClass::WRITE, 1),
                    RateLimit::per_minute(GENERATE, 2),
                    RateLimit::per_minute(FREE, 0),
                    RateLimit::per_minute(DAILY, 5),
                    RateLimit::per_day(DAILY, 2),
                ])
                .with_clock(|| NOW),
                checks: Mutex::default(),
            }),
            hanging: Arc::new(Hanging {
                entered: Arc::new(Notify::new()),
            }),
            panic_at_call: Arc::new(Panicking { at_call: true }),
            panic_when_polled: Arc::new(Panicking { at_call: false }),
            bodies: Arc::default(),
        }
    }
}

struct Limited {
    limiters: Limiters,
    tool_router: ToolRouter<Self>,
}

impl Limited {
    async fn run(
        &self,
        ctx: &RequestContext<RoleServer>,
        call: ToolCall,
    ) -> Result<CallToolResult, ErrorData> {
        let bodies = Arc::clone(&self.limiters.bodies);
        call.run(ctx, |principal| async move {
            bodies.fetch_add(1, Ordering::SeqCst);
            Ok(CallToolResult::success(vec![ContentBlock::text(
                principal.subject,
            )]))
        })
        .await
    }

    fn recording(&self) -> Arc<dyn RateLimiter> {
        self.limiters.recording.clone()
    }
}

#[tool_router]
impl Limited {
    #[tool(description = "Read class, no scope.")]
    async fn read(&self, ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
        let call = ToolCall::new("read").rate_limit(self.recording(), RateClass::READ);
        self.run(&ctx, call).await
    }

    #[tool(description = "Write class, needs notes:write.")]
    async fn write(&self, ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
        let call = ToolCall::new("write")
            .scopes(["notes:write"])
            .rate_limit(self.recording(), RateClass::WRITE);
        self.run(&ctx, call).await
    }

    #[tool(description = "Generate class.")]
    async fn generate(&self, ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
        let call = ToolCall::new("generate").rate_limit(self.recording(), GENERATE);
        self.run(&ctx, call).await
    }

    #[tool(description = "Daily class: 5 a minute, 2 a day.")]
    async fn daily(&self, ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
        let call = ToolCall::new("daily").rate_limit(self.recording(), DAILY);
        self.run(&ctx, call).await
    }

    #[tool(description = "A class whose limit is 0.")]
    async fn free(&self, ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
        let call = ToolCall::new("free").rate_limit(self.recording(), FREE);
        self.run(&ctx, call).await
    }

    #[tool(description = "Its limiter never answers; 50 ms deadline.")]
    async fn hang_timeout(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let call = ToolCall::new("hang_timeout")
            .timeout(Duration::from_millis(50))
            .rate_limit(self.limiters.hanging.clone(), RateClass::READ);
        self.run(&ctx, call).await
    }

    #[tool(description = "Its limiter never answers; the default deadline.")]
    async fn hang(&self, ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
        let call = ToolCall::new("hang").rate_limit(self.limiters.hanging.clone(), RateClass::READ);
        self.run(&ctx, call).await
    }

    #[tool(description = "Its limiter panics building its future.")]
    async fn panic_at_call(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let call = ToolCall::new("panic_at_call")
            .rate_limit(self.limiters.panic_at_call.clone(), RateClass::READ);
        self.run(&ctx, call).await
    }

    #[tool(description = "Its limiter panics when polled.")]
    async fn panic_when_polled(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let call = ToolCall::new("panic_when_polled")
            .rate_limit(self.limiters.panic_when_polled.clone(), RateClass::READ);
        self.run(&ctx, call).await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Limited {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

struct App {
    base: String,
    limiters: Limiters,
    /// Handler instances the factory built: one per request.
    instances: Arc<AtomicUsize>,
    /// Cancels every in-flight request: the server config's own token
    /// (named through a closure, so the test needs no tokio-util).
    cancel_all: Box<dyn Fn()>,
    _jwks: wiremock::MockServer,
}

async fn start() -> App {
    let jwks = good_jwks().await;
    let limiters = Limiters::new();
    let instances = Arc::new(AtomicUsize::new(0));
    let config = stridelabs_mcp::server_config(&resource(), ["127.0.0.1"]);
    let token = config.cancellation_token.clone();

    let (shared, counted) = (limiters.clone(), Arc::clone(&instances));
    let app = axum::Router::new().merge(stridelabs_mcp::router(
        McpAuthLayer::new(verifier(&jwks)),
        config,
        move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(Limited {
                limiters: shared.clone(),
                tool_router: Limited::tool_router(),
            })
        },
    ));

    App {
        base: serve(app).await,
        limiters,
        instances,
        cancel_all: Box::new(move || token.cancel()),
        _jwks: jwks,
    }
}

const RETRY: &str = "Retry in 40 seconds.";

fn refusal(class: &str, limit: u32) -> String {
    format!("Rate limit exceeded for {class} operations ({limit} per minute). {RETRY}")
}

// --- the tests --------------------------------------------------------------

#[tokio::test]
async fn an_exceeded_limit_is_pythons_text_and_a_ratelimited_audit_line() {
    let (capture, _guard) = Capture::install();
    let app = start().await;
    let alice = token("alice", "notes:read notes:write");

    let first = call(&app.base, &alice, "write").await;
    assert!(!is_error(&first), "{first}");
    assert_eq!(text_of(&first), "alice");
    capture.one_audit_line();

    let refused = call(&app.base, &alice, "write").await;
    assert!(is_error(&refused), "{refused}");
    assert!(
        refused.get("error").is_none(),
        "a tool error, not a protocol error"
    );
    assert_eq!(text_of(&refused), refusal("write", 1));

    let line = capture.one_audit_line();
    assert_eq!(line.level, tracing::Level::INFO);
    for (field, value) in [
        ("tool", "write"),
        ("outcome", "ratelimited"),
        ("error_class", "RateLimited"),
        ("required_scopes", "notes:write"),
        ("sub", "alice"),
        ("auth_method", "jwt"),
        ("scopes", "notes:read notes:write"),
        ("client_id", "connector-1"),
    ] {
        assert_eq!(line.field(field), Some(value), "{field}");
    }
    assert!(line.fields.contains_key("duration_ms"));
    assert_eq!(
        app.limiters.bodies.load(Ordering::SeqCst),
        1,
        "the refused body never ran"
    );
}

/// A day refusal reaches the model and the audit line exactly as a minute
/// one does, with the day's text.
#[tokio::test]
async fn an_exceeded_day_limit_is_the_day_text_and_a_ratelimited_audit_line() {
    let (capture, _guard) = Capture::install();
    let app = start().await;
    let alice = token("alice", "notes:read");

    for _ in 0..2 {
        assert!(!is_error(&call(&app.base, &alice, "daily").await));
        capture.one_audit_line();
    }
    let refused = call(&app.base, &alice, "daily").await;

    assert!(is_error(&refused), "{refused}");
    let text = "Rate limit exceeded for daily operations (2 per day). \
                The limit resets at 00:00 UTC, in 10 h 13 min.";
    assert_eq!(text_of(&refused), text);
    let line = capture.one_audit_line();
    assert_eq!(line.field("outcome"), Some("ratelimited"));
    assert_eq!(line.field("error_class"), Some("RateLimited"));
    assert_eq!(
        app.limiters.bodies.load(Ordering::SeqCst),
        2,
        "the refused body never ran"
    );
}

#[tokio::test]
async fn the_limit_is_checked_after_the_scopes_so_a_denial_consumes_nothing() {
    let (capture, _guard) = Capture::install();
    let app = start().await;
    let reader = token("alice", "notes:read");
    let writer = token("alice", "notes:read notes:write");

    for _ in 0..3 {
        let denied = call(&app.base, &reader, "write").await;
        assert!(text_of(&denied).starts_with("Missing required scope(s): notes:write."));
        let line = capture.one_audit_line();
        assert_eq!(line.field("outcome"), Some("denied"));
        assert_eq!(line.field("error_class"), Some("ScopeError"));
    }
    assert!(
        app.limiters.recording.checks().is_empty(),
        "no denial reached the limiter"
    );

    // The same subject's first permitted call is the window's first hit.
    let allowed = call(&app.base, &writer, "write").await;
    assert!(!is_error(&allowed), "{allowed}");
    let refused = call(&app.base, &writer, "write").await;
    assert_eq!(text_of(&refused), refusal("write", 1));
    assert_eq!(
        app.limiters.recording.checks(),
        [
            ("alice".to_owned(), RateClass::WRITE),
            ("alice".to_owned(), RateClass::WRITE)
        ]
    );
}

#[tokio::test]
async fn limits_are_per_user_and_per_class() {
    let app = start().await;
    let alice = token("alice", "notes:read notes:write");
    let bob = token("bob", "notes:read notes:write");

    for _ in 0..2 {
        assert!(!is_error(&call(&app.base, &alice, "generate").await));
    }
    assert_eq!(
        text_of(&call(&app.base, &alice, "generate").await),
        refusal("generate", 2)
    );

    // Alice's other classes, and Bob's generate, are untouched.
    assert!(!is_error(&call(&app.base, &alice, "read").await));
    assert!(!is_error(&call(&app.base, &alice, "write").await));
    for _ in 0..2 {
        assert!(!is_error(&call(&app.base, &bob, "generate").await));
    }
    assert_eq!(
        text_of(&call(&app.base, &bob, "generate").await),
        refusal("generate", 2)
    );
}

#[tokio::test]
async fn a_zero_limit_is_off() {
    let app = start().await;
    let alice = token("alice", "notes:read");

    for _ in 0..20 {
        let answer = call(&app.base, &alice, "free").await;
        assert!(!is_error(&answer), "{answer}");
    }
    assert_eq!(app.limiters.bodies.load(Ordering::SeqCst), 20);
}

#[tokio::test]
async fn the_limiter_state_is_shared_by_the_per_request_handler_instances() {
    let app = start().await;
    let alice = token("alice", "notes:read");

    for _ in 0..3 {
        assert!(!is_error(&call(&app.base, &alice, "read").await));
    }
    assert_eq!(
        text_of(&call(&app.base, &alice, "read").await),
        refusal("read", 3)
    );

    // Stateless: every request built its own handler, and the count carried
    // across all four because they share one limiter.
    assert!(app.instances.load(Ordering::SeqCst) >= 4);
}

#[tokio::test]
async fn a_hanging_limiter_is_bounded_by_the_tool_deadline() {
    let (capture, _guard) = Capture::install();
    let app = start().await;

    let answer = call(&app.base, &token("alice", "notes:read"), "hang_timeout").await;

    assert!(is_error(&answer), "{answer}");
    assert_eq!(
        text_of(&answer),
        "The operation timed out. Please try again."
    );
    let line = capture.one_audit_line();
    assert_eq!(line.field("outcome"), Some("timeout"));
    assert_eq!(line.field("error_class"), Some("Timeout"));
    assert_eq!(line.field("sub"), Some("alice"));
    assert_eq!(line.level, tracing::Level::WARN);
    assert_eq!(app.limiters.bodies.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_panicking_limiter_is_an_internal_error() {
    let (capture, _guard) = Capture::install();
    let app = start().await;
    let alice = token("alice", "notes:read");

    for tool in ["panic_at_call", "panic_when_polled"] {
        let answer = call(&app.base, &alice, tool).await;

        assert!(is_error(&answer), "{tool}: {answer}");
        assert_eq!(text_of(&answer), "Internal server error.", "{tool}");
        let line = capture.one_audit_line();
        assert_eq!(line.field("outcome"), Some("internal"), "{tool}");
        assert_eq!(line.field("error_class"), Some("panic"), "{tool}");
        assert_eq!(line.field("sub"), Some("alice"), "{tool}");
        assert_eq!(line.level, tracing::Level::ERROR, "{tool}");
    }
    assert!(
        !capture.everything().contains("a limiter bug"),
        "the payload is not logged"
    );
}

#[tokio::test]
async fn a_request_cancelled_while_the_limiter_waits_is_cancelled() {
    let (capture, _guard) = Capture::install();
    let app = start().await;
    let entered = Arc::clone(&app.limiters.hanging.entered);

    let base = app.base.clone();
    let mut request = tokio::spawn(async move {
        post(
            &base,
            &[("authorization", &token("alice", "notes:read"))],
            &tools_call("hang", json!({})),
        )
        .await
        .status()
    });
    // The cancellation must land while the limiter is waiting: so the
    // limiter is entered first, and the request has not finished.
    tokio::select! {
        () = entered.notified() => {}
        answered = &mut request => {
            panic!("the request finished before the limiter was entered: {answered:?}")
        }
        () = tokio::time::sleep(Duration::from_secs(10)) => {
            panic!("the limiter was never entered")
        }
    }
    assert!(
        !request.is_finished(),
        "the request is still waiting on the limiter"
    );
    (app.cancel_all)();
    // rmcp answers the abandoned request itself; the tool's answer is moot.
    let _ = request.await.expect("the client task");

    capture.wait_for(AUDIT_TARGET).await;
    let line = capture.one_audit_line();
    assert_eq!(line.field("outcome"), Some("cancelled"));
    assert_eq!(line.field("error_class"), Some("Cancelled"));
    assert_eq!(line.field("sub"), Some("alice"));
    assert_eq!(line.level, tracing::Level::WARN);
    assert_eq!(app.limiters.bodies.load(Ordering::SeqCst), 0);
}
