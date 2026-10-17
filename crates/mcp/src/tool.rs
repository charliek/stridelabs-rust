//! The tool boundary: one wrapper around every tool body.
//!
//! The Rust twin of stridelabs-python's `make_tool_decorator`, minus what is
//! app policy there too (database sessions, user provisioning): a tool calls
//! [`ToolCall::run`] and gets, around its body,
//!
//! 1. the authenticated [`Principal`] (missing → a safe "Not authenticated."
//!    error, outcome `denied`);
//! 2. its declared scopes enforced against it ([`Principal::check_scopes`];
//!    a [`ScopeError`](crate::ScopeError)'s actionable message is the
//!    result, outcome `denied`) — authorization, where the HTTP boundary did
//!    authentication;
//! 3. optionally, its rate limit ([`ToolCall::rate_limit`]): checked after
//!    the scopes, so a refused call consumes nothing, and before the body; a
//!    refusal's [`RateLimited`] text is the result, outcome `ratelimited`;
//! 4. a timeout (outcome `timeout`, a safe "try again" message), and the
//!    request's cancellation (outcome `cancelled`) — both covering the rate
//!    limit check as well as the body;
//! 5. error translation: [`ToolError::user`] and [`ToolError::denied`]
//!    messages are shown to the model, while anything internal — a
//!    [`ToolError::internal`], or a panic (in the body or the limiter) —
//!    becomes "Internal server error.";
//! 6. exactly **one** structured audit line per run (see [`AUDIT_TARGET`]).
//!
//! "Per run" is per call that reaches the tool's code: rmcp answers some
//! `tools/call` requests before any tool runs — arguments that do not
//! deserialize into the tool's parameters (an `isError` result) and an
//! unknown tool name (a JSON-RPC error) — and those write no audit line. The
//! HTTP boundary has already authenticated them; an app that wants them in
//! its audit trail logs them in its `ServerHandler::call_tool`.
//!
//! Failures are **tool results with `isError: true`**, never JSON-RPC
//! protocol errors: the model sees the message and can correct course (MCP
//! reserves protocol errors for requests that could not be routed at all).
//!
//! # Why internal errors are logged by type only
//!
//! An unexpected error's message can carry user-supplied data — a value that
//! failed to parse, a row's contents in a constraint violation, a path. The
//! client gets a fixed message, and the audit line records only the error's
//! *type* (`error_class`); the error itself is dropped unread. An app that
//! wants more server-side detail logs it before converting, knowing what its
//! own errors contain. (A panic is caught after the process's panic hook
//! has run, and the default hook prints the panic's message to stderr; a
//! service that cares installs its own hook.)

use std::borrow::Cow;
use std::fmt;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::FutureExt;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer};
use serde::Serialize;

use crate::limits::{RateClass, RateLimited, RateLimiter};
use crate::principal::Principal;
use crate::server::principal;

/// The `tracing` target of the one audit line per [`ToolCall::run`].
///
/// Fields: `tool`, `outcome` (`ok`, `error`, `denied`, `ratelimited`,
/// `timeout`, `internal`, `cancelled`), `duration_ms`, `required_scopes`, and
/// when the caller is known `sub`, `auth_method`, `scopes` and `client_id`;
/// plus `error_class` for anything but `ok`. Never a token, an email or a
/// name. `INFO`, except `timeout` and `cancelled` (`WARN`) and `internal`
/// (`ERROR`), so an alert can key on severity.
pub const AUDIT_TARGET: &str = "stridelabs.mcp.tool";

/// The per-call timeout when a tool sets none.
pub const DEFAULT_TOOL_TIMEOUT: Duration = Duration::from_secs(30);

const NOT_AUTHENTICATED: &str = "Not authenticated.";
const TIMED_OUT: &str = "The operation timed out. Please try again.";
const INTERNAL: &str = "Internal server error.";
const CANCELLED: &str = "The request was cancelled.";

/// How a tool call ended, as the audit line records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// The body returned a successful result.
    Ok,
    /// A [`ToolError::user`], or a result the body itself marked `isError`.
    Error,
    /// Not authenticated, a missing scope, or a [`ToolError::denied`].
    Denied,
    /// The body (or its rate limit check) outran the call's timeout.
    Timeout,
    /// A [`ToolError::internal`] or a panic.
    Internal,
    /// The request was cancelled, or the call was dropped, before the body
    /// finished.
    Cancelled,
    /// The call's [rate limiter](ToolCall::rate_limit) refused it. (Last, so
    /// the variants v0.6.0 had keep their discriminants.)
    RateLimited,
}

impl Outcome {
    /// The audit line's `outcome` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Error => "error",
            Outcome::Denied => "denied",
            Outcome::Timeout => "timeout",
            Outcome::Internal => "internal",
            Outcome::Cancelled => "cancelled",
            Outcome::RateLimited => "ratelimited",
        }
    }
}

/// A failed tool body.
///
/// [`ToolError::user`] and [`ToolError::denied`] carry a message **shown to
/// the model** — write it for that reader, and never put anything in it the
/// caller should not see. [`ToolError::internal`] carries nothing but the
/// error's type name: the caller sees "Internal server error.", and the
/// error itself is dropped unread (see the [module docs](self)).
///
/// No blanket `From` for every error type, deliberately: it would make `?`
/// turn an app error that *has* a user-safe message (a "not found") into an
/// opaque internal one, and it would forbid the app's own conversion. Write
/// `impl From<MyError> for ToolError` (user-safe variants to
/// [`ToolError::user`], the rest to [`ToolError::internal`]) and `?` works;
/// for a third-party error, `.map_err(ToolError::internal)?`.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToolError {
    /// A message for the model (outcome `error`): bad input, nothing found.
    User(String),
    /// A refusal for the model (outcome `denied`): a quota, a permission the
    /// app checks itself.
    Denied(String),
    /// Anything else (outcome `internal`). `error_class` is the original
    /// error's type name, for the audit line.
    Internal {
        /// The type name of the error this replaced.
        error_class: &'static str,
    },
}

impl ToolError {
    /// An error whose `message` the model sees.
    pub fn user(message: impl Into<String>) -> ToolError {
        ToolError::User(message.into())
    }

    /// A refusal whose `message` the model sees.
    pub fn denied(message: impl Into<String>) -> ToolError {
        ToolError::Denied(message.into())
    }

    /// An internal failure. `error` is dropped unread; only its type name
    /// survives, as the audit line's `error_class`.
    pub fn internal<E>(_error: E) -> ToolError {
        ToolError::Internal {
            error_class: std::any::type_name::<E>(),
        }
    }
}

/// Never renders an internal error's original (it is not kept); a user or
/// denied message is shown, as the client would see it.
impl std::fmt::Debug for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolError::User(message) => f.debug_tuple("User").field(message).finish(),
            ToolError::Denied(message) => f.debug_tuple("Denied").field(message).finish(),
            ToolError::Internal { error_class } => f
                .debug_struct("Internal")
                .field("error_class", error_class)
                .finish(),
        }
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolError::User(message) | ToolError::Denied(message) => f.write_str(message),
            ToolError::Internal { .. } => f.write_str(INTERNAL),
        }
    }
}

impl std::error::Error for ToolError {}

/// One tool call, configured: its name (for the audit line), its required
/// scopes, its rate limit and its timeout.
///
/// ```no_run
/// use rmcp::model::{CallToolResult, ContentBlock};
/// use rmcp::service::RequestContext;
/// use rmcp::{ErrorData, RoleServer};
/// use stridelabs_mcp::{ToolCall, ToolError};
///
/// async fn list_parcels(ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
///     ToolCall::new("list_parcels")
///         .scopes(["parcel:read"])
///         .run(&ctx, |principal| async move {
///             if principal.subject.is_empty() {
///                 return Err(ToolError::user("No such parcel."));
///             }
///             Ok(CallToolResult::success(vec![ContentBlock::text("[]")]))
///         })
///         .await
/// }
/// ```
///
/// `Clone`, `Send`, `Sync`, `UnwindSafe` and `RefUnwindSafe`; its `Debug`
/// names the rate class, never the limiter.
#[derive(Clone)]
pub struct ToolCall {
    name: Cow<'static, str>,
    scopes: Vec<String>,
    timeout: Duration,
    rate_limit: Option<(Arc<dyn RateLimiter>, RateClass)>,
}

impl ToolCall {
    /// A call to the tool `name`, requiring no scope, with the
    /// [`DEFAULT_TOOL_TIMEOUT`].
    pub fn new(name: impl Into<Cow<'static, str>>) -> ToolCall {
        ToolCall {
            name: name.into(),
            scopes: Vec::new(),
            timeout: DEFAULT_TOOL_TIMEOUT,
            rate_limit: None,
        }
    }

    /// Require the caller's credential to grant every one of `scopes`.
    pub fn scopes<I, S>(mut self, scopes: I) -> ToolCall
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Replace the timeout.
    pub fn timeout(mut self, timeout: Duration) -> ToolCall {
        self.timeout = timeout;
        self
    }

    /// Count each run against `limiter` in `class`, keyed by the caller's
    /// subject; a refusal is the call's result (outcome `ratelimited`).
    ///
    /// The check runs after the scope check — a call refused for its scopes
    /// consumes nothing — and inside the call's timeout, cancellation and
    /// panic capture, together with the body: a limiter that hangs ends the
    /// call as `timeout`, one that panics as `internal`. Share one limiter
    /// across the service's handler instances (they are built per request).
    pub fn rate_limit(mut self, limiter: Arc<dyn RateLimiter>, class: RateClass) -> ToolCall {
        self.rate_limit = Some((limiter, class));
        self
    }

    /// Run `body` for the caller of `ctx`'s request, inside the boundary
    /// (see the [module docs](self)).
    ///
    /// `body` gets the [`Principal`] (owned) and may borrow from its
    /// surroundings (the handler's `&self`). Always `Ok`: every failure is a
    /// tool result with `isError: true`, so the signature is the one a
    /// `#[tool]` method returns.
    pub async fn run<F, Fut>(
        self,
        ctx: &RequestContext<RoleServer>,
        body: F,
    ) -> Result<CallToolResult, ErrorData>
    where
        F: FnOnce(Principal) -> Fut,
        Fut: Future<Output = Result<CallToolResult, ToolError>>,
    {
        let mut audit = Audit::start(&self);

        let Some(principal) = principal(ctx).cloned() else {
            return Ok(audit.refuse(Outcome::Denied, "NotAuthenticated", NOT_AUTHENTICATED));
        };
        audit.caller(&principal);
        if let Err(missing) = principal.check_scopes(&self.scopes) {
            return Ok(audit.refuse(Outcome::Denied, "ScopeError", &missing.to_string()));
        }

        // The rate limit check and the body run as one guarded future, so the
        // timeout, the cancellation and the panic capture cover both. Called
        // inside it, so a panic while *building* either future is caught
        // too, not only one while polling it.
        let rate_limit = self.rate_limit;
        let guarded = AssertUnwindSafe(async move {
            if let Some((limiter, class)) = &rate_limit {
                limiter.check(&principal.subject, *class).await?;
            }
            Ok::<_, RateLimited>(body(principal).await)
        })
        .catch_unwind();
        let finished = tokio::select! {
            // Cancellation first: a cancelled request's result is unwanted.
            biased;
            () = ctx.ct.cancelled() => None,
            finished = tokio::time::timeout(self.timeout, guarded) => Some(finished),
        };

        Ok(match finished {
            None => audit.refuse(Outcome::Cancelled, "Cancelled", CANCELLED),
            Some(Err(_elapsed)) => audit.refuse(Outcome::Timeout, "Timeout", TIMED_OUT),
            Some(Ok(Err(_panic))) => audit.refuse(Outcome::Internal, "panic", INTERNAL),
            Some(Ok(Ok(Err(limited)))) => {
                audit.refuse(Outcome::RateLimited, "RateLimited", &limited.to_string())
            }
            Some(Ok(Ok(Ok(Ok(result))))) => {
                if result.is_error == Some(true) {
                    audit.finish(Outcome::Error, Some("CallToolResult"));
                } else {
                    audit.finish(Outcome::Ok, None);
                }
                result
            }
            Some(Ok(Ok(Ok(Err(error))))) => {
                let (outcome, class) = match &error {
                    ToolError::User(_) => (Outcome::Error, "ToolError::User"),
                    ToolError::Denied(_) => (Outcome::Denied, "ToolError::Denied"),
                    ToolError::Internal { error_class } => (Outcome::Internal, *error_class),
                };
                audit.refuse(outcome, class, &error.to_string())
            }
        })
    }
}

impl fmt::Debug for ToolCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolCall")
            .field("name", &self.name)
            .field("scopes", &self.scopes)
            .field("timeout", &self.timeout)
            .field(
                "rate_class",
                &self.rate_limit.as_ref().map(|(_, class)| *class),
            )
            .finish_non_exhaustive()
    }
}

/// The audit line for one call, written exactly once: by `finish`, or — if
/// the call's future is dropped first (the client went away) — on drop.
struct Audit {
    tool: Cow<'static, str>,
    required_scopes: String,
    started: Instant,
    caller: Option<Caller>,
    written: bool,
}

struct Caller {
    sub: String,
    auth_method: &'static str,
    scopes: String,
    client_id: Option<String>,
}

impl Audit {
    fn start(call: &ToolCall) -> Audit {
        Audit {
            tool: call.name.clone(),
            required_scopes: call.scopes.join(" "),
            started: Instant::now(),
            caller: None,
            written: false,
        }
    }

    /// Never the email or name: the subject is enough to find the user.
    fn caller(&mut self, principal: &Principal) {
        self.caller = Some(Caller {
            sub: principal.subject.clone(),
            auth_method: principal.auth_method.as_str(),
            scopes: principal
                .scopes
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(" "),
            client_id: principal.client_id.clone(),
        });
    }

    /// Write the line for a failure and build the `isError` result.
    fn refuse(&mut self, outcome: Outcome, error_class: &str, message: &str) -> CallToolResult {
        self.finish(outcome, Some(error_class));
        CallToolResult::error(vec![ContentBlock::text(message)])
    }

    fn finish(&mut self, outcome: Outcome, error_class: Option<&str>) {
        if std::mem::replace(&mut self.written, true) {
            return;
        }
        // Hundredths of a millisecond, as the Python boundary logs it.
        let duration_ms = (self.started.elapsed().as_secs_f64() * 100_000.0).round() / 100.0;
        let caller = self.caller.as_ref();
        macro_rules! audit_line {
            ($level:expr) => {
                tracing::event!(
                    target: AUDIT_TARGET,
                    $level,
                    tool = %self.tool,
                    outcome = outcome.as_str(),
                    duration_ms,
                    required_scopes = %self.required_scopes,
                    sub = caller.map(|c| c.sub.as_str()),
                    auth_method = caller.map(|c| c.auth_method),
                    scopes = caller.map(|c| c.scopes.as_str()),
                    client_id = caller.and_then(|c| c.client_id.as_deref()),
                    error_class,
                    "mcp_tool_call"
                )
            };
        }
        match outcome {
            Outcome::Internal => audit_line!(tracing::Level::ERROR),
            Outcome::Timeout | Outcome::Cancelled => audit_line!(tracing::Level::WARN),
            _ => audit_line!(tracing::Level::INFO),
        }
    }
}

impl Drop for Audit {
    fn drop(&mut self) {
        // The call's future was dropped before it finished: still one line.
        self.finish(Outcome::Cancelled, Some("Dropped"));
    }
}

/// The page size a list tool uses when the caller gives none.
pub const DEFAULT_LIMIT: i64 = 20;
/// The largest page size a list tool returns.
pub const MAX_LIMIT: i64 = 50;

/// A requested page size, clamped into `[1, MAX_LIMIT]` (absent →
/// [`DEFAULT_LIMIT`]).
///
/// Clamping rather than rejecting keeps an over-eager model's oversized (or
/// zero, or negative) `limit` from erroring: it just gets the nearest page.
/// `i64` in, so a negative value deserializes instead of failing the call,
/// and `i64` out, the type a Postgres `LIMIT` binds as.
pub fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.map_or(DEFAULT_LIMIT, |limit| limit.clamp(1, MAX_LIMIT))
}

/// A requested offset, clamped to `>= 0` (absent → `0`).
pub fn clamp_offset(offset: Option<i64>) -> i64 {
    offset.unwrap_or(0).max(0)
}

/// A list tool's response: `{items, total, has_more}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[non_exhaustive]
pub struct Page<T> {
    /// This page's items.
    pub items: Vec<T>,
    /// How many items there are in all.
    pub total: i64,
    /// Whether items remain beyond this page.
    pub has_more: bool,
}

impl<T> Page<T> {
    /// The page of `items` starting at `offset`, out of `total`.
    pub fn new(items: Vec<T>, total: i64, offset: i64) -> Page<T> {
        let shown = i64::try_from(items.len()).unwrap_or(i64::MAX);
        Page {
            has_more: offset.saturating_add(shown) < total,
            items,
            total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_clamp_into_range() {
        assert_eq!(clamp_limit(None), 20);
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(0)), 1);
        assert_eq!(clamp_limit(Some(-5)), 1);
        assert_eq!(clamp_limit(Some(51)), 50);
        assert_eq!(clamp_limit(Some(i64::MAX)), 50);
    }

    #[test]
    fn offsets_clamp_to_non_negative() {
        assert_eq!(clamp_offset(None), 0);
        assert_eq!(clamp_offset(Some(-1)), 0);
        assert_eq!(clamp_offset(Some(40)), 40);
    }

    #[test]
    fn a_page_knows_whether_more_remain() {
        assert!(Page::new(vec![1, 2], 5, 0).has_more);
        assert!(Page::new(vec![3, 4], 5, 2).has_more);
        assert!(!Page::new(vec![5], 5, 4).has_more);
        assert!(!Page::new(Vec::<i32>::new(), 0, 0).has_more);
        assert_eq!(
            serde_json::to_value(Page::new(vec!["a"], 3, 0)).expect("serializes"),
            serde_json::json!({"items": ["a"], "total": 3, "has_more": true})
        );
    }

    #[test]
    fn internal_errors_keep_their_type_and_never_their_message() {
        let error = ToolError::internal(std::io::Error::other("row 42: hunter2"));

        assert_eq!(
            error,
            ToolError::Internal {
                error_class: "std::io::error::Error"
            }
        );
        assert_eq!(error.to_string(), INTERNAL);
        assert!(!format!("{error:?}").contains("hunter2"));
    }

    #[test]
    fn user_and_denied_messages_are_shown_as_written() {
        assert_eq!(
            ToolError::user("No such parcel.").to_string(),
            "No such parcel."
        );
        assert_eq!(
            ToolError::denied("Quota reached.").to_string(),
            "Quota reached."
        );
    }

    /// The audit lines `f` writes, as `(level, outcome, error_class)`.
    fn audit_lines(f: impl FnOnce()) -> Vec<(tracing::Level, String, Option<String>)> {
        use std::sync::{Arc, Mutex};
        use tracing::field::{Field, Visit};
        use tracing_subscriber::layer::{Context, SubscriberExt};
        use tracing_subscriber::Layer;

        type Lines = Arc<Mutex<Vec<(tracing::Level, String, Option<String>)>>>;

        #[derive(Default)]
        struct Line {
            outcome: String,
            error_class: Option<String>,
        }
        impl Visit for Line {
            fn record_str(&mut self, field: &Field, value: &str) {
                match field.name() {
                    "outcome" => self.outcome = value.to_owned(),
                    "error_class" => self.error_class = Some(value.to_owned()),
                    _ => {}
                }
            }
            fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
        }
        struct Capture(Lines);
        impl<S: tracing::Subscriber> Layer<S> for Capture {
            fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
                if event.metadata().target() == AUDIT_TARGET {
                    let mut line = Line::default();
                    event.record(&mut line);
                    let level = *event.metadata().level();
                    self.0
                        .lock()
                        .unwrap()
                        .push((level, line.outcome, line.error_class));
                }
            }
        }

        let lines = Lines::default();
        let subscriber = tracing_subscriber::registry().with(Capture(lines.clone()));
        tracing::subscriber::with_default(subscriber, f);
        let lines = lines.lock().unwrap().clone();
        lines
    }

    #[test]
    fn a_call_dropped_before_it_finishes_still_writes_one_line() {
        let lines = audit_lines(|| drop(Audit::start(&ToolCall::new("slow"))));

        assert_eq!(
            lines,
            [(
                tracing::Level::WARN,
                "cancelled".to_owned(),
                Some("Dropped".to_owned())
            )]
        );
    }

    #[test]
    fn a_finished_call_writes_exactly_one_line_at_its_outcomes_level() {
        let lines = audit_lines(|| {
            let mut ok = Audit::start(&ToolCall::new("a"));
            ok.finish(Outcome::Ok, None);
            ok.finish(Outcome::Internal, Some("ignored: already written"));
            drop(ok);

            let mut internal = Audit::start(&ToolCall::new("b"));
            internal.refuse(Outcome::Internal, "panic", INTERNAL);
        });

        assert_eq!(
            lines,
            [
                (tracing::Level::INFO, "ok".to_owned(), None),
                (
                    tracing::Level::ERROR,
                    "internal".to_owned(),
                    Some("panic".to_owned())
                ),
            ]
        );
    }

    #[test]
    fn outcomes_render_for_the_audit_line() {
        let all = [
            Outcome::Ok,
            Outcome::Error,
            Outcome::Denied,
            Outcome::Timeout,
            Outcome::Internal,
            Outcome::Cancelled,
            Outcome::RateLimited,
        ];
        let names: Vec<&str> = all.iter().map(|outcome| outcome.as_str()).collect();
        assert_eq!(
            names,
            [
                "ok",
                "error",
                "denied",
                "timeout",
                "internal",
                "cancelled",
                "ratelimited"
            ]
        );
    }

    #[test]
    fn a_tool_call_keeps_its_auto_traits() {
        // Compile-time: adding the limiter must not cost `ToolCall` any of
        // the auto traits v0.6.0 gave it (they are part of its API).
        fn assert_traits<
            T: Clone
                + Send
                + Sync
                + Unpin
                + std::panic::UnwindSafe
                + std::panic::RefUnwindSafe
                + fmt::Debug
                + 'static,
        >() {
        }
        assert_traits::<ToolCall>();
    }

    #[test]
    fn debug_names_the_rate_class_never_the_limiter() {
        struct Secretive;
        impl RateLimiter for Secretive {
            fn check<'a>(&'a self, _: &'a str, _: RateClass) -> crate::LimitFuture<'a> {
                Box::pin(std::future::ready(Ok(())))
            }
        }

        let call = ToolCall::new("generate")
            .scopes(["image:generate"])
            .rate_limit(Arc::new(Secretive), RateClass("generate"));
        let debug = format!("{call:?}");

        assert!(
            debug.contains("rate_class: Some(RateClass(\"generate\"))"),
            "{debug}"
        );
        assert!(!debug.contains("Secretive"), "{debug}");
        let plain = format!("{:?}", ToolCall::new("ping"));
        assert!(plain.contains("rate_class: None"), "{plain}");
    }
}
