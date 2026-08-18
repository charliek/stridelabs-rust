//! Truthful method classification for axum routes: which methods a route
//! actually serves, and a truthful `405` for every other one.
//!
//! Carried over from a service's route-classification helpers
//! (`CLASSIFIED_METHODS`, `route_serving_over`/`refusing_unserved_over`,
//! `method_filter`), which exist because `axum::routing::MethodRouter`
//! gets two things wrong for a route that only names the methods it serves:
//!
//! | request | a plain `get()`/`post()`/… route | what a truthful route should do |
//! | --- | --- | --- |
//! | `HEAD` on a `GET`-only route | axum routes it to the `GET` handler (`200`) | `405`, unless `HEAD` is actually served |
//! | any other unserved method | `405` via `method_not_allowed_fallback`, `Allow` header lists the implicit `HEAD` too | `405`, `Allow` lists exactly the served methods |
//!
//! Both rows were confirmed against the real axum 0.8.9 in this workspace
//! while writing this module — a plain `get()`-only route really does
//! answer `HEAD` with `200`, and really does advertise `Allow: GET, HEAD`
//! on its other 405s. That's core `MethodRouter`/`method_not_allowed_
//! fallback` behavior (HEAD-to-GET routing and Allow-from-registered-
//! handlers), not something a patch release inside axum 0.8 is likely to
//! change, but it is a one-time observation rather than a standing test:
//! keeping a permanently-failing assertion against plain axum in this
//! suite would fail every CI run by design. What IS a standing test is
//! `head_and_allow_are_truthful_through_the_helper` below, which proves the
//! FIX — the same two behaviors, now correct, through
//! [`refusing_unserved_over`].
//!
//! [`refusing_unserved_over`] is the fix: given the methods a route serves
//! and the universe of methods it should be judged against, it adds a
//! refusal endpoint — [`method_filter`]-folded, so one call covers every
//! unserved method at once — that answers with a truthful `Allow`. `HEAD`
//! is claimed explicitly whenever it's in the refused set, which is what
//! keeps it from falling through to `GET`.
//!
//! # The caller-chosen universe is the API
//!
//! [`CLASSIFIED_METHODS`] is all nine methods axum's `MethodFilter` can
//! represent (`GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `CONNECT`, `OPTIONS`,
//! `TRACE`, `PATCH`) — the right universe for a route that should 405
//! *anything* it doesn't serve. But the reverse proxies in slauth, the
//! StrideLabs auth service, deliberately
//! judge against only **eight** of them: a proxy leg that has never handled
//! `CONNECT` keeps falling through to axum's own (untruthful) fallback
//! for `CONNECT` specifically, because closing that gap would be a new
//! behavior decision on a live upstream leg with no source-of-truth probe
//! to check it against — a gap kept on purpose, not an oversight. That
//! policy question belongs to the caller, not this module, which is why
//! [`refusing_unserved_over`] takes `universe` as a parameter instead of
//! hard-coding [`CLASSIFIED_METHODS`]: a literal route passes all nine, a
//! proxy route passes nine-minus-`CONNECT`, and both go through the exact
//! same fold.
//!
//! # Serving the whole universe is a no-op, not a panic
//!
//! A route that serves every method in its universe has nothing left to
//! refuse — [`refusing_unserved_over`] returns the router unchanged rather
//! than registering an endpoint for an empty method set (which
//! [`method_filter`] can't build a filter for anyway; see its doc comment
//! for why that's `None`, not a panic).
//!
//! # `OPTIONS` and CORS preflight
//!
//! Claiming `OPTIONS` in `universe` — as [`CLASSIFIED_METHODS`] does — is
//! only safe for a route that sits behind a CORS layer. A CORS preflight
//! carries `Access-Control-Request-Method` and is meant to be answered by
//! that layer **before** the request ever reaches routing; if it is, only a
//! BARE `OPTIONS` (one the browser never sends on its own) reaches this
//! module's refusal endpoint, and 405ing it is correct. A router with no
//! CORS layer in front of it has no such interception: judging the full
//! nine-method universe there means a real preflight request reaches the
//! refusal endpoint and gets 405ed, which breaks every cross-origin request
//! the route was meant to serve. Pair a `universe` that includes `OPTIONS`
//! with an outer CORS layer — this crate's own `cors` feature (`cors_layer`,
//! applied outermost, same as `tower_http::cors::CorsLayer`) is the natural
//! fit — or drop `OPTIONS` from `universe` the same way slauth's proxies
//! drop `CONNECT`. (`cors_layer` is named in a plain code span rather than
//! an intra-doc link because it's behind a feature this always-on module
//! isn't — see the crate root docs on that convention.)
//!
//! # What this module deliberately doesn't do
//!
//! No `literal_route`/slash-twin sugar, no OpenAPI wiring, no `AppState`
//! import — those are slauth's own composition on top of this seam, built
//! from a concrete state type and a trailing-slash convention that is
//! Starlette-parity policy, not a generic primitive. This module is the
//! part every service re-derives identically: fold methods, refuse the
//! complement, tell the truth in `Allow`.

use axum::response::{IntoResponse, Response};
use axum::routing::{MethodFilter, MethodRouter};
use http::header::ALLOW;
use http::{HeaderValue, Method, StatusCode};

/// All nine methods `axum::routing::MethodFilter` can represent, `CONNECT`
/// included.
///
/// This is the right universe for a literal route — Starlette 405s an
/// unserved method whatever it is, so an axum port should too. It is
/// deliberately **not** the universe every caller must use:
/// [`refusing_unserved_over`] takes its own `universe` parameter precisely
/// so a caller with a narrower policy (slauth's reverse proxies exclude
/// `CONNECT` — see the module docs) can filter this list at the one call
/// site that needs to, without a second constant that could drift from this
/// one.
pub const CLASSIFIED_METHODS: [Method; 9] = [
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::PUT,
    Method::DELETE,
    Method::CONNECT,
    Method::OPTIONS,
    Method::TRACE,
    Method::PATCH,
];

/// Fold `methods` into one [`MethodFilter`], or `None` if `methods` is
/// empty.
///
/// `MethodFilter` has no complement operation and no `empty()` — the OR
/// fold is the only way to combine several into one, and folding zero of
/// them has no identity element to fall back to. slauth's original panics
/// there (`.expect("a route classifies at least one method")`), which is
/// sound *there* because every call site is generated from a route's own
/// non-empty served-methods list — an invariant a library has no way to
/// require of its callers. Returning `None` instead pushes the "what does
/// an empty method set mean" decision to the caller, who is in a position
/// to answer it (typically: no-op, as [`refusing_unserved_over`] does).
///
/// Duplicate methods in the input are handled for free: OR-ing the same bit
/// twice is a no-op, so `[Method::GET, Method::GET]` folds to the same
/// filter as `[Method::GET]`.
///
/// A method with no `MethodFilter` representation (there is no ninth
/// `Method` beyond [`CLASSIFIED_METHODS`]'s nine that this can happen for
/// today, but a caller can still construct an extension method via
/// `Method::from_bytes`) is a programmer error, not a runtime condition:
/// `debug_assert!`s in debug and test builds, and is silently dropped from
/// the fold in release builds — the remaining, valid methods still classify
/// correctly rather than the whole route losing its method policy.
pub fn method_filter<'a>(methods: impl IntoIterator<Item = &'a Method>) -> Option<MethodFilter> {
    methods
        .into_iter()
        .filter_map(|method| match MethodFilter::try_from(method.clone()) {
            Ok(filter) => Some(filter),
            Err(_) => {
                debug_assert!(
                    false,
                    "method_filter: {method} has no MethodFilter representation \
                     (programmer error — pass only methods MethodFilter can \
                     represent, e.g. CLASSIFIED_METHODS or a subset of it); \
                     a release build (debug_assert compiled out) drops it \
                     from the fold instead of panicking"
                );
                None
            }
        })
        .reduce(MethodFilter::or)
}

/// The `Allow` header value for `served`: its methods' wire names, joined
/// with `", "`, in the order given.
///
/// `Method::as_str()` is always visible ASCII, so the `HeaderValue`
/// construction cannot fail — the `expect` is unreachable, not a validated
/// runtime condition.
fn allow_header(served: &[Method]) -> HeaderValue {
    HeaderValue::from_str(
        &served
            .iter()
            .map(Method::as_str)
            .collect::<Vec<_>>()
            .join(", "),
    )
    .expect("HTTP method names are visible ASCII")
}

/// The crate's out-of-the-box [`refusing_unserved_over`] refusal: `405
/// Method Not Allowed`, the truthful `allow` header value handed in, and an
/// empty body.
///
/// A consumer whose error convention has a body shape of its own (slauth's
/// `{"detail": "..."}`) passes its own closure to `refusing_unserved_over`
/// instead — this is the one every OTHER service gets for free by not
/// providing one.
pub fn default_refusal(allow: HeaderValue) -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [(ALLOW, allow)]).into_response()
}

/// Add a refusal endpoint to `router` for every method in `universe` that
/// `served` doesn't cover, so the resulting [`MethodRouter`] 405s anything
/// outside `served` with a truthful `Allow` header instead of falling
/// through to axum's own `method_not_allowed_fallback` (whose `Allow`
/// includes an implicit `HEAD` even when `HEAD` was never registered — see
/// the module docs).
///
/// **Transposition hazard:** `universe` and `served` are both
/// `&[Method]`-shaped — `served` literally is one, and `universe`'s `impl
/// IntoIterator<Item = &Method>` accepts a `&[Method]` directly, no
/// `.iter()` required. A call site that swaps two same-typed `&[Method]`
/// bindings compiles without error and silently classifies against the
/// wrong set (typically: refuses nothing a caller meant to refuse). Nothing
/// at the type level catches this; naming the two positions at the call
/// site (`/* universe */ ..., /* served */ ...`) is the cheapest defense —
/// see this crate's README for the pattern in a full example.
///
/// - **`universe`** is the caller-chosen method set this route is judged
///   against — [`CLASSIFIED_METHODS`] for a route that should 405 anything
///   unserved, or a caller's own narrower iterator (slauth's proxies pass
///   `CLASSIFIED_METHODS` filtered to drop `CONNECT`) for a route with a
///   deliberately narrower contract. The refused set is `universe` minus
///   `served`; a `universe` entry also present in `served` contributes
///   nothing.
/// - **`served`** is stated by the caller rather than read back off
///   `router` — axum's `MethodRouter` exposes no such accessor — so it is
///   expected to name exactly the methods `router` was actually built to
///   handle, and the two ways it can drift from that fail differently.
///   *Overstating* it (claiming a method `router` has no handler for) drops
///   that one method from the refused set, so it silently falls through to
///   axum's own `method_not_allowed_fallback` instead of this function's
///   truthful one — quietly losing the protection for that method, not a
///   crash. *Understating* it (omitting a method `router` DOES have a
///   handler for) puts that method in the refused set too, and
///   `MethodRouter::on` panics registering the refusal — `"Overlapping
///   method route"` — the instant two handlers claim the same method. The
///   second failure mode is loud specifically because it is the one that
///   would otherwise ship a route whose real handler is silently
///   unreachable behind this function's refusal.
/// - **`refusal_builder`** turns the computed `Allow` value into a full
///   response. [`default_refusal`] is the crate's own (`405`, that header,
///   empty body); a consumer with its own error body shape supplies its
///   own closure instead. Called once per refused request — `Clone` rather
///   than `Copy` because a closure that captures owned state (a shared
///   error-formatting helper, say) is a reasonable thing to hand in here.
///
/// If `served` already covers every method in `universe`, there is nothing
/// to refuse: `router` is returned unchanged (no endpoint registered, no
/// panic) rather than treating "nothing left to classify" as an error
/// condition. That is the expected shape for, say, a catch-all route that
/// legitimately serves every method in its universe.
///
/// Generic over the router's state type `S` — the same bounds
/// [`MethodRouter::on`] itself requires (`Clone + Send + Sync + 'static`,
/// which every axum `State` type needs anyway to be extractable), and
/// nothing more, so this composes under any axum service's own state.
pub fn refusing_unserved_over<'a, S, F>(
    universe: impl IntoIterator<Item = &'a Method>,
    served: &[Method],
    router: MethodRouter<S>,
    refusal_builder: F,
) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
    F: Fn(HeaderValue) -> Response + Clone + Send + Sync + 'static,
{
    let Some(refused) = method_filter(
        universe
            .into_iter()
            .filter(|method| !served.contains(method)),
    ) else {
        // Whole universe served (or an empty universe): nothing to refuse.
        return router;
    };

    let allow = allow_header(served);
    router.on(refused, move || {
        // Cloned per request rather than moved: this closure is `Fn` (axum
        // calls it once per matching request), and cloning a `HeaderValue`
        // this short is a `Bytes` refcount bump, not a string copy. Cloning
        // `refusal_builder` is the same story for whatever it captured.
        let allow = allow.clone();
        let refusal_builder = refusal_builder.clone();
        async move { refusal_builder(allow) }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use axum::body::{to_bytes, Body};
    use axum::extract::State;
    use axum::routing::{get, post, MethodRouter};
    use axum::Router;
    use http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    fn request(method: Method) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri("/x")
            .body(Body::empty())
            .unwrap()
    }

    async fn status_and_allow(router: Router, method: Method) -> (StatusCode, Option<String>) {
        let res = router.oneshot(request(method)).await.unwrap();
        let status = res.status();
        let allow = res
            .headers()
            .get(ALLOW)
            .map(|v| v.to_str().unwrap().to_string());
        (status, allow)
    }

    /// `refusing_unserved_over(CLASSIFIED_METHODS, &[GET], get(..), default_refusal)`
    /// — slauth's `route_serving` sugar (not part of this crate; the crate
    /// stops at this seam, see the module docs) without the sugar: a
    /// `GET`-only route, judged against the full nine-method universe.
    fn get_only_route() -> MethodRouter {
        refusing_unserved_over(
            CLASSIFIED_METHODS.iter(),
            &[Method::GET],
            get(|| async { "hi" }),
            default_refusal,
        )
    }

    // --- the class-killer: HEAD and Allow, proven fixed ---------------------

    /// The behavior the module-doc table promises, proven end to end: a
    /// `GET`-only route built through [`refusing_unserved_over`] answers
    /// `HEAD` truthfully (`405`, never a silent `200` from the `GET`
    /// handler) and its `Allow` on any other unserved method lists exactly
    /// what was served — the "HEAD explicitly refused when not served"
    /// class of bug this module exists to close. The same two assertions
    /// failed against a plain `get()`-only route with no helper involved;
    /// that one-time evidence lives outside this crate (the C3 gated-commit
    /// artifacts), not as a permanently-red test in this suite.
    #[tokio::test]
    async fn head_and_allow_are_truthful_through_the_helper() {
        let app = Router::new().route("/x", get_only_route());

        let (head_status, _) = status_and_allow(app.clone(), Method::HEAD).await;
        assert_eq!(
            head_status,
            StatusCode::METHOD_NOT_ALLOWED,
            "HEAD must be refused, not routed to the GET handler"
        );

        let (post_status, allow) = status_and_allow(app, Method::POST).await;
        assert_eq!(post_status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            allow.as_deref(),
            Some("GET"),
            "Allow must list exactly the served methods, not an implicit HEAD"
        );
    }

    // --- method_filter -------------------------------------------------

    #[test]
    fn empty_input_is_none_not_a_panic() {
        assert!(method_filter(std::iter::empty()).is_none());
    }

    #[test]
    fn duplicate_methods_fold_the_same_as_one() {
        let deduped = method_filter([&Method::GET]);
        let duplicated = method_filter([&Method::GET, &Method::GET, &Method::GET]);
        assert_eq!(deduped, duplicated);
    }

    #[test]
    fn folds_every_classified_method() {
        // Every entry in CLASSIFIED_METHODS has a MethodFilter representation
        // — this is what makes that assumption checkable in one place rather
        // than trusted at each of the nine call sites.
        assert!(method_filter(CLASSIFIED_METHODS.iter()).is_some());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "has no MethodFilter representation")]
    fn unsupported_method_panics_in_debug_builds() {
        let custom = Method::from_bytes(b"CUSTOM").unwrap();
        let _ = method_filter([&custom]);
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn unsupported_method_is_dropped_not_fatal_in_release_builds() {
        // `debug_assert!` compiles out in a release build (this crate's test
        // suite only reaches this arm under `cargo test --release`, since
        // the workspace's dev/test profile keeps debug-assertions on — see
        // `unsupported_method_panics_in_debug_builds` for that path). The
        // unsupported entry is silently skipped and the rest of the fold
        // still succeeds — a caller's one bad entry doesn't take down the
        // whole route's method policy.
        let custom = Method::from_bytes(b"CUSTOM").unwrap();
        let filter = method_filter([&Method::GET, &custom]);
        assert_eq!(filter, Some(MethodFilter::GET));
    }

    // --- refusing_unserved_over -----------------------------------------

    #[tokio::test]
    async fn empty_served_set_refuses_the_whole_universe() {
        let router: MethodRouter = refusing_unserved_over(
            CLASSIFIED_METHODS.iter(),
            &[],
            MethodRouter::new(),
            default_refusal,
        );
        let app = Router::new().route("/x", router);

        for method in CLASSIFIED_METHODS {
            let (status, allow) = status_and_allow(app.clone(), method.clone()).await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
            assert_eq!(
                allow.as_deref(),
                Some(""),
                "{method}: Allow must be empty, truthfully"
            );
        }
    }

    #[tokio::test]
    async fn serving_the_whole_universe_is_a_no_op_not_a_panic() {
        // Every CLASSIFIED_METHODS entry served -> nothing to refuse ->
        // the router comes back byte-for-byte what `on()` alone would have
        // built, and building it at all must not panic.
        let served = &CLASSIFIED_METHODS;
        let base: MethodRouter = on_every(served);
        let augmented = refusing_unserved_over(
            CLASSIFIED_METHODS.iter(),
            served,
            on_every(served),
            default_refusal,
        );

        let app_base = Router::new().route("/x", base);
        let app_augmented = Router::new().route("/x", augmented);

        for method in CLASSIFIED_METHODS {
            let (base_status, _) = status_and_allow(app_base.clone(), method.clone()).await;
            let (aug_status, _) = status_and_allow(app_augmented.clone(), method.clone()).await;
            assert_eq!(base_status, aug_status, "{method}");
            assert_eq!(base_status, StatusCode::OK, "{method}");
        }
    }

    /// A `MethodRouter` that answers every [`CLASSIFIED_METHODS`] entry with
    /// `200`, for the no-op test above: `refusing_unserved_over` must add
    /// nothing when `served` already covers the whole `universe`.
    fn on_every(served: &[Method]) -> MethodRouter {
        method_filter(served.iter())
            .into_iter()
            .fold(MethodRouter::new(), |router, filter| {
                router.on(filter, || async { "ok" })
            })
    }

    #[tokio::test]
    async fn allow_lists_exactly_the_served_methods_in_order() {
        let served = [Method::POST, Method::GET, Method::DELETE];
        let router: MethodRouter = refusing_unserved_over(
            CLASSIFIED_METHODS.iter(),
            &served,
            on_every(&served),
            default_refusal,
        );
        let app = Router::new().route("/x", router);

        let (_, allow) = status_and_allow(app, Method::PATCH).await;
        assert_eq!(allow.as_deref(), Some("POST, GET, DELETE"));
    }

    #[tokio::test]
    async fn custom_refusal_builder_replaces_the_default_body() {
        fn json_detail(allow: HeaderValue) -> Response {
            (
                StatusCode::METHOD_NOT_ALLOWED,
                [(ALLOW, allow)],
                axum::Json(serde_json::json!({"detail": "Method Not Allowed"})),
            )
                .into_response()
        }

        let router: MethodRouter = refusing_unserved_over(
            CLASSIFIED_METHODS.iter(),
            &[Method::GET],
            get(|| async { "hi" }),
            json_detail,
        );
        let app = Router::new().route("/x", router);

        let res = app.oneshot(request(Method::POST)).await.unwrap();
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(res.headers().get(ALLOW).unwrap(), "GET");
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, serde_json::json!({"detail": "Method Not Allowed"}));
    }

    #[test]
    #[should_panic(expected = "Overlapping method route")]
    fn understating_served_fails_fast_instead_of_shadowing_a_real_handler() {
        // `router` really answers GET and POST, but `served` only names GET
        // — so POST lands in the refused set too, and this function tries to
        // register a refusal for a method `router` already handles. That
        // collision panics in `MethodRouter::on` itself; see the `served`
        // bullet on `refusing_unserved_over`'s doc comment for why this
        // fail-fast is the wanted outcome (silently shadowing POST's real
        // handler behind a false 405 would be far worse).
        let router: MethodRouter = get(|| async { "hi" }).merge(post(|| async { "hi" }));
        let _ = refusing_unserved_over(
            CLASSIFIED_METHODS.iter(),
            &[Method::GET],
            router,
            default_refusal,
        );
    }

    #[tokio::test]
    async fn connect_can_be_excluded_from_the_judged_universe() {
        // slauth's reverse-proxy seam: judge against CLASSIFIED_METHODS minus
        // CONNECT, so an unhandled CONNECT still falls through to axum's own
        // fallback instead of this crate's truthful one.
        let proxy_universe = CLASSIFIED_METHODS
            .iter()
            .filter(|method| **method != Method::CONNECT);
        let served = [Method::GET, Method::POST];
        let router: MethodRouter =
            refusing_unserved_over(proxy_universe, &served, on_every(&served), default_refusal);
        let app = Router::new().route("/x", router);

        // PUT is in the narrowed universe and unserved -> this crate's
        // truthful refusal.
        let (put_status, put_allow) = status_and_allow(app.clone(), Method::PUT).await;
        assert_eq!(put_status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(put_allow.as_deref(), Some("GET, POST"));

        // CONNECT was excluded from the universe -> no refusal endpoint was
        // added for it -> axum's own `method_not_allowed_fallback` answers
        // instead, with axum's own notion of `Allow`: every method this
        // `MethodRouter` has ANY handler for — the two real GET/POST
        // handlers, plus the six methods this call registered refusal
        // handlers for — which happens to be every `CLASSIFIED_METHODS`
        // entry except `CONNECT`. Compared as a *set*, not a literal
        // string: axum's ordering there is an implementation detail this
        // crate does not pin, and a routine 0.8.x patch reordering it must
        // not break this test (or, worse, every consumer's copy of it).
        // What this test exists to prove is the *divergence* from `served`
        // — axum's fallback, unlike this crate's, does not distinguish "has
        // a real handler" from "has a refusal handler" when building
        // `Allow`, which is exactly why the CONNECT gap is worth excluding
        // from the universe rather than silently picking up truthful
        // handling as a side effect of this helper.
        let (connect_status, connect_allow) = status_and_allow(app, Method::CONNECT).await;
        assert_eq!(connect_status, StatusCode::METHOD_NOT_ALLOWED);

        let connect_allow_set: BTreeSet<&str> = connect_allow
            .as_deref()
            .unwrap()
            .split(',')
            .map(str::trim)
            .collect();
        let non_connect_universe: BTreeSet<&str> = CLASSIFIED_METHODS
            .iter()
            .filter(|method| **method != Method::CONNECT)
            .map(Method::as_str)
            .collect();
        assert_eq!(
            connect_allow_set, non_connect_universe,
            "axum's own fallback Allow should cover every method this \
             router has any handler for, real or refusal"
        );
        assert_ne!(
            connect_allow_set,
            served.iter().map(Method::as_str).collect::<BTreeSet<_>>(),
            "axum's fallback Allow must diverge from the truthful served \
             set — that divergence is exactly the gap CONNECT exclusion \
             preserves"
        );
    }

    // --- generic over router state ---------------------------------------

    #[derive(Clone)]
    struct AppState {
        greeting: &'static str,
    }

    #[tokio::test]
    async fn compiles_and_runs_over_a_consumer_state_type() {
        async fn handler(State(state): State<AppState>) -> &'static str {
            state.greeting
        }

        let router: MethodRouter<AppState> = refusing_unserved_over(
            CLASSIFIED_METHODS.iter(),
            &[Method::GET],
            get(handler),
            default_refusal,
        );
        let app: Router = Router::new()
            .route("/x", router)
            .with_state(AppState { greeting: "hi" });

        let ok = app.clone().oneshot(request(Method::GET)).await.unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        let (head_status, _) = status_and_allow(app, Method::HEAD).await;
        assert_eq!(head_status, StatusCode::METHOD_NOT_ALLOWED);
    }
}
