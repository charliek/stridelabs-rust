//! OpenAPI mechanics for services that document themselves with `utoipa`
//! (feature `openapi`): a canonicalizing serializer, an exhaustive
//! `(method, path)` enumerator, and a committed-spec freshness check.
//!
//! Extracted from a service that had all three and needed none of them to
//! be service-specific. Every function here takes a
//! [`utoipa::openapi::OpenApi`] that the *caller* built and knows nothing
//! about what is in it.
//!
//! # What this deliberately does not do
//!
//! There is no `ApiDoc` here, no security schemes, no `info`/`servers`/`tags`
//! block, no route list, no exclusion list, and no Swagger-UI wiring. All of
//! that is **policy**: slauth, the StrideLabs auth service, documents a
//! Kratos session cookie plus a PAT bearer with its own fixed, recognizable
//! prefix, while a resource server documents a
//! slauth-issued JWT bearer plus a PAT bearer with a different prefix, and
//! neither one's document root is a thing the other could adopt. A "spec
//! builder" in a shared crate would have to guess at that shape and would be
//! wrong for at least one consumer, so the shape stays in the service and
//! only the mechanics live here.
//!
//! # Two conventions worth carrying across services
//!
//! Neither is code and neither can be enforced from here. **This is the
//! single authoritative statement of both** — the crate README summarizes
//! them in two clauses and links here rather than restating them, because
//! they were previously written out at length in three places and a wrong
//! version of the `nest`/`merge` claim propagated into two repositories
//! before review caught it. Correct them here; nowhere else carries a copy to
//! keep in sync.
//!
//! - **Prefer structural exclusion to a maintained list — but know where the
//!   hole is.** A route reaches the document by being registered on an
//!   `utoipa_axum::router::OpenApiRouter` with `.routes(routes!(…))`, so the
//!   modules that must stay *out* (health checks, webhooks, static
//!   fallbacks, reverse proxies that publish their own contracts) stay out by
//!   never importing `utoipa` at all — no flag to flip, no exclusion list to
//!   keep in sync. What that does **not** buy is "you can't forget":
//!   `OpenApiRouter::route` and `OpenApiRouter::route_service` are
//!   pass-throughs to their `axum::Router` equivalents, registering a runtime
//!   route and adding nothing to the document, so a route can be undocumented
//!   without ever leaving `OpenApiRouter`. That escape hatch is silent. The
//!   guard is a route-pinning test: [`documented_pairs`] against an expected
//!   set turns a `.route` that should have been `.routes(routes!(…))` into a
//!   missing pair.
//! - **Apply a version prefix with `OpenApiRouter::nest`, never
//!   `axum::Router::nest`.** `OpenApiRouter::nest(prefix, router)` prefixes
//!   both halves — the OpenAPI path keys and the axum routes — which is what
//!   keeps the document and the wire in agreement. (`OpenApiRouter::merge`
//!   takes no prefix at all and combines both halves as-is: the right tool
//!   for assembling sibling routers, the wrong one for versioning.) The drift
//!   worth warning about comes from converting to an `axum::Router` first and
//!   nesting that — `axum::Router::nest` prefixes only the runtime routes,
//!   the document keeps its unprefixed paths, and the spec then describes
//!   URLs the service does not serve. [`documented_pairs`] plus a committed
//!   expectation is the cheap guard against both mistakes.
//!
//! # The committed spec file is LF, always
//!
//! [`check_committed_spec`] compares bytes, and the export side always writes
//! LF. A repository that commits a spec file must therefore pin it to LF —
//! one line in `.gitattributes`:
//!
//! ```text
//! openapi.json text eol=lf
//! ```
//!
//! Without it, a Windows checkout with `core.autocrlf=true` materializes the
//! file with CRLF endings and the freshness check fails on every line,
//! forever, with nothing wrong in the spec itself. Line endings are
//! deliberately **not** normalized before comparing — see
//! [`check_committed_spec`] for why silently accepting CRLF is worse than
//! refusing it — but the CRLF case is detected and the report names this fix.
//! A consumer should add the `.gitattributes` line as part of adopting this
//! module.
//!
//! # Feature and dependency note
//!
//! `openapi` pulls `utoipa` (default features, so the derive macros come
//! along) into this crate's graph. A consumer that derives schemas for
//! `Uuid`/`OffsetDateTime` still declares its **own** `utoipa` dependency
//! with the feature flags its types need (`uuid`, `time`, …); Cargo unifies
//! the two into one crate. This crate enables no schema features of its own
//! because it derives no schemas.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use utoipa::openapi::path::{HttpMethod, Operation, PathItem};
use utoipa::openapi::OpenApi;

/// Every HTTP method OpenAPI defines an operation slot for, as `utoipa`
/// models them.
///
/// Exhaustiveness is **compiler-enforced**, not eyeballed: [`operation_for`]
/// and [`method_name`] both `match` on all eight with no `_` arm, so a future
/// `utoipa` that adds an `HttpMethod` variant breaks this crate's build
/// instead of quietly dropping every route registered under the new method
/// out of [`documented_pairs`].
///
/// A `PathItem::operations` map would make all of this unnecessary, and the
/// obvious review comment is to ask for one. It does not exist in `utoipa`
/// 5.x — that was the utoipa 4 shape. 5.x's [`PathItem`] stores eight
/// independent `Option<Operation>` fields (`get`/`put`/`post`/`delete`/
/// `options`/`head`/`patch`/`trace`), exposes no iterator over them, and has
/// no `PathItemType` type at all; `PathItem::new` inside utoipa itself
/// `match`es an `HttpMethod` onto those same eight fields. Driving them from
/// an exhaustive match is the closest available equivalent.
///
/// **Deliberately private**, along with [`operation_for`] and
/// [`method_name`]. A `pub const ALL_HTTP_METHODS: [HttpMethod; 8]` would make
/// the array's *length* part of this crate's contract: the day utoipa adds a
/// ninth method, fixing the compile error this array exists to cause means
/// writing `[HttpMethod; 9]`, which is a breaking change for anyone who wrote
/// the type down — for a reason that has nothing to do with what they were
/// using it for. Consumers get the same guarantee through
/// [`documented_pairs`] and [`find_operation`], which is all either known
/// consumer ever needed.
const ALL_HTTP_METHODS: [HttpMethod; 8] = [
    HttpMethod::Get,
    HttpMethod::Put,
    HttpMethod::Post,
    HttpMethod::Delete,
    HttpMethod::Options,
    HttpMethod::Head,
    HttpMethod::Patch,
    HttpMethod::Trace,
];

/// The operation registered on `item` under `method`, if any.
///
/// The one place the eight `Option<Operation>` fields of a [`PathItem`] are
/// turned back into a lookup — see [`ALL_HTTP_METHODS`] for why that mapping
/// has to be written out by hand.
fn operation_for<'a>(item: &'a PathItem, method: &HttpMethod) -> Option<&'a Operation> {
    match method {
        HttpMethod::Get => item.get.as_ref(),
        HttpMethod::Put => item.put.as_ref(),
        HttpMethod::Post => item.post.as_ref(),
        HttpMethod::Delete => item.delete.as_ref(),
        HttpMethod::Options => item.options.as_ref(),
        HttpMethod::Head => item.head.as_ref(),
        HttpMethod::Patch => item.patch.as_ref(),
        HttpMethod::Trace => item.trace.as_ref(),
    }
}

/// An [`HttpMethod`]'s uppercase wire spelling (`"GET"`, `"DELETE"`, …).
///
/// `utoipa` serializes these lowercase (`#[serde(rename_all = "lowercase")]`),
/// implements no `Display`, and — unless its `debug` feature is on, which
/// this crate does not enable — no `Debug` either, so there is no way to name
/// a method in an assertion message without this. Written out without a `_`
/// arm for the same reason as [`operation_for`].
fn method_name(method: &HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Put => "PUT",
        HttpMethod::Post => "POST",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Head => "HEAD",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Trace => "TRACE",
    }
}

/// Every `(METHOD, path)` pair the document describes, with methods in their
/// uppercase wire spelling and paths exactly as the document keys them
/// (`"/api/v1/pat/{pat_id}"`).
///
/// Genuinely exhaustive over the eight operation slots `utoipa` models —
/// enumerated by a `match` with no `_` arm, so a `utoipa` that adds a method
/// is a compile error here rather than routes silently missing from every
/// consumer's spec — so a route registered under a method the calling test
/// never mentions by name still shows up. The `BTreeSet` return makes
/// `assert_eq!` against a hand-written expectation both order-insensitive and
/// readable when it fails.
///
/// This is the primitive behind the "the documented surface is exactly this
/// list" test: a route added without `#[utoipa::path]`, or annotated when it
/// should have stayed excluded, changes this set.
///
/// ```
/// use stridelabs_http::openapi::{documented_pairs, expected_pairs};
/// use utoipa::OpenApi;
///
/// #[utoipa::path(get, path = "/widgets", responses((status = 200, description = "ok")))]
/// fn list_widgets() {}
///
/// #[derive(OpenApi)]
/// #[openapi(paths(list_widgets))]
/// struct ApiDoc;
///
/// assert_eq!(
///     documented_pairs(&ApiDoc::openapi()),
///     expected_pairs(&[("GET", "/widgets")]),
/// );
/// ```
pub fn documented_pairs(spec: &OpenApi) -> BTreeSet<(String, String)> {
    let mut pairs = BTreeSet::new();
    for (path, item) in &spec.paths.paths {
        for method in &ALL_HTTP_METHODS {
            if operation_for(item, method).is_some() {
                pairs.insert((method_name(method).to_string(), path.clone()));
            }
        }
    }
    pairs
}

/// The expected side of a [`documented_pairs`] assertion, written the way a
/// test table wants to write it: `&[("GET", "/widgets"), …]`.
///
/// [`documented_pairs`] returns owned `String`s — it has to, since the paths
/// are cloned out of the document — so every consumer that compares against a
/// hand-written list needs the same `.map(|(m, p)| (m.to_string(),
/// p.to_string())).collect()`. Three independent copies of that closure
/// existed before this function did: a consumer's, this README's, and this
/// module's own tests'. It lives here so the conversion tracks
/// [`documented_pairs`]' return type by construction; the tests below use it
/// for exactly that reason, so a change to one side cannot compile against a
/// stale copy of the other.
///
/// No validation is performed — the argument is an *expectation*, and a
/// misspelled method or path is supposed to fail the `assert_eq!` loudly
/// rather than be rejected here with a worse message.
///
/// ```
/// use stridelabs_http::openapi::expected_pairs;
///
/// let expected = expected_pairs(&[("GET", "/widgets"), ("POST", "/widgets")]);
/// assert!(expected.contains(&("GET".to_string(), "/widgets".to_string())));
/// ```
pub fn expected_pairs(pairs: &[(&str, &str)]) -> BTreeSet<(String, String)> {
    pairs
        .iter()
        .map(|(method, path)| ((*method).to_string(), (*path).to_string()))
        .collect()
}

/// Why [`find_operation`] could not return an [`Operation`] — the three
/// distinguishable ways a `(method, path)` lookup misses.
///
/// The distinction is the point. A single "not found" makes a route-renamed
/// document and a route-that-lost-its-`POST` document fail identically, which
/// is strictly less than the two hand-written panics a consumer would have
/// written without this helper at all.
///
/// [`std::fmt::Display`] renders a complete, self-contained sentence for each
/// case, so a caller that only wants to fail can forward it verbatim (that is
/// what [`expect_operation`] does); a caller that wants to render its own
/// message, group misses, or count them has the path, the method, and — for
/// the near-miss case — the methods the path *does* document.
///
/// The variants do not overlap, because [`find_operation`] resolves them in a
/// fixed order: the method spelling is validated **first** (it is wrong or
/// right on its own terms, independent of what the document contains), then
/// the path, then the operation. So a typo'd method is always
/// [`UnknownMethod`](Self::UnknownMethod) — never masked by the path it
/// happened to be paired with.
#[derive(Debug, thiserror::Error)]
pub enum OperationNotFound {
    /// The document has no such path key at all. `method` is a valid
    /// spelling — an invalid one is [`UnknownMethod`](Self::UnknownMethod)
    /// whether or not the path exists.
    #[error("the OpenAPI document has no path `{path}` (looking up `{method} {path}`)")]
    Path { method: String, path: String },
    /// The path is documented, but carries no operation under `method`.
    #[error(
        "the OpenAPI document has path `{path}` but no `{method}` operation on it ({})",
        describe_documented(.documented)
    )]
    Method {
        method: String,
        path: String,
        /// The methods this path *does* document, sorted lexicographically —
        /// the same order [`documented_pairs`] yields them in, since that is
        /// a `BTreeSet` of uppercase spellings.
        ///
        /// May be **empty**. A [`PathItem`] whose eight operation fields are
        /// all `None` is constructible ([`PathItem`] derives `Default`) and
        /// deserializable from `{"/x": {}}`, so a document can carry a path
        /// key that documents nothing at all; `Display` phrases that case
        /// separately rather than trailing off after "it documents:".
        documented: Vec<&'static str>,
    },
    /// `method` is not one of the eight uppercase wire spellings, so the
    /// lookup never got as far as the document. Almost always a typo in the
    /// calling table (`"get"` for `"GET"`). Checked before the path, so this
    /// is the answer even when `path` is also absent.
    #[error(
        "`{method}` is not an HTTP method spelling this lookup recognizes (looking up `{path}`); \
         they are uppercase: GET, PUT, POST, DELETE, OPTIONS, HEAD, PATCH, TRACE"
    )]
    UnknownMethod { method: String, path: String },
}

/// The parenthetical in [`OperationNotFound::Method`]'s message.
///
/// Split out because the empty case needs different *words*, not a list with
/// nothing in it: `(it documents: )` reads like a truncated message and sends
/// the reader looking for the bug in the wrong place.
fn describe_documented(documented: &[&'static str]) -> String {
    if documented.is_empty() {
        "the path item documents no operations at all".to_string()
    } else {
        format!("it documents: {}", documented.join(", "))
    }
}

/// The methods `item` documents, sorted lexicographically.
///
/// Sorted rather than left in [`ALL_HTTP_METHODS`] slot order, which is
/// `utoipa`'s *field declaration* order (GET, PUT, POST, DELETE, …) and
/// carries no meaning for either audience: a human reading a panic gets an
/// arbitrary-looking sequence, and a caller comparing against anything this
/// crate produces is comparing against [`documented_pairs`]' `BTreeSet`,
/// which is lexicographic. Alphabetical is also what the rest of this module
/// stakes itself on — see [`to_pretty_json`].
fn documented_methods(item: &PathItem) -> Vec<&'static str> {
    let mut methods: Vec<&'static str> = ALL_HTTP_METHODS
        .iter()
        .filter(|m| operation_for(item, m).is_some())
        .map(method_name)
        .collect();
    methods.sort_unstable();
    methods
}

/// The [`Operation`] documented at `method` + `path`, addressed the way a
/// test table spells it (`("GET", "/api/v1/session")`) rather than through an
/// [`HttpMethod`] value.
///
/// Exists so a per-route assertion (documented status codes, security
/// requirements, response schemas) doesn't have to re-derive the
/// string-to-[`HttpMethod`] lookup, which is the same mapping
/// [`documented_pairs`] emits on its way out.
///
/// `method` is matched case-sensitively against the uppercase wire spellings
/// (`"GET"`, `"DELETE"`, …); an unrecognized spelling is
/// [`OperationNotFound::UnknownMethod`], not a panic.
///
/// # Why `Result` here and a panicking [`expect_operation`] alongside
///
/// This pair mirrors [`check_committed_spec`] / [`assert_committed_spec_is_fresh`]
/// deliberately, and for the same reason: the typed error is the primitive,
/// the panicking form is the one a test actually writes.
///
/// A test table is realistically the only caller, and for that caller
/// [`expect_operation`] is the whole answer — one expression, and the message
/// is already the two-case one. But the primitive stays a `Result` rather
/// than *only* a panic, because the error carries structure a panic throws
/// away: an `xtask` diffing two specs, or a lint that reports every missing
/// route in one pass instead of dying on the first, needs to inspect the miss
/// rather than abort on it. Building the panic on the `Result` costs one
/// `match`, and it guarantees the two forms can never describe the same miss
/// differently.
///
/// There is deliberately **no** `Option`-returning form. That was the
/// previous shape, and it is what this replaces: it collapsed all three cases
/// into one `None` and pushed callers back to `spec.paths.paths` to tell them
/// apart. A caller who genuinely wants "present or not, don't care why"
/// writes `.ok()` — one call, at the one call site that wants it, instead of
/// a second name in the crate's surface that everyone has to choose between.
///
/// One wrinkle worth knowing before it surprises you: `unwrap_err` and
/// `expect_err` do **not** compile on this `Result`. Both require the *ok*
/// type to be `Debug`, and `utoipa` implements `Debug` for [`Operation`] only
/// under its `debug` feature. `unwrap`, `expect` and `?` on the success side
/// are all fine ([`OperationNotFound`] is `Debug`). A test that wants to
/// assert on a miss has two ways round it:
///
/// ```
/// # use stridelabs_http::openapi::{find_operation, OperationNotFound};
/// # use utoipa::OpenApi;
/// # #[derive(OpenApi)]
/// # #[openapi()]
/// # struct ApiDoc;
/// # let spec = ApiDoc::openapi();
/// // Shortest, when you just want the error:
/// let err = find_operation(&spec, "GET", "/nope").err().expect("expected a miss");
///
/// // Preferable when the success case should fail with its own message:
/// let Err(err) = find_operation(&spec, "GET", "/nope") else {
///     panic!("/nope should not be documented");
/// };
/// ```
///
/// Enabling `utoipa`'s `debug` feature here would also work, and is
/// deliberately not done: Cargo unifies features across the graph, so every
/// consumer would carry `Debug` impls on `utoipa`'s whole type tree to buy
/// this crate's tests one method call.
pub fn find_operation<'a>(
    spec: &'a OpenApi,
    method: &str,
    path: &str,
) -> Result<&'a Operation, OperationNotFound> {
    // Method spelling first, deliberately: `"get"` is wrong on its own terms
    // — nothing in the document can make it right — so validating it after
    // the path lookup would report a typo'd method on a renamed route as
    // `Path`, hiding the typo behind the rename and making the answer depend
    // on which of the two mistakes you made second.
    let http_method = ALL_HTTP_METHODS
        .iter()
        .find(|m| method_name(m) == method)
        .ok_or_else(|| OperationNotFound::UnknownMethod {
            method: method.to_string(),
            path: path.to_string(),
        })?;

    let item = spec
        .paths
        .paths
        .get(path)
        .ok_or_else(|| OperationNotFound::Path {
            method: method.to_string(),
            path: path.to_string(),
        })?;

    operation_for(item, http_method).ok_or_else(|| OperationNotFound::Method {
        method: method.to_string(),
        path: path.to_string(),
        documented: documented_methods(item),
    })
}

/// [`find_operation`], panicking with the rendered [`OperationNotFound`].
///
/// The form a per-route test table wants: the lookup is one expression, and a
/// miss already says which of the three things went wrong — the path is
/// absent, the path is there but not under this method (with the methods it
/// does document), or the method spelling is a typo. `#[track_caller]` puts
/// the panic's location on the calling test line rather than inside this
/// crate.
///
/// ```
/// use stridelabs_http::openapi::expect_operation;
/// use utoipa::OpenApi;
///
/// #[utoipa::path(post, path = "/widgets", responses((status = 201, description = "created")))]
/// fn create_widget() {}
///
/// #[derive(OpenApi)]
/// #[openapi(paths(create_widget))]
/// struct ApiDoc;
///
/// let spec = ApiDoc::openapi();
/// let op = expect_operation(&spec, "POST", "/widgets");
/// let codes: Vec<&str> = op.responses.responses.keys().map(String::as_str).collect();
/// assert_eq!(codes, ["201"]);
/// ```
#[track_caller]
pub fn expect_operation<'a>(spec: &'a OpenApi, method: &str, path: &str) -> &'a Operation {
    match find_operation(spec, method, path) {
        Ok(operation) => operation,
        Err(e) => panic!("{e}"),
    }
}

/// Render an [`OpenApi`] document as pretty JSON with a CANONICAL
/// (alphabetical) key order at every nesting level, regardless of whichever
/// map types `utoipa`'s internals happen to use for a given field.
///
/// **This is the whole reason the function exists**: a committed `openapi.json`
/// is only reviewable, and only checkable against a fresh export, if
/// re-rendering the same document twice produces the same bytes. That is not
/// something a service controls on its own. `utoipa::openapi::path::Paths` is
/// a `BTreeMap` (alphabetical by construction) *unless* utoipa's
/// `preserve_path_order` feature is on, and several nested value types
/// further down (parameter lists, extension maps) are plain
/// `serde_json::Value` produced by macro-generated code — whose key order
/// flips from sorted to insertion-ordered the moment anything in the
/// dependency graph enables `serde_json`'s `preserve_order` feature, which
/// turns every `serde_json::Map` into an `IndexMap`. Cargo unifies features
/// across the whole graph, so a transitive dependency three levels away
/// turning that on silently reorders a service's committed spec and fails its
/// freshness test with a diff nobody can explain.
///
/// Rebuilding every object through a [`BTreeMap`] here makes the output
/// byte-identical run to run and machine to machine, independent of every one
/// of those flags.
///
/// ```
/// use stridelabs_http::openapi::to_pretty_json;
/// use utoipa::OpenApi;
///
/// #[derive(OpenApi)]
/// #[openapi()]
/// struct ApiDoc;
///
/// // The CLI subcommand that writes the committed file is one line:
/// println!("{}", to_pretty_json(&ApiDoc::openapi()));
/// ```
pub fn to_pretty_json(spec: &OpenApi) -> String {
    let value = serde_json::to_value(spec).expect("an OpenApi document always serializes");
    serde_json::to_string_pretty(&canonicalize(value))
        .expect("a canonicalized JSON value always serializes")
}

/// Recursively rebuild every JSON object with its keys in sorted order.
fn canonicalize(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> =
                map.into_iter().map(|(k, v)| (k, canonicalize(v))).collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(canonicalize).collect())
        }
        other => other,
    }
}

/// Exactly what a committed spec file must contain for [`check_committed_spec`]
/// to accept it: [`to_pretty_json`], **LF line endings**, plus **one trailing
/// newline**.
///
/// The newline is not decoration. The export side is a CLI subcommand that
/// `println!`s the spec and is redirected to the file (`svc openapi >
/// openapi.json`), and `println!` appends exactly one `\n`; POSIX text files
/// end in a newline, and every editor, `git diff` and "no newline at end of
/// file" marker agrees. Both halves of the convention are owned here so the
/// exporter and the test cannot disagree about it.
///
/// **LF, not CRLF** — see [`check_committed_spec`] for why that is a
/// requirement stated out loud rather than something normalized away, and for
/// the one `.gitattributes` line that makes it true on every checkout.
///
/// Named for what it returns — the contents a committed file is *expected* to
/// have — rather than `committed_file_contents`, which read like an accessor
/// for a file that exists when in fact nothing here touches the filesystem.
/// It pairs with [`expected_pairs`]: both name the right-hand side of a
/// comparison, derived from the document, that a repository is checked
/// against.
pub fn expected_file_contents(spec: &OpenApi) -> String {
    format!("{}\n", to_pretty_json(spec))
}

/// Why a committed OpenAPI file failed its freshness check.
///
/// [`std::fmt::Display`] is the whole point: it renders a multi-line report
/// naming the file, the first *useful* difference or boundary — the first
/// differing line where there is one, and otherwise the specific structural
/// problem (unreadable file, CRLF line endings, a missing or doubled trailing
/// newline, one file being a truncation of the other) — and the exact command
/// to regenerate it. Callers are expected to surface it verbatim.
#[derive(Debug, thiserror::Error)]
pub enum SpecFreshnessError {
    /// The committed file could not be read (missing, unreadable, not UTF-8).
    #[error(
        "could not read the committed OpenAPI spec at {path}: {source}\n\
         regenerate it with: {regenerate_command}"
    )]
    Read {
        path: PathBuf,
        regenerate_command: String,
        source: std::io::Error,
    },
    /// The committed file exists but is not what the current code exports.
    #[error(
        "{path} is stale — it does not match what this build exports.\n\
         {detail}\n\
         regenerate it with: {regenerate_command}"
    )]
    Stale {
        path: PathBuf,
        regenerate_command: String,
        /// A human-readable description of the first difference — computed
        /// eagerly at construction so `Display` stays cheap and total.
        detail: String,
    },
}

/// Check that a committed OpenAPI file is byte-identical to what `spec`
/// exports today.
///
/// `regenerate_command` is the shell command that rewrites the file — it
/// differs per service (per *binary*, even), so it is a parameter rather than
/// something this crate could compose, and it is reproduced verbatim in the
/// error. Pass the real, copy-pasteable command:
/// `cargo run --bin svc -- openapi > openapi.json`.
///
/// The comparison is against [`expected_file_contents`] and is exact: pretty
/// JSON, LF line endings, one trailing newline.
///
/// # LF is required, not normalized
///
/// A Windows checkout with `core.autocrlf=true` materializes an LF-committed
/// spec on disk with CRLF endings, while the export always writes LF. That
/// makes the byte comparison fail on every line, forever, through no fault of
/// the spec's contents.
///
/// This function does **not** normalize line endings before comparing, on
/// purpose. Normalizing would let a CRLF working copy pass the check and then
/// blow up on whoever next regenerates the file — their editor writes LF, the
/// diff is the entire document, and the real cause (a checkout setting, not
/// their change) is nowhere in sight. Instead the CRLF case is detected and
/// reported by name, with the fix: add
///
/// ```text
/// openapi.json text eol=lf
/// ```
///
/// to the repository's `.gitattributes` and re-checkout the file. A consumer
/// adopting this helper should add that line as part of adoption rather than
/// wait for a contributor on Windows to discover it.
///
/// Returns `Result` rather than panicking so this is usable outside a test —
/// a CI helper or an `xtask` that wants to print the report and exit
/// non-zero. In a test, prefer [`assert_committed_spec_is_fresh`].
///
/// ```no_run
/// use stridelabs_http::openapi::check_committed_spec;
/// # use utoipa::OpenApi;
/// # #[derive(OpenApi)]
/// # #[openapi()]
/// # struct ApiDoc;
/// let path = concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.json");
/// if let Err(e) = check_committed_spec(path, &ApiDoc::openapi(), "cargo run --bin svc -- openapi > openapi.json") {
///     eprintln!("{e}");
///     std::process::exit(1);
/// }
/// ```
pub fn check_committed_spec(
    committed_path: impl AsRef<Path>,
    spec: &OpenApi,
    regenerate_command: &str,
) -> Result<(), SpecFreshnessError> {
    let path = committed_path.as_ref();
    let committed = std::fs::read_to_string(path).map_err(|source| SpecFreshnessError::Read {
        path: path.to_path_buf(),
        regenerate_command: regenerate_command.to_string(),
        source,
    })?;

    let fresh = expected_file_contents(spec);
    if committed == fresh {
        return Ok(());
    }

    Err(SpecFreshnessError::Stale {
        path: path.to_path_buf(),
        regenerate_command: regenerate_command.to_string(),
        detail: describe_difference(path, &committed, &fresh),
    })
}

/// [`check_committed_spec`], panicking with the rendered report.
///
/// A panicking form is the right one for a test even though this crate
/// otherwise returns typed errors: `assert_committed_spec_is_fresh(…)` on one
/// line *is* the assertion, whereas the `Result` form makes every consumer
/// write the same `if let Err(e) = … { panic!("{e}") }` three-liner and get
/// the message formatting subtly different each time. The panic message is
/// the error's `Display`, which already names the file, the first useful
/// difference or boundary, and the regeneration command — so nothing is lost
/// versus asserting by hand, and the "stale spec" diff stays identical across
/// services.
///
/// ```no_run
/// # use utoipa::OpenApi;
/// # #[derive(OpenApi)]
/// # #[openapi()]
/// # struct ApiDoc;
/// #[test]
/// fn the_committed_openapi_json_matches_a_fresh_export() {
///     stridelabs_http::openapi::assert_committed_spec_is_fresh(
///         concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.json"),
///         &ApiDoc::openapi(),
///         "cargo run --bin svc -- openapi > openapi.json",
///     );
/// }
/// ```
#[track_caller]
pub fn assert_committed_spec_is_fresh(
    committed_path: impl AsRef<Path>,
    spec: &OpenApi,
    regenerate_command: &str,
) {
    if let Err(e) = check_committed_spec(committed_path, spec, regenerate_command) {
        panic!("{e}");
    }
}

/// The longest a quoted spec line gets before it is elided in a report. Spec
/// lines are indented JSON, so a long `description` would otherwise wrap the
/// terminal several times and bury the line number that actually matters.
const MAX_QUOTED_LINE: usize = 120;

/// Describe the first useful difference (or structural boundary) between
/// `committed` and `fresh`, in the terms someone staring at a red CI job
/// needs.
///
/// The line-ending and trailing-newline cases are called out by name because
/// they are the ones that produce a "the files look identical" diff: a
/// Windows checkout rewriting every line ending, an editor configured to
/// strip final newlines, or an exporter switched from `println!` to `print!`
/// each change bytes nobody can see.
fn describe_difference(path: &Path, committed: &str, fresh: &str) -> String {
    // Checked first, and before anything that walks lines: a CRLF working
    // copy differs from the export on *every* line, yet `str::lines()` strips
    // the trailing `\r` and would report the two as line-for-line identical,
    // leaving only a baffling "these files are the same" failure. Serialized
    // JSON never contains a literal CR — `serde_json` escapes control
    // characters inside strings — so a CR here is always a line-ending
    // artifact and never spec content.
    if committed.contains('\r') {
        let file = path.file_name().map_or_else(
            || path.display().to_string(),
            |n| n.to_string_lossy().into(),
        );
        let otherwise = if committed.replace("\r\n", "\n") == fresh {
            "the content is otherwise identical"
        } else {
            "and there are content differences on top of that"
        };
        return format!(
            "the committed file has CRLF line endings; the export always writes LF \
             ({otherwise}).\n  \
             This is a checkout artifact, not a code change — usually `core.autocrlf=true` on \
             Windows. Line endings are NOT normalized before comparing, because a normalized \
             pass would leave the next person to regenerate this file with a whole-document \
             diff and no clue why. Pin the file to LF instead, then re-checkout it:\n    \
             echo '{file} text eol=lf' >> .gitattributes"
        );
    }

    if committed.trim_end_matches('\n') == fresh.trim_end_matches('\n') {
        return match (committed.ends_with('\n'), committed.len().cmp(&fresh.len())) {
            (false, _) => "the content matches but the committed file has no trailing newline \
                           (something stripped it — an editor setting, or an exporter using \
                           `print!` where it should use `println!`)"
                .to_string(),
            (true, std::cmp::Ordering::Greater) => {
                "the content matches but the committed file has more than one trailing newline"
                    .to_string()
            }
            // Equal length with equal trimmed content means equal strings,
            // which never reaches this function.
            (true, _) => "the files differ only in trailing whitespace".to_string(),
        };
    }

    let committed_lines: Vec<&str> = committed.lines().collect();
    let fresh_lines: Vec<&str> = fresh.lines().collect();

    for (i, (c, f)) in committed_lines.iter().zip(fresh_lines.iter()).enumerate() {
        if c != f {
            return format!(
                "first difference at line {}:\n  committed: {}\n  exported:  {}",
                i + 1,
                quote(c),
                quote(f)
            );
        }
    }

    // One is a prefix of the other: a whole block was added or removed.
    match committed_lines.len().cmp(&fresh_lines.len()) {
        std::cmp::Ordering::Less => format!(
            "the committed file stops at line {} but the export continues:\n  exported:  {}",
            committed_lines.len(),
            quote(fresh_lines[committed_lines.len()])
        ),
        std::cmp::Ordering::Greater => format!(
            "the export stops at line {} but the committed file continues:\n  committed: {}",
            fresh_lines.len(),
            quote(committed_lines[fresh_lines.len()])
        ),
        // Defensive: equal line counts, no differing line, no CR, and the
        // trailing-newline cases already returned above — there is no known
        // input that lands here, so say only what is certainly true.
        std::cmp::Ordering::Equal => {
            "the files differ only in bytes that `str::lines()` does not surface".to_string()
        }
    }
}

/// A spec line, quoted and length-capped for a one-line report.
fn quote(line: &str) -> String {
    if line.chars().count() > MAX_QUOTED_LINE {
        let head: String = line.chars().take(MAX_QUOTED_LINE).collect();
        format!("{head:?} … (truncated)")
    } else {
        format!("{line:?}")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use utoipa::OpenApi as _;

    use super::*;

    /// One annotated handler per HTTP method OpenAPI defines a slot for, so
    /// the enumeration tests below exercise all eight rather than the two or
    /// three a realistic service happens to use.
    ///
    /// `#[allow(dead_code)]` on the module: none of these bodies is ever
    /// called. `#[utoipa::path]` documents a handler by generating a *sibling*
    /// `__path_<name>` type, and that type — not the function — is what
    /// `#[openapi(paths(…))]` reads. The functions exist only to hang the
    /// attribute on.
    #[allow(dead_code)]
    mod handlers {
        #[utoipa::path(get, path = "/widgets", responses((status = 200, description = "ok")))]
        pub fn list_widgets() {}

        #[utoipa::path(post, path = "/widgets", responses((status = 201, description = "created")))]
        pub fn create_widget() {}

        #[utoipa::path(put, path = "/widgets/{id}", responses((status = 200, description = "ok")))]
        pub fn replace_widget() {}

        #[utoipa::path(patch, path = "/widgets/{id}", responses((status = 200, description = "ok")))]
        pub fn update_widget() {}

        #[utoipa::path(delete, path = "/widgets/{id}", responses((status = 204, description = "gone")))]
        pub fn delete_widget() {}

        #[utoipa::path(head, path = "/widgets/{id}", responses((status = 200, description = "ok")))]
        pub fn head_widget() {}

        #[utoipa::path(options, path = "/widgets/{id}", responses((status = 204, description = "ok")))]
        pub fn widget_options() {}

        #[utoipa::path(trace, path = "/widgets/{id}", responses((status = 200, description = "ok")))]
        pub fn trace_widget() {}
    }

    #[derive(utoipa::OpenApi)]
    #[openapi(paths(
        handlers::list_widgets,
        handlers::create_widget,
        handlers::replace_widget,
        handlers::update_widget,
        handlers::delete_widget,
        handlers::head_widget,
        handlers::widget_options,
        handlers::trace_widget
    ))]
    struct ApiDoc;

    #[derive(utoipa::OpenApi)]
    #[openapi()]
    struct EmptyDoc;

    /// The error side of a [`find_operation`] miss.
    ///
    /// `Result::expect_err`/`unwrap_err` are unavailable: both require the
    /// *ok* type to be `Debug`, and `utoipa`'s [`Operation`] implements
    /// `Debug` only under its `debug` feature, which this crate does not
    /// enable. Worth knowing before a consumer writes `.unwrap_err()` and is
    /// confused by the bound — see [`find_operation`]'s docs, which name it
    /// and give the two one-liner workarounds. This helper is the same thing
    /// with a message worth reading when the lookup unexpectedly succeeds.
    #[track_caller]
    fn miss(result: Result<&Operation, OperationNotFound>) -> OperationNotFound {
        match result {
            Ok(_) => panic!("expected the lookup to miss, but it found an operation"),
            Err(e) => e,
        }
    }

    /// A file that would be committed for `spec`, written under a temp dir.
    fn write_spec_file(dir: &std::path::Path, contents: &str) -> PathBuf {
        let path = dir.join("openapi.json");
        std::fs::write(&path, contents).unwrap();
        path
    }

    const REGEN: &str = "cargo run --bin svc -- openapi > openapi.json";

    #[test]
    fn to_pretty_json_is_deterministic_across_independently_built_specs() {
        // Two independent builds of the same document — the property the
        // committed-spec workflow rests on, since the exporter and the
        // freshness test each build their own.
        assert_eq!(
            to_pretty_json(&ApiDoc::openapi()),
            to_pretty_json(&ApiDoc::openapi())
        );
    }

    /// A value whose keys are in insertion order, not sorted order, at three
    /// nesting levels: the top object, an object below it, and an object
    /// inside an array.
    ///
    /// Built by hand through `Map::insert` rather than with `json!` for a
    /// reason that is the whole point of these tests — see
    /// [`the_test_build_reproduces_the_preserve_order_hazard`].
    fn insertion_ordered_value() -> serde_json::Value {
        fn object(pairs: &[(&str, i64)]) -> serde_json::Value {
            let mut map = serde_json::Map::new();
            for (k, v) in pairs {
                map.insert((*k).to_string(), serde_json::Value::from(*v));
            }
            serde_json::Value::Object(map)
        }

        let mut outer = serde_json::Map::new();
        outer.insert("zebra".to_string(), serde_json::Value::from(1));
        outer.insert("alpha".to_string(), object(&[("z", 1), ("a", 2)]));
        outer.insert(
            "middle".to_string(),
            serde_json::Value::Array(vec![object(&[("c", 3), ("a", 1)])]),
        );
        serde_json::Value::Object(outer)
    }

    /// The guard that keeps every canonicalization test below from going
    /// vacuous.
    ///
    /// Without `serde_json`'s `preserve_order` feature a `serde_json::Map` is
    /// a `BTreeMap`: every `Value::Object` is sorted the instant it is built,
    /// `canonicalize` is a no-op, and deleting the whole function would not
    /// fail a single assertion. This crate's `[dev-dependencies]` turn
    /// `preserve_order` on (and only for test targets — see the comment
    /// there), which is what makes the hazard reproducible in-process. If
    /// that wiring is ever dropped, this test fails first and says why.
    #[test]
    fn the_test_build_reproduces_the_preserve_order_hazard() {
        assert_eq!(
            serde_json::to_string(&insertion_ordered_value()).unwrap(),
            r#"{"zebra":1,"alpha":{"z":1,"a":2},"middle":[{"c":3,"a":1}]}"#,
            "serde_json's `preserve_order` feature is not enabled in this test build, so a \
             `Value::Object` is already sorted and the canonicalization tests below assert \
             nothing — restore the `serde_json = {{ features = [\"preserve_order\"] }}` \
             dev-dependency in crates/http/Cargo.toml"
        );
    }

    #[test]
    fn canonicalize_sorts_object_keys_at_every_nesting_level() {
        let rendered = serde_json::to_string(&canonicalize(insertion_ordered_value())).unwrap();

        assert_eq!(
            rendered,
            r#"{"alpha":{"a":2,"z":1},"middle":[{"a":1,"c":3}],"zebra":1}"#
        );
    }

    #[test]
    fn to_pretty_json_sorts_a_document_utoipa_emits_in_declaration_order() {
        // End-to-end, on a real document rather than a hand-built value:
        // `utoipa`'s types serialize their fields in *declaration* order
        // (`openapi` before `info`), and with `preserve_order` on that order
        // survives into the `Value`. Only `canonicalize` sorts it — delete
        // that call from `to_pretty_json` and this fails.
        let spec = ApiDoc::openapi();

        let uncanonicalized = top_level_keys(
            &serde_json::to_string_pretty(&serde_json::to_value(&spec).unwrap()).unwrap(),
        );
        let mut sorted = uncanonicalized.clone();
        sorted.sort();
        assert_ne!(
            uncanonicalized, sorted,
            "this document's keys already come out sorted, so it cannot show canonicalization \
             doing anything: {uncanonicalized:?}"
        );

        assert_eq!(top_level_keys(&to_pretty_json(&spec)), sorted);
    }

    /// The keys of a pretty-printed JSON object's top level, in the order
    /// they appear in the text — `serde_json::to_string_pretty` indents them
    /// by exactly two spaces.
    fn top_level_keys(pretty: &str) -> Vec<String> {
        pretty
            .lines()
            .filter_map(|line| line.strip_prefix("  \""))
            .filter_map(|rest| rest.split_once("\":"))
            .map(|(key, _)| key.to_string())
            .collect()
    }

    #[test]
    fn to_pretty_json_emits_no_trailing_newline() {
        // The exporter's `println!` supplies it; `expected_file_contents` is
        // the one place the convention lives.
        let rendered = to_pretty_json(&ApiDoc::openapi());
        assert!(!rendered.ends_with('\n'), "{rendered:?}");
        assert_eq!(expected_file_contents(&ApiDoc::openapi()), rendered + "\n");
    }

    #[test]
    fn documented_pairs_covers_every_http_method() {
        // `expected_pairs`, not a local closure: it is the public conversion
        // consumers use, so exercising it here is what keeps it in step with
        // `documented_pairs`' return type rather than merely resembling it.
        assert_eq!(
            documented_pairs(&ApiDoc::openapi()),
            expected_pairs(&[
                ("GET", "/widgets"),
                ("POST", "/widgets"),
                ("PUT", "/widgets/{id}"),
                ("PATCH", "/widgets/{id}"),
                ("DELETE", "/widgets/{id}"),
                ("HEAD", "/widgets/{id}"),
                ("OPTIONS", "/widgets/{id}"),
                ("TRACE", "/widgets/{id}"),
            ])
        );
    }

    #[test]
    fn documented_pairs_is_empty_for_a_document_with_no_paths() {
        assert!(documented_pairs(&EmptyDoc::openapi()).is_empty());
    }

    #[test]
    fn every_method_name_round_trips_through_all_http_methods() {
        // The two hand-written matches must stay in step with each other and
        // with the array; a variant dropped from `ALL_HTTP_METHODS` would not
        // be a compile error, only a silent gap, so it is asserted.
        assert_eq!(ALL_HTTP_METHODS.len(), 8);
        let names: BTreeSet<&str> = ALL_HTTP_METHODS.iter().map(method_name).collect();
        assert_eq!(
            names.len(),
            8,
            "method spellings must be distinct: {names:?}"
        );
    }

    #[test]
    fn expected_pairs_matches_documented_pairs_for_a_single_route() {
        // The narrow claim `expected_pairs` exists to make: its output type
        // and element shape are `documented_pairs`', not merely similar.
        #[derive(utoipa::OpenApi)]
        #[openapi(paths(handlers::list_widgets))]
        struct OneRoute;

        assert_eq!(
            documented_pairs(&OneRoute::openapi()),
            expected_pairs(&[("GET", "/widgets")])
        );
    }

    #[test]
    fn expected_pairs_is_empty_for_an_empty_slice() {
        assert!(expected_pairs(&[]).is_empty());
    }

    #[test]
    fn find_operation_addresses_a_route_by_its_table_spelling() {
        let spec = ApiDoc::openapi();

        let op = find_operation(&spec, "POST", "/widgets").expect("POST /widgets is documented");
        let codes: Vec<&str> = op.responses.responses.keys().map(String::as_str).collect();
        assert_eq!(codes, ["201"]);
    }

    /// The regression this API shape exists to prevent: "the path is gone"
    /// and "the path lost this method" must not report identically, which is
    /// what a single `None` did.
    #[test]
    fn find_operation_tells_a_missing_path_apart_from_a_missing_method() {
        let spec = ApiDoc::openapi();

        let missing_path = miss(find_operation(&spec, "GET", "/nope"));
        assert!(
            matches!(missing_path, OperationNotFound::Path { .. }),
            "{missing_path:?}"
        );
        let msg = missing_path.to_string();
        assert!(msg.contains("no path `/nope`"), "{msg}");

        let missing_method = miss(find_operation(&spec, "DELETE", "/widgets"));
        assert!(
            matches!(missing_method, OperationNotFound::Method { .. }),
            "{missing_method:?}"
        );
        let msg = missing_method.to_string();
        assert!(msg.contains("has path `/widgets`"), "{msg}");
        assert!(msg.contains("no `DELETE` operation"), "{msg}");
        assert!(
            msg.contains("GET, POST"),
            "the near-miss case should name the methods the path does document: {msg}"
        );
    }

    #[test]
    fn find_operation_names_an_unrecognized_method_spelling_as_such() {
        let spec = ApiDoc::openapi();

        // The table spelling is uppercase; a lowercase one is a typo.
        let err = miss(find_operation(&spec, "get", "/widgets"));

        assert!(
            matches!(err, OperationNotFound::UnknownMethod { .. }),
            "{err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("`get` is not an HTTP method spelling"),
            "{msg}"
        );
        assert!(
            msg.contains("/widgets"),
            "a typo'd lookup should still say what was being looked up: {msg}"
        );
    }

    /// An unrecognized method spelling wins over a missing path, so the
    /// answer never depends on which of the two mistakes the caller made.
    /// The regression guard for a precedence bug: with the path looked up
    /// first, `("get", "/nope")` reported `Path` and the typo vanished.
    #[test]
    fn an_unknown_method_spelling_outranks_a_missing_path() {
        let err = miss(find_operation(&ApiDoc::openapi(), "get", "/nope"));

        assert!(
            matches!(err, OperationNotFound::UnknownMethod { .. }),
            "a typo'd method must not be masked by the path it was paired with: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("`get` is not an HTTP method spelling"),
            "{msg}"
        );
        assert!(
            msg.contains("/nope"),
            "the message should still name what was being looked up: {msg}"
        );
    }

    /// The `documented` list is lexicographic — the order
    /// [`documented_pairs`] yields for one path — not `ALL_HTTP_METHODS` slot
    /// order.
    ///
    /// `/widgets/{id}` is the path that can tell those apart: it documents
    /// six methods whose slot order (PUT, DELETE, OPTIONS, HEAD, PATCH,
    /// TRACE) and lexicographic order (DELETE, HEAD, OPTIONS, PATCH, PUT,
    /// TRACE) share no prefix. A two- or three-method path mostly cannot —
    /// GET+POST, for instance, sorts the same either way, which would make
    /// this test vacuous.
    #[test]
    fn the_documented_method_list_is_sorted_not_in_slot_order() {
        let spec = ApiDoc::openapi();

        // GET is the one method `/widgets/{id}` does not document.
        let err = miss(find_operation(&spec, "GET", "/widgets/{id}"));

        let OperationNotFound::Method { documented, .. } = &err else {
            panic!("expected a missing-method miss: {err:?}");
        };
        assert_eq!(
            documented,
            &["DELETE", "HEAD", "OPTIONS", "PATCH", "PUT", "TRACE"],
            "slot order would start PUT, DELETE, OPTIONS — this must be sorted"
        );
        assert!(
            err.to_string()
                .contains("it documents: DELETE, HEAD, OPTIONS, PATCH, PUT, TRACE"),
            "{err}"
        );

        // The claim the field docs make, asserted rather than asserted-about:
        // this is the order `documented_pairs` puts the same methods in.
        let from_pairs: Vec<String> = documented_pairs(&spec)
            .into_iter()
            .filter(|(_, path)| path == "/widgets/{id}")
            .map(|(method, _)| method)
            .collect();
        assert_eq!(from_pairs, *documented);
    }

    /// A path key that documents nothing at all. `PathItem` derives
    /// `Default` and all eight operation fields are `Option`, so this is
    /// constructible — and deserializable from `{"paths": {"/x": {}}}` —
    /// which makes the empty `documented` list reachable rather than
    /// theoretical. The message must not trail off after "it documents:".
    #[test]
    fn a_path_documenting_no_operations_is_phrased_as_such() {
        let mut spec = ApiDoc::openapi();
        spec.paths
            .paths
            .insert("/empty".to_string(), PathItem::default());

        let err = miss(find_operation(&spec, "GET", "/empty"));

        let OperationNotFound::Method { documented, .. } = &err else {
            panic!("the path exists, so this is a missing-method miss: {err:?}");
        };
        assert!(documented.is_empty(), "{documented:?}");

        let msg = err.to_string();
        assert!(msg.contains("documents no operations at all"), "{msg}");
        assert!(
            !msg.contains("it documents: )") && !msg.ends_with("()"),
            "an empty list must not render as a dangling parenthetical: {msg}"
        );
    }

    #[test]
    fn expect_operation_returns_the_operation_when_it_is_documented() {
        let spec = ApiDoc::openapi();

        let op = expect_operation(&spec, "POST", "/widgets");
        let codes: Vec<&str> = op.responses.responses.keys().map(String::as_str).collect();
        assert_eq!(codes, ["201"]);
    }

    #[test]
    #[should_panic(expected = "has no path `/nope`")]
    fn expect_operation_panics_naming_a_missing_path() {
        expect_operation(&ApiDoc::openapi(), "GET", "/nope");
    }

    #[test]
    #[should_panic(expected = "no `DELETE` operation")]
    fn expect_operation_panics_naming_a_missing_method_distinctly() {
        expect_operation(&ApiDoc::openapi(), "DELETE", "/widgets");
    }

    #[test]
    fn check_committed_spec_accepts_a_file_written_the_documented_way() {
        let dir = tempfile::tempdir().unwrap();
        let spec = ApiDoc::openapi();
        let path = write_spec_file(dir.path(), &expected_file_contents(&spec));

        check_committed_spec(&path, &spec, REGEN).expect("a freshly written file is fresh");
    }

    #[test]
    fn check_committed_spec_reports_a_missing_file_with_the_regeneration_command() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("openapi.json");

        let err = check_committed_spec(&path, &ApiDoc::openapi(), REGEN)
            .expect_err("the file does not exist");

        assert!(matches!(err, SpecFreshnessError::Read { .. }));
        let msg = err.to_string();
        assert!(msg.contains("openapi.json"), "{msg}");
        assert!(msg.contains(REGEN), "{msg}");
    }

    #[test]
    fn check_committed_spec_names_the_first_differing_line() {
        let dir = tempfile::tempdir().unwrap();
        let spec = ApiDoc::openapi();
        let stale = expected_file_contents(&spec).replace("/widgets", "/gadgets");
        let path = write_spec_file(dir.path(), &stale);

        let err = check_committed_spec(&path, &spec, REGEN).expect_err("the paths were renamed");

        let msg = err.to_string();
        assert!(msg.contains("first difference at line"), "{msg}");
        assert!(msg.contains("gadgets"), "{msg}");
        assert!(msg.contains(REGEN), "{msg}");
    }

    #[test]
    fn a_missing_trailing_newline_is_reported_as_such() {
        let dir = tempfile::tempdir().unwrap();
        let spec = ApiDoc::openapi();
        let path = write_spec_file(dir.path(), &to_pretty_json(&spec));

        let err = check_committed_spec(&path, &spec, REGEN).expect_err("no trailing newline");

        let msg = err.to_string();
        assert!(msg.contains("trailing newline"), "{msg}");
    }

    /// The regression guard for the failure that has no way out: a Windows
    /// checkout with `core.autocrlf=true` rewrites the committed LF spec to
    /// CRLF on disk, the export writes LF, and the byte comparison fails
    /// forever. `str::lines()` strips the trailing `\r`, so without an
    /// explicit CRLF check the report would say the two files are
    /// line-for-line identical.
    #[test]
    fn a_crlf_checkout_is_named_as_such_and_told_how_to_fix_it() {
        let dir = tempfile::tempdir().unwrap();
        let spec = ApiDoc::openapi();
        let crlf = expected_file_contents(&spec).replace('\n', "\r\n");
        let path = write_spec_file(dir.path(), &crlf);

        let err = check_committed_spec(&path, &spec, REGEN)
            .expect_err("CRLF is not what the export writes");

        let msg = err.to_string();
        assert!(msg.contains("CRLF"), "{msg}");
        assert!(
            msg.contains("the content is otherwise identical"),
            "only the line endings differ, and the report should say so: {msg}"
        );
        assert!(
            msg.contains("openapi.json text eol=lf"),
            "the report must name the exact .gitattributes line that fixes it: {msg}"
        );
        assert!(
            !msg.contains("first difference at line"),
            "a CRLF file must not be reported as an ordinary line diff: {msg}"
        );
    }

    #[test]
    fn a_crlf_file_that_also_drifted_says_there_is_more_than_line_endings() {
        let dir = tempfile::tempdir().unwrap();
        let spec = ApiDoc::openapi();
        let crlf = expected_file_contents(&spec)
            .replace("/widgets", "/gadgets")
            .replace('\n', "\r\n");
        let path = write_spec_file(dir.path(), &crlf);

        let err = check_committed_spec(&path, &spec, REGEN).expect_err("CRLF plus a rename");

        let msg = err.to_string();
        assert!(msg.contains("CRLF"), "{msg}");
        assert!(msg.contains("content differences on top of that"), "{msg}");
    }

    #[test]
    fn a_truncated_committed_file_says_where_it_stops() {
        let dir = tempfile::tempdir().unwrap();
        let spec = ApiDoc::openapi();
        let full = expected_file_contents(&spec);
        let head: String = full.lines().take(3).map(|l| format!("{l}\n")).collect();
        let path = write_spec_file(dir.path(), &head);

        let err = check_committed_spec(&path, &spec, REGEN).expect_err("the file is truncated");

        let msg = err.to_string();
        assert!(msg.contains("stops at line 3"), "{msg}");
    }

    #[test]
    fn a_long_differing_line_is_truncated_in_the_report() {
        let long = "x".repeat(MAX_QUOTED_LINE * 2);
        let detail =
            describe_difference(Path::new("openapi.json"), &format!("{long}\n"), "short\n");

        assert!(detail.contains("(truncated)"), "{detail}");
        assert!(detail.len() < long.len(), "{detail}");
    }

    #[test]
    fn assert_committed_spec_is_fresh_passes_on_a_fresh_file() {
        let dir = tempfile::tempdir().unwrap();
        let spec = ApiDoc::openapi();
        let path = write_spec_file(dir.path(), &expected_file_contents(&spec));

        assert_committed_spec_is_fresh(&path, &spec, REGEN);
    }

    #[test]
    #[should_panic(expected = "is stale")]
    fn assert_committed_spec_is_fresh_panics_with_the_report() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_spec_file(dir.path(), "{}\n");

        assert_committed_spec_is_fresh(&path, &ApiDoc::openapi(), REGEN);
    }
}
