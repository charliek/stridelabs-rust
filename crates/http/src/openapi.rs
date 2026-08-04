//! OpenAPI mechanics for services that document themselves with `utoipa`
//! (feature `openapi`): a canonicalizing serializer, an exhaustive
//! `(method, path)` enumerator, and a committed-spec freshness check.
//!
//! Extracted from slauth's `src/http/openapi.rs` and
//! `tests/openapi_shape.rs`, which had all three and needed none of them to
//! be about slauth. Every function here takes a
//! [`utoipa::openapi::OpenApi`] that the *caller* built and knows nothing
//! about what is in it.
//!
//! # What this deliberately does not do
//!
//! There is no `ApiDoc` here, no security schemes, no `info`/`servers`/`tags`
//! block, no route list, no exclusion list, and no Swagger-UI wiring. All of
//! that is **policy**: slauth documents a Kratos session cookie plus a
//! `slp_live_…` PAT bearer, spendwise documents a slauth-issued JWT bearer
//! plus a PAT bearer with a different prefix, and neither one's document root
//! is a thing the other could adopt. A "spec builder" in a shared crate would
//! have to guess at that shape and would be wrong for at least one consumer,
//! so the shape stays in the service and only the mechanics live here.
//!
//! Two conventions are worth carrying across services even though they are
//! not code and cannot be enforced from here:
//!
//! - **Exclusion should be structural, not a maintained list.** A route
//!   reaches the document by its router module being an
//!   `utoipa_axum::router::OpenApiRouter` built with `.routes(routes!(…))`,
//!   which is also that route's only way onto the wire. Then forgetting to
//!   annotate a new route is a route that 404s in production — loud —
//!   rather than a silent hole in the spec, and the modules that must stay
//!   *out* (health checks, webhooks, static fallbacks, reverse proxies that
//!   publish their own contracts) stay out because they never import
//!   `utoipa` at all. There is no flag to flip and no list to keep in sync.
//! - **Apply a version prefix with `OpenApiRouter::nest`, never `merge`.**
//!   `nest` rewrites the OpenAPI path keys with the same prefix it gives the
//!   underlying axum routes; `merge` gives the axum routes the prefix and
//!   leaves the documented paths at their unprefixed literals. The two then
//!   drift apart silently, and the document describes URLs the service does
//!   not serve. [`documented_pairs`] plus a committed expectation is the
//!   cheap guard against having got this wrong.
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
/// no `PathItemType` type at all; `PathItem::new` and
/// `PathItem::merge_operations` inside utoipa itself both `match` an
/// `HttpMethod` onto those same eight fields. Driving them from an exhaustive
/// match is the closest available equivalent.
pub const ALL_HTTP_METHODS: [HttpMethod; 8] = [
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
pub fn operation_for<'a>(item: &'a PathItem, method: &HttpMethod) -> Option<&'a Operation> {
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
pub fn method_name(method: &HttpMethod) -> &'static str {
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
/// Genuinely exhaustive over the operation slots `utoipa` models
/// ([`ALL_HTTP_METHODS`]), so a route registered under a method the calling
/// test never mentions by name still shows up. The `BTreeSet` return makes
/// `assert_eq!` against a hand-written expectation both order-insensitive and
/// readable when it fails.
///
/// This is the primitive behind the "the documented surface is exactly this
/// list" test: a route added without `#[utoipa::path]`, or annotated when it
/// should have stayed excluded, changes this set.
///
/// ```
/// use std::collections::BTreeSet;
/// use stridelabs_http::openapi::documented_pairs;
/// use utoipa::OpenApi;
///
/// #[utoipa::path(get, path = "/widgets", responses((status = 200, description = "ok")))]
/// fn list_widgets() {}
///
/// #[derive(OpenApi)]
/// #[openapi(paths(list_widgets))]
/// struct ApiDoc;
///
/// let expected: BTreeSet<(String, String)> =
///     [("GET", "/widgets")].into_iter().map(|(m, p)| (m.to_string(), p.to_string())).collect();
/// assert_eq!(documented_pairs(&ApiDoc::openapi()), expected);
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

/// The [`Operation`] documented at `method` + `path`, addressed the way a
/// test table spells it (`("GET", "/api/v1/session")`) rather than through an
/// [`HttpMethod`] value.
///
/// Exists so a per-route assertion (documented status codes, security
/// requirements, response schemas) doesn't have to re-derive the
/// string-to-[`HttpMethod`] lookup that [`method_name`] already encodes.
/// Returns `None` for both "no such path" and "no such method on that path" —
/// a caller wanting to tell those apart should reach into `spec.paths.paths`
/// itself.
///
/// `method` is matched case-sensitively against [`method_name`]'s uppercase
/// spellings; an unrecognized spelling is `None`, not a panic.
pub fn find_operation<'a>(spec: &'a OpenApi, method: &str, path: &str) -> Option<&'a Operation> {
    let item = spec.paths.paths.get(path)?;
    let method = ALL_HTTP_METHODS.iter().find(|m| method_name(m) == method)?;
    operation_for(item, method)
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
/// to accept it: [`to_pretty_json`] plus **one trailing newline**.
///
/// The newline is not decoration. The export side is a CLI subcommand that
/// `println!`s the spec and is redirected to the file (`svc openapi >
/// openapi.json`), and `println!` appends exactly one `\n`; POSIX text files
/// end in a newline, and every editor, `git diff` and "no newline at end of
/// file" marker agrees. Both halves of the convention are owned here so the
/// exporter and the test cannot disagree about it.
pub fn committed_file_contents(spec: &OpenApi) -> String {
    format!("{}\n", to_pretty_json(spec))
}

/// Why a committed OpenAPI file failed its freshness check.
///
/// [`std::fmt::Display`] is the whole point: it renders a multi-line report
/// naming the file, the first line that differs, and the exact command to
/// regenerate it. Callers are expected to surface it verbatim.
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
/// The comparison is against [`committed_file_contents`], i.e. pretty JSON
/// plus one trailing newline.
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

    let fresh = committed_file_contents(spec);
    if committed == fresh {
        return Ok(());
    }

    Err(SpecFreshnessError::Stale {
        path: path.to_path_buf(),
        regenerate_command: regenerate_command.to_string(),
        detail: describe_difference(&committed, &fresh),
    })
}

/// [`check_committed_spec`], panicking with the rendered report.
///
/// A panicking form is the right one for a test even though this crate
/// otherwise returns typed errors: `assert_committed_spec_is_fresh(…)` on one
/// line *is* the assertion, whereas the `Result` form makes every consumer
/// write the same `if let Err(e) = … { panic!("{e}") }` three-liner and get
/// the message formatting subtly different each time. The panic message is
/// the error's `Display`, which already names the file, the first differing
/// line and the regeneration command — so nothing is lost versus asserting by
/// hand, and the "stale spec" diff stays identical across services.
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

/// Describe the first way `committed` differs from `fresh`, in the terms
/// someone staring at a red CI job needs.
///
/// The trailing-newline cases are called out by name because they are the
/// ones that produce a "the files look identical" diff: an editor configured
/// to strip final newlines, or an exporter switched from `println!` to
/// `print!`, changes exactly one invisible byte.
fn describe_difference(committed: &str, fresh: &str) -> String {
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
        std::cmp::Ordering::Equal => "the files differ only in line endings".to_string(),
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

    fn pairs(pairs: &[(&str, &str)]) -> BTreeSet<(String, String)> {
        pairs
            .iter()
            .map(|(m, p)| (m.to_string(), p.to_string()))
            .collect()
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

    #[test]
    fn to_pretty_json_sorts_object_keys_at_every_nesting_level() {
        // Exercises `canonicalize` directly with deliberately unsorted input,
        // which is the only way to see the sort happen: whether the document
        // types themselves arrive sorted depends on the very Cargo features
        // this function exists to be immune to.
        let value = serde_json::json!({
            "zebra": 1,
            "alpha": {"z": [{"c": 3, "a": 1}], "a": 2},
        });

        let rendered = serde_json::to_string(&canonicalize(value)).unwrap();

        assert_eq!(
            rendered,
            r#"{"alpha":{"a":2,"z":[{"a":1,"c":3}]},"zebra":1}"#
        );
    }

    #[test]
    fn to_pretty_json_emits_no_trailing_newline() {
        // The exporter's `println!` supplies it; `committed_file_contents` is
        // the one place the convention lives.
        let rendered = to_pretty_json(&ApiDoc::openapi());
        assert!(!rendered.ends_with('\n'), "{rendered:?}");
        assert_eq!(committed_file_contents(&ApiDoc::openapi()), rendered + "\n");
    }

    #[test]
    fn documented_pairs_covers_every_http_method() {
        assert_eq!(
            documented_pairs(&ApiDoc::openapi()),
            pairs(&[
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
    fn find_operation_addresses_a_route_by_its_table_spelling() {
        let spec = ApiDoc::openapi();

        let op = find_operation(&spec, "POST", "/widgets").expect("POST /widgets is documented");
        let codes: Vec<&str> = op.responses.responses.keys().map(String::as_str).collect();
        assert_eq!(codes, ["201"]);
    }

    #[test]
    fn find_operation_is_none_for_an_undocumented_method_path_or_spelling() {
        let spec = ApiDoc::openapi();

        assert!(find_operation(&spec, "DELETE", "/widgets").is_none());
        assert!(find_operation(&spec, "GET", "/nope").is_none());
        assert!(
            find_operation(&spec, "get", "/widgets").is_none(),
            "the table spelling is uppercase; a lowercase one is a typo, not a lookup"
        );
    }

    #[test]
    fn check_committed_spec_accepts_a_file_written_the_documented_way() {
        let dir = tempfile::tempdir().unwrap();
        let spec = ApiDoc::openapi();
        let path = write_spec_file(dir.path(), &committed_file_contents(&spec));

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
        let stale = committed_file_contents(&spec).replace("/widgets", "/gadgets");
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

    #[test]
    fn a_truncated_committed_file_says_where_it_stops() {
        let dir = tempfile::tempdir().unwrap();
        let spec = ApiDoc::openapi();
        let full = committed_file_contents(&spec);
        let head: String = full.lines().take(3).map(|l| format!("{l}\n")).collect();
        let path = write_spec_file(dir.path(), &head);

        let err = check_committed_spec(&path, &spec, REGEN).expect_err("the file is truncated");

        let msg = err.to_string();
        assert!(msg.contains("stops at line 3"), "{msg}");
    }

    #[test]
    fn a_long_differing_line_is_truncated_in_the_report() {
        let long = "x".repeat(MAX_QUOTED_LINE * 2);
        let detail = describe_difference(&format!("{long}\n"), "short\n");

        assert!(detail.contains("(truncated)"), "{detail}");
        assert!(detail.len() < long.len(), "{detail}");
    }

    #[test]
    fn assert_committed_spec_is_fresh_passes_on_a_fresh_file() {
        let dir = tempfile::tempdir().unwrap();
        let spec = ApiDoc::openapi();
        let path = write_spec_file(dir.path(), &committed_file_contents(&spec));

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
