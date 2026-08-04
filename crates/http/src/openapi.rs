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
/// string-to-[`HttpMethod`] lookup, which is the same mapping
/// [`documented_pairs`] emits on its way out.
/// Returns `None` for both "no such path" and "no such method on that path" —
/// a caller wanting to tell those apart should reach into `spec.paths.paths`
/// itself.
///
/// `method` is matched case-sensitively against the uppercase wire spellings
/// (`"GET"`, `"DELETE"`, …); an unrecognized spelling is `None`, not a panic.
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
pub fn committed_file_contents(spec: &OpenApi) -> String {
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
/// The comparison is against [`committed_file_contents`] and is exact: pretty
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

    let fresh = committed_file_contents(spec);
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
        let crlf = committed_file_contents(&spec).replace('\n', "\r\n");
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
        let crlf = committed_file_contents(&spec)
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
        let detail =
            describe_difference(Path::new("openapi.json"), &format!("{long}\n"), "short\n");

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
