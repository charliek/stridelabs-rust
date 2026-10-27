//! The crate's two source guards (no feature, no service, so they run in
//! every lane): the core names no provider, and the crate builds no client
//! of its own. The build-graph guards (no provider in the core build, no
//! crypto provider selected) read `cargo tree` and are CI steps instead
//! ("Guard: stridelabs-voice ..." in `.github/workflows/ci.yml`).
//!
//! Each scan is a pure function over `(path, source)` pairs, so the tests
//! below it can plant a violation and watch the scan find it (the controls),
//! and the real scans then run over this crate's own `src/`.
//!
//! The own-client and `Message` scans read TOKENS ([`tokenize`]), not lines:
//! comments removed, whitespace (newlines included) gone, strings single
//! tokens. So an alias (`use tokio_tungstenite::connect_async as dial;`), a
//! `use` list over several lines with a comment in it, a path split over
//! lines and an imported `Client::new()` are as visible as the plain call.
//! The module stripper ([`without_test_modules`]) removes only a module
//! preceded by a test-only `#[cfg(..)]` attribute, by balanced braces.

use std::path::{Path, PathBuf};

/// The adapter modules (and anything under a directory of the same name):
/// the only source that may name a provider.
const ADAPTERS: [&str; 2] = ["muse", "inworld"];

/// What the core must not name, compared case-insensitively as a substring,
/// comments and strings included. `meta.ai` is Muse's host.
const PROVIDER_WORDS: [&str; 3] = ["muse", "inworld", "meta.ai"];

/// The one exception to the scan: `lib.rs`'s lines that declare the adapter
/// modules and gate `LOG_CAPS` (and its test) on `any(axum, muse)`. Compared
/// as a whole trimmed line, in `lib.rs` only, with the exact number of times
/// each stands: a line anywhere else, a different line, a second copy or a
/// missing one (a stale entry) fails.
const ALLOWED: [(&str, usize); 5] = [
    (r#"#[cfg(feature = "inworld")]"#, 1),
    ("pub mod inworld;", 1),
    (r#"#[cfg(feature = "muse")]"#, 1),
    ("pub mod muse;", 1),
    (r#"#[cfg(any(feature = "axum", feature = "muse"))]"#, 2),
];

/// What the crate builds no client of its own means, read as TOKENS (the
/// module docs): any of these identifiers anywhere in the code, whatever the
/// import or alias that brings it in, is a client, a builder or a dial the
/// app did not hand in. The Muse dial is `connect_async_tls_with_config`
/// with the app's connector, a different identifier.
const OWN_CLIENT_IDENTS: [&str; 5] = [
    "ClientBuilder",
    "ClientConfig",
    "client_builder",
    "connect_async",
    "connect_async_with_config",
];

/// What only the crate's own test code may name: a connector built in
/// place (the variants of `tokio_tungstenite::Connector`, however imported).
const OWN_CONNECTOR_IDENTS: [&str; 2] = ["Rustls", "Plain"];

/// A source file: its path under `src/`, `/`-separated, and its text.
struct Source {
    path: String,
    text: String,
}

/// One token of Rust source: what the scans read instead of lines, so a
/// path, a `use` list or a call split over lines (or with a comment in the
/// middle) is one sequence. Comments are gone; a string is its content.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Ident(String),
    Punct(char),
    Str(String),
    Other,
}

#[derive(Clone, Debug)]
struct Tok {
    kind: Kind,
    line: usize,
}

impl Tok {
    fn is_ident(&self, name: &str) -> bool {
        matches!(&self.kind, Kind::Ident(ident) if ident == name)
    }

    fn is_punct(&self, punct: char) -> bool {
        self.kind == Kind::Punct(punct)
    }

    fn ident(&self) -> Option<&str> {
        match &self.kind {
            Kind::Ident(ident) => Some(ident),
            _ => None,
        }
    }
}

/// `text` as tokens: line and nested block comments removed, string
/// literals (`"..."`, `b"..."`, `r#"..."#`) whole, char literals told from
/// lifetimes, identifiers, numbers and single punctuation characters.
fn tokenize(text: &str) -> Vec<Tok> {
    let chars: Vec<char> = text.chars().collect();
    let at = |i: usize| chars.get(i).copied();
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c.is_whitespace() {
            i += 1;
        } else if c == '/' && at(i + 1) == Some('/') {
            while at(i).is_some_and(|c| c != '\n') {
                i += 1;
            }
        } else if c == '/' && at(i + 1) == Some('*') {
            let mut depth = 0;
            while i < chars.len() {
                match (chars[i], at(i + 1)) {
                    ('/', Some('*')) => {
                        depth += 1;
                        i += 2;
                    }
                    ('*', Some('/')) => {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    }
                    ('\n', _) => {
                        line += 1;
                        i += 1;
                    }
                    _ => i += 1,
                }
            }
        } else if let Some((content_from, hashes)) = raw_string_start(&chars, i) {
            // r"..." / r#"..."# / br#"..."#: ends at a quote and as many hashes.
            let closing: Vec<char> = std::iter::once('"')
                .chain(std::iter::repeat_n('#', hashes))
                .collect();
            let mut end = content_from;
            while end < chars.len() && chars[end..].get(..closing.len()) != Some(&closing[..]) {
                end += 1;
            }
            let content: String = chars[content_from..end.min(chars.len())].iter().collect();
            tokens.push(Tok {
                kind: Kind::Str(content.clone()),
                line,
            });
            line += content.matches('\n').count();
            i = (end + closing.len()).min(chars.len());
        } else if c == '"' || (c == 'b' && at(i + 1) == Some('"')) {
            let first_line = line;
            i += if c == 'b' { 2 } else { 1 };
            let mut content = String::new();
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' {
                    i += 1;
                }
                if let Some(&escaped) = chars.get(i) {
                    if escaped == '\n' {
                        line += 1;
                    }
                    content.push(escaped);
                }
                i += 1;
            }
            i += 1;
            tokens.push(Tok {
                kind: Kind::Str(content),
                line: first_line,
            });
        } else if c == '\'' {
            // A char literal (`'a'`, `'\n'`, `'"'`, `'}'`) or a lifetime.
            let is_char = at(i + 1) == Some('\\') || at(i + 2) == Some('\'');
            if is_char {
                i += 1;
                if at(i) == Some('\\') {
                    i += 1;
                }
                i += 1;
                while at(i).is_some_and(|c| c != '\'') {
                    i += 1;
                }
                i += 1;
            } else {
                i += 1;
                while at(i).is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    i += 1;
                }
            }
            tokens.push(Tok {
                kind: Kind::Other,
                line,
            });
        } else if c.is_alphabetic() || c == '_' {
            let from = i;
            while at(i).is_some_and(|c| c.is_alphanumeric() || c == '_') {
                i += 1;
            }
            tokens.push(Tok {
                kind: Kind::Ident(chars[from..i].iter().collect()),
                line,
            });
        } else if c.is_ascii_digit() {
            while at(i).is_some_and(|c| c.is_alphanumeric() || c == '_') {
                i += 1;
            }
            tokens.push(Tok {
                kind: Kind::Other,
                line,
            });
        } else {
            tokens.push(Tok {
                kind: Kind::Punct(c),
                line,
            });
            i += 1;
        }
    }
    tokens
}

/// Where a raw string literal starting at `i` has its content, and its hash
/// count: `r"`, `r#"`, `br"`, `br#"`.
fn raw_string_start(chars: &[char], i: usize) -> Option<(usize, usize)> {
    let mut at = i;
    if chars.get(at) == Some(&'b') {
        at += 1;
    }
    if chars.get(at) != Some(&'r') {
        return None;
    }
    at += 1;
    let hashes = chars[at..].iter().take_while(|&&c| c == '#').count();
    (chars.get(at + hashes) == Some(&'"')).then_some((at + hashes + 1, hashes))
}

/// The index just past the group opened by `tokens[open]` (`(`, `[` or
/// `{`), found by balancing all three kinds, or `tokens.len()` if it never
/// closes. Strings and chars are single tokens, so a brace in one is not
/// counted.
fn group_end(tokens: &[Tok], open: usize) -> usize {
    let mut depth = 0usize;
    for (at, token) in tokens.iter().enumerate().skip(open) {
        match token.kind {
            Kind::Punct('(' | '[' | '{') => depth += 1,
            Kind::Punct(')' | ']' | '}') => {
                depth -= 1;
                if depth == 0 {
                    return at + 1;
                }
            }
            _ => {}
        }
    }
    tokens.len()
}

/// Whether a `cfg` predicate holds only in test code: `test`, or the
/// `test-support` feature, an `any` of those, an `all` with one of them;
/// never a `not`, any other feature, or anything unread.
fn cfg_is_test_only(tokens: &[Tok]) -> bool {
    match tokens {
        [first, ..] if first.is_ident("test") => true,
        [first, eq, value, ..]
            if first.is_ident("feature")
                && eq.is_punct('=')
                && value.kind == Kind::Str("test-support".into()) =>
        {
            true
        }
        [name, open, ..]
            if open.is_punct('(') && (name.is_ident("any") || name.is_ident("all")) =>
        {
            let end = group_end(tokens, 1);
            let inside = &tokens[2..end.saturating_sub(1).max(2)];
            let mut parts = Vec::new();
            let (mut from, mut depth) = (0, 0usize);
            for (at, token) in inside.iter().enumerate() {
                match token.kind {
                    Kind::Punct('(' | '[' | '{') => depth += 1,
                    Kind::Punct(')' | ']' | '}') => depth = depth.saturating_sub(1),
                    Kind::Punct(',') if depth == 0 => {
                        parts.push(&inside[from..at]);
                        from = at + 1;
                    }
                    _ => {}
                }
            }
            parts.push(&inside[from..]);
            let mut results = parts
                .into_iter()
                .filter(|part| !part.is_empty())
                .map(cfg_is_test_only);
            if name.is_ident("any") {
                let (mut all, mut any) = (true, false);
                for result in results {
                    all &= result;
                    any = true;
                }
                any && all
            } else {
                results.any(|result| result)
            }
        }
        _ => false,
    }
}

/// `tokens` without every `mod name { .. }` (or `mod name;`) that is
/// preceded by a test-only `#[cfg(..)]` ([`cfg_is_test_only`]), by balanced
/// braces: an empty `{}` closes at once, a string or char holding a brace
/// counts for nothing. A module without such an attribute is kept, whatever
/// it is called.
fn without_test_modules(tokens: &[Tok]) -> Vec<Tok> {
    let mut kept = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if !(tokens[i].is_punct('#') && tokens.get(i + 1).is_some_and(|t| t.is_punct('['))) {
            kept.push(tokens[i].clone());
            i += 1;
            continue;
        }
        // A run of attributes.
        let run_start = i;
        let mut test_only = false;
        while tokens[i..].len() > 1 && tokens[i].is_punct('#') && tokens[i + 1].is_punct('[') {
            let end = group_end(tokens, i + 1);
            let attribute = &tokens[i + 2..end.saturating_sub(1).max(i + 2)];
            if let [cfg, open, rest @ ..] = attribute {
                if cfg.is_ident("cfg") && open.is_punct('(') {
                    test_only |= cfg_is_test_only(&rest[..rest.len().saturating_sub(1)]);
                }
            }
            i = end;
        }
        let mut item = i;
        if tokens.get(item).is_some_and(|t| t.is_ident("pub")) {
            item += 1;
            if tokens.get(item).is_some_and(|t| t.is_punct('(')) {
                item = group_end(tokens, item);
            }
        }
        let is_module = tokens.get(item).is_some_and(|t| t.is_ident("mod"))
            && tokens.get(item + 1).and_then(Tok::ident).is_some();
        if test_only && is_module {
            match tokens.get(item + 2) {
                Some(t) if t.is_punct('{') => i = group_end(tokens, item + 2),
                Some(t) if t.is_punct(';') => i = item + 3,
                _ => i = item + 2,
            }
        } else {
            kept.extend_from_slice(&tokens[run_start..i]);
        }
    }
    kept
}

/// The identifiers of the path that ends just before `tokens[at]`
/// (`a::b::` before `c`), nearest first.
fn path_before(tokens: &[Tok], at: usize) -> Vec<&str> {
    let mut path = Vec::new();
    let mut at = at;
    while at >= 3 && tokens[at - 1].is_punct(':') && tokens[at - 2].is_punct(':') {
        match tokens[at - 3].ident() {
            Some(ident) => path.push(ident),
            None => break,
        }
        at -= 3;
    }
    path
}

/// `use` items as token ranges (from `use` to its `;`).
fn use_items(tokens: &[Tok]) -> Vec<(usize, usize)> {
    let mut items = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i].is_ident("use") {
            let end = (i..tokens.len())
                .find(|&at| tokens[at].is_punct(';'))
                .unwrap_or(tokens.len() - 1);
            items.push((i, end));
            i = end;
        }
        i += 1;
    }
    items
}

/// Every use of the provider transport's `Message` in `tokens`: a `use`
/// item that names `tungstenite` (or `tokio_tungstenite`) and `Message`
/// anywhere in it (a list, an alias, a comment between, any number of
/// lines), a `tungstenite` glob, or a path to `Message` through
/// `tungstenite`. Returns the lines.
fn tungstenite_message_lines(tokens: &[Tok]) -> Vec<usize> {
    let names = |token: &Tok| token.is_ident("tungstenite") || token.is_ident("tokio_tungstenite");
    let mut lines = Vec::new();
    for (from, to) in use_items(tokens) {
        let item = &tokens[from..=to];
        if item.iter().any(names)
            && item
                .iter()
                .any(|token| token.is_ident("Message") || token.is_punct('*'))
        {
            lines.push(tokens[from].line);
        }
    }
    for (at, token) in tokens.iter().enumerate() {
        if token.is_ident("Message")
            && path_before(tokens, at)
                .iter()
                .any(|part| *part == "tungstenite" || *part == "tokio_tungstenite")
        {
            lines.push(token.line);
        }
    }
    lines.sort_unstable();
    lines.dedup();
    lines
}

/// Every own-client finding in `tokens` as `(line, what)`. Anywhere in the
/// code: the identifiers of [`OWN_CLIENT_IDENTS`] (a `use` of them, aliased
/// or not, is the identifier too), a `reqwest` path to `Client`, an
/// imported `Client::new` / `Client::builder` / `Client::default`,
/// `InworldClient::builder`, a `use` that names `reqwest` and a client type
/// or a glob, and a `use` glob of `tokio_tungstenite`. Outside test-only
/// modules ([`without_test_modules`]): a connector variant
/// ([`OWN_CONNECTOR_IDENTS`]).
fn own_client_findings(tokens: &[Tok]) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        let Some(ident) = token.ident() else { continue };
        let next_path = |n: usize| tokens.get(at + n).and_then(Tok::ident);
        let colons = tokens.get(at + 1).is_some_and(|t| t.is_punct(':'))
            && tokens.get(at + 2).is_some_and(|t| t.is_punct(':'));
        if OWN_CLIENT_IDENTS.contains(&ident) {
            found.push((token.line, format!("`{ident}`")));
        } else if ident == "Client"
            && colons
            && matches!(next_path(3), Some("new" | "builder" | "default"))
        {
            found.push((
                token.line,
                format!("`Client::{}`", next_path(3).unwrap_or("")),
            ));
        } else if ident == "InworldClient" && colons && next_path(3) == Some("builder") {
            found.push((token.line, "`InworldClient::builder`".to_owned()));
        } else if ident == "Client" && path_before(tokens, at).contains(&"reqwest") {
            found.push((token.line, "`reqwest::Client`".to_owned()));
        }
    }
    for (from, to) in use_items(tokens) {
        let item = &tokens[from..=to];
        let names = |name: &str| item.iter().any(|token| token.is_ident(name));
        let glob = item.iter().any(|token| token.is_punct('*'));
        if (names("reqwest") && (names("Client") || glob)) || (names("tokio_tungstenite") && glob) {
            found.push((
                tokens[from].line,
                "an import of a client or a glob of its crate".to_owned(),
            ));
        }
    }
    for token in without_test_modules(tokens) {
        if let Some(ident) = token.ident() {
            if OWN_CONNECTOR_IDENTS.contains(&ident) {
                found.push((token.line, format!("the connector `{ident}`")));
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

fn is_adapter(path: &str) -> bool {
    let first = path.split('/').next().unwrap_or("");
    ADAPTERS
        .iter()
        .any(|adapter| first == format!("{adapter}.rs") || first == *adapter)
}

/// Every provider name the core carries outside the allowlist, as
/// `path:line: text`, every use of tungstenite's `Message` in it
/// ([`tungstenite_message_lines`]), and every allowlist entry that does not
/// stand exactly as often as it should.
fn core_violations(sources: &[Source]) -> Vec<String> {
    let mut found = Vec::new();
    let mut allowed_seen = [0usize; ALLOWED.len()];
    for source in sources.iter().filter(|source| !is_adapter(&source.path)) {
        for (index, line) in source.text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if !PROVIDER_WORDS.iter().any(|word| lower.contains(word)) {
                continue;
            }
            let entry = if source.path == "lib.rs" {
                ALLOWED.iter().position(|(text, _)| line.trim() == *text)
            } else {
                None
            };
            match entry {
                Some(entry) => allowed_seen[entry] += 1,
                None => found.push(format!("{}:{}: {}", source.path, index + 1, line.trim())),
            }
        }
        for line in tungstenite_message_lines(&tokenize(&source.text)) {
            found.push(format!("{}:{line}: tungstenite's Message", source.path));
        }
    }
    for ((text, expected), seen) in ALLOWED.iter().zip(allowed_seen) {
        if seen != *expected {
            found.push(format!(
                "lib.rs: the allowlisted line `{text}` stands {seen} time(s), not {expected}"
            ));
        }
    }
    found
}

/// Every own-client finding in `sources`, as `path:line: what`.
fn own_client_violations(sources: &[Source]) -> Vec<String> {
    sources
        .iter()
        .flat_map(|source| {
            own_client_findings(&tokenize(&source.text))
                .into_iter()
                .map(|(line, what)| format!("{}:{line}: {what}", source.path))
        })
        .collect()
}

fn read_sources() -> Vec<Source> {
    fn walk(root: &Path, dir: &Path, into: &mut Vec<Source>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
            .map(|entry| entry.expect("a directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(root, &path, into);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let relative = path
                    .strip_prefix(root)
                    .expect("under src")
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                into.push(Source {
                    path: relative,
                    text,
                });
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    walk(&root, &root, &mut sources);
    // A scan over a mis-rooted or empty directory would pass for the wrong
    // reason: it must have seen the core, an adapter and both flows.
    for expected in ["lib.rs", "relay.rs", "stream.rs", "muse.rs", "inworld.rs"] {
        assert!(
            sources.iter().any(|source| source.path == expected),
            "the scan did not see src/{expected} ({} files)",
            sources.len()
        );
    }
    sources
}

/// **The core names no provider:** no source outside the two adapters
/// contains `muse`, `inworld` or `meta.ai` (any case, comments and strings
/// included) or names `tungstenite::Message`, but `lib.rs`'s allowlisted
/// lines. A provider-neutral core is what a second provider's adapter
/// relies on.
#[test]
fn the_core_names_no_provider() {
    let violations = core_violations(&read_sources());
    assert!(
        violations.is_empty(),
        "the core names a provider (only the adapters may, and lib.rs's allowlisted lines):\n{}",
        violations.join("\n")
    );
}

/// **The crate builds no client of its own:** no `reqwest` client or
/// builder, no `ClientBuilder`, no rustls client config, no `connect_async`
/// anywhere in `src/` (the Muse dial is `connect_async_tls_with_config`
/// with the app's connector, proven by `the_dial_uses_the_injected_connector`
/// in `tests/muse.rs`), and no connector built in place outside the crate's
/// own mock and test modules.
#[test]
fn the_crate_builds_no_client_of_its_own() {
    let violations = own_client_violations(&read_sources());
    assert!(
        violations.is_empty(),
        "the crate builds a client of its own (the app injects every client and connector):\n{}",
        violations.join("\n")
    );
}

/// The controls: each scan finds what it is for, in the forms it must, and
/// lets through what it must. Each bypass a review found has its fixture,
/// which the scan before the fix passed.
mod controls {
    use super::*;

    fn source(path: &str, text: &str) -> Source {
        Source {
            path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    impl Source {
        fn with_text_replaced(mut self, from: &str, to: &str) -> Source {
            assert!(self.text.contains(from), "{from:?} is not in the source");
            self.text = self.text.replacen(from, to, 1);
            self
        }
    }

    fn lib_with(extra: &str) -> Source {
        let allowed = [
            "#[cfg(feature = \"inworld\")]\npub mod inworld;",
            "#[cfg(feature = \"muse\")]\npub mod muse;",
            "#[cfg(any(feature = \"axum\", feature = \"muse\"))]\npub const A: u8 = 1;",
            "#[cfg(any(feature = \"axum\", feature = \"muse\"))]\nfn b() {}",
        ]
        .join("\n");
        source("lib.rs", &format!("{allowed}\n{extra}\n"))
    }

    /// The own-client violations of one file's `text`.
    fn client(text: &str) -> Vec<String> {
        own_client_violations(&[source("muse.rs", text)])
    }

    /// The core's violations with `text` as one core file (and a good lib.rs).
    fn core(text: &str) -> Vec<String> {
        core_violations(&[lib_with(""), source("relay.rs", text)])
    }

    #[test]
    fn a_planted_provider_name_is_found_in_a_string_a_comment_and_an_identifier() {
        for planted in [
            r#"const A: &str = "the muse relay";"#,
            "// the Inworld voices",
            "/// reaches meta.ai",
            "fn muse_url() {}",
            "struct InworldClient;",
            "const B: &str = \"META.AI\";",
            "use tokio_tungstenite::tungstenite::Message;",
            "use tungstenite::{Error, Message};",
            "fn f(_: tungstenite::Message) {}",
        ] {
            let found = core(planted);
            assert_eq!(
                found.len(),
                1,
                "{planted:?} was not found exactly once: {found:?}"
            );
            assert!(found[0].starts_with("relay.rs:1:"), "{found:?}");
        }
    }

    #[test]
    fn the_adapters_may_name_their_provider() {
        let found = core_violations(&[
            lib_with(""),
            source(
                "muse.rs",
                "// Muse over tungstenite::Message\nuse tungstenite::Message;",
            ),
            source("inworld.rs", "const A: &str = \"Inworld\";"),
            source("muse/mock.rs", "// Muse's mock"),
            source("relay.rs", "// provider-neutral"),
        ]);
        assert_eq!(found, Vec::<String>::new());
    }

    #[test]
    fn the_allowlist_is_those_lines_in_lib_rs_and_nothing_broader() {
        assert_eq!(core_violations(&[lib_with("")]), Vec::<String>::new());
        // The same lines in another core file.
        for line in [
            r#"#[cfg(feature = "muse")]"#,
            "pub mod inworld;",
            r#"#[cfg(any(feature = "axum", feature = "muse"))]"#,
        ] {
            let found = core_violations(&[lib_with(""), source("relay.rs", line)]);
            assert_eq!(found.len(), 1, "{line}: {found:?}");
        }
        // A near miss in lib.rs: another line naming a provider, a wider
        // gate, a doc comment, an indented copy that is not the same line.
        for line in [
            "pub mod museum;",
            r#"#[cfg(all(feature = "muse", feature = "axum"))]"#,
            "/// The Muse adapter",
            "pub use muse::MuseStt;",
            r#"#[cfg(feature = "muse")] pub mod muse;"#,
        ] {
            let found = core_violations(&[lib_with(line)]);
            assert_eq!(found.len(), 1, "{line}: {found:?}");
        }
        // An allowed line in the wrong place does not stand in for the one
        // `lib.rs` lost: it is a violation itself, and the entry is stale.
        let lib_without_muse = source(
            "lib.rs",
            "#[cfg(feature = \"inworld\")]\npub mod inworld;\n#[cfg(feature = \"muse\")]\n\
             #[cfg(any(feature = \"axum\", feature = \"muse\"))]\nconst A: u8 = 1;\n\
             #[cfg(any(feature = \"axum\", feature = \"muse\"))]\nconst B: u8 = 1;\n",
        );
        let moved = core_violations(&[lib_without_muse, source("relay.rs", "pub mod muse;")]);
        assert_eq!(moved.len(), 2, "{moved:?}");
        // An allowed line with something after it is not the allowed line.
        let widened =
            core_violations(&[lib_with("")
                .with_text_replaced("pub mod muse;", "pub mod muse; pub use muse::All;")]);
        assert_eq!(widened.len(), 2, "{widened:?}");
        // A second copy of an allowed line, and a missing one.
        let twice = core_violations(&[lib_with("pub mod muse;")]);
        assert_eq!(twice.len(), 1, "{twice:?}");
        assert!(twice[0].contains("stands 2 time(s), not 1"), "{twice:?}");
        let missing = core_violations(&[source("lib.rs", "pub mod inworld;\n")]);
        assert!(
            missing.iter().any(|line| line.contains("stands 0 time(s)")),
            "{missing:?}"
        );
        // `tungstenite::Message` is never allowlisted, in lib.rs either.
        let found = core_violations(&[lib_with("use tungstenite::Message;")]);
        assert_eq!(found.len(), 1, "{found:?}");
    }

    /// Review P2 (multiline imports): `Message` behind a list, a comment and
    /// several lines, an alias, a glob, a path split over lines.
    #[test]
    fn tungstenites_message_is_found_however_it_is_imported_or_spelled() {
        for planted in [
            "use tungstenite::{\n    // A wire frame.\n    Message,\n};",
            "use tungstenite::{\n    Error,\n    /* a block */ Message as Frame,\n};",
            "use tokio_tungstenite::tungstenite::Message as M;",
            "use tokio_tungstenite::tungstenite::{\n    protocol::CloseFrame,\n    Message,\n};",
            "use tungstenite::*;",
            "pub use tokio_tungstenite::tungstenite::{self, Message};",
            "fn f(_: tokio_tungstenite::\n    tungstenite::\n    Message) {}",
            "fn g(_: tungstenite\n    ::Message) {}",
        ] {
            let found = core(planted);
            assert_eq!(found.len(), 1, "{planted:?}: {found:?}");
        }
        // What is not it.
        for fine in [
            "use axum::extract::ws::Message;",
            "use tungstenite::Error;",
            "use tungstenite::{\n    error::ProtocolError,\n    Error,\n};",
            "use tungstenite::error::ProtocolError;\nstruct Message;",
            "// tungstenite::Message in a comment\nconst A: &str = \"tungstenite::Message\";",
            "fn f(_: axum::extract::ws::Message) {}",
        ] {
            assert_eq!(core(fine), Vec::<String>::new(), "{fine:?}");
        }
    }

    /// Review P2 (aliased dials and constructors): each form passed the
    /// line scan. The first group is the dial, the second the client.
    #[test]
    fn every_own_client_form_is_found_aliased_imported_or_split() {
        for planted in [
            "let s = connect_async(url).await;",
            "let s = tokio_tungstenite::connect_async_with_config(url, None, false).await;",
            "use tokio_tungstenite::connect_async as dial;\nfn f() { dial(url); }",
            "use tokio_tungstenite::{connect_async, Connector};",
            "use tokio_tungstenite::{\n    // the dial\n    connect_async_with_config as dial,\n    Connector,\n};",
            "let s = tokio_tungstenite\n    ::connect_async\n    (url);",
            "let dial = tokio_tungstenite::connect_async;",
            "use tokio_tungstenite::*;",
            "let c = reqwest::Client::new();",
            "let c = reqwest::Client::builder().build();",
            "use reqwest::Client;",
            "use reqwest::{Client as C, Url};",
            "use reqwest::*;",
            "use reqwest as r;\nfn f() { let _ = r::Client::new(); }",
            "fn f() { let _ = Client::new(); }",
            "fn f() { let _ = Client\n    ::\n    builder(); }",
            "let b: reqwest::ClientBuilder;",
            "let b = ClientBuilder::new();",
            "use reqwest::ClientBuilder as B;",
            "let b = inworld.client_builder();",
            "let b = InworldClient::builder(url);",
            "let b = InworldClient\n    ::builder(url);",
            "let c: rustls::ClientConfig;",
            "use rustls::ClientConfig as C;",
        ] {
            let found = client(planted);
            assert!(!found.is_empty(), "{planted:?} passed the own-client scan");
        }
        // What is not an own client: the injected dial, a comment, a string,
        // other types that merely end in `Client`.
        for fine in [
            "let s = tokio_tungstenite::connect_async_tls_with_config(url, config, true, connector).await;",
            "// connect_async( and reqwest::Client::new() in a comment\n/* use tokio_tungstenite::connect_async; */",
            "const A: &str = \"reqwest::Client::new() connect_async(\";",
            "use stridelabs_inworld::{InworldClient, InworldError};\nfn f(_: &InworldClient) {}",
            "use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};",
            "struct Client;\nfn f(_: Client) {}",
            "use reqwest::StatusCode;",
        ] {
            assert_eq!(client(fine), Vec::<String>::new(), "{fine:?}");
        }
    }

    /// Review P2 (the module stripper): an empty `mod tests {}` closes at
    /// once; a module is exempt by its `cfg`, never by its name.
    #[test]
    fn connectors_are_exempt_only_in_modules_gated_for_tests() {
        let connector = "fn connector() -> Connector {\n    Connector::Plain\n}\n";
        // Exempt: the attributes the crate's own mocks and tests carry, and
        // the forms like them.
        for gate in [
            "#[cfg(test)]",
            "#[cfg(feature = \"test-support\")]",
            "#[cfg(any(test, feature = \"test-support\"))]",
            "#[cfg(all(feature = \"test-support\", feature = \"axum\"))]",
            "#[cfg(all(test, feature = \"muse\"))]",
            "#[cfg(test)]\n#[allow(dead_code)]",
            "#[allow(dead_code)]\n#[cfg(test)]",
        ] {
            for module in [
                "mod tests",
                "pub mod mock",
                "pub(crate) mod anything",
                "mod nested",
            ] {
                let text = format!("{gate}\n{module} {{\n    {connector}}}\n");
                assert_eq!(client(&text), Vec::<String>::new(), "{gate} {module}");
            }
        }
        // Not exempt: a module named `mock` or `tests` with no test gate, one
        // gated on anything else, a `not(test)`, an `any` with a production
        // arm.
        for gate in [
            "",
            "#[cfg(feature = \"muse\")]",
            "#[cfg(not(test))]",
            "#[cfg(any(test, feature = \"axum\"))]",
            "#[derive(Debug)]",
            "#[cfg_attr(test, allow(dead_code))]",
        ] {
            for module in ["mod tests", "pub mod mock"] {
                let text = format!("{gate}\n{module} {{\n    {connector}}}\n");
                assert_eq!(client(&text).len(), 1, "{gate:?} {module}");
            }
        }
        // The production code after an empty or small test module is still
        // scanned (the stripper used to run on to its own closing brace).
        for module in [
            "#[cfg(test)]\nmod tests {}\n",
            "#[cfg(test)]\nmod tests { }\n",
            "#[cfg(test)]\nmod tests;\n",
            "#[cfg(test)]\nmod tests { fn a() { let _ = \"}\"; let _ = '}'; } }\n",
            "#[cfg(test)]\nmod tests {\n    mod inner { fn b() {} }\n}\n",
        ] {
            let text = format!("{module}\n{connector}");
            assert_eq!(client(&text).len(), 1, "{module:?}");
        }
        // A test module after production code leaves that code scanned too,
        // and an import of a variant is as visible as its use.
        assert_eq!(
            client(&format!("{connector}\n#[cfg(test)]\nmod tests {{ fn f() {{ let _ = Connector::Rustls(c); }} }}\n")).len(),
            1
        );
        assert_eq!(client("use tokio_tungstenite::Connector::Plain;").len(), 1);
        // Only connectors are let through inside a test module: its own
        // client is still found.
        let inside =
            "#[cfg(test)]\nmod tests {\n    fn f() { let _ = reqwest::Client::new(); }\n}\n";
        assert_eq!(client(inside).len(), 1, "{:?}", client(inside));
    }

    #[test]
    fn the_tokenizer_reads_literals_comments_and_lifetimes() {
        let text = "fn f<'a>(x: &'a str) { let _ = (\"a // b\", r#\"c \" d\"#, '\"', '}', b\"e\"); } // end\n/* a /* nested */ b */ fn g() {}";
        let idents: Vec<String> = tokenize(text)
            .iter()
            .filter_map(|token| token.ident().map(str::to_owned))
            .collect();
        assert_eq!(idents, ["fn", "f", "x", "str", "let", "_", "fn", "g"]);
        // A brace in a char or string does not unbalance a group.
        let tokens = tokenize("{ let c = '}'; let s = \"}\"; } fn after() {}");
        assert_eq!(
            group_end(&tokens, 0),
            tokens.iter().position(|t| t.is_ident("fn")).unwrap()
        );
        // Lines count through block comments, raw strings and escapes.
        let lines: Vec<usize> = tokenize("a\n/* x\ny */ b\nr\"p\nq\" c\n\"d\\\ne\" f")
            .iter()
            .map(|token| token.line)
            .collect();
        assert_eq!(lines, [1, 3, 4, 5, 6, 7]);
    }
}
