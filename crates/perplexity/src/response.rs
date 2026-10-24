//! The `2xx` answer: `{"status": …, "output": [ {"type": "search_results",
//! "results": […]}, {"type": "message", "content": [{"type": "output_text",
//! "text": …}]} ], "usage": {…}, …}`, and the optional display helper.

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize as _;
use serde_json::value::RawValue;
use url::Url;

use crate::error::{MalformedReason, PerplexityError, ResponseStatus};

/// A completed search: the answer text, every search result it drew on, and
/// what Perplexity reported using. Faithful to the response; presentation
/// (which results to show, how) is the caller's, and
/// [`SearchAnswer::sources`] is one optional way to do it.
///
/// The text cites results by their `id` (`[5]`): look a citation up in
/// [`SearchAnswer::results`] by [`SearchResult::id`], never by position.
///
/// `Debug` shows lengths and counts only: the text and the results derive
/// from the query, and a caller that logs them formats them explicitly.
#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub struct SearchAnswer {
    /// Every `output_text` of every assistant `message` item (its `role`
    /// absent, `null` or `assistant`; a message with any other role, such as
    /// an echo of the user's input, contributes nothing), in order,
    /// concatenated with no separator. Never empty or only whitespace (that
    /// is [`MalformedReason::MissingAnswer`]); otherwise as given, untrimmed.
    pub text: String,
    /// Every usable entry of every `search_results` item, in order, ids as
    /// given (gaps, and repeats across items, allowed). An entry with no
    /// integer `id` or no non-empty string `url` is skipped.
    pub results: Vec<SearchResult>,
    /// The response's `status`: always [`ResponseStatus::Completed`] here
    /// (any other, or a `message` item's own `status` other than
    /// `completed`, is [`PerplexityError::Incomplete`]).
    pub status: ResponseStatus,
    /// The response's `usage`, field by field; `None` when it is absent or
    /// not an object. Never fails the search.
    pub usage: Option<Usage>,
}

impl fmt::Debug for SearchAnswer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchAnswer")
            .field("text", &Redacted(&self.text))
            .field("results", &self.results.len())
            .field("status", &self.status)
            .field("usage", &self.usage)
            .finish()
    }
}

/// One entry of a `search_results` item. `id` and `url` are required (an
/// entry without them is skipped); every other field is `None` when it is
/// absent, not a string, or empty.
///
/// `Debug` shows the id and each string's length, never its content.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SearchResult {
    /// The citation id the answer text uses (`[id]`), as given.
    pub id: i64,
    /// The result's URL, as given: not checked to be http(s) or to parse
    /// ([`SearchAnswer::sources`] checks both).
    pub url: String,
    /// `title`.
    pub title: Option<String>,
    /// `date`, as given (`2026-07-03`, say).
    pub date: Option<String>,
    /// `last_updated`, as given.
    pub last_updated: Option<String>,
    /// `snippet`.
    pub snippet: Option<String>,
    /// `source` (`web`, say).
    pub source: Option<String>,
}

impl fmt::Debug for SearchResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchResult")
            .field("id", &self.id)
            .field("url", &Redacted(&self.url))
            .field("title", &self.title.as_deref().map(Redacted))
            .field("date", &self.date.as_deref().map(Redacted))
            .field("last_updated", &self.last_updated.as_deref().map(Redacted))
            .field("snippet", &self.snippet.as_deref().map(Redacted))
            .field("source", &self.source.as_deref().map(Redacted))
            .finish()
    }
}

/// A result shaped for display, from [`SearchAnswer::sources`].
///
/// `Debug` shows the id and each string's length, never its content.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Source {
    /// The result's citation id, as given.
    pub id: i64,
    /// The result's title, trimmed and cut to the caller's bound at a char
    /// boundary; the domain when the result has none.
    pub title: String,
    /// The result's URL, parsed and re-serialized (so well-formed), `http` or
    /// `https`, with no userinfo.
    pub url: String,
    /// The URL's host, lower-case, without a leading `www.`.
    pub domain: String,
    /// The result's `date`, as given.
    pub date: Option<String>,
}

impl fmt::Debug for Source {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Source")
            .field("id", &self.id)
            .field("title", &Redacted(&self.title))
            .field("url", &Redacted(&self.url))
            .field("domain", &Redacted(&self.domain))
            .field("date", &self.date.as_deref().map(Redacted))
            .finish()
    }
}

impl SearchAnswer {
    /// The results as display rows: in order, `http`/`https` URLs only (one
    /// that does not parse, has another scheme, or carries userinfo is left
    /// out), the first of any duplicate URL only (compared parsed, so
    /// `https://A.example` and `https://a.example/` are one), at most `max`
    /// rows, each title cut to `title_chars` characters. Never applied
    /// implicitly: [`SearchAnswer::results`] is untouched, so a citation
    /// whose row this leaves out (a duplicate URL under another id) still
    /// resolves there.
    #[must_use]
    pub fn sources(&self, max: usize, title_chars: usize) -> Vec<Source> {
        let mut seen = HashSet::new();
        let mut sources = Vec::new();
        for result in &self.results {
            if sources.len() >= max {
                break;
            }
            let Ok(url) = Url::parse(&result.url) else {
                continue;
            };
            if !matches!(url.scheme(), "http" | "https")
                || !url.username().is_empty()
                || url.password().is_some()
            {
                continue;
            }
            // `http` and `https` URLs always have a host.
            let Some(host) = url.host_str() else {
                continue;
            };
            let domain = host.strip_prefix("www.").unwrap_or(host).to_owned();
            if !seen.insert(url.as_str().to_owned()) {
                continue;
            }
            let title = result
                .title
                .as_deref()
                .map(str::trim)
                .filter(|title| !title.is_empty())
                .unwrap_or(&domain);
            sources.push(Source {
                id: result.id,
                title: cut(title, title_chars),
                url: url.into(),
                domain,
                date: result.date.clone(),
            });
        }
        sources
    }
}

/// `text`'s first `chars` characters (Unicode scalar values), with trailing
/// whitespace the cut exposed trimmed.
fn cut(text: &str, chars: usize) -> String {
    match text.char_indices().nth(chars) {
        Some((at, _)) => text[..at].trim_end().to_owned(),
        None => text.to_owned(),
    }
}

/// The response's `usage`. A field that is absent or has another type is
/// `None`, and never fails the search (the answer is what was paid for).
///
/// `Debug` shows the counts and the cost, and the currency's length only.
#[derive(Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct Usage {
    /// `usage.input_tokens`, when it is a non-negative integer.
    pub input_tokens: Option<u64>,
    /// `usage.output_tokens`, when it is a non-negative integer.
    pub output_tokens: Option<u64>,
    /// `usage.total_tokens`, when it is a non-negative integer.
    pub total_tokens: Option<u64>,
    /// `usage.cost.total_cost`, when it is a number.
    pub total_cost: Option<f64>,
    /// `usage.cost.currency` (`USD`, say), when it is a non-empty string.
    pub currency: Option<String>,
}

impl fmt::Debug for Usage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Usage")
            .field("input_tokens", &self.input_tokens)
            .field("output_tokens", &self.output_tokens)
            .field("total_tokens", &self.total_tokens)
            .field("total_cost", &self.total_cost)
            .field("currency", &self.currency.as_deref().map(Redacted))
            .finish()
    }
}

/// A provider-supplied string in a `Debug`: `<N chars>`, never its content.
struct Redacted<'a>(&'a str);

impl fmt::Debug for Redacted<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<{} chars>", self.0.chars().count())
    }
}

fn malformed(reason: MalformedReason) -> PerplexityError {
    PerplexityError::Malformed(reason)
}

impl SearchAnswer {
    /// An Agent API response body as a [`SearchAnswer`]: exactly the parse
    /// [`crate::PerplexityClient::search`] runs on a `2xx` body, every rule
    /// included (the whole body UTF-8, one string top-level `status` and
    /// only `completed`, no `message` item's own `status` other than
    /// `completed`, the assistant text, the lenient fields). The entry point
    /// for parsing a recorded body, and for a consumer's tests of what it
    /// makes of an answer (its formatting, its cards) without a server.
    ///
    /// It applies no size bound: `body` is the caller's, where `search`
    /// refuses one over its `max_response_bytes` before parsing.
    ///
    /// ```
    /// use stridelabs_perplexity::SearchAnswer;
    ///
    /// let answer = SearchAnswer::from_json(br#"{
    ///     "status": "completed",
    ///     "output": [
    ///         {"type": "search_results",
    ///          "results": [{"id": 1, "url": "https://example.com/", "title": "Example"}]},
    ///         {"type": "message", "role": "assistant", "status": "completed",
    ///          "content": [{"type": "output_text", "text": "An example [1]."}]}
    ///     ]
    /// }"#)?;
    /// assert_eq!(answer.text, "An example [1].");
    /// assert_eq!(answer.sources(6, 200)[0].domain, "example.com");
    /// # Ok::<(), stridelabs_perplexity::PerplexityError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`PerplexityError::Incomplete`] and [`PerplexityError::Malformed`],
    /// as for a search (the crate docs map each to its cause).
    pub fn from_json(body: &[u8]) -> Result<SearchAnswer, PerplexityError> {
        // The whole body is checked as UTF-8 first: serde_json validates the
        // strings it builds, but skips an ignored one by its delimiters and
        // escapes only, so invalid UTF-8 inside a skipped field would pass.
        let body = std::str::from_utf8(body).map_err(|_| malformed(MalformedReason::NotUtf8))?;
        let mut deserializer = serde_json::Deserializer::from_str(body);
        let wire = TopLevel
            .deserialize(&mut deserializer)
            .and_then(|wire| deserializer.end().map(|()| wire))
            .map_err(|_| malformed(MalformedReason::NotJson))?;
        // Two statuses are contradictory completion evidence, whichever
        // comes last, so neither is believed.
        if wire.duplicate_status {
            return Err(malformed(MalformedReason::DuplicateStatus));
        }
        match wire.status {
            Some(ResponseStatus::Completed) => {}
            Some(status) => return Err(PerplexityError::Incomplete { status }),
            None => return Err(malformed(MalformedReason::MissingStatus)),
        }
        if let Some(status) = wire.output.unfinished {
            return Err(PerplexityError::Incomplete { status });
        }
        if wire.output.text.trim().is_empty() {
            return Err(malformed(MalformedReason::MissingAnswer));
        }
        Ok(SearchAnswer {
            text: wire.output.text,
            results: wire.output.results,
            status: ResponseStatus::Completed,
            usage: wire.usage,
        })
    }
}

// The body is read, not built. Every reader below is a seed whose visitor,
// not a derive, decides what is kept, so that the response bound is also the
// memory bound and a field of an unexpected type is left out rather than
// failing the answer: the top level must be a JSON object (anything else is
// `NotJson`), and every other value is taken only in the kinds its reader
// wants, the rest skipped with `IgnoredAny`, which builds nothing (serde_json
// skips iteratively, however deep). A `serde_json::Value` of the body would
// cost some 32 bytes per JSON value. A key that repeats keeps its last value,
// as a `serde_json::Map` (and Python's `json`) would, except where it is
// completion evidence: a second top-level `status` refuses the body
// (`DuplicateStatus`), and a message item's repeated `role` or `status`
// counts every value.

/// What the crate reads of the top-level object.
#[derive(Default)]
struct Wire {
    /// `status`, when it is a string.
    status: Option<ResponseStatus>,
    /// Whether `status` came more than once.
    duplicate_status: bool,
    output: Output,
    usage: Option<Usage>,
}

/// What `output` contributes: the assistant `message` items' text, the
/// `search_results` items' entries, and the first `message` item's own
/// status that is not `completed`.
#[derive(Default)]
struct Output {
    text: String,
    results: Vec<SearchResult>,
    unfinished: Option<ResponseStatus>,
}

/// One `output` item, whatever its `type` (the key may come after the
/// content it labels, so everything is read, then kept by type).
#[derive(Default)]
struct Item {
    kind: Option<String>,
    /// Set once a `role` is present and not `assistant`: the item is not
    /// the answer (a user-role echo of the query, say).
    foreign_role: bool,
    /// The first `status` present and not `completed`.
    unfinished: Option<ResponseStatus>,
    texts: Vec<String>,
    results: Vec<SearchResult>,
}

#[derive(Default)]
struct Cost {
    total: Option<f64>,
    currency: Option<String>,
}

/// A field name the crate reads, at any level; any other is [`Key::Other`].
enum Key {
    Status,
    Output,
    Usage,
    Type,
    Content,
    Results,
    Role,
    Text,
    Id,
    Url,
    Title,
    Date,
    LastUpdated,
    Snippet,
    Source,
    InputTokens,
    OutputTokens,
    TotalTokens,
    Cost,
    TotalCost,
    Currency,
    Other,
}

impl<'de> de::Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Key, D::Error> {
        struct KeyVisitor;

        impl Visitor<'_> for KeyVisitor {
            type Value = Key;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a field name")
            }

            fn visit_str<E: de::Error>(self, name: &str) -> Result<Key, E> {
                Ok(match name {
                    "status" => Key::Status,
                    "output" => Key::Output,
                    "usage" => Key::Usage,
                    "type" => Key::Type,
                    "content" => Key::Content,
                    "results" => Key::Results,
                    "role" => Key::Role,
                    "text" => Key::Text,
                    "id" => Key::Id,
                    "url" => Key::Url,
                    "title" => Key::Title,
                    "date" => Key::Date,
                    "last_updated" => Key::LastUpdated,
                    "snippet" => Key::Snippet,
                    "source" => Key::Source,
                    "input_tokens" => Key::InputTokens,
                    "output_tokens" => Key::OutputTokens,
                    "total_tokens" => Key::TotalTokens,
                    "cost" => Key::Cost,
                    "total_cost" => Key::TotalCost,
                    "currency" => Key::Currency,
                    _ => Key::Other,
                })
            }
        }

        deserializer.deserialize_identifier(KeyVisitor)
    }
}

/// The seed that reads a [`Wire`] from the top-level object; any other JSON
/// value is an error (`NotJson`).
struct TopLevel;

impl<'de> DeserializeSeed<'de> for TopLevel {
    type Value = Wire;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Wire, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for TopLevel {
    type Value = Wire;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Wire, A::Error> {
        let (mut wire, mut status_seen) = (Wire::default(), false);
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::Status if status_seen => {
                    wire.duplicate_status = true;
                    map.next_value::<IgnoredAny>()?;
                }
                Key::Status => {
                    status_seen = true;
                    wire.status = map.next_value_seed(Lenient(StatusReader))?;
                }
                Key::Output => wire.output = map.next_value_seed(Lenient(OutputReader))?,
                Key::Usage => wire.usage = map.next_value_seed(Lenient(UsageReader))?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(wire)
    }
}

/// A reader of one JSON value: it takes the kinds it implements, and every
/// other kind (a nested array or object drained with [`IgnoredAny`]) is its
/// `Value`'s default, so a value of an unexpected type is left out, never an
/// error; so is a number serde_json cannot represent ([`Lenient`]). Wrapped
/// in [`Lenient`] to become a seed.
trait Reader<'de>: Sized {
    type Value: Default;

    fn null(self) -> Self::Value {
        Self::Value::default()
    }

    fn string(self, _: &str) -> Self::Value {
        Self::Value::default()
    }

    fn signed(self, _: i64) -> Self::Value {
        Self::Value::default()
    }

    fn unsigned(self, _: u64) -> Self::Value {
        Self::Value::default()
    }

    fn float(self, _: f64) -> Self::Value {
        Self::Value::default()
    }

    fn array<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Self::Value::default())
    }

    fn object<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Self::Value::default())
    }
}

/// A [`Reader`] as a seed and a visitor of any JSON value.
///
/// The value is captured first, as the raw JSON text it is (a `&RawValue`
/// borrowed from the body: nothing is copied), and only then read: serde_json
/// range-checks a number before any visitor sees it, so `1e400` (or an
/// integer of 400 digits) read directly would fail the whole body, where
/// here it fails only its own position, which takes its reader's default.
/// The capture checks the value's syntax (a syntax error is still the
/// body's), without converting any number in it. Each position re-reads only
/// its own text, so a body is read once per level of nesting the readers
/// know (a handful).
struct Lenient<R>(R);

impl<'de, R: Reader<'de>> DeserializeSeed<'de> for Lenient<R> {
    type Value = R::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<R::Value, D::Error> {
        let raw = <&'de RawValue>::deserialize(deserializer)?;
        Ok(serde_json::Deserializer::from_str(raw.get())
            .deserialize_any(self)
            .unwrap_or_default())
    }
}

impl<'de, R: Reader<'de>> Visitor<'de> for Lenient<R> {
    type Value = R::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<R::Value, E> {
        Ok(R::Value::default())
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<R::Value, E> {
        Ok(self.0.signed(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<R::Value, E> {
        Ok(self.0.unsigned(value))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<R::Value, E> {
        Ok(self.0.float(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<R::Value, E> {
        Ok(self.0.string(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<R::Value, E> {
        Ok(self.0.null())
    }

    fn visit_none<E: de::Error>(self) -> Result<R::Value, E> {
        Ok(self.0.null())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<R::Value, A::Error> {
        self.0.array(seq)
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<R::Value, A::Error> {
        self.0.object(map)
    }
}

/// `status`: a string, by its documented name.
struct StatusReader;

impl Reader<'_> for StatusReader {
    type Value = Option<ResponseStatus>;

    fn string(self, value: &str) -> Option<ResponseStatus> {
        Some(ResponseStatus::from_wire(value))
    }
}

/// A non-empty string, kept whole.
struct StringReader;

impl Reader<'_> for StringReader {
    type Value = Option<String>;

    fn string(self, value: &str) -> Option<String> {
        (!value.is_empty()).then(|| value.to_owned())
    }
}

/// A message item's `role` or `status`, kept apart from a missing one: a
/// value that is present but not a string (a number, `true`, an array, a
/// number serde_json cannot represent) is [`Label::Unnamed`], so it can never
/// pass for `assistant` or `completed`. `null` is absent.
#[derive(Default)]
enum Label {
    Absent,
    Named(String),
    #[default]
    Unnamed,
}

struct LabelReader;

impl Reader<'_> for LabelReader {
    type Value = Label;

    fn null(self) -> Label {
        Label::Absent
    }

    fn string(self, value: &str) -> Label {
        Label::Named(value.to_owned())
    }
}

/// A result's `id`: an integer within `i64`. A float is never an id, `5.0`
/// included.
struct IdReader;

impl Reader<'_> for IdReader {
    type Value = Option<i64>;

    fn signed(self, value: i64) -> Option<i64> {
        Some(value)
    }

    fn unsigned(self, value: u64) -> Option<i64> {
        i64::try_from(value).ok()
    }
}

/// A token count: a non-negative integer. A float is never a count.
struct CountReader;

impl Reader<'_> for CountReader {
    type Value = Option<u64>;

    fn signed(self, value: i64) -> Option<u64> {
        u64::try_from(value).ok()
    }

    fn unsigned(self, value: u64) -> Option<u64> {
        Some(value)
    }
}

/// A cost: any JSON number.
struct NumberReader;

impl Reader<'_> for NumberReader {
    type Value = Option<f64>;

    fn signed(self, value: i64) -> Option<f64> {
        Some(value as f64)
    }

    fn unsigned(self, value: u64) -> Option<f64> {
        Some(value as f64)
    }

    fn float(self, value: f64) -> Option<f64> {
        Some(value)
    }
}

/// `output`: an array of items, each kept by its `type`.
struct OutputReader;

impl<'de> Reader<'de> for OutputReader {
    type Value = Output;

    fn array<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Output, A::Error> {
        let mut output = Output::default();
        while let Some(item) = seq.next_element_seed(Lenient(ItemReader))? {
            match item.kind.as_deref() {
                Some("message") => {
                    // Any message item's own unfinished status holds back the
                    // answer, a non-assistant one's included (fail closed).
                    if output.unfinished.is_none() {
                        output.unfinished = item.unfinished;
                    }
                    if !item.foreign_role {
                        output.text.extend(item.texts);
                    }
                }
                Some("search_results") => output.results.extend(item.results),
                _ => {}
            }
        }
        Ok(output)
    }
}

/// One `output` item: `type`, `role`, `status`, `content` and `results`. A
/// repeated `role` or `status` counts every value: one that is not
/// `assistant`, or not `completed`, is enough.
struct ItemReader;

impl<'de> Reader<'de> for ItemReader {
    type Value = Item;

    fn object<A: MapAccess<'de>>(self, mut map: A) -> Result<Item, A::Error> {
        let mut item = Item::default();
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::Type => item.kind = map.next_value_seed(Lenient(StringReader))?,
                Key::Role => match map.next_value_seed(Lenient(LabelReader))? {
                    Label::Absent => {}
                    Label::Named(role) if role == "assistant" => {}
                    Label::Named(_) | Label::Unnamed => item.foreign_role = true,
                },
                Key::Status => {
                    let status = match map.next_value_seed(Lenient(LabelReader))? {
                        Label::Absent => None,
                        Label::Named(status) => Some(ResponseStatus::from_wire(&status)),
                        Label::Unnamed => Some(ResponseStatus::Other),
                    };
                    if item.unfinished.is_none() {
                        item.unfinished =
                            status.filter(|status| *status != ResponseStatus::Completed);
                    }
                }
                Key::Content => item.texts = map.next_value_seed(Lenient(ListOf(PartReader)))?,
                Key::Results => item.results = map.next_value_seed(Lenient(ListOf(EntryReader)))?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(item)
    }
}

/// An array, each element read by `R` and kept when `R` makes something of
/// it: a `message` item's `content` (its parts' texts) and a
/// `search_results` item's `results` (its usable entries). An element `R`
/// cannot use is skipped, never an error.
struct ListOf<R>(R);

impl<'de, T, R: Reader<'de, Value = Option<T>> + Copy> Reader<'de> for ListOf<R> {
    type Value = Vec<T>;

    fn array<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
        let mut kept = Vec::new();
        while let Some(element) = seq.next_element_seed(Lenient(self.0))? {
            kept.extend(element);
        }
        Ok(kept)
    }
}

/// One content part: its `text`, when its `type` is `output_text`.
#[derive(Clone, Copy)]
struct PartReader;

impl<'de> Reader<'de> for PartReader {
    type Value = Option<String>;

    fn object<A: MapAccess<'de>>(self, mut map: A) -> Result<Option<String>, A::Error> {
        let (mut kind, mut text) = (None, None);
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::Type => kind = map.next_value_seed(Lenient(StringReader))?,
                Key::Text => text = map.next_value_seed(Lenient(StringReader))?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(text.filter(|_| kind.as_deref() == Some("output_text")))
    }
}

/// One result entry: `None` without an integer `id` and a non-empty `url`.
#[derive(Clone, Copy)]
struct EntryReader;

impl<'de> Reader<'de> for EntryReader {
    type Value = Option<SearchResult>;

    fn object<A: MapAccess<'de>>(self, mut map: A) -> Result<Option<SearchResult>, A::Error> {
        let (mut id, mut url) = (None, None);
        let (mut title, mut date, mut last_updated, mut snippet, mut source) =
            (None, None, None, None, None);
        while let Some(key) = map.next_key::<Key>()? {
            let string = Lenient(StringReader);
            match key {
                Key::Id => id = map.next_value_seed(Lenient(IdReader))?,
                Key::Url => url = map.next_value_seed(string)?,
                Key::Title => title = map.next_value_seed(string)?,
                Key::Date => date = map.next_value_seed(string)?,
                Key::LastUpdated => last_updated = map.next_value_seed(string)?,
                Key::Snippet => snippet = map.next_value_seed(string)?,
                Key::Source => source = map.next_value_seed(string)?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(id.zip(url).map(|(id, url)| SearchResult {
            id,
            url,
            title,
            date,
            last_updated,
            snippet,
            source,
        }))
    }
}

/// `usage`: an object, field by field; anything else is `None`.
struct UsageReader;

impl<'de> Reader<'de> for UsageReader {
    type Value = Option<Usage>;

    fn object<A: MapAccess<'de>>(self, mut map: A) -> Result<Option<Usage>, A::Error> {
        let mut usage = Usage::default();
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::InputTokens => {
                    usage.input_tokens = map.next_value_seed(Lenient(CountReader))?;
                }
                Key::OutputTokens => {
                    usage.output_tokens = map.next_value_seed(Lenient(CountReader))?;
                }
                Key::TotalTokens => {
                    usage.total_tokens = map.next_value_seed(Lenient(CountReader))?;
                }
                Key::Cost => {
                    let cost = map.next_value_seed(Lenient(CostReader))?;
                    usage.total_cost = cost.total;
                    usage.currency = cost.currency;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Some(usage))
    }
}

/// `usage.cost`: `total_cost` and `currency`.
struct CostReader;

impl<'de> Reader<'de> for CostReader {
    type Value = Cost;

    fn object<A: MapAccess<'de>>(self, mut map: A) -> Result<Cost, A::Error> {
        let mut cost = Cost::default();
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::TotalCost => cost.total = map.next_value_seed(Lenient(NumberReader))?,
                Key::Currency => cost.currency = map.next_value_seed(Lenient(StringReader))?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(body: &str) -> Result<SearchAnswer, PerplexityError> {
        SearchAnswer::from_json(body.as_bytes())
    }

    fn reason(body: &str) -> Option<MalformedReason> {
        match decoded(body) {
            Ok(_) => None,
            Err(PerplexityError::Malformed(reason)) => Some(reason),
            Err(other) => panic!("not Malformed: {other}"),
        }
    }

    /// A completed answer whose `output` is `output`.
    fn completed(output: &str) -> String {
        format!(r#"{{"status":"completed","output":{output}}}"#)
    }

    const MESSAGE: &str =
        r#"{"type":"message","content":[{"type":"output_text","text":"Paris [1]."}]}"#;

    fn result(id: i64, url: &str) -> SearchResult {
        SearchResult {
            id,
            url: url.to_owned(),
            title: None,
            date: None,
            last_updated: None,
            snippet: None,
            source: None,
        }
    }

    fn answer(results: Vec<SearchResult>) -> SearchAnswer {
        SearchAnswer {
            text: "text".to_owned(),
            results,
            status: ResponseStatus::Completed,
            usage: None,
        }
    }

    /// The order of an item's keys does not matter: a `type` after the
    /// content it labels still decides, for an item and for a part. Text
    /// parts of every message item join in order with no separator; parts
    /// and items of other types contribute nothing.
    #[test]
    fn text_is_every_output_text_in_order_whatever_the_key_order() {
        let body = completed(
            r#"[
                {"content":[{"text":"One ","type":"output_text"},{"type":"refusal","text":"NO"},
                            {"type":"output_text","text":"two"}],"type":"message"},
                {"type":"reasoning","content":[{"type":"output_text","text":"NOT THIS"}]},
                {"type":"message","content":[{"type":"output_text","text":" three."},
                                             {"type":"output_text","text":5},"junk",
                                             {"type":"output_text"}]}
            ]"#,
        );
        assert_eq!(decoded(&body).expect("an answer").text, "One two three.");
    }

    /// Only `status`, `output` and `usage` are read at the top level, and
    /// only the fields named below them; everything else, however large or
    /// deep, is skipped, a field of another type is left out, and a repeated
    /// key keeps its last value.
    #[test]
    fn the_body_is_read_field_by_field_and_the_rest_is_skipped() {
        let zeros = format!("[{}0]", "0,".repeat(100_000));
        let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        for body in [
            format!(r#"{{"x":{zeros},"status":"completed","output":[{MESSAGE}],"y":{deep}}}"#),
            format!(
                r#"{{"status":"completed","output":[{{"pad":{zeros},"type":"message","content":[{{"type":"output_text","text":"Paris [1].","annotations":{deep}}}]}}]}}"#
            ),
            // An escaped key and an escaped `/`.
            format!(r#"{{"status":"completed","output":[{MESSAGE}],"u":"\/"}}"#),
            // The last of a repeated key wins, both ways (but `status`, below).
            format!(r#"{{"status":"completed","output":[],"output":[{MESSAGE}]}}"#),
            format!(r#"{{"status":"completed","usage":5,"usage":{{}},"output":[{MESSAGE}]}}"#),
        ] {
            assert_eq!(decoded(&body).expect("an answer").text, "Paris [1].");
        }
        assert_eq!(
            reason(&format!(
                r#"{{"status":"completed","output":[{MESSAGE}],"output":{{"a":1}}}}"#
            )),
            Some(MalformedReason::MissingAnswer)
        );
    }

    /// A second top-level `status` refuses the body, in either order and
    /// whatever the values (an escaped spelling of the key included): last
    /// wins would let `"incomplete","completed"` pass partial text as an
    /// answer. The control: one `status` is read.
    #[test]
    fn a_duplicate_top_level_status_is_refused() {
        let text = format!(r#""output":[{MESSAGE}]"#);
        assert!(decoded(&format!(r#"{{"status":"completed",{text}}}"#)).is_ok());
        for statuses in [
            r#""status":"incomplete","status":"completed""#,
            r#""status":"completed","status":"incomplete""#,
            r#""status":"completed","status":"completed""#,
            r#""status":5,"status":"completed""#,
            r#""status":"completed","status":{"s":"completed"}"#,
            r#""status":"completed","status":"failed""#,
        ] {
            for body in [
                format!("{{{statuses},{text}}}"),
                format!("{{{text},{statuses}}}"),
            ] {
                assert_eq!(
                    reason(&body),
                    Some(MalformedReason::DuplicateStatus),
                    "{body}"
                );
            }
        }
    }

    /// A `message` item whose `role` is present and not `assistant` (a user
    /// echo of the query, a system note, a role of another type, a repeated
    /// role with any such value) contributes no text; an absent or `null`
    /// role is the assistant's.
    #[test]
    fn a_non_assistant_message_contributes_no_text() {
        let message = |role: &str, text: &str| {
            format!(
                r#"{{"type":"message"{role},"content":[{{"type":"output_text","text":"{text}"}}]}}"#
            )
        };
        let echo = message(r#","role":"user""#, "echoed query");
        assert_eq!(
            reason(&completed(&format!("[{echo}]"))),
            Some(MalformedReason::MissingAnswer)
        );
        let answer = message(r#","role":"assistant""#, "Paris.");
        assert_eq!(
            decoded(&completed(&format!("[{echo},{answer}]")))
                .expect("an answer")
                .text,
            "Paris."
        );
        for (role, counts) in [
            ("", true),
            (r#","role":null"#, true),
            (r#","role":"assistant","role":"assistant""#, true),
            (r#","role":"system""#, false),
            (r#","role":"""#, false),
            (r#","role":"Assistant""#, false),
            (r#","role":5"#, false),
            (r#","role":true"#, false),
            (r#","role":["assistant"]"#, false),
            (r#","role":{"name":"assistant"}"#, false),
            (r#","role":"assistant","role":"user""#, false),
            (r#","role":"user","role":"assistant""#, false),
        ] {
            let body = completed(&format!("[{},{answer}]", message(role, "Other. ")));
            let expected = if counts { "Other. Paris." } else { "Paris." };
            assert_eq!(decoded(&body).expect("an answer").text, expected, "{role}");
        }
    }

    /// A `message` item whose own `status` is present and not `completed`
    /// holds back the answer inside a `completed` response, as `Incomplete`
    /// with that status (a non-string one is `Other`, and a repeated status
    /// counts every value). It is checked after the response's status and
    /// before the text, and a non-assistant message's counts too (fail
    /// closed). An absent or `null` status is fine.
    #[test]
    fn a_message_whose_own_status_is_not_completed_holds_back_the_answer() {
        let message = |status: &str, role: &str, text: &str| {
            format!(
                r#"{{"type":"message","role":"{role}"{status},"content":[{{"type":"output_text","text":"{text}"}}]}}"#
            )
        };
        let incomplete = |output: String| match decoded(&completed(&output)) {
            Err(PerplexityError::Incomplete { status }) => Some(status),
            Ok(_) => None,
            Err(other) => panic!("{output}: {other}"),
        };
        for (status, expected) in [
            ("", None),
            (r#","status":null"#, None),
            (r#","status":"completed""#, None),
            (
                r#","status":"incomplete""#,
                Some(ResponseStatus::Incomplete),
            ),
            (
                r#","status":"in_progress""#,
                Some(ResponseStatus::InProgress),
            ),
            (r#","status":"done""#, Some(ResponseStatus::Other)),
            (r#","status":5"#, Some(ResponseStatus::Other)),
            (
                r#","status":{"s":"completed"}"#,
                Some(ResponseStatus::Other),
            ),
            (
                r#","status":"incomplete","status":"completed""#,
                Some(ResponseStatus::Incomplete),
            ),
            (
                r#","status":"completed","status":"failed""#,
                Some(ResponseStatus::Failed),
            ),
        ] {
            let output = format!("[{}]", message(status, "assistant", "Partial"));
            assert_eq!(incomplete(output), expected, "{status}");
        }
        // A user message's unfinished status holds the answer back too.
        let output = format!(
            "[{},{}]",
            message(r#","status":"incomplete""#, "user", "echo"),
            message(r#","status":"completed""#, "assistant", "Paris.")
        );
        assert_eq!(incomplete(output), Some(ResponseStatus::Incomplete));
        // Before the text: an unfinished message with no text is still
        // `Incomplete`, not `MissingAnswer`.
        let output = format!(
            "[{}]",
            message(r#","status":"incomplete""#, "assistant", "")
        );
        assert_eq!(incomplete(output), Some(ResponseStatus::Incomplete));
        // After the response's own status.
        let body = format!(
            r#"{{"status":"failed","output":[{}]}}"#,
            message(r#","status":"incomplete""#, "assistant", "Partial")
        );
        assert_eq!(
            decoded(&body),
            Err(PerplexityError::Incomplete {
                status: ResponseStatus::Failed
            })
        );
    }

    /// A number serde_json cannot represent (`1e400`, `-1e400`, an integer
    /// of 400 digits) fails only its own position, which takes its reader's
    /// default; a 30-digit integer is a float to serde_json, so never a
    /// count or an id (but a cost). The rest of the answer is intact, whichever lenient
    /// position it is in: a usage count or cost, a result's `id` (the entry
    /// skipped) or `title` (`None`), a message's `role` (no text: fail
    /// closed) or `status` (`Other`), `output`'s element or `usage` itself,
    /// an ignored field. A syntax error is still the body's.
    #[test]
    fn an_unrepresentable_number_fails_only_its_own_position() {
        let huge = format!("1{}", "0".repeat(400));
        for number in [
            "1e400",
            "-1e400",
            "123456789012345678901234567890",
            huge.as_str(),
        ] {
            let body = format!(
                r#"{{"x":{number},"status":"completed","output":[{number},
                    {{"type":"search_results","results":[
                        {{"id":{number},"url":"https://a.example/"}},
                        {{"id":2,"url":"https://b.example/","title":{number},"snippet":"S"}}]}},
                    {MESSAGE}],
                    "usage":{{"input_tokens":{number},"output_tokens":5,
                              "cost":{{"total_cost":{number},"currency":"USD"}}}}}}"#
            );
            let answer = decoded(&body).unwrap_or_else(|error| panic!("{number}: {error}"));
            assert_eq!(answer.text, "Paris [1].", "{number}");
            let mut kept = result(2, "https://b.example/");
            kept.snippet = Some("S".to_owned());
            assert_eq!(answer.results, vec![kept], "{number}");
            let usage = answer.usage.expect("usage");
            assert_eq!(
                (usage.input_tokens, usage.output_tokens),
                (None, Some(5)),
                "{number}"
            );
            // A cost is any number: the 30-digit integer is one.
            let representable = number.parse::<f64>().is_ok_and(f64::is_finite);
            assert_eq!(usage.total_cost.is_some(), representable, "{number}");
            assert_eq!(usage.currency.as_deref(), Some("USD"), "{number}");

            let usage_itself =
                format!(r#"{{"status":"completed","output":[{MESSAGE}],"usage":{number}}}"#);
            assert_eq!(
                decoded(&usage_itself).expect("an answer").usage,
                None,
                "{number}"
            );
            assert_eq!(
                reason(&format!(r#"{{"status":{number},"output":[{MESSAGE}]}}"#)),
                Some(MalformedReason::MissingStatus),
                "{number}"
            );
            let role = format!(
                r#"[{{"type":"message","role":{number},"content":[{{"type":"output_text","text":"x"}}]}}]"#
            );
            assert_eq!(
                reason(&completed(&role)),
                Some(MalformedReason::MissingAnswer),
                "{number}"
            );
            let status = format!(
                r#"[{{"type":"message","status":{number},"content":[{{"type":"output_text","text":"x"}}]}}]"#
            );
            assert_eq!(
                decoded(&completed(&status)),
                Err(PerplexityError::Incomplete {
                    status: ResponseStatus::Other
                }),
                "{number}"
            );
        }
        for broken in ["1e", "-", "1.", "01"] {
            let body = format!(
                r#"{{"status":"completed","output":[{MESSAGE}],"usage":{{"input_tokens":{broken}}}}}"#
            );
            assert_eq!(reason(&body), Some(MalformedReason::NotJson), "{broken}");
        }
    }

    /// Invalid UTF-8 anywhere in the body is refused, a skipped field's
    /// string included (serde_json would skip that one unchecked).
    #[test]
    fn invalid_utf8_anywhere_is_refused() {
        let valid = completed(&format!("[{MESSAGE}]"));
        assert!(decoded(&valid).is_ok(), "the control parses");
        let rest = &valid.as_bytes()[1..];
        let mut in_text = valid.clone().into_bytes();
        in_text[valid.find("Paris").expect("the text")] = 0xFF;
        for body in [
            [br#"{"x":""#.as_slice(), &[0xFF], br#"","#, rest].concat(),
            [br#"{"x":{"y":[""#.as_slice(), &[0xC3], br#""]},"#, rest].concat(),
            [br#"{""#.as_slice(), &[0xFF], br#"":1,"#, rest].concat(),
            in_text,
        ] {
            let outcome = SearchAnswer::from_json(&body);
            assert!(
                matches!(
                    outcome,
                    Err(PerplexityError::Malformed(MalformedReason::NotUtf8))
                ),
                "{:?}: {outcome:?}",
                String::from_utf8_lossy(&body)
            );
        }
    }

    #[test]
    fn every_malformed_body_has_its_reason() {
        let cases = [
            ("", MalformedReason::NotJson),
            ("not json", MalformedReason::NotJson),
            (r#"["status"]"#, MalformedReason::NotJson),
            (r#""completed""#, MalformedReason::NotJson),
            ("null", MalformedReason::NotJson),
            (
                r#"{"status":"completed"} trailing"#,
                MalformedReason::NotJson,
            ),
            ("{}", MalformedReason::MissingStatus),
            (r#"{"status":null}"#, MalformedReason::MissingStatus),
            (
                r#"{"status":1,"output":[]}"#,
                MalformedReason::MissingStatus,
            ),
            (
                r#"{"status":["completed"]}"#,
                MalformedReason::MissingStatus,
            ),
            (r#"{"status":"completed"}"#, MalformedReason::MissingAnswer),
            (
                r#"{"status":"completed","output":null}"#,
                MalformedReason::MissingAnswer,
            ),
            (
                r#"{"status":"completed","output":{}}"#,
                MalformedReason::MissingAnswer,
            ),
            (
                r#"{"status":"completed","output":[]}"#,
                MalformedReason::MissingAnswer,
            ),
            (
                r#"{"status":"completed","output":[{"type":"message","content":[]}]}"#,
                MalformedReason::MissingAnswer,
            ),
            (
                r#"{"status":"completed","output":[{"type":"message","content":"Paris"}]}"#,
                MalformedReason::MissingAnswer,
            ),
            (
                r#"{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":" \n\t"}]}]}"#,
                MalformedReason::MissingAnswer,
            ),
            (
                r#"{"status":"completed","output":[{"content":[{"type":"output_text","text":"Paris"}]}]}"#,
                MalformedReason::MissingAnswer,
            ),
        ];
        for (body, expected) in cases {
            assert_eq!(reason(body), Some(expected), "{body}");
        }
    }

    /// Any status but `completed` is `Incomplete`, whatever text it carries;
    /// a missing status is checked before the text.
    #[test]
    fn only_completed_is_an_answer() {
        for (wire, status) in [
            ("failed", ResponseStatus::Failed),
            ("incomplete", ResponseStatus::Incomplete),
            ("in_progress", ResponseStatus::InProgress),
            ("queued", ResponseStatus::Queued),
            ("cancelled", ResponseStatus::Cancelled),
            ("whatever", ResponseStatus::Other),
        ] {
            let body = format!(r#"{{"status":"{wire}","output":[{MESSAGE}]}}"#);
            assert_eq!(
                decoded(&body),
                Err(PerplexityError::Incomplete { status }),
                "{wire}"
            );
        }
        assert_eq!(
            reason(&format!(r#"{{"output":[{MESSAGE}]}}"#)),
            Some(MalformedReason::MissingStatus)
        );
    }

    /// An entry without an integer `id` or a non-empty string `url` is left
    /// out; an optional field of another type, or empty, is `None`. An id is
    /// any `i64`, as given.
    #[test]
    fn result_entries_are_read_field_by_field() {
        let body = completed(&format!(
            r#"[{{"type":"search_results","results":[
                {{"id":7,"url":"https://a.example/","title":"A","date":"2026-01-02","last_updated":"2026-03-04","snippet":"S","source":"web"}},
                {{"url":"https://no-id.example/"}},
                {{"id":"8","url":"https://string-id.example/"}},
                {{"id":8.0,"url":"https://float-id.example/"}},
                {{"id":9}},
                {{"id":10,"url":5}},
                {{"id":11,"url":""}},
                {{"id":-3,"url":"x","title":5,"date":null,"last_updated":[],"snippet":"","source":{{}}}},
                {{"id":18446744073709551615,"url":"https://too-big.example/"}},
                "junk", 5, null, []
            ]}},{MESSAGE}]"#
        ));
        let results = decoded(&body).expect("an answer").results;
        assert_eq!(
            results,
            vec![
                SearchResult {
                    id: 7,
                    url: "https://a.example/".to_owned(),
                    title: Some("A".to_owned()),
                    date: Some("2026-01-02".to_owned()),
                    last_updated: Some("2026-03-04".to_owned()),
                    snippet: Some("S".to_owned()),
                    source: Some("web".to_owned()),
                },
                result(-3, "x"),
            ]
        );
    }

    #[test]
    fn usage_is_read_field_by_field_and_never_fails_the_search() {
        let usage_of = |usage: &str| {
            decoded(&format!(
                r#"{{"status":"completed","output":[{MESSAGE}]{usage}}}"#
            ))
            .expect("the answer is fine")
            .usage
        };
        assert_eq!(usage_of(""), None);
        assert_eq!(usage_of(r#","usage":null"#), None);
        assert_eq!(usage_of(r#","usage":[1,2]"#), None);
        assert_eq!(usage_of(r#","usage":"lots""#), None);
        assert_eq!(usage_of(r#","usage":{}"#), Some(Usage::default()));
        assert_eq!(
            usage_of(
                r#","usage":{"input_tokens":4883,"output_tokens":50,"total_tokens":4933,
                    "cost":{"total_cost":0.00164,"currency":"USD","input_cost":0}}"#
            ),
            Some(Usage {
                input_tokens: Some(4883),
                output_tokens: Some(50),
                total_tokens: Some(4933),
                total_cost: Some(0.00164),
                currency: Some("USD".to_owned()),
            })
        );
        assert_eq!(
            usage_of(r#","usage":{"cost":{"total_cost":2}}"#).and_then(|usage| usage.total_cost),
            Some(2.0)
        );
        for ill_typed in [
            r#","usage":{"input_tokens":"1","output_tokens":-1,"total_tokens":1.5,"cost":5}"#,
            r#","usage":{"input_tokens":true,"cost":{"total_cost":"0.1","currency":""}}"#,
            r#","usage":{"total_tokens":null,"cost":{"total_cost":null,"currency":7}}"#,
        ] {
            assert_eq!(usage_of(ill_typed), Some(Usage::default()), "{ill_typed}");
        }
    }

    /// `sources`: http(s) only, no userinfo, the first of a duplicate URL
    /// (compared parsed), capped, titles trimmed and cut at a char boundary
    /// (the domain when there is none), `www.` dropped from the domain, and
    /// `results` untouched.
    #[test]
    fn sources_are_display_rows_and_leave_results_alone() {
        let mut titled = result(2, "https://www.Example.com/a?q=1");
        titled.title = Some("  Ünïcödé title that is long  ".to_owned());
        titled.date = Some("2026-10-01".to_owned());
        let mut blank = result(9, "http://plain.example");
        blank.title = Some("   ".to_owned());
        let results = vec![
            result(1, "ftp://files.example/x"),
            result(4, "not a url"),
            result(6, "https://user:pass@phish.example/"),
            result(8, "javascript:alert(1)"),
            titled,
            result(3, "https://www.example.com/a?q=1"),
            blank,
            result(5, "http://PLAIN.example/"),
            result(12, "https://[::1]:8443/x"),
            result(13, "https://late.example/"),
        ];
        let answer = answer(results.clone());
        let sources = answer.sources(4, 7);
        let rows: Vec<_> = sources
            .iter()
            .map(|source| {
                (
                    source.id,
                    source.title.as_str(),
                    source.url.as_str(),
                    source.domain.as_str(),
                    source.date.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                (
                    2,
                    "Ünïcödé",
                    "https://www.example.com/a?q=1",
                    "example.com",
                    Some("2026-10-01")
                ),
                (9, "plain.e", "http://plain.example/", "plain.example", None),
                (12, "[::1]", "https://[::1]:8443/x", "[::1]", None),
                (13, "late.ex", "https://late.example/", "late.example", None),
            ]
        );
        // The rows a duplicate URL left out still resolve by id.
        assert_eq!(answer.results, results);
        assert!(answer.results.iter().any(|result| result.id == 3));
        assert!(answer.results.iter().any(|result| result.id == 5));
        // The cap, both ends.
        assert!(answer.sources(0, 200).is_empty());
        assert_eq!(answer.sources(100, 200).len(), 4);
        assert_eq!(
            answer.sources(1, 200)[0].title,
            "Ünïcödé title that is long"
        );
    }

    #[test]
    fn a_cut_lands_on_a_char_boundary() {
        assert_eq!(cut("😀😀😀", 2), "😀😀");
        assert_eq!(cut("😀😀😀", 3), "😀😀😀");
        assert_eq!(cut("😀😀😀", 30), "😀😀😀");
        assert_eq!(cut("ab cd", 3), "ab");
        assert_eq!(cut("abc", 0), "");
    }

    #[test]
    fn debug_shows_lengths_and_counts_only() {
        let mut found = result(5, "https://example.com/CANARY");
        found.title = Some("CANARY title".to_owned());
        found.snippet = Some("CANARY snippet".to_owned());
        let answer = SearchAnswer {
            text: "CANARY text".to_owned(),
            results: vec![found.clone()],
            status: ResponseStatus::Completed,
            usage: Some(Usage {
                input_tokens: Some(3),
                currency: Some("CANARY".to_owned()),
                ..Usage::default()
            }),
        };
        let sources = answer.sources(6, 200);
        let rendered = format!("{answer:?} {answer:#?} {found:?} {sources:?} {sources:#?}");
        assert!(!rendered.contains("CANARY"), "{rendered}");
        assert_eq!(
            format!("{answer:?}"),
            "SearchAnswer { text: <11 chars>, results: 1, status: Completed, usage: \
             Some(Usage { input_tokens: Some(3), output_tokens: None, total_tokens: None, \
             total_cost: None, currency: Some(<6 chars>) }) }"
        );
        assert_eq!(
            format!("{found:?}"),
            "SearchResult { id: 5, url: <26 chars>, title: Some(<12 chars>), date: None, \
             last_updated: None, snippet: Some(<14 chars>), source: None }"
        );
    }
}
