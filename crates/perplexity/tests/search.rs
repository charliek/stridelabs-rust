//! The wire, the classification and the parsing matrix, against wiremock:
//! the exact request (method, path, headers, a body with the unset bound
//! omitted), a path-prefix base, each status class, redirects never
//! followed, the client-side refusal that sends nothing, the recorded real
//! response, and the response shapes the Agent API can send: citation ids
//! across several `search_results` items, duplicate URLs, malformed entries
//! against a malformed list, `failed` and `incomplete`, empty text, invalid
//! UTF-8 in an ignored field, a malformed `usage`, a user-role echo and an
//! unfinished message, a duplicate `status`, unrepresentable numbers; and
//! `SearchAnswer::from_json` agreeing with `search()`.

mod common;

use std::time::Duration;

use common::{
    answering, builder, client, completed, entry, incomplete, malformed, message, never_called,
    raw_json, rejected, response, search_results, unavailable, Outcome, KEY, RECORDED,
};
use serde_json::json;
use stridelabs_perplexity::{
    Effort, MalformedReason, PerplexityClient, PerplexityError, Phase, ResponseStatus,
    SearchAnswer, UnavailableReason,
};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The outcome of one search against a server answering `body`.
async fn answer_to(body: impl Into<Vec<u8>>) -> Outcome {
    let server = answering(raw_json(200, body)).await;
    client(&server.uri()).search("q").await
}

fn ids(answer: &SearchAnswer) -> Vec<i64> {
    answer.results.iter().map(|result| result.id).collect()
}

/// The one request on `server`.
async fn the_request(server: &MockServer) -> wiremock::Request {
    let mut requests = server.received_requests().await.expect("recording is on");
    assert_eq!(requests.len(), 1, "exactly one request");
    requests.remove(0)
}

/// `POST /v1/agent`, the key as `Bearer`, a JSON content type, and exactly
/// `{"effort":"fast","input":…}`, byte for byte: no `max_output_tokens`
/// unless set, no model, tools or stream.
#[tokio::test]
async fn the_request_is_exactly_the_documented_one() {
    let server = answering(raw_json(200, completed("Paris."))).await;
    let answer = client(&server.uri())
        .search("What is the capital of France?")
        .await
        .expect("an answer");
    assert_eq!(answer.text, "Paris.");

    let seen = the_request(&server).await;
    assert_eq!(seen.method.as_str(), "POST");
    assert_eq!(seen.url.path(), "/v1/agent");
    assert_eq!(seen.url.query(), None);
    let header_of = |name: &str| {
        seen.headers
            .get(name)
            .map(|value| value.to_str().expect("ASCII").to_string())
    };
    assert_eq!(header_of("authorization"), Some(format!("Bearer {KEY}")));
    assert_eq!(
        header_of("content-type").as_deref(),
        Some("application/json")
    );
    assert_eq!(
        String::from_utf8(seen.body).expect("UTF-8"),
        r#"{"effort":"fast","input":"What is the capital of France?"}"#
    );
}

/// A set effort and output bound are sent, in the pinned order.
#[tokio::test]
async fn the_effort_and_the_output_bound_are_sent_when_set() {
    for (effort, name) in [
        (Effort::Low, "low"),
        (Effort::Medium, "medium"),
        (Effort::High, "high"),
        (Effort::XHigh, "xhigh"),
    ] {
        let server = answering(raw_json(200, completed("Paris."))).await;
        builder(&server.uri())
            .effort(effort)
            .max_output_tokens(256)
            .build()
            .expect("builds")
            .search("q")
            .await
            .expect("an answer");
        assert_eq!(
            String::from_utf8(the_request(&server).await.body).expect("UTF-8"),
            format!(r#"{{"effort":"{name}","input":"q","max_output_tokens":256}}"#)
        );
    }
}

/// The input is sent as given, quotes, newlines and non-ASCII characters and
/// all (compared as JSON values: the order is pinned above).
#[tokio::test]
async fn the_input_is_sent_as_given() {
    let server = MockServer::start().await;
    let input = "Ça va? \"Oui\" — 😀\n</script>";
    Mock::given(method("POST"))
        .and(body_json(json!({"effort": "fast", "input": input})))
        .respond_with(raw_json(200, completed("Oui.")))
        .expect(1)
        .mount(&server)
        .await;
    client(&server.uri())
        .search(input)
        .await
        .expect("an answer");
}

/// A path prefix on the base URL is kept, with or without a trailing slash:
/// lumen-fakes' `/perplexity` base requests `/perplexity/v1/agent`.
#[tokio::test]
async fn a_base_url_path_prefix_is_kept() {
    for suffix in ["/perplexity", "/perplexity/"] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/perplexity/v1/agent"))
            .respond_with(raw_json(200, completed("Paris.")))
            .expect(1)
            .mount(&server)
            .await;
        let perplexity = client(&format!("{}{suffix}", server.uri()));
        assert_eq!(
            perplexity.endpoint().as_str(),
            format!("{}/perplexity/v1/agent", server.uri())
        );
        perplexity.search("q").await.expect("an answer");
    }
}

/// The key is used verbatim after trimming: surrounding whitespace never
/// reaches the header. (A trailing newline, which no header can carry, is
/// the unit tests'.)
#[tokio::test]
async fn the_key_is_trimmed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("authorization", "Bearer pplx-abc123"))
        .respond_with(raw_json(200, completed("Paris.")))
        .expect(1)
        .mount(&server)
        .await;
    PerplexityClient::builder(common::http(), " \t pplx-abc123 \t ")
        .base_url(server.uri())
        .build()
        .expect("builds")
        .search("q")
        .await
        .expect("the trimmed key is the one sent");
}

/// Input over the bound is refused before anything is sent, counted in
/// characters, not bytes: five four-byte characters are within five. The
/// control: input at the bound is sent. The default bound is 2,000.
#[tokio::test]
async fn input_over_the_bound_sends_nothing() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent"))
        .respond_with(raw_json(200, completed("Paris.")))
        .expect(3)
        .mount(&server)
        .await;
    let perplexity = builder(&server.uri())
        .max_input_chars(5)
        .build()
        .expect("builds");
    let outcome = perplexity.search("123456").await;
    assert!(
        matches!(
            outcome,
            Err(PerplexityError::InputTooLong { chars: 6, max: 5 })
        ),
        "{outcome:?}"
    );
    perplexity
        .search("12345")
        .await
        .expect("five characters are within five");
    perplexity
        .search("😀😀😀😀😀")
        .await
        .expect("five characters of four bytes each are within five");

    let perplexity = client(&server.uri());
    let outcome = perplexity.search(&"a".repeat(2_001)).await;
    assert!(
        matches!(
            outcome,
            Err(PerplexityError::InputTooLong {
                chars: 2_001,
                max: 2_000
            })
        ),
        "{outcome:?}"
    );
    perplexity
        .search(&"a".repeat(2_000))
        .await
        .expect("2,000 characters are within the default");
}

/// `408`, `429` and every status of `500` or more are `Unavailable`: the
/// `5xx`, and the `600`–`999` hyper also accepts. Every other non-2xx is
/// `Rejected`. Each body is a valid completed answer, so a client that read
/// a non-2xx body would have found one.
#[tokio::test]
async fn statuses_are_classified_before_any_body_is_read() {
    for status in [408, 429, 500, 502, 503, 504, 599, 600, 999] {
        let server = answering(raw_json(status, completed("Paris."))).await;
        let outcome = client(&server.uri()).search("q").await;
        assert_eq!(
            unavailable(&outcome),
            Some(UnavailableReason::Status(status)),
            "{status}: {outcome:?}"
        );
    }
    for status in [400, 401, 403, 404, 409, 413, 422, 451] {
        let server = answering(raw_json(status, completed("Paris."))).await;
        let outcome = client(&server.uri()).search("q").await;
        assert_eq!(rejected(&outcome), Some(status), "{status}: {outcome:?}");
    }
}

/// A `3xx` is `Rejected` and never followed: the server it points at sees no
/// request, so `Authorization` never reaches it. (lumen maps a `302` to
/// "Search failed: 302".)
#[tokio::test]
async fn a_redirect_is_rejected_and_not_followed() {
    let elsewhere = never_called().await;
    for status in [301, 302, 303, 307, 308] {
        let server = answering(
            ResponseTemplate::new(status)
                .insert_header("location", format!("{}/v1/agent", elsewhere.uri())),
        )
        .await;
        let outcome = client(&server.uri()).search("q").await;
        assert_eq!(rejected(&outcome), Some(status), "{status}: {outcome:?}");
        assert_eq!(the_request(&server).await.url.path(), "/v1/agent");
    }
}

/// Any `2xx` is an answer to read: a `201` with an answer is an answer; a
/// `204` has no body, so no JSON.
#[tokio::test]
async fn any_2xx_is_read() {
    let server = answering(raw_json(201, completed("Paris."))).await;
    client(&server.uri())
        .search("q")
        .await
        .expect("a 201 with an answer");
    let server = answering(ResponseTemplate::new(204)).await;
    let outcome = client(&server.uri()).search("q").await;
    assert_eq!(
        malformed(&outcome),
        Some(MalformedReason::NotJson),
        "{outcome:?}"
    );
}

/// A server that does not answer within the bound is a timeout before the
/// headers; a port nothing listens on is a transport failure while
/// connecting, connection refused.
#[tokio::test]
async fn a_timeout_and_a_refused_connection_are_unavailable() {
    let server =
        answering(raw_json(200, completed("Paris.")).set_delay(Duration::from_secs(10))).await;
    let outcome = builder(&server.uri())
        .timeout(Duration::from_millis(300))
        .build()
        .expect("builds")
        .search("q")
        .await;
    assert_eq!(
        unavailable(&outcome),
        Some(UnavailableReason::Timeout(Phase::Headers)),
        "{outcome:?}"
    );
    drop(server);

    let outcome = client(&common::refused_base_url().await).search("q").await;
    assert!(
        matches!(
            unavailable(&outcome),
            Some(UnavailableReason::Transport {
                phase: Phase::Connect,
                io: Some(std::io::ErrorKind::ConnectionRefused),
                ..
            })
        ),
        "{outcome:?}"
    );
}

/// The recorded real response (one billed contract call): the answer text
/// as given, its `[5]` resolving by id; the ten results in order with their
/// fields (two have no `date`); the usage; and the display helper's six rows.
#[tokio::test]
async fn the_recorded_response_is_read_faithfully() {
    let answer = answer_to(RECORDED).await.expect("the recorded answer");
    assert_eq!(
        answer.text,
        "Paris is the capital of France. It became a Frankish royal capital under Clovis I \
         around 508 CE; its role as the enduring center of the French kingdom was firmly \
         established under Hugh Capet in 987.[5]"
    );
    assert_eq!(answer.status, ResponseStatus::Completed);
    assert_eq!(ids(&answer), (1..=10).collect::<Vec<_>>());
    let cited = answer
        .results
        .iter()
        .find(|result| result.id == 5)
        .expect("[5] resolves by id");
    assert_eq!(cited.url, "https://www.britannica.com/place/Paris");
    assert_eq!(
        cited.title.as_deref(),
        Some("Paris | Definition, Map, Population, Facts, & History - Britannica")
    );
    assert_eq!(cited.date.as_deref(), Some("2026-10-22"));
    assert_eq!(cited.source.as_deref(), Some("web"));
    assert!(cited.last_updated.is_some() && cited.snippet.is_some());
    let undated: Vec<_> = answer
        .results
        .iter()
        .filter(|result| result.date.is_none())
        .map(|result| result.id)
        .collect();
    assert_eq!(undated, [3, 10]);

    let usage = answer.usage.as_ref().expect("usage");
    assert_eq!(usage.input_tokens, Some(4883));
    assert_eq!(usage.output_tokens, Some(50));
    assert_eq!(usage.total_tokens, Some(4933));
    assert_eq!(usage.total_cost, Some(0.00164));
    assert_eq!(usage.currency.as_deref(), Some("USD"));

    let rows: Vec<_> = answer
        .sources(6, 200)
        .into_iter()
        .map(|source| (source.id, source.domain, source.date))
        .collect();
    assert_eq!(
        rows,
        [
            (1, "kids.kiddle.co", Some("2026-07-03")),
            (2, "en.wikipedia.org", Some("2003-01-15")),
            (3, "home.adelphi.edu", None),
            (4, "machupicchu.org", Some("2025-10-31")),
            (5, "britannica.com", Some("2026-10-22")),
            (6, "sporcle.com", Some("2020-02-16")),
        ]
        .map(|(id, domain, date)| (id, domain.to_string(), date.map(String::from)))
    );
    let short = answer.sources(6, 10);
    assert_eq!(short[4].title, "Paris | De");
    assert_eq!(
        short[2].url,
        "https://home.adelphi.edu/~ca19535/page%204.html"
    );
}

/// Citation ids are the results' own, never positions: non-contiguous, and
/// in one id space across several `search_results` items, a repeat across
/// items included, all kept in order. The text's `[12]` is the fourth
/// result, which a position would call `[4]`.
#[tokio::test]
async fn citation_ids_are_kept_across_several_batches() {
    let body = response(
        "completed",
        json!([
            search_results(json!([
                entry(3, "https://a.example/"),
                entry(7, "https://b.example/")
            ])),
            message("Partly [3]"),
            search_results(json!([
                entry(7, "https://b.example/"),
                entry(12, "https://c.example/")
            ])),
            message(", partly [12]."),
        ]),
    );
    let answer = answer_to(body.to_string()).await.expect("an answer");
    assert_eq!(answer.text, "Partly [3], partly [12].");
    assert_eq!(ids(&answer), [3, 7, 7, 12]);
    let twelve = answer
        .results
        .iter()
        .find(|result| result.id == 12)
        .expect("[12] resolves by id");
    assert_eq!(twelve.url, "https://c.example/");
    assert_eq!(twelve.title.as_deref(), Some("Title 12"));
    assert_eq!(
        answer
            .sources(6, 200)
            .iter()
            .map(|source| source.id)
            .collect::<Vec<_>>(),
        [3, 7, 12]
    );
}

/// The same URL under two ids: both stay in `results`, so the later id's
/// citation still resolves there, while `sources` shows the URL once, under
/// the first id.
#[tokio::test]
async fn a_duplicate_url_under_another_id_still_resolves() {
    let body = response(
        "completed",
        json!([
            search_results(json!([
                entry(1, "https://a.example/page"),
                entry(2, "https://b.example/"),
                entry(4, "https://A.example/page"),
            ])),
            message("See [4]."),
        ]),
    );
    let answer = answer_to(body.to_string()).await.expect("an answer");
    assert_eq!(ids(&answer), [1, 2, 4]);
    let four = answer
        .results
        .iter()
        .find(|result| result.id == 4)
        .expect("[4] resolves by id");
    assert_eq!(four.url, "https://A.example/page");
    let sources = answer.sources(6, 200);
    assert_eq!(
        sources
            .iter()
            .map(|source| (source.id, source.url.as_str()))
            .collect::<Vec<_>>(),
        [(1, "https://a.example/page"), (2, "https://b.example/")]
    );
}

/// A malformed entry (no `url`, no `id`, an ill-typed id, not an object) is
/// skipped, and a malformed `results` (not an array) gives nothing from its
/// item. Neither fails the answer, and the good entries around them are kept.
#[tokio::test]
async fn malformed_entries_are_skipped_and_a_malformed_list_gives_nothing() {
    let body = response(
        "completed",
        json!([
            search_results(json!([
                entry(1, "https://a.example/"),
                {"id": 2, "title": "no url"},
                {"url": "https://no-id.example/"},
                {"id": "3", "url": "https://string-id.example/"},
                "not an entry",
                entry(5, "https://e.example/"),
            ])),
            search_results(json!("not a list")),
            search_results(json!({"id": 9, "url": "https://object.example/"})),
            {"type": "search_results"},
            search_results(json!([entry(6, "https://f.example/")])),
            message("Answer."),
        ]),
    );
    let answer = answer_to(body.to_string()).await.expect("an answer");
    assert_eq!(ids(&answer), [1, 5, 6]);
    assert_eq!(answer.text, "Answer.");
}

/// Only `completed` is an answer: `failed` and `incomplete` (each carrying
/// text, and an `error` object) are `Incomplete` with their status, and no
/// partial text comes back as complete; so is an undocumented status.
#[tokio::test]
async fn failed_and_incomplete_responses_are_not_answers() {
    for (wire, status) in [
        ("failed", ResponseStatus::Failed),
        ("incomplete", ResponseStatus::Incomplete),
        ("cancelled", ResponseStatus::Cancelled),
        ("in_progress", ResponseStatus::InProgress),
        ("brand_new", ResponseStatus::Other),
    ] {
        let mut body = response(
            wire,
            json!([
                search_results(json!([entry(1, "https://a.example/")])),
                message("Partial [1]")
            ]),
        );
        body["error"] = json!({"message": "model overloaded", "code": "server_error"});
        let outcome = answer_to(body.to_string()).await;
        assert_eq!(incomplete(&outcome), Some(status), "{wire}: {outcome:?}");
    }
}

/// `completed` with no answer text is `MissingAnswer`: an empty or
/// whitespace text, a message with no `output_text`, no message at all.
#[tokio::test]
async fn completed_with_no_text_is_missing_its_answer() {
    for output in [
        json!([message("")]),
        json!([message(" \n ")]),
        json!([{"type": "message", "content": [{"type": "refusal", "refusal": "no"}]}]),
        json!([search_results(json!([entry(1, "https://a.example/")]))]),
        json!([]),
    ] {
        let outcome = answer_to(response("completed", output.clone()).to_string()).await;
        assert_eq!(
            malformed(&outcome),
            Some(MalformedReason::MissingAnswer),
            "{output}: {outcome:?}"
        );
    }
}

/// Invalid UTF-8 inside a field the crate never reads still refuses the
/// body. The control: the same body with a valid character there is read.
#[tokio::test]
async fn invalid_utf8_in_an_ignored_field_is_refused() {
    let valid = response("completed", json!([message("Paris.")])).to_string();
    let rest = &valid.as_bytes()[1..];
    let with = |bytes: &[u8]| {
        [
            br#"{"metadata":{"note":""#.as_slice(),
            bytes,
            br#""},"#,
            rest,
        ]
        .concat()
    };
    let outcome = answer_to(with(&[0xFF])).await;
    assert_eq!(
        malformed(&outcome),
        Some(MalformedReason::NotUtf8),
        "{outcome:?}"
    );
    let outcome = answer_to(with("é".as_bytes())).await;
    assert_eq!(outcome.expect("the control is read").text, "Paris.");
}

/// A `usage` that is not an object is `None`, and one whose fields have
/// other types keeps only what it can; neither fails the answer.
#[tokio::test]
async fn a_malformed_usage_never_fails_the_answer() {
    for (usage, expect_some) in [
        (json!("lots"), false),
        (json!([1, 2]), false),
        (json!(null), false),
        (
            json!({"input_tokens": "10", "output_tokens": -1, "cost": "cheap"}),
            true,
        ),
    ] {
        let mut body = response("completed", json!([message("Paris.")]));
        body["usage"] = usage.clone();
        let answer = answer_to(body.to_string()).await.expect("an answer");
        assert_eq!(answer.text, "Paris.");
        match answer.usage {
            Some(read) => {
                assert!(expect_some, "{usage}");
                assert_eq!(read, Default::default(), "{usage}");
            }
            None => assert!(!expect_some, "{usage}"),
        }
    }
}

/// A `message` item's own `role` and `status` decide whether it is the
/// answer: a user-role echo of the query with no assistant text is
/// `MissingAnswer`; beside a real assistant message, only the assistant's
/// text is the answer; an `incomplete` assistant message inside a
/// `completed` response is `Incomplete`.
#[tokio::test]
async fn only_a_finished_assistant_message_is_the_answer() {
    let mut echo = message("What is the capital of France?");
    echo["role"] = json!("user");
    let outcome = answer_to(response("completed", json!([echo.clone()])).to_string()).await;
    assert_eq!(
        malformed(&outcome),
        Some(MalformedReason::MissingAnswer),
        "{outcome:?}"
    );

    let body = response("completed", json!([echo, message("Paris.")]));
    assert_eq!(
        answer_to(body.to_string()).await.expect("an answer").text,
        "Paris."
    );

    let mut partial = message("Paris is the cap");
    partial["status"] = json!("incomplete");
    let outcome = answer_to(response("completed", json!([partial])).to_string()).await;
    assert_eq!(
        incomplete(&outcome),
        Some(ResponseStatus::Incomplete),
        "{outcome:?}"
    );
}

/// Two top-level `status` keys refuse the body, in either order: partial
/// text under `"incomplete"` then `"completed"` is never promoted to an
/// answer. Built as text, since the order is the point. The control: one
/// `status` is read.
#[tokio::test]
async fn a_duplicate_status_is_refused_in_either_order() {
    let partial = message("Partial");
    let body = |statuses: &str| format!(r#"{{{statuses},"output":[{partial}]}}"#);
    let outcome = answer_to(body(r#""status":"completed""#)).await;
    assert_eq!(outcome.expect("the control").text, "Partial");
    for statuses in [
        r#""status":"incomplete","status":"completed""#,
        r#""status":"completed","status":"incomplete""#,
    ] {
        let outcome = answer_to(body(statuses)).await;
        assert_eq!(
            malformed(&outcome),
            Some(MalformedReason::DuplicateStatus),
            "{statuses}: {outcome:?}"
        );
    }
}

/// A number serde_json cannot represent (`1e400`, `-1e400`), or a 30-digit
/// integer (a float to serde_json), in a usage count, a result's `id` and a
/// result's `title`, is left out at that position: the count is `None`, the
/// entry with that id is skipped, the title is `None`, and the rest of the
/// answer is kept.
#[tokio::test]
async fn an_unrepresentable_number_is_left_out_and_the_answer_kept() {
    for number in ["1e400", "-1e400", "123456789012345678901234567890"] {
        let mut body = response(
            "completed",
            json!([
                search_results(json!([
                    entry(1, "https://a.example/"),
                    entry(2, "https://b.example/"),
                    entry(3, "https://c.example/"),
                ])),
                message("Paris [3]."),
            ]),
        );
        body["usage"]["input_tokens"] = json!("NUMBER");
        body["output"][0]["results"][0]["id"] = json!("NUMBER");
        body["output"][0]["results"][1]["title"] = json!("NUMBER");
        let raw = body.to_string().replace(r#""NUMBER""#, number);
        assert_eq!(raw.matches(number).count(), 3, "{raw}");
        let answer = answer_to(raw)
            .await
            .unwrap_or_else(|error| panic!("{number}: {error}"));
        assert_eq!(answer.text, "Paris [3].", "{number}");
        assert_eq!(ids(&answer), [2, 3], "{number}");
        assert_eq!(answer.results[0].title, None, "{number}");
        assert_eq!(
            answer.results[1].title.as_deref(),
            Some("Title 3"),
            "{number}"
        );
        let usage = answer.usage.expect("usage");
        assert_eq!(
            (usage.input_tokens, usage.output_tokens, usage.total_tokens),
            (None, Some(5), Some(15)),
            "{number}"
        );
    }
}

/// `SearchAnswer::from_json` is the parse `search()` runs on a `2xx` body:
/// the same answer for the recorded response, and the same error for each
/// failing body.
#[tokio::test]
async fn from_json_agrees_with_search() {
    let parsed = SearchAnswer::from_json(RECORDED.as_bytes()).expect("the recorded answer");
    assert!(parsed.text.ends_with("987.[5]"), "{parsed:?}");
    assert_eq!(parsed.results.len(), 10);
    assert_eq!(answer_to(RECORDED).await, Ok(parsed));

    let mut echo = message("echoed query");
    echo["role"] = json!("user");
    let partial = message("Partial");
    for body in [
        response("failed", json!([message("Partial")]))
            .to_string()
            .into_bytes(),
        response("completed", json!([echo]))
            .to_string()
            .into_bytes(),
        format!(r#"{{"status":"incomplete","status":"completed","output":[{partial}]}}"#)
            .into_bytes(),
        [br#"{"x":""#.as_slice(), &[0xFF], br#""}"#].concat(),
        b"not json".to_vec(),
    ] {
        let parsed = SearchAnswer::from_json(&body);
        assert!(parsed.is_err(), "{parsed:?}");
        assert_eq!(answer_to(body.clone()).await, parsed);
    }
}
