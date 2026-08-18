# stridelabs-testing

Test-only helpers for StrideLabs services: a fail-loud real-Postgres pool, a
`tower::ServiceExt::oneshot` wrapper for axum `Router`s, and a one-line
wiremock JSON stub. Extracted from the ad hoc idioms duplicated across
spendwise-rs's integration tests.

This crate is meant to sit in a consumer's **`[dev-dependencies]`**, never
`[dependencies]` — nothing here has any business in a production binary.

## Feature topology

`default = []`. `oneshot` and `wiremock` are unconditional; one feature gates
the database helper:

| Feature | Default | Adds |
|---|---|---|
| `postgres` | off | [`require_postgres`], via `sqlx`'s Postgres driver + `url` |

`postgres` is gated because `sqlx`'s driver pulls in a real network/TLS
stack — a consumer whose tests never touch a database shouldn't compile it
just to get the `oneshot` helpers.

## Adding the dependency

```toml
[dev-dependencies]
stridelabs-testing = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.4.0", features = ["postgres"] }
```

(During development against an unreleased commit, pin `rev = "<sha>"` instead
of `tag`; see the workspace root README for the local `[patch]` co-development
snippet.)

## `postgres` — fail loud, never skip

```rust,no_run
# #[cfg(feature = "postgres")]
# async fn example() {
use stridelabs_testing::require_postgres;

let pool = require_postgres("postgres://postgres:localdev@localhost:5437/myapp_test").await;
# let _ = pool;
# }
```

`require_postgres(default_url)` reads `DATABASE_URL` from the environment; if
it's unset, it connects to `default_url` instead. Either way, if the
connection can't be established within 2 seconds, **it panics** — naming the
URL it tried (password redacted), the `DATABASE_URL` env var, and the command
to bring the database up (`docker compose up -d`, or `make up`).

This is a direct replacement for the pattern nine of spendwise-rs's eleven
test files carried: a `setup()`/`pool_or_skip()` pair that printed a note to
stderr and returned `None` when Postgres wasn't reachable, silently skipping
every test built on top of it. A green `cargo test` under that pattern proved
nothing — the database-backed behavior might never have run. There is no
`Option`/`Result` return here to shrug off; fix the connection, don't handle
the failure.

**Runs no migrations.** That's deliberate: a shared test helper has no
business knowing an app's migration runner or schema. Build your own
`tests/common/mod.rs` on top of it once per consumer:

```rust,ignore
use sqlx::PgPool;
use stridelabs_testing::require_postgres;

const DEFAULT_DATABASE_URL: &str = "postgres://postgres:localdev@localhost:5437/spendwise_test";

/// A pool against a real, migrated database. Every test that touches the
/// database calls this — never `require_postgres` directly — so the
/// migration runner is wired in exactly one place.
pub async fn migrated_pool() -> PgPool {
    let pool = require_postgres(DEFAULT_DATABASE_URL).await;
    spendwise::db::migrate(&pool).await.expect("run migrations");
    pool
}

/// A migrated pool seeded with whatever fixture a whole test module shares.
pub async fn seeded_pool() -> PgPool {
    let pool = migrated_pool().await;
    seed_default_fixtures(&pool).await.expect("seed fixtures");
    pool
}
```

**Test isolation is explicitly out of scope for this version.** There is no
schema-per-test or transactional rollback here; consumers keep whatever
shared-database strategy they already use (spendwise-rs: random UUID
identifiers per test, so concurrent tests never collide on a unique
constraint). Schema-per-test is future work, not a silent limitation — it's
a decision, recorded here.

### The env-reading seam

`require_postgres` is a thin, env-reading wrapper around a private
`require_postgres_at(url)` that takes the URL directly. That split exists so
this crate's *own* unit tests can exercise the connect/panic path without
mutating `DATABASE_URL` — `std::env::set_var` in a test races every other
test in the same binary, which is the same reason `stridelabs-config` routes
its env helpers through an injectable lookup. Only one test in this crate
(the happy path) reads `DATABASE_URL` for real, by calling the public
function.

## `oneshot` — driving a `Router` without a socket

```rust,no_run
use axum::{routing::get, Router};
use serde_json::json;
use stridelabs_testing::{body_json, get as oneshot_get, post_json};

# async fn example() {
let app: Router = Router::new()
    .route("/widgets", get(|| async { "ok" }))
    .route("/widgets", axum::routing::post(|| async { "created" }));

let response = oneshot_get(app.clone(), "/widgets").await;
assert_eq!(response.status(), 200);

let response = post_json(app, "/widgets", &json!({"name": "gadget"})).await;
let body = body_json(response).await;
# let _ = body;
# }
```

- `get(router, uri)` — a plain `GET`.
- `post_json(router, uri, body)` — a `POST` with `body` JSON-serialized as
  the payload (`content-type: application/json` set automatically).
- `req(router, method, uri, body, headers)` — the general form the two above
  are built from: any method, an optional JSON body, and extra headers.
- `body_json(response)` — read a response body to completion and parse it as
  `serde_json::Value`.

Ported from the `get`/`body_json` pair duplicated across spendwise-rs's
integration tests (e.g. `tests/auth.rs:42-53`) and the same
`tower::ServiceExt::oneshot` idiom `stridelabs-http`'s own `cors` tests
already use — one router built once, then driven with plain
`http::Request`/`Response` values instead of a bound socket and a real HTTP
client.

## `wiremock` — a one-line JSON stub

```rust,no_run
use serde_json::json;
use stridelabs_testing::serve_json;

# async fn example() -> Result<(), reqwest::Error> {
let server = serve_json(201, json!({"id": "abc123"})).await;

let res = reqwest::get(format!("{}/anything", server.uri())).await?;
assert_eq!(res.status().as_u16(), 201);
# Ok(())
# }
```

`serve_json(status, body)` starts a `wiremock::MockServer` with a single
catch-all mock (any method, any path) that always answers with `status` and
`body`. It's deliberately the *only* thing this module owns: anything that
needs to match on path/method/body, return different responses across calls,
or assert on requests received should reach for
`wiremock::{Mock, MockServer, ResponseTemplate}` directly.

`wiremock` is a **regular** (non-dev) dependency of this crate, not a dev
dependency — the whole point of that module is to hand consumers a pinned
`wiremock` without every consumer having to pick and maintain its own version.
Since `stridelabs-testing` itself only ever belongs in a consumer's
`[dev-dependencies]`, that dependency never reaches a production build either
way.

## Not included

Schema-per-test isolation, transactional test rollback, fixture-seeding
helpers (too app-specific — an invite code and a plan tier aren't the same
kind of fixture), and anything issuer/auth-shaped (see `stridelabs-auth`'s
`test-support` feature for minting test JWTs).
