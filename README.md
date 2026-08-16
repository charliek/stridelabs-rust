# stridelabs-rust

Shared Rust crates for StrideLabs services — the Rust twin of
[stridelabs-python](https://github.com/charliek/stridelabs-python). Common
patterns and practices live here once, so services stay consistent.

**Status: all five crates implemented.** The workspace scaffold (Cargo
workspace, CI, toolchain pins) and `stridelabs-config`,
`stridelabs-observability`, `stridelabs-http`, `stridelabs-auth` and
`stridelabs-testing` are all in place. Next up is adopting them into
spendwise-rs. See `slauth/plans/rust-migration.md` for scope and sequencing,
and each crate's own README for its full API and feature topology.

## Crates

| Crate | Status | Contents | Seeded from |
|---|---|---|---|
| `stridelabs-config` | Implemented | Env-var config helpers + layered file loading with field-pathed errors | spendwise-rs `config.rs`, limen `config/load.rs` |
| `stridelabs-observability` | Implemented | tracing init (json/pretty), request-ID tower layer, Prometheus wiring | limen `observability/` |
| `stridelabs-http` | Implemented | `AppError`→`IntoResponse` convention, security-headers + CORS layers, graceful shutdown, reverse-proxy primitives (feature `proxy`), OpenAPI spec mechanics (feature `openapi`) | spendwise-rs `error.rs`, limen `http/`, slauth `http/openapi.rs` |
| `stridelabs-auth` | Implemented | slauth resource-server client: rate-limited JWKS cache, RS256 verification, bearer extraction, PAT hashing, offline test-key minting | spendwise-rs `auth/` |
| `stridelabs-testing` | Implemented | Fail-loud real-Postgres pool, `oneshot` axum router-test helpers, a one-line wiremock JSON stub | spendwise-rs test idioms, hardened |

See [§ Feature topology](#feature-topology-all-five-crates) below for what
each crate turns on by default versus behind a feature flag.

## Conventions

- Cargo virtual workspace; lockstep versions via `[workspace.package]`; shared
  `[workspace.lints]` and `[workspace.dependencies]`.
- **`publish = false` on every crate.** These never go to crates.io — see
  [Consuming these crates](#consuming-these-crates) for how a service
  actually depends on them.
- **Tests fail loudly on a missing external dependency — never skip.**
  `stridelabs-testing::require_postgres` is the concrete example: it panics
  with a message naming the env var and the compose/`make up` command rather
  than silently skipping the test, which is exactly the `pool_or_skip()`
  pattern it exists to replace (nine of spendwise-rs's eleven test files had
  their own copy). A green test suite must mean the behavior it claims to
  cover actually ran.
- OpenAPI default for services: utoipa 5 + utoipa-axum, Swagger UI dev-gated,
  spec exported and linted in CI.
- Issuer-side JWT helpers stay app-local until a second issuer exists (same
  "defer until a second consumer" rule as stridelabs-python).

## Consuming these crates

None of these crates are published to crates.io (`publish = false`
everywhere) — they're consumed as a **git dependency**, pinned to either a
release tag or a commit rev, fetched over plain `https`.

If this repository (or whatever fork you're pointed at) isn't reachable over
`https` — a private fork, or a clone from before this repo's own public flip
— use the SSH + deploy-key recipe in the
[Appendix: Private-fork / SSH consumption](#appendix-private-fork--ssh-consumption)
instead. Everything else below assumes the `https` path.

### Adding the dependency

Once a version is tagged, pin the tag:

```toml
[dependencies]
stridelabs-config = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.4.0" }
```

Before the first tag exists — or when depending on a reviewed-but-unreleased
change — pin the exact commit instead:

```toml
[dependencies]
stridelabs-config = { git = "https://github.com/charliek/stridelabs-rust.git", rev = "<full commit sha>" }
```

`rev` pins are meant to be temporary: once the corresponding change is
released and tagged, bump the consumer back to `tag = "vX.Y.Z"` so its
manifest reads the same way for everyone, forever. Every crate is versioned
in lockstep (one `[workspace.package].version` for the whole workspace), so a
consumer pins **one** tag/rev for however many of the five crates it uses.

### Local co-development

While iterating on a change to this workspace *and* a consumer at the same
time, override the git dependency with a path via `[patch]` in the
consumer's root `Cargo.toml` — never committed, since it points outside that
repository:

```toml
[patch."https://github.com/charliek/stridelabs-rust.git"]
stridelabs-config = { path = "../stridelabs-rust/crates/config" }
stridelabs-observability = { path = "../stridelabs-rust/crates/observability" }
stridelabs-http = { path = "../stridelabs-rust/crates/http" }
stridelabs-auth = { path = "../stridelabs-rust/crates/auth" }
stridelabs-testing = { path = "../stridelabs-rust/crates/testing" }
```

`[patch]` keys the whole *source* (the git URL), not one crate — list every
crate from this workspace the consumer actually depends on, whether directly
or transitively (e.g. `stridelabs-auth`'s `http` feature depends on
`stridelabs-http`, so the consumer's `[patch]` block needs both if it uses
that feature). A patch entry for a crate the consumer doesn't depend on is
harmless — Cargo only applies the ones that match a real dependency — so
listing all five up front, as above, is the simplest thing that stays correct
as a consumer's dependency set grows. The `[patch]` key must match whichever
source URL the consumer's `[dependencies]` actually used — `https://…` for
the primary path above, or the `ssh://…` URL from the appendix if the
consumer is on that path instead.

### Feature topology (all five crates)

Every crate that defines optional features defaults to `default = []` — a
consumer opts into the heavier parts of its dependency graph (a TLS stack, a
database driver, a metrics exporter) explicitly, one feature at a time.
`stridelabs-config` is the exception: it has no feature flags at all, since
everything it provides is unconditional. Full detail — including *why* each
gate exists — lives in each crate's own README; this is the map of what turns
on what.

| Crate | Feature | Default | Adds |
|---|---|---|---|
| `stridelabs-config` | *(none — everything is unconditional)* | — | — |
| `stridelabs-observability` | `prometheus` | off | `metrics` + `metrics-exporter-prometheus`: recorder install, `status_class`, `DURATION_BUCKETS` |
| `stridelabs-http` | `cors` | off | `cors_layer`, via `tower-http/cors` |
| `stridelabs-http` | `openapi` | off | spec canonicalization, `(method, path)` enumeration, committed-spec freshness check, via `utoipa` |
| `stridelabs-http` | `proxy` | off | reverse-proxy primitives, via `reqwest`/`url`/`bytes`/`futures` |
| `stridelabs-auth` | `axum` | off | `bearer_token(&Parts)`, via the `http` types crate |
| `stridelabs-auth` | `http` | off | `From<AuthError> for stridelabs_http::AppError` |
| `stridelabs-auth` | `test-support` | off | offline JWT minting against two committed throwaway keypairs |
| `stridelabs-testing` | `postgres` | off | `require_postgres`, via `sqlx`'s Postgres driver + `url` |

`stridelabs-testing`'s `oneshot` and `wiremock` modules have no feature gate
of their own — both are cheap and every consumer of the crate wants them; only
the Postgres driver is worth gating.

## Appendix: Private-fork / SSH consumption

Everything above assumes you can `git clone` the repo anonymously over plain
`https` — true once this repo is public, and true of a public fork regardless
of this one's own status. If instead you're consuming this repo (or a fork of
it) while it's **private** — today's state, or a private fork you maintain —
`https` won't authenticate and you need this appendix's SSH + deploy-key
recipe instead. The mechanics are the same as the primary path —
`[dependencies]` with `git =`, `[patch]` for local co-development — just with
an `ssh://` URL and a deploy key standing in for the credential-free `https`
fetch.

### Adding the dependency over SSH

```toml
[dependencies]
stridelabs-config = { git = "ssh://git@github.com/charliek/stridelabs-rust.git", tag = "v0.4.0" }
```

Everything from [Adding the dependency](#adding-the-dependency) above
applies the same way — `rev` pins for pre-tag/unreleased work, one tag/rev
per consumer regardless of how many of the five crates it uses — just with
this URL scheme.

### CI authentication for a private git dependency

A consumer's CI needs its own credentials to fetch a private `ssh://` remote
— separate from whatever `GITHUB_TOKEN` that CI run already has, since
`GITHUB_TOKEN` is scoped to the *consumer's* repo, not this one. The recipe
is a **read-only deploy key** registered on the repo being cloned, whose
private half lives only as an Actions secret on the consumer.

**One-time setup, per consumer repo** (needs admin on both repos; not part of
any commit — this is an operational step, see the plan's preflight):

```bash
# 1. Generate a fresh, dedicated keypair. No passphrase: it has to be usable
#    unattended in CI.
ssh-keygen -t ed25519 -f deploy_key -C "spendwise-rs-ci-readonly" -N ""

# 2. Register the public half on THIS repo as a read-only deploy key.
gh api repos/charliek/stridelabs-rust/keys \
  -f title=spendwise-rs-ci-readonly \
  -f key="$(cat deploy_key.pub)" \
  -F read_only=true

# 3. Store the private half as an Actions secret on the CONSUMER repo.
gh secret set STRIDELABS_RUST_DEPLOY_KEY --repo charliek/spendwise-rs < deploy_key

# 4. Shred the local key material. Nothing after this point should still
#    have a copy of the private key on disk.
shred -u deploy_key deploy_key.pub
```

The deterministic title (`<consumer-repo>-ci-readonly`) is what makes the key
identifiable for rotation later, without having to guess which of possibly
several deploy keys on this repo belongs to which consumer.

**The workflow side**, in the consumer's CI, on every job that runs `cargo`
against this dependency:

```yaml
env:
  # Cargo's built-in fetcher does support ssh-agent, but only a narrow
  # slice of SSH configuration with it; routing through the system `git`
  # CLI sidesteps that whole class of surprises (host-key files, agent
  # socket discovery, ssh_config directives) with one env var. See
  # https://doc.rust-lang.org/cargo/appendix/git-authentication.html
  CARGO_NET_GIT_FETCH_WITH_CLI: "true"

steps:
  - uses: actions/checkout@v6

  # Pinned by full commit SHA, not a floating tag — this step handles a
  # private key, so its supply chain is not something to trust to a mutable
  # ref. (SHA verified against the upstream v0.10.0 release tag.)
  - uses: webfactory/ssh-agent@e83874834305fe9a4a2997156cb26c5de65a8555 # v0.10.0
    with:
      ssh-private-key: ${{ secrets.STRIDELABS_RUST_DEPLOY_KEY }}

  # GitHub's published host keys, committed to the consumer's own repo
  # (this file lives alongside the consumer's workflow, not in
  # stridelabs-rust) rather than fetched with `ssh-keyscan` at CI time — a
  # scan trusts whatever answers on the wire during that run; a committed,
  # source-controlled list is what you meant to trust instead. See:
  # https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
  - run: |
      mkdir -p ~/.ssh
      cat .github/github_known_hosts >> ~/.ssh/known_hosts

  - run: cargo test --workspace --locked
```

Apply the `ssh-agent` + known-hosts + `CARGO_NET_GIT_FETCH_WITH_CLI` steps to
**every** job that touches `cargo` — a build-test job and, e.g., an e2e job,
both need their own fetch of this dependency.

### Rotating the deploy key

1. Delete the deploy key from this repo (`gh api -X DELETE
   repos/charliek/stridelabs-rust/keys/<key-id>`, found via `gh api
   repos/charliek/stridelabs-rust/keys`).
2. Delete the consumer's Actions secret (`gh secret delete
   STRIDELABS_RUST_DEPLOY_KEY --repo charliek/<consumer>`).
3. Re-run the one-time setup above to mint and register a replacement.

There is no in-place "update" — a rotation is always delete-then-recreate, so
a compromised key is fully revoked (not merely superseded) the moment step 1
completes.
