# stridelabs-auth

The resource-server half of slauth: verify the RS256 access tokens slauth (Ory
Hydra) issues, and hash the personal access tokens a service issues for
itself. Extracted from spendwise-rs's `auth::{slauth, token, mod}`.

A service holds one `Verifier` in its application state, hands it a bearer
token per request, and gets back a `VerifiedIdentity`. Turning that identity
into a database row — find-or-create, linking a pre-existing user by email,
admin checks — stays in the service; that is the part that differs everywhere.

## Feature topology

`default = []`. Verification, the JWKS cache and the PAT helpers are
unconditional: they are the crate.

| Feature | Default | Adds |
|---|---|---|
| `axum` | off | `bearer_token(&Parts)`, via the `http` types crate |
| `http` | off | `From<AuthError> for stridelabs_http::AppError` |
| `test-support` | off | `test_support` — offline JWT minting against two committed throwaway keypairs |

Two of those names are unavoidably confusing, so: **`http` means the
*stridelabs-http* crate** (the house `AppError`), while `axum` is what pulls
in the `http` *types* crate. `axum` is named for the consumer rather than the
dependency because `http::request::Parts` is all the helper needs — depending
on axum itself would be heavier than the feature is.

`test-support` keeps test signing keys out of a production build's public API
— and keeps production builds lighter: it is what enables `jsonwebtoken`'s PEM
machinery (~13 transitive crates), which only offline minting needs.
Verification decodes keys from the JWKS, never from PEM, so put the feature in
`dev-dependencies` and release graphs never see it.

## Adding the dependency

```toml
[dependencies]
stridelabs-auth = { git = "ssh://git@github.com/charliek/stridelabs-rust.git", tag = "v0.3.0", features = ["axum", "http"] }

[dev-dependencies]
stridelabs-auth = { git = "ssh://git@github.com/charliek/stridelabs-rust.git", tag = "v0.3.0", features = ["test-support"] }
```

(During development against an unreleased commit, pin `rev = "<sha>"` instead
of `tag`; see the workspace root README for the local `[patch]` snippet.)

## Verifying a token

```rust
use stridelabs_auth::{SlauthConfig, Verifier};

let verifier = Verifier::new(
    SlauthConfig {
        issuer: "https://auth.stridelabs.ai".into(),
        jwks_url: "https://auth.stridelabs.ai/.well-known/jwks.json".into(),
        audience: "spendwise".into(),
        pat_validate_url: None,
    },
    http_client.clone(),
);

let identity = verifier.verify_bearer(token).await?;   // -> VerifiedIdentity
```

`Verifier` is cheap to clone (one `Arc`) and **must be built once**, not per
request: the key cache lives inside it. Put it in `AppState`.

`Verifier::new` builds the `JwksCache` itself, from `config.jwks_url`. There
is no constructor that accepts a cache — a cache pointed at one issuer and a
config naming another is a hole no amount of verification logic can close.

`Verifier::verify_with_jwks(token, &jwks, kid, issuer, audience)` is the same
logic with the network removed: an associated function, public, so a consumer
can test its own wiring without an HTTP client.

## Security notes

### What is checked

In order: the token's `kid` is present in the issuer's key set; the key is
usable; the **RS256** signature; `exp`; `iss` equals the configured issuer;
`aud` contains the configured audience; a **non-empty `email`** claim; a
**non-empty `sub`**.

Pinning the algorithm to RS256 is what rules out the two classic forgeries
(`alg: none`, and HS256 signed with the issuer's public key as an HMAC
secret). The HS256 confusion attack is covered by a test; `alg: none` has no
test because it cannot be constructed — `jsonwebtoken`'s `Algorithm` enum has
no such variant, so a token carrying it fails to parse before any check runs.

`sub` is treated as an **opaque** OIDC subject. In a slauth deployment it
happens to be the Kratos identity UUID and services key their user rows on it,
but nothing here parses or validates its shape.

Two deliberate hardenings over the spendwise original:

- **An empty `sub` is rejected** (`AuthError::MissingSubject`). The original
  accepted `""`, which would key every emptily-subjected token onto one user.
  A token with no `sub` claim at all fails the same way.
- **JWKS refetches are rate-limited** — see below.

### The JWKS cache, and the 30-second interval

`JwksCache::jwks_for_kid(kid)` returns a key set that *contains* `kid`, or an
error.

- A cached set younger than `JWKS_TTL` (**1 hour**) that contains the kid is
  served from memory.
- Anything else is a miss and refetches. Refetching on an unknown kid, not
  just on age, is what makes a key rotation take effect in seconds rather than
  an hour.
- **At most one fetch per `MIN_REFETCH_INTERVAL` (30 seconds).** Without this,
  anyone can mint a syntactically valid token carrying a random `kid` and turn
  every request into an outbound HTTPS call — a request amplifier pointed at
  the one service every other service depends on. Inside the interval the
  answer comes from memory: the cached set if it happens to contain the kid (a
  stale key beats a spurious 401 — the interval protects the issuer, it does
  not expire keys), otherwise `AuthError::UnknownKid` — unless nothing has ever
  been cached, in which case the last *fetch* failed and the error is
  `Jwks`, not a verdict on the caller's token.
- A fetch *attempt* starts the interval, successful or not. A failing issuer
  is exactly when hammering it helps least.

The cost is bounded and worth naming: **a key rotation landing within 30
seconds of the last fetch is invisible for the rest of that interval**, so
tokens signed by the brand-new key are rejected for up to 30 seconds. Issuers
roll keys on the order of days.

Concurrency: the fetch happens under the write lock and the hit-check is
repeated after acquiring it (double-checked locking), so a thundering herd of
misses — what a restart or a rotation actually produces — makes one request.

The cache is an **instance** holding an **injected, shared** `reqwest::Client`.
The original was a process-global `OnceLock` that built and discarded a fresh
client (TLS setup included) on every fetch.

### Errors never echo the token

No `AuthError` variant carries the token, a claim value, or even the `kid` —
all attacker-supplied on exactly the requests that produce an error, and these
strings end up in logs.

`AuthError::InvalidToken` is the only variant whose payload derives from the
token at all, and it is a *classification*: the `jsonwebtoken` error kind is
mapped to one of a fixed set of phrases, never rendered with `Display`. That
is a departure from spendwise's `format!("token rejected: {e}")`, whose output
for a malformed-claims error can quote the claim value that failed to parse.

With the `http` feature:

| `AuthError` | `AppError` | Status |
|---|---|---|
| `Jwks(_)` | `Internal(anyhow)` | 500 |
| everything else | `Unauthorized("invalid or missing credentials")` | 401 |

A JWKS failure is *this service's* outage and says nothing about the caller's
token, so it is a 500 whose detail is logged and not returned. Every other
failure collapses to one generic 401 message: `AppError`'s contract is that a
non-`Internal` payload reaches the client verbatim, and telling a caller which
check failed ("audience is not accepted" vs "signature is invalid") is a free
oracle for anyone assembling a token. The specific `AuthError` is still in the
caller's hand before the conversion — log it there.

## `bearer_token` (feature `axum`)

```rust
use stridelabs_auth::{bearer_token, AuthError};

let token: &str = bearer_token(&parts)?;
let identity = state.verifier.verify_bearer(token).await?;
```

The scheme is matched case-insensitively (RFC 7235) while the credential is
returned verbatim apart from surrounding whitespace — its case is never
touched, because a JWT's base64url is case-sensitive. The result borrows from
`parts`, so extraction allocates nothing. Every way of not having a token (no
header, non-UTF-8 header, another scheme, no scheme at all, empty credential)
is the same `AuthError::MissingToken`.

## Personal access tokens

```rust
use stridelabs_auth::{pat, PatFormat};

// Once, at startup — an invalid prefix should fail the boot, not the tokens.
let format = PatFormat::new("sw_")?;

let token = format.generate();
// token.raw            -> "sw_a1b2c3d4…"   shown to the user once, never stored
// token.hash           -> 64 hex chars     the stored, indexed secret
// token.prefix_display -> "sw_a1b2c3d4"    non-secret, for a token list

// On an incoming request:
if format.has_prefix(raw) {
    let row = tokens::find_active_by_hash(&db, &pat::hash(raw)).await?;
}
```

- The prefix is a parameter (`sw_` is spendwise's brand, not a shared crate's),
  validated as non-empty, ≤ 16 bytes, ASCII alphanumeric/`_`/`-`. The ASCII
  rule is load-bearing: the display prefix is a byte slice.
- `has_prefix` is **a `starts_with` and nothing more** — deliberately, matching
  what spendwise checks inline today. It is a cheap "looks like one of ours"
  filter that skips a database round-trip for an obvious JWT. It validates
  neither the length nor the alphabet of the rest, and a `true` says nothing
  about validity; only the hash lookup does.
- Hashing is **SHA-256, not a password KDF**, on purpose. The body is 32 random
  alphanumeric characters (~190 bits), so an offline attacker holding the hash
  has nothing to guess; what matters instead is that verification is one
  indexed lookup per proxied request, where a bcrypt-per-request design would
  be a self-inflicted denial of service.

Storage, expiry, revocation and last-used tracking stay in the service — they
are database concerns and every service models them differently.

## Test support

```rust
use stridelabs_auth::test_support::{TestClaims, TestKey};

let key = TestKey::primary();
let token = key.mint(
    &TestClaims::new("https://auth.test", "my-service")
        .subject("user-1")
        .email("u@example.com")
        .build(),
);

// Serve the matching key set from a mock issuer:
Mock::given(method("GET")).and(path("/jwks"))
    .respond_with(ResponseTemplate::new(200)
        .set_body_raw(key.jwks_json().to_owned(), "application/json"))
    .mount(&server).await;
```

`TestClaims` defaults to a token that verifies; each setter takes it one step
away (`.email("")`, `.without_email()`, `.subject("")`, `.expires_in(-3600)`).
`TestKey::secondary()` is an unrelated keypair, for the two cases that need a
key the verifier does not trust: a wrong-key signature (`mint_with_kid` with
the primary kid) and a rotation the cache has to notice.

Both keypairs are **throwaway RSA keys committed to this repository** — not
secrets, never used for real authentication, generated fresh for this
workspace rather than copied from any service. See
[`testdata/README.md`](testdata/README.md); the repository `.gitignore` has a
global `*.pem` rule with an explicit exception for that directory.

## Not included

Issuer-side signing (minting real tokens), OAuth2 authorization-code/PKCE flow
handling, and slauth PAT introspection. `SlauthConfig::pat_validate_url`
exists as a config field for the last of these — every consumer that eventually
needs it would otherwise carry its own — but nothing here calls it yet.
