# stridelabs-auth

The resource-server half of slauth, the StrideLabs auth service: verify the
RS256 access tokens slauth (Ory Hydra) issues — or, through
`Verifier::for_issuer`, another issuer's, under claim rules you choose — and
hash the personal access tokens a service issues for itself.

A service holds one `Verifier` in its application state, hands it a bearer
token per request, and gets back a `VerifiedIdentity`. Turning that identity
into a database row — find-or-create, linking a pre-existing user by email,
admin checks — stays in the service; that is the part that differs everywhere.

## Feature topology

`default = []`. Verification, the JWKS cache and the PAT helpers are
unconditional: they are the crate. So is its tokio dependency (`sync`, `rt`,
`time`) and `futures-util` (`std` only): the JWKS cache runs each fetch on a
task of its own, spawned on the runtime the lookup is polled on, and bounds
each lookup's wait on a fetch with a timer on that lookup's runtime.
**Lookups require a Tokio runtime with the time driver enabled, as reqwest
does.**

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

**No TLS, in any feature.** The crate's `reqwest` (0.13) has `json` and
nothing else: it never builds a client outside its own tests —
`Verifier::new` and `JwksCache::new` take yours — so the TLS stack, and with
it the process's rustls crypto provider, is your choice. To fetch an
`https://` JWKS, enable a TLS feature on your own `reqwest` 0.13 (`rustls`:
the aws-lc-rs provider plus the OS trust store), and keep one rustls provider
in your graph: rustls `ring` from something else (redis-rs `tls-rustls`, sqlx
`tls-rustls-ring`) next to aws-lc-rs makes `rustls::ClientConfig::builder()`
panic. CI's "Guard: stridelabs-auth pulls no rustls" keeps rustls out of this
crate's graph.

**One JWT crypto backend: aws-lc-rs.** The crate's `jsonwebtoken` (11) uses
its `aws_lc_rs` backend, and that binds your whole graph, not just this crate:
jsonwebtoken picks its backend from crate features at runtime, Cargo unifies
those features across your graph, and with both `aws_lc_rs` and `rust_crypto`
on (or neither) it compiles cleanly and then panics at the first sign or
verify, in `verify_bearer`, `verify_with_jwks` and `TestKey::mint` alike. The
rule: **never enable jsonwebtoken `rust_crypto`**, on your own `jsonwebtoken`
or through any other dependency, **and use aws-lc-rs as the only rustls
provider** (install it at startup with
`rustls::crypto::aws_lc_rs::default_provider().install_default()` if your
service builds rustls configs itself). `rust_crypto` is rejected here because
it brings back the `rsa` crate (RUSTSEC-2023-0071, no fix). aws-lc-sys, a C
build like ring before it, comes along into production graphs.
`signing_and_verifying_work_on_the_one_crypto_backend` (in `verify.rs`) is the
test that panics when the backend set is wrong; a consumer's own mint-and-verify
test does the same for its graph.

`Verifier::verify_with_jwks`, `Verifier::claims_with_jwks`,
`Verifier::claims_with_jwks_checked`, `JwksCache::jwks_for_kid`,
`TestKey::jwks` and `test_support::test_jwks` take or return jsonwebtoken
11's `JwkSet`. To name
it, depend on the same major with the same backend:

```toml
jsonwebtoken = { version = "11", default-features = false, features = ["aws_lc_rs"] }
```

## Adding the dependency

```toml
[dependencies]
stridelabs-auth = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.8.0", features = ["axum", "http"] }

[dev-dependencies]
stridelabs-auth = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.8.0", features = ["test-support"] }
```

`PatValidator` (slauth PAT validation, below) is new in v0.7.0: pin
`tag = "v0.7.0"` or later to use it.

(During development against an unreleased commit, pin `rev = "<sha>"` instead
of `tag`; see the workspace root README for the local `[patch]` snippet.)

## Verifying a token

```rust
use stridelabs_auth::{SlauthConfig, Verifier};

let verifier = Verifier::new(
    SlauthConfig {
        issuer: "https://auth.example.com".into(),
        jwks_url: "https://auth.example.com/.well-known/jwks.json".into(),
        audience: "my-service".into(),
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

### Tokens with other claim rules

`verify_bearer` is for *sign-in* tokens: it insists on a non-empty `email` and
`sub` and hands back a `VerifiedIdentity`. A token minted for another purpose
— an MCP access token, whose audience is the MCP resource URL, whose email is
optional and whose scopes are the point — needs the same cryptography with
different claims:

```rust
#[derive(serde::Deserialize)]
struct McpClaims {
    #[serde(default)]
    sub: String,
    #[serde(default)]
    scope: Option<String>,
}

let claims: McpClaims = verifier.verify_bearer_claims(token).await?;
if claims.sub.is_empty() {
    // the caller's rule to enforce, not this crate's
}
```

`Verifier::verify_bearer_claims::<C>` fetches the key set by `kid` exactly as
`verify_bearer` does, and `Verifier::claims_with_jwks::<C>(token, &jwks, kid,
issuer, audience)` is its network-free twin. Both run the one copy of the key
selection and validation logic (`verify_with_jwks` is built on
`claims_with_jwks`): an RS256-fit key under the `kid`, the signature, `exp`,
`iss` and `aud`, all three required. **Nothing about `email` or `sub` is
checked** — the caller owns those, including rejecting an empty `sub` if it
keys rows on it. A claim set that does not deserialize into `C` is
`AuthError::InvalidToken("claims are malformed")`, never serde's message
(which can quote the value). `stridelabs-mcp`'s verifier is built on this.

### Tokens from another issuer: `Verifier::for_issuer`

`Verifier::new`'s claim rules are slauth's: `iss` exact, `aud` required, a
60 s leeway on `exp`, `nbf` not checked. An issuer with other rules — WorkOS,
whose access tokens carry no `aud` — gets a verifier built from a
`ClaimChecks`:

```rust
use std::time::Duration;
use stridelabs_auth::{Audience, ClaimChecks, Verifier};

// WorkOS: no `aud` in its access tokens; `iss` names the client.
let checks = ClaimChecks::new(
    format!("https://api.workos.com/user_management/{client_id}"),
    Audience::NotValidated,
)
.with_leeway(Duration::ZERO);          // `nbf` is checked by default

let verifier = Verifier::for_issuer(
    checks,
    format!("https://api.workos.com/sso/jwks/{client_id}"),
    Some(Duration::from_secs(3600)),   // JWKS TTL; `None` is `JWKS_TTL`
    http_client.clone(),
);

#[derive(serde::Deserialize)]
struct WorkosClaims {
    #[serde(default)]
    sub: String,
}

let claims: WorkosClaims = verifier.verify_bearer_claims(token).await?;
if claims.sub.is_empty() {
    // the caller's rule to enforce, not this crate's
}
```

`ClaimChecks::new(issuer, audience)` holds the claim rules, applied after
the signature:

| Rule | Default | Change with |
|---|---|---|
| `iss` equals the issuer, exactly (a trailing slash is a mismatch) | always; `iss` required | — |
| `exp` | always; required | — |
| `aud` | `Audience::Required(aud)`: required, and equal to `aud` or an array containing it. `Audience::NotValidated`: not checked, whatever the token carries | the `Audience` you pass |
| Leeway on `exp` and `nbf` | 60 s (`DEFAULT_LEEWAY`) | `.with_leeway(Duration)` — whole seconds (a fraction is dropped), at most a day |
| `nbf`, when present | checked; never required | `.with_nbf_validation(false)` |

Times are whole Unix seconds: with no leeway a token is accepted through the
second its `exp` names and refused from the next, and refused while its
`nbf` is later than now. A present `nbf` that is not a number is "token is
malformed" while `nbf` is checked. As everywhere in jsonwebtoken, an `iss`
*array* that contains the issuer passes too; RFC 7519 makes `iss` one string,
and only the issuer's own key can sign one.

**`Audience::NotValidated` skips the `aud` check, and is safe only when the
issuer binds the audience some other way**: when the exact `iss` you require
can only be stamped on tokens minted for your service. WorkOS's is
`https://api.workos.com/user_management/{client_id}`, so the issuer match
pins the client. Against an issuer that serves several services under one
`iss` (slauth, any shared OIDC provider) it accepts a token minted for any of
them. There is no `Default` for `Audience` and no conversion into
`NotValidated`: a consumer has to write it out, where a reviewer will see it.

Everything else is `Verifier::new`'s, from the same code: RS256 only (`none`
and HS256 refused before the signature), a `kid` required
(`AuthError::MissingKid`), the key-fitness rules below, and the error
classification. `for_issuer` builds its own `JwksCache` from the URL, as `new`
does — no cache for one issuer can be paired with rules for another — with
the TTL you give it (`None` is `JWKS_TTL`, an hour) and every other bound at
its default, so it inherits the whole cache contract below: a key set is
never served past its TTL, a lookup once it has expired and cannot be
refetched is `AuthError::Jwks` (a 5xx), and so on.

On a `for_issuer` verifier:

- `verify_bearer_claims::<C>` applies its `ClaimChecks`, and
  `claim_checks()` returns them. `Verifier::claims_with_jwks_checked::<C>(token,
  &jwks, kid, &checks)` is the network-free twin, and `claims_with_jwks` is
  that function with slauth's rules (`claim_checks()` on a `Verifier::new`
  verifier).
- `verify_bearer` applies its `ClaimChecks`, then `VerifiedIdentity`'s rules
  (a non-empty `email` and `sub`). That is meaningful only for an issuer
  whose access tokens carry an email: a WorkOS access token has none by
  default, so every one would be `AuthError::MissingEmail`. Use
  `verify_bearer_claims` with your own claims type, and check `sub` yourself.
- `config()` is **informational only**: a `SlauthConfig` synthesized from
  its arguments, with the issuer, the JWKS URL, no `pat_validate_url`, and
  `audience` the `Required` value or, under `NotValidated`, a sentinel no
  issuer mints (`"\0audience not validated"`, starting with a NUL
  character; never empty). It does not hold this verifier's rules
  (`claim_checks()` does). **Never rebuild the verifier with
  `Verifier::new(config)`**: that applies slauth's rules (`aud` required, a
  60 s leeway, `nbf` unchecked), not this verifier's leeway or `nbf`
  setting, so under `Required` it can accept tokens this verifier refuses.
  Under `NotValidated` the sentinel makes that mistake refuse every real
  token instead. Clone the verifier.
- `Debug` prints the JWKS URL redacted, as `Verifier::new`'s does. The
  issuer and the audience print as configured (the issuer exactly, so a
  trailing-slash mismatch is visible), except that an issuer that is a URL
  carrying userinfo, a query or a fragment prints as
  `scheme://host[:port]/path`, as `SlauthConfig`'s does.

`TestClaims::without_audience()` mints a token with no `aud`, and
`TestClaims::not_before_in(secs)` one with an `nbf` (feature
`test-support`, below).

## Security notes

### What is checked

In order: the issuer's key set has a key under the token's `kid` that is
**fit for RS256 signatures**; the key is usable; the **RS256** signature;
`exp`; `iss` equals the configured issuer; `aud` contains the configured
audience; a **non-empty `email`** claim; a **non-empty `sub`**. (That is
`verify_bearer` on a `Verifier::new` verifier. A `Verifier::for_issuer`
verifier's claim rules are its `ClaimChecks`, above; the key and signature
checks are the same.)

"Fit" means an RSA key whose `alg`, `use` and `key_ops`, where present, say
RS256, `sig` and `verify`. jsonwebtoken builds a verifier from a JWK without
reading any of them, so without this an RSA key the issuer published for
encryption (`use: enc`, `alg: RSA-OAEP`) would verify a token that names its
kid. A kid with only unfit keys is `UnknownKid` (401), not `Jwks` (500): there
is no verification key by that name, and the kid is the caller's to choose, so
a 500 would hand anyone a way to raise the error rate whenever the issuer
publishes encryption keys next to its signing keys. Keys sharing a kid are all
considered, so a listed-first encryption key cannot hide the signing key.

Pinning the algorithm to RS256 is what rules out the two classic forgeries
(`alg: none`, and HS256 signed with the issuer's public key as an HMAC
secret). Both are covered by tests. `jsonwebtoken` cannot mint an `alg: none`
token, so its test assembles the header by hand: `Algorithm` has no such
variant, so the header fails to parse (`AuthError::MalformedToken`) before any
check runs.

`sub` is treated as an **opaque** OIDC subject. In a slauth deployment it
happens to be the Kratos identity UUID and services key their user rows on it,
but nothing here parses or validates its shape.

Two deliberate hardenings over the original implementation this crate
replaced:

- **An empty `sub` is rejected** (`AuthError::MissingSubject`). The original
  accepted `""`, which would key every emptily-subjected token onto one user.
  A token with no `sub` claim at all fails the same way.
- **JWKS refetches are rate-limited** — see below.

### The JWKS cache: never past the TTL, refreshed ahead of it

`JwksCache::jwks_for_kid(kid)` returns a key set that *contains* `kid`, or an
error, and **never a set past its TTL**. A set's age counts from its last
*successful* fetch; every bound below is per cache instance, on its own
monotonic clock.

- **Fresh hit.** A set younger than `JWKS_TTL` (**1 hour**) that contains the
  kid is served from memory.
- **Refresh ahead.** In the last tenth of the TTL (at least 60 s, at most
  10 min: the last 6 minutes at the defaults), a lookup the set answers is
  still served at once and also starts a background refresh nobody waits on.
  A failed refresh is retried 1 s after it *completed*, doubling to 8 s
  (never more than the refetch floor), while the set keeps answering until
  its TTL, so an
  issuer blip near the hour costs nothing. It needs traffic in that window,
  and it is off for a TTL under three refetch floors (below); without it,
  the first lookup at or after the TTL fetches.
- **No stale fallback.** From the TTL on, a lookup waits for the fetch in
  flight or starts one, and is refused with `AuthError::Jwks` (a 500 under
  the `http` feature, a 503 `Unavailable` in stridelabs-mcp) if that fails.
  A key the issuer retired (say,
  because it leaked) stops verifying no later than one TTL after the last
  successful fetch that still published it, whatever the issuer is doing.
  Through v0.8.0 that bound was `JWKS_TTL + MIN_REFETCH_INTERVAL`.
- **Prompt recovery.** After a failure, the next fetch of a needed set is
  allowed on the same spacing, 1 s after that failure completed, doubling to
  8 s; lookups in between are refused at once. Once the issuer is back,
  recovery takes at most what is left of an attempt still failing at that
  moment (up to `FETCH_TIMEOUT`, 10 s), then the backoff (up to 8 s), then
  one successful fetch (up to `FETCH_TIMEOUT`): about 28 s at the defaults,
  and only once a lookup arrives to start that fetch.
- **Unknown kids are rate-limited.** Refetching on an unknown kid, not just
  on age, is what makes a key rotation take effect in seconds rather than an
  hour. Against a set inside its TTL it happens **at most once per refetch
  floor** (30 s at the defaults), counted from the start of the last attempt
  of any kind. Without that floor, anyone can mint a syntactically valid
  token carrying a random `kid` and turn every request into an outbound
  HTTPS call — a request amplifier pointed at the one service every other
  service depends on. Inside the floor the answer comes from memory, and
  tells two cases apart by the kids of the sets this cache fetched (it
  remembers the last few sets' kids, at most 64; only a fetched set adds to
  that memory, so forged kids cannot grow it):
  - a kid **seen** in an earlier set and since removed is a retired key:
    `AuthError::UnknownKid` (401), so a client refreshes its token at once;
  - a kid **never seen** may be a rotation newer than the last fetch, or a
    forged kid: `AuthError::UnseenKid`, "refetch suppressed" (a 500 under the
    `http` feature, a 503 `Unavailable` in stridelabs-mcp, as for `Jwks`).
    The token is refused either way, and the next lookup past the floor
    refetches; a kid still absent after that refetch is `UnknownKid`.

  Only a set inside its TTL gives either verdict: without one the error is
  `Jwks`, not a 401 blaming the caller's token for an outage.
- **The body is capped.** A fetch reads at most `jwks::MAX_JWKS_BYTES`
  (1 MiB; an issuer's set is a few keys of under 2 KiB each), chunk by
  chunk and inside `FETCH_TIMEOUT`. A larger body, a valid key set
  included, is a failed fetch (`AuthError::Jwks`), handled as any other is,
  and never buffered whole: the read stops at the chunk that would pass the
  cap. When your client decodes (a reqwest decoder feature in your graph),
  the cap counts decoded bytes, not bytes on the wire.

The **refetch floor** `F` is `min(MIN_REFETCH_INTERVAL, max(ttl, 1 s))`. A
TTL below the interval lowers it, so a TTL of 1 s or more is refetched at
expiry rather than refused for an interval longer than the set lives; but
never under 1 s unless the interval itself is, so a zero TTL is still
rate-limited. A TTL under 1 s is refused from its expiry until `F` after the
last completed attempt ("key set expired inside the minimum refetch
spacing"). A zero TTL caches nothing: each fetch serves only the lookups that
waited on it, and fetches start at most once per `F`: once a second while the
interval is at least 1 s, and once per interval when it is shorter (a zero
interval: no limit).

The cost of the floor is bounded and worth naming: **a key rotation landing
within 30 seconds of the last attempt is invisible for the rest of that
floor**, so tokens signed by the brand-new key are refused (`UnseenKid`) for
up to 30 seconds. A failed attempt counts, so a rotation that coincides with an issuer
blip waits out both. Issuers roll keys on the order of days.

**Load on the issuer**, per cache, with a failing issuer and steady traffic:
at most one unknown-kid fetch per floor against a valid set (2 a minute);
and, in the refresh window and after expiry alike, attempts 1, 2, 4, 8, 8 …
s apart (about 8 a minute). Nobody can make the age-driven ones happen
early. Replicas of one service expire, and so retry, in lockstep.

**Concurrency.** A fetch is single-flight and runs on a tokio task of its
own: cancelling the request that started it never cancels it, no lock is
held across it, and a fresh hit never waits behind one. A herd of misses —
what a restart or a rotation actually produces — makes one request. Every
lookup that joins a fetch has a bound of its own, a timer on its own runtime:
`FETCH_TIMEOUT` plus 1 s on a *first* attempt (the fetch's own 10 s timeout
normally ends it first), 2 s on a *retry*, so a black-holed issuer cannot
hold every request for a whole fetch timeout over and over. At its bound a
lookup gets `Jwks` while the fetch carries on. A joiner checks the set's age again when it resumes, and refuses
a set that crossed its TTL meanwhile.

**The tokio runtime.** Lookups require a Tokio runtime with IO and the time
driver enabled, as reqwest does: a lookup that starts a fetch (a
refresh-ahead included) or joins one panics outside a runtime, as v0.8.0's
did, and on a runtime built without `enable_time` a lookup that has to wait
on a fetch panics in tokio's timer; a fresh hit needs no runtime. The fetch
is spawned on the runtime of the lookup that starts it, which **must keep
being driven until the fetch ends**. A fetch on a
current-thread runtime whose `block_on` has returned is frozen with it:
lookups on other runtimes that need it give up at their own bound (their
own runtime's timer, never the frozen one's), but the slot stays taken until
that runtime finishes the fetch or is dropped. A runtime shut down mid-fetch
drops the task, which counts as a failed attempt; its waiters get `Jwks`.

`JwksCache::with_ttl` and `JwksCache::with_min_refetch_interval` replace the
two durations, for tests that need to watch a set expire or a floor close
without sleeping. The defaults are the contract: a zero interval turns all
rate limiting off, and `Verifier::new` always builds its cache with the
defaults. `Verifier::for_issuer` takes an optional TTL (`with_ttl`'s
semantics) and leaves the refetch interval at its default.

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
is a departure from the original implementation this crate replaced, whose
`format!("token rejected: {e}")` could quote the claim value that failed to
parse.

Nor do they echo the JWKS URL, and neither does any type's `Debug`.
`AuthError::Jwks` renders a failed fetch's `reqwest::Error` with
`without_url()`: a `reqwest::Error` otherwise ends `for url (…)` with the
query string, and a JWKS URL is configuration that can carry a credential.
`SlauthConfig`, `JwksCache` and `Verifier` print it in `Debug` as
`scheme://host[:port]/path` (userinfo, query and fragment dropped; so is
`pat_validate_url`'s), so `tracing::info!(?config)` is safe. The issuer
(`SlauthConfig`'s and `ClaimChecks`') prints exactly as configured unless it
is a URL carrying one of those parts, when it is redacted the same way. A
canary test pins both: a URL with a token in the query and userinfo in the
authority, checked in the error's `Display`/`Debug`, in the line the `http`
feature logs for the 500, and in each type's `Debug`.

With the `http` feature:

| `AuthError` | `AppError` | Status |
|---|---|---|
| `Jwks(_)` | `Internal(anyhow)` | 500 |
| `UnseenKid` | `Internal(anyhow)` | 500 |
| everything else | `Unauthorized("invalid or missing credentials")` | 401 |

A JWKS failure is *this service's* outage and says nothing about the caller's
token, so it is a 500 whose detail is logged and not returned. So is a
refetch the cache suppressed for a never-seen kid. Anyone can mint a token
with a random kid, so forged kids inside the refetch floor are one logged 500
each: their detail, `slauth JWKS: … refetch suppressed`, is distinct from a
fetch failure's, so 5xx alerting can exclude it, and a consumer that cares
about the volume rate-limits unauthenticated traffic. `AuthError` is
`#[non_exhaustive]`: a consumer mapping it itself needs a wildcard arm, and
should send `UnseenKid` where it sends `Jwks`. Every other
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

## slauth PATs: `PatValidator`

```rust
use stridelabs_auth::{PatValidationError, PatValidator, SLAUTH_PAT_PREFIX};

// Once, at startup. `None` when the config names no `pat_validate_url`:
// the service then takes no slauth PATs.
// The client MUST follow no redirects (below).
let no_redirects = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .build()?;
let pats: Option<PatValidator> = PatValidator::from_config(&config, no_redirects);

// Per request, when the service takes PATs:
if let Some(pats) = &pats {
    if bearer.starts_with(SLAUTH_PAT_PREFIX) {
        match pats.validate(bearer).await {
            Ok(identity_id) => { /* a uuid::Uuid: the slauth identity */ }
            Err(PatValidationError::Rejected { reason }) => { /* 401 */ }
            Err(PatValidationError::Unavailable { reason }) => { /* 503 */ }
        }
    }
}
```

slauth issues `slp_live_…` PATs and resolves them at
`POST /api/v1/pat/validate` (`Authorization: Bearer <pat>`, no body). The
validator is that call and nothing more — the Rust twin of
stridelabs-python's `PATValidator`, with its outcomes and its messages:

| What happened | Result |
|---|---|
| not `slp_live_` + exactly 43 characters (`is_slauth_pat`) | `Rejected("Invalid PAT format")`, without calling slauth |
| the answer came from anywhere but the validate URL (a following client was redirected elsewhere) | `Unavailable("Authentication service error")` |
| no complete answer within 5 s (`PAT_VALIDATION_TIMEOUT`) | `Unavailable("Authentication service timeout")` |
| any other transport failure | `Unavailable("Authentication service unavailable")` |
| a body over 16 KiB (`slauth_pat::MAX_ANSWER_BYTES`) | `Unavailable("Authentication service error")` |
| HTTP 401 | `Rejected("Invalid or expired PAT")` |
| any other status but 200, a 3xx included | `Unavailable("Authentication service error")` |
| a body that is not a JSON object | `Unavailable("Authentication service error")` |
| `valid` anything but `true` | `Rejected(<reason>)` for one of slauth's codes (`invalid_format`, `not_found`, `revoked`, `expired`), else `Rejected("Invalid token")` |
| `identity_id` not a UUID | `Unavailable("Authentication service error")` |
| otherwise | `Ok(identity_id)` |

**The client MUST NOT follow redirects: build it with
`reqwest::redirect::Policy::none()`.** The validator takes the consumer's
client, so its TLS stack and root store stay the consumer's choice — and so
does its redirect policy, which reqwest defaults to *following*. With
redirects off, every 3xx is the service error Python's httpx (which follows
none) made of it, and no redirect's answer is ever read as slauth's verdict.

With a following client, one check remains as defence in depth, and it is
only that: an answer whose final URL is not the validate URL — another
origin, or another path on slauth's — is a service error whatever it says.
It **cannot see** a redirect that ends where it started:
`POST /validate` → `303` → `GET /validate` has the requested URL as its
final one, so whatever answers that `GET` decides — a `valid: true` would be
trusted, and an outage could come back as a 401. A test pins that
limitation. (reqwest drops `Authorization` from a redirect that leaves the
origin, so the PAT itself does not follow one there.)

`is_slauth_pat` is Python's `is_pat_token` rule to the letter: the prefix,
then 43 Unicode scalar values, alphabet unchecked. Route a bearer token on
the prefix alone and let `validate` refuse a wrong shape, so a mangled slauth
PAT is refused as a PAT rather than tried as a JWT.

Where Python's behaviour is undefined (an unhandled exception) or cannot be
expressed, the answer is the nearest defined one: a token no HTTP header can
carry is `Rejected("Invalid PAT format")`, and JSON that is not an object is
a service error. Three hardenings go further than Python: the final-URL
check on redirects (above, and no substitute for a no-redirect client);
a body cap, where Python read any size; and `reason`, which passes through
only as one of slauth's four codes — Python passed any value through, so an
endpoint echoing its request could put the token or the URL into an error.
The 5 s is one deadline for the whole exchange (httpx's applied per phase).
`PatValidator::with_timeout` replaces the 5 s, for tests.

Caching is the consumer's to add (store and TTL are app-specific), and so is
what a PAT may do: slauth's answer carries an identity and no scopes.

Neither the token nor the validate URL ever appears in a
`PatValidationError` — it holds a fixed message or one of slauth's codes —
nor in the `warn` line each `Unavailable` outcome logs (a `reqwest::Error`
is rendered `without_url()`), nor in `PatValidator`'s `Debug`, which prints
the URL as `scheme://host[:port]/path`. The request's `Authorization` value
is marked sensitive.

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

- The prefix is a parameter (`sw_` is one service's brand, not a shared crate's),
  validated as non-empty, ≤ 16 bytes, ASCII alphanumeric/`_`/`-`. The ASCII
  rule is load-bearing: the display prefix is a byte slice.
- `has_prefix` is **a `starts_with` and nothing more** — deliberately. It is a
  cheap "looks like one of ours"
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
away (`.email("")`, `.without_email()`, `.subject("")`, `.expires_in(-3600)`,
`.without_audience()`, `.not_before_in(30)`). No `nbf` is minted unless
`.not_before_in` asks for one; a token for an issuer that sends no `aud` is
`TestClaims::new(issuer, "").without_audience()`.
`.claim(name, value)` adds any other claim — `.claim("scope", json!("a b"))`,
`.claim("scp", json!(["a"]))`, `.claim("client_id", json!("c"))` — and is
applied last, so it also replaces one of the builder's own (an `aud` array,
say).
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
handling, and caching PAT validations (a [`PatValidator`](#slauth-pats-patvalidator)
answer is the consumer's to cache — stridelabs-mcp's `redis` feature has one).
