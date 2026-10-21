# stridelabs-gcp

Policy-free Google Cloud building blocks for StrideLabs services: an access
token from Application Default Credentials, a small GCS JSON-API client, and
Vertex AI `generateContent` types. It speaks Google's REST APIs with the
consumer's `reqwest` client and nothing else. `gcp_auth`,
`google-cloud-storage` and `object_store` were rejected, because each brings a
heavy graph and a second TLS or crypto stack. tapper and parcel had already
rejected them for the same reasons.

What a user reads, how long a call may take, which model to call and how
objects are named all stay in the service. This crate reports what Google
answered.

## Feature topology

`default = []`.

| Feature | Default | Adds |
|---|---|---|
| `service-account-key` | off | `service_account` credentials: signing the RS256 JWT-bearer assertion, through jsonwebtoken (`aws_lc_rs` backend) with `use_pem`. With the feature off, a `service_account` credential is `GcpAuthError::Unsupported("service_account key support not compiled in (enable stridelabs-gcp/service-account-key)")`. It is never skipped in favour of the next source. |
| `vertex` | off | the `vertex` module. It adds no dependency. |

`auth` and `storage` are always present.

**No TLS, in any feature.** As with stridelabs-auth, the crate's `reqwest`
(0.13) has `json` and `form` and nothing else. Every constructor takes your
`reqwest::Client`, so the TLS stack, and with it the process's rustls crypto
provider, is your choice. Google's APIs are `https://`, so enable a TLS
feature on your own reqwest (`rustls`: the aws-lc-rs provider plus the OS
trust store). The metadata server is plain `http://` by design.

**Your client must carry no default credentials.** Do not give the
`reqwest::Client` you hand in a default `Authorization` header, or any other
credential in `default_headers`. reqwest sends default headers on every
request, including the plaintext one to the metadata server and every request
to an emulator.

**Credential files are trusted input.** A credential file or base64 blob is
operator-controlled configuration. A hostile one could cause harm before any
check here runs; for example, a pathological PEM could exhaust the stack inside
jsonwebtoken's `simple_asn1` parser. That risk is accepted, because whoever
can write the file already controls the identity.

**One JWT crypto backend: aws-lc-rs.** `service-account-key` signs with the
workspace's jsonwebtoken, which uses the `aws_lc_rs` backend. Never enable
jsonwebtoken `rust_crypto` anywhere in your graph (see the root README, "One
crypto provider").

## Adding the dependency

```toml
[dependencies]
stridelabs-gcp = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.8.0", features = ["service-account-key", "vertex"] }
```

(`v0.7.0` is the first release with this crate; `upload_with` and
`UploadOptions` are new in `v0.8.0`. During development against an
unreleased commit, pin `rev = "<sha>"` instead of `tag`; see the workspace
root README for the local `[patch]` co-development snippet.)

A service that runs only on ADC (the metadata server in production, a
developer's gcloud login locally) can leave out `service-account-key`. Turn
it on if any deployment hands the service a key file. imgmcp turns it on so
that one binary supports every documented source.

## `auth`: `TokenProvider`

```rust
use stridelabs_gcp::auth::{TokenProvider, CLOUD_PLATFORM_SCOPE};

// At startup. Synchronous, and only local reads (env vars and files).
let tokens = TokenProvider::from_environment(
    http.clone(),
    &[CLOUD_PLATFORM_SCOPE],
    config.google_credentials_base64.as_deref(),
)?;
tracing::info!(source = %tokens.source(), kind = %tokens.kind(), "GCP credentials");

// Per request.
let token = tokens.token().await?;
let response = token.authorize(http.post(url)).json(&body).send().await?;
```

`TokenProvider` is one `Arc`. Clones share the cache, so build it once and
keep it in your state. `token()` must run on a tokio runtime, because each
refresh runs on a task of its own.

### The source chain

`from_environment(http, scopes, explicit_b64)` takes the first source that is
**configured**:

1. `explicit_b64`: base64 credential JSON, which is imgmcp's
   `GOOGLE_CREDENTIALS_BASE64` and tapper's and parcel's
   `GOOGLE_CREDENTIALS`. Padding is optional and whitespace (line wrapping)
   is ignored. Any supported `type` is accepted. `None` means absent, and any
   `Some` is configured, including `Some("")`. If your env var is empty, map
   it to `None` yourself.
2. The file named by `GOOGLE_APPLICATION_CREDENTIALS`. Like google-auth,
   which tests `is None`, a variable that is set but empty counts as
   configured, and is an error.
3. gcloud's well-known file: `$CLOUDSDK_CONFIG/application_default_credentials.json`
   when `CLOUDSDK_CONFIG` is set, else
   `$HOME/.config/gcloud/application_default_credentials.json`. This is the
   Unix layout only; Windows' `%APPDATA%\gcloud` is not consulted.
4. The metadata server:
   `GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=a,b`
   with `Metadata-Flavor: Google` and a 3 s timeout.

| Source state | Result |
|---|---|
| **absent**: argument `None`, `GOOGLE_APPLICATION_CREDENTIALS` unset, well-known file missing (or `HOME`/`CLOUDSDK_CONFIG` unset or blank) | move on to the next source |
| **configured but broken**: an argument or `GOOGLE_APPLICATION_CREDENTIALS` that is set but empty, undecodable base64, invalid JSON, a missing or mistyped field, a file the env var names that is missing or unreadable, a well-known file that exists but cannot be read | `GcpAuthError::InvalidCredentials` from the constructor |
| **configured but unsupported**: any `type` other than the two below | `GcpAuthError::Unsupported` from the constructor; the type is quoted only if it is a plain `[a-z_]{1,64}` name, otherwise as `<unrecognized>` |

A misconfigured credential never quietly selects a different identity.

| `type` | Exchange |
|---|---|
| `service_account` (feature `service-account-key`) | RS256 assertion `{iss: client_email, scope: <space-joined scopes>, aud: token_uri, iat, exp: iat+3600}` (with `kid` = `private_key_id`), `POST token_uri` form `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=…`. PKCS#8 and PKCS#1 keys are both accepted. |
| `authorized_user` | `POST https://oauth2.googleapis.com/token`, always, with form `grant_type=refresh_token&client_id&client_secret&refresh_token` and no scope. Like google-auth, a `token_uri` in the file is **ignored**, so a file cannot send the refresh token and client secret elsewhere. Only `TokenOptions::default_token_uri`, a test seam, moves the endpoint. |
| anything else (`external_account`, `impersonated_service_account`, `external_account_authorized_user`, `gdch_service_account`, …) | `GcpAuthError::Unsupported` |

Explicit constructors exist too: `from_credentials_json` (any supported
type), `from_service_account_json`, `from_authorized_user_json` and
`metadata_server`. `with_options(TokenOptions)` replaces the metadata base
URL, the default token URI and the two timeouts. `with_quota_project`
replaces the quota project.

The two timeouts each bound one whole token request: connecting, sending
and reading the body. `metadata_timeout` (3 s, `DEFAULT_METADATA_TIMEOUT`)
covers the metadata server, and `token_timeout` (10 s,
`DEFAULT_TOKEN_TIMEOUT`) covers the token-endpoint exchange of a
`service_account` or `authorized_user` credential. What the refresh then
fails with depends on where the time ran out, and nothing is cached either
way:

- no response in time, or a success (2xx) whose body is not read in time:
  `GcpAuthError::Request { reason: "timed out", .. }`;
- an error status whose body stalls: that status,
  `GcpAuthError::Status { status, detail: "", .. }`. The body read is cut
  off at the timeout and the unread body contributes no error code.

### Quota project

`AccessToken { token, quota_project }`. The quota project is the file's
`quota_project_id`, and `GOOGLE_CLOUD_QUOTA_PROJECT` overrides it, as in
google-auth. `AccessToken::authorize` sends it as `x-goog-user-project`. A
user (`authorized_user`) credential needs one for most APIs, Vertex among
them.

The env var applies to metadata-server tokens too, matching google-auth's
`_apply_quota_project_id` for compute credentials. Without it, metadata
tokens carry no quota project. `TokenProvider::metadata_server` reads no
env var, so it has none until you call `with_quota_project`.

### The cache

- A token is served until 60 s (`REFRESH_MARGIN`) before it expires. The
  lifetime is counted from when the request was sent.
- A response with **no** `expires_in` field lives 300 s (`FALLBACK_LIFETIME`).
  An `expires_in` that is present but `null`, zero, negative or not an
  integer is `GcpAuthError::InvalidResponse` and is never cached. An integer
  string (`"3599"`) is accepted, as in google-auth. Lifetimes above a day are
  capped at a day.
- **Single-flight, per attempt.** At most one refresh is in flight. A call
  that finds one in flight waits on that attempt and gets exactly its
  outcome. That is a token, even one too short-lived to cache, or that
  attempt's error.
- A failure is never cached. A call that arrives after an attempt finished,
  with no usable cached token, starts a new attempt.
- The refresh runs on its own tokio task, and waiters share its outcome
  through a oneshot channel. Cancelling a caller never cancels the refresh,
  even the caller that started it. The other waiters still get its outcome,
  and a success is still cached.
- The slot guard is created before the task is spawned (after the cache lock
  is released), so it is dropped however the task ends: completed,
  panicked, or dropped by the runtime before its first poll. Dropping it
  clears the slot, but only while the slot still holds its own attempt, and
  then drops the unsent sender. Its waiters get
  `GcpAuthError::RefreshAborted`, and the next call starts a fresh attempt
  instead of inheriting a dead one.
- A token response is read up to 64 KiB (`MAX_TOKEN_RESPONSE`); anything
  larger is `InvalidResponse`. An error body is read only as far as its
  first 16 KiB.
- **`invalidate(&rejected) -> bool`** evicts the cached token when a Google
  API answered `401` to it, so the next `token()` refreshes. It is
  synchronous and needs no runtime: it takes the cache lock, and it never
  starts, cancels or duplicates a refresh.
  - **Matched by bearer string.** Any `AccessToken` carrying the cached
    bearer evicts it, whichever provider produced it. Anything else
    (a token already replaced or evicted, or never cached here) is a no-op
    that returns `false`.
  - **One refresh per wave, narrowly.** Callers whose rejections of one
    bearer overlap a single refresh cost one eviction and that one refresh,
    and all get its token, when it succeeds with a different bearer that
    lives longer than `REFRESH_MARGIN`. A later caller still holding the old
    bearer finds the new one cached: its `invalidate` is a no-op and its
    `token()` refreshes nothing. After a failed refresh the next call starts
    another; the evicted token is never served again.
  - **No re-install.** A refresh already in flight when its bearer was
    evicted, that returns that same bearer, hands it to its waiters (it is
    what the source has) but does not cache it, so the next `token()` asks
    the source again. A refresh that starts after the eviction caches
    whatever it gets.
  - **The same bearer can come back.** Google's metadata server caches a
    token until about five minutes before it expires, so a refresh there
    returns the bearer just rejected. A replay then adds requests without
    obtaining different credentials (a transient server-side rejection can
    still recover). Replay a bounded number of times, only on `401`, never
    on `403`.
  - It logs at `debug` with the source and kind, never the bearer.

  ```rust
  let token = tokens.token().await?;
  let mut response = token.authorize(http.post(url)).send().await?;
  if response.status() == reqwest::StatusCode::UNAUTHORIZED {
      tokens.invalidate(&token);
      let token = tokens.token().await?; // replay once
      response = token.authorize(http.post(url)).send().await?;
  }
  ```

  Neither `GcsClient` nor `VertexClient` replays a `401` itself: a `401`
  is returned as `Status`, and the caller decides whether to evict and
  replay as above.

### Errors never echo a secret

No `GcpAuthError` carries a private key, a refresh token, a client secret,
an access token, or a URL's query or userinfo:

- A credential that fails to parse is described by its origin (for example
  `GOOGLE_APPLICATION_CREDENTIALS file /path`) and the field or the failure
  category. serde_json's `Display`, which can quote a value, is not used.
- A token endpoint's body is never quoted. A failure keeps its status plus
  the RFC 6749 `error` code, and only when that code matches
  `[A-Za-z0-9_.-]{1,64}`. `error_description` is free text that a server
  may fill with anything, so it is dropped.
- Endpoints are rendered as `scheme://host[:port]/path`. A `reqwest::Error`
  becomes a fixed category: `timed out`, `connection failed`, `redirect
  refused`, `body error`, `decode error`, `invalid request`, `request error`
  or, for anything else, `request failed`. Its text is never formatted, because `without_url()` strips only
  the outer URL, and a refused redirect nests its target URL, query and all,
  in the source chain.
- `TokenProvider`'s, `AccessToken`'s and `TokenOptions`' `Debug` never print
  a token, a key, a secret or a URL's userinfo and query.

### Testing a consumer

`from_environment_with(http, scopes, explicit_b64, &dyn AdcEnvironment)`
reads env vars and files through a trait, so tests never mutate the process
environment. `ProcessEnvironment` is the real implementation. Point
`TokenOptions::metadata_base_url` / `default_token_uri` at wiremock.

## `storage`: GCS JSON API

```rust
use stridelabs_gcp::storage::{public_url, GcsClient};

let gcs = GcsClient::new(http.clone(), tokens.clone());
gcs.upload(bucket, "user/20261017-120000-ab12cd34.png", bytes, "image/png").await?;
let url = public_url(bucket, "user/20261017-120000-ab12cd34.png")?;
```

| Call | Request | Result |
|---|---|---|
| `upload(bucket, object, Bytes, content_type)` | `POST {base}/upload/storage/v1/b/{bucket}/o?uploadType=media&name={object}` | `()`; any non-2xx is an error |
| `upload_with(bucket, object, Bytes, content_type, &UploadOptions)` | default options: `upload`'s request, byte for byte; otherwise `POST {base}/upload/storage/v1/b/{bucket}/o?uploadType=multipart[&ifGenerationMatch=N]` (below) | `()`; any non-2xx is an error, a failed precondition's 412 included |
| `download(bucket, object)` | `GET {base}/storage/v1/b/{bucket}/o/{object}?alt=media` | `Some((bytes, content_type))`, or `None` on 404 |
| `delete(bucket, object)` | `DELETE {base}/storage/v1/b/{bucket}/o/{object}` | `true` if deleted, `false` on 404 |
| `bucket_reachable(bucket)` | `GET {base}/storage/v1/b/{bucket}/o?maxResults=1` | `()` on any 2xx; anything else, a 404 included, is `Status { operation: "list" }` |
| `public_url(bucket, object)` | (none) | `Ok("https://storage.googleapis.com/{bucket}/{object}")`, with the object's `/` kept |
| `public_url_with(bucket, object, ObjectNamePolicy)` | (none) | `public_url` under a name policy (below) |
| `validate_bucket_name(bucket)` | (none) | `Ok(())`, or the `InvalidBucketName` every operation would return |

Every default is v0.8.0's, on the wire and in results: `Strict` names and
one attempt per operation. Each widens on its own:
`with_object_name_policy(ObjectNamePolicy::Literal)` and
`with_retry(RetryPolicy::google_default())` (sections below).

- **Names are checked first**, before any token or request, and by
  `public_url` too:
  - A bucket must follow GCS's rules: 3 to 222 characters of `a-z 0-9 - _ .`,
    starting and ending with a letter or digit, with no `..`. Anything else
    is `StorageError::InvalidBucketName`. `validate_bucket_name` is that
    rule, public. The rules only GCS can judge (reserved words, IP shapes,
    63-character labels) are left to GCS, so a service wanting a stricter
    startup check (imgmcp has one) keeps its own.
  - An object, under the default `ObjectNamePolicy::Strict`, must be
    non-empty, must not start or end with `/`, and must have no empty, `.`
    or `..` segment (`u/../victim.png`, `./a`, `a//b`, `/a`). Anything else
    is `StorageError::InvalidObjectName`. Such names are legal to GCS, but
    their public URL becomes a different path as soon as a client
    normalizes it. `ObjectNamePolicy::Literal` sends them (below).
- **Encoding.** The bucket and object go in as one path segment or query
  value. Everything but RFC 3986 unreserved characters is percent-encoded,
  including `/`, so `a/b c.png` becomes `a%2Fb%20c.png`. A raw `/` would
  address a different resource.
- **Base URL.** The default is `https://storage.googleapis.com`.
  `GcsClient::emulator(http, base, Option<TokenProvider>)` targets
  fake-gcs-server and the like. It takes `STORAGE_EMULATOR_HOST`'s forms
  (`http://host:port`, or a bare `host:port`, which means `http://`) and makes
  auth optional: with no provider, no `Authorization` header is sent
  (parcel's rule). `with_base_url` changes the base and keeps the auth.
- **Timeout.** Each operation (token, request and body read) is bounded by
  60 s, which `with_timeout` changes. When it elapses the result is
  `StorageError::Timeout`. Under a retry policy the bound is per attempt.
- **Limits.** A download is read up to 32 MiB
  (`DEFAULT_MAX_DOWNLOAD_BYTES`; `with_max_download_bytes` changes it). Past
  the cap, reading stops and the result is `StorageError::TooLarge`. An
  error body is read only as far as its first 16 KiB.
- **Errors.** `StorageError::{InvalidBucketName, InvalidObjectName, Auth,
  Request, Timeout, TooLarge, Status, InvalidArgument}` names the
  operation (`upload`, `download`, `delete` or `list`).
  - **`Display` and `Debug` are safe for routine logs.** They carry the HTTP
    status and, from Google's JSON envelope, `error.status` when it matches
    `[A-Za-z0-9_.-]{1,64}` (for example `GCS upload answered HTTP 403
    (PERMISSION_DENIED)`). They never carry a URL, a transport error's
    text, or free text.
  - **`error.message` is held apart.** It is truncated to 200 characters on
    one line and wrapped in a `SensitiveMessage`, whose `Debug` prints only
    its length. Read it only through `StorageError::sensitive_message()`,
    because GCS messages name the object.
  - A body that is not the envelope, such as an HTML proxy page,
    contributes nothing beyond the status code.

### `upload_with`: object metadata at creation

```rust
use stridelabs_gcp::storage::UploadOptions;

let options = UploadOptions::default()
    .with_custom_time(custom_time)                // the lifecycle's clock
    .with_if_generation_match(0)                  // create only, never overwrite
    .with_cache_control("private, max-age=86400");
gcs.upload_with(bucket, &object, bytes, "image/png", &options).await?;
```

`UploadOptions` is `#[non_exhaustive]` (build it from `default()` and the
`with_*` setters):

| Option | Sent as | Rule |
|---|---|---|
| `custom_time: Option<SystemTime>` | metadata `customTime`, RFC 3339 UTC at whole seconds (`2025-10-09T08:53:20Z`), the fraction truncated | 1970-01-01 to 9999-12-31, else `StorageError::InvalidArgument` |
| `cache_control: Option<String>` | metadata `cacheControl`, which GCS serves as every read's `Cache-Control` (a public object without one is served `public, max-age=3600`, so an edge cache may keep it an hour) | a header value: non-empty visible ASCII, spaces and tabs only inside, never CR or LF |
| `if_generation_match: Option<i64>` | the `ifGenerationMatch` query parameter; `0` means only if no live object of that name exists | not negative |

- **Default options are the media upload**, the request `upload` sends.
  Any option set makes it a **multipart** upload, the JSON API's
  one-request way to create an object with metadata. The body is the JSON
  API's multipart layout, framed with CRLF:
  `--{b}`, a `Content-Type: application/json; charset=UTF-8` part holding
  `{"name","contentType"[,"customTime"][,"cacheControl"]}` (serde_json, in
  that order; the name is a JSON string here, never a query value), `--{b}`,
  a `Content-Type: {content_type}` part holding the bytes unchanged, and
  `--{b}--`. The request's `Content-Type` is `multipart/related;
  boundary={b}`.
- **The boundary** is `stridelabs-gcp-` plus 128 random bits in hex, drawn
  again until it appears in neither part (headers included), so no image
  can end a part early.
- **Checked before anything is sent** (no token, no request), as names
  are, for a multipart upload: the content type (written into a part header
  by hand, so it must be a header value), the cache control, the custom time
  and the generation. The refusal, `StorageError::InvalidArgument { reason }`,
  names the rule, never the value or the object. With **default options**
  `upload_with` is `upload` itself and takes exactly the content types
  `upload` takes (reqwest checks those).
- **A failed precondition is a 412**, `StorageError::Status` like any
  other non-2xx answer: never retried (under a retry policy too), and no
  fallback upload that would overwrite.
- Timeout, token, emulator base URL and sanitized errors are `upload`'s.
  The body is built in memory: one copy of the bytes.

### Object name policy

```rust
use stridelabs_gcp::storage::{public_url_with, ObjectNamePolicy};

let gcs = GcsClient::new(http.clone(), tokens.clone())
    .with_object_name_policy(ObjectNamePolicy::Literal); // default Strict
let url = public_url_with(bucket, &object, ObjectNamePolicy::Literal)?; // the name as GCS addresses it
```

`ObjectNamePolicy` (`#[non_exhaustive]`, `Default` = `Strict`) says which
object names a client sends and what `public_url_with` accepts:

| | `upload`, `upload_with` | `download`, `delete` | `public_url_with` |
|---|---|---|---|
| `Strict` (v0.8.0) | refuses an empty name, a leading or trailing `/`, an empty, `.` or `..` segment | the same | the same |
| `Literal` | sends every name | refuses only `""`, `.` and `..` | refuses no name |

- **`Literal` is GCS's literal addressing**: for a service whose existing
  objects carry names `Strict` refuses, which must stay addressable (served
  and deleted). It is a transport policy, not validation. On an upload the
  name is a query value (`name=`) or a JSON string, which nothing
  normalizes. On a download or a delete it is a URL path segment, and the
  whole names `""`, `.` and `..` cannot be one (`/o/.` goes out as `/o/`,
  and `/o/..` as the bucket itself), so they are refused before a token or
  a request. Refusing them on a download too stops `download("..")`
  returning the bucket's metadata as an object's bytes. Everything else is
  GCS's call: CR or LF, a `.well-known/acme-challenge/` prefix, a name past
  the length limit come back as GCS's `400`, `StorageError::Status`.
- **Encoding is the same under both policies:** RFC 3986's unreserved
  characters stay literal and everything else is percent-encoded (`/` too,
  in a segment or a query value; kept in a public URL's path). A literal
  `%2e%2e` goes out as `%252e%252e`, never as a dot segment. A table of 31
  names the tests own (`tests/storage.rs`) pins it: `public_url_with(..,
  Literal)` writes each as the table says, a delete goes to each name's own
  path for all but `""`, `.` and `..`, both uploads send all 31 names, and
  `Strict` refuses the same 14 of them as v0.8.0, with nothing sent.
- **A `Literal` public URL is exact addressing, not a safe URL.** A name
  with an empty, `.` or `..` segment is written as given, and a normalizing
  client (a browser, most HTTP stacks) resolves it to a different path,
  for a user-influenced name possibly in another user's prefix. Uploads and
  deletes stay exact: no write goes elsewhere. Validate user-influenced
  names yourself if they can be hostile.
- The free `public_url` is always `Strict`.

### Retry (opt-in)

```rust
use stridelabs_gcp::retry::RetryPolicy; // also `stridelabs_gcp::storage::RetryPolicy`

let gcs = GcsClient::new(http.clone(), tokens.clone())
    .with_retry(RetryPolicy::google_default()); // default RetryPolicy::disabled()
```

`RetryPolicy` (`#[non_exhaustive]`, `Copy`, `PartialEq`; in the `retry`
module, re-exported from `storage` and the crate root) is Cloud Storage's
documented retry strategy as a value: public fields `initial_delay`,
`multiplier`, `max_delay`, `deadline` and `max_attempts`, `const` `with_*`
setters (`with_max_attempts(n)` caps the attempts, the first included),
`google_default()` (1 s, ×2, 60 s, 120 s, no attempt cap: the client
libraries' documented defaults) and `disabled()` (`Default`: that schedule
with a zero deadline). Without a policy every operation is one attempt, as
in v0.8.0.

- **The schedule:** capped exponential backoff with full jitter. After a
  transient failure, wait a uniform draw under the current ceiling (at
  least 1 ms), the first ceiling `min(initial_delay, max_delay)` and each
  next one the last times the multiplier, capped at `max_delay`. The
  operation gives up when the attempt cap is reached or the wait would end
  past `deadline` from the first attempt's start, and returns that
  attempt's error unchanged. An attempt already running is never cut off.
  Each retry logs one `debug` line with the operation, the attempt,
  `wait_ms` and the status or transport category, never a name, a message
  or a URL.
- **Transient**, decided where the failure happens (never by reading an
  error's text back):
  - the statuses `408`, `429`, `500`, `502`, `503` and `504`;
  - a transport failure before the response that timed out, failed to
    connect or broke in flight (`timed out`, `connection failed`,
    `request error`);
  - any failure reading a body after the headers: an interrupted transfer.
    reqwest 0.13 reports one as a decode error, so the error still says
    `decode error`, as in v0.8.0: only its class is new;
  - an attempt cut off by the client's timeout (below);
  - the same classes on the way to the token (`StorageError::Auth`): the
    token endpoint's status, its transport, an interrupted token body.
- **Never retried:** a `404` (an answer: `None`, `false`, or the probe's
  `Status`); every other status, `401`, `403`, `412`, `501` and `505`
  included; a refused redirect, a request that cannot be built, an unknown
  transport failure (`request failed`); `TooLarge`; every `Invalid*`
  refusal; every other token error (`invalid_grant`, an unusable token
  body, a failed signature, a refresh that aborted).
- **An attempt cut off by the timeout** is `StorageError::Timeout` (v0.8.0's
  error there, because the body read is inside the bound). It is transient
  unless that attempt had itself received an error status that is not: a
  `412` or a `401` whose error body never arrives is not retried, while a
  `503`'s is. An attempt cut off while it waits on a token refresh is
  transient, whatever the token endpoint has said; the next attempt joins
  the same refresh, and the refresh's own outcome is final.
- **Each attempt is whole.** It takes a token and rebuilds the same
  request, a multipart body built once for the whole operation.
- **Invalid values are normalized, never refused.** A zero `deadline`, or
  a `max_attempts` of `Some(0)` or `Some(1)`, is exactly one attempt. A
  `multiplier` that is NaN or below 1 is 1; `+∞`, or a product past
  `max_delay`, is `max_delay`. `initial_delay > max_delay` starts at
  `max_delay`. Zero delays are allowed, and every wait is still at least
  1 ms (so a run of instant failures makes at most `deadline / 1 ms + 1`
  attempts). A `Duration::MAX` deadline with no attempt cap makes the
  deadline the only bound: the operation retries until it succeeds or
  meets a failure that is not transient.
- **Bounds, stated exactly.** `with_timeout` bounds each attempt, so the
  retry loop takes at most the deadline plus one attempt (≤ 120 + 60 =
  180 s at the defaults), under normal timer behaviour. That is not a bound
  on the whole method: a multipart body is built before the first attempt.
  Without an attempt cap, at zero latency the defaults make at least 7
  attempts (every draw at its ceiling), about 9 typically; real attempts
  take time and make fewer: two 60 s timeouts around one 1 s wait already
  end the loop at 2.
- **Library attempts are not wire requests.** The consumer's reqwest
  client may retry some protocol failures itself (reqwest 0.13's default
  retry policy) and apply its own `ClientBuilder::timeout` inside each
  attempt. Do not also configure a reqwest retry for the GCS host: the
  attempts would multiply. (reqwest's retry has no backoff, which is why
  this one lives here.)
- **Caveats when a response is lost** after GCS applied the request:
  - a retried create-only upload (`ifGenerationMatch=0`) answers `412`;
  - a retried delete may return `Ok(false)`;
  - a retried plain upload simply writes the object again.
- **A `401` is returned at once**, never retried: evict the token with
  `TokenProvider::invalidate` and replay yourself if you want to recover
  (the snippet above).
- **Token failures are retried by status alone.** `TokenProvider` never
  retries; a transient `StorageError::Auth` is retried at the operation
  level with the statuses above, whatever OAuth `error` its body carried.

### `bucket_reachable`: a startup probe

`gcs.bucket_reachable(bucket).await?` lists at most one object
(`GET {base}/storage/v1/b/{bucket}/o?maxResults=1`) through the same
timeout and retry as every operation. Any 2xx is `Ok(())`; anything
else, a `404` included, is `StorageError::Status { operation: "list", .. }`.
It is point-in-time evidence only: the bucket can disappear, or the grant
go, a moment after it succeeds. The identity needs `storage.objects.list`.
A `403` says nothing about whether the bucket exists: Google documents
that `forbidden` and `insufficientPermissions` can answer for a resource
that does not exist.

## `vertex` (feature `vertex`)

```rust
use stridelabs_gcp::vertex::{first_inline_image, GenerateContentRequest, GenerationConfig, ImageOutcome, Part, VertexClient};

let vertex = VertexClient::new(http, tokens, project, "global")?.with_timeout(Duration::from_secs(90));
let request = GenerateContentRequest::user(vec![Part::from_text(prompt), Part::from_bytes("image/png", source)])
    .with_generation_config(GenerationConfig::response_modalities(["IMAGE"]));
match first_inline_image(&vertex.generate_content(model, &request).await?) {
    ImageOutcome::Image { bytes, mime_type } => { /* … */ }
    ImageOutcome::Blocked { reason } => { /* … */ }
    ImageOutcome::Empty { reason } => { /* … */ }
}
```

- **Hosts.** `generate_content_url(project, location, model, api_version)`
  builds `https://aiplatform.googleapis.com/{ver}/projects/{p}/locations/global/publishers/google/models/{m}:generateContent`
  when `location == "global"`, and `https://{location}-aiplatform.googleapis.com/…`
  for any other location. This is google-genai's rule (`_api_client.py`,
  the Vertex branch). A naive `{location}-` builder produces the
  non-existent `global-aiplatform.googleapis.com`, and some models are served
  only from `global`. The API version defaults to `v1beta1`, as in
  google-genai. `with_base_url` swaps the scheme and host for a mock.
- **Every URL part is validated** before a URL is built and before a token is
  fetched. This matters most for the location, which is interpolated into
  the **host**: a location of `attacker.example/` would otherwise send the
  token and the prompt to `attacker.example`. Anything outside the pattern
  is `VertexError::InvalidArgument` and nothing is sent. `VertexClient::new`
  and `generate_content_url` are fallible, and so is `endpoint(model)`.

  | Part | Accepted |
  |---|---|
  | location | `global`, or `[a-z0-9]+(-[a-z0-9]+)*`, up to 52 characters (`{location}-aiplatform` must fit one 63-character DNS label) |
  | project | a project ID (`[a-z][a-z0-9-]{4,28}[a-z0-9]`), optionally domain-scoped (`example.com:my-project`), or a project number |
  | model | `[A-Za-z0-9][A-Za-z0-9._-]*`, up to 128 characters |
  | API version | `v1`, `v1beta1`, `v1alpha`, … (`v[0-9]+` plus an optional `beta`/`alpha` and digits), up to 16 characters |
- **Types.** The request carries `contents[{role, parts[text | inlineData{mimeType, data}]}]`
  and `generationConfig{responseModalities, …}`, with an `extra` map for
  `imageConfig` and the rest. `inlineData.data` is standard base64 on the
  wire and decoded bytes in Rust. Response types ignore unknown fields and
  accept every field as absent or `null`. The one strict field is
  `inlineData.data`: bytes that are not base64 are `VertexError::Decode`.
- **`first_inline_image`.** It returns the first non-thought part with
  non-empty `inlineData`, across candidates in order, as `Image`. Failing
  that, a `finishReason` containing one of `SAFETY`, `PROHIBITED`,
  `BLOCKLIST`, `RECITATION` or `SPII` (`BLOCK_MARKERS`) is `Blocked`. So is
  any `promptFeedback.blockReason` other than `BLOCKED_REASON_UNSPECIFIED`.
  Anything else is `Empty`, carrying the first candidate's `finishReason`.
- **Timeout.** There is none by default, because how long an image may take
  is the service's decision. `with_timeout` bounds the token, the request
  and the body read together.
- **A `401`** is one request and `VertexError::Status`, as on `GcsClient`.
- **Limits.** A response is read up to 64 MiB
  (`DEFAULT_MAX_RESPONSE_BYTES`; `with_max_response_bytes` changes it). That
  covers a 10 MiB image, which is about 13.4 MiB as base64, plus JSON. Past
  the cap the result is `VertexError::TooLarge`. An error body is read only
  as far as its first 16 KiB.
- **Errors.** `VertexError::{InvalidArgument, Auth, Request, Timeout,
  TooLarge, Status, Decode}`.
  - `Display` and `Debug` are safe for routine logs: the HTTP status, the
    validated `error.status`, fixed phrases.
  - Google's `error.message` can quote the **prompt**, so it is held apart
    as a `SensitiveMessage`, reachable only through
    `VertexError::sensitive_message()`.
  - `Decode` reports the parse failure's category and position, never
    serde's message, which could quote the body.
  - A blocked or image-less answer is not an error; `first_inline_image`
    classifies it.
- **Privacy of the types.** The request and response types derive `Debug`,
  and it **includes the prompt and response text**; inline images print as
  byte counts. That is fine in tests and not fine in routine logs.

## Not included

There is no retry or backoff by default (`GcsClient`'s retry above is
opt-in, and `VertexClient` has none), no `401` replay, no resumable
upload, no object listing beyond `bucket_reachable`'s probe, no object metadata
calls beyond what `upload_with` sets at creation (no read-back, no patch),
no service-account impersonation and no workload-identity federation (the
`external_account` family). There is no Windows
well-known-file lookup and no `GCE_METADATA_HOST` override.
