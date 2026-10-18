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
| `public_url(bucket, object)` | (none) | `Ok("https://storage.googleapis.com/{bucket}/{object}")`, with the object's `/` kept |

- **Names are checked first**, before any token or request, and by
  `public_url` too:
  - A bucket must follow GCS's rules: 3 to 222 characters of `a-z 0-9 - _ .`,
    starting and ending with a letter or digit, with no `..`. Anything else
    is `StorageError::InvalidBucketName`.
  - An object must be non-empty, must not start or end with `/`, and must
    have no empty, `.` or `..` segment (`u/../victim.png`, `./a`, `a//b`,
    `/a`). Anything else is `StorageError::InvalidObjectName`. Such names are
    legal to GCS, but their public URL becomes a different path as soon as a
    client normalizes it.
- **Encoding.** The bucket and object go in as one path segment or query
  value. Everything but RFC 3986 unreserved characters is percent-encoded,
  including `/`, so `a/b c.png` becomes `a%2Fb%20c.png`. A raw `/` would
  address a different resource. This matches google-cloud-storage's
  `_quote`, tapper and parcel.
- **Base URL.** The default is `https://storage.googleapis.com`.
  `GcsClient::emulator(http, base, Option<TokenProvider>)` targets
  fake-gcs-server and the like. It takes `STORAGE_EMULATOR_HOST`'s forms
  (`http://host:port`, or a bare `host:port`, which means `http://`) and makes
  auth optional: with no provider, no `Authorization` header is sent
  (parcel's rule). `with_base_url` changes the base and keeps the auth.
- **Timeout.** Each operation (token, request and body read) is bounded by
  60 s, which `with_timeout` changes. When it elapses the result is
  `StorageError::Timeout`.
- **Limits.** A download is read up to 32 MiB
  (`DEFAULT_MAX_DOWNLOAD_BYTES`; `with_max_download_bytes` changes it). Past
  the cap, reading stops and the result is `StorageError::TooLarge`. An
  error body is read only as far as its first 16 KiB.
- **Errors.** `StorageError::{InvalidBucketName, InvalidObjectName, Auth,
  Request, Timeout, TooLarge, Status, InvalidArgument}` names the
  operation.
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
  one-request way to create an object with metadata. The body is the layout
  google-resumable-media (the Python client) sends, framed with CRLF:
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
  other non-2xx answer: no retry, and no fallback upload that would
  overwrite.
- Timeout, token, emulator base URL and sanitized errors are `upload`'s.
  The body is built in memory: one copy of the bytes.

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

There is no retry or backoff, no resumable upload, no object metadata
calls beyond what `upload_with` sets at creation (no read-back, no patch),
no service-account impersonation and no workload-identity federation (the
`external_account` family). There is no Windows
well-known-file lookup and no `GCE_METADATA_HOST` override.
