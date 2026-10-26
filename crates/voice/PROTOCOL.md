# The StrideLabs voice protocol, revision 1

The wire contract between a StrideLabs app's voice client (the Dart package
`stridelabs_voice`) and its server (the Rust crate `stridelabs-voice`, mounted
by the app). This file is canonical: the crate implements the server side, the
package the client side, and both test against the golden fixture in §11.

Revision 1 is additive over what lumen and tapper spoke before the crate
(§12). Every later change is additive too, or it is a new route (§10).

## 1. Conventions

- JSON is UTF-8. A receiver ignores object fields it does not know, and a
  client skips an event `type` it does not know.
- Header names are case-insensitive.
- "Characters" are Unicode scalar values of the trimmed text. A client that
  counts UTF-16 code units (Dart's `String.length`) never counts fewer.
- The app chooses the two routes' paths and their authentication. Both
  lumen and tapper serve `GET /voice/stream` and `POST /voice/tts` with an
  `Authorization: Bearer <access token>`; a service key is never accepted.

## 2. The relay: `GET /voice/stream` (a WebSocket)

### 2.1 The upgrade request

| part | rule |
|---|---|
| `rate` query parameter | optional; one of the server's sample rates (§3); absent means the server's first. Revision 1: every server takes BOTH `24000` and `16000`, the rates installed clients use (they open at 24000 and fall back to 16000 only when the microphone refuses 24000). Sent at most once. |
| `encoding` query parameter | RESERVED. Optional; `pcm_s16le` is its only revision-1 value, and absent means that. Sent at most once. A revision-1 client does not send it. |
| other parameters | ignored |

Every check happens BEFORE the `101`, so a refusal is an ordinary HTTP
answer:

| status | body (`detail`) | meaning, and what a client does |
|---|---|---|
| `401` | the app's | no token, or one that did not verify. Refresh the token ONCE and retry the upgrade once; a second `401` ends the attempt, and the app's auth rules decide whether the user is signed out. |
| `404` | the app's | voice is not served by this deployment: unavailable. |
| `422` | `rate must be 24000 or 16000` (the server's rates), or `encoding must be pcm_s16le` | a `rate` the server does not take: try the next candidate rate (§3.2); otherwise a client bug. |
| `426` | `expected a WebSocket upgrade` (+ `Upgrade: websocket`) | not an upgrade (a client bug). |
| `429` | `voice beta limit reached` + `scope` + `resets_at` (§7) | a budget is spent; `Retry-After` counts to `resets_at`. A client that can read the refusal SHOULD NOT retry before it. |
| `429` | `voice stream reopened too soon` | this user opened a session less than 2 s ago; `Retry-After: 2`. A client that can read the refusal retries once after it. |
| `503` | `voice beta not configured` (no `Retry-After`) | voice is off on this deployment. |
| `503` | `voice beta unavailable` + `Retry-After: 5` | Redis is briefly unavailable, or a newer upgrade for this user won a race; retry later. |
| `503` | the app's auth-outage body + `Retry-After: 5` | the token could not be CHECKED (the issuer's key set is briefly unavailable). This is NOT a `401`: never refresh on it (§5.3). |

A client that sees only the upgrade's STATUS cannot tell the two `429`s
apart. The reference client (`stridelabs_voice`, and every installed
client) is such a client: `dart:io` reports a refused upgrade's status alone.
Its rule, normative for status-only clients in revision 1: after a `429`,
retry the upgrade ONCE after 2.1 s; a second `429` ends the attempt as a
limit of UNKNOWN scope (the unscoped limit message). A budget `429` therefore
costs one extra refused upgrade, which charges nothing. `scope` and
`resets_at` on the upgrade's `429` serve clients that read bodies; the TTS
route's `429` and the relay's `error{limit}` carry them to every client.

Then `101`, and the session below.

### 2.2 Client frames

- **Binary: audio.** In the session's format (revision 1: 16-bit
  little-endian signed PCM, mono, at `rate`), so an EVEN number of bytes, at
  most 64 KiB per message and per frame. lumen and tapper send 80 ms frames.
- **Pacing:** cumulatively, never more than `(time since ready + lead) × rate × 2`
  bytes, where `lead` is the server's (§3.1: `lead_ms`); never more than
  10 s BEHIND real time either, and never 10 s without a frame (silence is
  audio: send it).
- None before `ready`, none after `end`.
- **Text: exactly `{"type":"end"}`**, once: no more audio is coming. The
  server then delivers what is left and closes `1000`. Any other text is
  ignored.

### 2.3 Server events (text frames)

| event | meaning |
|---|---|
| `{"type":"ready", …}` | the provider accepted the session: send audio. Carries the advertised facts (§3.1). |
| `{"type":"speech_start"}` | the speaker started |
| `{"type":"partial","text":…}` | OPTIONAL: the current turn's text so far, CUMULATIVE (each replaces the last). A provider may send none. |
| `{"type":"speech_end"}` | the speaker stopped (the turn may still be completing) |
| `{"type":"end_of_turn","text":…}` | the turn's final text |
| `{"type":"error","code":"provider"\|"limit"\|"internal"}` | sent just before some closes (§4.1); a `limit` also carries `scope` and `resets_at` (§7) |

- Order: a turn's `end_of_turn` comes before the next turn's `speech_start`.
  One utterance may still arrive as several turns split at pauses; joining
  them is the client's policy.
- A `limit` error with no `scope` (an older server), or a scope the client
  does not know, is a limit of unknown scope.

### 2.4 The rules the server enforces

Values marked **(server's)** are each deployment's configuration, within
the bound given; the others are fixed by this revision.

| rule | value | ends with |
|---|---|---|
| `ready` | the server gives the provider `open_timeout` to open and then writes `ready` within `close_timeout`: together **(server's: at most 10 s)** after the `101`. A provider that does not open in time starts the session's provider-error close at that point (the close itself takes up to a few more seconds). The reference client waits 12 s | `1011` (provider) |
| the session cap | 15 min **(server's)**, sooner when what was left of a budget window runs out first | `4000` (`4002` for a window) |
| idle | no frame for 10 s, or the audio 10 s behind real time **(server's: at least 10 s; the reference client fills a capture stall over 2 s with silence)** | `1008 idle` |
| pacing | more than `lead` ahead of real time (§3.1) | `1008 pacing` |
| frames | odd length; over 64 KiB; audio before `ready` or after `end` | `1008` (reason names it) |
| ping/pong | the server pings every 10 s; no pong for 25 s **(server's: non-zero, the pong deadline longer than the ping interval)**; WebSocket clients answer pings themselves | `1008 pong timeout` |
| one session per user | a newer session takes over | the older closes `4001` |
| admission | at most one upgrade per user per 2 s **(server's: at most 2 s; the reference client retries a `429` after 2.1 s)** | `429` before the upgrade |
| after `end` | the provider gets 2 s to finish **(server's: at most 2 s; the reference client waits 2 s for the close, then closes `1000` itself)** | `1000` |

## 3. The advertised facts

### 3.1 What `ready` carries

```json
{"type":"ready","rates":[24000,16000],"encoding":"pcm_s16le","lead_ms":5000}
```

| field | meaning | when absent (an older server) |
|---|---|---|
| `rates` | the sample rates the server accepts, its default first | `[24000, 16000]` |
| `encoding` | the audio encoding of this session | `pcm_s16le` |
| `lead_ms` | how far ahead of real time the server lets audio run (the pacing rule), in ms; at least 5000 in revision 1 (installed clients send a 3 s burst at `ready` and lead 4 s) | `5000` |

### 3.2 What a client does with them

- **Rates:** the client's candidate list is the last `ready`'s `rates`
  (kept for the client's lifetime), followed by `24000` and `16000` where
  not already in it; with no `ready` seen yet, `[24000, 16000]`. It opens
  at the first candidate its microphone can capture. A capture failure at a
  rate moves to the next candidate. A `422` at the upgrade forgets the kept
  list and tries the next candidate, at most twice per start (the reference
  client's addition; a revision-1 server takes both 24000 and 16000, so it
  never answers `422` to either). Installed clients have no `422` fallback:
  they move to 16000 only when the microphone refuses 24000, which is why
  revision 1 requires BOTH rates of every server. A rate refused by the
  microphone stays refused for the client's lifetime; the next `ready`
  replaces the kept list.
- **Lead:** the client's own lead is `lead_ms − 1000`, at least 500 ms
  (`4000` ms when absent). Audio buffered before `ready` (up to 3 s) is
  trimmed, oldest first, to that lead before it is sent (with revision 1's
  minimum `lead_ms` of 5000 this removes nothing).
- **Encoding:** anything but `pcm_s16le` is a session this client cannot
  speak: it closes `4104` (client failure).

## 4. Close codes

### 4.1 The server's

| code | reason | preceded by | meaning |
|---|---|---|---|
| `1000` | `done` | — | after `end`: the provider finished, or did not within 2 s |
| `1001` | `shutting down` | — | the server is going away; reconnect |
| `1008` | the rule (`pacing`, `idle`, `odd audio frame`, `message too big`, `audio before ready`, `audio after end`, `pong timeout`, `invalid utf-8`, `protocol error`) | — | the client broke a rule |
| `1011` | `provider error` | `error{provider}` | the speech-to-text provider failed |
| `1011` | `internal error` | `error{internal}` | the server could not charge the budget for too long |
| `4000` | `session limit` | — | the 15-minute cap; a new session may continue |
| `4001` | `superseded` | — | a newer session for this user took over |
| `4002` | `limit reached` | `error{limit,scope,resets_at}` | a budget window is spent (sent after the final charge, so its scope is the final one) |

A server close that is none of these is a drop.

### 4.2 The client's (advisory)

The server records the code of the client's close frame and never acts on
it. Revision 1's table:

| code | the client is leaving because |
|---|---|
| `1000` | the mic is off, after `end` |
| `4100` | the user left the conversation, or signed out |
| `4101` | the app was paused or backgrounded |
| `4102` | idle |
| `4103` | the transport was disposed or replaced (another rate included) |
| `4104` | a client-side failure: no `ready` in time, capture failed or stopped, a start failed, a recorder that would not stop, an encoding it cannot speak |

## 5. Text to speech: `POST /voice/tts`

### 5.1 The request

- `Content-Type: application/json` (`application/json` or any
  `application/*+json`, parameters ignored); else `415`.
- The body at most `max(4096, 6 × max_chars + 256)` bytes (4 KiB for
  `max_chars` 600; computed with checked arithmetic); else `413`. The
  basis: a client that sends raw UTF-8 (both reference clients do) spends
  at most 4 bytes per character and 6 per `\u`-escaped control character,
  plus at most 256 for the rest of the object. A client that escapes
  supplementary characters as surrogate pairs (12 bytes each) may not fit a
  maximum-length text: the byte cap is a limit of its own.
- A JSON object `{"text": <string>, "voice": <string or null>}`; any other
  shape, or `text` or `voice` given twice, is `422`. Unknown fields are
  ignored.
- `text` is trimmed, then must be 1 to `max_chars` characters (§1); the
  trimmed text is what is charged and spoken.
- `voice` is an id from the APP's voice catalog (§6); absent or `null` is the
  app's default voice.
- `Idempotency-Key`, optional: 1 to 64 characters of `A-Z a-z 0-9 _ -`, sent
  as one header; else `422`. Absent, the server mints one for the request.

### 5.2 The answer

- **`200`:** the audio, one body. `Content-Type` is its media type, one of
  the ALLOWED types (§8; revision 1: `audio/mpeg` only); `Cache-Control:
  no-store`.
- **Every response** of the route, refusals included (`200`, `401`,
  `405`, `413`, `415`, `422`, `429`, `502`, `503`), carries
  `X-Voice-Tts-Max-Chars: <max_chars>`, the server's text bound, at least
  600 (`TTS_MIN_TEXT_CHARS`).
- **Refusals**, each `{"detail":…}`:

| status | `detail` | `Retry-After` |
|---|---|---|
| `401` | the app's | — |
| `413` | `request body over <limit> bytes`, `<limit>` being §5.1's body bound; at its 4,096-byte floor (any `max_chars` up to 640, so 600 included), `request body over 4 KiB` | — |
| `415` | `expected an application/json body` | — |
| `422` | `expected a JSON object with a string text and an optional voice`; `unknown voice; expected one of <the catalog's ids>`; `text is empty`; `text is over <max_chars> characters`; `Idempotency-Key must be sent once, as 1 to 64 characters of A-Z, a-z, 0-9, _ and -`; `Idempotency-Key was already used for another sentence` | — |
| `429` | `voice beta limit reached` + `scope` + `resets_at` (§7) | to `resets_at` |
| `502` | `voice provider error` (retrying will not help) | — |
| `503` | `voice beta not configured` | — |
| `503` | `voice beta unavailable`; `voice provider unavailable` | `5` |
| `503` | the app's auth-outage body (not a `401`, §5.3) | `5` |

- **Charging:** a request is charged BEFORE the provider is called and never
  refunded. Under one `Idempotency-Key` (same voice, same trimmed text) it is
  charged ONCE for ten minutes: a repeat answers the first verdict (an
  admitted sentence is spoken again; a refusal keeps its first
  `resets_at`). The same key with another sentence is a `422`.

### 5.3 What a client does

- **Chunking:** the bound is the MOST RECENT TTS response's
  `X-Voice-Tts-Max-Chars` (a decimal integer of at least 600; any other
  value, or none, means 600). A sentence already split under a larger bound
  is split again before it is sent. A `422` resets the bound to 600.
- **One key per sentence:** a fresh `Idempotency-Key` for every sentence, and
  the SAME key on that sentence's retry.
- **Refresh ahead:** before a sentence's first attempt, a client whose access
  token is expired or expires within 30 s refreshes it first. The
  sentence's time budget starts BEFORE that refresh.
- **At most ONE retry per sentence**, under the same key, and only:
  - after a TRANSPORT failure with no response headers (the connection was
    refused or reset; never a timeout, never once any response arrived), or
  - after a `401`, once a token refresh SUCCEEDED (a `401` is decided before
    any charge, so the retry is the sentence's first charge);
  - and only while the reply is still the current one, the user still the
    one the sentence was sent for, and at least 5 s of the sentence's time
    budget is left: the same check before EVERY send, the first included
    (after a refresh ahead) and the retry.
  A sentence is therefore sent at most twice. A `401` with no send left
  still triggers a refresh (for the next sentence) without resending; a
  second `401`, or a refresh that fails, gives the sentence up.
- **A `503` is never a reason to refresh**, whatever its body: an
  auth-outage `503` means the token could not be checked, not that it is
  bad. Every `429` and `503` with a positive `Retry-After` is a cooldown.
- **Typed audio:** a `200` whose `Content-Type` (its media type, parameters
  dropped, lower-cased) is not in the client's allowed set is refused
  gracefully: that sentence is skipped, the reply goes on.

## 6. The app's voice catalog

- `voice` values are the APP's ids (what clients show, store and send),
  never a provider's names. The server maps each to a provider voice; a
  provider swap remaps them in the app's configuration, and no stored setting
  breaks.
- lumen and tapper use `Jason`, `Hazel`, `Casey`, `Nadia`, `Brian`,
  `Imogen`, `Liam`, `Evan` (default `Jason`).
- Ids are 1 to 64 characters of `A-Z a-z 0-9 _ -`.

## 7. Limits

- A spent budget is `429` (both routes) or `error{limit}` then `4002` (the
  relay), naming ONE `scope`: `user_day` (the user's UTC day), `user_month`
  (the user's UTC calendar month) or `global_month` (everyone's UTC calendar
  month: voice is off for all until it resets) — of several spent windows,
  the one that resets last — and `resets_at` (RFC 3339, UTC, whole seconds,
  `Z`).
- `429` body: `{"detail":"voice beta limit reached","scope":"user_day","resets_at":"2026-10-25T00:00:00Z"}`.
- A client reads `detail` as it always has; `scope` and `resets_at` may be
  absent (an older server).

## 8. Allowed audio types

| media type | file extension | since |
|---|---|---|
| `audio/mpeg` | `.mp3` | revision 1 |

Adding a type is a revision bump (§10) AND client support first: a server
never answers a type before the clients it serves accept it.

## 9. Encodings (reserved)

| `encoding` | audio | since |
|---|---|---|
| `pcm_s16le` | 16-bit little-endian signed PCM, mono | revision 1 |

## 10. Compatibility

- **Additive and presence-based; there is no version handshake.** A new
  field is optional and has a stated default when absent; a new event type
  is skipped by an older client; a new query parameter is optional with a
  default; a new response header is ignored by an older client.
- **Both directions are supported:** a revision-1 client against a server
  from before revision 1 (no advertised facts, no header, no scope: every
  default above applies), and a client from before revision 1 against a
  revision-1 server (it ignores the new fields, never sends `encoding`, and
  a server mints an `Idempotency-Key` for it).
- **Anything else is a new route** (`/voice/v2/...`), served alongside this
  one until no supported client uses it.
- A revision bump updates this file, the golden fixture (§11) and its
  SHA-256, together.

## 11. The golden fixture

`fixtures/relay_events.json` holds one of every event, in this order, one
compact JSON object per line (two-space indent, LF line ends, a final LF):

```json
[
  {"type":"ready","rates":[24000,16000],"encoding":"pcm_s16le","lead_ms":5000},
  {"type":"speech_start"},
  {"type":"partial","text":"what's the weather"},
  {"type":"speech_end"},
  {"type":"end_of_turn","text":"What's the weather in Chicago?"},
  {"type":"error","code":"provider"},
  {"type":"error","code":"limit","scope":"user_day","resets_at":"2026-10-25T00:00:00Z"},
  {"type":"error","code":"limit","scope":"user_month","resets_at":"2026-11-01T00:00:00Z"},
  {"type":"error","code":"limit","scope":"global_month","resets_at":"2026-11-01T00:00:00Z"},
  {"type":"error","code":"internal"},
  {"type":"ready"}
]
```

- SHA-256 `0437bc8114b0397e3b9734e03c9cb3d72f18ba928f22a160e19fb68f6226ed15`
  (620 bytes). The last `ready` is an older server's.
- The crate's test compares the file byte for byte with its rendering of
  `RelayEvent::golden()` and checks this hash; the package keeps a byte copy
  whose test checks the same hash and parses every event. Neither repository
  reads the other's files: the hash is the drift check.

## 12. What revision 1 added (for the record)

Over what lumen (v2026.10.23) and tapper (v2026.10.24) spoke before the
crate: `ready`'s `rates`/`encoding`/`lead_ms`; the reserved `encoding`
parameter; `X-Voice-Tts-Max-Chars`; typed audio with an allowed set; the
app voice catalog rule; and, for lumen, what tapper already had:
`Idempotency-Key`, `scope`/`resets_at` on both `429`s and on `error{limit}`.
`partial` is now explicitly optional.

Revision 1 also holds servers to what the installed clients can do: a
server takes both 24 and 16 kHz, leads at least 5000 ms, writes `ready`
within 10 s, keeps an idle timeout of at least 10 s, admits a reopen after
at most 2 s, and gives the provider at most 2 s after `end`. A provider
that must be fed slower than the installed clients' 3 s pre-`ready` burst
allows is unsupported. Lifting any of these is a later revision.
