//! Scripted adapters (feature `test-support`): a speech-to-text and a
//! text-to-speech provider that do exactly what a test scripts, record what
//! they were given, and name no real provider. The core's relay, admission
//! and text-to-speech suites run against them, and so can an app's.
//!
//! - [`ScriptedStt`] opens [`ScriptedSession`]s that yield an [`SttScript`]'s
//!   events at audio-time thresholds, after the end of input, or never;
//!   that fail, drop, flood, block or hang to order; and that record every
//!   open, frame, end, close, keepalive tick and cancelled call in a shared
//!   [`SttLog`].
//! - [`ScriptedTts`] answers its queued replies (an MP3 by default) and
//!   records every request.
//! - [`RecordingUsage`] keeps every usage record.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use tokio::time::{Instant, Sleep};
use uuid::Uuid;

use crate::lease::audio_ms;
use crate::protocol::TTS_MIN_TEXT_CHARS;
use crate::stt::{
    AudioFormat, SttError, SttEvent, SttOpenError, SttProvider, SttSession, MIN_PACING_LEAD,
    PROTOCOL_DEFAULT_RATES,
};
use crate::tts::{Audio, SynthesisRequest, TtsFailure, TtsProvider};
use crate::usage::{UsageSink, VoiceMetric};

/// A short, valid MP3: an empty ID3v2.4 tag, then two silent MPEG-1 Layer
/// III frames (32 kbit/s, 48 kHz, mono; 96 bytes each). It opens the way an
/// MP3 does (`ID3`), so a client's or a provider client's MP3 shape check
/// passes it; [`ScriptedTts`] answers it by default.
pub const MP3_FIXTURE: &[u8] = &MP3;

/// The tag: `ID3`, version 4.0, no flags, a size of 0 (syncsafe).
const ID3_TAG: [u8; 10] = *b"ID3\x04\x00\x00\x00\x00\x00\x00";
/// A frame header: the sync, MPEG-1 Layer III without CRC; 32 kbit/s at
/// 48 kHz, no padding; mono. The rest of the frame is zero (silence: an
/// all-zero side information block holds no main data).
const FRAME_HEADER: [u8; 4] = [0xFF, 0xFB, 0x14, 0xC0];
/// 144 × 32,000 / 48,000 bytes, the header included.
const FRAME_BYTES: usize = 96;
const MP3_BYTES: usize = ID3_TAG.len() + 2 * FRAME_BYTES;
const MP3: [u8; MP3_BYTES] = mp3();

const fn mp3() -> [u8; MP3_BYTES] {
    let mut bytes = [0; MP3_BYTES];
    let mut at = 0;
    while at < ID3_TAG.len() {
        bytes[at] = ID3_TAG[at];
        at += 1;
    }
    let mut frame = 0;
    while frame < 2 {
        let start = ID3_TAG.len() + frame * FRAME_BYTES;
        let mut at = 0;
        while at < FRAME_HEADER.len() {
            bytes[start + at] = FRAME_HEADER[at];
            at += 1;
        }
        frame += 1;
    }
    bytes
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A scripted speech-to-text provider. Defaults: configured; the formats
/// 24,000 and 16,000 Hz PCM s16le (24,000 the default); a 5 s pacing lead;
/// every `open` succeeds at once. Each open plays a fresh copy of the
/// script. `Clone` shares the log: a test keeps a clone and reads it after
/// `Voice::new` took the provider.
#[derive(Debug, Clone)]
pub struct ScriptedStt {
    configured: bool,
    formats: Vec<AudioFormat>,
    lead: Duration,
    open: OpenScript,
    script: SttScript,
    log: Arc<SttLog>,
}

impl ScriptedStt {
    /// A configured provider whose sessions play `script`.
    #[must_use]
    pub fn new(script: SttScript) -> ScriptedStt {
        ScriptedStt {
            configured: true,
            formats: PROTOCOL_DEFAULT_RATES
                .into_iter()
                .map(AudioFormat::pcm_s16le)
                .collect(),
            lead: MIN_PACING_LEAD,
            open: OpenScript::Immediate,
            script,
            log: Arc::default(),
        }
    }

    /// A provider whose `configured()` is `false` (the configuration `503`).
    #[must_use]
    pub fn unconfigured() -> ScriptedStt {
        ScriptedStt {
            configured: false,
            ..ScriptedStt::new(SttScript::default())
        }
    }

    /// Offer `formats` (in order, the default first) instead.
    #[must_use]
    pub fn with_formats(self, formats: Vec<AudioFormat>) -> ScriptedStt {
        ScriptedStt { formats, ..self }
    }

    /// Advertise and be held to `lead` instead.
    #[must_use]
    pub fn with_pacing_lead(self, lead: Duration) -> ScriptedStt {
        ScriptedStt { lead, ..self }
    }

    /// Open by `open` instead.
    #[must_use]
    pub fn with_open(self, open: OpenScript) -> ScriptedStt {
        ScriptedStt { open, ..self }
    }

    /// What every session this provider opened saw (shared, live).
    #[must_use]
    pub fn log(&self) -> Arc<SttLog> {
        Arc::clone(&self.log)
    }
}

impl SttProvider for ScriptedStt {
    type Session = ScriptedSession;

    fn configured(&self) -> bool {
        self.configured
    }

    fn formats(&self) -> &[AudioFormat] {
        &self.formats
    }

    fn pacing_lead(&self) -> Duration {
        self.lead
    }

    /// Counts the open as started at once (`SttLog::opens_started`), then
    /// follows the [`OpenScript`]. Like every adapter, it applies no deadline
    /// of its own: the caller's bound is the only one.
    fn open(
        &self,
        format: AudioFormat,
        _deadline: Instant,
    ) -> impl Future<Output = Result<ScriptedSession, SttOpenError>> + Send {
        self.log.update(|record| record.opens_started += 1);
        let unfinished = Unfinished::new(&self.log, Call::Open);
        let log = Arc::clone(&self.log);
        let open = self.open.clone();
        let script = self.script.clone();
        async move {
            match open {
                OpenScript::Immediate => {}
                OpenScript::After(delay) => tokio::time::sleep(delay).await,
                OpenScript::Fail(error) => {
                    unfinished.complete();
                    return Err(error);
                }
                OpenScript::Hang => std::future::pending::<()>().await,
            }
            unfinished.complete();
            log.update(|record| record.opened.push(format));
            Ok(ScriptedSession::new(script, format, log))
        }
    }
}

/// How a [`ScriptedStt`] opens.
#[derive(Debug, Clone)]
pub enum OpenScript {
    /// At once.
    Immediate,
    /// After this long (a slow dial).
    After(Duration),
    /// With this error, at once.
    Fail(SttOpenError),
    /// Never: the open future pends until it is dropped.
    Hang,
}

/// One scripted session: an [`SttSession`] playing its [`SttScript`].
///
/// - **`poll_next`** first runs the keepalive timer (if scripted), then
///   yields the NEXT step if its condition holds, else returns `Pending`
///   having registered the waker it needs: an accepted frame or a returned
///   `end_input` wakes it, and a delay is a tokio timer. Steps keep their
///   order: none overtakes an earlier one. An exhausted script pends forever
///   (never `None`).
/// - **`send_audio`** counts the call, then honours the script's write
///   behaviour (block or fail from the scripted frame on), and only then
///   accepts the frame: it counts towards the audio thresholds,
///   `SttLog::frames` and `SttLog::frame_bytes`.
/// - **`end_input`** returns (or hangs), and once it has RETURNED the
///   after-end steps are ready.
/// - **`close(end_sent)`** records `Some(end_sent)` when called, then
///   returns (or hangs).
/// - **Every call's future** (`open`'s too) counts into `SttLog::cancelled`
///   when it is dropped before it completed.
#[derive(Debug)]
pub struct ScriptedSession {
    script: SttScript,
    cursor: usize,
    format: AudioFormat,
    /// The audio this session accepted.
    audio_bytes: u64,
    /// `send_audio` calls made, accepted or not: the write behaviour's frame
    /// number.
    writes: usize,
    end_returned_at: Option<Instant>,
    state: State,
    /// The current after-end step's delay.
    delay: Option<Pin<Box<Sleep>>>,
    keepalive: Option<Pin<Box<Sleep>>>,
    waker: Option<Waker>,
    log: Arc<SttLog>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Streaming,
    /// A `fail_at` step yielded its error: the stream pends from here on.
    Failed,
    /// A `drop_at` step ended the stream: `None` from here on.
    Ended,
}

impl ScriptedSession {
    fn new(script: SttScript, format: AudioFormat, log: Arc<SttLog>) -> ScriptedSession {
        ScriptedSession {
            script,
            cursor: 0,
            format,
            audio_bytes: 0,
            writes: 0,
            end_returned_at: None,
            state: State::Streaming,
            delay: None,
            keepalive: None,
            waker: None,
            log,
        }
    }

    fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    /// One keepalive tick when its timer is due, counted, the timer re-armed.
    fn run_keepalive(&mut self, context: &mut Context<'_>) {
        let Some(every) = self.script.keepalive else {
            return;
        };
        let timer = self
            .keepalive
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(every)));
        if timer.as_mut().poll(context).is_ready() {
            self.log.update(|record| record.keepalives += 1);
            timer.as_mut().reset(Instant::now() + every);
            if timer.as_mut().poll(context).is_ready() {
                context.waker().wake_by_ref();
            }
        }
    }

    /// The next step's item when its condition holds (`Some(None)`: the
    /// stream ends), else `None`.
    fn next_step(
        &mut self,
        context: &mut Context<'_>,
    ) -> Option<Option<Result<SttEvent, SttError>>> {
        let step = self.script.steps.get(self.cursor)?.clone();
        let ready = match &step {
            Step::Flood(_) => true,
            Step::At(threshold, _) | Step::FailAt(threshold, _) | Step::DropAt(threshold) => {
                audio_ms(self.audio_bytes, self.format.bytes_per_second()) >= *threshold
            }
            Step::AfterEnd(_) | Step::FinishAfterEnd => self.end_returned_at.is_some(),
            Step::AfterEndDelayed(delay, _) => match self.end_returned_at {
                None => false,
                Some(returned) => self
                    .delay
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(returned + *delay)))
                    .as_mut()
                    .poll(context)
                    .is_ready(),
            },
        };
        if !ready {
            return None;
        }
        let item = match step {
            // The cursor stays: the same event on every poll from here on.
            Step::Flood(event) => return Some(Some(Ok(event))),
            Step::At(_, event) | Step::AfterEnd(event) | Step::AfterEndDelayed(_, event) => {
                Some(Ok(event))
            }
            Step::FinishAfterEnd => Some(Ok(SttEvent::Finished)),
            Step::FailAt(_, error) => {
                self.state = State::Failed;
                Some(Err(error))
            }
            Step::DropAt(_) => {
                self.state = State::Ended;
                None
            }
        };
        self.cursor += 1;
        self.delay = None;
        Some(item)
    }
}

impl futures_core::Stream for ScriptedSession {
    type Item = Result<SttEvent, SttError>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let session = self.get_mut();
        session.run_keepalive(context);
        let next = match session.state {
            State::Ended => return Poll::Ready(None),
            State::Failed => None,
            State::Streaming => session.next_step(context),
        };
        match next {
            Some(item) => Poll::Ready(item),
            None => {
                session.waker = Some(context.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl SttSession for ScriptedSession {
    fn send_audio(&mut self, frame: Bytes) -> impl Future<Output = Result<(), SttError>> + Send {
        self.writes += 1;
        let number = self.writes;
        let unfinished = Unfinished::new(&self.log, Call::SendAudio);
        async move {
            match &self.script.writes {
                Writes::BlockAfter(frames) if number > *frames => {
                    std::future::pending::<()>().await;
                }
                Writes::FailAfter(frames, error) if number > *frames => {
                    let error = error.clone();
                    unfinished.complete();
                    return Err(error);
                }
                _ => {}
            }
            let length = frame.len();
            let bytes = u64::try_from(length).unwrap_or(u64::MAX);
            self.audio_bytes = self.audio_bytes.saturating_add(bytes);
            self.log.update(|record| {
                record.frames.push(length);
                record.frame_bytes.push(frame);
                record.audio_bytes = record.audio_bytes.saturating_add(bytes);
            });
            self.wake();
            unfinished.complete();
            Ok(())
        }
    }

    fn end_input(&mut self) -> impl Future<Output = Result<(), SttError>> + Send {
        let unfinished = Unfinished::new(&self.log, Call::EndInput);
        async move {
            if self.script.end_hangs {
                std::future::pending::<()>().await;
            }
            self.end_returned_at = Some(Instant::now());
            self.log.update(|record| record.end_inputs += 1);
            self.wake();
            unfinished.complete();
            Ok(())
        }
    }

    fn close(self, end_sent: bool) -> impl Future<Output = ()> + Send {
        self.log.update(|record| record.closed = Some(end_sent));
        let unfinished = Unfinished::new(&self.log, Call::Close);
        async move {
            // Held until the close completes, as an adapter holds its socket.
            let session = self;
            if session.script.close_hangs {
                std::future::pending::<()>().await;
            }
            unfinished.complete();
        }
    }
}

/// What a scripted session does: ordered steps (each waits for its
/// condition, and none overtakes an earlier one), plus behaviours that are
/// not steps. The default is an empty script: a session that yields nothing
/// and accepts every frame.
#[derive(Debug, Clone, Default)]
pub struct SttScript {
    steps: Vec<Step>,
    writes: Writes,
    end_hangs: bool,
    close_hangs: bool,
    keepalive: Option<Duration>,
}

#[derive(Debug, Clone)]
enum Step {
    At(u64, SttEvent),
    AfterEnd(SttEvent),
    AfterEndDelayed(Duration, SttEvent),
    FinishAfterEnd,
    FailAt(u64, SttError),
    DropAt(u64),
    Flood(SttEvent),
}

#[derive(Debug, Clone, Default)]
enum Writes {
    #[default]
    Accept,
    BlockAfter(usize),
    FailAfter(usize, SttError),
}

impl SttScript {
    fn step(mut self, step: Step) -> SttScript {
        self.steps.push(step);
        self
    }

    /// `event`, once the session has accepted at least `audio_ms` of audio
    /// (at its format's rate; `0` is at once).
    #[must_use]
    pub fn at(self, audio_ms: u64, event: SttEvent) -> SttScript {
        self.step(Step::At(audio_ms, event))
    }

    /// `event`, once `end_input` has RETURNED.
    #[must_use]
    pub fn after_end(self, event: SttEvent) -> SttScript {
        self.step(Step::AfterEnd(event))
    }

    /// `event`, `delay` after `end_input` returned: a final the provider
    /// flushes late.
    #[must_use]
    pub fn after_end_delayed(self, delay: Duration, event: SttEvent) -> SttScript {
        self.step(Step::AfterEndDelayed(delay, event))
    }

    /// `Finished` (the provider's normal end), once `end_input` returned.
    #[must_use]
    pub fn finish_after_end(self) -> SttScript {
        self.step(Step::FinishAfterEnd)
    }

    /// `Err(error)` once `audio_ms` of audio was accepted; afterwards the
    /// stream pends.
    #[must_use]
    pub fn fail_at(self, audio_ms: u64, error: SttError) -> SttScript {
        self.step(Step::FailAt(audio_ms, error))
    }

    /// The stream's end (`None`, a drop) once `audio_ms` of audio was
    /// accepted.
    #[must_use]
    pub fn drop_at(self, audio_ms: u64) -> SttScript {
        self.step(Step::DropAt(audio_ms))
    }

    /// From here on, `event` on EVERY poll, never `Pending`: a provider that
    /// breaks the no-starvation rule.
    #[must_use]
    pub fn flood(self, event: SttEvent) -> SttScript {
        self.step(Step::Flood(event))
    }

    /// A keepalive timer of `every` (at least 1 ms), polled inside
    /// `poll_next`; each tick is counted (`SttLog::keepalives`).
    #[must_use]
    pub fn keepalive_every(self, every: Duration) -> SttScript {
        SttScript {
            keepalive: Some(every.max(Duration::from_millis(1))),
            ..self
        }
    }

    /// `send_audio` of frame `frames + 1` and every later one pends forever
    /// (a provider that stopped reading).
    #[must_use]
    pub fn block_writes_after(self, frames: usize) -> SttScript {
        SttScript {
            writes: Writes::BlockAfter(frames),
            ..self
        }
    }

    /// `send_audio` of frame `frames + 1` and every later one fails with
    /// `error`.
    #[must_use]
    pub fn fail_writes_after(self, frames: usize, error: SttError) -> SttScript {
        SttScript {
            writes: Writes::FailAfter(frames, error),
            ..self
        }
    }

    /// `end_input` pends forever.
    #[must_use]
    pub fn hang_end_input(self) -> SttScript {
        SttScript {
            end_hangs: true,
            ..self
        }
    }

    /// `close` pends forever (the caller bounds it).
    #[must_use]
    pub fn hang_close(self) -> SttScript {
        SttScript {
            close_hangs: true,
            ..self
        }
    }
}

/// What a [`ScriptedStt`]'s sessions saw, all of them together; every method
/// is a snapshot.
#[derive(Debug, Default)]
pub struct SttLog {
    record: Mutex<Record>,
}

#[derive(Debug, Default)]
struct Record {
    opened: Vec<AudioFormat>,
    opens_started: usize,
    frames: Vec<usize>,
    frame_bytes: Vec<Bytes>,
    audio_bytes: u64,
    end_inputs: usize,
    closed: Option<bool>,
    keepalives: usize,
    cancelled: Cancelled,
}

impl SttLog {
    fn update(&self, change: impl FnOnce(&mut Record)) {
        change(&mut lock(&self.record));
    }

    /// The format of every open that SUCCEEDED, in order.
    #[must_use]
    pub fn opened(&self) -> Vec<AudioFormat> {
        lock(&self.record).opened.clone()
    }

    /// How many open futures were created (polled or not, completed or
    /// not): what proves the relay does not re-dial.
    #[must_use]
    pub fn opens_started(&self) -> usize {
        lock(&self.record).opens_started
    }

    /// Each accepted frame's length, in order.
    #[must_use]
    pub fn frames(&self) -> Vec<usize> {
        lock(&self.record).frames.clone()
    }

    /// Each accepted frame's bytes, in order: what reached the provider,
    /// byte for byte.
    #[must_use]
    pub fn frame_bytes(&self) -> Vec<Bytes> {
        lock(&self.record).frame_bytes.clone()
    }

    /// The accepted frames' bytes, together.
    #[must_use]
    pub fn audio_bytes(&self) -> u64 {
        lock(&self.record).audio_bytes
    }

    /// The `end_input` calls that RETURNED.
    #[must_use]
    pub fn end_inputs(&self) -> usize {
        lock(&self.record).end_inputs
    }

    /// `Some(end_sent)` once `close` was called (the latest session's).
    #[must_use]
    pub fn closed(&self) -> Option<bool> {
        lock(&self.record).closed
    }

    /// The keepalive ticks.
    #[must_use]
    pub fn keepalives(&self) -> usize {
        lock(&self.record).keepalives
    }

    /// The call futures dropped before they completed.
    #[must_use]
    pub fn cancelled(&self) -> Cancelled {
        lock(&self.record).cancelled
    }
}

/// The call futures dropped before they completed, per call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Cancelled {
    /// `SttProvider::open`.
    pub open: usize,
    /// `SttSession::send_audio`.
    pub send_audio: usize,
    /// `SttSession::end_input`.
    pub end_input: usize,
    /// `SttSession::close`.
    pub close: usize,
}

#[derive(Debug, Clone, Copy)]
enum Call {
    Open,
    SendAudio,
    EndInput,
    Close,
}

/// Held by a call's future: counts the call into [`SttLog::cancelled`] when
/// dropped before [`Unfinished::complete`].
struct Unfinished {
    log: Arc<SttLog>,
    call: Call,
    done: bool,
}

impl Unfinished {
    fn new(log: &Arc<SttLog>, call: Call) -> Unfinished {
        Unfinished {
            log: Arc::clone(log),
            call,
            done: false,
        }
    }

    fn complete(mut self) {
        self.done = true;
    }
}

impl Drop for Unfinished {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let call = self.call;
        self.log.update(|record| {
            let cancelled = &mut record.cancelled;
            match call {
                Call::Open => cancelled.open += 1,
                Call::SendAudio => cancelled.send_audio += 1,
                Call::EndInput => cancelled.end_input += 1,
                Call::Close => cancelled.close += 1,
            }
        });
    }
}

/// A scripted text-to-speech provider. Defaults: configured; declares and
/// answers `audio/mpeg`; a 600-character bound; `knows_voice` is `None`;
/// every request is answered [`MP3_FIXTURE`]. `Clone` shares the queued
/// replies and the recorded calls.
#[derive(Debug, Clone)]
pub struct ScriptedTts {
    configured: bool,
    declared: &'static str,
    answered: &'static str,
    max_text_chars: usize,
    known_voices: Option<Vec<String>>,
    script: Arc<Mutex<TtsScript>>,
    delay: Option<Duration>,
}

/// What a [`ScriptedTts`]'s clones share, behind ONE lock: a call is
/// recorded and its reply taken in one step, so the `n`th recorded call is
/// the one that got the `n`th queued reply, however many run at once.
#[derive(Debug, Default)]
struct TtsScript {
    replies: VecDeque<Result<Bytes, TtsFailure>>,
    calls: Vec<(String, String)>,
}

impl Default for ScriptedTts {
    fn default() -> ScriptedTts {
        ScriptedTts::new()
    }
}

impl ScriptedTts {
    /// A configured provider with the defaults above.
    #[must_use]
    pub fn new() -> ScriptedTts {
        ScriptedTts {
            configured: true,
            declared: "audio/mpeg",
            answered: "audio/mpeg",
            max_text_chars: TTS_MIN_TEXT_CHARS,
            known_voices: None,
            script: Arc::default(),
            delay: None,
        }
    }

    /// A provider whose `configured()` is `false` (the configuration `503`).
    #[must_use]
    pub fn unconfigured() -> ScriptedTts {
        ScriptedTts {
            configured: false,
            ..ScriptedTts::new()
        }
    }

    /// Declare AND answer `media_type`.
    #[must_use]
    pub fn with_media_type(self, media_type: &'static str) -> ScriptedTts {
        ScriptedTts {
            declared: media_type,
            answered: media_type,
            ..self
        }
    }

    /// Answer `media_type` while still declaring the other: the mismatch
    /// case.
    #[must_use]
    pub fn answering_media_type(self, media_type: &'static str) -> ScriptedTts {
        ScriptedTts {
            answered: media_type,
            ..self
        }
    }

    /// State a text bound of `max` characters.
    #[must_use]
    pub fn with_max_text_chars(self, max: usize) -> ScriptedTts {
        ScriptedTts {
            max_text_chars: max,
            ..self
        }
    }

    /// Know exactly `voices`: `knows_voice` is `Some(true)` for them and
    /// `Some(false)` for any other.
    #[must_use]
    pub fn with_known_voices(self, voices: &[&str]) -> ScriptedTts {
        ScriptedTts {
            known_voices: Some(voices.iter().map(|voice| (*voice).to_string()).collect()),
            ..self
        }
    }

    /// Queue `reply` for a later request (first in, first out); with the
    /// queue empty, a request is answered [`MP3_FIXTURE`].
    #[must_use]
    pub fn then(self, reply: Result<Bytes, TtsFailure>) -> ScriptedTts {
        lock(&self.script).replies.push_back(reply);
        self
    }

    /// Sleep `delay` before answering each request.
    #[must_use]
    pub fn with_delay(self, delay: Duration) -> ScriptedTts {
        ScriptedTts {
            delay: Some(delay),
            ..self
        }
    }

    /// Every request, `(text, provider voice)`, in the order `synthesize`
    /// was called: the `n`th got the `n`th queued reply.
    #[must_use]
    pub fn calls(&self) -> Vec<(String, String)> {
        lock(&self.script).calls.clone()
    }
}

impl TtsProvider for ScriptedTts {
    fn configured(&self) -> bool {
        self.configured
    }

    fn media_type(&self) -> &'static str {
        self.declared
    }

    fn max_text_chars(&self) -> usize {
        self.max_text_chars
    }

    fn knows_voice(&self, provider_voice: &str) -> Option<bool> {
        self.known_voices
            .as_ref()
            .map(|known| known.iter().any(|voice| voice == provider_voice))
    }

    /// Records the request and takes the next queued reply when called, in
    /// one step; then sleeps the delay (if any) and answers.
    fn synthesize(
        &self,
        request: &SynthesisRequest<'_>,
    ) -> impl Future<Output = Result<Audio, TtsFailure>> + Send {
        let reply = {
            let mut script = lock(&self.script);
            script
                .calls
                .push((request.text.to_string(), request.provider_voice.to_string()));
            script.replies.pop_front()
        };
        let (delay, answered) = (self.delay, self.answered);
        async move {
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            reply
                .unwrap_or_else(|| Ok(Bytes::from_static(MP3_FIXTURE)))
                .map(|bytes| Audio {
                    bytes,
                    media_type: answered,
                })
        }
    }
}

/// A usage sink that keeps every record, synchronously. `Clone` shares
/// them.
#[derive(Debug, Clone, Default)]
pub struct RecordingUsage {
    records: Arc<Mutex<Vec<Recorded>>>,
}

/// One `UsageSink::record` call's arguments.
type Recorded = (Uuid, VoiceMetric, u64, DateTime<Utc>);

impl RecordingUsage {
    /// Every record so far, in order.
    #[must_use]
    pub fn records(&self) -> Vec<(Uuid, VoiceMetric, u64, DateTime<Utc>)> {
        lock(&self.records).clone()
    }
}

impl UsageSink for RecordingUsage {
    fn record(&self, user: Uuid, metric: VoiceMetric, quantity: u64, at: DateTime<Utc>) {
        lock(&self.records).push((user, metric, quantity, at));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    use futures::{FutureExt as _, Stream as _};

    use super::*;

    /// 24 kHz PCM s16le: 48 bytes a millisecond.
    const BYTES_PER_MS: usize = 48;

    /// `ms` of audio whose bytes depend on `ms` (so frames of different
    /// lengths never share a prefix by accident).
    fn audio(ms: usize) -> Bytes {
        (0..ms * BYTES_PER_MS)
            .map(|index| u8::try_from((index + ms) % 251).expect("< 251"))
            .collect()
    }

    /// A waker that counts its wakes.
    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Wakes {
        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    type Item = Option<Result<SttEvent, SttError>>;

    fn poll(session: &mut ScriptedSession, waker: &Waker) -> Poll<Item> {
        Pin::new(session).poll_next(&mut Context::from_waker(waker))
    }

    async fn open(stt: &ScriptedStt) -> ScriptedSession {
        stt.open(AudioFormat::pcm_s16le(24_000), Instant::now())
            .await
            .expect("an immediate open")
    }

    fn event(item: Poll<Item>) -> SttEvent {
        match item {
            Poll::Ready(Some(Ok(event))) => event,
            other => panic!("expected an event, got {other:?}"),
        }
    }

    /// The defaults: configured, 24 and 16 kHz PCM s16le (24 the default),
    /// a 5 s lead; `unconfigured` differs only in `configured()`.
    #[test]
    fn the_scripted_stt_defaults_are_the_protocols() {
        let stt = ScriptedStt::new(SttScript::default());
        assert!(stt.configured());
        assert_eq!(
            stt.formats(),
            [
                AudioFormat::pcm_s16le(24_000),
                AudioFormat::pcm_s16le(16_000)
            ]
        );
        assert_eq!(stt.pacing_lead(), Duration::from_secs(5));
        let off = ScriptedStt::unconfigured();
        assert!(!off.configured());
        assert_eq!(off.formats(), stt.formats());
        let custom = stt
            .with_formats(vec![AudioFormat::pcm_s16le(16_000)])
            .with_pacing_lead(Duration::from_secs(7));
        assert_eq!(custom.formats(), [AudioFormat::pcm_s16le(16_000)]);
        assert_eq!(custom.pacing_lead(), Duration::from_secs(7));
    }

    /// Each open script: at once; after its delay (and not before); failing
    /// with its error; never. An open is "started" when its future is made,
    /// "opened" when it succeeds, "cancelled" when dropped unfinished.
    #[tokio::test(start_paused = true)]
    async fn an_open_follows_its_script() {
        let format = AudioFormat::pcm_s16le(16_000);
        let stt = ScriptedStt::new(SttScript::default());
        let log = stt.log();
        open(&stt).await;
        assert_eq!(log.opened(), [AudioFormat::pcm_s16le(24_000)]);

        let slow = stt
            .clone()
            .with_open(OpenScript::After(Duration::from_secs(3)));
        let mut pending = Box::pin(slow.open(format, Instant::now()));
        assert!((&mut pending).now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(2_999)).await;
        assert!((&mut pending).now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(pending.await.is_ok());
        assert_eq!(log.opened(), [AudioFormat::pcm_s16le(24_000), format]);

        let refused = SttOpenError {
            label: crate::stt::OpenLabel::Refused,
            class: crate::ErrorClass::fixed("an error event"),
        };
        let failing = stt.clone().with_open(OpenScript::Fail(refused.clone()));
        assert_eq!(
            failing
                .open(format, Instant::now())
                .await
                .expect_err("refused"),
            refused
        );

        let hanging = stt.clone().with_open(OpenScript::Hang);
        let never = tokio::time::timeout(
            Duration::from_secs(60),
            hanging.open(format, Instant::now()),
        )
        .await;
        assert!(never.is_err(), "a hung open never resolves");
        drop(hanging.open(format, Instant::now()));

        assert_eq!(log.opens_started(), 5, "every future made, polled or not");
        assert_eq!(log.opened().len(), 2, "the two that succeeded");
        assert_eq!(
            log.cancelled(),
            Cancelled {
                open: 2,
                ..Cancelled::default()
            },
            "the timed-out open and the one never polled"
        );
    }

    /// Steps wait for the audio their threshold names (at the session's
    /// rate) and keep their order: a later step that is already due waits
    /// for an earlier one. An accepted frame wakes a pending poll; an
    /// exhausted script pends.
    #[tokio::test]
    async fn steps_wait_for_their_audio_and_keep_their_order() {
        let stt = ScriptedStt::new(
            SttScript::default()
                .at(100, SttEvent::SpeechStart)
                .at(0, SttEvent::Partial("what's".into()))
                .at(160, SttEvent::SpeechEnd),
        );
        let log = stt.log();
        let mut session = open(&stt).await;
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));

        assert!(poll(&mut session, &waker).is_pending(), "no audio yet");
        session.send_audio(audio(80)).await.expect("accepted");
        assert_eq!(wakes.count(), 1, "the accepted frame woke the stream");
        assert!(poll(&mut session, &waker).is_pending(), "80 ms < 100 ms");
        session.send_audio(audio(20)).await.expect("accepted");
        assert_eq!(event(poll(&mut session, &waker)), SttEvent::SpeechStart);
        assert_eq!(
            event(poll(&mut session, &waker)),
            SttEvent::Partial("what's".into()),
            "due since the start, after the step before it"
        );
        assert!(poll(&mut session, &waker).is_pending(), "100 ms < 160 ms");
        session.send_audio(audio(60)).await.expect("accepted");
        assert_eq!(event(poll(&mut session, &waker)), SttEvent::SpeechEnd);
        session.send_audio(audio(80)).await.expect("accepted");
        assert!(
            poll(&mut session, &waker).is_pending(),
            "exhausted: pends, never None"
        );
        assert_eq!(log.frames(), [3_840, 960, 2_880, 3_840]);
        assert_eq!(
            log.frame_bytes(),
            [audio(80), audio(20), audio(60), audio(80)],
            "each frame's bytes, as accepted"
        );
        assert_eq!(log.audio_bytes(), 11_520);
        assert_eq!(log.cancelled(), Cancelled::default());
    }

    /// After-end steps are ready once `end_input` has RETURNED; a delayed one
    /// that long after; `finish_after_end` is `Finished`. A hung `end_input`
    /// never returns, readies nothing, and counts as cancelled when dropped.
    #[tokio::test(start_paused = true)]
    async fn after_end_steps_wait_for_end_input_to_return() {
        let script = SttScript::default()
            .after_end(SttEvent::EndOfTurn("Hello.".into()))
            .after_end_delayed(
                Duration::from_millis(1_500),
                SttEvent::EndOfTurn("Late.".into()),
            )
            .finish_after_end();
        let stt = ScriptedStt::new(script.clone());
        let log = stt.log();
        let mut session = open(&stt).await;
        let waker = Waker::noop();
        assert!(poll(&mut session, waker).is_pending());
        session.end_input().await.expect("returned");
        assert_eq!(log.end_inputs(), 1);
        assert_eq!(
            event(poll(&mut session, waker)),
            SttEvent::EndOfTurn("Hello.".into())
        );
        assert!(
            poll(&mut session, waker).is_pending(),
            "the delayed final waits"
        );
        tokio::time::advance(Duration::from_millis(1_499)).await;
        assert!(poll(&mut session, waker).is_pending());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(
            event(poll(&mut session, waker)),
            SttEvent::EndOfTurn("Late.".into())
        );
        assert_eq!(event(poll(&mut session, waker)), SttEvent::Finished);
        assert!(poll(&mut session, waker).is_pending());

        let hanging = ScriptedStt::new(script.hang_end_input());
        let hung_log = hanging.log();
        let mut session = open(&hanging).await;
        let end = tokio::time::timeout(Duration::from_secs(60), session.end_input()).await;
        assert!(end.is_err(), "a hung end_input never returns");
        assert!(
            poll(&mut session, waker).is_pending(),
            "nothing after a hung end"
        );
        assert_eq!(hung_log.end_inputs(), 0);
        assert_eq!(hung_log.cancelled().end_input, 1);
    }

    /// `fail_at` yields its error, then the stream pends; `drop_at` ends it
    /// (`None`, and `None` again).
    #[tokio::test]
    async fn a_failure_pends_after_its_error_and_a_drop_ends_the_stream() {
        let waker = Waker::noop();
        let failing = ScriptedStt::new(
            SttScript::default()
                .fail_at(0, SttError::fixed("an error event"))
                .at(0, SttEvent::SpeechStart),
        );
        let mut session = open(&failing).await;
        assert_eq!(
            poll(&mut session, waker),
            Poll::Ready(Some(Err(SttError::fixed("an error event"))))
        );
        assert!(
            poll(&mut session, waker).is_pending(),
            "nothing after the error"
        );

        let dropping = ScriptedStt::new(
            SttScript::default()
                .at(0, SttEvent::SpeechStart)
                .drop_at(40)
                .at(0, SttEvent::SpeechEnd),
        );
        let mut session = open(&dropping).await;
        assert_eq!(event(poll(&mut session, waker)), SttEvent::SpeechStart);
        assert!(poll(&mut session, waker).is_pending());
        session.send_audio(audio(40)).await.expect("accepted");
        assert_eq!(poll(&mut session, waker), Poll::Ready(None));
        assert_eq!(
            poll(&mut session, waker),
            Poll::Ready(None),
            "ended stays ended"
        );
    }

    /// A flood is ready on every poll, never `Pending`, after the steps
    /// before it.
    #[tokio::test]
    async fn a_flood_is_ready_on_every_poll() {
        let stt = ScriptedStt::new(
            SttScript::default()
                .at(0, SttEvent::SpeechStart)
                .flood(SttEvent::Ignored),
        );
        let mut session = open(&stt).await;
        let waker = Waker::noop();
        assert_eq!(event(poll(&mut session, waker)), SttEvent::SpeechStart);
        for _ in 0..1_000 {
            assert_eq!(event(poll(&mut session, waker)), SttEvent::Ignored);
        }
    }

    /// The keepalive is a timer inside `poll_next`: one tick per interval
    /// while the stream is polled (however often), none before it is due or
    /// while the stream is not polled, and the timer wakes the stream.
    #[tokio::test(start_paused = true)]
    async fn the_keepalive_ticks_inside_poll_next() {
        let stt = ScriptedStt::new(SttScript::default().keepalive_every(Duration::from_secs(3)));
        let log = stt.log();
        let mut session = open(&stt).await;
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        assert!(poll(&mut session, &waker).is_pending());
        tokio::time::advance(Duration::from_millis(2_999)).await;
        assert!(poll(&mut session, &waker).is_pending());
        assert_eq!((log.keepalives(), wakes.count()), (0, 0), "not yet due");
        tokio::time::advance(Duration::from_millis(1)).await;
        for tick in 1..=3 {
            assert_eq!(wakes.count(), tick, "the timer woke the stream");
            for _ in 0..3 {
                assert!(poll(&mut session, &waker).is_pending());
                assert_eq!(log.keepalives(), tick, "one tick per interval");
            }
            tokio::time::advance(Duration::from_secs(3)).await;
        }
        assert_eq!(log.keepalives(), 3);
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_eq!(log.keepalives(), 3, "not polled: no tick");
        assert!(poll(&mut session, &waker).is_pending());
        assert_eq!(log.keepalives(), 4, "a long gap is one tick, not a burst");
    }

    /// Writes after the scripted frame block (forever) or fail; neither is
    /// accepted. A blocked write dropped at its bound counts as cancelled,
    /// and the session still streams and closes.
    #[tokio::test(start_paused = true)]
    async fn blocked_and_failed_writes() {
        let stt = ScriptedStt::new(
            SttScript::default()
                .at(80, SttEvent::SpeechStart)
                .block_writes_after(2),
        );
        let log = stt.log();
        let mut session = open(&stt).await;
        session.send_audio(audio(40)).await.expect("frame 1");
        session.send_audio(audio(40)).await.expect("frame 2");
        let blocked =
            tokio::time::timeout(Duration::from_secs(2), session.send_audio(audio(40))).await;
        assert!(blocked.is_err(), "frame 3 blocks");
        assert_eq!(log.frames(), [1_920, 1_920]);
        assert_eq!(log.cancelled().send_audio, 1);
        assert_eq!(
            event(poll(&mut session, Waker::noop())),
            SttEvent::SpeechStart
        );
        session.close(false).await;
        assert_eq!(log.closed(), Some(false));
        assert_eq!(log.cancelled().close, 0);

        let failing = ScriptedStt::new(
            SttScript::default().fail_writes_after(1, SttError::fixed("io BrokenPipe")),
        );
        let log = failing.log();
        let mut session = open(&failing).await;
        session.send_audio(audio(20)).await.expect("frame 1");
        assert_eq!(
            session.send_audio(audio(20)).await,
            Err(SttError::fixed("io BrokenPipe"))
        );
        assert_eq!(
            session.send_audio(audio(20)).await,
            Err(SttError::fixed("io BrokenPipe"))
        );
        assert_eq!(log.frames(), [960]);
        assert_eq!(log.cancelled(), Cancelled::default());
    }

    /// `close` records `end_sent` when called; a hung close never returns and
    /// counts as cancelled when its bound drops it.
    #[tokio::test(start_paused = true)]
    async fn a_hung_close_is_recorded_and_counted_when_dropped() {
        let stt = ScriptedStt::new(SttScript::default().hang_close());
        let log = stt.log();
        let session = open(&stt).await;
        let closing = tokio::time::timeout(Duration::from_secs(2), session.close(true)).await;
        assert!(closing.is_err(), "a hung close never returns");
        assert_eq!(log.closed(), Some(true));
        assert_eq!(log.cancelled().close, 1);
    }

    /// Each open plays the script from its start; every session writes the
    /// one shared log.
    #[tokio::test]
    async fn each_open_plays_a_fresh_copy_of_the_script() {
        let stt = ScriptedStt::new(SttScript::default().at(0, SttEvent::SpeechStart));
        let log = stt.log();
        let mut first = open(&stt).await;
        assert_eq!(
            event(poll(&mut first, Waker::noop())),
            SttEvent::SpeechStart
        );
        let mut second = open(&stt.clone()).await;
        assert_eq!(
            event(poll(&mut second, Waker::noop())),
            SttEvent::SpeechStart
        );
        second.send_audio(audio(10)).await.expect("accepted");
        assert_eq!(log.opened().len(), 2);
        assert_eq!(log.frames(), [480]);
    }

    /// The scripted provider's defaults and seams: configured, `audio/mpeg`,
    /// 600, voices unknown (`None`); the MP3 by default; queued replies in
    /// order, failures included; a mismatched answer; known voices; every
    /// call recorded, shared by clones.
    #[tokio::test(start_paused = true)]
    async fn the_scripted_tts_answers_its_script() {
        let tts = ScriptedTts::new();
        assert!(tts.configured());
        assert!(!ScriptedTts::unconfigured().configured());
        assert_eq!(tts.media_type(), "audio/mpeg");
        assert_eq!(tts.max_text_chars(), 600);
        assert_eq!(tts.knows_voice("anyone"), None);

        let unavailable = TtsFailure::Unavailable(crate::ErrorClass::fixed("timed out"));
        let shared = tts
            .clone()
            .then(Ok(Bytes::from_static(b"first")))
            .then(Err(unavailable.clone()));
        let spoken = tts
            .synthesize(&SynthesisRequest::new("one", "v1"))
            .await
            .expect("queued audio");
        assert_eq!(
            (&spoken.bytes[..], spoken.media_type),
            (&b"first"[..], "audio/mpeg")
        );
        assert_eq!(
            tts.synthesize(&SynthesisRequest::new("two", "v2"))
                .await
                .expect_err("queued"),
            unavailable
        );
        let default = shared
            .synthesize(&SynthesisRequest::new("three", "v1"))
            .await
            .expect("the default");
        assert_eq!(&default.bytes[..], MP3_FIXTURE);
        assert_eq!(
            tts.calls(),
            [
                ("one".to_string(), "v1".to_string()),
                ("two".to_string(), "v2".to_string()),
                ("three".to_string(), "v1".to_string()),
            ]
        );

        let mismatched = ScriptedTts::new().answering_media_type("audio/wav");
        assert_eq!(mismatched.media_type(), "audio/mpeg");
        let answer = mismatched
            .synthesize(&SynthesisRequest::new("hi", "v"))
            .await
            .expect("audio");
        assert_eq!(answer.media_type, "audio/wav");
        let typed = ScriptedTts::new()
            .with_media_type("audio/ogg")
            .with_max_text_chars(2_000);
        assert_eq!(
            (typed.media_type(), typed.max_text_chars()),
            ("audio/ogg", 2_000)
        );
        let answer = typed
            .synthesize(&SynthesisRequest::new("hi", "v"))
            .await
            .expect("audio");
        assert_eq!(answer.media_type, "audio/ogg");

        let known = ScriptedTts::new().with_known_voices(&["Jason", "Hazel"]);
        assert_eq!(known.knows_voice("Jason"), Some(true));
        assert_eq!(known.knows_voice("jason"), Some(false));

        let slow = ScriptedTts::new().with_delay(Duration::from_secs(4));
        let request = SynthesisRequest::new("hi", "v");
        let mut answer = Box::pin(slow.synthesize(&request));
        assert!((&mut answer).now_or_never().is_none());
        assert_eq!(slow.calls().len(), 1, "recorded when called");
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(answer.await.is_ok());
    }

    /// Concurrent calls (16 threads, 200 each, no delay) each get the reply
    /// queued at their own index in `calls()`: the record and the reply are
    /// taken together, so a test can map every answer to its request.
    #[test]
    fn concurrent_calls_get_the_reply_at_their_recorded_index() {
        const THREADS: usize = 16;
        const CALLS: usize = 200;
        let mut tts = ScriptedTts::new();
        for index in 0..THREADS * CALLS {
            tts = tts.then(Ok(Bytes::from(index.to_string())));
        }
        let start = Arc::new(std::sync::Barrier::new(THREADS));
        let threads: Vec<_> = (0..THREADS)
            .map(|thread| {
                let (tts, start) = (tts.clone(), Arc::clone(&start));
                std::thread::spawn(move || {
                    start.wait();
                    (0..CALLS)
                        .map(|call| {
                            let text = format!("{thread}-{call}");
                            let request = SynthesisRequest::new(&text, "v");
                            let audio = tts
                                .synthesize(&request)
                                .now_or_never()
                                .expect("no delay: answered at once")
                                .expect("a queued reply");
                            (text, audio.bytes)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let answered: std::collections::HashMap<String, Bytes> = threads
            .into_iter()
            .flat_map(|thread| thread.join().expect("a thread"))
            .collect();
        let calls = tts.calls();
        assert_eq!(calls.len(), THREADS * CALLS);
        for (index, (text, _)) in calls.iter().enumerate() {
            assert_eq!(
                answered[text],
                Bytes::from(index.to_string()),
                "call {index} ({text}) got another call's reply"
            );
        }
    }

    #[test]
    fn recording_usage_keeps_every_record_in_order() {
        let usage = RecordingUsage::default();
        let sink: Arc<dyn UsageSink> = Arc::new(usage.clone());
        let at = Utc::now();
        let user = Uuid::new_v4();
        sink.record(user, VoiceMetric::TtsCharacters, 12, at);
        sink.record(user, VoiceMetric::SttMilliseconds, 1_500, at);
        assert_eq!(
            usage.records(),
            [
                (user, VoiceMetric::TtsCharacters, 12, at),
                (user, VoiceMetric::SttMilliseconds, 1_500, at),
            ]
        );
    }

    /// The fixture: an ID3v2.4 tag, then two 96-byte MPEG-1 Layer III frames
    /// whose headers sync, and which an MP3 sniff (an `ID3` tag, or `0xFF`
    /// then a byte with its top three bits set) passes.
    #[test]
    fn the_mp3_fixture_is_a_tag_and_two_frames() {
        assert_eq!(MP3_FIXTURE.len(), 202);
        assert!(MP3_FIXTURE.starts_with(b"ID3\x04\x00"));
        for start in [10, 106] {
            let frame = &MP3_FIXTURE[start..start + 96];
            assert_eq!(frame[..4], [0xFF, 0xFB, 0x14, 0xC0], "the frame at {start}");
            assert_eq!(frame[1] & 0xE0, 0xE0, "frame sync");
            assert!(frame[4..].iter().all(|byte| *byte == 0), "silence");
        }
    }
}
