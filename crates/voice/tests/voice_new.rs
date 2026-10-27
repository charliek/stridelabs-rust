//! `Voice::new`'s refusals (feature `test-support`; no service): revision 1
//! of the protocol holds every app's parts to what the installed clients can
//! do, and `Voice::new` refuses parts that break it, the first problem in
//! its order. Each case moves ONE fact of the scripted adapters, which pass
//! as they come.

use std::sync::Arc;
use std::time::Duration;

use stridelabs_redis::RedisHandle;
use stridelabs_voice::budget::{TtsBudget, TtsCaps};
use stridelabs_voice::lease::{StreamBudget, StreamCaps};
use stridelabs_voice::stt::{AudioFormat, SttProvider as _};
use stridelabs_voice::testing::{RecordingUsage, ScriptedStt, ScriptedTts, SttScript};
use stridelabs_voice::tts::{TtsProvider as _, VoiceCatalog};
use stridelabs_voice::{RelaySettings, Voice, VoiceParts, VoiceSetupError};

/// Both apps' catalog: the eight, identity-mapped, `Jason` the default.
const EIGHT: [&str; 8] = [
    "Jason", "Hazel", "Casey", "Nadia", "Brian", "Imogen", "Liam", "Evan",
];

fn parts(stt: ScriptedStt, tts: ScriptedTts) -> VoiceParts<ScriptedStt, ScriptedTts> {
    VoiceParts {
        stt,
        tts,
        catalog: VoiceCatalog::identity(EIGHT, "Jason").expect("the eight"),
        tts_budget: TtsBudget::new(
            "voice-new-test:tts",
            TtsCaps::new(20_000, 300_000, 300_000).expect("valid caps"),
        ),
        stream_budget: StreamBudget::new(
            "voice-new-test:stream",
            StreamCaps::from_minutes(120, 1_800, 1_800).expect("valid caps"),
        ),
        relay: RelaySettings::default(),
        usage: Arc::new(RecordingUsage::default()),
    }
}

fn stt() -> ScriptedStt {
    ScriptedStt::new(SttScript::default())
}

fn with_stt(stt: ScriptedStt) -> Result<(), VoiceSetupError> {
    Voice::new(parts(stt, ScriptedTts::new())).map(drop)
}

fn with_tts(tts: ScriptedTts) -> Result<(), VoiceSetupError> {
    Voice::new(parts(stt(), tts)).map(drop)
}

fn pcm(rates: &[u32]) -> Vec<AudioFormat> {
    rates.iter().copied().map(AudioFormat::pcm_s16le).collect()
}

/// The scripted parts pass, and the voice keeps what it was given; each
/// route is configured only with its adapter configured AND a Redis.
#[test]
fn the_scripted_parts_pass_and_are_kept() {
    let voice = Voice::new(parts(stt(), ScriptedTts::new())).expect("the defaults pass");
    assert_eq!(voice.catalog().default_voice(), "Jason");
    assert_eq!(voice.tts_budget().prefix(), "voice-new-test:tts");
    assert_eq!(voice.stream_budget().prefix(), "voice-new-test:stream");
    assert_eq!(voice.relay_settings(), RelaySettings::default());
    assert_eq!(voice.stt().pacing_lead(), Duration::from_secs(5));
    assert_eq!(voice.tts().max_text_chars(), 600);

    // A handle is lazy: nothing dials 127.0.0.1:1 here.
    let redis = RedisHandle::open("redis://127.0.0.1:1/0").expect("a lazy handle");
    assert!(voice.tts_configured(Some(&redis)));
    assert!(voice.stream_configured(Some(&redis)));
    assert!(!voice.tts_configured(None));
    assert!(!voice.stream_configured(None));

    let off = Voice::new(parts(
        ScriptedStt::unconfigured(),
        ScriptedTts::unconfigured(),
    ))
    .expect("an unconfigured adapter is the routes' 503, not a startup failure");
    assert!(!off.tts_configured(Some(&redis)));
    assert!(!off.stream_configured(Some(&redis)));
}

/// The formats: at least one; each rate within 8,000–48,000 Hz and offered
/// once. The edges pass.
#[test]
fn voice_new_refuses_bad_formats() {
    for (formats, refusal) in [
        (vec![], VoiceSetupError::NoAudioFormats),
        (
            pcm(&[24_000, 16_000, 24_000]),
            VoiceSetupError::DuplicateAudioFormat {
                sample_rate: 24_000,
            },
        ),
        (
            pcm(&[24_000, 16_000, 7_999]),
            VoiceSetupError::SampleRateOutOfRange { sample_rate: 7_999 },
        ),
        (
            pcm(&[48_001, 24_000, 16_000]),
            VoiceSetupError::SampleRateOutOfRange {
                sample_rate: 48_001,
            },
        ),
        (
            pcm(&[0, 24_000, 16_000]),
            VoiceSetupError::SampleRateOutOfRange { sample_rate: 0 },
        ),
    ] {
        assert_eq!(
            with_stt(stt().with_formats(formats.clone())),
            Err(refusal),
            "{formats:?}"
        );
    }
    assert_eq!(
        with_stt(stt().with_formats(pcm(&[8_000, 24_000, 16_000, 48_000]))),
        Ok(())
    );
}

/// Revision 1 requires BOTH 24,000 and 16,000 Hz of every provider: an
/// installed client opens at 24 kHz and moves to 16 kHz only when its
/// microphone refuses 24 kHz. Either missing is refused; their order (which
/// is the default) is the provider's.
#[test]
fn voice_new_refuses_formats_missing_either_protocol_rate() {
    for (formats, missing) in [
        (pcm(&[24_000]), 16_000),
        (pcm(&[16_000]), 24_000),
        (pcm(&[48_000, 16_000]), 24_000),
        (pcm(&[24_000, 22_050]), 16_000),
    ] {
        assert_eq!(
            with_stt(stt().with_formats(formats.clone())),
            Err(VoiceSetupError::MissingProtocolRate {
                sample_rate: missing
            }),
            "{formats:?}"
        );
    }
    for formats in [
        pcm(&[16_000, 24_000]),
        pcm(&[48_000, 24_000, 16_000]),
        pcm(&[24_000, 16_000]),
    ] {
        assert_eq!(
            with_stt(stt().with_formats(formats.clone())),
            Ok(()),
            "{formats:?}"
        );
    }
}

/// The pacing lead is at least 5 s: the installed clients' 3 s pre-`ready`
/// burst and 4 s lead are fixed.
#[test]
fn voice_new_refuses_a_pacing_lead_under_5_s() {
    for lead in [Duration::ZERO, Duration::from_millis(4_999)] {
        assert_eq!(
            with_stt(stt().with_pacing_lead(lead)),
            Err(VoiceSetupError::PacingLeadTooShort { lead }),
            "{lead:?}"
        );
    }
    for lead in [Duration::from_millis(5_000), Duration::from_secs(8)] {
        assert_eq!(with_stt(stt().with_pacing_lead(lead)), Ok(()), "{lead:?}");
    }
}

/// The media type must be an allowed one, exactly as the protocol writes it
/// (revision 1: `audio/mpeg` alone).
#[test]
fn voice_new_refuses_a_disallowed_media_type() {
    for media_type in [
        "audio/wav",
        "audio/ogg",
        "audio/MPEG",
        "audio/mpeg; x=1",
        "",
    ] {
        assert_eq!(
            with_tts(ScriptedTts::new().with_media_type(media_type)),
            Err(VoiceSetupError::MediaTypeNotAllowed { media_type }),
            "{media_type:?}"
        );
    }
    assert_eq!(
        with_tts(ScriptedTts::new().with_media_type("audio/mpeg")),
        Ok(())
    );
}

/// The text bound is at least 600 characters: every client chunks at 600
/// until a response advertises more.
#[test]
fn voice_new_refuses_a_text_bound_under_600() {
    for max_text_chars in [0, 599] {
        assert_eq!(
            with_tts(ScriptedTts::new().with_max_text_chars(max_text_chars)),
            Err(VoiceSetupError::TextBoundBelowMinimum { max_text_chars }),
            "{max_text_chars}"
        );
    }
    for max_text_chars in [600, 2_000] {
        assert_eq!(
            with_tts(ScriptedTts::new().with_max_text_chars(max_text_chars)),
            Ok(()),
            "{max_text_chars}"
        );
    }
}

/// A provider that says it lacks a mapped voice (`Some(false)`) is refused,
/// naming the APP id; one that cannot tell (`None`) passes. The check reads
/// the PROVIDER id the catalog maps to.
#[test]
fn voice_new_refuses_an_unknown_provider_voice() {
    let all_but_liam: Vec<&str> = EIGHT.into_iter().filter(|voice| *voice != "Liam").collect();
    assert_eq!(
        with_tts(ScriptedTts::new().with_known_voices(&all_but_liam)),
        Err(VoiceSetupError::UnknownProviderVoice {
            app_voice: "Liam".to_string()
        })
    );
    assert_eq!(
        with_tts(ScriptedTts::new().with_known_voices(&EIGHT)),
        Ok(())
    );
    assert_eq!(with_tts(ScriptedTts::new()), Ok(()), "None: cannot tell");

    let mapped = |known: &[&str]| {
        Voice::new(VoiceParts {
            catalog: VoiceCatalog::new([("calm", "p-1"), ("bright", "p-2")], "calm")
                .expect("a mapped catalog"),
            ..parts(stt(), ScriptedTts::new().with_known_voices(known))
        })
        .map(drop)
    };
    assert_eq!(mapped(&["p-1", "p-2"]), Ok(()));
    assert_eq!(
        mapped(&["calm", "bright", "p-1"]),
        Err(VoiceSetupError::UnknownProviderVoice {
            app_voice: "bright".to_string()
        })
    );
}

/// A relay setting outside revision 1's bounds is refused (the bounds
/// themselves: `RelaySettings::check`'s own test).
#[test]
fn voice_new_refuses_relay_settings_out_of_range() {
    let refused = Voice::new(VoiceParts {
        relay: RelaySettings {
            end_timeout: Duration::from_secs(3),
            ..RelaySettings::default()
        },
        ..parts(stt(), ScriptedTts::new())
    })
    .map(drop);
    assert_eq!(
        refused,
        Err(VoiceSetupError::RelaySettingOutOfRange {
            setting: "end_timeout"
        })
    );
}

/// The order: the relay's clocks, then the speech-to-text facts, then the
/// text-to-speech facts. With all three wrong, each fix reveals the next.
#[test]
fn voice_new_checks_the_relay_then_stt_then_tts() {
    let bad_relay = RelaySettings {
        admit_interval: Duration::from_secs(3),
        ..RelaySettings::default()
    };
    let bad_stt = || stt().with_formats(pcm(&[24_000]));
    let bad_tts = || ScriptedTts::new().with_max_text_chars(100);
    let attempt = |relay: RelaySettings, stt: ScriptedStt, tts: ScriptedTts| {
        Voice::new(VoiceParts {
            relay,
            ..parts(stt, tts)
        })
        .map(drop)
    };
    assert_eq!(
        attempt(bad_relay, bad_stt(), bad_tts()),
        Err(VoiceSetupError::RelaySettingOutOfRange {
            setting: "admit_interval"
        })
    );
    assert_eq!(
        attempt(RelaySettings::default(), bad_stt(), bad_tts()),
        Err(VoiceSetupError::MissingProtocolRate {
            sample_rate: 16_000
        })
    );
    assert_eq!(
        attempt(RelaySettings::default(), stt(), bad_tts()),
        Err(VoiceSetupError::TextBoundBelowMinimum {
            max_text_chars: 100
        })
    );
}

/// Each refusal reads as the fact it names, for the app's startup line.
#[test]
fn each_refusal_names_its_fact() {
    for (refusal, expected) in [
        (
            VoiceSetupError::MediaTypeNotAllowed {
                media_type: "audio/wav",
            },
            "text to speech: the media type \"audio/wav\" is not one the protocol allows",
        ),
        (
            VoiceSetupError::TextBoundBelowMinimum {
                max_text_chars: 599,
            },
            "text to speech: a text bound of 599 characters is under the protocol's minimum of 600",
        ),
        (
            VoiceSetupError::MissingProtocolRate {
                sample_rate: 16_000,
            },
            "speech to text: the provider does not take 16000 Hz, which the protocol requires",
        ),
        (
            VoiceSetupError::PacingLeadTooShort {
                lead: Duration::from_millis(4_999),
            },
            "speech to text: a pacing lead of 4.999s is under the protocol's minimum of 5 s",
        ),
        (
            VoiceSetupError::RelaySettingOutOfRange {
                setting: "open_timeout + close_timeout",
            },
            "relay setting open_timeout + close_timeout is outside the protocol's bounds",
        ),
    ] {
        assert_eq!(refusal.to_string(), expected);
    }
}

/// The test seam for short clocks: any non-zero setting is taken (a 300 ms
/// idle, which `check` refuses), and the parts' checks still ran at
/// `Voice::new`.
#[test]
fn short_test_clocks_are_taken_unchecked() {
    let short = RelaySettings {
        idle_timeout: Duration::from_millis(300),
        session_cap: Duration::from_secs(1),
        ..RelaySettings::default()
    };
    assert!(short.check().is_err());
    let voice = Voice::new(parts(stt(), ScriptedTts::new()))
        .expect("the defaults pass")
        .with_relay_settings_unchecked(short);
    assert_eq!(voice.relay_settings(), short);
}

/// A zero duration would panic the relay's timers later: the seam refuses
/// it at once, naming it.
#[test]
#[should_panic(expected = "relay setting pong_deadline is outside the protocol's bounds")]
fn a_zero_test_clock_is_refused_at_once() {
    let _ = Voice::new(parts(stt(), ScriptedTts::new()))
        .expect("the defaults pass")
        .with_relay_settings_unchecked(RelaySettings {
            pong_deadline: Duration::ZERO,
            ..RelaySettings::default()
        });
}
