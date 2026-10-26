#![doc = include_str!("../README.md")]

pub mod budget;
pub mod lease;
pub mod window;

/// What holds the crate to its extraction base (tapper `82be95f`): every
/// script byte for byte, and every key shape under tapper's own prefixes.
#[cfg(test)]
mod extraction_base {
    use std::time::Duration;

    use chrono::{DateTime, Utc};
    use sha1::{Digest as _, Sha1};
    use uuid::Uuid;

    use crate::budget::{
        lua_helpers, ChargeKey, TtsBudget, TtsCaps, CHARGE_SCRIPT, CHARGE_SCRIPT_SHA1,
        CHARGE_VERDICT_SECONDS, MAX_CHARGE_KEY_CHARS,
    };
    use crate::lease::{
        StreamBudget, StreamCaps, ACQUIRE_SCRIPT, ACQUIRE_SCRIPT_SHA1, FENCE_TTL_SECONDS,
        ISSUE_SCRIPT, ISSUE_SCRIPT_SHA1, LEASE_TTL, METER_SCRIPT, METER_SCRIPT_SHA1,
        METER_TTL_SECONDS, MILLIS_PER_MINUTE,
    };
    use crate::window::{DAY_KEY_GRACE_SECONDS, MONTH_KEY_GRACE_SECONDS};

    fn sha1_hex(bytes: &str) -> String {
        Sha1::digest(bytes.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// **The scripts are the extraction base's, byte for byte**: the SHA-1 of
    /// the exact bytes each script sends (and its length) equals the public
    /// constant AND the literal computed from tapper `82be95f`'s source
    /// (`tapper-rs/src/voice/budget.rs`, `lease.rs`; D1 §4.3, the ledger's
    /// D-R1). Every script opens with the shared helpers, whose own SHA-1 is
    /// pinned too. A ported tapper fix moves the base, the constants and this
    /// table together.
    #[test]
    fn the_scripts_are_the_extraction_bases() {
        let helpers: &str = lua_helpers!();
        assert_eq!(
            (helpers.len(), sha1_hex(helpers).as_str()),
            (649, "882d901b042222ab1dfa60cad4981e1af84fd928"),
            "LUA_HELPERS"
        );
        for (name, script, constant, length, literal) in [
            (
                "CHARGE_SCRIPT",
                CHARGE_SCRIPT,
                CHARGE_SCRIPT_SHA1,
                2_398,
                "6db0a4afd52968ffb65e754d4dc48c7112016757",
            ),
            (
                "ISSUE_SCRIPT",
                ISSUE_SCRIPT,
                ISSUE_SCRIPT_SHA1,
                927,
                "71b413abe08a2fe9288ecd807b0e8e8fad6cc6c0",
            ),
            (
                "ACQUIRE_SCRIPT",
                ACQUIRE_SCRIPT,
                ACQUIRE_SCRIPT_SHA1,
                2_035,
                "96f220b3004096553dc0fa570d43b306aa7e52d9",
            ),
            (
                "METER_SCRIPT",
                METER_SCRIPT,
                METER_SCRIPT_SHA1,
                1_926,
                "b07b06c546464c457e44086bce1d96cbd5823ecb",
            ),
        ] {
            assert!(script.starts_with(helpers), "{name} opens with the helpers");
            let computed = sha1_hex(script);
            assert_eq!(computed, constant, "{name}: the public constant");
            assert_eq!(computed, literal, "{name}: the extraction base");
            assert_eq!(script.len(), length, "{name}'s length");
            assert!(
                script.is_ascii() && !script.contains('\r'),
                "{name}: ASCII with LF line ends"
            );
        }
    }

    /// **The lifetimes are the extraction base's** (D1 §4.1's expiry column,
    /// §4.4's arguments): the verdict's ten minutes, the lease's 30 s, the
    /// fence's day, the session meter's hour, the windows' graces, and the
    /// key and unit constants the scripts are sent. The live suites compare
    /// what Redis holds with these constants; this pins the constants.
    #[test]
    fn the_lifetimes_are_the_extraction_bases() {
        assert_eq!(CHARGE_VERDICT_SECONDS, 600);
        assert_eq!(MAX_CHARGE_KEY_CHARS, 64);
        assert_eq!(LEASE_TTL, Duration::from_secs(30));
        assert_eq!(FENCE_TTL_SECONDS, 24 * 60 * 60);
        assert_eq!(METER_TTL_SECONDS, 60 * 60);
        assert_eq!(MILLIS_PER_MINUTE, 60_000);
        assert_eq!(DAY_KEY_GRACE_SECONDS, 60 * 60);
        assert_eq!(MONTH_KEY_GRACE_SECONDS, 24 * 60 * 60);
    }

    /// Every key both budgets write, for `user` (session `token`) at `now`,
    /// under `tts` and `stream`: the text budget's four, then the stream's
    /// seven.
    fn every_key(tts: &str, stream: &str) -> Vec<String> {
        let user = Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("a uuid");
        let token = Uuid::parse_str("99999999-8888-7777-6666-555555555555").expect("a uuid");
        let now: DateTime<Utc> = "2026-10-17T23:59:59Z".parse().expect("an instant");
        // The caps are not part of a key: any valid caps build the same strings.
        let tts = TtsBudget::new(tts, TtsCaps::new(1, 2, 3).expect("valid caps"));
        let key = ChargeKey::parse("sentence-1").expect("a key");
        let stream = StreamBudget::new(
            stream,
            StreamCaps::from_minutes(1, 2, 3).expect("valid caps"),
        );
        vec![
            tts.user_key(user, now),
            tts.user_month_key(user, now),
            tts.global_key(now),
            tts.charge_key(user, &key),
            stream.lease_key(user),
            stream.user_key(user, now),
            stream.user_month_key(user, now),
            stream.global_key(now),
            stream.meter_key(token),
            stream.admit_key(user),
            stream.fence_key(user),
        ]
    }

    /// **Every key shape is tapper's under tapper's prefixes** (D1 §4.1): each
    /// key both budgets write, built with `TtsBudget::new("tapper:voice:tts",
    /// …)` and `StreamBudget::new("tapper:voice:stream", …)` at a fixed
    /// instant, is exactly the string tapper's own tests assert today
    /// (`the_keys_name_the_utc_day_and_month`, `the_charge_key_is_scoped_by_user`,
    /// `the_keys_are_under_the_prefix`, `every_issue_answer_has_one_meaning`
    /// at `82be95f`), so tapper's adoption changes no key on the wire. And the
    /// same keys under lumen's prefixes (`lumen:voice:tts`,
    /// `lumen:voice:stream`), literally, as lumen's adoption writes them. This
    /// is where the apps' own key strings are held: the live suites write only
    /// under prefixes of their own (`tests/test_redis`), never an app's.
    #[test]
    fn the_key_shapes_are_tappers_under_tappers_prefixes() {
        assert_eq!(
            every_key("tapper:voice:tts", "tapper:voice:stream"),
            [
                "tapper:voice:tts:user:11111111-2222-3333-4444-555555555555:2026-10-17",
                "tapper:voice:tts:user-month:11111111-2222-3333-4444-555555555555:2026-10",
                "tapper:voice:tts:global:2026-10",
                "tapper:voice:tts:charge:11111111-2222-3333-4444-555555555555:sentence-1",
                "tapper:voice:stream:lease:11111111-2222-3333-4444-555555555555",
                "tapper:voice:stream:user:11111111-2222-3333-4444-555555555555:2026-10-17",
                "tapper:voice:stream:user-month:11111111-2222-3333-4444-555555555555:2026-10",
                "tapper:voice:stream:global:2026-10",
                "tapper:voice:stream:session:99999999-8888-7777-6666-555555555555",
                "tapper:voice:stream:admit:11111111-2222-3333-4444-555555555555",
                "tapper:voice:stream:fence:11111111-2222-3333-4444-555555555555",
            ]
        );
        assert_eq!(
            every_key("lumen:voice:tts", "lumen:voice:stream"),
            [
                "lumen:voice:tts:user:11111111-2222-3333-4444-555555555555:2026-10-17",
                "lumen:voice:tts:user-month:11111111-2222-3333-4444-555555555555:2026-10",
                "lumen:voice:tts:global:2026-10",
                "lumen:voice:tts:charge:11111111-2222-3333-4444-555555555555:sentence-1",
                "lumen:voice:stream:lease:11111111-2222-3333-4444-555555555555",
                "lumen:voice:stream:user:11111111-2222-3333-4444-555555555555:2026-10-17",
                "lumen:voice:stream:user-month:11111111-2222-3333-4444-555555555555:2026-10",
                "lumen:voice:stream:global:2026-10",
                "lumen:voice:stream:session:99999999-8888-7777-6666-555555555555",
                "lumen:voice:stream:admit:11111111-2222-3333-4444-555555555555",
                "lumen:voice:stream:fence:11111111-2222-3333-4444-555555555555",
            ]
        );
    }
}
