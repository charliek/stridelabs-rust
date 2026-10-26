//! The protocol's golden fixture (no feature, no service): the file the
//! client package keeps a byte copy of. It must be EXACTLY the crate's
//! rendering of its events, and its SHA-256 the one `PROTOCOL.md` records,
//! so a change to an event, a field's order or the rendering fails here
//! before it can drift from the clients.

use sha2::{Digest as _, Sha256};
use stridelabs_voice::protocol::{RelayEvent, GOLDEN_FIXTURE, GOLDEN_FIXTURE_SHA256};

/// The SHA-256 every copy is checked against, literally: a change to it is a
/// protocol revision (`PROTOCOL.md` §10).
const REVISION_1_SHA256: &str = "0437bc8114b0397e3b9734e03c9cb3d72f18ba928f22a160e19fb68f6226ed15";

fn read(path: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// **The fixture is the protocol's bytes:** the file on disk equals
/// `RelayEvent::golden_fixture()` byte for byte (and the constant compiled
/// from it): 620 bytes, LF line ends and a final LF, one compact event per
/// line. Every line parses back to its event, the eleven in `PROTOCOL.md`
/// §11's order, the advertising `ready` first and a bare one last.
#[test]
fn the_golden_fixture_is_the_protocols_bytes() {
    let file = read("fixtures/relay_events.json");
    let rendered = RelayEvent::golden_fixture();
    assert_eq!(
        std::str::from_utf8(&file),
        Ok(rendered.as_str()),
        "fixtures/relay_events.json is not the crate's rendering of RelayEvent::golden()"
    );
    assert_eq!(GOLDEN_FIXTURE.as_bytes(), file.as_slice());
    assert_eq!(file.len(), 620);
    assert!(!file.contains(&b'\r') && file.ends_with(b"]\n"));

    let events: Vec<RelayEvent> = serde_json::from_slice(&file).expect("a JSON array of events");
    assert_eq!(events, RelayEvent::golden());
    let lines: Vec<&str> = rendered.lines().collect();
    assert_eq!((lines[0], lines[lines.len() - 1]), ("[", "]"));
    for (line, event) in lines[1..lines.len() - 1].iter().zip(RelayEvent::golden()) {
        let compact = line
            .strip_prefix("  ")
            .map(|line| line.strip_suffix(',').unwrap_or(line))
            .expect("two spaces of indent");
        assert_eq!(compact, event.to_json());
        assert_eq!(
            serde_json::from_str::<RelayEvent>(compact).expect("an event"),
            event
        );
    }
    assert_eq!(
        lines[1],
        r#"  {"type":"ready","rates":[24000,16000],"encoding":"pcm_s16le","lead_ms":5000},"#
    );
    assert_eq!(lines[11], r#"  {"type":"ready"}"#);
}

/// **Its SHA-256 is the protocol's:** the file's hash equals the constant,
/// the literal, and the hash `PROTOCOL.md` records (with its size), so the
/// client package's copy, which checks the same hash, cannot drift.
#[test]
fn its_sha256_is_the_protocols() {
    let computed = sha256_hex(&read("fixtures/relay_events.json"));
    assert_eq!(computed, REVISION_1_SHA256);
    assert_eq!(GOLDEN_FIXTURE_SHA256, REVISION_1_SHA256);
    assert_eq!(sha256_hex(GOLDEN_FIXTURE.as_bytes()), REVISION_1_SHA256);

    let protocol = String::from_utf8(read("PROTOCOL.md")).expect("UTF-8");
    let recorded: Vec<&str> = protocol
        .match_indices("SHA-256 `")
        .map(|(at, marker)| &protocol[at + marker.len()..])
        .map(|rest| rest.split('`').next().unwrap_or_default())
        .collect();
    assert_eq!(
        recorded,
        [REVISION_1_SHA256],
        "PROTOCOL.md records ONE hash, this one"
    );
    assert!(
        protocol.contains(&format!("`{REVISION_1_SHA256}`\n  (620 bytes)")),
        "PROTOCOL.md records the fixture's size beside its hash"
    );
    assert!(protocol.starts_with("# The StrideLabs voice protocol, revision 1\n"));
}
