//! The response bound is also the memory bound. A `2xx` body just under the
//! 4 MiB bound whose bulk is a field the crate does not read (an array of
//! about two million zeros) is skipped as it is parsed, never built: parsed
//! into a `serde_json::Value`, the array alone would be about 64 MiB of
//! values (32 bytes each).
//!
//! Its own test binary, with this one test, so nothing else in the process
//! allocates beside it. The workspace forbids `unsafe`, so there is no
//! counting allocator here; on Linux the process's peak resident set size is
//! measured instead (reset through `/proc/self/clear_refs`, read from
//! `/proc/self/status`'s `VmHWM`), and everywhere the parse must return the
//! audio, quickly.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{audio_body, client, mp3, request, RawServer};
use stridelabs_inworld::DEFAULT_MAX_RESPONSE_BYTES;

/// The most the process's peak RSS may grow during the synthesis: the body
/// (4 MiB, read once into a buffer that may double as it grows), its
/// `audioContent` and the client's own buffers. A `Value` of the body would
/// pass it by some 40 MiB.
#[cfg(target_os = "linux")]
const PEAK_GROWTH_BOUND_KIB: u64 = 24 * 1024;

#[cfg(target_os = "linux")]
mod peak_rss {
    /// `VmHWM`, in KiB.
    pub fn kib() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status");
        status
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .and_then(|value| value.trim().strip_suffix("kB"))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or_else(|| panic!("no VmHWM in /proc/self/status:\n{status}"))
    }

    /// Reset the peak to the current RSS (`clear_refs` `5`), and return it.
    pub fn reset() -> u64 {
        std::fs::write("/proc/self/clear_refs", "5")
            .expect("resetting the peak RSS through /proc/self/clear_refs");
        kib()
    }
}

#[tokio::test]
async fn a_body_of_skipped_values_under_the_bound_parses_in_bounded_memory() {
    let audio = mp3(64);
    let opening = audio_body(&audio);
    // `{"audioContent":"…","x":[0,0,…,0]}`, one byte under the bound.
    let mut body = opening.strip_suffix('}').expect("an object").to_string();
    body.push_str(r#","x":["#);
    let zeros = (DEFAULT_MAX_RESPONSE_BYTES - 1 - body.len() - 2) / 2;
    body.push_str(&"0,".repeat(zeros));
    body.push_str("0]}");
    while body.len() < DEFAULT_MAX_RESPONSE_BYTES - 1 {
        body.insert(1, ' ');
    }
    assert_eq!(body.len(), DEFAULT_MAX_RESPONSE_BYTES - 1);
    assert!(zeros > 2_000_000, "{zeros} zeros");
    let response = Arc::new(
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    );
    drop(body);
    let server = RawServer::start(move |mut exchange| {
        let response = Arc::clone(&response);
        async move {
            exchange
                .send(&response)
                .await
                .expect("the client reads the whole answer");
        }
    })
    .await;
    let inworld = client(&server.base_url);

    #[cfg(target_os = "linux")]
    let before = peak_rss::reset();
    let started = Instant::now();
    let synthesis = inworld
        .synthesize(&request("hi"))
        .await
        .expect("the audio, the rest skipped");
    let elapsed = started.elapsed();
    #[cfg(target_os = "linux")]
    let grew = peak_rss::kib().saturating_sub(before);

    assert_eq!(synthesis.audio.as_ref(), audio.as_slice());
    assert!(
        elapsed < Duration::from_secs(5),
        "{elapsed:?} to read and parse 4 MiB"
    );
    #[cfg(target_os = "linux")]
    assert!(
        grew < PEAK_GROWTH_BOUND_KIB,
        "the peak RSS grew {grew} KiB during the synthesis, over {PEAK_GROWTH_BOUND_KIB} KiB: \
         is the body being built rather than skipped?"
    );
    drop(inworld);
    assert_eq!(server.finish().await, 1);
}
