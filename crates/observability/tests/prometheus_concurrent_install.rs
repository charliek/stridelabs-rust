//! Racing first callers of `prometheus::install`, in a process of their own.
//!
//! This file must keep exactly ONE `#[test]`. The race only exists for the
//! FIRST `install()` in a process: any earlier call (another test in the same
//! binary, even the idempotence test) leaves the cell filled, every worker
//! takes the lock-free fast path, and the test would pass without exercising
//! the mutex at all. Cargo runs each file under `tests/` as its own process,
//! so a test alone in its file is guaranteed to be the first caller.

use std::sync::{Arc, Barrier};

use stridelabs_observability::install;

#[test]
fn concurrent_first_installs_all_succeed_over_one_registry() {
    // A barrier releases every thread together so they all reach the
    // not-yet-installed state at once. Without the install mutex the losers
    // hit "recorder already set" and `install()` returns `Err`.
    const THREADS: usize = 16;
    let barrier = Arc::new(Barrier::new(THREADS));

    let workers: Vec<_> = (0..THREADS)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                install()
            })
        })
        .collect();

    let handles: Vec<_> = workers
        .into_iter()
        .map(|worker| {
            worker
                .join()
                .expect("a worker thread panicked")
                .expect("every concurrent install succeeds")
        })
        .collect();

    // Identical EMPTY renders would also come from 16 unrelated registries, so
    // record one sample through the process-global recorder and require every
    // handle to expose it: that is only true if they all share the registry
    // the winning install published.
    metrics::counter!("concurrent_install_probe_total").increment(1);

    for (i, handle) in handles.iter().enumerate() {
        let scrape = handle.render();
        assert!(
            scrape
                .lines()
                .any(|l| l == "concurrent_install_probe_total 1"),
            "handle {i} does not see the probe sample:\n{scrape}"
        );
    }
}
