//! Graceful-shutdown primitives.
//!
//! Carried over from a production reverse proxy's `http::server`, where both
//! functions were private helpers. Only these two are extracted: that
//! proxy's *bounded drain* (stop
//! accepting, then wait out in-flight requests up to a configured timeout)
//! is embedded in its `serve_with_shutdown` and is entangled with that
//! service's config and its background refresh task — there is no standalone
//! drain primitive to lift, and inventing one here would be designing a new
//! API rather than sharing a proven one. The drain stays app-side.

use tokio::sync::watch;

/// Resolve once the process is asked to stop: SIGINT (Ctrl-C) or, on unix,
/// SIGTERM — whichever arrives first.
///
/// Pass it straight to axum's graceful shutdown:
///
/// ```no_run
/// # async fn example(listener: tokio::net::TcpListener, app: axum::Router) -> std::io::Result<()> {
/// axum::serve(listener, app)
///     .with_graceful_shutdown(stridelabs_http::shutdown_signal())
///     .await
/// # }
/// ```
///
/// On non-unix targets only Ctrl-C applies; the SIGTERM arm becomes a future
/// that never resolves, so the `select!` degrades cleanly rather than needing
/// a second function.
///
/// Panics if a signal handler cannot be installed. That happens at startup,
/// on a platform misconfiguration, and the alternative — a service that runs
/// but can never be shut down gracefully — is worse than a loud early exit.
///
/// Not covered by unit tests: exercising it means actually delivering a
/// signal to the test process, which would race every other test in the
/// binary. The body is a `select!` over two `tokio::signal` futures with no
/// logic of its own.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
}

/// Resolve once a shutdown flag flips to `true`, or immediately if it is
/// already set.
///
/// The point of the "already set" check is fan-out: a process running several
/// servers holds one `watch::Sender<bool>` and hands each server its own
/// `Receiver`, so a receiver cloned *after* the flag was set must not wait
/// for a change that has already happened.
///
/// ```no_run
/// # async fn example(app: axum::Router, listener: tokio::net::TcpListener) {
/// let (tx, rx) = tokio::sync::watch::channel(false);
/// tokio::spawn(async move {
///     stridelabs_http::shutdown_signal().await;
///     let _ = tx.send(true);
/// });
///
/// axum::serve(listener, app)
///     .with_graceful_shutdown(stridelabs_http::wait_for_shutdown(rx))
///     .await
///     .unwrap();
/// # }
/// ```
///
/// The flag is assumed one-way (`false` → `true`, never back): this returns
/// on the *first* change without re-reading the value, and also returns if
/// every sender is dropped — a dropped sender means nothing can ever signal
/// shutdown again, which for this purpose is indistinguishable from it having
/// been signalled.
pub async fn wait_for_shutdown(mut rx: watch::Receiver<bool>) {
    if *rx.borrow_and_update() {
        return;
    }
    let _ = rx.changed().await;
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn returns_immediately_when_the_flag_is_already_set() {
        let (_tx, rx) = watch::channel(true);

        // No timeout needed: if the "already set" check regressed, this awaits
        // a change that never comes and the test hangs — a failure either way.
        wait_for_shutdown(rx).await;
    }

    #[tokio::test]
    async fn resolves_when_the_flag_flips() {
        let (tx, rx) = watch::channel(false);
        let waiting = tokio::spawn(wait_for_shutdown(rx));

        tx.send(true).unwrap();

        waiting.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn pends_while_the_flag_stays_false() {
        let (_tx, rx) = watch::channel(false);

        // Paused clock: the timeout fires instantly in wall-clock terms, so
        // proving "does not resolve" costs no test time.
        let outcome = tokio::time::timeout(Duration::from_secs(60), wait_for_shutdown(rx)).await;

        assert!(outcome.is_err(), "must not resolve before the flag flips");
    }

    #[tokio::test]
    async fn resolves_when_every_sender_is_dropped() {
        let (tx, rx) = watch::channel(false);

        drop(tx);

        wait_for_shutdown(rx).await;
    }
}
