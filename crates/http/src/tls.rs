//! The process's one rustls crypto provider: aws-lc-rs (feature `tls`).
//!
//! rustls needs a process-level `CryptoProvider`. When nothing installed one,
//! `rustls::ClientConfig::builder()` derives it from rustls's crate features,
//! and it PANICS there if the features name zero providers or two (`ring`
//! next to `aws_lc_rs`). Cargo unifies features over a consumer's whole
//! graph, so one dependency asking for `ring` is enough, the failure never
//! shows at compile time, and it shows at runtime only on the first TLS
//! connect through a builder that relies on the default — which may be one
//! no local or CI run makes.
//!
//! [`install_default_provider`] closes the runtime half: a service calls it
//! once at startup, before anything connects, and no TLS path in the process
//! falls back on the feature-derived default again. reqwest (this crate's
//! `proxy` and `ssrf`) and sqlx name their provider themselves and would not
//! panic either way; the install is for every *other* `ClientConfig::builder()`
//! in the graph — `rediss://` dials through redis-rs, today's and the next
//! dependency's. The compile-time half stays the consumer's: keep aws-lc-rs
//! the only rustls provider in the graph (the workspace README's "One crypto
//! provider" rule, and the `cargo tree` guard its CI runs).
//!
//! Lifted from slauth's `tls.rs`; tapper and limen carry the same function.
//! It lives here rather than in `stridelabs-auth` because that crate is
//! CI-guarded to stay rustls-free — it takes the consumer's `reqwest::Client`
//! and must not pick a TLS stack for it.

/// What [`install_default_provider`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderInstall {
    /// aws-lc-rs is now the process default.
    Installed,
    /// A provider was already the process default and was left in place.
    AlreadyInstalled,
}

/// Make aws-lc-rs the process's default rustls `CryptoProvider`. Call once,
/// at startup, after logging is initialized and before any TLS connection.
///
/// A provider already installed is accepted, not an error: rustls allows one
/// install per process and offers no way to replace it, so whatever got there
/// first stays (a library that installs its own, a test harness, a second call
/// to this function). In a graph that follows the one-provider rule that
/// provider is aws-lc-rs too. The outcome is returned so a caller that cares
/// can assert on it; this function itself only logs it at debug.
pub fn install_default_provider() -> ProviderInstall {
    match rustls::crypto::aws_lc_rs::default_provider().install_default() {
        Ok(()) => ProviderInstall::Installed,
        Err(_already_installed) => {
            tracing::debug!("a rustls CryptoProvider was already installed; keeping it");
            ProviderInstall::AlreadyInstalled
        }
    }
}
