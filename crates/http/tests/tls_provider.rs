//! `tls::install_default_provider`, in a process of its own.
//!
//! This file must keep exactly ONE `#[test]`. The process-default
//! `CryptoProvider` can be installed once per process, so a second test in
//! this binary — or anything else that installs one — would either hide the
//! first install or fail on it. Cargo runs each file under `tests/` as its
//! own process, which is what makes the premise below (nothing installed
//! yet) hold; it is asserted, so a violation fails loudly instead of proving
//! nothing.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use stridelabs_http::tls::{install_default_provider, ProviderInstall};

/// `provider` is aws-lc-rs's default: the same cipher suites and key
/// exchange groups, in the same order. ring's default differs in its key
/// exchange groups, so the two never compare equal.
fn assert_is_aws_lc_rs(provider: &CryptoProvider) {
    let expected = rustls::crypto::aws_lc_rs::default_provider();
    let suites = |p: &CryptoProvider| {
        p.cipher_suites
            .iter()
            .map(|s| s.suite())
            .collect::<Vec<_>>()
    };
    let groups = |p: &CryptoProvider| p.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>();
    assert_eq!(suites(provider), suites(&expected), "cipher suites");
    assert_eq!(groups(provider), groups(&expected), "key exchange groups");
}

#[test]
fn the_first_install_makes_aws_lc_rs_the_default_and_later_ones_keep_it() {
    assert!(
        CryptoProvider::get_default().is_none(),
        "premise: no rustls CryptoProvider may be installed yet (a second test in this \
         binary, or something it links, installed one)"
    );

    assert_eq!(install_default_provider(), ProviderInstall::Installed);
    let installed: &Arc<CryptoProvider> =
        CryptoProvider::get_default().expect("installed by install_default_provider");
    assert_is_aws_lc_rs(installed);

    // A second install — a library that installs too, a test harness, a
    // repeated startup path — is accepted and changes nothing.
    assert_eq!(
        install_default_provider(),
        ProviderInstall::AlreadyInstalled
    );
    let still = CryptoProvider::get_default().expect("still installed");
    assert!(Arc::ptr_eq(installed, still), "the first provider stays");

    // And the call the install exists for: a builder that relies on the
    // process default gets that provider instead of deriving (or panicking
    // over) one from crate features.
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    assert!(
        Arc::ptr_eq(config.crypto_provider(), installed),
        "ClientConfig::builder() uses the installed provider"
    );
}
