//! Integration tests for the `signingTime` skew check
//! (plan Task 4.7).
//!
//! `openssl cms -sign` stamps the current wall clock into each
//! `SignerInfo`'s signed attributes, so the happy path just signs *now*
//! and asserts the verifier accepts.  Forging a far-past signing time
//! without re-implementing CMS encoding is non-trivial, so the negative
//! path uses a zero-skew window: any non-zero clock movement between
//! signing and verification exceeds the window.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "fixtures/cms_helpers.rs"]
mod cms_helpers;

use cms_helpers::{make_ca, make_signer_cert, sign_cms_detached};
use openssl::x509::store::X509StoreBuilder;
use pam_certauth_core::cms::{verify, CmsVerifyError, VerifyParams};

fn store_with(cert: &openssl::x509::X509) -> openssl::x509::store::X509Store {
    let mut b = X509StoreBuilder::new().unwrap();
    b.add_cert(cert.clone()).unwrap();
    b.build()
}

#[test]
fn signing_time_within_skew_accepted() {
    let (approver_ca, approver_key) = make_ca();
    let (engineer_ca, _engineer_key) = make_ca();

    let host_hash = "c".repeat(64);
    let host_entry = format!("sha256:{host_hash}");

    let alice = make_signer_cert(
        "Alice",
        &["bios.flash"],
        &[&host_entry],
        &approver_ca,
        &approver_key,
    );

    let cms = sign_cms_detached(b"", &[alice]);

    let approver_store = store_with(&approver_ca);
    let engineer_store = store_with(&engineer_ca);

    let params = VerifyParams {
        approver_store: &approver_store,
        engineer_store: &engineer_store,
        host_id_hash: &host_hash,
        scope: "bios.flash",
        m_of_n: 1,
        require_approver_eku: false,
        require_timestamp_token: false,
        signing_time_skew_seconds: 300,
        tsa_store: None,
    };

    let signers = verify(&cms, &params).expect("happy path verify").signers;
    assert_eq!(signers.len(), 1);
    // The parsed signing-time should be close to now (within ~5 minutes).
    let drift = (signers[0].signing_time - chrono::Utc::now()).num_seconds().abs();
    assert!(drift < 60, "drift = {drift}s, expected near-zero");
}

#[test]
fn zero_skew_window_after_delay_rejected() {
    let (approver_ca, approver_key) = make_ca();
    let (engineer_ca, _engineer_key) = make_ca();

    let host_hash = "d".repeat(64);
    let host_entry = format!("sha256:{host_hash}");

    let alice = make_signer_cert(
        "Alice",
        &["bios.flash"],
        &[&host_entry],
        &approver_ca,
        &approver_key,
    );

    let cms = sign_cms_detached(b"", &[alice]);

    // Wait one full second so the rounded-to-seconds UTCTime stamped
    // by `openssl cms -sign` is strictly in the past.
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let approver_store = store_with(&approver_ca);
    let engineer_store = store_with(&engineer_ca);

    let params = VerifyParams {
        approver_store: &approver_store,
        engineer_store: &engineer_store,
        host_id_hash: &host_hash,
        scope: "bios.flash",
        m_of_n: 1,
        require_approver_eku: false,
        require_timestamp_token: false,
        signing_time_skew_seconds: 0,
        tsa_store: None,
    };

    match verify(&cms, &params) {
        Err(CmsVerifyError::SigningTimeOutOfWindow) => {}
        other => panic!("expected SigningTimeOutOfWindow, got {other:?}"),
    }
}
