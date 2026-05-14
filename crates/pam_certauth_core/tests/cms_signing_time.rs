//! Integration tests for the `signingTime` signed attribute.
//!
//! Prior to 0.2.2 these tests asserted a symmetric skew window around
//! `now()`.  That enforcement was dropped (see `docs/work-order.md`)
//! because legitimate banking workflows pre-sign work orders weeks
//! ahead of execution; the cert validity window is the authoritative
//! time bound now.  signing-time is retained as an audit attribute and
//! surfaced via `VerifiedSigner.signing_time`, but no longer compared
//! to wall-clock at verify time.
//!
//! Tests below assert:
//!   * the parsed `signing_time` lands in `VerifiedSigner` close to
//!     the wall clock for a freshly-signed CMS (happy path),
//!   * a CMS whose `signingTime` is far in the past still verifies
//!     successfully (the regression that 0.2.2 fixes).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[path = "fixtures/cms_helpers.rs"]
mod cms_helpers;

use cms_helpers::{make_ca, make_signer_cert, sign_cms_detached};
use openssl::x509::store::X509StoreBuilder;
use pam_certauth_core::cms::{verify, VerifyParams};

fn store_with(cert: &openssl::x509::X509) -> openssl::x509::store::X509Store {
    let mut b = X509StoreBuilder::new().unwrap();
    b.add_cert(cert.clone()).unwrap();
    b.build()
}

#[test]
fn signing_time_populated_on_verified_signer() {
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
    // signing_time must be populated for audit downstream — the
    // parsed value should be close to the wall clock for a CMS we
    // just minted.
    let drift = (signers[0].signing_time - chrono::Utc::now()).num_seconds().abs();
    assert!(drift < 60, "drift = {drift}s, expected near-zero");
}

#[test]
fn old_signing_time_still_verifies() {
    // Regression for the 0.2.2 change: a CMS whose `signingTime` is
    // arbitrarily far in the past (within cert validity) must still
    // verify.  We simulate "old" by setting a tiny skew window
    // (`signing_time_skew_seconds: 0`) and sleeping past it before
    // calling verify; the verifier must accept regardless.
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

    // Sleep so the rounded-to-seconds UTCTime stamped at signing is
    // strictly in the past — under the pre-0.2.2 zero-skew rule this
    // would have been rejected as SigningTimeOutOfWindow.
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

    let result = verify(&cms, &params).expect("pre-signed CMS must verify");
    assert_eq!(result.signers.len(), 1);
    // And signing_time is still parsed and surfaced for audit.
    assert!(result.signers[0].signing_time.timestamp() > 0);
}
