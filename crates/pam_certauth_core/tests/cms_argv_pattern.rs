//! Commit 1 of the review-fix plan: `cms::verify` must return the
//! encapsulated content bytes alongside verified signers so the
//! orchestrator can read `argv_pattern` from the *signed* CMS payload
//! rather than an unsigned sidecar file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "fixtures/cms_helpers.rs"]
mod cms_helpers;

use cms_helpers::{make_ca, make_signer_cert, sign_cms, PayloadMode};
use openssl::x509::store::X509StoreBuilder;
use pam_certauth_core::cms::{verify, VerifyParams};

fn store_with(cert: &openssl::x509::X509) -> openssl::x509::store::X509Store {
    let mut b = X509StoreBuilder::new().unwrap();
    b.add_cert(cert.clone()).unwrap();
    b.build()
}

#[test]
fn verify_returns_embedded_payload_for_argv_pattern() {
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
    let bob = make_signer_cert(
        "Bob",
        &["bios.flash"],
        &[&host_entry],
        &approver_ca,
        &approver_key,
    );

    let payload = b"argv_pattern = \"flashrom -w *.bin\"\n";
    let cms = sign_cms(payload, &[alice, bob], PayloadMode::Embedded);

    let approver_store = store_with(&approver_ca);
    let engineer_store = store_with(&engineer_ca);

    let params = VerifyParams {
        approver_store: &approver_store,
        engineer_store: &engineer_store,
        host_id_hash: &host_hash,
        scope: "bios.flash",
        m_of_n: 2,
        require_approver_eku: false,
        require_timestamp_token: false,
        signing_time_skew_seconds: 300,
        tsa_store: None,
    };

    let result = verify(&cms, &params).expect("embedded payload verify");
    assert_eq!(result.signers.len(), 2, "two signers expected");
    let encap = result
        .encap_payload
        .expect("embedded eContent must be returned to caller");
    let s = std::str::from_utf8(&encap).unwrap();
    assert!(
        s.contains("argv_pattern"),
        "returned encap payload should preserve TOML body, got {s:?}"
    );
}

#[test]
fn verify_returns_none_payload_for_detached() {
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

    let cms = sign_cms(b"", &[alice], PayloadMode::Detached);

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

    let result = verify(&cms, &params).expect("detached verify");
    assert_eq!(result.signers.len(), 1);
    assert!(
        result.encap_payload.is_none(),
        "detached CMS must yield Option::None for encap_payload"
    );
}
