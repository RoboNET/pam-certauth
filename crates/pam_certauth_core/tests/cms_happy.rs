//! Happy-path integration test for [`pam_certauth_core::cms::verify`]
//! (plan Task 4.3).  Builds a real 2-signer CMS `SignedData` via the
//! `cms_helpers` fixture and asserts that `verify` returns two distinct
//! `VerifiedSigner` records.

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
fn verify_two_signers_returns_distinct_skis() {
    let (approver_ca, approver_key) = make_ca();
    // Separate disjoint CA so the shared-trust-anchor branch (Task 4.6)
    // never trips during the happy path.
    let (engineer_ca, _engineer_key) = make_ca();

    let host_hash = "b".repeat(64);
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

    let cms = sign_cms_detached(b"", &[alice, bob]);

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

    let result = verify(&cms, &params).expect("happy path verify");
    let signers = result.signers;
    assert!(result.encap_payload.is_none(), "detached fixture should yield no encap payload");
    assert_eq!(signers.len(), 2, "two signers expected");
    assert_ne!(
        signers[0].subject_key_identifier, signers[1].subject_key_identifier,
        "distinct SKIs expected"
    );
    let cns: std::collections::HashSet<&str> =
        signers.iter().map(|s| s.subject_cn.as_str()).collect();
    assert!(cns.contains("Alice"));
    assert!(cns.contains("Bob"));
}
