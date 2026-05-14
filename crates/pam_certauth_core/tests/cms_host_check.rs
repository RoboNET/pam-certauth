//! Task 4.5 — `cms::verify` rejects work orders where any signer cert's
//! `pam_cert_host_binding` extension does not authorise the running
//! host.

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
fn rejects_when_one_signer_targets_other_host() {
    let (approver_ca, approver_key) = make_ca();
    let (engineer_ca, _e_key) = make_ca();
    let host_a = "a".repeat(64);
    let host_b = "b".repeat(64);
    let entry_a = format!("sha256:{host_a}");
    let entry_b = format!("sha256:{host_b}");

    let alice = make_signer_cert(
        "Alice",
        &["bios.flash"],
        &[&entry_a],
        &approver_ca,
        &approver_key,
    );
    // Bob's cert binds him to host B — irrelevant for this host.
    let bob = make_signer_cert(
        "Bob",
        &["bios.flash"],
        &[&entry_b],
        &approver_ca,
        &approver_key,
    );
    let cms = sign_cms_detached(b"", &[alice, bob]);

    let approver_store = store_with(&approver_ca);
    let engineer_store = store_with(&engineer_ca);
    let params = VerifyParams {
        approver_store: &approver_store,
        engineer_store: &engineer_store,
        host_id_hash: &host_a,
        scope: "bios.flash",
        m_of_n: 2,
        require_approver_eku: false,
        require_timestamp_token: false,
        signing_time_skew_seconds: 300,
        tsa_store: None,
    };
    match verify(&cms, &params) {
        Err(CmsVerifyError::HostMismatch) => {}
        other => panic!("expected HostMismatch, got {other:?}"),
    }
}

#[test]
fn accepts_when_all_signers_bind_correct_host() {
    let (approver_ca, approver_key) = make_ca();
    let (engineer_ca, _e_key) = make_ca();
    let host = "e".repeat(64);
    let entry = format!("sha256:{host}");

    let alice = make_signer_cert(
        "Alice",
        &["bios.flash"],
        &[&entry],
        &approver_ca,
        &approver_key,
    );
    let bob = make_signer_cert(
        "Bob",
        &["bios.flash"],
        &[&entry],
        &approver_ca,
        &approver_key,
    );
    let cms = sign_cms_detached(b"", &[alice, bob]);

    let approver_store = store_with(&approver_ca);
    let engineer_store = store_with(&engineer_ca);
    let params = VerifyParams {
        approver_store: &approver_store,
        engineer_store: &engineer_store,
        host_id_hash: &host,
        scope: "bios.flash",
        m_of_n: 2,
        require_approver_eku: false,
        require_timestamp_token: false,
        signing_time_skew_seconds: 300,
        tsa_store: None,
    };
    let signers = verify(&cms, &params).expect("host binding passes for both signers").signers;
    assert_eq!(signers.len(), 2);
}
