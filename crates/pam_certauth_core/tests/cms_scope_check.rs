//! Task 4.4 — `cms::verify` rejects work orders where any signer cert
//! lacks the requested scope in its `pam_cert_scopes` extension.

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

fn host_entry(hash: &str) -> String {
    format!("sha256:{hash}")
}

#[test]
fn rejects_when_one_signer_lacks_scope() {
    let (approver_ca, approver_key) = make_ca();
    let (engineer_ca, _e_key) = make_ca();
    let host_hash = "c".repeat(64);
    let entry = host_entry(&host_hash);

    // Alice has the WRONG scope, Bob has the right one.
    let alice = make_signer_cert(
        "Alice",
        &["other.scope"],
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
        host_id_hash: &host_hash,
        scope: "bios.flash",
        m_of_n: 2,
        require_approver_eku: false,
        require_timestamp_token: false,
        signing_time_skew_seconds: 300,
        tsa_store: None,
    };
    match verify(&cms, &params) {
        Err(CmsVerifyError::ScopeMissing { scope }) => {
            assert_eq!(scope, "bios.flash");
        }
        other => panic!("expected ScopeMissing, got {other:?}"),
    }
}

#[test]
fn accepts_when_all_signers_carry_scope() {
    let (approver_ca, approver_key) = make_ca();
    let (engineer_ca, _e_key) = make_ca();
    let host_hash = "d".repeat(64);
    let entry = host_entry(&host_hash);

    let alice = make_signer_cert(
        "Alice",
        &["bios.flash", "net.admin"],
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
        host_id_hash: &host_hash,
        scope: "bios.flash",
        m_of_n: 2,
        require_approver_eku: false,
        require_timestamp_token: false,
        signing_time_skew_seconds: 300,
        tsa_store: None,
    };
    let signers = verify(&cms, &params).expect("scope passes for both signers").signers;
    assert_eq!(signers.len(), 2);
}
