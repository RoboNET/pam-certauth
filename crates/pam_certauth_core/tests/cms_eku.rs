//! Integration tests for the approver-EKU policy check
//! (plan Task 4.8).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "fixtures/cms_helpers.rs"]
mod cms_helpers;

use cms_helpers::{make_ca, make_signer_cert, make_signer_cert_no_eku, sign_cms_detached};
use openssl::x509::store::X509StoreBuilder;
use pam_certauth_core::cms::{verify, CmsVerifyError, VerifyParams};

fn store_with(cert: &openssl::x509::X509) -> openssl::x509::store::X509Store {
    let mut b = X509StoreBuilder::new().unwrap();
    b.add_cert(cert.clone()).unwrap();
    b.build()
}

fn params<'a>(
    approver_store: &'a openssl::x509::store::X509Store,
    engineer_store: &'a openssl::x509::store::X509Store,
    host_hash: &'a str,
    require: bool,
) -> VerifyParams<'a> {
    VerifyParams {
        approver_store,
        engineer_store,
        host_id_hash: host_hash,
        scope: "bios.flash",
        m_of_n: 1,
        require_approver_eku: require,
        require_timestamp_token: false,
        signing_time_skew_seconds: 300,
        tsa_store: None,
    }
}

#[test]
fn accepts_when_signer_has_eku_and_policy_requires_it() {
    let (approver_ca, approver_key) = make_ca();
    let (engineer_ca, _engineer_key) = make_ca();

    let host_hash = "e".repeat(64);
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
    let p = params(&approver_store, &engineer_store, &host_hash, true);

    let signers = verify(&cms, &p).expect("verify with EKU present should pass").signers;
    assert_eq!(signers.len(), 1);
}

#[test]
fn rejects_when_signer_lacks_eku_and_policy_requires_it() {
    let (approver_ca, approver_key) = make_ca();
    let (engineer_ca, _engineer_key) = make_ca();

    let host_hash = "f".repeat(64);
    let host_entry = format!("sha256:{host_hash}");

    let alice = make_signer_cert_no_eku(
        "Alice",
        &["bios.flash"],
        &[&host_entry],
        &approver_ca,
        &approver_key,
    );

    let cms = sign_cms_detached(b"", &[alice]);

    let approver_store = store_with(&approver_ca);
    let engineer_store = store_with(&engineer_ca);
    let p = params(&approver_store, &engineer_store, &host_hash, true);

    match verify(&cms, &p) {
        Err(CmsVerifyError::EkuMissing) => {}
        other => panic!("expected EkuMissing, got {other:?}"),
    }
}

#[test]
fn accepts_when_policy_disabled_even_without_eku() {
    let (approver_ca, approver_key) = make_ca();
    let (engineer_ca, _engineer_key) = make_ca();

    let host_hash = "1".repeat(64);
    let host_entry = format!("sha256:{host_hash}");

    let alice = make_signer_cert_no_eku(
        "Alice",
        &["bios.flash"],
        &[&host_entry],
        &approver_ca,
        &approver_key,
    );

    let cms = sign_cms_detached(b"", &[alice]);

    let approver_store = store_with(&approver_ca);
    let engineer_store = store_with(&engineer_ca);
    let p = params(&approver_store, &engineer_store, &host_hash, false);

    let signers = verify(&cms, &p).expect("verify without EKU policy should pass").signers;
    assert_eq!(signers.len(), 1);
}
