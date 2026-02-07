//! Task 4.6 — `cms::verify` rejects work orders whose signer chain
//! terminates at the engineer trust anchor (i.e. the same anchor that
//! authenticates the requester).

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
fn rejects_when_engineer_and_approver_share_anchor() {
    let (shared_ca, shared_key) = make_ca();
    let host = "f".repeat(64);
    let entry = format!("sha256:{host}");

    let alice = make_signer_cert(
        "Alice",
        &["bios.flash"],
        &[&entry],
        &shared_ca,
        &shared_key,
    );
    let bob = make_signer_cert(
        "Bob",
        &["bios.flash"],
        &[&entry],
        &shared_ca,
        &shared_key,
    );
    let cms = sign_cms_detached(b"", &[alice, bob]);

    // Same CA used for both stores — this is the misconfiguration we
    // are guarding against.
    let approver_store = store_with(&shared_ca);
    let engineer_store = store_with(&shared_ca);
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
    match verify(&cms, &params) {
        Err(CmsVerifyError::SharedTrustAnchor) => {}
        other => panic!("expected SharedTrustAnchor, got {other:?}"),
    }
}
