//! Integration tests for the RFC 3161 `TimeStampToken` enforcement path
//! introduced by Commit 2 of the 0.2.1 review-fix plan.
//!
//! # Scope
//!
//! `cms::verify` honors `VerifyParams::require_timestamp_token`.  When
//! the flag is set, every verified signer must carry an
//! `id-aa-timeStampToken` unsigned attribute that chain-validates
//! against `params.tsa_store`.  In 0.2.0 the flag was silently no-op,
//! which downgraded the spec §4 row 4 guarantee.
//!
//! # Coverage
//!
//! * **Negative — missing TST:** signed CMS without any
//!   `unsignedAttrs[id-aa-timeStampToken]` must be rejected with
//!   `TimestampTokenMissing` when `require_timestamp_token = true`.
//! * **Misconfiguration — flag set but no store:** must be rejected as
//!   a configuration error (`Verify(...)`).
//!
//! # Deferred (phase-2)
//!
//! Positive-path round-trip (a CMS *with* a valid TST that the
//! verifier accepts end-to-end) requires (a) running an actual
//! `openssl ts -reply` TSA to mint a token over a `SignerInfo`'s
//! signature octets and (b) attaching that token to the CMS's
//! `SignerInfo.unsignedAttrs` — for which `openssl` 0.10 does not
//! wrap `CMS_unsigned_add1_attr_by_OBJ`, and neither
//! `openssl cms -sign` nor `-resign` exposes a CLI flag.  The
//! parser-side coverage is exercised by unit tests:
//!   * `cms::der_walk::tests::extract_unsigned_attrs_returns_attr_value_set`
//!   * `cms::der_walk::tests::extract_signatures_returns_signature_octets`
//!   * `cms::der_walk::tests::extract_signatures_skips_signed_attrs`
//!   * `cms::der_walk::tests::parse_tst_message_imprint_extracts_oid_and_hash`
//!
//! These prove the RFC 3161 §2.4.1 messageImprint binding pipeline
//! parses correctly.  The production code path is correct regardless:
//! it *rejects* CMS without TST when policy demands one, and it now
//! additionally binds `TSTInfo.messageImprint.hashedMessage` to
//! `hash(signature_bytes)` so a compromised TSA cannot forge a token
//! for a different signature.  A future commit will plumb the attach
//! helper through FFI to cover the positive case end-to-end.

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

fn empty_store() -> openssl::x509::store::X509Store {
    X509StoreBuilder::new().unwrap().build()
}

#[test]
fn cms_without_tst_rejected_when_required() {
    let (approver_ca, approver_key) = make_ca();
    let (engineer_ca, _engineer_key) = make_ca();
    let (tsa_ca, _tsa_key) = make_ca();

    let host_hash = "e".repeat(64);
    let host_entry = format!("sha256:{host_hash}");

    let alice = make_signer_cert(
        "Alice",
        &["bios.flash"],
        &[&host_entry],
        &approver_ca,
        &approver_key,
    );
    // Detached CMS produced by `openssl cms -sign` does NOT attach an
    // RFC 3161 timestamp-token unsigned attribute (no CLI flag does).
    let cms = sign_cms_detached(b"", &[alice]);

    let approver_store = store_with(&approver_ca);
    let engineer_store = store_with(&engineer_ca);
    let tsa_store = store_with(&tsa_ca);

    let params = VerifyParams {
        approver_store: &approver_store,
        engineer_store: &engineer_store,
        host_id_hash: &host_hash,
        scope: "bios.flash",
        m_of_n: 1,
        require_approver_eku: false,
        require_timestamp_token: true,
        signing_time_skew_seconds: 300,
        tsa_store: Some(&tsa_store),
    };

    match verify(&cms, &params) {
        Err(CmsVerifyError::TimestampTokenMissing) => {}
        other => panic!("expected TimestampTokenMissing, got {other:?}"),
    }
}

#[test]
fn require_timestamp_token_without_tsa_store_is_misconfiguration() {
    let (approver_ca, approver_key) = make_ca();
    let (engineer_ca, _engineer_key) = make_ca();

    let host_hash = "f".repeat(64);
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
        require_timestamp_token: true,
        signing_time_skew_seconds: 300,
        tsa_store: None,
    };

    match verify(&cms, &params) {
        Err(CmsVerifyError::Verify(msg)) => {
            assert!(
                msg.contains("tsa_store"),
                "unexpected Verify message: {msg}"
            );
        }
        other => panic!("expected Verify(tsa_store...) misconfig, got {other:?}"),
    }
}

#[test]
fn require_timestamp_token_false_still_passes_without_tst() {
    // Sanity check: ensure the new code path is gated on the flag — a
    // CMS with no TST should still verify when the policy does not
    // require timestamping.  This catches an accidental
    // "always enforce" bug.
    let (approver_ca, approver_key) = make_ca();
    let (engineer_ca, _engineer_key) = make_ca();

    let host_hash = "1".repeat(64);
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
    let _empty = empty_store();

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

    verify(&cms, &params).expect("happy path verify");
}
