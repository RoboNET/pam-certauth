//! Smoke test for the multi-signer CMS fixture helpers (Task 4.2).
//!
//! Verifies that `sign_cms_detached` produces a buffer that the Rust
//! `openssl` binding can parse with `CmsContentInfo::from_der`.  Real
//! verification (signature soundness, signer enumeration) lands in the
//! Tasks 4.3+ integration tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "fixtures/cms_helpers.rs"]
mod cms_helpers;

use cms_helpers::{make_ca, make_signer_cert, sign_cms_detached};

#[test]
fn shell_cms_multi_signer_smoke() {
    let (ca_cert, ca_key) = make_ca();
    // Use a real 64-char hex host hash so the host_binding entry passes
    // the `Sha256Hex` classification in the production parser.
    let host_hash = "a".repeat(64);
    let host_entry = format!("sha256:{host_hash}");
    let alice = make_signer_cert(
        "Alice",
        &["bios.flash"],
        &[&host_entry],
        &ca_cert,
        &ca_key,
    );
    let bob = make_signer_cert(
        "Bob",
        &["bios.flash"],
        &[&host_entry],
        &ca_cert,
        &ca_key,
    );

    let cms = sign_cms_detached(b"", &[alice, bob]);
    assert!(
        cms.len() > 100,
        "CMS unexpectedly short: {} bytes",
        cms.len()
    );

    // Parse with the Rust openssl crate to confirm DER validity.
    let _parsed =
        openssl::cms::CmsContentInfo::from_der(&cms).expect("parse multi-signer CMS");
}
