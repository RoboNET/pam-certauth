#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use pam_certauth_core::pkcs12::{LoadedKeyMaterial, Pkcs12Error};
use secrecy::SecretString;

const RSA: &[u8] = include_bytes!("fixtures/leaf_rsa.p12");
const ECDSA: &[u8] = include_bytes!("fixtures/leaf_ecdsa.p12");

#[test]
fn loads_rsa_p12() {
    let pin = SecretString::from("correct-pin".to_string());
    let m = LoadedKeyMaterial::from_p12(RSA, &pin).unwrap();
    assert_eq!(m.end_entity.subject_cn().unwrap(), "alice");
    assert!(
        !m.presented_chain.is_empty(),
        "expected at least the intermediate CA to ride along"
    );
    // The chain certificate is the intermediate.
    assert_eq!(
        m.presented_chain[0].subject_cn().unwrap(),
        "CertAuth Test Intermediate"
    );
}

#[test]
fn loads_ecdsa_p12() {
    let pin = SecretString::from("correct-pin".to_string());
    let m = LoadedKeyMaterial::from_p12(ECDSA, &pin).unwrap();
    assert_eq!(m.end_entity.subject_cn().unwrap(), "bob");
    assert!(!m.presented_chain.is_empty());
}

#[test]
fn wrong_pin_returns_wrong_pin() {
    let pin = SecretString::from("nope".to_string());
    let err = LoadedKeyMaterial::from_p12(RSA, &pin).unwrap_err();
    assert!(matches!(err, Pkcs12Error::WrongPin), "got {err:?}");
}

#[test]
fn corrupt_p12_returns_corrupt() {
    let pin = SecretString::from("correct-pin".to_string());
    let err = LoadedKeyMaterial::from_p12(b"not-a-p12-byte-stream", &pin).unwrap_err();
    assert!(matches!(err, Pkcs12Error::Corrupt(_)), "got {err:?}");
}

#[test]
fn empty_input_returns_corrupt() {
    let pin = SecretString::from("correct-pin".to_string());
    let err = LoadedKeyMaterial::from_p12(b"", &pin).unwrap_err();
    assert!(matches!(err, Pkcs12Error::Corrupt(_)), "got {err:?}");
}

#[test]
fn private_key_round_trips() {
    let pin = SecretString::from("correct-pin".to_string());
    let m = LoadedKeyMaterial::from_p12(RSA, &pin).unwrap();
    // Materialise the PKey twice — the stored PKCS#8 DER must be reusable.
    let _ = m.private_key().unwrap();
    let _ = m.private_key().unwrap();
}
