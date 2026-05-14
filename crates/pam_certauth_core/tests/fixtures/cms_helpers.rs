//! Test fixture helpers for producing multi-signer CMS `SignedData`
//! buffers used by the `cms::verify` integration tests (Tasks 4.3-4.10).
//!
//! # Why shell out to `openssl cms`
//!
//! The Rust `openssl` 0.10 crate (`openssl-0.10.78` at workspace lock)
//! only exposes single-signer `CmsContentInfo::sign` and the omnibus
//! `CmsContentInfo::verify`.  It does **not** wrap:
//!
//! * `CMS_add1_signer` / additional `SignerInfo` insertion
//! * iteration over `SignerInfo` entries on a parsed `CmsContentInfo`
//! * access to signed attributes (`signingTime`, content-type, etc.)
//! * access to unsigned attributes (RFC 3161 timestamp tokens)
//! * an EKU accessor on `X509Ref`
//!
//! So to forge **N-signer** CMS objects in tests we shell out to the
//! `openssl cms` CLI:
//!
//!   1. `openssl cms -sign  -binary -outform DER -in payload -signer …` → 1-signer DER
//!   2. `openssl cms -resign -binary -outform DER -inform DER -in step_N.cms \
//!         -signer cert.pem -inkey key.pem -outform DER`  for each extra signer
//!
//! This produces a real RFC 5652 `SignedData` with N distinct
//! `SignerInfo` entries.  `openssl` 3.x is assumed available in any dev
//! or CI environment; if it is not, the smoke test below will fail
//! loudly with the missing-command stderr — which is the correct CI
//! signal (the project already depends on `openssl cms` via several
//! existing scripts under `tests/fixtures/`).
//!
//! # Known limitations
//!
//! * Detached vs. attached signatures: helpers default to
//!   **detached** mode (`-binary`, no `-nodetach`) because that is what
//!   the work-order protocol uses.  Attached mode would only require
//!   dropping `-binary` and feeding the resigning chain the same flag.
//! * EKU on signer leaves is **not** set here.  Task 4.8 will add a
//!   `make_signer_cert_with_eku` variant; for now we emit minimal v3
//!   leaves carrying the host-binding + scopes extensions only.
//! * `signingTime` is automatically inserted by `openssl cms -sign` /
//!   `-resign`; Task 4.7 will reach into the DER to read it back.

#![allow(dead_code)] // Helpers consumed by future integration tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(missing_docs)]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509Extension, X509Name, X509};

/// One CMS signer: keypair + leaf certificate, both PEM-encoded.
pub struct Signer {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

/// Produce a fresh self-signed RSA CA.  Returned as (cert, key) so the
/// caller can both add it to an `X509Store` for chain validation and use
/// it as the issuer for [`make_signer_cert`].
pub fn make_ca() -> (X509, PKey<Private>) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut nb = X509Name::builder().unwrap();
    nb.append_entry_by_text("CN", "test-approver-ca").unwrap();
    let name = nb.build();

    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let serial = {
        let mut bn = BigNum::new().unwrap();
        bn.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .unwrap();
        Asn1Integer::from_bn(&bn).unwrap()
    };
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    b.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
    )
    .unwrap();
    let ski = {
        let ctx = b.x509v3_context(None, None);
        SubjectKeyIdentifier::new().build(&ctx).unwrap()
    };
    b.append_extension(ski).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (b.build(), key)
}

const TAG_SEQUENCE: u8 = 0x30;
const TAG_UTF8_STRING: u8 = 0x0C;

fn encode_short_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 0x80);
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(tag);
    out.push(u8::try_from(body.len()).unwrap());
    out.extend_from_slice(body);
    out
}

fn encode_seq_of_utf8(items: &[&str]) -> Vec<u8> {
    let mut inner = Vec::new();
    for s in items {
        inner.extend_from_slice(&encode_short_tlv(TAG_UTF8_STRING, s.as_bytes()));
    }
    encode_short_tlv(TAG_SEQUENCE, &inner)
}

// OIDs match the values used by the production scopes/host-binding parsers
// under `crates/pam_certauth_core/src/x509/oids.rs`.  We re-import them from
// the crate so any drift is impossible — the integration tests link against
// the same crate they exercise.
use pam_certauth_core::x509::oids::{APPROVER_EKU_OID, HOST_BINDING_OID as OID_HOST_BINDING, SCOPES_OID};

/// OID for `extendedKeyUsage` (X.509 v3).
const OID_EXT_KEY_USAGE: &str = "2.5.29.37";

fn encode_oid_arc(parts: &[u128]) -> Vec<u8> {
    assert!(parts.len() >= 2);
    let mut out = Vec::new();
    out.push(u8::try_from(parts[0] * 40 + parts[1]).unwrap());
    for &p in &parts[2..] {
        // Encode in base-128, big-endian, continuation bit on all but last.
        let mut buf = [0u8; 20];
        let mut idx = buf.len();
        let mut value = p;
        loop {
            idx -= 1;
            buf[idx] = u8::try_from(value & 0x7F).unwrap();
            value >>= 7;
            if value == 0 {
                break;
            }
        }
        let end = buf.len() - 1;
        for b in &mut buf[idx..end] {
            *b |= 0x80;
        }
        out.extend_from_slice(&buf[idx..]);
    }
    out
}

fn parse_oid(dotted: &str) -> Vec<u128> {
    dotted
        .split('.')
        .map(|s| s.parse::<u128>().unwrap())
        .collect()
}

fn encode_oid_tlv(dotted: &str) -> Vec<u8> {
    let content = encode_oid_arc(&parse_oid(dotted));
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(0x06); // OBJECT IDENTIFIER tag
    encode_length_into(&mut out, content.len());
    out.extend_from_slice(&content);
    out
}

fn encode_length_into(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(u8::try_from(n).unwrap());
    } else if n < 0x100 {
        out.push(0x81);
        out.push(u8::try_from(n).unwrap());
    } else if n < 0x1_0000 {
        out.push(0x82);
        out.push(u8::try_from(n >> 8).unwrap());
        out.push(u8::try_from(n & 0xFF).unwrap());
    } else {
        panic!("OID encoding length too large for this fixture helper");
    }
}

/// Encode `SEQUENCE OF OBJECT IDENTIFIER` (for `extendedKeyUsage`).
pub fn encode_seq_of_oids(dotted: &[&str]) -> Vec<u8> {
    let mut inner = Vec::new();
    for d in dotted {
        inner.extend_from_slice(&encode_oid_tlv(d));
    }
    let mut out = Vec::with_capacity(inner.len() + 4);
    out.push(0x30);
    encode_length_into(&mut out, inner.len());
    out.extend_from_slice(&inner);
    out
}

/// Builds a leaf cert signed by `ca_cert` / `ca_key` with the scopes
/// extension carrying `scopes` and the host-binding extension carrying
/// the literal `host_bindings` entries (each will be wrapped as a
/// `UTF8String` inside a `SEQUENCE OF UTF8String`, matching the
/// production `pam_cert_host_binding` schema).  Pass entries like
/// `"sha256:<64-char-hex>"`, `"*"`, or a raw machine-id string.
pub fn make_signer_cert(
    cn: &str,
    scopes: &[&str],
    host_bindings: &[&str],
    ca_cert: &X509,
    ca_key: &PKey<Private>,
) -> Signer {
    make_signer_cert_inner(cn, scopes, host_bindings, ca_cert, ca_key, true)
}

/// Same as [`make_signer_cert`] but without the approver-EKU extension.
/// Used by Task 4.8 negative tests.
pub fn make_signer_cert_no_eku(
    cn: &str,
    scopes: &[&str],
    host_bindings: &[&str],
    ca_cert: &X509,
    ca_key: &PKey<Private>,
) -> Signer {
    make_signer_cert_inner(cn, scopes, host_bindings, ca_cert, ca_key, false)
}

fn make_signer_cert_inner(
    cn: &str,
    scopes: &[&str],
    host_bindings: &[&str],
    ca_cert: &X509,
    ca_key: &PKey<Private>,
    with_approver_eku: bool,
) -> Signer {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut nb = X509Name::builder().unwrap();
    nb.append_entry_by_text("CN", cn).unwrap();
    let name = nb.build();

    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let serial = {
        let mut bn = BigNum::new().unwrap();
        bn.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .unwrap();
        Asn1Integer::from_bn(&bn).unwrap()
    };
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(ca_cert.subject_name()).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();

    // Scopes extension: SEQUENCE OF UTF8String
    {
        let value = encode_seq_of_utf8(scopes);
        let octet = Asn1OctetString::new_from_bytes(&value).unwrap();
        let oid_obj = Asn1Object::from_str(SCOPES_OID).unwrap();
        b.append_extension(X509Extension::new_from_der(&oid_obj, false, &octet).unwrap())
            .unwrap();
    }
    // Host-binding extension: SEQUENCE OF UTF8String (matches the
    // production `pam_cert_host_binding` schema).
    {
        let value = encode_seq_of_utf8(host_bindings);
        let octet = Asn1OctetString::new_from_bytes(&value).unwrap();
        let oid_obj = Asn1Object::from_str(OID_HOST_BINDING).unwrap();
        b.append_extension(X509Extension::new_from_der(&oid_obj, false, &octet).unwrap())
            .unwrap();
    }
    {
        // Always include `emailProtection` (1.3.6.1.5.5.7.3.4) — required
        // by `CMS_verify`'s certificate-purpose check.  When the test
        // requests it, also include the project's approver-EKU OID so
        // Task 4.8 can exercise the `require_approver_eku` branch.
        let oids: Vec<&str> = if with_approver_eku {
            vec!["1.3.6.1.5.5.7.3.4", APPROVER_EKU_OID]
        } else {
            vec!["1.3.6.1.5.5.7.3.4"]
        };
        let value = encode_seq_of_oids(&oids);
        let octet = Asn1OctetString::new_from_bytes(&value).unwrap();
        let oid_obj = Asn1Object::from_str(OID_EXT_KEY_USAGE).unwrap();
        b.append_extension(X509Extension::new_from_der(&oid_obj, false, &octet).unwrap())
            .unwrap();
    }
    let ski = {
        let ctx = b.x509v3_context(Some(ca_cert), None);
        SubjectKeyIdentifier::new().build(&ctx).unwrap()
    };
    b.append_extension(ski).unwrap();

    b.sign(ca_key, MessageDigest::sha256()).unwrap();
    let cert = b.build();

    Signer {
        cert_pem: cert.to_pem().unwrap(),
        key_pem: key.private_key_to_pem_pkcs8().unwrap(),
    }
}

/// Payload-embedding mode for [`sign_cms`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadMode {
    /// Classic detached signature: eContent absent on the wire.  The
    /// payload bytes are hashed but not transmitted; the verifier must
    /// know them out-of-band.
    Detached,
    /// Embedded: payload goes into `encapContentInfo.eContent`, signed
    /// and shipped together with the signatures.  This is the mode used
    /// for `argv_pattern` transport in 0.2.1+.
    Embedded,
}

/// Multi-signer CMS `SignedData` over `payload`, in either detached or
/// embedded mode.
///
/// Uses `openssl cms -sign` for the first signer then `openssl cms
/// -resign` for each subsequent one.  Returns the final DER buffer.
///
/// Panics on any subprocess failure with the captured stderr.
pub fn sign_cms(payload: &[u8], signers: &[Signer], mode: PayloadMode) -> Vec<u8> {
    assert!(!signers.is_empty(), "need at least one signer");

    let tmp = tempfile::tempdir().unwrap();
    let payload_path = tmp.path().join("payload.bin");
    fs::write(&payload_path, payload).unwrap();

    let signer_paths: Vec<(std::path::PathBuf, std::path::PathBuf)> = signers
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let cert_path = tmp.path().join(format!("signer_{i}_cert.pem"));
            let key_path = tmp.path().join(format!("signer_{i}_key.pem"));
            fs::write(&cert_path, &s.cert_pem).unwrap();
            fs::write(&key_path, &s.key_pem).unwrap();
            (cert_path, key_path)
        })
        .collect();

    let step1_path = tmp.path().join("step_1.cms");
    let mut sign_args: Vec<&str> = vec![
        "cms",
        "-sign",
        "-binary",
        "-outform",
        "DER",
        "-in",
        path_str(&payload_path),
        "-signer",
        path_str(&signer_paths[0].0),
        "-inkey",
        path_str(&signer_paths[0].1),
        "-out",
        path_str(&step1_path),
    ];
    if matches!(mode, PayloadMode::Embedded) {
        sign_args.push("-nodetach");
    }
    run_openssl(&sign_args, "cms -sign (signer 0)");

    let mut current = step1_path;
    for (i, (cert, key)) in signer_paths.iter().enumerate().skip(1) {
        let next = tmp.path().join(format!("step_{}.cms", i + 1));
        let mut resign_args: Vec<&str> = vec![
            "cms",
            "-resign",
            "-binary",
            "-inform",
            "DER",
            "-in",
            path_str(&current),
            "-outform",
            "DER",
            "-out",
            path_str(&next),
            "-signer",
            path_str(cert),
            "-inkey",
            path_str(key),
        ];
        if matches!(mode, PayloadMode::Detached) {
            // Pass payload again so -resign hashes the same detached
            // content instead of treating the input CMS as payload.
            resign_args.push("-content");
            resign_args.push(path_str(&payload_path));
        }
        let label = format!("cms -resign (signer {i})");
        run_openssl(&resign_args, &label);
        current = next;
    }

    fs::read(&current).unwrap()
}

/// Back-compat wrapper preserving the legacy detached signature
/// signature for tests that have not been migrated to [`sign_cms`].
pub fn sign_cms_detached(payload: &[u8], signers: &[Signer]) -> Vec<u8> {
    sign_cms(payload, signers, PayloadMode::Detached)
}

fn path_str(p: &Path) -> &str {
    p.to_str().expect("non-UTF8 tempdir path")
}

fn run_openssl(args: &[&str], label: &str) {
    let mut child = Command::new("openssl")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn openssl ({label}): {e}"));
    // No stdin data — close it so openssl doesn't block.
    drop(child.stdin.take());
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait openssl ({label}): {e}"));
    assert!(
        out.status.success(),
        "openssl {label} failed: status={:?}\nstderr={}\nstdout={}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
}

/// Convenience helper: write a chunk of bytes to a tempfile path and
/// return that path.  Some tests need fixture inputs on disk.
pub fn write_tmp(dir: &Path, name: &str, body: &[u8]) -> std::path::PathBuf {
    let p = dir.join(name);
    let mut f = fs::File::create(&p).unwrap();
    f.write_all(body).unwrap();
    p
}
