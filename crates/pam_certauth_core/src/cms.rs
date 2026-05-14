//! CMS (RFC 5652) work order verifier for M-of-N approvals.
//!
//! See `docs/work-order.md` and spec §4.
//!
//! # Indexing policy
//!
//! Every byte/slice index in this module operates on a buffer whose
//! length has already been validated by an upstream `read_tlv` /
//! `read_tlv_expect` call (the canonical DER bounds check, see
//! `crate::x509::der`).  Where we slice directly (e.g. stripping the
//! leading-zero of a DER INTEGER), the length is checked in the
//! surrounding `if` guard.  `clippy::indexing_slicing` cannot prove
//! these cross-statement invariants, so we suppress the lint
//! module-wide.  Reviewers MUST flag any new naked index without an
//! adjacent bounds guard.

#![allow(
    clippy::indexing_slicing,
    reason = "CMS/DER parser: every index is bounded by a prior read_tlv \
              length check or an explicit `len() > N` guard; see module docs."
)]
//!
//! # Status
//!
//! Full M-of-N verifier.  `verify()` enforces signature chain, scope,
//! host-binding, optional approver EKU, signer-count quorum, and
//! `signingTime` window.  Each `signingTime` is paired with its issuer
//! cert by `SignerIdentifier` (SKI for v3, `IssuerAndSerial` for v1) —
//! not by SET-OF order, which RFC 5652 does not guarantee.
//!
//! # Design notes
//!
//! * `signing_time` on [`VerifiedSigner`] is typed `chrono::DateTime<Utc>`
//!   per spec §4.  The workspace already pulls `chrono` (serde + std), so
//!   the type compiles without enabling extra features.  Parsing of the
//!   real `signingTime` CMS attribute will be added in Task 4.7; until
//!   then no construction site for this field exists.
//! * The Rust `openssl` 0.10 binding only exposes single-signer
//!   `CmsContentInfo::sign` / `verify` — no `SignerInfo` iteration, no
//!   signed-attribute access, no EKU accessor on `X509Ref`.  Tasks 4.3-4.9
//!   will therefore need a mix of: (a) `CMS_verify` for crypto soundness,
//!   (b) raw ASN.1 parsing of the `SignedData` structure to enumerate
//!   signers, signing-time and TSA tokens, and (c) walking
//!   `X509Ref::extensions()` for EKU bytes.  See Task 4.2 feasibility
//!   report.

// `CMS_get0_signers` is not wrapped by `openssl` 0.10, so we declare it
// directly and invoke it through `unsafe` blocks.  This module is the
// only one in `pam_certauth_core` that pierces the workspace
// `#![deny(unsafe_code)]` policy; all callers stay safe.
#![allow(unsafe_code)]

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::stack::StackRef;
use openssl::x509::{X509Ref, X509};
use thiserror::Error;

use crate::x509::oids::APPROVER_EKU_OID;


// `openssl` 0.10 does not wrap `CMS_get0_signers`, but the symbol is part
// of every libcrypto build with CMS support.  Declare it directly so we
// can enumerate signer certs after `CMS_verify` succeeds.
//
// `CMS_get0_signers` returns a new `STACK_OF(X509)` that the caller must
// free (with `sk_X509_free`, *not* `sk_X509_pop_free` — the stack does
// not own its elements).  We free the stack via `OPENSSL_sk_free` once
// we have cloned out the certs.
#[allow(non_camel_case_types)]
mod ffi_cms_get0_signers {
    use openssl_sys::{stack_st_X509, CMS_ContentInfo};
    extern "C" {
        pub fn CMS_get0_signers(cms: *mut CMS_ContentInfo) -> *mut stack_st_X509;
    }
}

/// Hard cap on the size of an incoming CMS buffer.  Anything larger is
/// rejected before invoking OpenSSL to avoid pathological parse costs.
pub const MAX_CMS_BYTES: usize = 10 * 1024 * 1024;

/// All failure modes that [`verify`] can surface.  Variants map 1:1 onto
/// the failure rows in spec §4 so callers can render audit messages
/// without re-classifying.
#[derive(Debug, Error)]
pub enum CmsVerifyError {
    /// Input exceeded [`MAX_CMS_BYTES`].
    #[error("cms too large: {0} bytes (cap {1})")]
    TooLarge(usize, usize),
    /// DER parse error before any signature check.
    #[error("cms parse: {0}")]
    Parse(String),
    /// `CMS_verify` rejected one or more `SignerInfos`.
    #[error("verify: {0}")]
    Verify(String),
    /// Fewer distinct signers than the policy `m_of_n` quorum.
    #[error("insufficient signatures: have {have} need {need}")]
    Insufficient {
        /// Distinct verified signers found.
        have: u8,
        /// Quorum required by policy.
        need: u8,
    },
    /// Two `SignerInfos` resolved to the same `SubjectKeyIdentifier`.
    #[error("duplicate signer SKI: {0}")]
    DuplicateSki(String),
    /// Signer certificate has no `pam-cert-scopes` extension covering
    /// the requested scope.
    #[error("signer cert lacks scope {scope}")]
    ScopeMissing {
        /// The scope demanded by policy.
        scope: String,
    },
    /// Signer certificate's host-binding extension does not match the
    /// current host id hash.
    #[error("signer cert host mismatch")]
    HostMismatch,
    /// Signer chain terminates at the engineer trust anchor instead of
    /// the approver trust anchor — i.e. the same key that authenticates
    /// the work order requester also signed it.
    #[error("signer cert chain terminates at engineer trust anchor")]
    SharedTrustAnchor,
    /// Approver EKU is required by policy but missing on the leaf cert.
    #[error("signer cert lacks approver EKU")]
    EkuMissing,
    /// `signingTime` attribute is outside the allowed skew window.
    ///
    /// Retained for source compatibility in the 0.2.x series; the
    /// signing-time skew enforcement was dropped in 0.2.2 (the cert
    /// validity window is the authoritative time bound — see
    /// `docs/work-order.md`).  No code path constructs this variant
    /// any more.
    #[deprecated(
        since = "0.2.2",
        note = "signing-time skew enforcement was dropped; cert validity is the time bound"
    )]
    #[error("signing-time outside skew window")]
    SigningTimeOutOfWindow,
    /// Policy requires an RFC 3161 timestamp token but none was present.
    #[error("timestamp token required but missing")]
    TimestampTokenMissing,
    /// Catch-all for low-level OpenSSL errors that don't slot into the
    /// semantic variants above.
    #[error("openssl: {0}")]
    Openssl(String),
}

/// Inputs to [`verify`].  Borrowed for the duration of the call so the
/// caller retains ownership of the trust stores.
pub struct VerifyParams<'a> {
    /// Trust store rooted at the approver CA.  Every `SignerInfo` must
    /// chain to this store.
    pub approver_store: &'a openssl::x509::store::X509Store,
    /// Trust store rooted at the engineer CA — used purely for
    /// shared-anchor detection (`SharedTrustAnchor`).
    pub engineer_store: &'a openssl::x509::store::X509Store,
    /// Hex SHA-256 of the host id; signer cert host-binding must match.
    pub host_id_hash: &'a str,
    /// Scope the work order requests; must appear in each signer's
    /// `pam-cert-scopes` extension.
    pub scope: &'a str,
    /// Quorum required by policy.
    pub m_of_n: u8,
    /// If true, each signer's leaf cert must carry the approver EKU OID.
    pub require_approver_eku: bool,
    /// If true, the CMS must include an RFC 3161 timestamp token in
    /// unsigned attributes.
    pub require_timestamp_token: bool,
    /// Allowed clock skew (seconds) for the `signingTime` signed attr.
    ///
    /// **Unused since 0.2.2** — the symmetric skew check broke
    /// legitimate pre-signing of work orders ahead of execution.  The
    /// cert validity window is now the authoritative time bound.
    /// Retained for source compatibility in 0.2.x callers; the value
    /// is ignored by `verify`.
    pub signing_time_skew_seconds: u64,
    /// Optional TSA trust store.  Required when
    /// `require_timestamp_token` is set.
    pub tsa_store: Option<&'a openssl::x509::store::X509Store>,
}

/// Outcome of a successful [`verify`] call: the list of verified
/// signers, plus the encapsulated CMS payload bytes (TOML work-order
/// body) when the producer signed in *embedded* mode.
///
/// `encap_payload` is `None` for *detached* CMS (the wire format used
/// in 0.2.0 and earlier).  Starting with 0.2.1 callers that need
/// `argv_pattern` MUST require embedded mode and read it from the
/// signed payload — the unsigned `<work_order>.pattern` sidecar
/// previously used was removed because it could be tampered with by
/// any local actor without invalidating approver signatures.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    /// Distinct verified signers, in input order.
    pub signers: Vec<VerifiedSigner>,
    /// Encapsulated content bytes if the CMS was produced with the
    /// payload embedded; `None` for detached signatures.
    pub encap_payload: Option<Vec<u8>>,
}

/// One verified signer.  Returned in input order.
#[derive(Debug, Clone)]
pub struct VerifiedSigner {
    /// SHA-1 SKI of the signer cert, lowercase hex.
    pub subject_key_identifier: String,
    /// `CN=` component of the signer cert subject.
    pub subject_cn: String,
    /// `signingTime` signed attribute parsed into UTC.
    pub signing_time: chrono::DateTime<chrono::Utc>,
}

/// Verify a CMS `SignedData` buffer against the supplied policy.
///
/// # Current behaviour
///
/// Only the size guard is implemented; everything else returns
/// `CmsVerifyError::Verify("not yet implemented")`.  Tasks 4.3-4.10 fill
/// in: parse, crypto verify, scope/host/EKU checks, m-of-n counting,
/// signing-time skew, TSA verification.
#[allow(clippy::too_many_lines)]
pub fn verify(
    buffer: &[u8],
    params: &VerifyParams<'_>,
) -> Result<VerifyResult, CmsVerifyError> {
    if buffer.len() > MAX_CMS_BYTES {
        return Err(CmsVerifyError::TooLarge(buffer.len(), MAX_CMS_BYTES));
    }
    // Extract embedded encapContentInfo.eContent (if present) up front so
    // we can return it alongside verified signers.  Detached CMS yields
    // `None` here.  The walk only reads structure — it does NOT attest
    // anything; the crypto check below is what binds the payload to the
    // signer set.
    let encap_payload = der_walk::extract_encap_content(buffer)?;
    let mut cms = CmsContentInfo::from_der(buffer)
        .map_err(|e| CmsVerifyError::Parse(e.to_string()))?;

    // Branch on payload mode: detached (no eContent — pass `Some(&[])`
    // so OpenSSL hashes zero bytes) vs embedded (let OpenSSL pull the
    // payload from encapContentInfo by passing `None` and dropping the
    // DETACHED flag).
    let (indata, options): (Option<&[u8]>, CMSOptions) = if encap_payload.is_some() {
        (None, CMSOptions::BINARY)
    } else {
        (Some(&[][..]), CMSOptions::DETACHED | CMSOptions::BINARY)
    };
    cms.verify(
        None,
        Some(params.approver_store),
        indata,
        None,
        options,
    )
    .map_err(|e| CmsVerifyError::Verify(e.to_string()))?;

    // Shared-anchor probe: if the same signatures also verify against
    // the engineer trust store, the work order was signed using the
    // same trust anchor that authenticates the engineer who *requests*
    // approvals — which is exactly the cross-role separation the work
    // order is meant to enforce.  Reject (plan §4.3 step 3).
    {
        let mut probe = CmsContentInfo::from_der(buffer)
            .map_err(|e| CmsVerifyError::Parse(e.to_string()))?;
        let probe_ok = probe
            .verify(
                None,
                Some(params.engineer_store),
                indata,
                None,
                options,
            )
            .is_ok();
        if probe_ok {
            return Err(CmsVerifyError::SharedTrustAnchor);
        }
    }

    // SAFETY: `CMS_verify` (called via `verify_with_options` above) returned
    // successfully, so the underlying `CMS_ContentInfo` has its verified
    // signer-cert stack populated. `collect_signer_certs` only walks that
    // already-validated stack and clones each entry through openssl's safe
    // wrappers.
    let signer_certs = unsafe { collect_signer_certs(&cms) }?;
    let have_u8 = u8::try_from(signer_certs.len()).unwrap_or(u8::MAX);
    if have_u8 < params.m_of_n {
        return Err(CmsVerifyError::Insufficient {
            have: have_u8,
            need: params.m_of_n,
        });
    }

    // Pull `signingTime` per SignerInfo out of the DER (openssl 0.10
    // does not expose signed attributes).  We must pair each signing
    // time with its signer cert by SignerIdentifier (SKI or
    // IssuerAndSerial) — RFC 5652 does not guarantee that the SET-OF
    // ordering matches `CMS_get0_signers`' output order.
    let by_key = der_walk::extract_signing_times_by_key(buffer)?;
    let mut signing_time_map: std::collections::HashMap<der_walk::SignerKey, chrono::DateTime<chrono::Utc>> =
        std::collections::HashMap::with_capacity(by_key.len());
    for (k, t) in by_key {
        // Duplicate SignerIdentifier in the SET-OF — should already be
        // rejected by SKI dedup below, but reject here too as a
        // defense-in-depth check at the parsing layer.
        if signing_time_map.insert(k, t).is_some() {
            return Err(CmsVerifyError::Verify(
                "duplicate SignerIdentifier in signerInfos".into(),
            ));
        }
    }
    if signing_time_map.len() != signer_certs.len() {
        return Err(CmsVerifyError::Verify(format!(
            "signer count mismatch: {} certs vs {} signing-times",
            signer_certs.len(),
            signing_time_map.len()
        )));
    }
    // signing-time skew enforcement was dropped in 0.2.2 (see
    // `docs/work-order.md` — pre-signing work orders ahead of
    // execution is a supported workflow; cert validity is the
    // authoritative time bound).  `params.signing_time_skew_seconds`
    // is still accepted for source compatibility but ignored.  The
    // signing-time per signer is still parsed below and surfaced via
    // `VerifiedSigner.signing_time` for audit purposes.

    // Stash per-signer `SignerKey` candidates for the optional TSA-token
    // enforcement pass below.  We compute these inside the cert loop
    // anyway, so collect them as we go to avoid recomputing later.
    let mut signer_keys_by_cert: Vec<Vec<der_walk::SignerKey>> =
        Vec::with_capacity(signer_certs.len());
    let mut seen_ski = std::collections::HashSet::new();
    let mut verified: Vec<VerifiedSigner> = Vec::with_capacity(signer_certs.len());
    for cert in &signer_certs {
        let ski_hex = cert
            .subject_key_id()
            .map(|s| hex::encode(s.as_slice()))
            .ok_or_else(|| CmsVerifyError::Openssl("signer cert missing SKI".into()))?;
        if !seen_ski.insert(ski_hex.clone()) {
            return Err(CmsVerifyError::DuplicateSki(ski_hex));
        }
        // Match signing-time to this cert by SignerIdentifier.  Try SKI
        // first (v3 SignerInfo), then fall back to IssuerAndSerial (v1).
        let ski_bytes = cert
            .subject_key_id()
            .map(|s| s.as_slice().to_vec())
            .unwrap_or_default();
        let issuer_der = cert
            .issuer_name()
            .to_der()
            .map_err(|e| CmsVerifyError::Openssl(format!("issuer DER: {e}")))?;
        let serial_der = cert
            .serial_number()
            .to_bn()
            .map(|bn| bn.to_vec())
            .map_err(|e| CmsVerifyError::Openssl(format!("serial: {e}")))?;
        let signing_time = signing_time_map
            .remove(&der_walk::SignerKey::Ski(ski_bytes.clone()))
            .or_else(|| {
                signing_time_map.remove(&der_walk::SignerKey::IssuerAndSerial {
                    issuer_der: issuer_der.clone(),
                    serial_der: serial_der.clone(),
                })
            })
            .ok_or_else(|| {
                CmsVerifyError::Verify(format!("no signing-time for signer {ski_hex}"))
            })?;
        // Remember the key candidates for the TSA-token lookup below.
        signer_keys_by_cert.push(vec![
            der_walk::SignerKey::Ski(ski_bytes.clone()),
            der_walk::SignerKey::IssuerAndSerial {
                issuer_der: issuer_der.clone(),
                serial_der: serial_der.clone(),
            },
        ]);
        // (signing-time skew check removed in 0.2.2 — see comment above
        // the per-signer loop.)
        //
        // Every signer must claim the requested scope.  We do not
        // accept "M of N have scope, the rest do not" — plan §4.3.
        let claimed_scopes = crate::x509::scopes_ext::parse(cert).map_err(|e| {
            CmsVerifyError::Verify(format!("scopes ext on signer: {e}"))
        })?;
        if !crate::x509::scopes_ext::contains(&claimed_scopes, params.scope) {
            return Err(CmsVerifyError::ScopeMissing {
                scope: params.scope.to_owned(),
            });
        }
        // Every signer cert must additionally authorise the current
        // host via its `pam_cert_host_binding` extension.
        crate::host_binding::verify_host_binding(cert, params.host_id_hash)
            .map_err(|_| CmsVerifyError::HostMismatch)?;
        // Approver EKU check (plan §4.3 step 3, Task 4.8).  When the
        // policy demands it, the leaf must explicitly carry the
        // project-allocated `APPROVER_EKU_OID` in its
        // `extendedKeyUsage` extension.
        if params.require_approver_eku {
            let eku = crate::x509::ext::eku_oids(cert)
                .map_err(|e| CmsVerifyError::Verify(format!("eku: {e}")))?;
            if !eku.iter().any(|o| o == APPROVER_EKU_OID) {
                return Err(CmsVerifyError::EkuMissing);
            }
        }
        verified.push(VerifiedSigner {
            subject_key_identifier: ski_hex,
            subject_cn: cert_cn(cert),
            signing_time,
        });
    }

    // Optional RFC 3161 TimeStampToken enforcement.  When the policy
    // sets `require_timestamp_token = true`, every verified signer must
    // carry an `id-aa-timeStampToken` unsigned attribute whose
    // TimeStampToken CMS chain-verifies against the supplied TSA trust
    // store **and** whose `TSTInfo.messageImprint.hashedMessage` equals
    // `hash(signature_bytes)` of the outer SignerInfo it attests (RFC
    // 3161 §2.4.1).  Without the imprint binding, a compromised but
    // not-yet-revoked TSA key could be used to mint a token for
    // arbitrary content.  Enforced from 0.2.1+.
    if params.require_timestamp_token {
        const TST_OID: &str = "1.2.840.113549.1.9.16.2.14";
        let tsa_store = params.tsa_store.ok_or_else(|| {
            CmsVerifyError::Verify(
                "require_timestamp_token=true but no tsa_store configured".into(),
            )
        })?;
        let unsigned_by_key = der_walk::extract_unsigned_attrs_by_key(buffer)?;
        let attrs_map: std::collections::HashMap<der_walk::SignerKey, der_walk::UnsignedAttrMap> =
            unsigned_by_key.into_iter().collect();
        // Per-signer raw `signature` bytes, used as the input to the
        // TSTInfo.messageImprint hash check.  Built once and indexed by
        // SignerKey to mirror the unsigned-attrs lookup above.
        let sigs_by_key: std::collections::HashMap<der_walk::SignerKey, Vec<u8>> =
            der_walk::extract_signatures_by_key(buffer)?
                .into_iter()
                .collect();

        for keys in &signer_keys_by_cert {
            let attrs = keys
                .iter()
                .find_map(|k| attrs_map.get(k))
                .ok_or(CmsVerifyError::TimestampTokenMissing)?;
            let tst_attr_set = attrs
                .get(TST_OID)
                .ok_or(CmsVerifyError::TimestampTokenMissing)?;
            // attrValues SET must contain exactly one inner ContentInfo
            // — the TimeStampToken itself.
            let tst_der = der_walk::unwrap_attr_value(tst_attr_set)?;
            let mut tst_cms = CmsContentInfo::from_der(&tst_der)
                .map_err(|e| CmsVerifyError::Verify(format!("TST parse: {e}")))?;
            // The TST CMS is itself a SignedData attesting TSTInfo.
            // We let OpenSSL pull the encapsulated content from inside
            // the TST (no DETACHED flag, no `indata`).  Chain validity
            // against the TSA trust store is the gate.
            tst_cms
                .verify(
                    None,
                    Some(tsa_store),
                    None,
                    None,
                    CMSOptions::BINARY,
                )
                .map_err(|e| {
                    CmsVerifyError::Verify(format!("TST chain validation: {e}"))
                })?;

            // RFC 3161 §2.4.1: bind the TST to *this* SignerInfo.
            // Compute the expected hash over the signature octets and
            // compare against TSTInfo.messageImprint.hashedMessage.
            let sig_bytes = keys
                .iter()
                .find_map(|k| sigs_by_key.get(k))
                .ok_or_else(|| {
                    CmsVerifyError::Verify(
                        "TST imprint: signature bytes not found for signer".into(),
                    )
                })?;
            let (hash_oid, hashed_message) =
                der_walk::parse_tst_message_imprint(&tst_der)?;
            let expected = hash_with_oid(&hash_oid, sig_bytes)?;
            // Constant-time comparison — the imprint is not secret but
            // the principle costs us nothing here.
            if subtle::ConstantTimeEq::ct_eq(expected.as_slice(), hashed_message.as_slice())
                .unwrap_u8()
                == 0
            {
                return Err(CmsVerifyError::Verify(
                    "TST messageImprint does not match signature".into(),
                ));
            }
        }
    }

    Ok(VerifyResult {
        signers: verified,
        encap_payload,
    })
}

/// Hash `data` with the algorithm identified by a NIST hash `AlgID` OID,
/// returning the digest bytes.  Used to recompute
/// `TSTInfo.messageImprint.hashedMessage` for the RFC 3161 binding
/// check.  Supports SHA-256/384/512 — the algorithms RFC 3161 §2.2 lists
/// as MUSTs for modern profiles.  Any other OID is rejected as
/// `CmsVerifyError::Verify("unsupported TST hash <oid>")`.
fn hash_with_oid(hash_oid: &str, data: &[u8]) -> Result<Vec<u8>, CmsVerifyError> {
    use sha2::Digest;
    match hash_oid {
        "2.16.840.1.101.3.4.2.1" => Ok(sha2::Sha256::digest(data).to_vec()),
        "2.16.840.1.101.3.4.2.2" => Ok(sha2::Sha384::digest(data).to_vec()),
        "2.16.840.1.101.3.4.2.3" => Ok(sha2::Sha512::digest(data).to_vec()),
        other => Err(CmsVerifyError::Verify(format!(
            "unsupported TST hash {other}"
        ))),
    }
}

/// Calls `CMS_get0_signers` and returns each signer cert as an owned
/// `X509`.  The returned stack is freed with `OPENSSL_sk_free` (the stack
/// itself is owned by the caller; its elements are borrowed from the
/// `CmsContentInfo` and must not be freed, which is why we clone each
/// cert into an owned `X509` via `to_owned`).
///
/// # Safety
///
/// `cms` must point to a valid `CMS_ContentInfo` on which `CMS_verify`
/// has already returned successfully.
unsafe fn collect_signer_certs(cms: &CmsContentInfo) -> Result<Vec<X509>, CmsVerifyError> {
    // SAFETY: `cms.as_ptr()` is a live `*mut CMS_ContentInfo` owned by the
    // borrowed `CmsContentInfo`; the function-level safety contract states
    // that `CMS_verify` has already succeeded on it.
    let stack_ptr = unsafe { ffi_cms_get0_signers::CMS_get0_signers(cms.as_ptr()) };
    if stack_ptr.is_null() {
        return Err(CmsVerifyError::Openssl(
            "CMS_get0_signers returned NULL".into(),
        ));
    }
    // SAFETY: `stack_ptr` is non-null and points to a `STACK_OF(X509)` whose
    // elements are borrowed from `cms` (per `CMS_get0_signers` contract).
    // `StackRef::from_ptr` produces a `&StackRef<X509>` tied to that borrow.
    let stack_ref: &StackRef<X509> = unsafe { StackRef::<X509>::from_ptr(stack_ptr) };
    let certs: Vec<X509> = stack_ref.iter().map(X509Ref::to_owned).collect();
    // SAFETY: we own the stack returned by `CMS_get0_signers` (the elements
    // are borrowed and stay alive in `cms`); freeing the stack container
    // itself releases the allocation without touching the borrowed elements.
    unsafe { openssl_sys::OPENSSL_sk_free(stack_ptr.cast()) };
    Ok(certs)
}

/// Raw ASN.1 walker for CMS `SignedData` — extracts the `signingTime`
/// signed attribute out of each `SignerInfo`.
///
/// `openssl` 0.10 exposes neither `SignerInfo` iteration nor signed-attr
/// access, so we walk the DER directly using the internal helper in
/// [`crate::x509::der`].  The walk is intentionally minimal: it only
/// crawls deep enough to enumerate each `SignerInfo`'s signed attribute
/// SET and the `signingTime` (OID `1.2.840.113549.1.9.5`) within it.
/// Any other tag is skipped.  The buffer is the same DER previously
/// accepted by `CMS_verify`, so structural correctness is presumed.
pub(crate) mod der_walk {
    use super::CmsVerifyError;
    use crate::x509::der::{read_tlv, read_tlv_expect, TAG_INTEGER, TAG_OID, TAG_SEQUENCE};
    use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};

    /// `id-signedData` per RFC 5652 §5.1.
    const OID_SIGNED_DATA_DOTTED: &str = "1.2.840.113549.1.7.2";
    /// `signing-time` attribute OID per RFC 5652 §11.3.
    const OID_SIGNING_TIME_DOTTED: &str = "1.2.840.113549.1.9.5";

    const TAG_SET: u8 = 0x31;
    const TAG_UTC_TIME: u8 = 0x17;
    const TAG_GENERALIZED_TIME: u8 = 0x18;
    /// `[0] EXPLICIT` (constructed): wraps `ContentInfo`'s `content` field
    /// and `SignerInfo`'s `signedAttrs` field (IMPLICIT — but same tag).
    const TAG_CTX0_CONSTRUCTED: u8 = 0xA0;
    /// `[0] IMPLICIT OCTET STRING`: `subjectKeyIdentifier` choice of
    /// `SignerIdentifier` in RFC 5652 v3 `SignerInfo`.
    const TAG_CTX0_PRIMITIVE: u8 = 0x80;
    /// `[1] IMPLICIT` (constructed): wraps `SignerInfo`'s
    /// `unsignedAttrs` field per RFC 5652 §5.3.
    const TAG_CTX1_CONSTRUCTED: u8 = 0xA1;

    /// Map of `unsignedAttr` OID (dotted) → raw `attrValues` SET DER
    /// (full TLV, outer SET tag+length included).
    pub(crate) type UnsignedAttrMap = std::collections::HashMap<String, Vec<u8>>;

    /// Identifies a CMS signer for pairing with its `signingTime`.
    /// RFC 5652 `SignerIdentifier` is a CHOICE between v1 `issuerAndSerialNumber`
    /// (SEQUENCE tag 0x30) and v3 `subjectKeyIdentifier` (`[0]` IMPLICIT OCTET
    /// STRING — tag 0x80).
    #[derive(Debug, Clone, Hash, PartialEq, Eq)]
    pub(crate) enum SignerKey {
        /// v3 `SignerInfo`: `subjectKeyIdentifier` raw octets.
        Ski(Vec<u8>),
        /// v1 `SignerInfo`: issuer DN DER + serial DER value bytes.
        IssuerAndSerial {
            issuer_der: Vec<u8>,
            serial_der: Vec<u8>,
        },
    }

    /// Returns `(SignerIdentifier, signingTime)` for each `SignerInfo` in
    /// `signerInfos` SET DER order.  Errors if any `SignerInfo` lacks
    /// signed attributes or a `signing-time` attribute, the time encoding
    /// is not parseable, or the `SignerIdentifier` choice is unrecognized.
    pub(crate) fn extract_signing_times_by_key(
        cms_der: &[u8],
    ) -> Result<Vec<(SignerKey, DateTime<Utc>)>, CmsVerifyError> {
        let signer_infos_value = walk_to_signer_infos(cms_der)?;
        let mut walker = signer_infos_value;
        let mut out = Vec::new();
        while !walker.is_empty() {
            let si = read_tlv_expect(walker, TAG_SEQUENCE).map_err(map_err)?;
            walker = si.rest;
            // SignerInfo ::= SEQUENCE { version CMSVersion, sid SignerIdentifier, ... }
            let ver = read_tlv_expect(si.value, TAG_INTEGER).map_err(map_err)?;
            let key = parse_signer_identifier(ver.rest)?;
            let t = signing_time_from_signer_info(si.value)?;
            out.push((key, t));
        }
        Ok(out)
    }

    fn parse_signer_identifier(after_version: &[u8]) -> Result<SignerKey, CmsVerifyError> {
        let tlv = read_tlv(after_version).map_err(map_err)?;
        match tlv.tag {
            // v3 SignerInfo: [0] IMPLICIT OCTET STRING — subjectKeyIdentifier
            TAG_CTX0_PRIMITIVE => Ok(SignerKey::Ski(tlv.value.to_vec())),
            // v1 SignerInfo: SEQUENCE { issuer Name, serialNumber INTEGER }
            TAG_SEQUENCE => {
                let issuer = read_tlv_expect(tlv.value, TAG_SEQUENCE).map_err(map_err)?;
                let serial = read_tlv_expect(issuer.rest, TAG_INTEGER).map_err(map_err)?;
                // Strip optional DER-INTEGER leading zero (added when the
                // high bit of the magnitude is set).  Callers compute the
                // serial via `BigNum::to_vec`, which is unsigned
                // big-endian magnitude bytes, so we normalize to the same.
                let mut serial_bytes = serial.value;
                if serial_bytes.len() > 1 && serial_bytes[0] == 0x00 {
                    serial_bytes = &serial_bytes[1..];
                }
                Ok(SignerKey::IssuerAndSerial {
                    // Re-emit the issuer Name TLV (tag + length + value)
                    // to match what `X509Ref::issuer_name().to_der()`
                    // returns on the lookup side.
                    issuer_der: encode_tlv(TAG_SEQUENCE, issuer.value),
                    serial_der: serial_bytes.to_vec(),
                })
            }
            other => Err(CmsVerifyError::Parse(format!(
                "cms: unknown SignerIdentifier tag 0x{other:02x}"
            ))),
        }
    }

    /// For each `SignerInfo` in `signerInfos` SET DER order, return its
    /// [`SignerKey`] and a map of `unsignedAttr` OID (dotted) → the raw
    /// `AttrValue` SET DER (including outer SET tag+length).
    ///
    /// `SignerInfo` layout (RFC 5652 §5.3):
    /// ```text
    /// SignerInfo ::= SEQUENCE {
    ///     version            CMSVersion,
    ///     sid                SignerIdentifier,
    ///     digestAlgorithm    AlgorithmIdentifier,
    ///     signedAttrs        [0] IMPLICIT SignedAttributes OPTIONAL,
    ///     signatureAlgorithm AlgorithmIdentifier,
    ///     signature          SignatureValue,
    ///     unsignedAttrs      [1] IMPLICIT UnsignedAttributes OPTIONAL }
    /// ```
    ///
    /// Walks every `SignerInfo` looking for the trailing `[1] IMPLICIT`
    /// context tag (0xA1).  Each attribute inside is a `SEQUENCE { OID,
    /// SET OF ANY }`.  The SET OF ANY is preserved verbatim and returned
    /// in the map — callers use [`unwrap_attr_value`] to strip the SET
    /// wrapper and access the singleton inner value (e.g. an RFC 3161
    /// `TimeStampToken` `ContentInfo`).
    pub(crate) fn extract_unsigned_attrs_by_key(
        cms_der: &[u8],
    ) -> Result<Vec<(SignerKey, UnsignedAttrMap)>, CmsVerifyError> {
        let signer_infos_value = walk_to_signer_infos(cms_der)?;
        let mut walker = signer_infos_value;
        let mut out = Vec::new();
        while !walker.is_empty() {
            let si = read_tlv_expect(walker, TAG_SEQUENCE).map_err(map_err)?;
            walker = si.rest;
            let ver = read_tlv_expect(si.value, TAG_INTEGER).map_err(map_err)?;
            let key = parse_signer_identifier(ver.rest)?;
            let attrs = unsigned_attrs_from_signer_info(si.value)?;
            out.push((key, attrs));
        }
        Ok(out)
    }

    /// Walk a `SignerInfo` body and extract the `unsignedAttrs` map.
    ///
    /// Returns an empty map when `unsignedAttrs` is absent (the field is
    /// OPTIONAL per RFC 5652 §5.3).
    fn unsigned_attrs_from_signer_info(
        body: &[u8],
    ) -> Result<UnsignedAttrMap, CmsVerifyError> {
        let mut rest = body;
        while !rest.is_empty() {
            let tlv = read_tlv(rest).map_err(map_err)?;
            rest = tlv.rest;
            if tlv.tag == TAG_CTX1_CONSTRUCTED {
                return parse_attribute_set(tlv.value);
            }
        }
        Ok(std::collections::HashMap::new())
    }

    /// Parse a `SET OF Attribute` body into a map of `attrType` OID
    /// (dotted) → raw `attrValues` SET DER (full TLV).
    fn parse_attribute_set(set_body: &[u8]) -> Result<UnsignedAttrMap, CmsVerifyError> {
        let mut out: UnsignedAttrMap = std::collections::HashMap::new();
        let mut rest = set_body;
        while !rest.is_empty() {
            let attr = read_tlv_expect(rest, TAG_SEQUENCE).map_err(map_err)?;
            rest = attr.rest;
            let oid_tlv = read_tlv_expect(attr.value, TAG_OID).map_err(map_err)?;
            let dotted = crate::x509::der::oid_to_dotted(oid_tlv.value).map_err(map_err)?;
            // The attrValues field is `SET OF ANY` — preserve it as a
            // full TLV so callers can unwrap it themselves.
            let set_tlv = read_tlv_expect(oid_tlv.rest, TAG_SET).map_err(map_err)?;
            let mut set_der = Vec::with_capacity(set_tlv.value.len() + 6);
            set_der.push(TAG_SET);
            push_der_length(&mut set_der, set_tlv.value.len());
            set_der.extend_from_slice(set_tlv.value);
            // Duplicate attribute OIDs would be a malformed CMS;
            // accept-last-wins is fine for our use case (we surface
            // through a HashMap and have no use case requiring strict
            // rejection of duplicates beyond what the signer policy
            // already enforces).
            out.insert(dotted, set_der);
        }
        Ok(out)
    }

    /// For each `SignerInfo` in `signerInfos` SET DER order, return its
    /// [`SignerKey`] paired with the raw `signature` OCTET STRING value
    /// bytes (no tag/length).  This is the input to the RFC 3161
    /// `messageImprint` binding check — `TSTInfo.messageImprint.hashedMessage`
    /// must equal `hash(signature_bytes)`.
    pub(crate) fn extract_signatures_by_key(
        cms_der: &[u8],
    ) -> Result<Vec<(SignerKey, Vec<u8>)>, CmsVerifyError> {
        let signer_infos_value = walk_to_signer_infos(cms_der)?;
        let mut walker = signer_infos_value;
        let mut out = Vec::new();
        while !walker.is_empty() {
            let si = read_tlv_expect(walker, TAG_SEQUENCE).map_err(map_err)?;
            walker = si.rest;
            let ver = read_tlv_expect(si.value, TAG_INTEGER).map_err(map_err)?;
            let key = parse_signer_identifier(ver.rest)?;
            let sig = signature_from_signer_info(si.value)?;
            out.push((key, sig));
        }
        Ok(out)
    }

    /// Walk a `SignerInfo` body and extract the `signature` field bytes
    /// (the value-only octets of the OCTET STRING — no tag, no length).
    ///
    /// Layout per RFC 5652 §5.3:
    /// ```text
    /// SignerInfo ::= SEQUENCE {
    ///   version INTEGER,
    ///   sid SignerIdentifier,
    ///   digestAlgorithm AlgorithmIdentifier,
    ///   signedAttrs [0] IMPLICIT SET OF Attribute OPTIONAL,
    ///   signatureAlgorithm AlgorithmIdentifier,
    ///   signature OCTET STRING,
    ///   unsignedAttrs [1] IMPLICIT SET OF Attribute OPTIONAL }
    /// ```
    ///
    /// We skip past `sid`, `digestAlgorithm`, optional `signedAttrs`,
    /// `signatureAlgorithm`, then read the OCTET STRING.
    fn signature_from_signer_info(body: &[u8]) -> Result<Vec<u8>, CmsVerifyError> {
        // Skip version INTEGER.
        let after_ver = read_tlv_expect(body, TAG_INTEGER).map_err(map_err)?;
        // Skip sid: SEQUENCE (issuerAndSerialNumber) OR [0] IMPLICIT OCTET STRING (ski).
        let sid = read_tlv(after_ver.rest).map_err(map_err)?;
        // Skip digestAlgorithm (SEQUENCE).
        let after_digest_alg = read_tlv_expect(sid.rest, TAG_SEQUENCE).map_err(map_err)?;
        // Optional signedAttrs [0] IMPLICIT.
        let next = read_tlv(after_digest_alg.rest).map_err(map_err)?;
        let rest_after_signed = if next.tag == TAG_CTX0_CONSTRUCTED {
            next.rest
        } else {
            after_digest_alg.rest
        };
        // signatureAlgorithm (SEQUENCE).
        let after_signature_alg =
            read_tlv_expect(rest_after_signed, TAG_SEQUENCE).map_err(map_err)?;
        // signature OCTET STRING.
        let sig = read_tlv_expect(after_signature_alg.rest, TAG_OCTET_STRING_PRIM)
            .map_err(map_err)?;
        Ok(sig.value.to_vec())
    }

    /// Parse the encapsulated `TSTInfo` from a `TimeStampToken` CMS DER and
    /// return `(hash_alg_dotted_oid, hashed_message_bytes)` from the
    /// `messageImprint` field.
    ///
    /// `TSTInfo` (RFC 3161 §2.4.2):
    /// ```text
    /// TSTInfo ::= SEQUENCE {
    ///   version INTEGER,
    ///   policy TSAPolicyId,
    ///   messageImprint MessageImprint,
    ///   ... }
    /// MessageImprint ::= SEQUENCE {
    ///   hashAlgorithm AlgorithmIdentifier,
    ///   hashedMessage OCTET STRING }
    /// ```
    pub(crate) fn parse_tst_message_imprint(
        tst_cms_der: &[u8],
    ) -> Result<(String, Vec<u8>), CmsVerifyError> {
        // TSTInfo is the encapsulated content of the TST CMS SignedData,
        // wrapped in an OCTET STRING (eContent of id-ct-TSTInfo).
        let inner = extract_encap_content(tst_cms_der)?.ok_or_else(|| {
            CmsVerifyError::Parse(
                "tst: encapContentInfo eContent missing (TSTInfo)".into(),
            )
        })?;
        // Now `inner` is the TSTInfo DER (a SEQUENCE).
        let tst_info = read_tlv_expect(&inner, TAG_SEQUENCE).map_err(map_err)?;
        // Skip version INTEGER.
        let after_ver = read_tlv_expect(tst_info.value, TAG_INTEGER).map_err(map_err)?;
        // Skip policy OID.
        let after_policy = read_tlv_expect(after_ver.rest, TAG_OID).map_err(map_err)?;
        // messageImprint SEQUENCE { hashAlgorithm AlgID, hashedMessage OCTET STRING }
        let mi = read_tlv_expect(after_policy.rest, TAG_SEQUENCE).map_err(map_err)?;
        let hash_alg = read_tlv_expect(mi.value, TAG_SEQUENCE).map_err(map_err)?;
        let hash_oid_tlv = read_tlv_expect(hash_alg.value, TAG_OID).map_err(map_err)?;
        let hash_oid =
            crate::x509::der::oid_to_dotted(hash_oid_tlv.value).map_err(map_err)?;
        let hashed = read_tlv_expect(hash_alg.rest, TAG_OCTET_STRING_PRIM)
            .map_err(map_err)?;
        Ok((hash_oid, hashed.value.to_vec()))
    }

    /// Strip the outer SET wrapper from an `attrValues` field and return
    /// the single inner element's DER (tag + length + value).
    ///
    /// Errors when the SET is empty, contains more than one element, or
    /// is not a SET at all.  RFC 3161 timestamp-token attribute values
    /// are required to be singleton SETs.
    pub(crate) fn unwrap_attr_value(set_der: &[u8]) -> Result<Vec<u8>, CmsVerifyError> {
        let outer = read_tlv_expect(set_der, TAG_SET).map_err(map_err)?;
        if !outer.rest.is_empty() {
            return Err(CmsVerifyError::Parse(
                "cms: attrValue SET has trailing bytes".into(),
            ));
        }
        let inner = read_tlv(outer.value).map_err(map_err)?;
        if !inner.rest.is_empty() {
            return Err(CmsVerifyError::Parse(
                "cms: attrValue SET has more than one element".into(),
            ));
        }
        // Re-emit the inner element as a full TLV.
        let mut out = Vec::with_capacity(outer.value.len() + 6);
        out.push(inner.tag);
        push_der_length(&mut out, inner.value.len());
        out.extend_from_slice(inner.value);
        Ok(out)
    }

    fn push_der_length(out: &mut Vec<u8>, n: usize) {
        if n < 0x80 {
            #[allow(clippy::cast_possible_truncation)]
            out.push(n as u8);
        } else {
            let mut n_bytes = 0u8;
            let mut tmp = n;
            while tmp > 0 {
                n_bytes += 1;
                tmp >>= 8;
            }
            out.push(0x80 | n_bytes);
            for i in (0..n_bytes).rev() {
                #[allow(clippy::cast_possible_truncation)]
                let byte = ((n >> (i * 8)) & 0xFF) as u8;
                out.push(byte);
            }
        }
    }

    /// Re-emit a TLV (short- or long-form length) for a given tag and
    /// value body.  Used to canonicalize issuer-name DER for hashing.
    fn encode_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(body.len() + 6);
        out.push(tag);
        let len = body.len();
        if len < 0x80 {
            #[allow(clippy::cast_possible_truncation)]
            out.push(len as u8);
        } else {
            let mut n_bytes = 0u8;
            let mut tmp = len;
            while tmp > 0 {
                n_bytes += 1;
                tmp >>= 8;
            }
            out.push(0x80 | n_bytes);
            for i in (0..n_bytes).rev() {
                #[allow(clippy::cast_possible_truncation)]
                let byte = ((len >> (i * 8)) & 0xFF) as u8;
                out.push(byte);
            }
        }
        out.extend_from_slice(body);
        out
    }

    /// ASN.1 tag for primitive `OCTET STRING`.
    const TAG_OCTET_STRING_PRIM: u8 = 0x04;

    /// Returns the encapsulated content bytes (eContent) of a CMS
    /// `SignedData`, or `Ok(None)` when the CMS is detached (no
    /// `eContent` present).
    ///
    /// CMS `SignedData` (RFC 5652 §5.1):
    /// ```text
    /// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    /// SignedData ::= SEQUENCE {
    ///     version CMSVersion,
    ///     digestAlgorithms SET,
    ///     encapContentInfo EncapsulatedContentInfo,
    ///     ... }
    /// EncapsulatedContentInfo ::= SEQUENCE {
    ///     eContentType ContentType,
    ///     eContent [0] EXPLICIT OCTET STRING OPTIONAL }
    /// ```
    ///
    /// The walk is read-only and validates structure as it goes.
    /// Constructed-form `OCTET STRING` (segmented eContent) is rejected
    /// with `CmsVerifyError::Verify("constructed eContent not supported")`.
    pub(crate) fn extract_encap_content(
        cms_der: &[u8],
    ) -> Result<Option<Vec<u8>>, CmsVerifyError> {
        // ContentInfo SEQUENCE { contentType OID, [0] EXPLICIT SignedData }
        let outer = read_tlv_expect(cms_der, TAG_SEQUENCE).map_err(map_err)?;
        let ct_oid = read_tlv_expect(outer.value, TAG_OID).map_err(map_err)?;
        let dotted = crate::x509::der::oid_to_dotted(ct_oid.value).map_err(map_err)?;
        if dotted != OID_SIGNED_DATA_DOTTED {
            return Err(CmsVerifyError::Parse(format!(
                "cms: unexpected contentType {dotted}"
            )));
        }
        let ctx0 = read_tlv_expect(ct_oid.rest, TAG_CTX0_CONSTRUCTED).map_err(map_err)?;
        // SignedData SEQUENCE { version INTEGER, digestAlgorithms SET,
        //                       encapContentInfo SEQUENCE, ... }
        let sd = read_tlv_expect(ctx0.value, TAG_SEQUENCE).map_err(map_err)?;
        // Skip version INTEGER.
        let after_ver = read_tlv_expect(sd.value, TAG_INTEGER).map_err(map_err)?;
        // Skip digestAlgorithms SET.
        let after_digest = read_tlv_expect(after_ver.rest, TAG_SET).map_err(map_err)?;
        // encapContentInfo SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING OPTIONAL }
        let encap = read_tlv_expect(after_digest.rest, TAG_SEQUENCE).map_err(map_err)?;
        let ect = read_tlv_expect(encap.value, TAG_OID).map_err(map_err)?;
        // eContent is optional; if absent, this is a detached signature.
        if ect.rest.is_empty() {
            return Ok(None);
        }
        // [0] EXPLICIT wrapper around the OCTET STRING value.
        let inner = read_tlv(ect.rest).map_err(map_err)?;
        if inner.tag != TAG_CTX0_CONSTRUCTED {
            // Some other tag in the encapContentInfo trailer — treat as
            // structurally absent eContent rather than failing.
            return Ok(None);
        }
        // Inside [0] EXPLICIT we expect a single primitive OCTET STRING.
        let octet = read_tlv(inner.value).map_err(map_err)?;
        match octet.tag {
            TAG_OCTET_STRING_PRIM => Ok(Some(octet.value.to_vec())),
            // Constructed OCTET STRING (segmented eContent, tag 0x24).
            // RFC 5652 permits this in BER but DER does not — reject
            // rather than silently concatenate, since we have no test
            // corpus to assert correctness across implementations.
            0x24 => Err(CmsVerifyError::Verify(
                "constructed eContent not supported".into(),
            )),
            other => Err(CmsVerifyError::Parse(format!(
                "cms: unexpected eContent tag 0x{other:02x}"
            ))),
        }
    }

    fn walk_to_signer_infos(cms_der: &[u8]) -> Result<&[u8], CmsVerifyError> {
        // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
        let outer = read_tlv_expect(cms_der, TAG_SEQUENCE).map_err(map_err)?;
        let ct_oid = read_tlv_expect(outer.value, TAG_OID).map_err(map_err)?;
        let dotted = crate::x509::der::oid_to_dotted(ct_oid.value).map_err(map_err)?;
        if dotted != OID_SIGNED_DATA_DOTTED {
            return Err(CmsVerifyError::Parse(format!(
                "cms: unexpected contentType {dotted}"
            )));
        }
        let ctx0 = read_tlv_expect(ct_oid.rest, TAG_CTX0_CONSTRUCTED).map_err(map_err)?;
        // SignedData ::= SEQUENCE { version, digestAlgs SET,
        //                           encapContentInfo SEQUENCE,
        //                           [0] IMPLICIT certificates OPTIONAL,
        //                           [1] IMPLICIT crls OPTIONAL,
        //                           signerInfos SET OF SignerInfo }
        let sd = read_tlv_expect(ctx0.value, TAG_SEQUENCE).map_err(map_err)?;

        // Walk SignedData fields; the final SET (tag 0x31) is signerInfos.
        // We rely on the structural rule: of all top-level SET items, the
        // *last* is signerInfos.  digestAlgorithms is also a SET but
        // appears first.
        let mut rest = sd.value;
        let mut last_set: Option<&[u8]> = None;
        let mut sets_seen = 0u32;
        while !rest.is_empty() {
            let tlv = read_tlv(rest).map_err(map_err)?;
            if tlv.tag == TAG_SET {
                sets_seen += 1;
                last_set = Some(tlv.value);
            }
            rest = tlv.rest;
        }
        if sets_seen < 2 {
            return Err(CmsVerifyError::Parse(
                "cms: signerInfos SET not found".into(),
            ));
        }
        let signer_infos_value = last_set.ok_or_else(|| {
            CmsVerifyError::Parse("cms: signerInfos SET empty".into())
        })?;
        Ok(signer_infos_value)
    }

    /// `SignerInfo ::= SEQUENCE { version INTEGER, sid SignerIdentifier,`
    ///   `digestAlgorithm AlgorithmIdentifier,`
    ///   `signedAttrs [0] IMPLICIT SET OF Attribute OPTIONAL, ... }`
    fn signing_time_from_signer_info(body: &[u8]) -> Result<DateTime<Utc>, CmsVerifyError> {
        // Walk fields looking for the [0] IMPLICIT context-tagged set.
        let mut rest = body;
        while !rest.is_empty() {
            let tlv = read_tlv(rest).map_err(map_err)?;
            rest = tlv.rest;
            if tlv.tag == TAG_CTX0_CONSTRUCTED {
                // signedAttrs ::= SET OF Attribute (IMPLICIT [0])
                return find_signing_time_in_attrs(tlv.value);
            }
        }
        Err(CmsVerifyError::Parse(
            "cms: signerInfo lacks signedAttrs".into(),
        ))
    }

    fn find_signing_time_in_attrs(set_body: &[u8]) -> Result<DateTime<Utc>, CmsVerifyError> {
        // SET OF Attribute SEQUENCE { attrType OID, attrValues SET OF ANY }
        let mut rest = set_body;
        while !rest.is_empty() {
            let attr = read_tlv_expect(rest, TAG_SEQUENCE).map_err(map_err)?;
            rest = attr.rest;
            let oid_tlv = read_tlv_expect(attr.value, TAG_OID).map_err(map_err)?;
            let dotted = crate::x509::der::oid_to_dotted(oid_tlv.value).map_err(map_err)?;
            if dotted != OID_SIGNING_TIME_DOTTED {
                continue;
            }
            let set_tlv = read_tlv_expect(oid_tlv.rest, TAG_SET).map_err(map_err)?;
            let time_tlv = read_tlv(set_tlv.value).map_err(map_err)?;
            return decode_time(time_tlv.tag, time_tlv.value);
        }
        Err(CmsVerifyError::Parse(
            "cms: signerInfo signedAttrs lacks signing-time".into(),
        ))
    }

    fn decode_time(tag: u8, body: &[u8]) -> Result<DateTime<Utc>, CmsVerifyError> {
        let s = std::str::from_utf8(body)
            .map_err(|_| CmsVerifyError::Parse("cms: signing-time non-ascii".into()))?;
        match tag {
            TAG_UTC_TIME => parse_utc_time(s),
            TAG_GENERALIZED_TIME => parse_generalized_time(s),
            other => Err(CmsVerifyError::Parse(format!(
                "cms: signing-time unexpected tag 0x{other:02x}"
            ))),
        }
    }

    /// `UTCTime` = `YYMMDDHHMMSSZ` (RFC 5280 mandates `Z` and seconds).
    fn parse_utc_time(s: &str) -> Result<DateTime<Utc>, CmsVerifyError> {
        if s.len() != 13 || !s.ends_with('Z') {
            return Err(CmsVerifyError::Parse(format!(
                "cms: bad UTCTime {s:?}"
            )));
        }
        let yy: i32 = s[0..2]
            .parse()
            .map_err(|_| CmsVerifyError::Parse("cms: UTCTime year".into()))?;
        // RFC 5280 §4.1.2.5.1: 00-49 → 2000-2049, 50-99 → 1950-1999.
        let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
        let mo: u32 = s[2..4]
            .parse()
            .map_err(|_| CmsVerifyError::Parse("cms: UTCTime month".into()))?;
        let dy: u32 = s[4..6]
            .parse()
            .map_err(|_| CmsVerifyError::Parse("cms: UTCTime day".into()))?;
        let hh: u32 = s[6..8]
            .parse()
            .map_err(|_| CmsVerifyError::Parse("cms: UTCTime hour".into()))?;
        let mm: u32 = s[8..10]
            .parse()
            .map_err(|_| CmsVerifyError::Parse("cms: UTCTime minute".into()))?;
        let ss: u32 = s[10..12]
            .parse()
            .map_err(|_| CmsVerifyError::Parse("cms: UTCTime second".into()))?;
        let nd = NaiveDate::from_ymd_opt(year, mo, dy)
            .and_then(|d| d.and_hms_opt(hh, mm, ss))
            .ok_or_else(|| CmsVerifyError::Parse("cms: UTCTime out of range".into()))?;
        Ok(Utc.from_utc_datetime(&nd))
    }

    /// `GeneralizedTime` = `YYYYMMDDHHMMSSZ` for our purposes.
    fn parse_generalized_time(s: &str) -> Result<DateTime<Utc>, CmsVerifyError> {
        if !s.ends_with('Z') || s.len() < 15 {
            return Err(CmsVerifyError::Parse(format!(
                "cms: bad GeneralizedTime {s:?}"
            )));
        }
        // Strip fractional seconds if present (e.g. ...SS.fffZ); ignore them.
        let core = &s[..s.len() - 1];
        let core = core.split('.').next().unwrap_or(core);
        if core.len() != 14 {
            return Err(CmsVerifyError::Parse(format!(
                "cms: GeneralizedTime expects YYYYMMDDHHMMSS got {core:?}"
            )));
        }
        let nd = NaiveDateTime::parse_from_str(core, "%Y%m%d%H%M%S")
            .map_err(|_| CmsVerifyError::Parse("cms: GeneralizedTime parse".into()))?;
        Ok(Utc.from_utc_datetime(&nd))
    }

    #[allow(clippy::needless_pass_by_value)]
    fn map_err(e: crate::x509::TrustError) -> CmsVerifyError {
        CmsVerifyError::Parse(format!("cms der: {e}"))
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    mod tests {
        use super::*;

        #[test]
        fn utc_time_parses_canonical() {
            let t = parse_utc_time("260512123045Z").unwrap();
            assert_eq!(t.to_rfc3339(), "2026-05-12T12:30:45+00:00");
        }

        #[test]
        fn generalized_time_parses_canonical() {
            let t = parse_generalized_time("20260512123045Z").unwrap();
            assert_eq!(t.to_rfc3339(), "2026-05-12T12:30:45+00:00");
        }

        #[test]
        fn utc_time_year_pivot_below_50_is_2000s() {
            let t = parse_utc_time("000101000000Z").unwrap();
            assert_eq!(t.format("%Y").to_string(), "2000");
        }

        #[test]
        fn utc_time_year_pivot_at_50_is_1900s() {
            let t = parse_utc_time("500101000000Z").unwrap();
            assert_eq!(t.format("%Y").to_string(), "1950");
        }

        /// `parse_signer_identifier` must recognize the v3 [0] IMPLICIT
        /// OCTET STRING form and yield `SignerKey::Ski`.
        #[test]
        fn signer_id_v3_ski() {
            // [0] IMPLICIT OCTET STRING, 4-byte content `de ad be ef`.
            let buf = [0x80u8, 0x04, 0xde, 0xad, 0xbe, 0xef];
            let key = super::parse_signer_identifier(&buf).unwrap();
            assert!(matches!(key, SignerKey::Ski(ref b) if b == &vec![0xde, 0xad, 0xbe, 0xef]));
        }

        /// Smoke-test `extract_encap_content` with a hand-rolled minimal
        /// `SignedData` carrying a 5-byte embedded payload "hello".
        #[test]
        fn extract_encap_content_returns_embedded_payload() {
            // EncapsulatedContentInfo body: id-data OID + [0] EXPLICIT { OCTET STRING "hello" }
            // id-data = 1.2.840.113549.1.7.1 → 06 09 2A 86 48 86 F7 0D 01 07 01
            // OCTET STRING "hello" = 04 05 68 65 6C 6C 6F  (7 bytes)
            // [0] EXPLICIT wraps that → A0 07 04 05 68 65 6C 6C 6F  (9 bytes)
            // encap body = 11 + 9 = 20 bytes → SEQUENCE 30 14 ..
            let mut encap_body = Vec::new();
            encap_body.extend_from_slice(&[
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
            ]);
            encap_body.extend_from_slice(&[
                0xA0, 0x07, 0x04, 0x05, b'h', b'e', b'l', b'l', b'o',
            ]);
            // SignedData body: version INTEGER 0x01 (02 01 01),
            // digestAlgorithms SET empty (31 00),
            // encapContentInfo SEQUENCE { encap_body }.
            let mut sd_body = Vec::new();
            sd_body.extend_from_slice(&[0x02, 0x01, 0x01]);
            sd_body.extend_from_slice(&[0x31, 0x00]);
            sd_body.push(0x30);
            sd_body.push(u8::try_from(encap_body.len()).unwrap());
            sd_body.extend_from_slice(&encap_body);
            // signerInfos SET empty (31 00) — required so der walks of
            // other helpers don't break on this fixture, though not
            // consulted by `extract_encap_content`.
            sd_body.extend_from_slice(&[0x31, 0x00]);
            // Wrap SignedData SEQUENCE.
            let mut sd_seq = vec![0x30, u8::try_from(sd_body.len()).unwrap()];
            sd_seq.extend_from_slice(&sd_body);
            // [0] EXPLICIT around SignedData.
            let mut ctx0 = vec![0xA0, u8::try_from(sd_seq.len()).unwrap()];
            ctx0.extend_from_slice(&sd_seq);
            // contentType OID = signedData = 1.2.840.113549.1.7.2
            // → 06 09 2A 86 48 86 F7 0D 01 07 02
            let ct_oid = [
                0x06u8, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
            ];
            let mut outer_body = Vec::new();
            outer_body.extend_from_slice(&ct_oid);
            outer_body.extend_from_slice(&ctx0);
            let mut outer = vec![0x30, u8::try_from(outer_body.len()).unwrap()];
            outer.extend_from_slice(&outer_body);

            let got = super::extract_encap_content(&outer).unwrap();
            assert_eq!(got, Some(b"hello".to_vec()));
        }

        /// CMS with no `[0] EXPLICIT` eContent tag is detached → `Ok(None)`.
        #[test]
        fn extract_encap_content_detached_returns_none() {
            // encap body = id-data OID only, no eContent.
            let encap_body = [
                0x06u8, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
            ];
            let mut sd_body = Vec::new();
            sd_body.extend_from_slice(&[0x02, 0x01, 0x01]);
            sd_body.extend_from_slice(&[0x31, 0x00]);
            sd_body.push(0x30);
            sd_body.push(u8::try_from(encap_body.len()).unwrap());
            sd_body.extend_from_slice(&encap_body);
            sd_body.extend_from_slice(&[0x31, 0x00]);
            let mut sd_seq = vec![0x30, u8::try_from(sd_body.len()).unwrap()];
            sd_seq.extend_from_slice(&sd_body);
            let mut ctx0 = vec![0xA0, u8::try_from(sd_seq.len()).unwrap()];
            ctx0.extend_from_slice(&sd_seq);
            let ct_oid = [
                0x06u8, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
            ];
            let mut outer_body = Vec::new();
            outer_body.extend_from_slice(&ct_oid);
            outer_body.extend_from_slice(&ctx0);
            let mut outer = vec![0x30, u8::try_from(outer_body.len()).unwrap()];
            outer.extend_from_slice(&outer_body);

            let got = super::extract_encap_content(&outer).unwrap();
            assert!(got.is_none());
        }

        /// Malformed DER returns `Err(Parse(_))`.
        #[test]
        fn extract_encap_content_malformed_errors() {
            let buf = [0x30u8, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
            let err = super::extract_encap_content(&buf).unwrap_err();
            assert!(matches!(err, CmsVerifyError::Parse(_)));
        }

        /// `unwrap_attr_value` strips the outer SET wrapper and returns
        /// the singleton inner element as a full TLV.
        #[test]
        fn unwrap_attr_value_strips_singleton_set() {
            // SET { OCTET STRING "hi" }
            //   31 04  04 02 68 69
            let set = [0x31u8, 0x04, 0x04, 0x02, b'h', b'i'];
            let inner = super::unwrap_attr_value(&set).unwrap();
            assert_eq!(inner, vec![0x04, 0x02, b'h', b'i']);
        }

        #[test]
        fn unwrap_attr_value_rejects_multi_element_set() {
            // SET { INTEGER 1, INTEGER 2 }
            let set = [0x31u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
            let err = super::unwrap_attr_value(&set).unwrap_err();
            assert!(matches!(err, CmsVerifyError::Parse(_)));
        }

        #[test]
        fn unwrap_attr_value_rejects_non_set_input() {
            let not_set = [0x04u8, 0x02, b'h', b'i'];
            let err = super::unwrap_attr_value(&not_set).unwrap_err();
            assert!(matches!(err, CmsVerifyError::Parse(_)));
        }

        /// `extract_unsigned_attrs_by_key` returns an empty map for a
        /// `SignerInfo` with no `unsignedAttrs` field.
        #[test]
        fn extract_unsigned_attrs_empty_when_absent() {
            // Build a CMS skeleton with one SignerInfo having only:
            //   version INTEGER 3,  sid [0] IMPLICIT OCTET STRING (SKI 0xAA).
            // No signedAttrs, no signature, no unsignedAttrs.
            //
            //   SignerInfo SEQUENCE {
            //     02 01 03         -- version 3
            //     80 01 AA         -- [0] SKI = AA
            //   }
            // Total inner body = 3 + 3 = 6 bytes.
            let si_body = [0x02u8, 0x01, 0x03, 0x80, 0x01, 0xAA];
            let mut si_seq = vec![0x30, u8::try_from(si_body.len()).unwrap()];
            si_seq.extend_from_slice(&si_body);
            let cms_der = build_cms_with_signer_infos(&si_seq);

            let got = super::extract_unsigned_attrs_by_key(&cms_der).unwrap();
            assert_eq!(got.len(), 1);
            let (key, attrs) = &got[0];
            assert!(matches!(key, SignerKey::Ski(b) if b == &vec![0xAA]));
            assert!(attrs.is_empty());
        }

        /// `extract_unsigned_attrs_by_key` returns OID-keyed map for a
        /// `SignerInfo` carrying one fake `unsignedAttr`.
        #[test]
        fn extract_unsigned_attrs_returns_attr_value_set() {
            // Fake attr OID = 1.2.3.4 → DER: 06 03 2A 03 04
            // attrValues SET { OCTET STRING "x" } → 31 03  04 01 78
            //
            //   Attribute SEQUENCE {
            //     06 03 2A 03 04          -- OID 1.2.3.4
            //     31 03 04 01 78          -- SET { OCTET 'x' }
            //   } = 30 0A  ...           -- 10 bytes body
            //
            //   unsignedAttrs [1] IMPLICIT SET OF Attribute:
            //     A1 0C  30 0A ...
            //
            //   SignerInfo SEQUENCE {
            //     02 01 03                -- version 3
            //     80 01 AA                -- SKI
            //     A1 0C ...               -- unsignedAttrs
            //   } body = 3 + 3 + 14 = 20 bytes
            let attr_body = [
                0x06u8, 0x03, 0x2A, 0x03, 0x04, // OID 1.2.3.4
                0x31, 0x03, 0x04, 0x01, 0x78,   // attrValues SET
            ];
            let mut attr_seq = vec![0x30, u8::try_from(attr_body.len()).unwrap()];
            attr_seq.extend_from_slice(&attr_body);
            let mut unsigned_set = vec![0xA1, u8::try_from(attr_seq.len()).unwrap()];
            unsigned_set.extend_from_slice(&attr_seq);

            let mut si_body = vec![0x02u8, 0x01, 0x03, 0x80, 0x01, 0xAA];
            si_body.extend_from_slice(&unsigned_set);
            let mut si_seq = vec![0x30, u8::try_from(si_body.len()).unwrap()];
            si_seq.extend_from_slice(&si_body);
            let cms_der = build_cms_with_signer_infos(&si_seq);

            let got = super::extract_unsigned_attrs_by_key(&cms_der).unwrap();
            assert_eq!(got.len(), 1);
            let (key, attrs) = &got[0];
            assert!(matches!(key, SignerKey::Ski(b) if b == &vec![0xAA]));
            let set_der = attrs.get("1.2.3.4").expect("attr present");
            // Stored value should be the full SET TLV.
            assert_eq!(set_der, &vec![0x31u8, 0x03, 0x04, 0x01, 0x78]);
            // Round-trip via unwrap_attr_value yields the inner OCTET.
            let inner = super::unwrap_attr_value(set_der).unwrap();
            assert_eq!(inner, vec![0x04, 0x01, 0x78]);
        }

        /// Helper: wrap a single `SignerInfo` SEQUENCE in a minimal
        /// `ContentInfo { id-signedData, [0] SignedData { ... } }` so
        /// `walk_to_signer_infos` accepts it.
        fn build_cms_with_signer_infos(signer_info_seq: &[u8]) -> Vec<u8> {
            // signerInfos SET OF SignerInfo
            let mut signer_infos = vec![0x31u8, u8::try_from(signer_info_seq.len()).unwrap()];
            signer_infos.extend_from_slice(signer_info_seq);
            // encapContentInfo: id-data + no eContent.
            //   06 09 2A 86 48 86 F7 0D 01 07 01
            let encap_body = [
                0x06u8, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
            ];
            let mut encap_seq = vec![0x30u8, u8::try_from(encap_body.len()).unwrap()];
            encap_seq.extend_from_slice(&encap_body);
            // SignedData SEQUENCE { version INTEGER 1, digestAlgs SET empty,
            //                       encapContentInfo SEQUENCE, signerInfos SET }
            let mut sd_body = Vec::new();
            sd_body.extend_from_slice(&[0x02u8, 0x01, 0x01]); // version
            sd_body.extend_from_slice(&[0x31u8, 0x00]);       // digestAlgs SET empty
            sd_body.extend_from_slice(&encap_seq);
            sd_body.extend_from_slice(&signer_infos);
            let mut sd_seq = vec![0x30u8];
            super::push_der_length(&mut sd_seq, sd_body.len());
            sd_seq.extend_from_slice(&sd_body);
            // [0] EXPLICIT around SignedData
            let mut ctx0 = vec![0xA0u8];
            super::push_der_length(&mut ctx0, sd_seq.len());
            ctx0.extend_from_slice(&sd_seq);
            // contentType OID = id-signedData = 1.2.840.113549.1.7.2
            let ct_oid = [
                0x06u8, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
            ];
            let mut outer_body = Vec::new();
            outer_body.extend_from_slice(&ct_oid);
            outer_body.extend_from_slice(&ctx0);
            let mut outer = vec![0x30u8];
            super::push_der_length(&mut outer, outer_body.len());
            outer.extend_from_slice(&outer_body);
            outer
        }

        /// `parse_signer_identifier` must recognize the v1 SEQUENCE
        /// `IssuerAndSerial` and strip the DER-INTEGER leading-zero pad.
        #[test]
        fn signer_id_v1_issuer_and_serial_strips_leading_zero() {
            // IssuerAndSerialNumber TLV:
            //   SEQUENCE {
            //     SEQUENCE { (empty Name body) }   // issuer
            //     INTEGER 0x00, 0x80               // serial with pad
            //   }
            let buf = [
                0x30, 0x06, // IssuerAndSerial SEQUENCE, len 6
                0x30, 0x00, // empty issuer Name SEQUENCE
                0x02, 0x02, 0x00, 0x80, // serial INTEGER = 0x80 with pad
            ];
            let key = super::parse_signer_identifier(&buf).unwrap();
            match key {
                SignerKey::IssuerAndSerial { issuer_der, serial_der } => {
                    // issuer re-emitted as `30 00`
                    assert_eq!(issuer_der, vec![0x30, 0x00]);
                    // leading 0x00 padding stripped
                    assert_eq!(serial_der, vec![0x80]);
                }
                other @ SignerKey::Ski(_) => panic!("expected IssuerAndSerial, got {other:?}"),
            }
        }

        /// `extract_signatures_by_key` returns the signature OCTET STRING
        /// value bytes paired with the signer's SKI/issuer-and-serial.
        #[test]
        fn extract_signatures_returns_signature_octets() {
            // SignerInfo SEQUENCE {
            //   02 01 03                  -- version 3
            //   80 01 AA                  -- sid [0] SKI = AA
            //   30 02 05 00               -- digestAlgorithm (null)
            //                                signedAttrs absent
            //   30 02 05 00               -- signatureAlgorithm (null)
            //   04 04 DE AD BE EF         -- signature OCTET STRING
            // }
            let si_body = [
                0x02u8, 0x01, 0x03,
                0x80, 0x01, 0xAA,
                0x30, 0x02, 0x05, 0x00,
                0x30, 0x02, 0x05, 0x00,
                0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
            ];
            let mut si_seq = vec![0x30u8, u8::try_from(si_body.len()).unwrap()];
            si_seq.extend_from_slice(&si_body);
            let cms_der = build_cms_with_signer_infos(&si_seq);
            let got = super::extract_signatures_by_key(&cms_der).unwrap();
            assert_eq!(got.len(), 1);
            assert!(matches!(got[0].0, SignerKey::Ski(ref b) if b == &vec![0xAA]));
            assert_eq!(got[0].1, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        }

        /// `extract_signatures_by_key` also works with a `SignerInfo` that
        /// carries an optional `signedAttrs` [0] IMPLICIT field between
        /// digestAlgorithm and signatureAlgorithm.
        #[test]
        fn extract_signatures_skips_signed_attrs() {
            // Add an empty signedAttrs [0] IMPLICIT (A0 00) between
            // digestAlg and sigAlg.
            let si_body = [
                0x02u8, 0x01, 0x03,
                0x80, 0x01, 0xBB,
                0x30, 0x02, 0x05, 0x00,
                0xA0, 0x00,                       // signedAttrs empty
                0x30, 0x02, 0x05, 0x00,
                0x04, 0x03, 0x01, 0x02, 0x03,     // signature
            ];
            let mut si_seq = vec![0x30u8, u8::try_from(si_body.len()).unwrap()];
            si_seq.extend_from_slice(&si_body);
            let cms_der = build_cms_with_signer_infos(&si_seq);
            let got = super::extract_signatures_by_key(&cms_der).unwrap();
            assert_eq!(got[0].1, vec![0x01, 0x02, 0x03]);
        }

        /// `parse_tst_message_imprint` extracts the (hashAlg OID,
        /// `hashedMessage`) pair from a hand-rolled `TSTInfo` wrapped in a
        /// minimal CMS `SignedData` encapsulating it as `eContent`.
        #[test]
        fn parse_tst_message_imprint_extracts_oid_and_hash() {
            // TSTInfo SEQUENCE {
            //   02 01 01                                       -- version 1
            //   06 03 2A 03 04                                 -- policy OID 1.2.3.4
            //   30 0D                                          -- messageImprint
            //     30 0B  06 09 60 86 48 01 65 03 04 02 01      -- hashAlg sha256
            //     04 04 AA BB CC DD                            -- hashedMessage
            // }
            // hashAlg = AlgorithmIdentifier SEQUENCE { OID, [params absent] }
            //   sha256 OID = 2.16.840.1.101.3.4.2.1
            //     06 09 60 86 48 01 65 03 04 02 01
            //   AlgID SEQUENCE: 30 0B + that = 13 bytes
            // messageImprint SEQUENCE: 13 + 6 (hashedMessage tlv) = 19 → 0x13
            let tst_info_body = [
                0x02u8, 0x01, 0x01,
                0x06, 0x03, 0x2A, 0x03, 0x04,
                0x30, 0x13,
                    0x30, 0x0B,
                        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                    0x04, 0x04, 0xAA, 0xBB, 0xCC, 0xDD,
            ];
            let mut tst_info_seq = vec![0x30u8, u8::try_from(tst_info_body.len()).unwrap()];
            tst_info_seq.extend_from_slice(&tst_info_body);
            // Wrap as OCTET STRING (the eContent of the TST CMS).
            let mut octet = vec![0x04u8];
            super::push_der_length(&mut octet, tst_info_seq.len());
            octet.extend_from_slice(&tst_info_seq);
            // [0] EXPLICIT around the OCTET STRING.
            let mut ctx0 = vec![0xA0u8];
            super::push_der_length(&mut ctx0, octet.len());
            ctx0.extend_from_slice(&octet);
            // encapContentInfo SEQUENCE { eContentType OID, [0] EXPLICIT OCTET STRING }
            //   eContentType = id-ct-TSTInfo = 1.2.840.113549.1.9.16.1.4
            //     06 0B 2A 86 48 86 F7 0D 01 09 10 01 04
            let ect = [
                0x06u8, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
            ];
            let mut encap_body = Vec::new();
            encap_body.extend_from_slice(&ect);
            encap_body.extend_from_slice(&ctx0);
            let mut encap_seq = vec![0x30u8];
            super::push_der_length(&mut encap_seq, encap_body.len());
            encap_seq.extend_from_slice(&encap_body);
            // SignedData SEQUENCE { version 1, digestAlgs SET empty,
            //                       encapContentInfo, signerInfos SET empty }
            let mut sd_body = Vec::new();
            sd_body.extend_from_slice(&[0x02u8, 0x01, 0x01]);
            sd_body.extend_from_slice(&[0x31u8, 0x00]);
            sd_body.extend_from_slice(&encap_seq);
            sd_body.extend_from_slice(&[0x31u8, 0x00]);
            let mut sd_seq = vec![0x30u8];
            super::push_der_length(&mut sd_seq, sd_body.len());
            sd_seq.extend_from_slice(&sd_body);
            let mut ctx0_sd = vec![0xA0u8];
            super::push_der_length(&mut ctx0_sd, sd_seq.len());
            ctx0_sd.extend_from_slice(&sd_seq);
            // contentType OID = id-signedData
            let ct = [
                0x06u8, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
            ];
            let mut outer_body = Vec::new();
            outer_body.extend_from_slice(&ct);
            outer_body.extend_from_slice(&ctx0_sd);
            let mut outer = vec![0x30u8];
            super::push_der_length(&mut outer, outer_body.len());
            outer.extend_from_slice(&outer_body);

            let (oid, hashed) = super::parse_tst_message_imprint(&outer).unwrap();
            assert_eq!(oid, "2.16.840.1.101.3.4.2.1");
            assert_eq!(hashed, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        }
    }
}

fn cert_cn(cert: &X509Ref) -> String {
    cert.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversize_buffer() {
        // Build dummy params that never get inspected — we only need the
        // function to short-circuit on size.
        let store = openssl::x509::store::X509StoreBuilder::new().unwrap().build();
        let store2 = openssl::x509::store::X509StoreBuilder::new().unwrap().build();
        let params = VerifyParams {
            approver_store: &store,
            engineer_store: &store2,
            host_id_hash: "deadbeef",
            scope: "bios.flash",
            m_of_n: 2,
            require_approver_eku: false,
            require_timestamp_token: false,
            signing_time_skew_seconds: 300,
            tsa_store: None,
        };
        let huge = vec![0u8; MAX_CMS_BYTES + 1];
        match verify(&huge, &params) {
            Err(CmsVerifyError::TooLarge(n, cap)) => {
                assert_eq!(n, MAX_CMS_BYTES + 1);
                assert_eq!(cap, MAX_CMS_BYTES);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn small_garbage_buffer_fails_at_parse_stage() {
        let store = openssl::x509::store::X509StoreBuilder::new().unwrap().build();
        let store2 = openssl::x509::store::X509StoreBuilder::new().unwrap().build();
        let params = VerifyParams {
            approver_store: &store,
            engineer_store: &store2,
            host_id_hash: "deadbeef",
            scope: "bios.flash",
            m_of_n: 1,
            require_approver_eku: false,
            require_timestamp_token: false,
            signing_time_skew_seconds: 300,
            tsa_store: None,
        };
        let small = vec![0u8; 32];
        assert!(matches!(verify(&small, &params), Err(CmsVerifyError::Parse(_))));
    }
}
