//! [`CertClaims`] — the central, I/O-free projection of a validated X.509
//! certificate into the fields the PAM module, the daemon IPC layer, and
//! the `pam-certauth execute` subcommand consume.
//!
//! Layout:
//! - `host_descriptors` — parsed from the `pam_cert_host_binding` extension
//!   (mandatory).
//! - `user_descriptors` — parsed from the `pam_cert_user_binding` extension
//!   (mandatory).
//! - `scopes`            — parsed from the `pam_cert_scopes` extension
//!   (OPTIONAL: empty `Vec` when the extension is absent).
//! - `subject_key_identifier` — lowercase hex of the cert's SKI extension.
//! - `cert_sha256`           — lowercase hex of `SHA-256(cert DER)`.
//!
//! `from_cert` is pure: it does not touch the filesystem, the network, or
//! any clocks. The caller passes in a parsed `X509Ref`.

use crate::x509::host_binding_ext::{self, HostBindingExtError, HostDescriptor};
use crate::x509::scopes_ext::{self, Scope, ScopesExtError};
use crate::x509::user_binding_ext::{self, UserBindingExtError, UserDescriptor};
use openssl::x509::X509Ref;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Projection of an X.509 leaf certificate into the fields used downstream
/// by the PAM module, the daemon IPC payloads, and `pam-certauth execute`.
#[derive(Debug, Clone)]
pub struct CertClaims {
    /// Parsed entries of the `pam_cert_host_binding` extension.
    pub host_descriptors: Vec<HostDescriptor>,
    /// Parsed entries of the `pam_cert_user_binding` extension.
    pub user_descriptors: Vec<UserDescriptor>,
    /// Parsed entries of the `pam_cert_scopes` extension.
    ///
    /// Empty when the extension is absent — not an error.
    pub scopes: Vec<Scope>,
    /// Lowercase hex of the cert's `SubjectKeyIdentifier` extension value.
    pub subject_key_identifier: String,
    /// Lowercase hex of `SHA-256(cert DER)`.
    pub cert_sha256: String,
}

/// Errors produced while building a [`CertClaims`] from a certificate.
#[derive(Debug, Error)]
pub enum CertClaimsError {
    /// `openssl` returned an error while serialising or inspecting the cert.
    #[error("openssl: {0}")]
    Openssl(String),
    /// The `pam_cert_host_binding` extension is malformed or missing.
    #[error("host_binding ext: {0}")]
    HostBinding(#[from] HostBindingExtError),
    /// The `pam_cert_user_binding` extension is malformed or missing.
    #[error("user_binding ext: {0}")]
    UserBinding(#[from] UserBindingExtError),
    /// The `pam_cert_scopes` extension is present but malformed.
    #[error("scopes ext: {0}")]
    Scopes(#[from] ScopesExtError),
    /// The cert has no `SubjectKeyIdentifier` extension.
    #[error("cert missing SubjectKeyIdentifier")]
    SkiMissing,
}

impl CertClaims {
    /// Extract `host_binding` + `user_binding` + `scopes` claims from a
    /// cert, plus the `SubjectKeyIdentifier` and the SHA-256 of the cert
    /// DER.
    ///
    /// The `pam_cert_scopes` extension is optional — when absent the
    /// resulting [`Self::scopes`] is an empty `Vec`. Host- and user-binding
    /// extensions are required; their absence is a hard error surfaced via
    /// [`CertClaimsError::HostBinding`] / [`CertClaimsError::UserBinding`].
    ///
    /// # Errors
    ///
    /// - [`CertClaimsError::HostBinding`] / [`CertClaimsError::UserBinding`]
    ///   — the corresponding extension is missing or malformed.
    /// - [`CertClaimsError::Scopes`] — the scopes extension is present but
    ///   malformed (empty SEQUENCE, bad UTF-8, or invalid scope name).
    /// - [`CertClaimsError::SkiMissing`] — the cert has no
    ///   `SubjectKeyIdentifier` extension.
    /// - [`CertClaimsError::Openssl`] — DER serialisation of the cert
    ///   failed.
    pub fn from_cert(cert: &X509Ref) -> Result<Self, CertClaimsError> {
        let host_descriptors = host_binding_ext::parse(cert)?;
        let user_descriptors = user_binding_ext::parse(cert)?;
        let scopes = match scopes_ext::parse(cert) {
            Ok(v) => v,
            Err(ScopesExtError::Missing) => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        let subject_key_identifier = subject_key_identifier_hex(cert)?;
        let cert_sha256 = sha256_hex_of_der(cert)?;
        Ok(Self {
            host_descriptors,
            user_descriptors,
            scopes,
            subject_key_identifier,
            cert_sha256,
        })
    }
}

fn subject_key_identifier_hex(cert: &X509Ref) -> Result<String, CertClaimsError> {
    let ski = cert.subject_key_id().ok_or(CertClaimsError::SkiMissing)?;
    Ok(hex::encode(ski.as_slice()))
}

fn sha256_hex_of_der(cert: &X509Ref) -> Result<String, CertClaimsError> {
    let der = cert
        .to_der()
        .map_err(|e| CertClaimsError::Openssl(e.to_string()))?;
    Ok(hex::encode(Sha256::digest(&der)))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::x509::oids::{HOST_BINDING_OID, SCOPES_OID, USER_BINDING_OID};
    use crate::x509::test_utils::{build_cert, encode_seq_of_utf8};

    #[test]
    fn from_cert_extracts_all_fields() {
        let cert = build_cert(&[
            (HOST_BINDING_OID, encode_seq_of_utf8(&["*"])),
            (USER_BINDING_OID, encode_seq_of_utf8(&["alice"])),
            (
                SCOPES_OID,
                encode_seq_of_utf8(&["bios.flash", "service.restart"]),
            ),
        ]);
        let claims = CertClaims::from_cert(&cert).unwrap();
        assert_eq!(claims.scopes.len(), 2);
        assert_eq!(claims.scopes[0], Scope::Exact("bios.flash".into()));
        assert_eq!(claims.subject_key_identifier.len(), 40); // 20 bytes hex
        assert_eq!(claims.cert_sha256.len(), 64);
        assert!(!claims.host_descriptors.is_empty());
        assert!(!claims.user_descriptors.is_empty());
    }

    #[test]
    fn from_cert_scopes_optional_returns_empty() {
        let cert = build_cert(&[
            (HOST_BINDING_OID, encode_seq_of_utf8(&["*"])),
            (USER_BINDING_OID, encode_seq_of_utf8(&["alice"])),
            // no SCOPES_OID
        ]);
        let claims = CertClaims::from_cert(&cert).unwrap();
        assert!(claims.scopes.is_empty());
    }

    #[test]
    fn from_cert_propagates_invalid_scope_error() {
        let cert = build_cert(&[
            (HOST_BINDING_OID, encode_seq_of_utf8(&["*"])),
            (USER_BINDING_OID, encode_seq_of_utf8(&["alice"])),
            (SCOPES_OID, encode_seq_of_utf8(&["BAD UPPERCASE"])),
        ]);
        assert!(matches!(
            CertClaims::from_cert(&cert),
            Err(CertClaimsError::Scopes(_))
        ));
    }

    #[test]
    fn cert_sha256_is_stable() {
        let cert = build_cert(&[
            (HOST_BINDING_OID, encode_seq_of_utf8(&["*"])),
            (USER_BINDING_OID, encode_seq_of_utf8(&["alice"])),
        ]);
        let a = CertClaims::from_cert(&cert).unwrap().cert_sha256;
        let b = CertClaims::from_cert(&cert).unwrap().cert_sha256;
        assert_eq!(a, b);
    }
}
