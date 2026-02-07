//! Project-private OIDs used by the `pam_certauth` extensions.
//!
//! These OIDs are allocated in the RFC 4530 unregistered arc `2.25.<UUID>`
//! (the OID-from-UUID range), so they are guaranteed unique without going
//! through any external registry.  They are stable across versions and form
//! part of the on-the-wire X.509 certificate contract — do **not** change
//! these values.

/// OID of the `pam_cert_host_binding` X.509 extension.
///
/// `extnValue ::= SEQUENCE OF UTF8String`, where each entry is a host
/// descriptor (`"*"`, `"sha256:<hex>"`, or a raw `machine_id`).
pub const HOST_BINDING_OID: &str = "2.25.183976554325829274683049824615098";

/// OID of the `pam_cert_user_binding` X.509 extension.
///
/// `extnValue ::= SEQUENCE OF UTF8String`, where each entry is either `"*"`
/// (matches any user) or an exact PAM username.
pub const USER_BINDING_OID: &str = "2.25.215438916728501023845629178354627";

/// OID of the `pam_cert_scopes` X.509 extension.
///
/// `extnValue ::= SEQUENCE OF UTF8String`, where each entry is a scope name
/// matching regex `^[a-z][a-z0-9_.-]{0,127}$` or the wildcard `"*"`.
pub const SCOPES_OID: &str = "2.25.148783702439522084104654664555598657967";

/// OID for the *approver* Extended Key Usage purpose.
///
/// Each signer's leaf certificate must include this OID in its
/// `extendedKeyUsage` extension when policy `require_approver_eku = true`.
/// It is the contract that the issuing CA explicitly authorised the cert
/// to act as an approver for `pam_certauth` work orders, regardless of
/// the cert's `pam_cert_scopes`.
pub const APPROVER_EKU_OID: &str = "2.25.164448633110302675590304402232871779284";
