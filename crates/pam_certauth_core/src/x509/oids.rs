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
