//! Audit events for the MAC subsystem.  Placeholder; full event set is wired
//! up in Phase 5 (Task 5.1).

/// Emit a warning that the running process is missing the `PARSEC_CAP_CHMAC`
/// capability.  Operations that set file labels in IRELAX mode will still be
/// attempted and rejected by the kernel — this is a soft warning, not a
/// failure.
#[cfg(feature = "astra-mac")]
pub fn emit_caps_missing(reason: &str) {
    tracing::warn!(
        target: "mac.audit",
        event = "mac_caps_missing",
        reason = reason,
    );
}
