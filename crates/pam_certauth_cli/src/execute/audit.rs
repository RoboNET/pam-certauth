//! Structured audit events for the `execute` subcommand.
//!
//! Emitted via `tracing` so they flow through the `tracing-journald` layer
//! configured by the binary entry point. Free-form strings (engineer CN,
//! denial reasons) are passed through [`sanitize`] before emission.

use tracing::info;

use pam_certauth_policy::AuditLevel;

/// Strip ASCII control characters from `s`, preserving horizontal tab.
///
/// Used on any free-form string that ends up in a structured audit field
/// to keep journald records single-line and parser-friendly.
#[must_use]
pub fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .collect()
}

/// Context bag describing a single audit event.
///
/// `event` is one of `"execute_start"`, `"execute_done"`, `"execute_denied"`,
/// or `"execute_timeout"`.
#[derive(Debug)]
pub struct AuditCtx<'a> {
    /// Event kind.
    pub event: &'static str,
    /// Scope name being executed.
    pub scope: &'a str,
    /// Engineer certificate Common Name.
    pub engineer_cn: &'a str,
    /// Engineer certificate Subject Key Identifier (hex).
    pub engineer_ski: &'a str,
    /// Active monitord session ID for the engineer.
    pub engineer_session_id: &'a str,
    /// Hex SHA-256 of the loaded policy.toml.
    pub policy_sha256_hex: &'a str,
    /// Hex SHA-256 of the raw CMS work-order bytes.
    pub work_order_cms_sha256: &'a str,
    /// SKIs (hex) of the approvers whose signatures were verified.
    pub approver_skis: &'a [String],
    /// Canonical argv that will be / was executed.
    pub argv: &'a [String],
    /// Effective audit level resolved from policy.
    pub audit_level: AuditLevel,
    /// Exit code, if the child has completed.
    pub exit_code: Option<i32>,
    /// Denial reason (only for `execute_denied`).
    pub denied_reason: Option<&'a str>,
}

/// Emit a single audit event for `ctx` via `tracing::info!`.
pub fn emit(ctx: &AuditCtx<'_>) {
    info!(
        target: "pam_certauth.execute",
        event = ctx.event,
        scope = %ctx.scope,
        engineer_cn = %sanitize(ctx.engineer_cn),
        engineer_ski = %ctx.engineer_ski,
        engineer_session_id = %ctx.engineer_session_id,
        policy_sha256 = %ctx.policy_sha256_hex,
        work_order_cms_sha256 = %ctx.work_order_cms_sha256,
        approvers = ?ctx.approver_skis,
        argv = ?ctx.argv,
        audit_level = ?ctx.audit_level,
        exit_code = ?ctx.exit_code,
        denied_reason = ?ctx.denied_reason,
        "execute audit event"
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_newline() {
        assert_eq!(sanitize("Alice\nBob"), "AliceBob");
    }

    #[test]
    fn sanitize_preserves_tab() {
        assert_eq!(sanitize("hello\tworld"), "hello\tworld");
    }

    #[test]
    fn sanitize_strips_nul() {
        assert_eq!(sanitize("\x00bad"), "bad");
    }

    #[test]
    fn sanitize_strips_assorted_controls() {
        assert_eq!(sanitize("a\r\nb\x1bc"), "abc");
    }

    #[test]
    fn emit_compiles_with_typical_context() {
        // Smoke: ensure the macro expands and accepts our field set.
        let policy_hash = "0".repeat(64);
        let wo_hash = "1".repeat(64);
        let approvers = vec!["a".repeat(40), "b".repeat(40)];
        let argv = vec![
            "/usr/sbin/flashrom".to_string(),
            "-w".to_string(),
            "fw.bin".to_string(),
        ];
        let ctx = AuditCtx {
            event: "execute_start",
            scope: "bios.flash",
            engineer_cn: "Alice",
            engineer_ski: "deadbeef",
            engineer_session_id: "sess-1",
            policy_sha256_hex: &policy_hash,
            work_order_cms_sha256: &wo_hash,
            approver_skis: &approvers,
            argv: &argv,
            audit_level: AuditLevel::Info,
            exit_code: None,
            denied_reason: None,
        };
        emit(&ctx);
    }
}
