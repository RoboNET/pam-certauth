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
/// `event` is one of `"execute_attempt"`, `"execute_start"`,
/// `"execute_done"`, `"execute_denied"`, or `"execute_timeout"`.
///
/// `execute_attempt` is emitted immediately on CLI entry, BEFORE any I/O
/// (no session lookup, no CMS read). All cert / CMS / policy fields are
/// empty for that event; only `scope`, `argv`, and `work_order_path` are
/// populated. The subsequent `execute_start` carries the verified data.
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
    /// Raw `--work-order` path as supplied on the CLI. Populated for
    /// `execute_attempt`; `None` for later events that already carry
    /// the cryptographic SHA-256 of the file content.
    pub work_order_path: Option<&'a str>,
    /// PID of the `pam-certauth execute` process emitting the event.
    /// Pure syscall — no I/O. Populated on `execute_attempt` so the
    /// early audit record stays correlatable across SIGKILL cycles
    /// (forensic-completeness field).
    pub pid: u32,
    /// Real uid of the emitting process (`getuid(2)`).
    pub uid: u32,
    /// `$SUDO_UID` from the environment, if pam-certauth was invoked
    /// via sudo. Lets the auditor reconstruct which engineer launched
    /// the command even after the elevated wrapper has died.
    pub sudo_uid: Option<&'a str>,
    /// Parent pid (`getppid(2)`). Useful when correlating against
    /// systemd, sudo, or a remote SSH session.
    pub parent_pid: i32,
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
        work_order_path = ?ctx.work_order_path,
        pid = ctx.pid,
        uid = ctx.uid,
        sudo_uid = ?ctx.sudo_uid,
        parent_pid = ctx.parent_pid,
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
    fn emit_attempt_compiles_with_empty_cert_fields() {
        // execute_attempt is emitted before any I/O, so cert / CMS /
        // policy fields are intentionally empty. Validate the type
        // accepts that shape.
        let wo_path = "/var/lib/pam_certauth/work_orders/in.cms".to_string();
        let argv = vec!["/bin/sleep".to_string(), "10".to_string()];
        let ctx = AuditCtx {
            event: "execute_attempt",
            scope: "test.scope",
            engineer_cn: "",
            engineer_ski: "",
            engineer_session_id: "",
            policy_sha256_hex: "",
            work_order_cms_sha256: "",
            approver_skis: &[],
            argv: &argv,
            audit_level: AuditLevel::Notice,
            exit_code: None,
            denied_reason: None,
            work_order_path: Some(&wo_path),
            pid: 1,
            uid: 1000,
            sudo_uid: None,
            parent_pid: 1,
        };
        emit(&ctx);
    }

    /// Use a `tracing` test subscriber to confirm `execute_attempt` is
    /// emitted with the expected event name and that
    /// `work_order_path` reaches the formatted output. This is the
    /// closest in-process analogue to "journald layer saw the event"
    /// without coupling to journald itself.
    #[test]
    fn emit_attempt_reaches_subscriber() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl<'a> MakeWriter<'a> for Sink {
            type Writer = SinkWriter;
            fn make_writer(&'a self) -> Self::Writer {
                SinkWriter(self.0.clone())
            }
        }
        struct SinkWriter(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for SinkWriter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let sink = Sink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_max_level(tracing::Level::INFO)
            .finish();

        let argv = vec!["/bin/sleep".to_string(), "10".to_string()];
        let wo_path = "/wo/path".to_string();
        let ctx = AuditCtx {
            event: "execute_attempt",
            scope: "test.scope",
            engineer_cn: "",
            engineer_ski: "",
            engineer_session_id: "",
            policy_sha256_hex: "",
            work_order_cms_sha256: "",
            approver_skis: &[],
            argv: &argv,
            audit_level: AuditLevel::Notice,
            exit_code: None,
            denied_reason: None,
            work_order_path: Some(&wo_path),
            pid: 4242,
            uid: 1001,
            sudo_uid: Some("1234"),
            parent_pid: 999,
        };
        tracing::subscriber::with_default(subscriber, || emit(&ctx));

        let captured = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(captured.contains("execute_attempt"), "{captured}");
        assert!(captured.contains("/wo/path"), "{captured}");
        assert!(captured.contains("test.scope"), "{captured}");
        // Verify forensic fields make it into the rendered output so
        // the journald layer will receive them at runtime.
        assert!(
            captured.contains("pid") && captured.contains("4242"),
            "missing pid: {captured}"
        );
        assert!(
            captured.contains("sudo_uid") && captured.contains("1234"),
            "missing sudo_uid: {captured}"
        );
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
            work_order_path: None,
            pid: 0,
            uid: 0,
            sudo_uid: None,
            parent_pid: 0,
        };
        emit(&ctx);
    }
}
