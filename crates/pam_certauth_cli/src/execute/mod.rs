//! `pam-certauth execute` subcommand modules.
//!
//! Each submodule is independent and unit-testable. The orchestrator in
//! [`run`] wires them together: validate args → load config & policy → look
//! up engineer session over IPC → verify CMS work order → canonicalise argv
//! → optional `argv_pattern` glob match (read from the **signed** CMS
//! encapsulated content, NOT a sidecar file) → spawn the requested command
//! with a scrubbed environment → emit structured audit events around the
//! lifecycle.

pub mod argv;
pub mod audit;
pub mod child;
pub mod cli;
pub mod glob;
pub mod retention;
pub mod work_order;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use serde::Deserialize;

use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::X509;

use pam_certauth_core::cms::{verify as cms_verify, CmsVerifyError, VerifyParams};
use pam_certauth_core::config::load_validated_config;
use pam_certauth_core::config::validated::{TrustSection, ValidatedConfig};
use pam_certauth_core::ipc::client::{ActiveSessionReply, MonitorClientFactory};
use pam_certauth_policy::{AuditLevel, Policy, ScopeRule};

use crate::execute::audit::AuditCtx;
use crate::execute::cli::ExecuteArgs;
use crate::hooks::{run_hooks, HookContext, HookPhase};

/// Exit code returned for "policy denial / pre-flight" failures.
pub const EXIT_DENIED: u8 = 2;
/// Exit code returned when the child could not even be spawned.
pub const EXIT_SPAWN_FAILED: u8 = 126;

/// Default location of the shared config file (also used by `daemon`).
const DEFAULT_CONFIG_PATH: &str = "/etc/pam_certauth/config.toml";

/// Environment variable that overrides [`DEFAULT_CONFIG_PATH`] (used by
/// integration tests and emergency operator override).
const ENV_CONFIG_PATH: &str = "PAM_CERTAUTH_CONFIG";

/// Orchestrate a full `pam-certauth execute` invocation.
///
/// Returns the resolved process exit code as an [`ExitCode`]. Any
/// policy-level denial yields [`EXIT_DENIED`]; child exit codes are
/// truncated to the low byte to fit `u8`.
#[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
pub fn run(args: ExecuteArgs) -> ExitCode {
    let Some(scope) = args.scope.as_deref() else {
        return explain_mode(&args);
    };
    let Some(wo_path) = args.work_order.clone() else {
        eprintln!("--work-order is required when --scope is given");
        return ExitCode::from(EXIT_DENIED);
    };

    // -- config + policy -------------------------------------------------
    let config_path = std::env::var(ENV_CONFIG_PATH)
        .map_or_else(|_| PathBuf::from(DEFAULT_CONFIG_PATH), PathBuf::from);
    let config = match load_validated_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config from {}: {e}", config_path.display());
            return ExitCode::from(EXIT_DENIED);
        }
    };

    let policy = match Policy::load(&config.policy.path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "Failed to load policy from {}: {e}",
                config.policy.path.display()
            );
            return ExitCode::from(EXIT_DENIED);
        }
    };
    let policy_sha = hex::encode(policy.sha256());
    let rule = policy.rule_for(scope);

    // -- engineer session via monitord IPC --------------------------------
    let uid = current_uid();
    let session = match lookup_active_session(&config, uid) {
        Ok(s) => s,
        Err(e) => {
            return audit_denied(
                "no active engineer session",
                scope,
                &rule,
                &policy_sha,
                "",
                &[],
                &args.cmd,
                &format!("ipc: {e}"),
            );
        }
    };

    // engineer cert must claim the requested scope
    if !engineer_session_has_scope(&session, scope) {
        return audit_denied(
            "engineer cert lacks scope",
            scope,
            &rule,
            &policy_sha,
            "",
            &[],
            &args.cmd,
            "engineer cert lacks scope",
        );
    }

    // -- read + hash work order ------------------------------------------
    let buf = match work_order::read_work_order(&wo_path) {
        Ok(b) => b,
        Err(e) => {
            return audit_denied(
                "work-order read failed",
                scope,
                &rule,
                &policy_sha,
                "",
                &[],
                &args.cmd,
                &format!("work-order: {e}"),
            );
        }
    };
    let cms_sha = work_order::sha256_hex(&buf);

    // -- build trust stores + verify CMS ---------------------------------
    let approver_store = match config
        .approver_trust
        .as_ref()
        .ok_or_else(|| "approver_trust section is required for execute".to_string())
        .and_then(|t| build_store(t).map_err(|e| format!("approver_trust: {e}")))
    {
        Ok(s) => s,
        Err(e) => {
            return audit_denied(
                "approver trust store unusable",
                scope,
                &rule,
                &policy_sha,
                &cms_sha,
                &[],
                &args.cmd,
                &e,
            );
        }
    };
    let engineer_store = match build_store(&config.trust).map_err(|e| format!("trust: {e}")) {
        Ok(s) => s,
        Err(e) => {
            return audit_denied(
                "engineer trust store unusable",
                scope,
                &rule,
                &policy_sha,
                &cms_sha,
                &[],
                &args.cmd,
                &e,
            );
        }
    };

    let tsa_store_opt = match config
        .tsa_trust
        .as_ref()
        .map(build_store)
        .transpose()
    {
        Ok(s) => s,
        Err(e) => {
            return audit_denied(
                "tsa trust store unusable",
                scope,
                &rule,
                &policy_sha,
                &cms_sha,
                &[],
                &args.cmd,
                &format!("tsa_trust: {e}"),
            );
        }
    };
    if rule.require_timestamp_token && tsa_store_opt.is_none() {
        return audit_denied(
            "policy requires timestamp token but [tsa_trust] is absent",
            scope,
            &rule,
            &policy_sha,
            &cms_sha,
            &[],
            &args.cmd,
            "tsa_trust missing",
        );
    }

    // Host id hash: the daemon-recorded value is authoritative. We do
    // NOT silently fall back to a local resolver — if the running
    // monitord did not record one, that means there is a protocol /
    // version mismatch between the daemon and this CLI, and the
    // host-binding check downstream would otherwise compare against a
    // hash the daemon never verified the session against. Fail closed.
    if session.host_id_hash.is_empty() {
        return audit_denied(
            "monitord returned empty host_id_hash; protocol mismatch?",
            scope,
            &rule,
            &policy_sha,
            &cms_sha,
            &[],
            &args.cmd,
            "monitord: host_id_hash missing in ActiveSessionReply",
        );
    }
    let host_id_hash = session.host_id_hash.clone();

    let m_of_n = rule.m_of_n;
    let params = VerifyParams {
        approver_store: &approver_store,
        engineer_store: &engineer_store,
        host_id_hash: &host_id_hash,
        scope,
        m_of_n,
        require_approver_eku: config.policy.require_approver_eku,
        require_timestamp_token: rule.require_timestamp_token,
        signing_time_skew_seconds: config.policy.signing_time_skew.as_secs(),
        tsa_store: tsa_store_opt.as_ref(),
    };
    let verify_result = match cms_verify(&buf, &params) {
        Ok(v) => v,
        Err(e) => {
            return audit_denied(
                cms_error_summary(&e),
                scope,
                &rule,
                &policy_sha,
                &cms_sha,
                &[],
                &args.cmd,
                &format!("cms verify: {e}"),
            );
        }
    };
    let signers = verify_result.signers;
    let encap_payload = verify_result.encap_payload;

    let approver_skis: Vec<String> = signers
        .iter()
        .map(|s| s.subject_key_identifier.clone())
        .collect();

    // -- retain CMS for forensics ----------------------------------------
    // Best-effort: a retention failure must NOT deny an already-verified
    // action. Path: `<retention_dir>/<cms_sha256>.cms`, mode 0640.
    {
        let dir = retention::retention_dir();
        if let Err(e) = retention::retain_cms(&buf, &cms_sha, &dir) {
            tracing::warn!(
                target: "pam_certauth.execute.retention",
                error = %e,
                dir = %dir.display(),
                cms_sha256 = %cms_sha,
                "retention write failed (continuing)"
            );
        }
    }

    // -- self-approval guard ---------------------------------------------
    if rule.forbid_self_approval
        && !session.engineer_ski.is_empty()
        && signers
            .iter()
            .any(|s| s.subject_key_identifier.eq_ignore_ascii_case(&session.engineer_ski))
    {
        return audit_denied(
            "self-approval forbidden",
            scope,
            &rule,
            &policy_sha,
            &cms_sha,
            &approver_skis,
            &args.cmd,
            "engineer SKI present in approver set",
        );
    }

    // -- argv canonicalisation -------------------------------------------
    let canonical = match argv::canonicalize_and_validate(&args.cmd) {
        Ok(c) => c,
        Err(e) => {
            return audit_denied(
                "argv invalid",
                scope,
                &rule,
                &policy_sha,
                &cms_sha,
                &approver_skis,
                &args.cmd,
                &format!("argv: {e}"),
            );
        }
    };

    // -- argv_pattern check ---------------------------------------------
    // argv_pattern is read from the *signed* CMS encapContentInfo
    // (RFC 5652 §5.1).  The previous sidecar `<work_order>.pattern`
    // file (0.2.0) was not cryptographically bound to approver
    // signatures — any local actor could overwrite it without
    // invalidating the CMS — and so has been removed.  Operators must
    // sign work orders with `openssl cms -sign` in embedded mode (no
    // `-nodetach`), placing a TOML body containing `argv_pattern = ...`
    // into the eContent.
    if rule.require_argv_pattern {
        let pattern = match extract_argv_pattern(encap_payload.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                return audit_denied(
                    "argv_pattern missing from signed payload",
                    scope,
                    &rule,
                    &policy_sha,
                    &cms_sha,
                    &approver_skis,
                    &args.cmd,
                    &format!("payload: {e}"),
                );
            }
        };
        if let Err(e) = glob::validate_pattern(&pattern) {
            return audit_denied(
                "argv_pattern invalid",
                scope,
                &rule,
                &policy_sha,
                &cms_sha,
                &approver_skis,
                &args.cmd,
                &format!("pattern: {e}"),
            );
        }
        if !glob::glob_match(&pattern, &canonical.joined) {
            return audit_denied(
                "argv_pattern mismatch",
                scope,
                &rule,
                &policy_sha,
                &cms_sha,
                &approver_skis,
                &args.cmd,
                "argv_pattern did not match canonical argv",
            );
        }
    }

    let argv_strings: Vec<String> = std::iter::once(canonical.argv0_resolved.to_string_lossy().into_owned())
        .chain(args.cmd.iter().skip(1).cloned())
        .collect();

    // -- emit execute_start audit ----------------------------------------
    let ctx_start = AuditCtx {
        event: "execute_start",
        scope,
        engineer_cn: &session.cert_cn,
        engineer_ski: &session.engineer_ski,
        engineer_session_id: &session.session_id,
        policy_sha256_hex: &policy_sha,
        work_order_cms_sha256: &cms_sha,
        approver_skis: &approver_skis,
        argv: &argv_strings,
        audit_level: rule.audit_level,
        exit_code: None,
        denied_reason: None,
    };
    audit::emit(&ctx_start);

    // -- pre-hooks -------------------------------------------------------
    // Failure → deny + audit. Run after execute_start so the audit trail
    // shows we *intended* to execute, then aborted.
    {
        let pre_ctx = HookContext {
            phase: HookPhase::Pre,
            scope,
            engineer_cn: &session.cert_cn,
            argv: &argv_strings,
            exit_code: None,
        };
        if let Err(e) = run_hooks(&rule.pre_hooks, &pre_ctx) {
            return audit_denied(
                "pre-hook failed",
                scope,
                &rule,
                &policy_sha,
                &cms_sha,
                &approver_skis,
                &argv_strings,
                &format!("pre-hook: {e}"),
            );
        }
    }

    // -- spawn child ------------------------------------------------------
    let env = child::build_child_env();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let timeout = rule.timeout_seconds.map(Duration::from_secs);
    let tail: Vec<String> = args.cmd.iter().skip(1).cloned().collect();

    let exit_code = match child::run_child_with_timeout(
        &canonical.argv0_resolved,
        &tail,
        env,
        cwd,
        timeout,
    ) {
        Ok(res) => res.exit_code,
        Err(e) => {
            let ctx_err = AuditCtx {
                event: "execute_denied",
                scope,
                engineer_cn: &session.cert_cn,
                engineer_ski: &session.engineer_ski,
                engineer_session_id: &session.session_id,
                policy_sha256_hex: &policy_sha,
                work_order_cms_sha256: &cms_sha,
                approver_skis: &approver_skis,
                argv: &argv_strings,
                audit_level: AuditLevel::Critical,
                exit_code: Some(i32::from(EXIT_SPAWN_FAILED)),
                denied_reason: Some(&format!("spawn failed: {e}")),
            };
            audit::emit(&ctx_err);
            return ExitCode::from(EXIT_SPAWN_FAILED);
        }
    };

    // -- post-hooks ------------------------------------------------------
    // Errors are logged inside `run_hooks` but cannot abort: the child has
    // already executed. We surface a top-level error too in case hook
    // resolution itself failed (unknown name slipping past the validator).
    {
        let post_ctx = HookContext {
            phase: HookPhase::Post,
            scope,
            engineer_cn: &session.cert_cn,
            argv: &argv_strings,
            exit_code: Some(exit_code),
        };
        if let Err(e) = run_hooks(&rule.post_hooks, &post_ctx) {
            tracing::warn!(
                target: "pam_certauth.execute.hooks",
                error = %e,
                "post-hook resolution failed (continuing)"
            );
        }
    }

    let event_kind: &'static str = if exit_code == child::TIMEOUT_EXIT_CODE {
        "execute_timeout"
    } else {
        "execute_done"
    };
    let ctx_done = AuditCtx {
        event: event_kind,
        scope,
        engineer_cn: &session.cert_cn,
        engineer_ski: &session.engineer_ski,
        engineer_session_id: &session.session_id,
        policy_sha256_hex: &policy_sha,
        work_order_cms_sha256: &cms_sha,
        approver_skis: &approver_skis,
        argv: &argv_strings,
        audit_level: rule.audit_level,
        exit_code: Some(exit_code),
        denied_reason: None,
    };
    audit::emit(&ctx_done);

    let byte = u8::try_from(exit_code & 0xff).unwrap_or(0xff);
    ExitCode::from(byte)
}

/// MVP placeholder for `--scope`-less invocations. Phase 8 will grow this
/// into a real "given this argv, what scope/rule would apply?" inspector.
fn explain_mode(_args: &ExecuteArgs) -> ExitCode {
    eprintln!("--scope is required (explain mode not implemented in MVP)");
    ExitCode::from(EXIT_DENIED)
}

#[allow(clippy::too_many_arguments)]
fn audit_denied(
    reason: &str,
    scope: &str,
    rule: &ScopeRule,
    policy_sha: &str,
    cms_sha: &str,
    approver_skis: &[String],
    argv: &[String],
    detail: &str,
) -> ExitCode {
    let ctx = AuditCtx {
        event: "execute_denied",
        scope,
        engineer_cn: "",
        engineer_ski: "",
        engineer_session_id: "",
        policy_sha256_hex: policy_sha,
        work_order_cms_sha256: cms_sha,
        approver_skis,
        argv,
        audit_level: max_level(rule.audit_level, AuditLevel::Notice),
        exit_code: Some(i32::from(EXIT_DENIED)),
        denied_reason: Some(reason),
    };
    audit::emit(&ctx);
    eprintln!("Execute denied: {reason}: {detail}");
    ExitCode::from(EXIT_DENIED)
}

fn max_level(a: AuditLevel, b: AuditLevel) -> AuditLevel {
    fn rank(l: AuditLevel) -> u8 {
        match l {
            AuditLevel::Info => 0,
            AuditLevel::Notice => 1,
            AuditLevel::Warning => 2,
            AuditLevel::Critical => 3,
        }
    }
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

fn current_uid() -> u32 {
    // SAFETY: `getuid` is a syscall wrapper with no preconditions.
    #[allow(unsafe_code)]
    unsafe {
        libc::getuid()
    }
}

fn lookup_active_session(
    config: &ValidatedConfig,
    uid: u32,
) -> Result<ActiveSessionReply, String> {
    let factory = MonitorClientFactory::new(
        config.monitor.socket_path.clone(),
        config.monitor.timeout,
    );
    let mut client = factory.connect().map_err(|e| e.to_string())?;
    client.get_active_session_by_uid(uid).map_err(|e| e.to_string())
}

fn engineer_session_has_scope(session: &ActiveSessionReply, requested: &str) -> bool {
    // Single source of truth for wildcard scope-match semantics.
    pam_certauth_core::x509::scopes_ext::matches_strings(&session.scopes, requested)
}

fn build_store(trust: &TrustSection) -> Result<X509Store, String> {
    let mut b = X509StoreBuilder::new().map_err(|e| e.to_string())?;
    for path in trust.anchors.iter().chain(trust.intermediates.iter()) {
        let pem = std::fs::read(path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        // A single PEM file may contain multiple certificates.
        let certs = X509::stack_from_pem(&pem)
            .map_err(|e| format!("parse {}: {e}", path.display()))?;
        for cert in certs {
            b.add_cert(cert).map_err(|e| e.to_string())?;
        }
    }
    Ok(b.build())
}

/// TOML schema for the CMS encapsulated payload.  Only fields the
/// orchestrator consumes are declared; unknown keys are ignored so that
/// future producers can add metadata without breaking older verifiers.
#[derive(Debug, Deserialize)]
struct PayloadToml {
    #[serde(default)]
    argv_pattern: Option<String>,
}

/// Extract `argv_pattern` from the verified CMS encapContent.
///
/// Returns `Err` (deny) when:
/// * the CMS is detached (no eContent) — i.e. the producer signed in
///   the legacy 0.2.0 wire format,
/// * the payload is not valid UTF-8,
/// * the payload is not parseable TOML,
/// * `argv_pattern` is absent from the TOML body.
fn extract_argv_pattern(payload: Option<&[u8]>) -> Result<String, String> {
    let bytes = payload.ok_or_else(|| {
        "CMS has no encapsulated payload (detached signature) but \
         rule.require_argv_pattern is set — re-sign work order with \
         openssl cms -sign in embedded mode".to_string()
    })?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "encap payload is not valid UTF-8".to_string())?;
    let parsed: PayloadToml = toml::from_str(text)
        .map_err(|e| format!("payload TOML parse: {e}"))?;
    let pattern = parsed
        .argv_pattern
        .ok_or_else(|| "payload TOML missing argv_pattern key".to_string())?;
    if pattern.trim().is_empty() {
        return Err("argv_pattern is empty".to_string());
    }
    Ok(pattern)
}

fn cms_error_summary(e: &CmsVerifyError) -> &'static str {
    match e {
        CmsVerifyError::TooLarge(_, _) => "work-order too large",
        CmsVerifyError::Parse(_) => "work-order parse failed",
        CmsVerifyError::Verify(_) => "cms verify failed",
        CmsVerifyError::Insufficient { .. } => "insufficient approver signatures",
        CmsVerifyError::DuplicateSki(_) => "duplicate approver SKI",
        CmsVerifyError::ScopeMissing { .. } => "approver cert lacks scope",
        CmsVerifyError::HostMismatch => "approver cert host mismatch",
        CmsVerifyError::SharedTrustAnchor => "approver chain == engineer chain",
        CmsVerifyError::EkuMissing => "approver cert lacks approver EKU",
        CmsVerifyError::SigningTimeOutOfWindow => "signing time outside skew window",
        CmsVerifyError::TimestampTokenMissing => "timestamp token missing",
        CmsVerifyError::Openssl(_) => "openssl internal error",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn engineer_session_scope_match_exact() {
        let s = ActiveSessionReply {
            session_id: "s".into(),
            cert_cn: "Alice".into(),
            engineer_ski: "aa".into(),
            engineer_cert_sha256: "bb".into(),
            scopes: vec!["bios.flash".into()],
            host_id_hash: String::new(),
        };
        assert!(engineer_session_has_scope(&s, "bios.flash"));
        assert!(!engineer_session_has_scope(&s, "bios.erase"));
    }

    #[test]
    fn engineer_session_scope_wildcard_star() {
        let s = ActiveSessionReply {
            session_id: "s".into(),
            cert_cn: "Alice".into(),
            engineer_ski: "aa".into(),
            engineer_cert_sha256: "bb".into(),
            scopes: vec!["*".into()],
            host_id_hash: String::new(),
        };
        assert!(engineer_session_has_scope(&s, "anything.goes"));
    }

    #[test]
    fn engineer_session_scope_prefix_wildcard() {
        let s = ActiveSessionReply {
            session_id: "s".into(),
            cert_cn: "Alice".into(),
            engineer_ski: "aa".into(),
            engineer_cert_sha256: "bb".into(),
            scopes: vec!["bios.*".into()],
            host_id_hash: String::new(),
        };
        assert!(engineer_session_has_scope(&s, "bios.flash"));
        assert!(engineer_session_has_scope(&s, "bios.erase"));
        assert!(!engineer_session_has_scope(&s, "service.restart"));
        // Bare "bios" must NOT match "bios.*" — wildcard requires the dot.
        assert!(!engineer_session_has_scope(&s, "bios"));
    }

    #[test]
    fn extract_argv_pattern_reads_signed_toml_payload() {
        let payload = b"argv_pattern = \"flashrom -w *.bin\"\n";
        let pat = extract_argv_pattern(Some(payload)).unwrap();
        assert_eq!(pat, "flashrom -w *.bin");
    }

    #[test]
    fn extract_argv_pattern_rejects_detached_cms() {
        let err = extract_argv_pattern(None).unwrap_err();
        assert!(err.contains("detached"), "got: {err}");
    }

    #[test]
    fn extract_argv_pattern_rejects_missing_key() {
        let payload = b"other_key = \"x\"\n";
        let err = extract_argv_pattern(Some(payload)).unwrap_err();
        assert!(err.contains("argv_pattern"), "got: {err}");
    }

    #[test]
    fn extract_argv_pattern_rejects_bad_utf8() {
        let payload = [0xFFu8, 0xFE, 0xFD];
        let err = extract_argv_pattern(Some(&payload)).unwrap_err();
        assert!(err.contains("UTF-8"), "got: {err}");
    }

    #[test]
    fn extract_argv_pattern_rejects_malformed_toml() {
        let payload = b"argv_pattern = ";
        let err = extract_argv_pattern(Some(payload)).unwrap_err();
        assert!(err.contains("TOML"), "got: {err}");
    }

    #[test]
    fn max_level_picks_critical_over_info() {
        assert_eq!(max_level(AuditLevel::Info, AuditLevel::Critical), AuditLevel::Critical);
        assert_eq!(max_level(AuditLevel::Critical, AuditLevel::Info), AuditLevel::Critical);
    }
}
