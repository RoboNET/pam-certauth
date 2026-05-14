#![cfg(feature = "mac-tests")]
#![allow(clippy::unwrap_used)]

//! Smoke test for the open-session MAC pipeline.  Drives
//! [`pam_certauth::session::run_open_session_pipeline_with_backend`]
//! through the same code path the cdylib's `pam_sm_open_session`
//! invokes, using a `MockMacBackend` to assert the orchestrator was
//! wired up correctly.

use pam_certauth::session::run_open_session_pipeline_with_backend;
use pam_certauth_core::config::validated::{CertIntegrityMode, MacPolicy, ValidatedConfig};
use pam_certauth_core::mac::backend::{MacRuntime, MockMacBackend};
use pam_certauth_core::mac::IntegrityLabel;
use pam_certauth_core::pam_data::AuthContext;
use pam_certauth_core::x509::CertIdent;

mod common;

fn make_ctx() -> AuthContext {
    let mut ctx = AuthContext::new("sess-1".into(), "login".into());
    ctx.cert_cn = Some("alice".into());
    ctx.cert_serial = Some("01".into());
    ctx.cert_max_integrity = Some(IntegrityLabel {
        level: 3,
        categories: 0,
    });
    ctx.cert_ident = Some(CertIdent {
        serial: "01".into(),
        issuer: "CN=Test".into(),
        cn: "alice".into(),
        fingerprint: "deadbeef".into(),
    });
    ctx
}

fn cfg_with_mac(mode: CertIntegrityMode) -> ValidatedConfig {
    let mut cfg = common::minimal_cfg();
    cfg.mac = MacPolicy {
        cert_integrity: mode,
        fallback_max_integrity: None,
        warn_on_homedir_label_mismatch: false,
    };
    cfg
}

#[test]
fn open_session_applies_when_runtime_active() {
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    backend.expect_get_user_mnkc().returning(|_| {
        Ok(IntegrityLabel {
            level: 5,
            categories: 0,
        })
    });
    backend.expect_apply_session().returning(|_| Ok(()));

    let cfg = cfg_with_mac(CertIntegrityMode::Required);
    let ctx = make_ctx();
    let r = run_open_session_pipeline_with_backend(&backend, &cfg, &ctx, "alice");
    assert!(r.is_ok(), "expected Ok, got {r:?}");
}

#[test]
fn open_session_skips_when_runtime_unavailable_optional() {
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Unavailable);
    let cfg = cfg_with_mac(CertIntegrityMode::Optional);
    let ctx = make_ctx();
    let r = run_open_session_pipeline_with_backend(&backend, &cfg, &ctx, "alice");
    assert!(r.is_ok(), "expected Ok (skipped), got {r:?}");
}

#[test]
fn open_session_fails_when_required_but_runtime_unavailable() {
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Unavailable);
    let cfg = cfg_with_mac(CertIntegrityMode::Required);
    let ctx = make_ctx();
    let r = run_open_session_pipeline_with_backend(&backend, &cfg, &ctx, "alice");
    // PAM_AUTH_ERR == 7.
    assert_eq!(r, Err(7));
}

#[test]
fn open_session_fails_when_required_but_cert_lacks_ext() {
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    let cfg = cfg_with_mac(CertIntegrityMode::Required);
    let mut ctx = make_ctx();
    ctx.cert_max_integrity = None;
    let r = run_open_session_pipeline_with_backend(&backend, &cfg, &ctx, "alice");
    assert_eq!(r, Err(7));
}
