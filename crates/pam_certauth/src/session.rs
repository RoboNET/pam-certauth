//! Session-open glue between PAM, the MAC orchestrator, and the
//! configured [`pam_certauth_core::mac::backend::MacBackend`].
//!
//! Kept in its own module so the orchestrator wiring can be exercised
//! by tests under `--features mac-tests` without dragging in the cdylib
//! PAM symbols.

use pam_certauth_core::config::ValidatedConfig;
use pam_certauth_core::mac::backend::MacBackend;
#[cfg(feature = "astra-mac")]
use pam_certauth_core::mac::backend::ParsecBackend;
#[cfg(not(feature = "astra-mac"))]
use pam_certauth_core::mac::backend::StubBackend;
use pam_certauth_core::mac::orchestrator::{
    apply_session_policy, OrchestratorError, SessionContext,
};
use pam_certauth_core::pam_data::AuthContext;
use pam_certauth_core::x509::CertIdent;

/// `PAM_AUTH_ERR` — same numeric value as in `entry.rs`.
const PAM_AUTH_ERR: i32 = 7;
/// `PAM_SESSION_ERR` — keep in lock-step with `entry.rs`.
const PAM_SESSION_ERR: i32 = 14;

/// Build the active backend.  On Astra hosts (`astra-mac` feature) this
/// is the `ParsecBackend`; everywhere else the `StubBackend` is used
/// and the orchestrator's runtime probe will return `Unavailable`.
fn build_backend() -> Box<dyn MacBackend> {
    #[cfg(feature = "astra-mac")]
    {
        Box::new(ParsecBackend::new())
    }
    #[cfg(not(feature = "astra-mac"))]
    {
        Box::new(StubBackend::new())
    }
}

/// Run the MAC orchestrator for an open-session call.  Maps orchestrator
/// failures onto PAM return codes:
///
/// * `RuntimeRequired` / `CertLacksExt` → `PAM_AUTH_ERR` (cert/policy
///   contract violated — refuse to open a session).
/// * `ApplyFailed` → `PAM_SESSION_ERR` (the runtime decided we cannot
///   safely apply the label).
///
/// # Errors
///
/// On failure returns the PAM return code the cdylib should propagate.
pub fn run_open_session_pipeline(
    cfg: &ValidatedConfig,
    ctx: &AuthContext,
    pam_user: &str,
) -> Result<(), i32> {
    let backend = build_backend();
    run_open_session_pipeline_with_backend(backend.as_ref(), cfg, ctx, pam_user)
}

/// Test-friendly variant accepting a `&dyn MacBackend`.
///
/// # Errors
///
/// See [`run_open_session_pipeline`].
pub fn run_open_session_pipeline_with_backend(
    backend: &dyn MacBackend,
    cfg: &ValidatedConfig,
    ctx: &AuthContext,
    pam_user: &str,
) -> Result<(), i32> {
    let cert_ident = ctx.cert_ident.clone().unwrap_or(CertIdent {
        serial: ctx.cert_serial.clone().unwrap_or_default(),
        issuer: String::new(),
        cn: ctx.cert_cn.clone().unwrap_or_default(),
        fingerprint: String::new(),
    });
    let sctx = SessionContext {
        pam_user: pam_user.to_string(),
        pam_service: ctx.pam_service.clone(),
        cert_ident,
        home_dir: ctx.home_dir.clone(),
    };

    match apply_session_policy(backend, &cfg.mac, ctx.cert_max_integrity, &sctx) {
        Ok(_) => Ok(()),
        Err(OrchestratorError::CertLacksExt | OrchestratorError::RuntimeRequired(_)) => {
            tracing::error!(
                target: "pam_certauth.session",
                pam_user = %pam_user,
                "MAC orchestrator refused session (policy violation)",
            );
            Err(PAM_AUTH_ERR)
        }
        Err(OrchestratorError::ApplyFailed(e)) => {
            tracing::error!(
                target: "pam_certauth.session",
                pam_user = %pam_user,
                error = %e,
                "MAC orchestrator apply failed",
            );
            Err(PAM_SESSION_ERR)
        }
    }
}

/// Test-only re-exports.  Available only under `mac-tests`.
#[cfg(feature = "mac-tests")]
pub mod test_only {
    /// `PAM_AUTH_ERR` numeric value.
    pub const PAM_AUTH_ERR: i32 = super::PAM_AUTH_ERR;
    /// `PAM_SESSION_ERR` numeric value.
    pub const PAM_SESSION_ERR: i32 = super::PAM_SESSION_ERR;
    pub use super::run_open_session_pipeline_with_backend;
}
