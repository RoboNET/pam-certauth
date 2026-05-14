//! Tracing init for `pam-certauth-execute`.
//!
//! Mirrors `pam_certauth_cli::logging::init` — kept in this crate as a
//! 40-line copy so the privileged execute binary does **not** need to
//! depend on the daemon crate (and therefore on zbus, udev, &c.). Both
//! initialisers wire the same stderr + journald layers, so audit events
//! land on identical fields and targets regardless of which binary
//! emitted them.
//!
//! See `pam_certauth_cli/src/logging.rs` for the historical rationale
//! behind the journald layer (sudo-forwarded stderr was leaving SIEM
//! blind before 0.2.2). The two copies must stay in lock-step; clippy
//! cannot enforce that, but every audit-event field is exercised by
//! the Phase 13 vagrant E2E harness.

use anyhow::Result;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Initialise tracing. Idempotent across calls within a process.
///
/// On a non-systemd host the journald layer is silently dropped and
/// only stderr remains, keeping `cargo test` and dev-loop output
/// working on macOS / WSL.
pub fn init() -> Result<()> {
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    if INIT.get().is_some() {
        return Ok(());
    }
    let env = tracing_subscriber::EnvFilter::try_from_env("PAM_CERTAUTH_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let stderr_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let journald_layer = tracing_journald::layer().ok();
    tracing_subscriber::registry()
        .with(env)
        .with(stderr_layer)
        .with(journald_layer)
        .try_init()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    _ = INIT.set(());
    Ok(())
}
