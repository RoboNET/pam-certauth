//! Logging initialization for the `pam-certauth` CLI.
//!
//! All subcommands (daemon, execute, policy, gc) funnel through
//! [`init`]: each one builds a tracing subscriber with both a stderr
//! `fmt` layer (operator-visible output) **and**, when the host is
//! running systemd, a `tracing-journald` layer so audit events
//! (`execute_start`, `execute_done`, `execute_denied`, …) survive
//! even when the binary is invoked under `sudo` rather than as a
//! systemd unit child.  Before 0.2.2 only stderr was wired up, and
//! `sudo` forwarded that stream to the user terminal — journald
//! never saw `execute_*` events, blinding SIEM. See
//! `docs/operations.md` and the 0.2.2 changelog entry.

use anyhow::Result;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Initialize tracing. Idempotent across calls within a process.
///
/// Adds a `tracing-journald` layer on a best-effort basis: if
/// `/run/systemd/journal/socket` is missing (e.g. non-systemd host,
/// or running inside a minimal container) the journald layer is
/// silently dropped and only stderr remains.  This keeps `cargo
/// test` and dev-loop output working on macOS / WSL while ensuring
/// the production Linux ATM path emits structured audit records
/// into journald.
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
    // OnceCell::set returns Err only if already set; we treat re-init as a noop.
    _ = INIT.set(());
    Ok(())
}
