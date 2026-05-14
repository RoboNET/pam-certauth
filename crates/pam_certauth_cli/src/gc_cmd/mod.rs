//! `pam-certauth gc` subcommand: sweep the work-order retention store and
//! delete entries older than `--retention-days` days.
//!
//! Triggered nightly by `pam-certauth-gc.timer` (see `dist/systemd/`). Can
//! also be invoked manually for ad-hoc cleanup; safe to run while the
//! daemon is live because the sweep only touches `*.cms` files (never
//! `.tmp` half-writes, never anything in subdirectories).

use std::process::ExitCode;

use clap::Args;

use crate::execute::retention;

/// Arguments accepted by `pam-certauth gc`.
#[derive(Args, Debug, Clone)]
pub struct GcArgs {
    /// Retain CMS work-orders newer than this many days. Default mirrors
    /// the spec's 90-day forensic window.
    #[arg(long, default_value_t = 90)]
    pub retention_days: u32,
}

/// Run the gc sweep using the active retention directory (honours the
/// `PAM_CERTAUTH_RETENTION_DIR` env override).
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn run(args: GcArgs) -> ExitCode {
    let dir = retention::retention_dir();
    match retention::gc(&dir, args.retention_days, std::time::SystemTime::now()) {
        Ok(removed) => {
            tracing::info!(
                target: "pam_certauth.execute.retention.gc",
                dir = %dir.display(),
                retention_days = args.retention_days,
                removed,
                "gc completed"
            );
            println!(
                "gc: removed {removed} file(s) from {} (retention {} days)",
                dir.display(),
                args.retention_days
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("gc: failed: {e}");
            ExitCode::from(1)
        }
    }
}
