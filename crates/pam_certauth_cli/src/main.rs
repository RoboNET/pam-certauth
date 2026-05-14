//! `pam-certauth` entry point.
//!
//! Thin clap dispatcher: every subcommand's lifecycle lives in its own
//! library module (see `pam_certauth_cli::daemon` for the monitor daemon).
//!
//! Note (0.2.4): the `execute` subcommand has been split out into a
//! standalone binary `pam-certauth-execute` shipped from the
//! `pam_certauth_execute` crate. To make upgrades from <=0.2.3 less
//! surprising for operators, the `Execute` variant is kept here as a
//! deprecation stub: it parses but immediately prints an actionable
//! error and exits 2.

// Warn on `let _ = …` for #[must_use] returns so a future refactor
// of `let daemon_lock = DaemonLock::acquire(...)` into `let _ = ...`
// trips a lint instead of silently breaking the singleton invariant.
#![warn(clippy::let_underscore_must_use)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use pam_certauth_cli::daemon::{self, DaemonArgs};
use pam_certauth_cli::gc_cmd::{self, GcArgs};
use pam_certauth_cli::logging;
use pam_certauth_cli::policy_cmd::{self, PolicyArgs};

#[derive(Debug, Parser)]
#[command(name = "pam-certauth", version, about = "PAM CertAuth control plane")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// Deprecation stub for the old `pam-certauth execute` subcommand.
///
/// Accepts any trailing args (so legacy sudoers rules continue to clap-parse)
/// and exits 2 with a pointer to the new binary path. The variant is gated
/// behind `Cmd::Execute` solely for the friendlier error; the orchestrator
/// lives in `pam_certauth_execute`.
#[derive(Debug, clap::Args)]
#[allow(missing_docs)]
struct ExecuteStubArgs {
    /// Catch-all so the old CLI surface still parses; ignored.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    _rest: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run the monitor daemon (USB / logind enforcement, IPC server).
    Daemon(DaemonArgs),
    /// **Removed in 0.2.4.** Moved to `/usr/bin/pam-certauth-execute`.
    Execute(ExecuteStubArgs),
    /// Inspect a `policy.toml` (validate / explain effective rule).
    Policy(PolicyArgs),
    /// Sweep the work-order retention store; delete entries older than
    /// `--retention-days` days (default 90).
    Gc(GcArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Initialise tracing once for every subcommand so audit events
    // (GC sweep, policy explain, …) land in journald uniformly — not
    // just when we run as a systemd unit child. `daemon::run_async`
    // calls `logging::init` again; the OnceLock guard inside makes
    // that a no-op. Failure is logged to stderr and the process
    // continues — tracing is best-effort, not a hard prereq.
    if let Err(e) = logging::init() {
        eprintln!("pam-certauth: failed to initialise tracing: {e:#}");
    }
    match cli.cmd {
        Cmd::Daemon(args) => daemon::run(args),
        Cmd::Execute(_) => {
            eprintln!(
                "error: `pam-certauth execute` was moved to `/usr/bin/pam-certauth-execute` in 0.2.4."
            );
            eprintln!(
                "hint:  update your sudoers rule from `/usr/bin/pam-certauth execute *` to `/usr/bin/pam-certauth-execute *`."
            );
            ExitCode::from(2)
        }
        Cmd::Policy(args) => policy_cmd::run(args),
        Cmd::Gc(args) => gc_cmd::run(args),
    }
}
