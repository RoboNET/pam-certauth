//! `pam-certauth` entry point.
//!
//! Thin clap dispatcher: every subcommand's lifecycle lives in its own
//! library module (see `pam_certauth_cli::daemon` for the monitor daemon).
//! Phases 7 / 8 of the scopes & M-of-N plan add `execute`, `policy`, … as
//! sibling subcommands; their wiring should follow the same pattern.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use pam_certauth_cli::daemon::{self, DaemonArgs};
use pam_certauth_cli::execute;
use pam_certauth_cli::gc_cmd::{self, GcArgs};
use pam_certauth_cli::logging;
use pam_certauth_cli::policy_cmd::{self, PolicyArgs};

#[derive(Debug, Parser)]
#[command(name = "pam-certauth", version, about = "PAM CertAuth control plane")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run the monitor daemon (USB / logind enforcement, IPC server).
    Daemon(DaemonArgs),
    /// Execute a scoped command under policy + CMS work-order authorisation.
    Execute(execute::cli::ExecuteArgs),
    /// Inspect a `policy.toml` (validate / explain effective rule).
    Policy(PolicyArgs),
    /// Sweep the work-order retention store; delete entries older than
    /// `--retention-days` days (default 90).
    Gc(GcArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Initialise tracing once for every subcommand so audit events
    // (`execute_start`, `execute_done`, `execute_denied`, GC sweep,
    // policy explain, …) land in journald uniformly — not just when
    // we run as a systemd unit child.  `daemon::run_async` calls
    // `logging::init` again; the OnceLock guard inside makes that a
    // no-op.  Failure is logged to stderr and the process continues
    // — tracing is best-effort, not a hard prereq.
    if let Err(e) = logging::init() {
        eprintln!("pam-certauth: failed to initialise tracing: {e:#}");
    }
    match cli.cmd {
        Cmd::Daemon(args) => daemon::run(args),
        Cmd::Execute(args) => execute::run(args),
        Cmd::Policy(args) => policy_cmd::run(args),
        Cmd::Gc(args) => gc_cmd::run(args),
    }
}
