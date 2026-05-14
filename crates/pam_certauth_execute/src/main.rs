//! `pam-certauth-execute` binary entry point.
//!
//! Thin top-level CLI (no subcommands — the binary IS execute). Parses
//! [`pam_certauth_execute::cli::ExecuteArgs`] flat at the root,
//! initialises tracing so the very first `execute_attempt` audit event
//! inside the orchestrator already has a subscriber attached, then
//! dispatches into [`pam_certauth_execute::run`].

#![warn(clippy::let_underscore_must_use)]

use std::process::ExitCode;

use clap::Parser;

use pam_certauth_execute::cli::ExecuteArgs;

/// Top-level CLI for the privileged execute binary.
///
/// Mirrors the surface the old `pam-certauth execute` accepted; the
/// only shape change is the binary itself, not the flag set.
#[derive(Debug, Parser)]
#[command(
    name = "pam-certauth-execute",
    version,
    about = "Execute a scoped command under policy + CMS work-order authorisation"
)]
struct Cli {
    #[command(flatten)]
    args: ExecuteArgs,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // ORDERING REQUIREMENT: tracing must be initialised BEFORE we hand
    // control to the orchestrator. The very first I/O-free statement in
    // `run` emits the `execute_attempt` audit event; if tracing weren't
    // yet attached, that event would drop on the floor — defeating the
    // entire point of the early-emit forensic guarantee.
    if let Err(e) = pam_certauth_execute::logging::init() {
        eprintln!("pam-certauth-execute: failed to initialise tracing: {e:#}");
    }
    pam_certauth_execute::run(cli.args)
}
