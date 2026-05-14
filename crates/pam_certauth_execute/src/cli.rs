//! `pam-certauth execute` CLI argument parsing.

use std::path::PathBuf;

use clap::Args;

/// Arguments for the `execute` subcommand.
///
/// Without `--scope`, the binary runs in *explain* mode (Task 7.8). With
/// `--scope` plus an optional CMS `--work-order` it performs an authorised
/// invocation of the command supplied after `--`.
#[derive(Args, Debug, Clone)]
pub struct ExecuteArgs {
    /// Scope name (e.g. `bios.flash`). Required for enforcement mode.
    #[arg(long)]
    pub scope: Option<String>,

    /// Path to a CMS-signed work-order file.
    #[arg(long)]
    pub work_order: Option<PathBuf>,

    /// Command and arguments to execute, supplied after `--`.
    #[arg(last = true, required = true)]
    pub cmd: Vec<String>,
}
