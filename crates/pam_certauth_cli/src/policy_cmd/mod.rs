//! `pam-certauth policy` subcommand: load + introspect a `policy.toml`.
//!
//! Two operations:
//!
//! - `validate` — parse + run [`pam_certauth_policy::Policy::validate`]; exit
//!   `0` on success, `2` on parse/validation error.
//! - `explain`  — print the *effective* [`pam_certauth_policy::ScopeRule`]
//!   produced by merging `[defaults]` with the closest matching `[scope.*]`
//!   block (exact > prefix wildcard > defaults).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

/// Top-level args for `pam-certauth policy`.
#[derive(Args, Debug, Clone)]
pub struct PolicyArgs {
    /// Operation to perform.
    #[command(subcommand)]
    pub cmd: PolicySubcommand,
}

/// `validate` or `explain`.
#[derive(Subcommand, Debug, Clone)]
pub enum PolicySubcommand {
    /// Parse and validate a `policy.toml` file.
    Validate {
        /// Path to the policy file.
        #[arg(long, default_value = "/etc/pam_certauth/policy.toml")]
        path: PathBuf,
    },
    /// Print the effective rule for a scope after merge with defaults +
    /// wildcards.
    Explain {
        /// Scope name to resolve (e.g. `bios.flash`).
        #[arg(long)]
        scope: String,
        /// Path to the policy file.
        #[arg(long, default_value = "/etc/pam_certauth/policy.toml")]
        path: PathBuf,
    },
}

/// Exit code reserved for `policy` operational failures (load / parse /
/// validate). `0` is reserved for success.
const EXIT_POLICY_ERR: u8 = 2;

/// Dispatch a parsed `PolicyArgs` to the right sub-handler.
#[must_use]
pub fn run(args: PolicyArgs) -> ExitCode {
    match args.cmd {
        PolicySubcommand::Validate { path } => match pam_certauth_policy::Policy::load(&path) {
            Ok(_) => {
                println!("OK: policy at {} parses and validates", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("ERROR: {e}");
                ExitCode::from(EXIT_POLICY_ERR)
            }
        },
        PolicySubcommand::Explain { scope, path } => {
            match pam_certauth_policy::Policy::load(&path) {
                Ok(policy) => {
                    let rule = policy.rule_for(&scope);
                    println!("Effective rule for {scope:?}:");
                    println!("  m_of_n              = {}", rule.m_of_n);
                    println!("  require_argv_pattern= {}", rule.require_argv_pattern);
                    println!("  forbid_self_approval= {}", rule.forbid_self_approval);
                    println!(
                        "  require_timestamp_token = {}",
                        rule.require_timestamp_token
                    );
                    println!("  audit_level         = {:?}", rule.audit_level);
                    println!("  pre_hooks           = {:?}", rule.pre_hooks);
                    println!("  post_hooks          = {:?}", rule.post_hooks);
                    println!("  timeout_seconds     = {:?}", rule.timeout_seconds);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("ERROR loading policy: {e}");
                    ExitCode::from(EXIT_POLICY_ERR)
                }
            }
        }
    }
}
