//! `pam-certauth-execute` binary entry point.
//!
//! See `lib.rs` for the architectural rationale. This file is a thin
//! shim: it parses the top-level CLI (which has *no* subcommands —
//! the binary IS execute), initialises tracing, and dispatches to
//! `pam_certauth_execute::run`.
//!
//! Scaffolding commit: the actual orchestration logic is moved into
//! this crate in the next commit. Today the binary just prints a stub.

fn main() -> std::process::ExitCode {
    eprintln!(
        "pam-certauth-execute: scaffolded but not yet wired (refactor in progress)"
    );
    std::process::ExitCode::from(2)
}
