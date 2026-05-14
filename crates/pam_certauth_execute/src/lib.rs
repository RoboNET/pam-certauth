//! `pam_certauth_execute` — standalone library backing the
//! `pam-certauth-execute` root-privileged binary.
//!
//! This crate is the M-of-N work-order execute path that was previously
//! the `execute` subcommand of `pam-certauth`. Splitting it out of the
//! daemon binary keeps the dependency closure of the privileged path
//! minimal: no zbus, no udev, no DBus, no multi-thread tokio runtime —
//! only the synchronous CMS verifier, IPC client, and CLI surface.
//!
//! The library surface is kept so integration tests can exercise the
//! orchestrator and child watchdog without spawning the binary.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::manual_let_else,
    clippy::single_match_else,
    clippy::match_wildcard_for_single_variants
)]

// Scaffolding commit — modules are added incrementally in the next
// commit. The crate compiles as an empty library + a binary that
// prints an explanatory message until the move lands.
