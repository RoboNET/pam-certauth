//! Placeholder backend types.  Populated in Phase 3.

use thiserror::Error;

/// Errors produced by a `MacBackend`.  Placeholder; final variants live in
/// Phase 3.
#[derive(Debug, Error)]
#[error("placeholder")]
pub struct MacError;

/// Runtime mode of the MAC backend on the current host.
#[derive(Debug, Clone, Copy)]
pub enum MacRuntime {
    /// Backend wired up and operational.
    Active,
    /// Backend present but explicitly disabled.
    Disabled,
    /// Backend not available on this host.
    Unavailable,
}

/// Trait for МКЦ backends.  Placeholder; methods land in Phase 3.
pub trait MacBackend: Send + Sync {}
