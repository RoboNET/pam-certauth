//! Mandatory Access Control (МКЦ) integration: types, traits, FFI/stub.
//!
//! See `docs/superpowers/specs/2026-05-14-mac-integrity-design.md`.

pub mod audit;
pub mod backend;
pub mod label;
#[cfg(not(feature = "astra-mac"))]
mod stub;

pub use backend::{MacBackend, MacError, MacRuntime};
pub use label::IntegrityLabel;
