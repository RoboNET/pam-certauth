//! Mandatory Access Control (МКЦ) integration: types, traits, FFI/stub.
//!
//! See `docs/superpowers/specs/2026-05-14-mac-integrity-design.md`.

pub mod audit;
pub mod backend;
pub mod label;
#[cfg(not(feature = "astra-mac"))]
mod stub;

#[cfg(feature = "mac-tests")]
pub use backend::MockMacBackend;
pub use backend::{MacBackend, MacError, MacRuntime, StubBackend};
pub use label::IntegrityLabel;
