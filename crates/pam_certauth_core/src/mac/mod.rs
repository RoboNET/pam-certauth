//! Mandatory Access Control (МКЦ) integration: types, traits, FFI/stub.
//!
//! See `docs/superpowers/specs/2026-05-14-mac-integrity-design.md`.

pub mod audit;
pub mod backend;
#[cfg(feature = "astra-mac")]
pub mod ffi;
pub mod label;
#[cfg(not(feature = "astra-mac"))]
mod stub;
pub(crate) mod text_codec;

#[cfg(feature = "mac-tests")]
pub use backend::MockMacBackend;
#[cfg(feature = "astra-mac")]
pub use backend::ParsecBackend;
pub use backend::{MacBackend, MacError, MacRuntime, StubBackend};
pub use label::IntegrityLabel;
