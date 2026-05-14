//! Compile-only smoke for `ParsecBackend::new` and the `parsec_capget`
//! self-check.  Real behaviour is verified on the Astra VM via `test-mac.sh`
//! (Phase 10 E2E).
#![cfg(feature = "astra-mac")]
#![allow(missing_docs)]

#[test]
fn parsec_backend_new_compiles() {
    // Cannot actually call `new()` on a Mac dev box (no libpdp linker
    // target), but ensure the type and constructor exist.
    let _ctor: fn() -> pam_certauth_core::mac::ParsecBackend =
        pam_certauth_core::mac::ParsecBackend::new;
    let _ = std::any::TypeId::of::<pam_certauth_core::mac::ParsecBackend>();
}
