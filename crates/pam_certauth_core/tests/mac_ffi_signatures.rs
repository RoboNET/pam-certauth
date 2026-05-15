//! Compile-only smoke for the libpdp FFI surface.  Real behaviour is
//! verified on the Astra VM via `test-mac.sh` (Phase 10 E2E).
#![cfg(feature = "astra-mac")]
#![allow(missing_docs)]

#[test]
fn ffi_surface_compiles() {
    // Forcing a reference to `probe_runtime` keeps the FFI module wired
    // into the test binary; real execution is gated on Astra (libpdp).
    let _ =
        pam_certauth_core::mac::ffi::probe_runtime as fn() -> pam_certauth_core::mac::MacRuntime;
}
