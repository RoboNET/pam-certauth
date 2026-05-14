//! Build script for `pam_certauth_core`.
//!
//! Emits a `cargo:rustc-link-lib=pdp` directive when the `astra-mac` feature
//! is enabled so the crate links against Astra Linux's `libpdp.so` for the
//! МКЦ (mandatory integrity control) FFI surface.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "astra-mac")]
    {
        // Реальная shared library — libpdp. Подтверждено demo-рецептом
        // в docs.astralinux.ru/.../szi/api/demo/label/ (compile-команда
        // `gcc -o pdp_set_get_path pdp_set_get_path.c -lpdp`).
        // Text-API (`pdpl_get_from_text`, `pdpl_put`, `pdp_set_pid`,
        // `pdp_set_fd`, `pdp_set_path`, `pdp_get_lpath`, `pdpl_get_text`,
        // `getmicnam`, `freemicent_r`) живёт в libpdp.so.
        // NB: `pdp_set_current` — inline-обёртка в pdp.h над `pdp_set_pid(0, l)`,
        // символа в .so нет — вызываем `pdp_set_pid` напрямую (spec §4.1).
        println!("cargo:rustc-link-lib=pdp");
    }
}
