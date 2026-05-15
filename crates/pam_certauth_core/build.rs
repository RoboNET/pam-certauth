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
        // Text/label-API (`pdpl_get_from_text`, `pdpl_put`, `pdp_set_pid`,
        // `pdp_set_fd`, `pdp_set_path`, `pdp_get_lpath`, `pdpl_get_text`)
        // живёт в libpdp.so.
        // NB: `pdp_set_current` — inline-обёртка в pdp.h над `pdp_set_pid(0, l)`,
        // символа в .so нет — вызываем `pdp_set_pid` напрямую (spec §4.1).
        println!("cargo:rustc-link-lib=pdp");
        // `parsec_capget` лежит в libparsec-base.so, НЕ в libpdp.so —
        // verified Astra CI 2026-05-15 (ubi18:latest container,
        // run 25903325006: linker error `undefined symbol: parsec_capget`
        // при линковке только с `-lpdp`; `nm -D /usr/lib/libparsec-base.so*`
        // показывает экспортируемый `parsec_capget`). См. spec §C.5.
        println!("cargo:rustc-link-lib=parsec-base");
        // MIC name lookups (`getmicnam`, `freemicent_r`) живут в
        // libparsec-mic.so.3 — verified `dpkg -S getmicnam` →
        // libparsec-mic3-dev на Astra 1.8.4. Без явного `-lparsec-mic`
        // pam_certauth.so загружается, но dlopen падает с
        // `undefined symbol: getmicnam`, и pamtester репортит
        // "Module is unknown".
        println!("cargo:rustc-link-lib=parsec-mic");
    }
}
