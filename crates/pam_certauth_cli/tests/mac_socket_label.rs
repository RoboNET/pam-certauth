//! Phase 6 — verify that `server::bind_with_label` labels the per-PID
//! temp socket via `MacBackend::set_file_label` with `level=0` and
//! `irelax=true` BEFORE the atomic rename onto the final path.

#![cfg(feature = "mac-tests")]
#![allow(clippy::unwrap_used)]

use pam_certauth_core::mac::backend::MockMacBackend;

#[test]
fn bind_calls_set_file_label_with_irelax_before_rename() {
    let tmp = tempfile::tempdir().unwrap();
    let final_path = tmp.path().join("monitord.sock");
    let mut mock = MockMacBackend::new();
    mock.expect_set_file_label()
        .withf(|p, l, irelax| {
            let name_ok = p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".tmp."));
            name_ok && l.level == 0 && l.categories == 0 && *irelax
        })
        .return_once(|_, _, _| Ok(()));

    pam_certauth_cli::server::bind_with_label(&final_path, &mock).unwrap();
    assert!(final_path.exists(), "final socket path must exist post-rename");
}
