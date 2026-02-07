//! Integration tests for `pam-certauth gc`.
//!
//! Uses the `PAM_CERTAUTH_RETENTION_DIR` env override to point the CLI at
//! a temp directory so the test never touches `/var/lib`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_wrap,
    clippy::duration_suboptimal_units,
    unsafe_code
)]

use std::process::Command;
use std::time::{Duration, SystemTime};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pam-certauth")
}

fn set_mtime(path: &std::path::Path, t: SystemTime) {
    let secs = t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let tv = libc::timeval {
        tv_sec: secs as libc::time_t,
        tv_usec: 0,
    };
    let times = [tv, tv];
    let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let rc = unsafe { libc::utimes(cpath.as_ptr(), times.as_ptr()) };
    assert_eq!(rc, 0, "utimes failed");
}

#[test]
fn gc_removes_old_cms_files() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("aaaa.cms");
    let fresh = dir.path().join("bbbb.cms");
    std::fs::write(&old, b"old").unwrap();
    std::fs::write(&fresh, b"fresh").unwrap();

    // Backdate "old" by 100 days.
    let hundred = SystemTime::now() - Duration::from_secs(100 * 86_400);
    set_mtime(&old, hundred);

    let out = Command::new(bin())
        .env("PAM_CERTAUTH_RETENTION_DIR", dir.path())
        .args(["gc", "--retention-days", "90"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("removed 1"), "stdout={stdout}");
    assert!(!old.exists());
    assert!(fresh.exists());
}

#[test]
fn gc_with_default_retention_does_not_touch_fresh_files() {
    let dir = tempfile::tempdir().unwrap();
    let fresh = dir.path().join("cccc.cms");
    std::fs::write(&fresh, b"fresh").unwrap();

    let out = Command::new(bin())
        .env("PAM_CERTAUTH_RETENTION_DIR", dir.path())
        .args(["gc"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("removed 0"), "stdout={stdout}");
    assert!(fresh.exists());
}
