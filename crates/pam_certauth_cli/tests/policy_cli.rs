//! Integration tests for `pam-certauth policy {validate,explain}`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pam-certauth")
}

#[test]
fn validate_accepts_well_formed_policy() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("policy.toml");
    std::fs::write(
        &p,
        "[defaults]\nm_of_n = 1\n[scope.\"bios.flash\"]\nm_of_n = 2\n",
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["policy", "validate", "--path"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("OK:"), "stdout={stdout}");
}

#[test]
fn validate_rejects_zero_m_of_n() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("policy.toml");
    std::fs::write(&p, "[scope.\"x\"]\nm_of_n = 0\n").unwrap();

    let out = Command::new(bin())
        .args(["policy", "validate", "--path"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ERROR"), "stderr={stderr}");
}

#[test]
fn explain_prints_effective_rule() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("policy.toml");
    std::fs::write(
        &p,
        "[defaults]\nm_of_n = 1\n[scope.\"bios.*\"]\nm_of_n = 3\n[scope.\"bios.flash\"]\nm_of_n = 2\n",
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["policy", "explain", "--scope", "bios.flash", "--path"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Effective rule for"), "stdout={stdout}");
    assert!(stdout.contains("m_of_n              = 2"), "stdout={stdout}");
}

#[test]
fn explain_falls_back_to_wildcard() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("policy.toml");
    std::fs::write(
        &p,
        "[defaults]\nm_of_n = 1\n[scope.\"bios.*\"]\nm_of_n = 3\n",
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["policy", "explain", "--scope", "bios.erase", "--path"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("m_of_n              = 3"), "stdout={stdout}");
}

#[test]
fn explain_reports_load_error() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("nope.toml");
    let out = Command::new(bin())
        .args(["policy", "explain", "--scope", "x", "--path"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(2));
}
