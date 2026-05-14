use pam_certauth_policy::Policy;
use std::fs;
use std::path::PathBuf;

fn write_tmp(contents: &str) -> PathBuf {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("policy.toml");
    fs::write(&p, contents).unwrap();
    // We intentionally leak the TempDir: Policy::load reads the file
    // synchronously and returns owned data, but callers want the path to
    // still be valid until the test ends (no borrow of `dir` propagates,
    // so RAII Drop would otherwise unlink before assertions read it).
    // The leak is bounded by the test binary's process lifetime.
    #[allow(
        clippy::mem_forget,
        reason = "test helper: bounded leak of TempDir to keep on-disk path \
                  alive until end of test; no fds/locks/secrets in TempDir."
    )]
    std::mem::forget(dir);
    p
}

#[test]
fn sha256_is_stable_across_loads() {
    let p1 = Policy::load(&write_tmp("[defaults]\nm_of_n = 1\n")).unwrap();
    let p2 = Policy::load(&write_tmp("[defaults]\nm_of_n = 1\n")).unwrap();
    assert_eq!(p1.sha256(), p2.sha256());
}

#[test]
fn sha256_changes_on_trailing_newline() {
    let p1 = Policy::load(&write_tmp("[defaults]\nm_of_n = 1")).unwrap();
    let p2 = Policy::load(&write_tmp("[defaults]\nm_of_n = 1\n")).unwrap();
    assert_ne!(p1.sha256(), p2.sha256());
}
