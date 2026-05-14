use pam_certauth_policy::Policy;
use std::fs;
use std::path::PathBuf;

fn write_tmp(contents: &str) -> PathBuf {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("policy.toml");
    fs::write(&p, contents).unwrap();
    std::mem::forget(dir); // не удалять до конца теста
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
