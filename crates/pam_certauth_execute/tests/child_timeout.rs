//! Integration test for the child-timeout watchdog.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::time::Duration;

use pam_certauth_execute::child::{run_child_with_timeout, TIMEOUT_EXIT_CODE};

#[test]
fn timeout_sends_sigterm_then_sigkill() {
    let cwd = std::env::current_dir().expect("cwd");
    let sleep_bin = if std::path::Path::new("/bin/sleep").exists() {
        std::path::PathBuf::from("/bin/sleep")
    } else {
        std::path::PathBuf::from("/usr/bin/sleep")
    };

    let r = run_child_with_timeout(
        &sleep_bin,
        &["10".to_string()],
        HashMap::new(),
        cwd,
        Some(Duration::from_millis(500)),
    )
    .expect("spawn sleep");

    assert_eq!(
        r.exit_code, TIMEOUT_EXIT_CODE,
        "expected timeout exit code 124, got {}",
        r.exit_code
    );
}
