//! Integration tests against the real udev backend.
//!
//! These are gated by `#[ignore]` because they require Linux + a real USB
//! block device.  Run manually:
//!
//! ```bash
//! cargo test -p pam_certauth_core --test usb_real -- --ignored
//! ```

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use pam_certauth_core::usb::{wait_for_usb, UsbError};
use std::time::Duration;

#[test]
#[ignore = "requires Linux + a real plugged-in USB block device"]
fn waits_and_returns_device() {
    let dev = wait_for_usb(Duration::from_secs(30), None).expect("device");
    assert!(!dev.devnode.as_os_str().is_empty());
}

#[test]
#[ignore = "no device — short timeout exercises the timeout path"]
fn timeouts_when_no_device() {
    let err = wait_for_usb(Duration::from_millis(200), Some((0xDEAD, 0xBEEF))).unwrap_err();
    assert!(matches!(err, UsbError::Timeout));
}
