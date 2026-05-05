//! Integration tests for [`pam_certauth_core::mount::usb`].
//!
//! These require Linux + root + a real block device.  Always `#[ignore]`'d.
//!
//! Run manually with:
//!
//! ```bash
//! sudo -E cargo test -p pam_certauth_core --test mount_usb -- --ignored
//! ```

#![cfg(target_os = "linux")]

use pam_certauth_core::mount::usb::{mount_usb_device, MountError};
use pam_certauth_core::usb::UsbDevice;
use std::path::PathBuf;

#[test]
#[ignore = "requires root + a real USB device with a vfat partition"]
fn mounts_real_device_and_unmounts_on_drop() {
    // Caller must export e.g. CERTAUTH_TEST_DEVNODE=/dev/sdb1.
    let dev_path =
        std::env::var("CERTAUTH_TEST_DEVNODE").expect("set CERTAUTH_TEST_DEVNODE=/dev/sdX to run");
    let dev = UsbDevice {
        devnode: PathBuf::from(dev_path),
        serial: Some("integration".into()),
        vid: 0,
        pid: 0,
        fs_type: Some("vfat".into()),
    };
    let mp = tempfile::tempdir().unwrap();
    {
        let _g = mount_usb_device(&dev, mp.path()).expect("mount");
        // Drop unmounts.
    }
}

#[test]
#[ignore = "requires root + a USB device with an unsupported fs"]
fn rejects_disallowed_fs_on_real_kernel() {
    let dev = UsbDevice {
        devnode: PathBuf::from("/dev/sdX-bogus"),
        serial: None,
        vid: 0,
        pid: 0,
        fs_type: Some("xfs".into()),
    };
    let mp = tempfile::tempdir().unwrap();
    let err = mount_usb_device(&dev, mp.path()).unwrap_err();
    assert!(matches!(err, MountError::UnsupportedFs(_)));
}
