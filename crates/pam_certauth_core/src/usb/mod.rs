//! USB block-device discovery.
//!
//! Two-phase strategy:
//!
//! 1. **Enumerate** already-attached USB block devices (sync, fast path).
//! 2. **Monitor** for new "add" events until either a match shows up or the
//!    caller-supplied timeout elapses.
//!
//! On non-Linux platforms the public API surface is preserved but every
//! call returns [`UsbError::UnsupportedPlatform`].
//!
//! Tests that need not bind to real udev should plug a mock implementation
//! of [`UsbEnumerator`] into [`wait_for_usb_with`].

pub mod error;

#[cfg(target_os = "linux")]
mod linux_impl;

pub use error::UsbError;

use std::path::PathBuf;
use std::time::Duration;

/// A USB block device discovered through udev.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDevice {
    /// `/dev/...` device node.
    pub devnode: PathBuf,
    /// Best-effort serial number (`ID_SERIAL_SHORT` or `ID_SERIAL`).
    pub serial: Option<String>,
    /// USB Vendor ID (parsed from hex).
    pub vid: u16,
    /// USB Product ID (parsed from hex).
    pub pid: u16,
    /// Filesystem type as reported by blkid/udev (`vfat`, `ext4`, ...).
    pub fs_type: Option<String>,
}

/// Pluggable USB enumerator.
///
/// The production implementation calls into `udev::Enumerator`.  Tests use
/// [`MockEnumerator`] to inject a fixed list of devices without touching the
/// real udev database.
pub trait UsbEnumerator {
    /// Enumerate USB block devices currently attached to the system.
    ///
    /// `vid_pid_filter`, when set, restricts the result to devices whose
    /// `(vid, pid)` matches exactly.
    ///
    /// # Errors
    ///
    /// Returns [`UsbError::Udev`] on udev failures, [`UsbError::Io`] on raw
    /// I/O failures and [`UsbError::MissingProperty`] when a device record
    /// is too partial to be useful.
    fn enumerate(&self, vid_pid_filter: Option<(u16, u16)>) -> Result<Vec<UsbDevice>, UsbError>;
}

/// Default Linux enumerator backed by `udev::Enumerator`.
///
/// On non-Linux platforms `enumerate` always returns
/// [`UsbError::UnsupportedPlatform`].
#[derive(Debug, Default)]
pub struct UdevEnumerator;

impl UsbEnumerator for UdevEnumerator {
    fn enumerate(&self, vid_pid_filter: Option<(u16, u16)>) -> Result<Vec<UsbDevice>, UsbError> {
        #[cfg(target_os = "linux")]
        {
            linux_impl::enumerate_once(vid_pid_filter)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = vid_pid_filter;
            Err(UsbError::UnsupportedPlatform)
        }
    }
}

/// Mock enumerator for unit tests.
///
/// Returns a copy of its `devices` field, applying the optional VID/PID
/// filter.  `mode` controls one-shot failure modes useful for test cases
/// (e.g. simulating a transient udev error).
#[derive(Debug, Clone, Default)]
pub struct MockEnumerator {
    /// Pre-canned device list to return.
    pub devices: Vec<UsbDevice>,
    /// Optional canned error.  When set, [`UsbEnumerator::enumerate`] returns
    /// an error string identical to this value (wrapped in
    /// [`UsbError::Udev`]) instead of the device list.
    pub error: Option<String>,
}

impl UsbEnumerator for MockEnumerator {
    fn enumerate(&self, vid_pid_filter: Option<(u16, u16)>) -> Result<Vec<UsbDevice>, UsbError> {
        if let Some(msg) = &self.error {
            return Err(UsbError::Udev(msg.clone()));
        }
        let out: Vec<UsbDevice> = self
            .devices
            .iter()
            .filter(|d| match vid_pid_filter {
                Some((v, p)) => d.vid == v && d.pid == p,
                None => true,
            })
            .cloned()
            .collect();
        Ok(out)
    }
}

/// Wait for a USB block device, optionally filtered by `(vid, pid)`.
///
/// On Linux this enumerates currently attached devices and then falls back
/// to a blocking udev monitor with the caller's `timeout` budget.  On
/// non-Linux platforms it returns [`UsbError::UnsupportedPlatform`]
/// immediately.
///
/// # Errors
///
/// - [`UsbError::Timeout`] — no matching device within `timeout`.
/// - [`UsbError::Udev`] / [`UsbError::Io`] — propagated from udev.
/// - [`UsbError::UnsupportedPlatform`] — on non-Linux targets.
pub fn wait_for_usb(
    timeout: Duration,
    vid_pid_filter: Option<(u16, u16)>,
) -> Result<UsbDevice, UsbError> {
    #[cfg(target_os = "linux")]
    {
        linux_impl::wait_for_usb_real(timeout, vid_pid_filter)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (timeout, vid_pid_filter);
        Err(UsbError::UnsupportedPlatform)
    }
}

/// Test-friendly sibling of [`wait_for_usb`].
///
/// Polls `enumerator.enumerate(filter)` repeatedly with a short sleep until
/// a device shows up or `timeout` expires.  Used by unit tests where the
/// real udev monitor is unavailable.
///
/// # Errors
///
/// As [`wait_for_usb`].  Additionally surfaces enumerator errors verbatim.
pub fn wait_for_usb_with<E: UsbEnumerator>(
    enumerator: &E,
    timeout: Duration,
    vid_pid_filter: Option<(u16, u16)>,
    poll_interval: Duration,
) -> Result<UsbDevice, UsbError> {
    use std::time::Instant;
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        match enumerator.enumerate(vid_pid_filter)? {
            ref devs if !devs.is_empty() => {
                // Take the first match; iteration order is enumerator-defined.
                #[allow(clippy::indexing_slicing)]
                return Ok(devs[0].clone());
            }
            _ => {}
        }
        if now >= deadline {
            return Err(UsbError::Timeout);
        }
        let remaining = deadline.saturating_duration_since(now);
        std::thread::sleep(std::cmp::min(poll_interval, remaining));
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn device(vid: u16, pid: u16, fs: &str) -> UsbDevice {
        UsbDevice {
            devnode: PathBuf::from(format!("/dev/sd{vid:x}{pid:x}")),
            serial: Some(format!("S-{vid:x}-{pid:x}")),
            vid,
            pid,
            fs_type: Some(fs.to_string()),
        }
    }

    #[test]
    fn mock_enumerator_filters_by_vid_pid() {
        let m = MockEnumerator {
            devices: vec![device(0x1, 0x2, "vfat"), device(0x3, 0x4, "ext4")],
            error: None,
        };
        let out = m.enumerate(Some((0x3, 0x4))).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].vid, 0x3);
        assert_eq!(out[0].pid, 0x4);
    }

    #[test]
    fn mock_enumerator_no_filter_returns_all() {
        let m = MockEnumerator {
            devices: vec![device(0x1, 0x2, "vfat"), device(0x3, 0x4, "ext4")],
            error: None,
        };
        let out = m.enumerate(None).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn wait_for_usb_with_returns_device_quickly() {
        let m = MockEnumerator {
            devices: vec![device(0x1, 0x2, "vfat")],
            error: None,
        };
        let start = std::time::Instant::now();
        let dev = wait_for_usb_with(
            &m,
            Duration::from_secs(5),
            Some((0x1, 0x2)),
            Duration::from_millis(10),
        )
        .unwrap();
        assert_eq!(dev.vid, 0x1);
        assert!(start.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn wait_for_usb_with_picks_first_when_multiple_match() {
        let m = MockEnumerator {
            devices: vec![device(0x1, 0x2, "vfat"), device(0x1, 0x2, "ext4")],
            error: None,
        };
        let dev = wait_for_usb_with(
            &m,
            Duration::from_millis(100),
            Some((0x1, 0x2)),
            Duration::from_millis(10),
        )
        .unwrap();
        // First in enumeration order.
        assert_eq!(dev.fs_type.as_deref(), Some("vfat"));
    }

    #[test]
    fn wait_for_usb_with_times_out_when_empty() {
        let m = MockEnumerator {
            devices: vec![],
            error: None,
        };
        let start = std::time::Instant::now();
        let err = wait_for_usb_with(
            &m,
            Duration::from_millis(100),
            None,
            Duration::from_millis(20),
        )
        .unwrap_err();
        assert!(matches!(err, UsbError::Timeout));
        assert!(start.elapsed() >= Duration::from_millis(100));
        // Sanity: should not run forever.
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn wait_for_usb_with_filter_excludes_non_matching() {
        let m = MockEnumerator {
            devices: vec![device(0x9, 0x9, "vfat")],
            error: None,
        };
        let err = wait_for_usb_with(
            &m,
            Duration::from_millis(80),
            Some((0x1, 0x2)),
            Duration::from_millis(20),
        )
        .unwrap_err();
        assert!(matches!(err, UsbError::Timeout));
    }

    #[test]
    fn wait_for_usb_with_propagates_enumerator_error() {
        let m = MockEnumerator {
            devices: vec![],
            error: Some("simulated".into()),
        };
        let err = wait_for_usb_with(
            &m,
            Duration::from_millis(100),
            None,
            Duration::from_millis(10),
        )
        .unwrap_err();
        match err {
            UsbError::Udev(s) => assert_eq!(s, "simulated"),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
