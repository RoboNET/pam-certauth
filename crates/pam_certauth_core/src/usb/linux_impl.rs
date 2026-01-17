//! Linux-only udev backend for [`super::wait_for_usb`] and
//! [`super::UdevEnumerator`].
//!
//! Only compiled on `cfg(target_os = "linux")`.  Splitting it out keeps
//! `mod.rs` readable on non-Linux hosts (such as the maintainers' macOS dev
//! boxes) and avoids leaking udev types into the public surface.

use super::{UsbDevice, UsbError};
use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// One-shot enumeration of attached USB block devices.
pub(super) fn enumerate_once(
    vid_pid_filter: Option<(u16, u16)>,
) -> Result<Vec<UsbDevice>, UsbError> {
    let mut e = udev::Enumerator::new().map_err(|e| UsbError::Udev(e.to_string()))?;
    e.match_subsystem("block")
        .map_err(|e| UsbError::Udev(e.to_string()))?;
    e.match_property("ID_BUS", "usb")
        .map_err(|e| UsbError::Udev(e.to_string()))?;

    let mut out = Vec::new();
    let scanned = e
        .scan_devices()
        .map_err(|e| UsbError::Udev(e.to_string()))?;
    for d in scanned {
        if let Some(dev) = device_from(&d, vid_pid_filter)? {
            out.push(dev);
        }
    }
    Ok(out)
}

/// Two-phase wait: enumerate, then monitor "add" events.
pub(super) fn wait_for_usb_real(
    timeout: Duration,
    vid_pid_filter: Option<(u16, u16)>,
) -> Result<UsbDevice, UsbError> {
    // Phase 1 — already attached?
    if let Some(dev) = enumerate_once(vid_pid_filter)?.into_iter().next() {
        return Ok(dev);
    }

    // Phase 2 — block on udev monitor for "add" events.
    let socket = udev::MonitorBuilder::new()
        .map_err(|e| UsbError::Udev(e.to_string()))?
        .match_subsystem("block")
        .map_err(|e| UsbError::Udev(e.to_string()))?
        .listen()
        .map_err(|e| UsbError::Udev(e.to_string()))?;

    let deadline = Instant::now() + timeout;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(UsbError::Timeout);
        }
        let remaining = deadline.saturating_duration_since(now);
        let remaining_ms = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);

        // Drain whatever is already queued without blocking.
        for event in socket.iter() {
            if event.event_type() == udev::EventType::Add {
                let dev_ref = event.device();
                if dev_ref
                    .property_value("ID_BUS")
                    .map(|v| v == OsStr::new("usb"))
                    .unwrap_or(false)
                {
                    if let Some(dev) = device_from(&dev_ref, vid_pid_filter)? {
                        return Ok(dev);
                    }
                }
            }
        }

        // Block on the monitor FD.
        let mut pollfds = [nix::poll::PollFd::new(
            &socket,
            nix::poll::PollFlags::POLLIN,
        )];
        match nix::poll::poll(&mut pollfds, remaining_ms) {
            Ok(0) => return Err(UsbError::Timeout),
            Ok(_) => continue, // loop back, drain queue
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                return Err(UsbError::Io(std::io::Error::from_raw_os_error(e as i32)));
            }
        }
    }
}

fn device_from(
    d: &udev::Device,
    filter: Option<(u16, u16)>,
) -> Result<Option<UsbDevice>, UsbError> {
    let Some(devnode) = d.devnode() else {
        return Ok(None);
    };
    let devnode: PathBuf = devnode.to_path_buf();

    let vid = parse_hex16(d.property_value("ID_VENDOR_ID"))?;
    let pid = parse_hex16(d.property_value("ID_MODEL_ID"))?;

    if let Some((fv, fp)) = filter {
        if vid != fv || pid != fp {
            return Ok(None);
        }
    }

    let serial = d
        .property_value("ID_SERIAL_SHORT")
        .or_else(|| d.property_value("ID_SERIAL"))
        .map(|s| s.to_string_lossy().into_owned());

    let fs_type = d
        .property_value("ID_FS_TYPE")
        .map(|s| s.to_string_lossy().into_owned());

    Ok(Some(UsbDevice {
        devnode,
        serial,
        vid,
        pid,
        fs_type,
    }))
}

fn parse_hex16(v: Option<&OsStr>) -> Result<u16, UsbError> {
    let s = v
        .and_then(|s| s.to_str())
        .ok_or_else(|| UsbError::MissingProperty("ID_VENDOR_ID/ID_MODEL_ID".to_string()))?;
    u16::from_str_radix(s, 16)
        .map_err(|_| UsbError::MissingProperty(format!("malformed hex VID/PID: {s}")))
}
