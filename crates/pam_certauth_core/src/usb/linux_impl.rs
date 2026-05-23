//! Linux-only udev backend for [`super::wait_for_usb`] and
//! [`super::UdevEnumerator`].
//!
//! Only compiled on `cfg(target_os = "linux")`.  Splitting it out keeps
//! `mod.rs` readable on non-Linux hosts (such as the maintainers' macOS dev
//! boxes) and avoids leaking udev types into the public surface.

use super::partition::{select_partition, PartitionCandidate};
use super::{UsbDevice, UsbError};
use std::ffi::OsStr;
use std::os::fd::AsFd;
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
        let remaining_ms = u16::try_from(remaining.as_millis()).unwrap_or(u16::MAX);

        // Drain whatever is already queued without blocking.
        for event in socket.iter() {
            if event.event_type() == udev::EventType::Add {
                let dev_ref = event.device();
                if dev_ref
                    .property_value("ID_BUS")
                    .is_some_and(|v| v == OsStr::new("usb"))
                {
                    if let Some(dev) = device_from(&dev_ref, vid_pid_filter)? {
                        return Ok(dev);
                    }
                }
            }
        }

        // Block on the monitor FD.
        let socket_fd = socket.as_fd();
        let mut pollfds = [nix::poll::PollFd::new(
            socket_fd,
            nix::poll::PollFlags::POLLIN,
        )];
        match nix::poll::poll(&mut pollfds, nix::poll::PollTimeout::from(remaining_ms)) {
            Ok(0) => return Err(UsbError::Timeout),
            Ok(_) | Err(nix::errno::Errno::EINTR) => {
                // loop back, drain queue / restart on EINTR
            }
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
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty());

    // Partition-table fallback: whole-device has no FS but is a
    // `DEVTYPE=disk` node — scan child partitions for the PAMCERT label.
    let (devnode, fs_type) = if fs_type.is_none() && is_whole_disk(d) {
        tracing::info!(
            target: "pam_certauth.usb",
            parent_devnode = %devnode.display(),
            "whole-device has no FS, scanning partitions for label=PAMCERT",
        );
        match collect_partition_candidates(d) {
            Ok(candidates) => match select_partition(None, &devnode, &candidates) {
                Ok(Some(picked)) => {
                    let part_fs = picked.fs_type.clone();
                    tracing::info!(
                        target: "pam_certauth.usb",
                        partition_devnode = %picked.devnode.display(),
                        fs_type = part_fs.as_deref().unwrap_or("(unknown)"),
                        "found PAMCERT partition",
                    );
                    (picked.devnode.clone(), part_fs)
                }
                Ok(None) => (devnode, None),
                Err(e) => {
                    if let UsbError::AmbiguousPartition {
                        devnode: ref dn,
                        count,
                    } = e
                    {
                        tracing::warn!(
                            target: "pam_certauth.usb",
                            parent_devnode = %dn.display(),
                            count,
                            "multiple PAMCERT partitions found; refusing to guess",
                        );
                    }
                    return Err(e);
                }
            },
            Err(e) => {
                tracing::warn!(
                    target: "pam_certauth.usb",
                    parent_devnode = %devnode.display(),
                    error = %e,
                    "failed to enumerate child partitions",
                );
                (devnode, None)
            }
        }
    } else {
        (devnode, fs_type)
    };

    Ok(Some(UsbDevice {
        devnode,
        serial,
        vid,
        pid,
        fs_type,
    }))
}

/// `true` when the udev device is a whole-disk node (`DEVTYPE=disk`),
/// suitable for the partition-table fallback.
fn is_whole_disk(d: &udev::Device) -> bool {
    d.property_value("DEVTYPE")
        .is_some_and(|v| v == OsStr::new("disk"))
}

/// Enumerate child partition nodes of `parent` and convert them to pure
/// [`PartitionCandidate`] records suitable for [`select_partition`].
fn collect_partition_candidates(
    parent: &udev::Device,
) -> Result<Vec<PartitionCandidate>, UsbError> {
    let mut e = udev::Enumerator::new().map_err(|e| UsbError::Udev(e.to_string()))?;
    e.match_subsystem("block")
        .map_err(|e| UsbError::Udev(e.to_string()))?;
    e.match_parent(parent)
        .map_err(|e| UsbError::Udev(e.to_string()))?;

    let mut out = Vec::new();
    for child in e
        .scan_devices()
        .map_err(|e| UsbError::Udev(e.to_string()))?
    {
        // Skip the parent itself; we only want partitions.
        let is_partition = child
            .property_value("DEVTYPE")
            .is_some_and(|v| v == OsStr::new("partition"));
        if !is_partition {
            continue;
        }
        let Some(devnode) = child.devnode() else {
            continue;
        };
        let fs_type = child
            .property_value("ID_FS_TYPE")
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty());
        let fs_label = child
            .property_value("ID_FS_LABEL")
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty());
        out.push(PartitionCandidate {
            devnode: devnode.to_path_buf(),
            fs_type,
            fs_label,
        });
    }
    Ok(out)
}

fn parse_hex16(v: Option<&OsStr>) -> Result<u16, UsbError> {
    let s = v
        .and_then(|s| s.to_str())
        .ok_or_else(|| UsbError::MissingProperty("ID_VENDOR_ID/ID_MODEL_ID".to_string()))?;
    u16::from_str_radix(s, 16)
        .map_err(|_| UsbError::MissingProperty(format!("malformed hex VID/PID: {s}")))
}
