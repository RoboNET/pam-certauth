//! Pure partition-selection helper for the partition-table fallback.
//!
//! Some USB sticks carry a partition table (`DEVTYPE=disk`) where the
//! filesystem lives on a child partition (`DEVTYPE=partition`).  In that
//! case udev reports `ID_FS_TYPE` only on the partition node, not the
//! whole device, so the existing whole-device path fails with
//! `UnsupportedFs("(unknown)")`.
//!
//! [`select_partition`] picks a single PAMCERT-labelled child with an
//! allow-listed FS.  It is deliberately pure — no udev calls — so it can
//! be unit-tested on any platform.
//!
//! Fail-closed: when the parent device already has a filesystem the
//! function returns `Ok(None)` (the caller stays on the whole-device
//! path); when zero partitions match it likewise returns `Ok(None)` (the
//! caller produces the same `UnsupportedFs("(unknown)")` error as before);
//! when more than one partition matches it returns
//! [`UsbError::AmbiguousPartition`] so the operator must clarify intent.

use super::UsbError;
use crate::mount::usb::{ALLOWED_FS, REQUIRED_PARTITION_LABEL};
use std::path::PathBuf;

/// A child-partition record observed under a whole-device USB block.
///
/// Built by the udev backend from `ID_FS_TYPE` / `ID_FS_LABEL` properties
/// of a `DEVTYPE=partition` child node.  Kept minimal so the pure
/// selection logic stays trivially testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionCandidate {
    /// Partition devnode (e.g. `/dev/sdb1`).
    pub devnode: PathBuf,
    /// `ID_FS_TYPE` reported by udev/blkid on the partition itself.
    pub fs_type: Option<String>,
    /// `ID_FS_LABEL` reported by udev/blkid on the partition itself.
    pub fs_label: Option<String>,
}

/// Decide whether a partition-table fallback applies, and, if so, pick
/// the single matching child partition.
///
/// - `parent_fs_type` — `ID_FS_TYPE` reported on the whole-device.  When
///   `Some`, the whole-device already has a filesystem and the caller
///   must NOT fall back (returns `Ok(None)`).
/// - `parent_devnode` — used only to enrich the
///   [`UsbError::AmbiguousPartition`] error.
/// - `partitions` — children of the whole-device with `DEVTYPE=partition`.
///
/// # Errors
///
/// [`UsbError::AmbiguousPartition`] when 2+ partitions match.
pub fn select_partition<'a>(
    parent_fs_type: Option<&str>,
    parent_devnode: &std::path::Path,
    partitions: &'a [PartitionCandidate],
) -> Result<Option<&'a PartitionCandidate>, UsbError> {
    // Whole-device already has a filesystem — caller stays on existing path.
    if parent_fs_type.is_some() {
        return Ok(None);
    }

    let matches: Vec<&PartitionCandidate> = partitions
        .iter()
        .filter(|p| {
            let fs_ok = p
                .fs_type
                .as_deref()
                .is_some_and(|fs| ALLOWED_FS.contains(&fs));
            let label_ok = p.fs_label.as_deref() == Some(REQUIRED_PARTITION_LABEL);
            fs_ok && label_ok
        })
        .collect();

    match matches.len() {
        0 => Ok(None),
        1 => Ok(Some(matches[0])),
        n => Err(UsbError::AmbiguousPartition {
            devnode: parent_devnode.to_path_buf(),
            count: n,
        }),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn part(devnode: &str, fs: Option<&str>, label: Option<&str>) -> PartitionCandidate {
        PartitionCandidate {
            devnode: PathBuf::from(devnode),
            fs_type: fs.map(str::to_string),
            fs_label: label.map(str::to_string),
        }
    }

    fn parent() -> PathBuf {
        PathBuf::from("/dev/sdb")
    }

    #[test]
    fn parent_has_fs_skips_fallback_even_with_matching_partitions() {
        let parts = vec![part("/dev/sdb1", Some("vfat"), Some("PAMCERT"))];
        let res = select_partition(Some("ext4"), &parent(), &parts).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn parent_no_fs_no_partitions_returns_none() {
        let parts: Vec<PartitionCandidate> = vec![];
        let res = select_partition(None, &parent(), &parts).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn parent_no_fs_one_vfat_pamcert_match() {
        let parts = vec![part("/dev/sdb1", Some("vfat"), Some("PAMCERT"))];
        let res = select_partition(None, &parent(), &parts).unwrap();
        assert_eq!(res.unwrap().devnode, PathBuf::from("/dev/sdb1"));
    }

    #[test]
    fn parent_no_fs_one_ext4_pamcert_match() {
        let parts = vec![part("/dev/sdb1", Some("ext4"), Some("PAMCERT"))];
        let res = select_partition(None, &parent(), &parts).unwrap();
        assert_eq!(res.unwrap().devnode, PathBuf::from("/dev/sdb1"));
    }

    #[test]
    fn wrong_label_returns_none() {
        let parts = vec![part("/dev/sdb1", Some("ext4"), Some("OTHER"))];
        let res = select_partition(None, &parent(), &parts).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn wrong_fs_returns_none() {
        let parts = vec![part("/dev/sdb1", Some("btrfs"), Some("PAMCERT"))];
        let res = select_partition(None, &parent(), &parts).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn case_sensitive_label_match() {
        // "pamcert" is NOT "PAMCERT" — must be rejected.
        let parts = vec![part("/dev/sdb1", Some("vfat"), Some("pamcert"))];
        let res = select_partition(None, &parent(), &parts).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn two_matches_yield_ambiguous_partition_error() {
        let parts = vec![
            part("/dev/sdb1", Some("ext4"), Some("PAMCERT")),
            part("/dev/sdb2", Some("vfat"), Some("PAMCERT")),
        ];
        let err = select_partition(None, &parent(), &parts).unwrap_err();
        match err {
            UsbError::AmbiguousPartition { devnode, count } => {
                assert_eq!(devnode, PathBuf::from("/dev/sdb"));
                assert_eq!(count, 2);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn one_match_among_irrelevant_partitions() {
        let parts = vec![
            part("/dev/sdb1", Some("ext4"), Some("PAMCERT")),
            part("/dev/sdb2", Some("btrfs"), Some("PAMCERT")),
            part("/dev/sdb3", Some("vfat"), Some("OTHER")),
        ];
        let res = select_partition(None, &parent(), &parts).unwrap();
        assert_eq!(res.unwrap().devnode, PathBuf::from("/dev/sdb1"));
    }

    #[test]
    fn empty_fs_or_label_does_not_match() {
        let parts = vec![
            part("/dev/sdb1", None, Some("PAMCERT")),
            part("/dev/sdb2", Some("vfat"), None),
        ];
        let res = select_partition(None, &parent(), &parts).unwrap();
        assert!(res.is_none());
    }
}
