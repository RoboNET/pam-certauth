//! Persist verified CMS work-orders to `/var/lib/pam_certauth/work_orders`
//! for forensic / audit purposes.
//!
//! Storage layout: `<retention_dir>/<cms_sha256_hex>.cms`, mode `0640`,
//! owned by the invoking process (expected to be root in production).
//! Writes are atomic (write to `.tmp`, fsync-free `rename`) so a crashed
//! `execute` cannot leave a half-written file behind.
//!
//! The retention directory defaults to [`DEFAULT_RETENTION_DIR`] and can
//! be overridden with the `PAM_CERTAUTH_RETENTION_DIR` env var (used by
//! tests + emergency operator override).

use std::path::{Path, PathBuf};

/// Default location for retained CMS work-orders.
pub const DEFAULT_RETENTION_DIR: &str = "/var/lib/pam_certauth/work_orders";

/// Environment variable that overrides [`DEFAULT_RETENTION_DIR`]. Used by
/// the integration tests and operators who want to redirect the retention
/// store to a different filesystem.
pub const ENV_RETENTION_DIR: &str = "PAM_CERTAUTH_RETENTION_DIR";

/// Resolve the active retention directory, honouring the env var override.
#[must_use]
pub fn retention_dir() -> PathBuf {
    std::env::var(ENV_RETENTION_DIR)
        .map_or_else(|_| PathBuf::from(DEFAULT_RETENTION_DIR), PathBuf::from)
}

/// Persist `buf` to `<dir>/<cms_sha256_hex>.cms` atomically with mode `0640`.
///
/// Creates the retention directory (and parents) on demand. A retention
/// failure is intentionally non-fatal at the call site — losing the
/// forensic copy is preferable to denying an already-authorised action.
///
/// # Errors
///
/// Returns the underlying [`std::io::Error`] for directory creation,
/// write, permission, or rename failures.
pub fn retain_cms(buf: &[u8], cms_sha256_hex: &str, dir: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    let final_path = dir.join(format!("{cms_sha256_hex}.cms"));
    let tmp_path = dir.join(format!("{cms_sha256_hex}.cms.tmp"));
    std::fs::write(&tmp_path, buf)?;
    let mut perm = std::fs::metadata(&tmp_path)?.permissions();
    perm.set_mode(0o640);
    std::fs::set_permissions(&tmp_path, perm)?;
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// Delete every `*.cms` file under `dir` whose mtime is older than
/// `retention_days` days from `now`.
///
/// Returns the number of files removed. Errors on individual files are
/// logged at `warn!` and do not abort the sweep.
///
/// # Errors
///
/// Returns the underlying [`std::io::Error`] only for failures *opening*
/// the retention directory itself — per-entry errors are swallowed.
pub fn gc(dir: &Path, retention_days: u32, now: std::time::SystemTime) -> std::io::Result<u64> {
    if !dir.exists() {
        return Ok(0);
    }
    let cutoff = now
        .checked_sub(std::time::Duration::from_secs(u64::from(retention_days) * 86_400))
        .unwrap_or(std::time::UNIX_EPOCH);
    let mut removed = 0u64;
    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        // Only ever touch `*.cms` files; leave `.tmp` and unrelated files
        // alone so we can never delete data we did not write.
        if path.extension().and_then(|s| s.to_str()) != Some("cms") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(mtime) = meta.modified() else { continue };
        if mtime < cutoff {
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(e) => {
                    tracing::warn!(
                        target: "pam_certauth.execute.retention.gc",
                        path = %path.display(),
                        error = %e,
                        "gc: failed to remove file"
                    );
                }
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::items_after_statements,
    clippy::duration_suboptimal_units
)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn retain_writes_file_with_0640_perms() {
        let dir = tempfile::tempdir().unwrap();
        let p = retain_cms(b"abc", "deadbeef", dir.path()).unwrap();
        assert!(p.exists());
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        let data = std::fs::read(&p).unwrap();
        assert_eq!(data, b"abc");
    }

    #[test]
    fn retain_creates_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a/b/c");
        let p = retain_cms(b"x", "abc123", &sub).unwrap();
        assert!(p.exists());
    }

    #[test]
    fn retain_is_idempotent_for_same_hash() {
        let dir = tempfile::tempdir().unwrap();
        let _ = retain_cms(b"x", "hash", dir.path()).unwrap();
        // second call must succeed (rename over existing file)
        let _ = retain_cms(b"x", "hash", dir.path()).unwrap();
    }

    /// Move the mtime/atime of `path` to `t` via libc::utimes.
    #[allow(clippy::items_after_statements)]
    fn set_mtime(path: &std::path::Path, t: SystemTime) {
        let secs = t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let tv = libc::timeval {
            #[allow(clippy::cast_possible_wrap)]
            tv_sec: secs as libc::time_t,
            tv_usec: 0,
        };
        let times = [tv, tv];
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: cpath is a valid NUL-terminated path; times is a 2-element array.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::utimes(cpath.as_ptr(), times.as_ptr()) };
        assert_eq!(rc, 0, "utimes failed");
    }

    #[test]
    fn gc_removes_old_files_and_keeps_new() {
        let dir = tempfile::tempdir().unwrap();
        let old = retain_cms(b"old", "0000", dir.path()).unwrap();
        let fresh = retain_cms(b"fresh", "1111", dir.path()).unwrap();

        // Backdate the "old" file by 100 days.
        let hundred_days_ago = SystemTime::now() - Duration::from_secs(100 * 86_400);
        set_mtime(&old, hundred_days_ago);

        let removed = gc(dir.path(), 90, SystemTime::now()).unwrap();
        assert_eq!(removed, 1);
        assert!(!old.exists());
        assert!(fresh.exists());
    }

    #[test]
    fn gc_ignores_non_cms_files() {
        let dir = tempfile::tempdir().unwrap();
        let stray = dir.path().join("stray.txt");
        std::fs::write(&stray, b"hi").unwrap();
        let hundred_days_ago = SystemTime::now() - Duration::from_secs(100 * 86_400);
        set_mtime(&stray, hundred_days_ago);

        let removed = gc(dir.path(), 90, SystemTime::now()).unwrap();
        assert_eq!(removed, 0);
        assert!(stray.exists());
    }

    #[test]
    fn gc_returns_zero_when_dir_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let removed = gc(&missing, 90, SystemTime::now()).unwrap();
        assert_eq!(removed, 0);
    }
}
