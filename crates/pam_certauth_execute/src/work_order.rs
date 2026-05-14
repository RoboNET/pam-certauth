//! Read a CMS work-order file with `O_NOFOLLOW` and a 10 MiB cap.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use thiserror::Error;

/// Maximum accepted work-order size (10 MiB).
pub const MAX_BYTES: usize = 10 * 1024 * 1024;

/// Errors returned by [`read_work_order`].
#[derive(Debug, Error)]
pub enum WorkOrderError {
    /// The path is a symlink — refused for safety.
    #[error("symlink rejected")]
    SymlinkRejected,
    /// Underlying I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// File or read buffer exceeded [`MAX_BYTES`].
    #[error("too large: {0} bytes (cap {1})")]
    TooLarge(usize, usize),
}

/// Open `path` with `O_NOFOLLOW`, refusing symlinks, and read at most
/// [`MAX_BYTES`] bytes.
pub fn read_work_order(path: &Path) -> Result<Vec<u8>, WorkOrderError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    opts.custom_flags(libc::O_NOFOLLOW);
    let mut f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(WorkOrderError::SymlinkRejected);
        }
        Err(e) => return Err(e.into()),
    };
    let meta = f.metadata()?;
    let size = usize::try_from(meta.len()).unwrap_or(usize::MAX);
    if size > MAX_BYTES {
        return Err(WorkOrderError::TooLarge(size, MAX_BYTES));
    }
    let mut buf = Vec::with_capacity(size);
    f.read_to_end(&mut buf)?;
    if buf.len() > MAX_BYTES {
        return Err(WorkOrderError::TooLarge(buf.len(), MAX_BYTES));
    }
    Ok(buf)
}

/// Hex-encoded SHA-256 of `buf`.
pub fn sha256_hex(buf: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(buf))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn read_rejects_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real.cms");
        std::fs::write(&real, b"hi").expect("write");
        let link = dir.path().join("link.cms");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let err = read_work_order(&link).expect_err("symlink should be rejected");
        assert!(matches!(err, WorkOrderError::SymlinkRejected));
    }

    #[test]
    fn read_caps_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("big.cms");
        let big = vec![0u8; 11 * 1024 * 1024];
        std::fs::write(&p, &big).expect("write");
        let err = read_work_order(&p).expect_err("oversize should be rejected");
        assert!(matches!(err, WorkOrderError::TooLarge(_, _)));
    }

    #[test]
    fn read_small_file_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("ok.cms");
        std::fs::write(&p, b"hello").expect("write");
        let buf = read_work_order(&p).expect("read");
        assert_eq!(buf, b"hello");
    }

    #[test]
    fn sha256_hex_is_64_chars() {
        let h = sha256_hex(b"abc");
        assert_eq!(h.len(), 64);
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
