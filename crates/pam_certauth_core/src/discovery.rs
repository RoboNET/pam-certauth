//! Discover PKCS#12 credentials and an optional intermediate chain on a
//! mounted USB filesystem.
//!
//! Convention:
//!
//! - `<mountpoint>/certs/user.p12` — required.
//! - `<mountpoint>/certs/chain.pem` — optional.
//!
//! Both files are bounded in size to refuse pathological inputs cheaply.

use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Hard upper bound for the user PKCS#12 file (10 MB).
pub const MAX_P12_BYTES: u64 = 10 * 1024 * 1024;

/// Hard upper bound for the optional chain.pem file (1 MB).
pub const MAX_CHAIN_BYTES: u64 = 1024 * 1024;

/// Discovered credentials returned by [`discover_credentials`].
#[derive(Debug)]
pub struct DiscoveredCreds {
    /// Path the PKCS#12 was loaded from (for diagnostics).
    pub p12_path: PathBuf,
    /// Raw PKCS#12 bytes.
    pub p12_bytes: Vec<u8>,
    /// Optional intermediate chain PEM bytes.
    pub chain_pem: Option<Vec<u8>>,
}

/// Errors raised while discovering credentials on a mounted filesystem.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// I/O failure (read, metadata, etc.).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The required `user.p12` file was missing.
    #[error("required file missing: certs/user.p12")]
    P12NotFound,

    /// PKCS#12 file exceeds the size cap.
    #[error("user.p12 too large: {actual} bytes (max {MAX_P12_BYTES})")]
    P12TooLarge {
        /// Observed file size.
        actual: u64,
    },

    /// chain.pem exceeds its (more conservative) size cap.
    #[error("chain.pem too large: {actual} bytes (max {MAX_CHAIN_BYTES})")]
    ChainTooLarge {
        /// Observed file size.
        actual: u64,
    },
}

/// Look for credentials at the conventional locations under `mountpoint`.
///
/// `mountpoint` must be a directory the caller already mounted; this
/// function does not check the mount state.
///
/// # Errors
///
/// See [`DiscoveryError`].
pub fn discover_credentials(mountpoint: &Path) -> Result<DiscoveredCreds, DiscoveryError> {
    let p12_path = mountpoint.join("certs").join("user.p12");
    if !p12_path.is_file() {
        return Err(DiscoveryError::P12NotFound);
    }

    let p12_meta = fs::metadata(&p12_path)?;
    if p12_meta.len() > MAX_P12_BYTES {
        return Err(DiscoveryError::P12TooLarge {
            actual: p12_meta.len(),
        });
    }
    let p12_bytes = fs::read(&p12_path)?;

    let chain_path = mountpoint.join("certs").join("chain.pem");
    let chain_pem = if chain_path.is_file() {
        let meta = fs::metadata(&chain_path)?;
        if meta.len() > MAX_CHAIN_BYTES {
            return Err(DiscoveryError::ChainTooLarge { actual: meta.len() });
        }
        Some(fs::read(&chain_path)?)
    } else {
        None
    };

    Ok(DiscoveredCreds {
        p12_path,
        p12_bytes,
        chain_pem,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_file(p: &Path, bytes: &[u8]) {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut f = std::fs::File::create(p).unwrap();
        f.write_all(bytes).unwrap();
    }

    #[test]
    fn finds_p12_and_chain() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("certs/user.p12"), b"PFXBYTES");
        write_file(
            &dir.path().join("certs/chain.pem"),
            b"-----BEGIN CERTIFICATE-----",
        );
        let d = discover_credentials(dir.path()).unwrap();
        assert_eq!(d.p12_bytes, b"PFXBYTES");
        assert_eq!(
            d.chain_pem.as_deref(),
            Some(b"-----BEGIN CERTIFICATE-----".as_slice())
        );
        assert!(d.p12_path.ends_with("certs/user.p12"));
    }

    #[test]
    fn finds_only_p12_when_chain_missing() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("certs/user.p12"), b"x");
        let d = discover_credentials(dir.path()).unwrap();
        assert!(d.chain_pem.is_none());
    }

    #[test]
    fn errors_when_p12_missing() {
        let dir = tempfile::tempdir().unwrap();
        let err = discover_credentials(dir.path()).unwrap_err();
        assert!(matches!(err, DiscoveryError::P12NotFound));
    }

    #[test]
    fn errors_when_certs_dir_missing() {
        let dir = tempfile::tempdir().unwrap();
        // No certs/ at all.
        let err = discover_credentials(dir.path()).unwrap_err();
        assert!(matches!(err, DiscoveryError::P12NotFound));
    }

    #[test]
    fn rejects_oversized_p12() {
        let dir = tempfile::tempdir().unwrap();
        // We can't actually write 11 MB cheaply in a test — use a sparse
        // file via set_len on the file metadata.
        let p = dir.path().join("certs/user.p12");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let f = std::fs::File::create(&p).unwrap();
        f.set_len(MAX_P12_BYTES + 1).unwrap();
        let err = discover_credentials(dir.path()).unwrap_err();
        match err {
            DiscoveryError::P12TooLarge { actual } => assert_eq!(actual, MAX_P12_BYTES + 1),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rejects_oversized_chain() {
        let dir = tempfile::tempdir().unwrap();
        let p12 = dir.path().join("certs/user.p12");
        let chain = dir.path().join("certs/chain.pem");
        write_file(&p12, b"x");
        let f = std::fs::File::create(&chain).unwrap();
        f.set_len(MAX_CHAIN_BYTES + 1).unwrap();
        let err = discover_credentials(dir.path()).unwrap_err();
        match err {
            DiscoveryError::ChainTooLarge { actual } => assert_eq!(actual, MAX_CHAIN_BYTES + 1),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
