//! Atomic JSON persistence for the session registry.
//!
//! The file is written to a temp path opened with `O_CREAT | O_EXCL`
//! and `mode=0o600` (so the create itself sets the secure mode without a
//! race against `umask`), then `fsync`'d, `rename(2)`'d into place, and
//! the parent directory is then `fsync`'d so the rename hits stable storage
//! across power loss. Sessions include cert CN/serial which we do not want
//! exposed — the file therefore stays at `0600`.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Per-process counter for temp filename uniqueness; mixed with the current
/// nanos so two persists in the same nanosecond collide neither on the
/// filename nor on `O_CREAT|O_EXCL`.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Inline cleanup guard for [`RegistryStore::persist`]: removes the temp
/// file if the function aborts before the rename completes.
struct PersistCleanupGuard<'a> {
    path: &'a Path,
    armed: bool,
}

impl Drop for PersistCleanupGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Cleanup is best-effort in Drop; can't return errors from Drop.
            _ = std::fs::remove_file(self.path);
        }
    }
}

use super::ActiveSession;

/// On-disk store for the session registry.
#[derive(Debug, Clone)]
pub struct RegistryStore {
    path: PathBuf,
}

impl RegistryStore {
    /// Construct a store rooted at `path`.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Path to the persisted file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load existing sessions from disk.
    ///
    /// A missing file or a corrupt JSON body is treated as "empty registry"
    /// and logged as WARN — we do not propagate the error so that the daemon
    /// can still start with a fresh registry after a crash.
    ///
    /// # Errors
    ///
    /// Returns the underlying `io::Error` only for non-`NotFound` IO failures.
    pub fn load(&self) -> io::Result<Vec<ActiveSession>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => match serde_json::from_slice::<Vec<ActiveSession>>(&bytes) {
                Ok(v) => Ok(v),
                Err(e) => {
                    tracing::warn!(
                        target: "pam_certauth.monitord",
                        error = %e,
                        path = ?self.path,
                        "sessions.json corrupt, starting empty"
                    );
                    Ok(Vec::new())
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Atomically replace the on-disk file with a new snapshot.
    ///
    /// Implementation notes:
    ///
    /// * The temp file is opened via `O_CREAT | O_EXCL` with `mode=0o600`
    ///   so the secure mode is set at creation time — closing the
    ///   `umask`-vs-`set_permissions` race window where the world-readable
    ///   bits could otherwise be observable for an instant.
    /// * After writing, the temp file is `fsync`'d and renamed into place.
    /// * The containing directory is then `fsync`'d so the rename survives
    ///   a power loss.
    ///
    /// This call is synchronous and may block; async callers should run it
    /// inside `tokio::task::spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Returns the underlying `io::Error` for any failure during temp-file
    /// creation, write, rename, or directory fsync.
    pub fn persist(&self, snapshot: &[ActiveSession]) -> io::Result<()> {
        let parent = self.path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "registry path has no parent")
        })?;
        std::fs::create_dir_all(parent)?;

        // Race-free temp create: pick a unique sibling name and open with
        // O_CREAT|O_EXCL|mode=0o600. Retry a small bounded number of times
        // on the (extremely unlikely) collision.
        let mut last_err: Option<io::Error> = None;
        let mut tmp_path: Option<PathBuf> = None;
        let mut tmp_file: Option<File> = None;
        for _ in 0..16 {
            let candidate = parent.join(format!(
                ".sessions.{}.{}.tmp",
                std::process::id(),
                rand_suffix()
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&candidate)
            {
                Ok(f) => {
                    tmp_file = Some(f);
                    tmp_path = Some(candidate);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        let (mut tmp, tmp_path) = match (tmp_file, tmp_path) {
            (Some(f), Some(p)) => (f, p),
            _ => {
                return Err(last_err.unwrap_or_else(|| {
                    io::Error::other("failed to create unique tmp file for registry persist")
                }))
            }
        };

        // Best-effort cleanup if we abort partway through write/fsync/rename.
        let mut guard = PersistCleanupGuard {
            path: &tmp_path,
            armed: true,
        };

        let bytes = serde_json::to_vec_pretty(snapshot)?;
        tmp.write_all(&bytes)?;
        tmp.sync_all()?;
        // Drop the file handle before rename to avoid Windows-isms (no-op
        // here but keeps the close ordering tidy).
        drop(tmp);

        std::fs::rename(&tmp_path, &self.path)?;
        guard.armed = false;

        // fsync the parent directory so the rename is durable.
        // Best-effort: on filesystems that don't support it (very rare on
        // Linux for native FS), surface the error.
        let dir = File::open(parent)?;
        dir.sync_all()?;

        Ok(())
    }
}

/// Cheap pseudo-random suffix for temp filenames. We only need uniqueness
/// within the same parent dir/process, not cryptographic strength.
fn rand_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let c = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}{c:x}")
}
