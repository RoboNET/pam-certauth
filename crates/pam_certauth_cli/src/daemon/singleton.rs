//! Daemon singleton enforcement via `flock(2)`.
//!
//! Layer 1 of the defence-in-depth that prevents a stale pre-0.2.1
//! `pam-certauth-monitord` (running as root) from coexisting with the
//! 0.2.1+ `pam-certauth daemon` (running as `pamcertauth`). The other two
//! layers are systemd `ExecStartPre=pkill …` and a debian/postinst
//! migration block.
//!
//! Semantics:
//!
//! * Open `<state_dir>/daemon.lock` (mode 0600) with `O_RDWR | O_CREAT`.
//! * Attempt a non-blocking exclusive `flock(LOCK_EX | LOCK_NB)`.
//! * On `EWOULDBLOCK` the existing PID is read from the file and a
//!   CRITICAL audit event is emitted, then the caller exits.
//! * On success we truncate the file and write our own PID. The fd is
//!   kept alive (inside [`DaemonLock`]) for the lifetime of the daemon.
//!   Closing the fd would release the kernel-held flock; the kernel
//!   releases it for us automatically on process exit/crash.
//!
//! `Drop` deliberately does NOT explicitly close or unlock — `Flock`'s
//! own drop releases the lock when the process is shutting down anyway,
//! which is fine, and avoiding an explicit close means we cannot
//! accidentally drop the guard mid-life (use-after-free of the singleton
//! invariant). Storing this struct in a long-lived binding is sufficient.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};

/// Errors returned from [`DaemonLock::acquire`].
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// Could not open the lock file (permissions, missing parent dir,
    /// etc.).
    #[error("failed to open lock file {path}: {source}")]
    Open {
        /// Path that failed to open.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Another process already holds the exclusive lock.
    #[error("another daemon instance holds the lock at {path} (pid={pid:?})")]
    AlreadyHeld {
        /// Lock path.
        path: PathBuf,
        /// PID read from the lock file content, if parseable.
        pid: Option<i32>,
    },
    /// Unexpected `flock(2)` failure (something other than `EWOULDBLOCK`).
    #[error("flock({path}) failed: {errno}")]
    FlockOther {
        /// Lock path.
        path: PathBuf,
        /// `errno` from `flock(2)`.
        errno: Errno,
    },
    /// Could not write our PID into the lock file.
    #[error("failed to write pid to {path}: {source}")]
    Write {
        /// Lock path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Owns the exclusive `flock(2)` over the daemon lock file.
///
/// The wrapped [`Flock`] keeps the underlying fd alive for the lifetime
/// of this value; the lock is released by the kernel either when
/// `Flock::drop` runs (process tear-down) or when the process exits.
#[must_use = "dropping the guard releases the singleton lock; bind it to a daemon-lifetime variable"]
#[derive(Debug)]
pub struct DaemonLock {
    /// Path of the lock file, retained for diagnostics.
    path: PathBuf,
    /// Active `flock`. Held until process exit.
    _lock: Flock<File>,
}

impl DaemonLock {
    /// Path on disk this lock is bound to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Attempt to acquire the singleton lock at `path`.
    ///
    /// On success the current PID is written into the file (truncating
    /// any prior content). On contention the caller gets back
    /// [`LockError::AlreadyHeld`] with the conflicting PID parsed from
    /// the existing content (best-effort; `None` if unreadable).
    pub fn acquire(path: &Path) -> Result<Self, LockError> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false).mode(0o600);
        let file = opts.open(path).map_err(|e| LockError::Open {
            path: path.to_path_buf(),
            source: e,
        })?;

        let lock = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(l) => l,
            Err((existing, errno)) => {
                // On Linux EWOULDBLOCK == EAGAIN so we only need to match one.
                if matches!(errno, Errno::EWOULDBLOCK) {
                    let pid = read_pid_from(existing);
                    return Err(LockError::AlreadyHeld {
                        path: path.to_path_buf(),
                        pid,
                    });
                }
                return Err(LockError::FlockOther {
                    path: path.to_path_buf(),
                    errno,
                });
            }
        };

        // Truncate and write our PID. Best-effort: if we got the lock
        // but can't write our pid, that's still fatal because the
        // operator-visible diagnostic relies on it.
        write_pid(&lock, path)?;

        Ok(Self {
            path: path.to_path_buf(),
            _lock: lock,
        })
    }
}

/// Truncate the on-disk file backing the lock and write
/// `std::process::id()` followed by a newline. We do not write through
/// the lock-holding fd because `Flock<File>` only exposes a shared
/// borrow; opening a second handle to the same path while we hold the
/// flock is race-free for our purpose. The second handle is closed at
/// function return, and closing it does NOT release the kernel flock
/// (which is bound to the first open file description, retained inside
/// `Flock`).
fn write_pid(_lock: &Flock<File>, path: &Path) -> Result<(), LockError> {
    let mut writer = OpenOptions::new()
        .read(false)
        .write(true)
        .create(false)
        .truncate(true)
        .open(path)
        .map_err(|e| LockError::Write {
            path: path.to_path_buf(),
            source: e,
        })?;
    writer
        .write_all(format!("{}\n", std::process::id()).as_bytes())
        .map_err(|e| LockError::Write {
            path: path.to_path_buf(),
            source: e,
        })?;
    writer.sync_data().map_err(|e| LockError::Write {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

/// Best-effort parse of the PID stored inside an existing lock file.
fn read_pid_from(mut file: File) -> Option<i32> {
    let _ = file.seek(SeekFrom::Start(0));
    let mut buf = String::new();
    file.read_to_string(&mut buf).ok()?;
    buf.trim().parse::<i32>().ok()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_wrap
)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn acquires_lock_when_unheld() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.lock");
        let lock = DaemonLock::acquire(&path).expect("acquire");
        assert_eq!(lock.path(), path);
        // PID was written.
        let content = std::fs::read_to_string(&path).unwrap();
        let pid: u32 = content.trim().parse().unwrap();
        assert_eq!(pid, std::process::id());
        drop(lock);
    }

    #[test]
    fn rejects_when_already_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.lock");
        let _first = DaemonLock::acquire(&path).expect("first acquire");

        // Second acquire must fail. flock(2) is per-open-file-description,
        // and OpenOptions::open in a child thread creates a separate
        // description, so this exercises the contention path correctly.
        let path_for_thread = path.clone();
        let result = thread::spawn(move || DaemonLock::acquire(&path_for_thread))
            .join()
            .expect("thread");
        match result {
            Err(LockError::AlreadyHeld { pid, .. }) => {
                assert_eq!(pid, Some(std::process::id() as i32));
            }
            other => panic!("expected AlreadyHeld, got {other:?}"),
        }
    }

    #[test]
    fn releases_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.lock");
        let first = DaemonLock::acquire(&path).expect("first");
        drop(first);
        // After drop the kernel-held flock is released; we can acquire again.
        let _second = DaemonLock::acquire(&path).expect("second after drop");
    }
}
