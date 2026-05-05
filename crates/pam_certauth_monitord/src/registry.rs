//! Active session registry.
//!
//! Holds every session that monitord knows about. Persisted via
//! [`store::RegistryStore`] to `/run/pam_certauth/sessions.json` (writable
//! by root only, atomic temp-file replace).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::Mutex;
use uuid::Uuid;

use pam_certauth_proto::SessionTarget;

pub mod store;

pub use store::RegistryStore;

/// Snapshot of one active session as known to monitord.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveSession {
    /// Session id (matches what the PAM module sent in `SessionOpen`).
    pub session_id: Uuid,
    /// PAM user.
    pub pam_user: String,
    /// PAM service.
    pub pam_service: String,
    /// Where the session lives.
    pub target: SessionTarget,
    /// USB serial that authorised the session.
    pub usb_serial: Option<String>,
    /// Hex host id hash.
    pub host_id_hash: String,
    /// Wall-clock open time.
    #[serde(with = "pam_certauth_proto::system_time_serde")]
    pub opened_at: SystemTime,
    /// Cert CN.
    pub cert_cn: String,
    /// Cert serial.
    pub cert_serial: String,
}

/// Thread-safe in-memory registry.
#[derive(Default, Clone)]
pub struct SessionRegistry {
    inner: Arc<Mutex<HashMap<Uuid, ActiveSession>>>,
}

impl std::fmt::Debug for SessionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRegistry")
            .field("len", &self.inner.lock().len())
            .finish()
    }
}

impl SessionRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct from a pre-loaded vector of sessions (used at startup).
    #[must_use]
    pub fn from_snapshot(sessions: Vec<ActiveSession>) -> Self {
        let mut map = HashMap::with_capacity(sessions.len());
        for s in sessions {
            map.insert(s.session_id, s);
        }
        Self {
            inner: Arc::new(Mutex::new(map)),
        }
    }

    /// Insert a session (overwrites any existing entry with the same id).
    pub fn add(&self, s: ActiveSession) {
        self.inner.lock().insert(s.session_id, s);
    }

    /// Remove and return a session by id.
    pub fn remove(&self, id: Uuid) -> Option<ActiveSession> {
        self.inner.lock().remove(&id)
    }

    /// Get a session by id.
    pub fn find_by_session_id(&self, id: Uuid) -> Option<ActiveSession> {
        self.inner.lock().get(&id).cloned()
    }

    /// Return every session whose `usb_serial` matches `serial`.
    pub fn find_by_serial(&self, serial: &str) -> Vec<ActiveSession> {
        self.inner
            .lock()
            .values()
            .filter(|s| s.usb_serial.as_deref() == Some(serial))
            .cloned()
            .collect()
    }

    /// Snapshot of every active session.
    #[must_use]
    pub fn snapshot(&self) -> Vec<ActiveSession> {
        self.inner.lock().values().cloned().collect()
    }

    /// Convenience alias for [`Self::snapshot`].
    #[must_use]
    pub fn all(&self) -> Vec<ActiveSession> {
        self.snapshot()
    }

    /// Number of active sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}
