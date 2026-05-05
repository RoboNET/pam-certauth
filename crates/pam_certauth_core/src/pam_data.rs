//! PAM auth context stored by the cdylib.

use std::time::SystemTime;

use crate::host_identity::HostIdSourceKind;

/// Authentication context stored in PAM data.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Session id.
    pub session_id: String,
    /// Certificate CN.
    pub cert_cn: Option<String>,
    /// Certificate serial.
    pub cert_serial: Option<String>,
    /// USB serial.
    pub usb_serial: Option<String>,
    /// USB VID/PID.
    pub usb_vid_pid: Option<String>,
    /// PAM service.
    pub pam_service: String,
    /// Host id.
    pub host_id: String,
    /// Host id source.
    pub host_id_source: HostIdSourceKind,
    /// Authentication timestamp.
    pub authenticated_at: SystemTime,
    /// Certificate `notAfter`, captured at authenticate time so that
    /// [`pam_sm_acct_mgmt`] can re-check expiry without re-loading the cert.
    pub cert_not_after: Option<SystemTime>,
}

impl AuthContext {
    /// Create a Stage 1 default context.
    pub fn new(session_id: String, pam_service: String) -> Self {
        Self {
            session_id,
            cert_cn: None,
            cert_serial: None,
            usb_serial: None,
            usb_vid_pid: None,
            pam_service,
            host_id: String::new(),
            host_id_source: HostIdSourceKind::Override,
            authenticated_at: SystemTime::now(),
            cert_not_after: None,
        }
    }
}
