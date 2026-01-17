//! Sync, blocking IPC client targeting `pam-certauth-monitord`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use uuid::Uuid;

use pam_certauth_proto::{
    decode_line, encode_message, error_codes, ClientMessage, ServerMessage, SessionOpenPayload,
    PROTOCOL_VERSION,
};

use crate::error::IpcError;
use crate::ipc::{MonitorClient, OpenSessionInfo};

const AGENT: &str = concat!("libpam_certauth/", env!("CARGO_PKG_VERSION"));

/// Sync IPC client that holds an open Unix socket connection.
///
/// One `MonitordClient` is normally constructed per RPC by
/// [`MonitorClientFactory::open_session`] / [`MonitorClientFactory::ping`] — the
/// PAM module never reuses a connection across calls because the cdylib is
/// strictly request/response and connect-per-call removes any need to track
/// stream state.
#[allow(missing_debug_implementations)]
pub struct MonitordClient {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
    /// Hard budget that started ticking on `connect`.
    deadline_remaining: Duration,
}

impl MonitordClient {
    /// Connect to monitord at `path`, perform `Hello` handshake, and return
    /// a ready-to-use client. The full handshake completes inside `timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Unavailable`] if the socket cannot be reached,
    /// [`IpcError::Timeout`] if the handshake takes longer than `timeout`,
    /// [`IpcError::ProtocolMismatch`] on version disagreement, and
    /// [`IpcError::UnexpectedReply`] on anything else.
    pub fn connect(path: &Path, timeout: Duration) -> Result<Self, IpcError> {
        let stream = UnixStream::connect(path).map_err(|e| {
            tracing::warn!(target: "pam_certauth.ipc", error = %e, ?path, "connect failed");
            IpcError::Unavailable
        })?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let writer_clone = stream.try_clone()?;
        let reader = BufReader::new(writer_clone);
        let mut me = Self {
            stream,
            reader,
            deadline_remaining: timeout,
        };
        me.send(&ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            agent: Some(AGENT.into()),
        })?;
        match me.recv()? {
            ServerMessage::HelloAck {
                protocol_version, ..
            } if protocol_version == PROTOCOL_VERSION => Ok(me),
            ServerMessage::HelloAck {
                protocol_version, ..
            } => Err(IpcError::ProtocolMismatch {
                server: protocol_version,
            }),
            ServerMessage::Error { code, message } => Err(map_server_error(code, message)),
            other => Err(IpcError::UnexpectedReply(format!("{other:?}"))),
        }
    }

    /// Send a `Ping` and expect `Pong`.
    pub fn ping(&mut self) -> Result<(), IpcError> {
        self.send(&ClientMessage::Ping)?;
        match self.recv()? {
            ServerMessage::Pong => Ok(()),
            ServerMessage::Error { code, message } => Err(map_server_error(code, message)),
            other => Err(IpcError::UnexpectedReply(format!("{other:?}"))),
        }
    }

    /// Send `SessionOpen`.
    pub fn send_session_open(&mut self, payload: &SessionOpenPayload) -> Result<(), IpcError> {
        let msg = ClientMessage::SessionOpen {
            session_id: payload.session_id,
            pam_user: payload.pam_user.clone(),
            pam_service: payload.pam_service.clone(),
            target: payload.target.clone(),
            usb_serial: payload.usb_serial.clone(),
            host_id_hash: payload.host_id_hash.clone(),
            opened_at: payload.opened_at,
            cert_cn: payload.cert_cn.clone(),
            cert_serial: payload.cert_serial.clone(),
        };
        self.send(&msg)?;
        match self.recv()? {
            ServerMessage::Ack => Ok(()),
            ServerMessage::Error { code, message } => Err(map_server_error(code, message)),
            other => Err(IpcError::UnexpectedReply(format!("{other:?}"))),
        }
    }

    /// Send `SessionClose`.
    pub fn send_session_close(
        &mut self,
        session_id: Uuid,
        closed_at: SystemTime,
    ) -> Result<(), IpcError> {
        self.send(&ClientMessage::SessionClose {
            session_id,
            closed_at,
        })?;
        match self.recv()? {
            ServerMessage::Ack => Ok(()),
            ServerMessage::Error { code, message } => Err(map_server_error(code, message)),
            other => Err(IpcError::UnexpectedReply(format!("{other:?}"))),
        }
    }

    fn send(&mut self, msg: &ClientMessage) -> Result<(), IpcError> {
        let bytes = encode_message(msg)?;
        self.stream.write_all(&bytes)?;
        self.stream.flush()?;
        Ok(())
    }

    fn recv(&mut self) -> Result<ServerMessage, IpcError> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line)?;
        if n == 0 {
            return Err(IpcError::Unavailable);
        }
        let _ = self.deadline_remaining; // best-effort budget bookkeeping (read_timeout enforces the wall clock)
        Ok(decode_line(&line)?)
    }
}

fn map_server_error(code: u32, message: String) -> IpcError {
    match code {
        error_codes::DEVICE_GONE => IpcError::DeviceGone,
        error_codes::PROTOCOL_MISMATCH => IpcError::ProtocolMismatch { server: 0 },
        error_codes::UNAUTHORIZED => IpcError::Unauthorized,
        _ => IpcError::Server { code, message },
    }
}

/// Factory holding a connection target + timeout.
///
/// Consumers ask the factory to connect on every RPC; this matches
/// "connect-per-call" with a fresh socket each time, which is the simplest way
/// to make the sync client robust under restart of monitord.
#[derive(Debug, Clone)]
pub struct MonitorClientFactory {
    path: PathBuf,
    timeout: Duration,
}

impl MonitorClientFactory {
    /// Construct a new factory.
    #[must_use]
    pub fn new(path: PathBuf, timeout: Duration) -> Self {
        Self { path, timeout }
    }

    /// Open a fresh connection to monitord.
    pub fn connect(&self) -> Result<MonitordClient, IpcError> {
        MonitordClient::connect(&self.path, self.timeout)
    }
}

/// A `MonitorClient` impl that opens a fresh connection per call.
pub struct ConnectPerCall {
    factory: MonitorClientFactory,
}

impl ConnectPerCall {
    /// Construct a connect-per-call client.
    #[must_use]
    pub fn new(factory: MonitorClientFactory) -> Self {
        Self { factory }
    }
}

impl MonitorClient for ConnectPerCall {
    fn hello(&self) -> Result<(), IpcError> {
        let mut c = self.factory.connect()?;
        c.ping()
    }

    fn open_session(&self, info: &OpenSessionInfo<'_>) -> Result<(), IpcError> {
        let session_uuid = uuid_from_session_id(info.session_id);
        let mut c = self.factory.connect()?;
        let payload = SessionOpenPayload {
            session_id: session_uuid,
            pam_user: info.pam_user.to_string(),
            pam_service: info.pam_service.to_string(),
            target: info.target.clone(),
            usb_serial: info.usb_serial.map(str::to_string),
            host_id_hash: info.host_id_hash.to_string(),
            opened_at: SystemTime::now(),
            cert_cn: info.cert_cn.to_string(),
            cert_serial: info.cert_serial.to_string(),
        };
        c.send_session_open(&payload)
    }

    fn close_session(&self, session_id: &str, _reason: &str) -> Result<(), IpcError> {
        let session_uuid = uuid_from_session_id(session_id);
        let mut c = self.factory.connect()?;
        c.send_session_close(session_uuid, SystemTime::now())
    }

    fn ping(&self) -> Result<(), IpcError> {
        let mut c = self.factory.connect()?;
        c.ping()
    }
}

/// Map a stringly-typed session id (e.g. random hex from the PAM module) into
/// a stable [`Uuid`]. The PAM module historically passes a string; monitord
/// wants a `Uuid` so we hash deterministically.
fn uuid_from_session_id(s: &str) -> Uuid {
    if let Ok(parsed) = Uuid::parse_str(s) {
        return parsed;
    }
    Uuid::new_v5(&Uuid::NAMESPACE_OID, s.as_bytes())
}
