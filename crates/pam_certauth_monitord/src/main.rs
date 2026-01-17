//! `pam-certauth-monitord` entry point.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::ignored_unit_patterns,
    clippy::module_name_repetitions
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use pam_certauth_core::config::validated::OnUsbRemoved as CoreOnUsbRemoved;
use pam_certauth_monitord::{
    actions, logging, logind, notify, registry, server, shutdown, state, udev_monitor,
};

use pam_certauth_monitord::logind::{LogindActionsTrait, NoopActions};
#[cfg(target_os = "linux")]
use pam_certauth_monitord::logind::LogindActions;
use pam_certauth_monitord::registry::{RegistryStore, SessionRegistry};
use pam_certauth_monitord::state::{spawn_state_manager, OnUsbRemoved, StateConfig};
use pam_certauth_monitord::udev_query::{AlwaysPresent, UdevQuery};

#[derive(Debug, Parser)]
#[command(version, about = "PAM CertAuth USB monitor daemon")]
struct Args {
    /// Path to the shared TOML config file. When present, fields under
    /// `[monitor]` populate the daemon's runtime knobs; CLI flags below
    /// (when supplied) override the config values.
    #[arg(long, default_value = "/etc/pam_certauth/config.toml")]
    config: PathBuf,
    /// Unix socket path. Overrides `monitor.socket_path`.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Path to the persisted session registry. Overrides
    /// `monitor.state_file_path`.
    #[arg(long)]
    state_file: Option<PathBuf>,
    /// Grace seconds between USB removal and the configured action.
    /// Overrides `monitor.usb_removed_grace_seconds`.
    #[arg(long)]
    grace_seconds: Option<u64>,
    /// Suspend grace window in seconds. Overrides
    /// `monitor.suspend_grace_seconds`.
    #[arg(long)]
    suspend_grace_seconds: Option<u64>,
    /// Skip launching the udev monitor thread.
    ///
    /// When set, the [`UdevQuery`] used by `SessionOpen` race-checks also
    /// degrades to [`AlwaysPresent`] so e2e tests that disable the udev
    /// thread don't get spurious `DEVICE_GONE` rejections from a `RealUdevQuery`
    /// that would scan a non-functional bus.
    #[arg(long, default_value_t = false)]
    no_udev: bool,
    /// Skip connecting to D-Bus.
    ///
    /// When set, the actions backend degrades to a no-op (lock/terminate/
    /// power-off requests are logged but never sent) and the logind signal
    /// listener is not started. Production must NEVER set this — the whole
    /// point of monitord is to enforce removal via logind.
    #[arg(long, default_value_t = false)]
    no_dbus: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn main() -> anyhow::Result<()> {
    logging::init()?;
    let args = Args::parse();
    tracing::info!(target: "pam_certauth.monitord", "starting");

    // Load the shared validated config: monitord and the PAM cdylib MUST
    // agree on socket path / state file / removal action / grace timers.
    // Operators previously had to edit the systemd unit's CLI flags AND
    // config.toml in lockstep; with this change the daemon reads the same
    // file as PAM and CLI flags only act as overrides.
    let validated = pam_certauth_core::config::load_validated_config(&args.config)
        .map_err(|e| anyhow::anyhow!("failed to load monitord config from {}: {e}", args.config.display()))?;
    let monitor_cfg = &validated.monitor;

    let socket_path = args.socket.clone().unwrap_or_else(|| monitor_cfg.socket_path.clone());
    let state_file_path = args
        .state_file
        .clone()
        .unwrap_or_else(|| monitor_cfg.state_file_path.clone());
    let grace_seconds = args
        .grace_seconds
        .unwrap_or(monitor_cfg.usb_removed_grace.as_secs());
    let suspend_grace_seconds = args
        .suspend_grace_seconds
        .unwrap_or(monitor_cfg.suspend_grace.as_secs());

    let store = RegistryStore::new(state_file_path);
    let initial = store.load().unwrap_or_default();
    let registry = SessionRegistry::from_snapshot(initial);

    let shutdown_tok = CancellationToken::new();
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (action_tx, action_rx) = mpsc::unbounded_channel();

    // Production runs the real udev query so SessionOpen race checks
    // (T19 / T08) actually consult the bus. When `--no-udev` is set we
    // fall back to `AlwaysPresent`: dev/test runs that have no working
    // udev still need SessionOpen to succeed instead of failing closed
    // on a non-functional bus.
    let udev_q: Arc<dyn UdevQuery> = if args.no_udev {
        Arc::new(AlwaysPresent)
    } else {
        // RealUdevQuery is a unit struct on Linux and a type-alias to a unit
        // struct (AlwaysAbsent) on non-Linux dev builds; ::default() is the
        // single expression that compiles on both.
        #[allow(clippy::default_trait_access)]
        Arc::new(<pam_certauth_monitord::udev_query::RealUdevQuery as Default>::default())
    };
    // Map the validated `[monitor].on_usb_removed` (a fieldless enum in
    // pam_certauth_core) onto monitord's local `OnUsbRemoved` (which
    // carries the hook path inline for `Hook` mode). The validator
    // already guaranteed `on_usb_removed_hook_path` is `Some` whenever
    // the action is `Hook`, so the unwrap-style match is safe — but we
    // bail with a structured error instead of panicking, per
    // err-no-unwrap-prod.
    let on_usb_removed = match monitor_cfg.on_usb_removed {
        CoreOnUsbRemoved::Lock => OnUsbRemoved::Lock,
        CoreOnUsbRemoved::Logout => OnUsbRemoved::Logout,
        CoreOnUsbRemoved::Shutdown => OnUsbRemoved::Shutdown,
        CoreOnUsbRemoved::Hook => {
            let path = monitor_cfg.on_usb_removed_hook_path.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "monitor.on_usb_removed = \"hook\" requires monitor.on_usb_removed_hook_path; \
                     validator should have rejected this config"
                )
            })?;
            OnUsbRemoved::Hook { path }
        }
    };
    let cfg = StateConfig {
        grace_seconds,
        suspend_grace_seconds,
        on_usb_removed,
        registry_store: store.clone(),
    };

    let state_handle = spawn_state_manager(
        cfg,
        registry.clone(),
        event_rx,
        action_tx,
        udev_q,
        shutdown_tok.clone(),
    );

    // Build the actions backend.
    //
    // - On Linux with D-Bus enabled: open a system-bus connection once and
    //   share it via `Arc`. Failure to connect is fail-fast — silently
    //   falling back to `NoopActions` would defeat removal enforcement.
    // - On Linux with `--no-dbus`: NoopActions (test/dev escape hatch only).
    // - On non-Linux dev builds: `LogindActions` aliases to `NoopActions`,
    //   so the same code path compiles without zbus.
    let actions_backend: Arc<dyn LogindActionsTrait> = if args.no_dbus {
        Arc::new(NoopActions)
    } else {
        #[cfg(target_os = "linux")]
        {
            let conn = zbus::Connection::system().await.map_err(|e| {
                anyhow::anyhow!(
                    "monitord requires a working system D-Bus connection for logind actions; \
                     pass --no-dbus only for tests/dev. Underlying error: {e}"
                )
            })?;
            Arc::new(LogindActions::new(Arc::new(conn)))
        }
        #[cfg(not(target_os = "linux"))]
        {
            // On non-Linux dev builds `LogindActions` is a type alias for
            // `NoopActions`; construct the underlying value directly.
            Arc::new(NoopActions)
        }
    };
    let action_handle =
        actions::spawn_action_runner(action_rx, actions_backend, shutdown_tok.clone());

    let udev_handle = if args.no_udev {
        None
    } else {
        let (udev_tx, mut udev_rx) = mpsc::unbounded_channel();
        let _udev_thread = udev_monitor::spawn_udev_thread(udev_tx, shutdown_tok.clone());
        let event_tx = event_tx.clone();
        let token = shutdown_tok.clone();
        Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    Some(ev) = udev_rx.recv() => {
                        if event_tx.send(state::Event::Udev(ev)).is_err() { break; }
                    }
                }
            }
        }))
    };

    let logind_handle = if args.no_dbus {
        None
    } else {
        let (sig_tx, mut sig_rx) = mpsc::unbounded_channel();
        let _h =
            logind::listener::spawn_logind_listener(logind::listener::BusAddress::System, sig_tx);
        let event_tx = event_tx.clone();
        let token = shutdown_tok.clone();
        Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    Some(s) = sig_rx.recv() => {
                        if event_tx.send(state::Event::Logind(s)).is_err() { break; }
                    }
                }
            }
        }))
    };

    let listener = server::bind_listener(&socket_path).await?;
    let accept_event_tx = event_tx.clone();
    let accept_token = shutdown_tok.clone();
    let accept_handle = tokio::spawn(async move {
        server::run_accept_loop(listener, accept_event_tx, accept_token).await;
    });

    let mut notify_handle = notify::NotifyHandle::system_default();
    notify::notify_ready(&mut notify_handle);

    let _ = shutdown::install_signal_handlers(shutdown_tok.clone()).await;

    let mut handles = vec![accept_handle, state_handle, action_handle];
    if let Some(h) = udev_handle {
        handles.push(h);
    }
    if let Some(h) = logind_handle {
        handles.push(h);
    }
    shutdown::graceful_finish(handles, Duration::from_secs(5), &socket_path).await;

    // Reference unused symbols to silence dead-code in the binary build.
    let _ = registry::ActiveSession {
        session_id: uuid::Uuid::nil(),
        pam_user: String::new(),
        pam_service: String::new(),
        target: pam_certauth_proto::SessionTarget::Unknown,
        usb_serial: None,
        host_id_hash: String::new(),
        opened_at: std::time::SystemTime::UNIX_EPOCH,
        cert_cn: String::new(),
        cert_serial: String::new(),
    };
    Ok(())
}
