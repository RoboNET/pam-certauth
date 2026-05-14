//! Child process spawn helpers — env scrub (Task 7.5) and the spawn loop
//! with `setpgid`, signal forwarding, and timeout enforcement (Task 7.6).

use std::collections::HashMap;
use std::io;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use thiserror::Error;

/// Standard system path forced into every child environment.
pub const CHILD_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// Exit code returned when the child is killed by the timeout watchdog.
pub const TIMEOUT_EXIT_CODE: i32 = 124;

/// Errors returned by [`run_child_with_timeout`].
#[derive(Debug, Error)]
pub enum ChildError {
    /// Spawn (`fork`/`execve`) failed.
    #[error("spawn failed: {0}")]
    Spawn(#[from] io::Error),
    /// Could not install the signal-forwarding handler.
    #[error("signal handler setup failed: {0}")]
    SignalSetup(io::Error),
}

/// Result of a completed (or terminated) child run.
#[derive(Debug, Clone, Copy)]
pub struct ChildResult {
    /// Exit code of the child. `128 + signum` for signal-terminated, or
    /// [`TIMEOUT_EXIT_CODE`] for the timeout watchdog.
    pub exit_code: i32,
}

/// Build the environment passed to the child process.
///
/// The result contains:
/// * a fixed `PATH=/usr/sbin:/usr/bin:/sbin:/bin`,
/// * the safe locale / terminal whitelist (`LANG`, `LC_*`, `TERM`, `HOME`,
///   `USER`, `LOGNAME`) — only if currently set in our environment,
/// * every `PAM_CERTAUTH_*` variable passed through unchanged for audit /
///   downstream tooling.
pub fn build_child_env() -> HashMap<String, String> {
    const WHITELIST: &[&str] = &["LANG", "TERM", "HOME", "USER", "LOGNAME"];

    let mut env: HashMap<String, String> = HashMap::new();
    env.insert("PATH".to_string(), CHILD_PATH.to_string());
    for &k in WHITELIST {
        if let Ok(v) = std::env::var(k) {
            env.insert(k.to_string(), v);
        }
    }
    for (k, v) in std::env::vars() {
        if k.starts_with("LC_") || k.starts_with("PAM_CERTAUTH_") {
            env.insert(k, v);
        }
    }
    env
}

/// Spawn `argv0` with `args`, environment `env`, working directory `cwd`,
/// running in a fresh process group. Forwards a useful set of TTY/job-control
/// signals to the child's process group. If `timeout` elapses, the watchdog
/// SIGTERMs the group, waits 5 seconds, then SIGKILLs and returns
/// [`TIMEOUT_EXIT_CODE`].
#[allow(clippy::needless_pass_by_value)]
pub fn run_child_with_timeout(
    argv0: &Path,
    args: &[String],
    env: HashMap<String, String>,
    cwd: PathBuf,
    timeout: Option<Duration>,
) -> Result<ChildResult, ChildError> {
    let mut cmd = Command::new(argv0);
    cmd.args(args).env_clear().envs(&env).current_dir(&cwd);

    // SAFETY: `pre_exec` callback runs in the forked child between fork and
    // execve. We only invoke async-signal-safe operations (setpgid) and
    // return errors as `io::Error`. No allocations, no locks.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0))
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            Ok(())
        });
    }

    let mut child = cmd.spawn()?;
    let child_pid_raw = i32::try_from(child.id()).unwrap_or(i32::MAX);
    let pgid_neg = Pid::from_raw(-child_pid_raw);

    let forwarder = SignalForwarder::install(pgid_neg).map_err(ChildError::SignalSetup)?;

    let start = Instant::now();
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let code = status
                    .code()
                    .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
                break Ok(ChildResult { exit_code: code });
            }
            Ok(None) => {
                if let Some(t) = timeout {
                    if start.elapsed() >= t {
                        // Best-effort signals to the process group: child may
                        // already be gone (ESRCH) and that's fine.
                        _ = kill(pgid_neg, Signal::SIGTERM);
                        let kill_deadline = Instant::now() + Duration::from_secs(5);
                        loop {
                            match child.try_wait() {
                                Ok(Some(_)) => break,
                                _ if Instant::now() >= kill_deadline => break,
                                _ => std::thread::sleep(Duration::from_millis(50)),
                            }
                        }
                        _ = kill(pgid_neg, Signal::SIGKILL);
                        _ = child.wait();
                        break Ok(ChildResult {
                            exit_code: TIMEOUT_EXIT_CODE,
                        });
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => break Err(ChildError::Spawn(e)),
        }
    };

    forwarder.detach();
    result
}

/// Guard handle for the spawned signal-forwarding thread.
struct SignalForwarder {
    handle: Option<signal_hook::iterator::Handle>,
}

impl SignalForwarder {
    fn install(pgid: Pid) -> io::Result<Self> {
        use signal_hook::consts::{
            SIGCONT, SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGTSTP, SIGUSR1, SIGUSR2, SIGWINCH,
        };
        use signal_hook::iterator::Signals;

        let mut signals = Signals::new([
            SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2, SIGTSTP, SIGCONT, SIGWINCH,
        ])?;
        let handle = signals.handle();
        std::thread::spawn(move || {
            for sig in &mut signals {
                if let Ok(s) = Signal::try_from(sig) {
                    // Best-effort signal forwarding; ESRCH on race is fine.
                    _ = kill(pgid, s);
                }
            }
        });
        Ok(Self {
            handle: Some(handle),
        })
    }

    fn detach(mut self) {
        if let Some(h) = self.handle.take() {
            h.close();
        }
    }
}

impl Drop for SignalForwarder {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.close();
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::disallowed_methods
)]
mod tests {
    use super::*;

    #[test]
    fn env_is_scrubbed_to_whitelist() {
        // We use unique names to avoid collisions with parallel tests.
        std::env::set_var("EVIL_CERTAUTH_TEST_VAR", "should_be_gone");
        std::env::set_var("PAM_CERTAUTH_TEST_FOO", "kept");

        let env = build_child_env();

        assert!(!env.contains_key("EVIL_CERTAUTH_TEST_VAR"));
        assert_eq!(
            env.get("PAM_CERTAUTH_TEST_FOO").map(String::as_str),
            Some("kept")
        );
        assert_eq!(
            env.get("PATH").map(String::as_str),
            Some("/usr/sbin:/usr/bin:/sbin:/bin")
        );

        std::env::remove_var("EVIL_CERTAUTH_TEST_VAR");
        std::env::remove_var("PAM_CERTAUTH_TEST_FOO");
    }
}
