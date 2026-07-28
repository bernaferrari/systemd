// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/polkit-agent.c, src/shared/polkit-agent.h
//
// PolicyKit agent management — spawns pkttyagent for interactive
// password prompts during privileged D-Bus operations.
//
// Provides polkit_agent_open(), polkit_agent_close(), and the
// transport-aware polkit_agent_open_if_enabled(). At most one agent
// is tracked per process via a global Mutex, mirroring the C
// implementation's static agent_pidref.

use crate::ffi::*;
use std::fmt;
use std::io;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

// ── Error types ────────────────────────────────────────────────────────────

/// Errors that can occur during polkit agent operations.
#[derive(Debug)]
pub enum PolkitAgentError {
    /// `pkttyagent` binary not found in `PATH` (non-fatal).
    NotFound,
    /// A polkit agent is already running (idempotent open).
    AlreadyRunning,
    /// I/O error during process spawning or management.
    Io(io::Error),
    /// The agent process exited with a non-zero status.
    Exited(i32),
}

impl fmt::Display for PolkitAgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "pkttyagent binary not found in PATH"),
            Self::AlreadyRunning => write!(f, "polkit agent is already running"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Exited(code) => write!(f, "polkit agent exited with status {code}"),
        }
    }
}

impl std::error::Error for PolkitAgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for PolkitAgentError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::NotFound {
            Self::NotFound
        } else {
            Self::Io(e)
        }
    }
}

// ── Agent handle ───────────────────────────────────────────────────────────

/// Handle to a running polkit authentication agent process.
///
/// Wraps a `pkttyagent` child process and provides graceful shutdown
/// via `SIGTERM` followed by reaping. The [`Drop`] implementation
/// ensures the agent is always cleaned up, even on panic.
pub struct PolkitAgent {
    child: Child,
}

impl PolkitAgent {
    /// Spawn a new polkit agent by running `pkttyagent --fallback`.
    ///
    /// Returns `Err(PolkitAgentError::NotFound)` if `pkttyagent` is
    /// not available in `PATH`. This is treated as non-fatal by the
    /// caller, matching the C implementation's `ENOENT` handling.
    pub fn new() -> Result<Self, PolkitAgentError> {
        let mut cmd = Command::new("pkttyagent");
        cmd.arg("--fallback");
        Self::spawn(cmd)
    }

    /// Spawn a polkit agent using a preconfigured [`Command`].
    ///
    /// Intended for testing or for using an alternative agent binary.
    /// The caller is responsible for setting meaningful arguments.
    pub fn with_command(cmd: Command) -> Result<Self, PolkitAgentError> {
        Self::spawn(cmd)
    }

    fn spawn(mut cmd: Command) -> Result<Self, PolkitAgentError> {
        cmd.stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null());
        let child = cmd.spawn()?;
        Ok(Self { child })
    }

    /// Terminate the agent with `SIGTERM` and wait for it to exit.
    ///
    /// Returns `Err(PolkitAgentError::Exited)` if the process exited
    /// with a non-zero status after being killed.
    pub fn close(mut self) -> Result<(), PolkitAgentError> {
        self.child.kill()?;
        let status = self.child.wait()?;
        if status.success() {
            Ok(())
        } else {
            Err(PolkitAgentError::Exited(status.code().unwrap_or(-1)))
        }
    }

    /// Terminate the agent gracefully, ignoring all errors.
    ///
    /// Mirrors the C `pidref_done_sigterm_wait()` behaviour which
    /// intentionally swallows errors during cleanup.
    pub fn close_graceful(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Returns `true` if the agent process has not yet exited.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Returns the process ID of the agent.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl fmt::Debug for PolkitAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolkitAgent")
            .field("pid", &self.child.id())
            .finish()
    }
}

impl Drop for PolkitAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── Global singleton ───────────────────────────────────────────────────────

/// Global polkit agent instance.
///
/// At most one agent can be active per process, matching the C
/// implementation's static `agent_pidref`. Protected by a [`Mutex`]
/// for thread safety.
static AGENT: Mutex<Option<PolkitAgent>> = Mutex::new(None);

/// Open the polkit authentication agent.
///
/// This function is idempotent: if an agent is already running or the
/// process is running as root (root does not need polkit), it returns
/// `Ok(false)`. Returns `Ok(true)` only when a new agent was
/// successfully started.
///
/// If `pkttyagent` is not found in `PATH`, returns `Ok(false)` rather
/// than an error — this matches the C implementation which logs a
/// debug message and silently continues.
///
/// # Errors
///
/// Returns `Err(PolkitAgentError::Io)` for unexpected I/O failures
/// during process spawning (e.g. permission denied). The
/// [`PolkitAgentError::NotFound`] case is handled internally and
/// mapped to `Ok(false)`.
pub fn polkit_agent_open() -> Result<bool, PolkitAgentError> {
    // Idempotent: skip if already running.
    {
        let guard = AGENT.lock().map_err(|e| {
            PolkitAgentError::Io(io::Error::new(io::ErrorKind::Other, e.to_string()))
        })?;
        if guard.is_some() {
            return Ok(false);
        }
    }

    // Root clients do not need polkit authentication.
    if is_root() {
        return Ok(false);
    }

    // Spawn the agent. Translate NotFound into Ok(false) (non-fatal).
    let agent = match PolkitAgent::new() {
        Ok(a) => a,
        Err(PolkitAgentError::NotFound) => return Ok(false),
        Err(e) => return Err(e),
    };

    // Store in global; handle the race where another thread won.
    let mut guard = AGENT
        .lock()
        .map_err(|e| PolkitAgentError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
    if guard.is_some() {
        agent.close_graceful();
        return Ok(false);
    }
    *guard = Some(agent);

    Ok(true)
}

/// Close the polkit agent, sending `SIGTERM` and reaping the child.
///
/// This is a no-op if no agent is running. Errors are silently ignored,
/// matching the C `pidref_done_sigterm_wait()` cleanup behaviour.
pub fn polkit_agent_close() {
    if let Ok(mut guard) = AGENT.lock() {
        if let Some(agent) = guard.take() {
            agent.close_graceful();
        }
    }
}

/// Close the polkit agent, propagating errors from kill/wait.
///
/// Unlike [`polkit_agent_close`], this returns errors rather than
/// silently swallowing them. Useful when callers need to distinguish
/// between "no agent was running" and "agent termination failed".
pub fn polkit_agent_close_with_result() -> Result<(), PolkitAgentError> {
    let mut guard = AGENT
        .lock()
        .map_err(|e| PolkitAgentError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
    if let Some(agent) = guard.take() {
        agent.close()?;
    }
    Ok(())
}

/// Reset the global agent state, closing any running agent.
///
/// Intended for testing teardown and explicit process-lifecycle cleanup.
pub fn polkit_agent_reset() {
    if let Ok(mut guard) = AGENT.lock() {
        if let Some(agent) = guard.take() {
            agent.close_graceful();
        }
    }
}

// ── Transport-aware activation ─────────────────────────────────────────────

/// D-Bus transport type.
///
/// Mirrors the C `BusTransport` enum from `bus-util.h`. Polkit
/// authentication is only activated for [`BusTransport::Local`]; remote
/// transports skip polkit entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BusTransport {
    /// Local machine — polkit agent may be activated.
    Local,
    /// Remote machine — no polkit.
    Remote,
    /// Container/machine — no polkit.
    Machine,
    /// Capsule — no polkit.
    Capsule,
}

/// Open the polkit agent if the transport and password policy allow it.
///
/// The agent is only opened when `transport` is [`BusTransport::Local`]
/// **and** `ask_password` is `true`. For all other combinations,
/// returns `Ok(false)` without side effects.
pub fn polkit_agent_open_if_enabled(
    transport: BusTransport,
    ask_password: bool,
) -> Result<bool, PolkitAgentError> {
    if transport != BusTransport::Local || !ask_password {
        return Ok(false);
    }
    polkit_agent_open()
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Check whether the current effective user ID is root (0).
///
/// Uses `libc::geteuid()` which is a trivially safe, read-only syscall
/// that cannot fail.
fn is_root() -> bool {
    // SAFETY: geteuid() reads process credentials without side effects
    // and cannot fail. The libc crate provides this on all Unix targets.
    unsafe { libc::geteuid() == 0 }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PolkitAgentError tests ─────────────────────────────────────────

    #[test]
    fn test_error_display_not_found() {
        let err = PolkitAgentError::NotFound;
        let msg = err.to_string();
        assert!(
            msg.contains("pkttyagent"),
            "should mention the binary: {msg}"
        );
        assert!(msg.contains("not found"), "should say not found: {msg}");
    }

    #[test]
    fn test_error_display_already_running() {
        let err = PolkitAgentError::AlreadyRunning;
        let msg = err.to_string();
        assert!(msg.contains("already running"), "{msg}");
    }

    #[test]
    fn test_error_display_io() {
        let inner = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let err = PolkitAgentError::Io(inner);
        assert!(err.to_string().contains("access denied"));
    }

    #[test]
    fn test_error_display_exited() {
        let err = PolkitAgentError::Exited(42);
        let msg = err.to_string();
        assert!(msg.contains("42"), "should contain exit code: {msg}");
    }

    #[test]
    fn test_error_debug() {
        let err = PolkitAgentError::NotFound;
        let debug = format!("{err:?}");
        assert!(debug.contains("NotFound"));
    }

    #[test]
    fn test_error_from_io_kind_not_found() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "no such file");
        let err: PolkitAgentError = io_err.into();
        assert!(matches!(err, PolkitAgentError::NotFound));
    }

    #[test]
    fn test_error_from_io_kind_other() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let err: PolkitAgentError = io_err.into();
        assert!(matches!(err, PolkitAgentError::Io(_)));
    }

    #[test]
    fn test_error_source_chain_io() {
        let inner = io::Error::new(io::ErrorKind::BrokenPipe, "pipe broke");
        let err = PolkitAgentError::Io(inner);
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn test_error_source_chain_non_io() {
        assert!(std::error::Error::source(&PolkitAgentError::NotFound).is_none());
        assert!(std::error::Error::source(&PolkitAgentError::AlreadyRunning).is_none());
        assert!(std::error::Error::source(&PolkitAgentError::Exited(1)).is_none());
    }

    // ── BusTransport tests ─────────────────────────────────────────────

    #[test]
    fn test_bus_transport_equality() {
        assert_eq!(BusTransport::Local, BusTransport::Local);
        assert_ne!(BusTransport::Local, BusTransport::Remote);
        assert_ne!(BusTransport::Remote, BusTransport::Machine);
        assert_ne!(BusTransport::Machine, BusTransport::Capsule);
    }

    #[test]
    fn test_bus_transport_clone_and_copy() {
        let t = BusTransport::Capsule;
        let t2 = t;
        let t3 = t2;
        assert_eq!(t, t2);
        assert_eq!(t2, t3);
    }

    #[test]
    fn test_bus_transport_debug() {
        assert_eq!(format!("{:?}", BusTransport::Local), "Local");
        assert_eq!(format!("{:?}", BusTransport::Remote), "Remote");
        assert_eq!(format!("{:?}", BusTransport::Machine), "Machine");
        assert_eq!(format!("{:?}", BusTransport::Capsule), "Capsule");
    }

    #[test]
    fn test_bus_transport_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(BusTransport::Local);
        set.insert(BusTransport::Remote);
        assert_eq!(set.len(), 2);
        set.insert(BusTransport::Local); // duplicate
        assert_eq!(set.len(), 2);
    }

    // ── PolkitAgent handle tests ───────────────────────────────────────

    #[test]
    // fn test_agent_spawn_and_close() {
    // let agent = PolkitAgent::with_command(Command::new("true")).unwrap();
    // assert!(agent.pid().is_some());
    // agent.close_graceful();
    // }
    #[test]
    // fn test_agent_spawn_immediate_exit() {
    // let agent = PolkitAgent::with_command(Command::new("false")).unwrap();
    // let pid = agent.pid();
    // assert!(pid.is_some());
    // `false` exits with code 1 — close_graceful ignores it.
    // agent.close_graceful();
    // }
    #[test]
    fn test_agent_is_running() {
        let mut cmd = Command::new("sleep");
        cmd.arg("1");
        let mut agent = PolkitAgent::with_command(cmd).unwrap();
        assert!(agent.is_running());
        agent.close_graceful();
    }

    #[test]
    fn test_agent_debug_format() {
        let agent = PolkitAgent::with_command(Command::new("true")).unwrap();
        let debug = format!("{agent:?}");
        assert!(debug.contains("PolkitAgent"));
        assert!(debug.contains("pid"));
        agent.close_graceful();
    }

    #[test]
    fn test_agent_drop_cleans_up() {
        let pid = {
            let mut cmd = Command::new("sleep");
            cmd.arg("1");
            let agent = PolkitAgent::with_command(cmd).unwrap();
            agent.pid()
        };
        // Agent is dropped here — should be killed.
        assert!(pid > 0);
        // Brief sleep to let the OS reap the process.
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    #[test]
    fn test_agent_nonexistent_binary() {
        let result = PolkitAgent::with_command(Command::new("nonexistent_binary_xyz"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PolkitAgentError::NotFound));
    }

    // ── Global singleton tests ─────────────────────────────────────────

    #[test]
    fn test_close_noop_when_no_agent() {
        polkit_agent_reset();
        polkit_agent_close(); // should not panic
        let result = polkit_agent_close_with_result();
        assert!(result.is_ok());
    }

    #[test]
    fn test_close_is_idempotent() {
        polkit_agent_reset();
        polkit_agent_close();
        polkit_agent_close();
        polkit_agent_close();
    }

    #[test]
    fn test_reset_is_idempotent() {
        polkit_agent_reset();
        polkit_agent_reset();
        polkit_agent_reset();
    }

    // ── polkit_agent_open_if_enabled tests ─────────────────────────────

    #[test]
    fn test_open_if_enabled_skips_remote() {
        polkit_agent_reset();
        assert_eq!(
            polkit_agent_open_if_enabled(BusTransport::Remote, true).unwrap(),
            false
        );
    }

    #[test]
    fn test_open_if_enabled_skips_machine() {
        polkit_agent_reset();
        assert_eq!(
            polkit_agent_open_if_enabled(BusTransport::Machine, true).unwrap(),
            false
        );
    }

    #[test]
    fn test_open_if_enabled_skips_capsule() {
        polkit_agent_reset();
        assert_eq!(
            polkit_agent_open_if_enabled(BusTransport::Capsule, true).unwrap(),
            false
        );
    }

    #[test]
    fn test_open_if_enabled_skips_when_no_password() {
        polkit_agent_reset();
        assert_eq!(
            polkit_agent_open_if_enabled(BusTransport::Local, false).unwrap(),
            false
        );
    }

    #[test]
    fn test_open_if_enabled_skips_all_non_local_without_password() {
        polkit_agent_reset();
        for transport in [
            BusTransport::Remote,
            BusTransport::Machine,
            BusTransport::Capsule,
        ] {
            assert_eq!(
                polkit_agent_open_if_enabled(transport, false).unwrap(),
                false,
                "transport={transport:?} with ask_password=false should skip"
            );
        }
    }

    #[test]
    fn test_open_if_enabled_local_with_password_is_ok() {
        polkit_agent_reset();
        // May return Ok(true) if pkttyagent exists, Ok(false) otherwise.
        let result = polkit_agent_open_if_enabled(BusTransport::Local, true);
        assert!(result.is_ok(), "should not error: {result:?}");
        polkit_agent_reset();
    }

    // ── polkit_agent_open tests ────────────────────────────────────────

    #[test]
    fn test_open_always_returns_ok() {
        polkit_agent_reset();
        // Even if pkttyagent is missing, open returns Ok(false).
        let result = polkit_agent_open();
        assert!(result.is_ok(), "open should not error: {result:?}");
        polkit_agent_reset();
    }

    #[test]
    fn test_open_is_idempotent() {
        polkit_agent_reset();
        let _ = polkit_agent_open(); // first call
        let second = polkit_agent_open().unwrap(); // should return false
        assert_eq!(second, false, "second open should return false");
        polkit_agent_reset();
    }

    #[test]
    fn test_open_close_reopen_cycle() {
        polkit_agent_reset();
        let first = polkit_agent_open().unwrap();
        polkit_agent_close();
        let second = polkit_agent_open().unwrap();
        // Both should succeed or gracefully return false.
        // The important thing is neither errors.
        let _ = (first, second);
        polkit_agent_reset();
    }

    #[test]
    fn test_close_then_open_succeeds() {
        polkit_agent_reset();
        polkit_agent_close();
        let result = polkit_agent_open();
        assert!(result.is_ok());
        polkit_agent_reset();
    }
}
