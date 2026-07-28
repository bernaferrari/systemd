// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/plymouth-util.c, src/shared/plymouth-util.h
//
// Plymouth boot splash utilities.
//
// Provides communication with the Plymouth boot splash daemon via
// Unix domain sockets. Supports querying Plymouth status, sending
// messages, and controlling splash screen display. Uses the abstract
// Unix socket \0/org/freedesktop/plymouthd (overridable via the
// PLYMOUTH_SOCKET environment variable).

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

// ── Constants ─────────────────────────────────────────────────────────────

/// Default abstract Unix socket address for plymouthd communication.
const PLYMOUTH_SOCKET_ADDR: &str = "\0/org/freedesktop/plymouthd";

/// Path to the Plymouth runtime directory.
const PLYMOUTH_RUN_DIR: &str = "/run/plymouth";

/// Path to the Plymouth PID file.
const PLYMOUTH_PID_FILE: &str = "/run/plymouth/pid";

/// Path to the Plymouth mode file.
const PLYMOUTH_MODE_FILE: &str = "/run/plymouth/mode";

/// Maximum message length (u8::MAX, matching C's UCHAR_MAX constraint).
const MAX_MESSAGE_LEN: usize = 254;

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors that can occur during Plymouth operations.
#[derive(Debug)]
pub enum PlymouthError {
    /// Failed to connect to the Plymouth daemon.
    Connect(io::Error),
    /// Failed to send data to the Plymouth daemon.
    Send(io::Error),
    /// Failed to read data from the Plymouth daemon.
    Read(io::Error),
    /// Plymouth daemon is not running or not available.
    NotAvailable,
    /// Invalid Plymouth mode string encountered.
    InvalidMode(String),
    /// Message text exceeds maximum allowed length.
    MessageTooLong(usize),
}

impl std::fmt::Display for PlymouthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlymouthError::Connect(e) => write!(f, "failed to connect to plymouth: {e}"),
            PlymouthError::Send(e) => write!(f, "failed to send to plymouth: {e}"),
            PlymouthError::Read(e) => write!(f, "failed to read from plymouth: {e}"),
            PlymouthError::NotAvailable => write!(f, "plymouth is not available"),
            PlymouthError::InvalidMode(s) => write!(f, "invalid plymouth mode: {s}"),
            PlymouthError::MessageTooLong(len) => {
                write!(f, "message too long: {len} bytes (max {MAX_MESSAGE_LEN})")
            }
        }
    }
}

impl std::error::Error for PlymouthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PlymouthError::Connect(e) | PlymouthError::Send(e) | PlymouthError::Read(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for PlymouthError {
    fn from(e: io::Error) -> Self {
        PlymouthError::Connect(e)
    }
}

// ── Plymouth Mode ─────────────────────────────────────────────────────────

/// Plymouth display mode, indicating the current state of the splash screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlymouthMode {
    /// Plymouth is not running or splash is off.
    Off,
    /// Plymouth is displaying a boot splash screen.
    Boot,
    /// Plymouth is displaying a shutdown splash screen.
    Shutdown,
    /// Plymouth is in updates/firmware mode.
    Updates,
}

impl PlymouthMode {
    /// Parse a Plymouth mode from its string representation.
    ///
    /// Recognized values: `"boot"`, `"shutdown"`, `"updates"`, `"off"`.
    /// Leading/trailing whitespace is trimmed. Returns `None` for
    /// unrecognized strings.
    pub fn from_str_mode(s: &str) -> Option<Self> {
        match s.trim() {
            "boot" => Some(PlymouthMode::Boot),
            "shutdown" => Some(PlymouthMode::Shutdown),
            "updates" => Some(PlymouthMode::Updates),
            "off" => Some(PlymouthMode::Off),
            _ => None,
        }
    }

    /// Convert the mode to its string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            PlymouthMode::Off => "off",
            PlymouthMode::Boot => "boot",
            PlymouthMode::Shutdown => "shutdown",
            PlymouthMode::Updates => "updates",
        }
    }

    /// Returns `true` if Plymouth is actively displaying a splash screen.
    pub fn is_active(&self) -> bool {
        !matches!(self, PlymouthMode::Off)
    }
}

impl std::fmt::Display for PlymouthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Error Classification ──────────────────────────────────────────────────

/// Check if an I/O error indicates that Plymouth is not available.
///
/// Mirrors the C `ERRNO_IS_NO_PLYMOUTH` macro, which considers EAGAIN,
/// ENOENT, and various disconnection errors as "plymouth not available"
/// conditions.
pub fn errno_is_no_plymouth(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::NotFound
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
            | io::ErrorKind::AddrNotAvailable
    )
}

// ── Socket Connection ─────────────────────────────────────────────────────

/// Resolve the Plymouth socket address.
///
/// Checks the `PLYMOUTH_SOCKET` environment variable first, then falls
/// back to the abstract Unix socket `\0/org/freedesktop/plymouthd`.
fn plymouth_socket_path() -> String {
    env::var("PLYMOUTH_SOCKET").unwrap_or_else(|_| PLYMOUTH_SOCKET_ADDR.to_string())
}

/// Connect to the Plymouth daemon's Unix domain socket.
///
/// Uses the `PLYMOUTH_SOCKET` environment variable if set, otherwise
/// connects to the abstract socket `\0/org/freedesktop/plymouthd`.
/// The socket is set to non-blocking mode, matching the C implementation's
/// `SOCK_NONBLOCK` usage in [`plymouth_send_msg`] and [`plymouth_hide_splash`].
///
/// # Errors
///
/// Returns [`PlymouthError::NotAvailable`] if the connection fails due to
/// Plymouth not running (classified by [`errno_is_no_plymouth`]).
/// Returns [`PlymouthError::Connect`] for other connection errors.
pub fn plymouth_connect() -> Result<UnixStream, PlymouthError> {
    let path = plymouth_socket_path();
    let stream = UnixStream::connect(&path).map_err(|e| {
        if errno_is_no_plymouth(&e) {
            PlymouthError::NotAvailable
        } else {
            PlymouthError::Connect(e)
        }
    })?;
    stream
        .set_nonblocking(true)
        .map_err(PlymouthError::Connect)?;
    Ok(stream)
}

// ── Raw Send ──────────────────────────────────────────────────────────────

/// Send raw bytes to the Plymouth daemon.
///
/// Connects to Plymouth and writes the entire `payload` buffer.
///
/// # Errors
///
/// Returns [`PlymouthError::NotAvailable`] if Plymouth is not running.
/// Returns [`PlymouthError::Send`] if the write fails after connection.
pub fn plymouth_send_raw(raw: &[u8]) -> Result<(), PlymouthError> {
    let mut stream = plymouth_connect()?;
    stream.write_all(raw).map_err(PlymouthError::Send)?;
    Ok(())
}

// ── Message Send ──────────────────────────────────────────────────────────

/// Send a text message to the Plymouth splash screen.
///
/// Formats and sends a message using the Plymouth protocol:
/// `M\x02<len><text>\0<spinner_flag>\0`
///
/// Where `<len>` is `text.len() + 1` (including NUL terminator) encoded
/// as a single byte, and `<spinner_flag>` is `'A'` to pause or `'a'` to
/// resume the spinner animation.
///
/// # Arguments
///
/// * `text` - The message text to display (must be ≤ 254 bytes).
/// * `pause_spinner` - If `true`, pause the spinner; if `false`, resume it.
///
/// # Errors
///
/// Returns [`PlymouthError::MessageTooLong`] if the text exceeds 254 bytes.
/// Returns [`PlymouthError::NotAvailable`] if Plymouth is not running.
/// Returns [`PlymouthError::Send`] if the write fails.
pub fn plymouth_send_msg(text: &str, pause_spinner: bool) -> Result<(), PlymouthError> {
    let text_bytes = text.as_bytes();
    if text_bytes.len() > MAX_MESSAGE_LEN {
        return Err(PlymouthError::MessageTooLong(text_bytes.len()));
    }

    let spinner = if pause_spinner { b'A' } else { b'a' };
    let len = (text_bytes.len() + 1) as u8; // +1 for NUL terminator

    let mut payload = Vec::with_capacity(text_bytes.len() + 6);
    payload.extend_from_slice(b"M\x02");
    payload.push(len);
    payload.extend_from_slice(text_bytes);
    payload.push(0x00); // NUL after text
    payload.push(spinner);
    payload.push(0x00); // trailing NUL

    plymouth_send_raw(&payload)
}

// ── Hide Splash ───────────────────────────────────────────────────────────

/// Hide the Plymouth splash screen.
///
/// Sends the `H\0` command to the Plymouth daemon, causing it to exit
/// and display the underlying console. This is typically called before
/// interactive prompts (e.g., password entry, firstboot setup).
///
/// # Errors
///
/// Returns [`PlymouthError::NotAvailable`] if Plymouth is not running.
/// This is not considered a hard error — Plymouth may simply not be
/// installed or active. Returns [`PlymouthError::Send`] if the write
/// fails after a successful connection.
pub fn plymouth_hide_splash() -> Result<(), PlymouthError> {
    plymouth_send_raw(b"H\0")
}

// ── Status Queries ────────────────────────────────────────────────────────

/// Check whether the Plymouth daemon is currently running.
///
/// Performs a layered detection:
/// 1. Checks for `/run/plymouth/pid` (PID file).
/// 2. Checks for `/run/plymouth/` directory existence.
/// 3. Falls back to attempting a socket connection.
///
/// Returns `true` if Plymouth is detected, `false` otherwise.
pub fn plymouth_is_running() -> bool {
    if Path::new(PLYMOUTH_PID_FILE).exists() {
        return true;
    }

    if Path::new(PLYMOUTH_RUN_DIR).is_dir() {
        return true;
    }

    plymouth_connect().is_ok()
}

/// Determine the current Plymouth display mode.
///
/// Reads the mode string from `/run/plymouth/mode` and parses it into
/// a [`PlymouthMode`] variant.
///
/// # Errors
///
/// Returns [`PlymouthError::NotAvailable`] if the mode file does not
/// exist (Plymouth not running).
/// Returns [`PlymouthError::InvalidMode`] if the file contains an
/// unrecognized mode string.
/// Returns [`PlymouthError::Read`] for other I/O errors.
pub fn plymouth_mode() -> Result<PlymouthMode, PlymouthError> {
    let content = fs::read_to_string(PLYMOUTH_MODE_FILE).map_err(|e| {
        if errno_is_no_plymouth(&e) {
            PlymouthError::NotAvailable
        } else {
            PlymouthError::Read(e)
        }
    })?;

    PlymouthMode::from_str_mode(&content)
        .ok_or_else(|| PlymouthError::InvalidMode(content.trim().to_string()))
}

/// Send a query command to Plymouth and read the response.
///
/// Sends `command` bytes over the Plymouth socket, shuts down the
/// write half, then reads the full response. The response is trimmed
/// of trailing whitespace and returned as a UTF-8 string.
///
/// # Arguments
///
/// * `command` - Raw command bytes to send (e.g., protocol query bytes).
///
/// # Errors
///
/// Returns [`PlymouthError::NotAvailable`] if Plymouth is not running.
/// Returns [`PlymouthError::Send`] if the command cannot be sent.
/// Returns [`PlymouthError::Read`] if the response cannot be read.
/// Returns [`PlymouthError::InvalidMode`] if the response is not valid UTF-8.
pub fn plymouth_query(command: &[u8]) -> Result<String, PlymouthError> {
    let mut stream = plymouth_connect()?;
    stream.write_all(command).map_err(PlymouthError::Send)?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(PlymouthError::Send)?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(PlymouthError::Read)?;

    String::from_utf8(response)
        .map(|s| s.trim_end().to_string())
        .map_err(|_| PlymouthError::InvalidMode("non-UTF-8 response".to_string()))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::TestEnvironment;
    use std::error::Error;

    // ── PlymouthMode parsing ──────────────────────────────────────────

    #[test]
    fn test_plymouth_mode_from_str_boot() {
        assert_eq!(
            PlymouthMode::from_str_mode("boot"),
            Some(PlymouthMode::Boot)
        );
    }

    #[test]
    fn test_plymouth_mode_from_str_shutdown() {
        assert_eq!(
            PlymouthMode::from_str_mode("shutdown"),
            Some(PlymouthMode::Shutdown)
        );
    }

    #[test]
    fn test_plymouth_mode_from_str_updates() {
        assert_eq!(
            PlymouthMode::from_str_mode("updates"),
            Some(PlymouthMode::Updates)
        );
    }

    #[test]
    fn test_plymouth_mode_from_str_off() {
        assert_eq!(PlymouthMode::from_str_mode("off"), Some(PlymouthMode::Off));
    }

    #[test]
    fn test_plymouth_mode_from_str_unknown() {
        assert_eq!(PlymouthMode::from_str_mode("bogus"), None);
        assert_eq!(PlymouthMode::from_str_mode(""), None);
        assert_eq!(PlymouthMode::from_str_mode("BOOT"), None);
    }

    #[test]
    fn test_plymouth_mode_from_str_trims_whitespace() {
        assert_eq!(
            PlymouthMode::from_str_mode(" boot \n"),
            Some(PlymouthMode::Boot)
        );
        assert_eq!(
            PlymouthMode::from_str_mode("\tshutdown\n"),
            Some(PlymouthMode::Shutdown)
        );
        assert_eq!(
            PlymouthMode::from_str_mode("  updates  "),
            Some(PlymouthMode::Updates)
        );
    }

    // ── PlymouthMode display / properties ─────────────────────────────

    #[test]
    fn test_plymouth_mode_as_str() {
        assert_eq!(PlymouthMode::Off.as_str(), "off");
        assert_eq!(PlymouthMode::Boot.as_str(), "boot");
        assert_eq!(PlymouthMode::Shutdown.as_str(), "shutdown");
        assert_eq!(PlymouthMode::Updates.as_str(), "updates");
    }

    #[test]
    fn test_plymouth_mode_display_trait() {
        assert_eq!(format!("{}", PlymouthMode::Boot), "boot");
        assert_eq!(format!("{}", PlymouthMode::Shutdown), "shutdown");
    }

    #[test]
    fn test_plymouth_mode_equality() {
        assert_eq!(PlymouthMode::Boot, PlymouthMode::Boot);
        assert_ne!(PlymouthMode::Boot, PlymouthMode::Shutdown);
        assert_eq!(PlymouthMode::Off, PlymouthMode::Off);
        assert_ne!(PlymouthMode::Boot, PlymouthMode::Off);
    }

    #[test]
    fn test_plymouth_mode_is_active() {
        assert!(PlymouthMode::Boot.is_active());
        assert!(PlymouthMode::Shutdown.is_active());
        assert!(PlymouthMode::Updates.is_active());
        assert!(!PlymouthMode::Off.is_active());
    }

    // ── errno_is_no_plymouth ──────────────────────────────────────────

    #[test]
    fn test_errno_is_no_plymouth_would_block() {
        let err = io::Error::new(io::ErrorKind::WouldBlock, "would block");
        assert!(errno_is_no_plymouth(&err));
    }

    #[test]
    fn test_errno_is_no_plymouth_not_found() {
        let err = io::Error::new(io::ErrorKind::NotFound, "not found");
        assert!(errno_is_no_plymouth(&err));
    }

    #[test]
    fn test_errno_is_no_plymouth_connection_refused() {
        let err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        assert!(errno_is_no_plymouth(&err));
    }

    #[test]
    fn test_errno_is_no_plymouth_connection_reset() {
        let err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        assert!(errno_is_no_plymouth(&err));
    }

    #[test]
    fn test_errno_is_no_plymouth_connection_aborted() {
        let err = io::Error::new(io::ErrorKind::ConnectionAborted, "aborted");
        assert!(errno_is_no_plymouth(&err));
    }

    #[test]
    fn test_errno_is_no_plymouth_broken_pipe() {
        let err = io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe");
        assert!(errno_is_no_plymouth(&err));
    }

    #[test]
    fn test_errno_is_no_plymouth_timed_out() {
        let err = io::Error::new(io::ErrorKind::TimedOut, "timed out");
        assert!(errno_is_no_plymouth(&err));
    }

    #[test]
    fn test_errno_is_no_plymouth_not_connected() {
        let err = io::Error::new(io::ErrorKind::NotConnected, "not connected");
        assert!(errno_is_no_plymouth(&err));
    }

    #[test]
    fn test_errno_is_no_plymouth_addr_not_available() {
        let err = io::Error::new(io::ErrorKind::AddrNotAvailable, "addr not available");
        assert!(errno_is_no_plymouth(&err));
    }

    #[test]
    fn test_errno_is_not_no_plymouth_permission_denied() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "permission denied");
        assert!(!errno_is_no_plymouth(&err));
    }

    #[test]
    fn test_errno_is_not_no_plymouth_already_exists() {
        let err = io::Error::new(io::ErrorKind::AlreadyExists, "already exists");
        assert!(!errno_is_no_plymouth(&err));
    }

    #[test]
    fn test_errno_is_not_no_plymouth_invalid_input() {
        let err = io::Error::new(io::ErrorKind::InvalidInput, "invalid input");
        assert!(!errno_is_no_plymouth(&err));
    }

    // ── PlymouthError ────────────────────────────────────────────────

    #[test]
    fn test_plymouth_error_display_not_available() {
        let err = PlymouthError::NotAvailable;
        let msg = err.to_string();
        assert!(msg.contains("plymouth"));
        assert!(msg.contains("not available"));
    }

    #[test]
    fn test_plymouth_error_display_invalid_mode() {
        let err = PlymouthError::InvalidMode("bogus".to_string());
        let msg = err.to_string();
        assert!(msg.contains("bogus"));
        assert!(msg.contains("invalid"));
    }

    #[test]
    fn test_plymouth_error_display_message_too_long() {
        let err = PlymouthError::MessageTooLong(300);
        let msg = err.to_string();
        assert!(msg.contains("300"));
        assert!(msg.contains("254"));
    }

    #[test]
    fn test_plymouth_error_source_chain() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let err = PlymouthError::Connect(io_err);
        assert!(err.source().is_some());

        let err = PlymouthError::NotAvailable;
        assert!(err.source().is_none());
    }

    // ── Message construction ─────────────────────────────────────────

    #[test]
    fn test_plymouth_send_msg_too_long() {
        let long_text = "x".repeat(256);
        let result = plymouth_send_msg(&long_text, false);
        assert!(matches!(result, Err(PlymouthError::MessageTooLong(256))));
    }

    #[test]
    fn test_plymouth_send_msg_max_length_ok() {
        let max_text = "x".repeat(MAX_MESSAGE_LEN);
        let result = plymouth_send_msg(&max_text, false);
        // Should not fail at message construction (may fail at connect)
        assert!(!matches!(result, Err(PlymouthError::MessageTooLong(_))));
    }

    #[test]
    fn test_plymouth_send_msg_exactly_max_plus_one() {
        let over_text = "y".repeat(MAX_MESSAGE_LEN + 1);
        let result = plymouth_send_msg(&over_text, true);
        assert!(matches!(
            result,
            Err(PlymouthError::MessageTooLong(n)) if n == MAX_MESSAGE_LEN + 1
        ));
    }

    #[test]
    fn test_plymouth_send_msg_empty_text() {
        // Empty text should be valid (0 + 1 = 1 byte length field)
        let result = plymouth_send_msg("", false);
        assert!(!matches!(result, Err(PlymouthError::MessageTooLong(_))));
    }

    // ── Socket path resolution ───────────────────────────────────────

    #[test]
    fn test_plymouth_socket_path_default() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        environment.remove("PLYMOUTH_SOCKET");
        let path = plymouth_socket_path();
        assert!(path.starts_with('\0'));
        assert!(path.contains("plymouthd"));
    }

    #[test]
    fn test_plymouth_socket_path_env_override() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        environment.set("PLYMOUTH_SOCKET", "/tmp/test-plymouth-sock");
        let path = plymouth_socket_path();
        assert_eq!(path, "/tmp/test-plymouth-sock");
    }

    // ── Status queries (environment-dependent) ───────────────────────

    #[test]
    fn test_plymouth_is_running_returns_bool() {
        // Doesn't assert specific value — depends on test environment
        let _result = plymouth_is_running();
    }

    #[test]
    fn test_plymouth_hide_splash_no_panic() {
        // Should not panic even without plymouth running
        let _result = plymouth_hide_splash();
    }

    #[test]
    fn test_plymouth_mode_no_plymouth() {
        // Without plymouth, should fail (mode file missing)
        let result = plymouth_mode();
        assert!(result.is_err());
    }
}
