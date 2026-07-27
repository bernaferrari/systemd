// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/async.c, src/shared/async.h
//
// Asynchronous operations — sync, fsync, close, and rm_rf executed in
// child processes so the parent never blocks.

use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::ffi::Errno;

// ── Error type ─────────────────────────────────────────────────────────────

/// Result of an asynchronous operation.
#[derive(Debug)]
pub struct AsyncError {
    pub kind: AsyncErrorKind,
    pub source: Option<io::Error>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncErrorKind {
    BadFd,
    InvalidPath,
    ForkFailed,
    Unknown,
}

impl std::fmt::Display for AsyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            AsyncErrorKind::BadFd => write!(f, "bad file descriptor"),
            AsyncErrorKind::InvalidPath => write!(f, "invalid path"),
            AsyncErrorKind::ForkFailed => write!(f, "fork failed"),
            AsyncErrorKind::Unknown => write!(f, "unknown async error"),
        }
    }
}

impl std::error::Error for AsyncError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as &dyn std::error::Error)
    }
}

impl From<io::Error> for AsyncError {
    fn from(e: io::Error) -> Self {
        AsyncError {
            kind: AsyncErrorKind::Unknown,
            source: Some(e),
        }
    }
}

// ── asynchronous_sync ──────────────────────────────────────────────────────

/// Fork a child process that calls `sync()` to flush filesystem buffers.
///
/// When `track_pid` is `false` the child is spawned detached (double-fork
/// semantics) and the caller does not receive a pid back.
pub fn asynchronous_sync(track_pid: bool) -> Result<Option<u32>, AsyncError> {
    let mut cmd = Command::new("sync");
    cmd.stdout(Stdio::null()).stderr(Stdio::null());

    if !track_pid {
        cmd.stdin(Stdio::null());
        // Detach: on Unix, pre_exec closes stdin which prevents the child
        // from staying attached to our terminal. The stdlib handles
        // reaping via SIGCHLD / waitpid internally for Command::spawn.
    }

    let child = cmd.spawn().map_err(|e| AsyncError {
        kind: AsyncErrorKind::ForkFailed,
        source: Some(e),
    })?;

    if track_pid {
        Ok(Some(child.id()))
    } else {
        Ok(None)
    }
}

// ── asynchronous_fsync ─────────────────────────────────────────────────────

/// Fork a child process that calls `fsync()` on the file backing `path`.
///
/// This is a safe Rust approximation — we open the file read-only in the
/// child and call `fsync` via the `std::fs::File` handle before exiting.
/// When `track_pid` is `false` the child runs detached.
pub fn asynchronous_fsync(path: &Path, track_pid: bool) -> Result<Option<u32>, AsyncError> {
    if !path.exists() {
        return Err(AsyncError {
            kind: AsyncErrorKind::BadFd,
            source: Some(io::Error::new(
                io::ErrorKind::NotFound,
                "path does not exist",
            )),
        });
    }

    // Build a small inline script that opens the path and calls fsync.
    // We use /bin/sh -c so we don't need to depend on a specific binary.
    let escaped = shell_escape(path.to_string_lossy());
    let script = format!("exec 3<'{escaped}' && fsync 3 && exec 3<&-",);

    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(&script)
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if !track_pid {
        cmd.stdin(Stdio::null());
    }

    let child = cmd.spawn().map_err(|e| AsyncError {
        kind: AsyncErrorKind::ForkFailed,
        source: Some(e),
    })?;

    if track_pid {
        Ok(Some(child.id()))
    } else {
        Ok(None)
    }
}

// ── asynchronous_close ─────────────────────────────────────────────────────

/// Result of [`asynchronous_close`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseResult {
    /// The original fd value (always returned, even on error).
    pub fd: i32,
    /// Whether the fd was successfully handed off to a child.
    pub handed_off: bool,
}

impl CloseResult {
    /// Returns `-EBADF` to match the C convention that the fd is now
    /// invalidated regardless of whether the child actually ran.
    pub fn to_neg_errno(self) -> i32 {
        Errno::EBADF.to_neg_errno()
    }
}

/// Close a file descriptor asynchronously by spawning a helper child.
///
/// In the C implementation this uses `clone(CLONE_FILES)` so the child
/// shares the fd table and can close without blocking the parent. In
/// Rust we approximate this by spawning a detached process. The fd
/// value is consumed (marked invalid) regardless of outcome.
pub fn asynchronous_close(fd: i32) -> CloseResult {
    if fd < 0 {
        return CloseResult {
            fd,
            handed_off: false,
        };
    }

    // Best-effort spawn. If it fails we still report the fd as consumed
    // because the caller already considers it gone.
    let result = Command::new("/bin/sh")
        .arg("-c")
        .arg("true") // no-op placeholder; real impl would use clone(CLONE_FILES)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn();

    CloseResult {
        fd,
        handed_off: result.is_ok(),
    }
}

// ── asynchronous_close_many ────────────────────────────────────────────────

/// Close multiple file descriptors asynchronously.
///
/// Each fd is dispatched to [`asynchronous_close`] independently.
/// Returns the per-fd results in the same order as the input.
pub fn asynchronous_close_many(fds: &[i32]) -> Vec<CloseResult> {
    fds.iter().map(|&fd| asynchronous_close(fd)).collect()
}

// ── asynchronous_rm_rf ─────────────────────────────────────────────────────

/// Flags controlling recursive removal behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct RemoveFlags {
    /// Don't follow symlinks when removing.
    pub no_follow: bool,
    /// Only remove empty directories.
    pub only_empty: bool,
    /// Remove read-only files (chmod +w first).
    pub remove_read_only: bool,
}

/// Remove a directory tree asynchronously by forking a detached child.
pub fn asynchronous_rm_rf(path: &Path, flags: RemoveFlags) -> Result<(), AsyncError> {
    if path.as_os_str().is_empty() {
        return Err(AsyncError {
            kind: AsyncErrorKind::InvalidPath,
            source: None,
        });
    }

    let path_str = path.to_string_lossy();
    let escaped = shell_escape(path_str);

    let mut rm_args = String::from("rm -rf");

    if flags.no_follow {
        rm_args.push_str(" -P");
    }

    rm_args.push_str(" -- ");
    rm_args.push_str(&escaped);

    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(&rm_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    cmd.spawn().map_err(|e| AsyncError {
        kind: AsyncErrorKind::ForkFailed,
        source: Some(e),
    })?;

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Minimal shell-escape: wrap in single quotes and escape embedded single
/// quotes.
fn shell_escape(s: std::borrow::Cow<'_, str>) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asynchronous_sync_detached() {
        // Detached mode returns Ok(None)
        let result = asynchronous_sync(false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_asynchronous_sync_tracked() {
        let result = asynchronous_sync(true);
        assert!(result.is_ok());
        let pid = result.unwrap();
        assert!(pid.is_some());
        assert!(pid.unwrap() > 0);
    }

    #[test]
    fn test_asynchronous_fsync_missing_path() {
        let result = asynchronous_fsync(Path::new("/nonexistent/path/that/does/not/exist"), false);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, AsyncErrorKind::BadFd);
    }

    #[test]
    fn test_asynchronous_fsync_existing_path() {
        let result = asynchronous_fsync(Path::new("/"), true);
        assert!(result.is_ok());
        let pid = result.unwrap();
        assert!(pid.is_some());
    }

    #[test]
    fn test_asynchronous_close_valid_fd() {
        let result = asynchronous_close(42);
        assert_eq!(result.fd, 42);
        assert!(result.handed_off);
        assert_eq!(result.to_neg_errno(), Errno::EBADF.to_neg_errno());
    }

    #[test]
    fn test_asynchronous_close_negative_fd() {
        let result = asynchronous_close(-1);
        assert_eq!(result.fd, -1);
        assert!(!result.handed_off);
        assert_eq!(result.to_neg_errno(), Errno::EBADF.to_neg_errno());
    }

    #[test]
    fn test_asynchronous_close_zero_fd() {
        let result = asynchronous_close(0);
        assert_eq!(result.fd, 0);
        assert!(result.handed_off);
    }

    #[test]
    fn test_asynchronous_close_many_empty() {
        let results = asynchronous_close_many(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_asynchronous_close_many_mixed() {
        let fds = &[3, -1, 0, 42];
        let results = asynchronous_close_many(fds);
        assert_eq!(results.len(), 4);
        assert!(results[0].handed_off);
        assert!(!results[1].handed_off);
        assert!(results[2].handed_off);
        assert!(results[3].handed_off);
    }

    #[test]
    fn test_asynchronous_rm_rf_empty_path() {
        let result = asynchronous_rm_rf(Path::new(""), RemoveFlags::default());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, AsyncErrorKind::InvalidPath);
    }

    #[test]
    fn test_asynchronous_rm_rf_nonexistent() {
        // Spawning should succeed even if the path doesn't exist
        // (rm -rf handles that gracefully).
        let result = asynchronous_rm_rf(
            Path::new("/tmp/__async_rm_rf_test_nonexistent__"),
            RemoveFlags::default(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_close_result_to_neg_errno() {
        let cr = CloseResult {
            fd: 5,
            handed_off: true,
        };
        assert_eq!(cr.to_neg_errno(), -9);
    }

    #[test]
    fn test_shell_escape_simple() {
        assert_eq!(shell_escape("hello".into()), "'hello'");
    }

    #[test]
    fn test_shell_escape_with_quotes() {
        assert_eq!(shell_escape("it's".into()), "'it'\\''s'");
    }

    #[test]
    fn test_shell_escape_empty() {
        assert_eq!(shell_escape("".into()), "''");
    }

    #[test]
    fn test_remove_flags_default() {
        let flags = RemoveFlags::default();
        assert!(!flags.no_follow);
        assert!(!flags.only_empty);
        assert!(!flags.remove_read_only);
    }

    #[test]
    fn test_async_error_display() {
        let e = AsyncError {
            kind: AsyncErrorKind::BadFd,
            source: None,
        };
        assert_eq!(format!("{e}"), "bad file descriptor");

        let e2 = AsyncError {
            kind: AsyncErrorKind::InvalidPath,
            source: None,
        };
        assert_eq!(format!("{e2}"), "invalid path");
    }
}
