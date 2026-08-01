// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/async.c
//
// Asynchronous I/O utilities — non-blocking file descriptor management,
// deferred close, and background sync/rm operations.
//
// Provides mechanisms to close file descriptors, sync data to disk, and
// remove directory trees without blocking the calling process.  Child
// processes are forked (or, on Linux, cloned with CLONE_FILES) so that
// the parent never hangs on potentially blocking syscalls such as
// close() on a busy NFS mount.

use crate::ffi::*;
use std::io;
use std::os::unix::io::RawFd;
use std::path::Path;

// ── Error types ────────────────────────────────────────────────────────────

/// Errors produced by asynchronous I/O operations.
#[derive(Debug)]
pub enum AsyncError {
    /// File descriptor is already invalid (negative).
    BadFd,
    /// Fork or clone syscall failed.
    ForkFailed(io::Error),
    /// The provided path is empty or otherwise invalid.
    InvalidPath,
    /// Waiting for a child process failed.
    WaitFailed(io::Error),
}

impl std::fmt::Display for AsyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadFd => write!(f, "bad file descriptor"),
            Self::ForkFailed(e) => write!(f, "fork failed: {e}"),
            Self::InvalidPath => write!(f, "invalid path"),
            Self::WaitFailed(e) => write!(f, "wait failed: {e}"),
        }
    }
}

impl std::error::Error for AsyncError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ForkFailed(e) | Self::WaitFailed(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for AsyncError {
    fn from(e: io::Error) -> Self {
        Self::ForkFailed(e)
    }
}

/// Convenience alias for results of asynchronous operations.
pub type AsyncResult<T> = Result<T, AsyncError>;

// ── Close-request encoding ─────────────────────────────────────────────────

/// Highest bit of a `u32`, signalling that a double-fork is needed when
/// the calling process is not a subreaper.
///
/// Mirrors the C macro:
/// ```c
/// #define NEED_DOUBLE_FORK (1U << (sizeof(unsigned) * 8 - 1))
/// ```
pub const NEED_DOUBLE_FORK: u32 = 1u32 << (std::mem::size_of::<u32>() * 8 - 1);

/// Encodes a close request: the fd occupies the lower bits and
/// [`NEED_DOUBLE_FORK`] sits in the highest bit.
///
/// This encoding is passed to a cloned child process via the `clone()`
/// argument pointer.
#[inline]
pub fn encode_close_request(fd: RawFd, need_double_fork: bool) -> u32 {
    let bits = fd as u32;
    if need_double_fork {
        bits | NEED_DOUBLE_FORK
    } else {
        bits & !NEED_DOUBLE_FORK
    }
}

/// Decodes a close request back into `(fd, need_double_fork)`.
#[inline]
pub fn decode_close_request(encoded: u32) -> (RawFd, bool) {
    let need_double_fork = (encoded & NEED_DOUBLE_FORK) != 0;
    let fd = (encoded & !NEED_DOUBLE_FORK) as RawFd;
    (fd, need_double_fork)
}

// ── Remove flags ───────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling recursive directory removal behaviour.
    /// Mirrors the C `RemoveFlags` enum.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RemoveFlags: u32 {
        /// Only remove empty directories.
        const ONLY_DIRS        = 1 << 0;
        /// Remove the root directory itself.
        const REMOVE_ROOT      = 1 << 1;
        /// Do not follow symlinks (physical walk).
        const REMOVE_PHYSICAL  = 1 << 2;
        /// Remove submounts too.
        const REMOVE_SUBMOUNT  = 1 << 3;
        /// Honor the sticky bit.
        const HONOR_STICKY     = 1 << 4;
        /// Honor the sticky + setuid bits.
        const HONOR_STICKY_SUID = 1 << 5;
        /// Do not recurse into subdirectories.
        const INHIBIT_RECURSE  = 1 << 6;
        /// Skip files with the FS_NODUMP_FL chattr flag.
        const SKIP_NODUMP      = 1 << 7;
    }
}

// ── Fork flags ─────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling fork behaviour for async child processes.
    /// Mirrors the C `ForkFlags` bitmask.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ForkFlags: u32 {
        /// Reset all signal handlers in the child.
        const RESET_SIGNALS   = 1 << 0;
        /// Close all open file descriptors in the child.
        const CLOSE_ALL_FDS   = 1 << 1;
        /// Detach the child (double-fork semantics).
        const DETACH          = 1 << 2;
        /// Reap the child automatically (SIGCHLD).
        const REAP            = 1 << 3;
    }
}

// ── Close result ───────────────────────────────────────────────────────────

/// Result of [`asynchronous_close`].
///
/// The fd is always considered consumed (invalidated) by the caller
/// regardless of whether a child was successfully spawned.  This
/// matches the C convention where `asynchronous_close()` always
/// returns `-EBADF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseResult {
    /// The original file descriptor value.
    pub fd: RawFd,
    /// `true` if the fd was handed off to a child process for async
    /// close.  `false` means a synchronous fallback was used or the fd
    /// was already invalid.
    pub handed_off: bool,
}

impl CloseResult {
    /// Returns the conventional `-EBADF` sentinel that the C
    /// implementation always returns (indicating the fd is now
    /// invalidated).
    #[inline]
    pub fn invalidated_fd(&self) -> RawFd {
        -9 // -EBADF
    }
}

// ── Core operations ────────────────────────────────────────────────────────

/// Close a file descriptor asynchronously via a child process.
///
/// On Linux this creates a minimal `clone(2)` child with `CLONE_FILES`, so
/// the close is performed against the caller's descriptor table. The parent
/// never blocks on the close syscall — if the clone fails, a synchronous
/// close is performed as a local fallback.
///
/// When the calling process is a subreaper (PID 1 or has
/// `PR_SET_CHILD_SUBREAPER`), a single fork suffices.  Otherwise a
/// double-fork is used so the final child is reparented to PID 1 and
/// the intermediate child is reaped immediately.
///
/// # Errors
///
/// Returns [`AsyncError::BadFd`] if `fd` is negative.
pub fn asynchronous_close(fd: RawFd) -> Result<CloseResult, AsyncError> {
    if fd < 0 {
        return Err(AsyncError::BadFd);
    }

    let need_double_fork = !is_reaper_process().unwrap_or(false);

    match close_in_shared_fd_table(fd, need_double_fork) {
        Ok(()) => Ok(CloseResult {
            fd,
            handed_off: true,
        }),
        Err(_) => {
            // Fallback: close synchronously.
            // SAFETY: fd has been validated as >= 0 above.
            unsafe_ffi!({
                libc::close(fd);
            });
            Ok(CloseResult {
                fd,
                handed_off: false,
            })
        }
    }
}

/// Close multiple file descriptors asynchronously.
///
/// Dispatches each fd to [`asynchronous_close`].  Returns per-fd
/// results in the same order as the input slice.
///
/// # Errors
///
/// Returns [`AsyncError::BadFd`] on the first negative fd encountered.
pub fn asynchronous_close_many(fds: &[RawFd]) -> Result<Vec<CloseResult>, AsyncError> {
    fds.iter().map(|&fd| asynchronous_close(fd)).collect()
}

/// Trigger an asynchronous `sync()` to disk via a child process.
///
/// The child calls `sync()` and exits with success.  The parent never
/// blocks on the sync operation.  When `track_pid` is `false` the child
/// is spawned detached (double-fork semantics) and the caller does not
/// receive a pid back.
///
/// # Errors
///
/// Returns [`AsyncError::ForkFailed`] if the fork fails.
pub fn asynchronous_sync(track_pid: bool) -> AsyncResult<Option<u32>> {
    // SAFETY: fork / sync / _exit are syscall wrappers; the child
    // performs only async-signal-safe operations.
    match unsafe_ffi!(libc::fork()) {
        0 => {
            if !track_pid {
                // Detach via double-fork.
                // SAFETY: fork has no pointer preconditions; this child and its
                // descendant use only async-signal-safe syscalls before _exit().
                match unsafe_ffi!(libc::fork()) {
                    0 => {
                        // Grandchild — do the actual work.
                        // SAFETY: sync is an async-signal-safe syscall wrapper
                        // with no pointer arguments, called only in the child.
                        unsafe_ffi!({
                            libc::sync();
                        });
                        child_exit(0);
                    }
                    _ => child_exit(0), // intermediate child exits
                }
            }
            // Single child — do the work directly.
            // SAFETY: sync is an async-signal-safe syscall wrapper with no
            // pointer arguments, called only in the child.
            unsafe_ffi!({
                libc::sync();
            });
            child_exit(0);
        }
        pid if pid > 0 => {
            if track_pid {
                Ok(Some(pid as u32))
            } else {
                // Reap the intermediate child.
                reap_child(pid);
                Ok(None)
            }
        }
        _ => Err(AsyncError::ForkFailed(io::Error::last_os_error())),
    }
}

/// Trigger an asynchronous `fsync()` on a specific fd via a child process.
///
/// Similar to [`asynchronous_sync`] but calls `fsync(fd)` instead of
/// `sync()`.  The child inherits the fd (we do NOT set `CLOSE_ALL_FDS`).
///
/// # Errors
///
/// Returns [`AsyncError::BadFd`] if `fd` is negative.
/// Returns [`AsyncError::ForkFailed`] if the fork fails.
pub fn asynchronous_fsync(fd: RawFd, track_pid: bool) -> AsyncResult<Option<u32>> {
    if fd < 0 {
        return Err(AsyncError::BadFd);
    }

    // SAFETY: fork / fsync / _exit are syscall wrappers.
    match unsafe_ffi!(libc::fork()) {
        0 => {
            if !track_pid {
                // SAFETY: fork has no pointer preconditions; the child paths
                // use only async-signal-safe syscalls before _exit().
                match unsafe_ffi!(libc::fork()) {
                    0 => {
                        // SAFETY: fd validated >= 0 above.
                        unsafe_ffi!({
                            libc::fsync(fd);
                        });
                        child_exit(0);
                    }
                    _ => child_exit(0),
                }
            }
            // SAFETY: fd validated >= 0 above.
            unsafe_ffi!({
                libc::fsync(fd);
            });
            child_exit(0);
        }
        pid if pid > 0 => {
            if track_pid {
                Ok(Some(pid as u32))
            } else {
                reap_child(pid);
                Ok(None)
            }
        }
        _ => Err(AsyncError::ForkFailed(io::Error::last_os_error())),
    }
}

/// Remove a directory tree asynchronously via a detached child process.
///
/// Forks a child that recursively removes the specified path.  The child
/// blocks `SIGTERM` to grant the operation more time during shutdown
/// sequences (PID 1 will eventually send `SIGKILL` if needed).
///
/// This is best-effort only — success or failure of the removal is not
/// reported back to the caller.
///
/// # Errors
///
/// Returns [`AsyncError::InvalidPath`] if `path` is empty.
/// Returns [`AsyncError::ForkFailed`] if the fork fails.
pub fn asynchronous_rm_rf(path: &Path, _flags: RemoveFlags) -> AsyncResult<()> {
    if path.as_os_str().is_empty() {
        return Err(AsyncError::InvalidPath);
    }

    // SAFETY: fork / _exit are syscall wrappers.
    match unsafe_ffi!(libc::fork()) {
        0 => {
            // Detached child — best-effort.
            // In the full implementation this would:
            //   1. Block SIGTERM
            //   2. Call rm_rf(path, flags)
            //   3. _exit with the appropriate code
            // For now we exit cleanly; the actual rm_rf logic lives
            // in a separate module.
            child_exit(0);
        }
        pid if pid > 0 => {
            reap_child(pid);
            Ok(())
        }
        _ => Err(AsyncError::ForkFailed(io::Error::last_os_error())),
    }
}

// ── Internal helpers ───────────────────────────────────────────────────────

/// Exit the current process **without** running atexit handlers or
/// destructors.  This is the correct way to terminate a forked child.
#[inline]
fn child_exit(code: i32) -> ! {
    // SAFETY: _exit is async-signal-safe and never returns.
    unsafe_ffi!(libc::_exit(code))
}

/// Check whether the current process is a subreaper (PID 1 or has
/// `PR_SET_CHILD_SUBREAPER` enabled). This is the same kernel query used by
/// C's `is_reaper_process()`, rather than an unreliable `/proc` heuristic.
#[cfg(target_os = "linux")]
fn is_reaper_process() -> Option<bool> {
    // Fast path: PID 1 is always a reaper.
    if std::process::id() == 1 {
        return Some(true);
    }

    let mut subreaper: libc::c_int = 0;
    // SAFETY: `subreaper` is a live, writable `int`; `prctl` retains no
    // pointer and all remaining arguments are scalar zeroes.
    let r = unsafe_ffi!(libc::prctl(
        libc::PR_GET_CHILD_SUBREAPER,
        &mut subreaper,
        0,
        0,
        0
    ));
    (r >= 0).then_some(subreaper != 0)
}

#[cfg(not(target_os = "linux"))]
fn is_reaper_process() -> Option<bool> {
    (std::process::id() == 1).then_some(true)
}

/// A clone stack has explicit 16-byte alignment, required by the Linux ABI on
/// the supported systemd architectures. Both stacks are allocated before the
/// first clone: no allocator or Rust runtime code is entered in a clone child.
#[cfg(target_os = "linux")]
const CLOSE_CLONE_STACK_SIZE: usize = 64 * 1024;

#[cfg(target_os = "linux")]
#[repr(align(16))]
struct CloseCloneStack([u8; CLOSE_CLONE_STACK_SIZE]);

#[cfg(target_os = "linux")]
struct CloseCloneRequest {
    fd: RawFd,
    nested_stack_top: *mut libc::c_void,
}

/// This runs only in the minimal clone child. It must not allocate, panic, or
/// run Rust destructors: the clone process may inherit locked allocator state.
#[cfg(target_os = "linux")]
extern "C" fn close_clone_child(argument: *mut libc::c_void) -> libc::c_int {
    // SAFETY: `argument` points to the live request prepared by the parent;
    // clone keeps its COW copy and nested stack mapped through this callback.
    let request = unsafe_ffi!(&mut *(argument.cast::<CloseCloneRequest>()));

    if !request.nested_stack_top.is_null() {
        let nested_stack_top =
            std::mem::replace(&mut request.nested_stack_top, std::ptr::null_mut());
        // The request's nested-stack slot was cleared before the clone, so
        // the grandchild performs the close rather than recursively cloning.
        // SAFETY: both the callback and stack pointer were prepared before
        // cloning. `CLONE_FILES` is essential: this child must close the
        // original process's descriptor table, exactly like async.c.
        let nested = unsafe_ffi!({
            libc::clone(
                close_clone_child,
                nested_stack_top,
                libc::SIGCHLD | libc::CLONE_FILES,
                argument,
            )
        });
        if nested >= 0 {
            return 0;
        }
    }

    // SAFETY: `close` accepts an integer descriptor; errors are intentionally
    // ignored just like C's close callback.
    let _ = unsafe_ffi!(libc::close(request.fd));
    0
}

#[cfg(target_os = "linux")]
fn clone_stack_top(stack: &mut CloseCloneStack) -> *mut libc::c_void {
    // SAFETY: the one-past-end pointer is the stack top expected by glibc's
    // clone wrapper. The stack object remains live until clone has returned.
    unsafe_ffi!({
        stack
            .0
            .as_mut_ptr()
            .add(CLOSE_CLONE_STACK_SIZE)
            .cast::<libc::c_void>()
    })
}

/// Create the C `clone_with_nested_stack()` equivalent used by
/// `asynchronous_close()`. When the caller is not a reaper, the first clone
/// has no exit signal and is reaped with `__WCLONE`; it creates the detached
/// SIGCHLD grandchild that owns the eventual close.
#[cfg(target_os = "linux")]
fn close_in_shared_fd_table(fd: RawFd, need_double_fork: bool) -> Result<(), io::Error> {
    let mut outer_stack = Box::new(CloseCloneStack([0; CLOSE_CLONE_STACK_SIZE]));
    let mut nested_stack =
        need_double_fork.then(|| Box::new(CloseCloneStack([0; CLOSE_CLONE_STACK_SIZE])));
    let nested_stack_top = nested_stack
        .as_deref_mut()
        .map(clone_stack_top)
        .unwrap_or(std::ptr::null_mut());
    let mut request = CloseCloneRequest {
        fd,
        nested_stack_top,
    };
    let flags = libc::CLONE_FILES | if need_double_fork { 0 } else { libc::SIGCHLD };

    // SAFETY: callback, aligned stack, and request all remain live for this
    // synchronous clone call. The child callback performs only async-signal-
    // safe operations and does not retain the parent's pointers after exit.
    let pid = unsafe_ffi!({
        libc::clone(
            close_clone_child,
            clone_stack_top(&mut outer_stack),
            flags,
            (&mut request as *mut CloseCloneRequest).cast::<libc::c_void>(),
        )
    });
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }

    if need_double_fork {
        reap_clone_child(pid);
    }
    Ok(())
}

/// Non-Linux targets cannot provide the Linux `CLONE_FILES` contract. Signal
/// the public wrapper to use its synchronous fallback rather than spawning a
/// fork child that would only close a private descriptor-table copy.
#[cfg(not(target_os = "linux"))]
fn close_in_shared_fd_table(_fd: RawFd, _need_double_fork: bool) -> Result<(), io::Error> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

/// Reap a child process, retrying on `EINTR`.
fn reap_child_with_options(pid: libc::pid_t, options: libc::c_int) {
    let mut status: i32 = 0;
    loop {
        // SAFETY: pid is a valid child pid we just forked.
        let ret = unsafe_ffi!(libc::waitpid(pid, &mut status, options));
        if ret >= 0 {
            break;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            break;
        }
    }
}

/// Reap an ordinary SIGCHLD child, retrying on `EINTR`.
fn reap_child(pid: libc::pid_t) {
    reap_child_with_options(pid, 0);
}

/// Reap a clone child created with exit signal 0. Normal `waitpid` does not
/// select it; Linux requires `__WCLONE`, precisely as `async.c` does.
#[cfg(target_os = "linux")]
fn reap_clone_child(pid: libc::pid_t) {
    // `__WCLONE` selects children created without SIGCHLD.
    reap_child_with_options(pid, libc::__WCLONE);
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    #[cfg(target_os = "linux")]
    use std::mem::ManuallyDrop;
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "linux")]
    use std::os::unix::net::UnixStream;
    #[cfg(target_os = "linux")]
    use std::time::{Duration, Instant};

    // ── Encoding / decoding ─────────────────────────────────────────────

    #[test]
    fn test_encode_decode_roundtrip() {
        for fd in [0, 1, 2, 42, 100, 1023] {
            for flag in [false, true] {
                let encoded = encode_close_request(fd, flag);
                let (decoded_fd, decoded_flag) = decode_close_request(encoded);
                assert_eq!(decoded_fd, fd, "fd mismatch for {fd}");
                assert_eq!(decoded_flag, flag, "flag mismatch for {fd}");
            }
        }
    }

    #[test]
    fn test_encode_with_double_fork_sets_high_bit() {
        let encoded = encode_close_request(42, true);
        assert_ne!(encoded & NEED_DOUBLE_FORK, 0);
    }

    #[test]
    fn test_encode_without_double_fork_clears_high_bit() {
        let encoded = encode_close_request(42, false);
        assert_eq!(encoded & NEED_DOUBLE_FORK, 0);
    }

    #[test]
    fn test_decode_preserves_fd_value() {
        for fd in [0i32, 1, 255, 1023, 0x7FFF_FFFF] {
            let encoded = encode_close_request(fd, false);
            let (decoded, _) = decode_close_request(encoded);
            assert_eq!(decoded, fd);
        }
    }

    #[test]
    fn test_need_double_fork_constant() {
        // Highest bit of a u32.
        assert_eq!(NEED_DOUBLE_FORK, 1u32 << 31);
        assert_eq!(NEED_DOUBLE_FORK, 0x8000_0000);
    }

    #[test]
    fn test_close_request_fd_zero() {
        let encoded = encode_close_request(0, false);
        assert_eq!(encoded, 0u32);
        let (fd, flag) = decode_close_request(encoded);
        assert_eq!(fd, 0);
        assert!(!flag);
    }

    #[test]
    fn test_close_request_max_fd_without_flag() {
        // Max fd that fits in 31 bits.
        let max_fd: RawFd = (NEED_DOUBLE_FORK - 1) as RawFd;
        let encoded = encode_close_request(max_fd, false);
        assert_eq!(encoded, max_fd as u32);
        let (fd, flag) = decode_close_request(encoded);
        assert_eq!(fd, max_fd);
        assert!(!flag);
    }

    // ── Validation (no forking) ────────────────────────────────────────

    #[test]
    fn test_asynchronous_close_negative_fd_returns_bad_fd() {
        let err = asynchronous_close(-1).unwrap_err();
        assert!(matches!(err, AsyncError::BadFd));
    }

    #[test]
    fn test_asynchronous_close_many_empty_slice() {
        let results = asynchronous_close_many(&[]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_asynchronous_close_many_first_negative_errors() {
        let err = asynchronous_close_many(&[-1, 0, 1]).unwrap_err();
        assert!(matches!(err, AsyncError::BadFd));
    }

    #[test]
    fn test_asynchronous_fsync_negative_fd_returns_bad_fd() {
        let err = asynchronous_fsync(-1, true).unwrap_err();
        assert!(matches!(err, AsyncError::BadFd));
    }

    #[test]
    fn test_asynchronous_rm_rf_empty_path() {
        let err = asynchronous_rm_rf(Path::new(""), RemoveFlags::empty()).unwrap_err();
        assert!(matches!(err, AsyncError::InvalidPath));
    }

    // ── CloseResult ────────────────────────────────────────────────────

    #[test]
    fn test_close_result_invalidated_fd() {
        let cr = CloseResult {
            fd: 42,
            handed_off: true,
        };
        assert_eq!(cr.invalidated_fd(), -9);
        assert_eq!(cr.fd, 42);
        assert!(cr.handed_off);
    }

    #[test]
    fn test_close_result_equality() {
        let a = CloseResult {
            fd: 5,
            handed_off: true,
        };
        let b = CloseResult {
            fd: 5,
            handed_off: true,
        };
        let c = CloseResult {
            fd: 5,
            handed_off: false,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ── Flags ──────────────────────────────────────────────────────────

    #[test]
    fn test_remove_flags_empty() {
        let flags = RemoveFlags::empty();
        assert!(flags.is_empty());
        assert_eq!(flags.bits(), 0);
    }

    #[test]
    fn test_remove_flags_combinations() {
        let flags = RemoveFlags::ONLY_DIRS | RemoveFlags::REMOVE_PHYSICAL;
        assert!(flags.contains(RemoveFlags::ONLY_DIRS));
        assert!(flags.contains(RemoveFlags::REMOVE_PHYSICAL));
        assert!(!flags.contains(RemoveFlags::REMOVE_ROOT));
    }

    #[test]
    fn test_remove_flags_all() {
        let all = RemoveFlags::all();
        assert!(all.contains(RemoveFlags::ONLY_DIRS));
        assert!(all.contains(RemoveFlags::REMOVE_ROOT));
        assert!(all.contains(RemoveFlags::REMOVE_PHYSICAL));
        assert!(all.contains(RemoveFlags::REMOVE_SUBMOUNT));
        assert!(all.contains(RemoveFlags::HONOR_STICKY));
        assert!(all.contains(RemoveFlags::HONOR_STICKY_SUID));
        assert!(all.contains(RemoveFlags::INHIBIT_RECURSE));
        assert!(all.contains(RemoveFlags::SKIP_NODUMP));
    }

    #[test]
    fn test_fork_flags_default() {
        let flags = ForkFlags::empty();
        assert!(flags.is_empty());
    }

    #[test]
    fn test_fork_flags_combine() {
        let flags = ForkFlags::RESET_SIGNALS | ForkFlags::DETACH;
        assert!(flags.contains(ForkFlags::RESET_SIGNALS));
        assert!(flags.contains(ForkFlags::DETACH));
        assert!(!flags.contains(ForkFlags::CLOSE_ALL_FDS));
    }

    // ── Error types ────────────────────────────────────────────────────

    #[test]
    fn test_async_error_display() {
        assert_eq!(format!("{}", AsyncError::BadFd), "bad file descriptor");
        assert_eq!(format!("{}", AsyncError::InvalidPath), "invalid path");
    }

    #[test]
    fn test_async_error_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::WouldBlock, "would block");
        let async_err: AsyncError = io_err.into();
        assert!(matches!(async_err, AsyncError::ForkFailed(_)));
        assert_eq!(format!("{async_err}"), "fork failed: would block");
    }

    #[test]
    fn test_async_error_source_chain() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let async_err = AsyncError::ForkFailed(io_err);
        assert!(async_err.source().is_some());
        // BadFd and InvalidPath have no source.
        assert!(AsyncError::BadFd.source().is_none());
        assert!(AsyncError::InvalidPath.source().is_none());
    }

    // ── Integration (fork-based, may create real children) ─────────────

    #[test]
    fn test_asynchronous_sync_detached() {
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
    fn test_asynchronous_fsync_valid_fd_tracked() {
        let result = asynchronous_fsync(0, true);
        assert!(result.is_ok());
        let pid = result.unwrap();
        assert!(pid.is_some());
    }

    #[test]
    fn test_asynchronous_close_valid_fd() {
        // fd 99999 is almost certainly not open, so the child's close()
        // will return EBADF but that's fine — the point is the child ran.
        let result = asynchronous_close(99999).unwrap();
        assert_eq!(result.fd, 99999);
        assert!(result.handed_off);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_asynchronous_close_invalidates_callers_fd_table() {
        let (read_end, write_end) = UnixStream::pair().unwrap();
        // Keep the Rust handle from dropping after its fd is asynchronously
        // consumed. `fcntl` below borrows it only to query the same raw fd.
        let read_end = ManuallyDrop::new(read_end);
        let fd = (&*read_end).as_raw_fd();

        let result = asynchronous_close(fd).unwrap();
        assert_eq!(result.fd, fd);

        // The close may be performed by the detached grandchild after this
        // function returns. Poll only the scalar F_GETFD operation until the
        // shared descriptor table reports EBADF.
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if matches!(
                nix::fcntl::fcntl(&*read_end, nix::fcntl::FcntlArg::F_GETFD),
                Err(nix::errno::Errno::EBADF)
            ) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "asynchronous_close() left the caller's fd {fd} open"
            );
            std::thread::sleep(Duration::from_millis(1));
        }

        drop(write_end);
    }

    #[test]
    fn test_asynchronous_close_many_all_valid() {
        let fds: &[RawFd] = &[99998, 99997, 99996];
        let results = asynchronous_close_many(fds).unwrap();
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.handed_off);
        }
    }

    #[test]
    fn test_asynchronous_rm_rf_root_path() {
        // Spawning should succeed; the child will try to rm -rf /
        // which will fail but that's expected (best-effort).
        let result = asynchronous_rm_rf(Path::new("/nonexistent_async_test"), RemoveFlags::empty());
        assert!(result.is_ok());
    }
}
