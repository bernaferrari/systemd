// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/barrier.c, src/shared/barrier.h
//
// Barrier synchronization primitive for inter-process coordination.
//
// Uses two eventfd counters (one per side) for barrier signaling and a
// pipe for detecting remote process exit (implicit abortion).  The
// barrier counter (i64) encodes both the placed-barrier difference and
// abort states: positive = we placed more, zero = equal, negative =
// they placed more.  Values near i64::MIN encode abort states with the
// invariant WE_ABORTED < THEY_ABORTED < I_ABORTED.

use crate::ffi::*;
use std::fmt;
use std::io;

// ── Constants ─────────────────────────────────────────────────────────────

/// Single barrier increment value written to the eventfd.
pub const BARRIER_SINGLE: i64 = 1;

/// Sentinel written to the eventfd to signal an abort.
pub const BARRIER_ABORTION: i64 = i64::MAX;

/// Bias for encoding abort states at the bottom of the i64 range.
pub const BARRIER_BIAS: i64 = i64::MIN;

/// Both sides aborted.
pub const BARRIER_WE_ABORTED: i64 = BARRIER_BIAS + 1;

/// The other side aborted.
pub const BARRIER_THEY_ABORTED: i64 = BARRIER_BIAS + 2;

/// This side aborted.
pub const BARRIER_I_ABORTED: i64 = BARRIER_BIAS + 3;

/// Parent role — keeps pipe[0] (read end), closes pipe[1].
pub const BARRIER_PARENT: u32 = 0;

/// Child role — keeps pipe[1] (write end), closes pipe[0], swaps me/them.
pub const BARRIER_CHILD: u32 = 1;

/// Sentinel file descriptor for "closed / invalid".
const INVALID_FD: i32 = -9;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors produced by barrier operations.
#[derive(Debug)]
pub enum BarrierError {
    /// An OS-level I/O error (from eventfd, pipe, poll, read, or write).
    Io(io::Error),

    /// The barrier has been aborted (locally, remotely, or both).
    Aborted(BarrierState),

    /// Invalid role was provided (must be `BARRIER_PARENT` or `BARRIER_CHILD`).
    InvalidRole(u32),

    /// `set_role` was called more than once.
    AlreadyAssigned,
}

impl fmt::Display for BarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BarrierError::Io(e) => write!(f, "barrier I/O error: {e}"),
            BarrierError::Aborted(s) => write!(f, "barrier aborted: {s:?}"),
            BarrierError::InvalidRole(r) => write!(f, "invalid barrier role: {r}"),
            BarrierError::AlreadyAssigned => write!(f, "barrier role already assigned"),
        }
    }
}

impl std::error::Error for BarrierError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BarrierError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for BarrierError {
    fn from(e: io::Error) -> Self {
        BarrierError::Io(e)
    }
}

// ── Barrier state ─────────────────────────────────────────────────────────

/// Reflects the current abort state of a barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierState {
    /// No abort has occurred.
    Active,
    /// This side called `abort()`.
    IAborted,
    /// The other side called `abort()`.
    TheyAborted,
    /// Both sides called `abort()`.
    WeAborted,
}

impl fmt::Display for BarrierState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BarrierState::Active => write!(f, "active"),
            BarrierState::IAborted => write!(f, "I aborted"),
            BarrierState::TheyAborted => write!(f, "they aborted"),
            BarrierState::WeAborted => write!(f, "we aborted"),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn errno_is_transient(err: i32) -> bool {
    matches!(err, libc::EINTR | libc::EAGAIN)
}

fn safe_close(fd: i32) -> i32 {
    if fd < 0 {
        return INVALID_FD;
    }
    // SAFETY: fd is known to be a valid file descriptor we own.
    unsafe {
        libc::close(fd);
    }
    INVALID_FD
}

fn decode_barrier_state(barriers: i64) -> BarrierState {
    match barriers {
        BARRIER_I_ABORTED => BarrierState::IAborted,
        BARRIER_THEY_ABORTED => BarrierState::TheyAborted,
        BARRIER_WE_ABORTED => BarrierState::WeAborted,
        _ => BarrierState::Active,
    }
}

fn barriers_to_state(barriers: i64) -> Result<BarrierState, BarrierError> {
    let state = decode_barrier_state(barriers);
    if state != BarrierState::Active {
        return Err(BarrierError::Aborted(state));
    }
    Ok(state)
}

// ── Platform-specific syscalls ────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[inline]
fn sys_eventfd(initval: u32, flags: i32) -> i32 {
    // SAFETY: eventfd() accepts value arguments only.
    unsafe { libc::eventfd(initval, flags) }
}

#[cfg(not(target_os = "linux"))]
#[inline]
fn sys_eventfd(_initval: u32, _flags: i32) -> i32 {
    -1
}

#[cfg(target_os = "linux")]
fn create_pipe() -> io::Result<[i32; 2]> {
    let mut fds: [i32; 2] = [-1, -1];
    // SAFETY: fds points to storage for exactly two descriptors as required by pipe2().
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fds)
}

#[cfg(not(target_os = "linux"))]
fn create_pipe() -> io::Result<[i32; 2]> {
    let mut fds: [i32; 2] = [-1, -1];
    // SAFETY: fds points to storage for exactly two descriptors as required by pipe().
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let cleanup = || {
        // SAFETY: both values were initialized by a successful pipe() call.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    };

    for &fd in &fds {
        // SAFETY: fcntl() accepts a descriptor and value arguments.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            cleanup();
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fcntl() accepts a descriptor and this command has no variadic argument.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            cleanup();
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fcntl() accepts a descriptor and value arguments.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            cleanup();
            return Err(io::Error::last_os_error());
        }
    }

    Ok(fds)
}

// ── Barrier ───────────────────────────────────────────────────────────────

/// Synchronization barrier for inter-process coordination.
///
/// A `Barrier` contains two eventfd file descriptors (one written by each
/// side) and a pipe used to detect when the remote process exits.  Both
/// sides must call [`Barrier::set_role`] after `fork()` before placing
/// or waiting on any barriers.
///
/// # Roles
///
/// - **Parent** — writes to the original `me` eventfd, reads from the
///   original `them` eventfd, keeps `pipe[0]` (read end).
/// - **Child** — writes to the original `them` eventfd (swapped to `me`),
///   reads from the original `me` eventfd (swapped to `them`), keeps
///   `pipe[1]` (write end).
///
/// # Abortion
///
/// Either side can call [`Barrier::abort`] to irreversibly cancel all
/// pending barriers.  Both sides can then observe the abort state via
/// [`Barrier::state`].
///
/// # Layout
///
/// The struct is `#[repr(C)]` to match the C `struct Barrier` layout.
#[repr(C)]
pub struct Barrier {
    me: i32,
    them: i32,
    pipe: [i32; 2],
    barriers: i64,
}

/// Sentinel for an uninitialized or destroyed barrier (matches C `BARRIER_NULL`).
pub const BARRIER_NULL: Barrier = Barrier {
    me: INVALID_FD,
    them: INVALID_FD,
    pipe: [INVALID_FD, INVALID_FD],
    barriers: 0,
};

impl Barrier {
    // ── Construction / destruction ────────────────────────────────────

    /// Create a new barrier, allocating two eventfd objects and a pipe.
    ///
    /// On failure, all partially-allocated resources are released.
    pub fn create() -> Result<Self, BarrierError> {
        // SAFETY: eventfd(2) is a simple syscall with no invariants beyond
        // valid flags.
        let me = sys_eventfd(0, libc::O_CLOEXEC | libc::O_NONBLOCK);
        if me < 0 {
            return Err(io::Error::last_os_error().into());
        }

        let them = sys_eventfd(0, libc::O_CLOEXEC | libc::O_NONBLOCK);
        if them < 0 {
            // SAFETY: me is a successfully created eventfd owned by this function.
            unsafe {
                libc::close(me);
            }
            return Err(io::Error::last_os_error().into());
        }

        let pipe = match create_pipe() {
            Ok(p) => p,
            Err(e) => {
                // SAFETY: both eventfds were successfully created and are owned by this function.
                unsafe {
                    libc::close(me);
                    libc::close(them);
                }
                return Err(e.into());
            }
        };

        Ok(Barrier {
            me,
            them,
            pipe,
            barriers: 0,
        })
    }

    /// Close all file descriptors and reset to the invalid state.
    ///
    /// Safe to call multiple times.
    pub fn destroy(&mut self) {
        self.me = safe_close(self.me);
        self.them = safe_close(self.them);
        self.pipe[0] = safe_close(self.pipe[0]);
        self.pipe[1] = safe_close(self.pipe[1]);
        self.barriers = 0;
    }

    // ── Role assignment ───────────────────────────────────────────────

    /// Assign the local role (parent or child).
    ///
    /// Must be called exactly once per side after `fork()`.  The parent
    /// keeps `pipe[0]`; the child keeps `pipe[1]` and swaps `me`/`them`.
    pub fn set_role(&mut self, role: u32) -> Result<(), BarrierError> {
        match role {
            BARRIER_PARENT => {
                if self.pipe[1] == INVALID_FD {
                    return Err(BarrierError::AlreadyAssigned);
                }
                self.pipe[1] = safe_close(self.pipe[1]);
            }
            BARRIER_CHILD => {
                if self.pipe[0] == INVALID_FD {
                    return Err(BarrierError::AlreadyAssigned);
                }
                self.pipe[0] = safe_close(self.pipe[0]);
                std::mem::swap(&mut self.me, &mut self.them);
            }
            other => return Err(BarrierError::InvalidRole(other)),
        }
        Ok(())
    }

    // ── State queries ─────────────────────────────────────────────────

    /// Returns the current barrier state.
    pub fn state(&self) -> BarrierState {
        decode_barrier_state(self.barriers)
    }

    /// `true` if this side called [`abort`](Self::abort).
    #[inline]
    pub fn i_aborted(&self) -> bool {
        matches!(self.barriers, BARRIER_I_ABORTED | BARRIER_WE_ABORTED)
    }

    /// `true` if the other side called [`abort`](Self::abort).
    #[inline]
    pub fn they_aborted(&self) -> bool {
        matches!(self.barriers, BARRIER_THEY_ABORTED | BARRIER_WE_ABORTED)
    }

    /// `true` if both sides called [`abort`](Self::abort).
    #[inline]
    pub fn we_aborted(&self) -> bool {
        self.barriers == BARRIER_WE_ABORTED
    }

    /// `true` if any abort has occurred.
    #[inline]
    pub fn is_aborted(&self) -> bool {
        matches!(
            self.barriers,
            BARRIER_I_ABORTED | BARRIER_THEY_ABORTED | BARRIER_WE_ABORTED
        )
    }

    // ── Internal: write to our eventfd ────────────────────────────────

    /// Write `buf` to our eventfd.  On success, updates the barrier
    /// counter (or transitions to an abort state if `buf >=
    /// BARRIER_ABORTION`).  On fatal error, closes the pipe to signal
    /// implicit abortion to the other side.
    ///
    /// Returns `Ok(true)` if the barrier was written successfully,
    /// `Ok(false)` if we already aborted (write suppressed), or
    /// `Err` on a fatal I/O error.
    fn write_fd(&mut self, buf: u64) -> Result<bool, BarrierError> {
        if self.i_aborted() {
            return Ok(false);
        }

        assert!(self.me >= 0, "barrier eventfd not initialized");

        // SAFETY: self.me is a valid eventfd we own; buf points to a
        // properly aligned u64.
        let len = loop {
            let len = unsafe {
                libc::write(
                    self.me,
                    &buf as *const u64 as *const libc::c_void,
                    std::mem::size_of::<u64>(),
                )
            };
            if len >= 0 {
                break len;
            }
            if let Some(e) = io::Error::last_os_error().raw_os_error() {
                if errno_is_transient(e) {
                    continue;
                }
            }
            // Fatal error — close pipe to signal implicit abortion.
            self.pipe[0] = safe_close(self.pipe[0]);
            self.pipe[1] = safe_close(self.pipe[1]);
            self.barriers = BARRIER_WE_ABORTED;
            return Err(io::Error::last_os_error().into());
        };

        if len != std::mem::size_of::<u64>() as isize {
            self.pipe[0] = safe_close(self.pipe[0]);
            self.pipe[1] = safe_close(self.pipe[1]);
            self.barriers = BARRIER_WE_ABORTED;
            return Err(BarrierError::Aborted(BarrierState::WeAborted));
        }

        if buf >= BARRIER_ABORTION as u64 {
            if self.they_aborted() {
                self.barriers = BARRIER_WE_ABORTED;
            } else {
                self.barriers = BARRIER_I_ABORTED;
            }
        } else if !self.is_aborted() {
            self.barriers += buf as i64;
        }

        Ok(!self.i_aborted())
    }

    // ── Internal: read from their eventfd ─────────────────────────────

    /// Read from the other side's eventfd until `barriers <= comp`.
    ///
    /// Uses `poll(2)` to wait on both the eventfd (`POLLIN`) and the
    /// pipe (`POLLHUP`).  A pipe HUP is treated as implicit abortion,
    /// but only when no eventfd data is pending — this guarantees that
    /// exit-abortion events do not overwrite real barriers that were
    /// already queued before the remote side exited.
    ///
    /// Returns `Ok(true)` if the other side is still alive and hasn't
    /// aborted, `Ok(false)` if they aborted, or `Err` on a fatal I/O
    /// error.
    fn read_fd(&mut self, comp: i64) -> Result<bool, BarrierError> {
        if self.they_aborted() {
            return Ok(false);
        }

        while self.barriers > comp {
            let pipe_fd = if self.pipe[0] >= 0 {
                self.pipe[0]
            } else {
                self.pipe[1]
            };

            let mut pfds = [
                libc::pollfd {
                    fd: pipe_fd,
                    events: libc::POLLHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.them,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];

            // SAFETY: pfds is a valid stack-allocated array; fds are valid.
            let r = unsafe { libc::poll(pfds.as_mut_ptr(), 2, -1) };
            if r < 0 {
                if let Some(e) = io::Error::last_os_error().raw_os_error() {
                    if e == libc::EINTR {
                        continue;
                    }
                }
                self.pipe[0] = safe_close(self.pipe[0]);
                self.pipe[1] = safe_close(self.pipe[1]);
                self.barriers = BARRIER_WE_ABORTED;
                return Err(io::Error::last_os_error().into());
            }

            let mut buf: u64 = 0;

            if pfds[1].revents != 0 {
                // SAFETY: self.them is a valid eventfd we own.
                let len = loop {
                    let len = unsafe {
                        libc::read(
                            self.them,
                            &mut buf as *mut u64 as *mut libc::c_void,
                            std::mem::size_of::<u64>(),
                        )
                    };
                    if len >= 0 {
                        break len;
                    }
                    if let Some(e) = io::Error::last_os_error().raw_os_error() {
                        if errno_is_transient(e) {
                            continue;
                        }
                    }
                    self.pipe[0] = safe_close(self.pipe[0]);
                    self.pipe[1] = safe_close(self.pipe[1]);
                    self.barriers = BARRIER_WE_ABORTED;
                    return Err(io::Error::last_os_error().into());
                };

                if len != std::mem::size_of::<u64>() as isize {
                    self.pipe[0] = safe_close(self.pipe[0]);
                    self.pipe[1] = safe_close(self.pipe[1]);
                    self.barriers = BARRIER_WE_ABORTED;
                    return Err(BarrierError::Aborted(BarrierState::WeAborted));
                }
            } else if pfds[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                buf = BARRIER_ABORTION as u64;
            } else {
                continue;
            }

            if buf >= BARRIER_ABORTION as u64 {
                if self.i_aborted() {
                    self.barriers = BARRIER_WE_ABORTED;
                } else {
                    self.barriers = BARRIER_THEY_ABORTED;
                }
            } else if !self.is_aborted() {
                self.barriers -= buf as i64;
            }
        }

        Ok(!self.they_aborted())
    }

    // ── Public API ────────────────────────────────────────────────────

    /// Place a new barrier.
    ///
    /// If either side already aborted this is a no-op and returns
    /// `Err(BarrierError::Aborted(..))`.  Otherwise the barrier is placed
    /// and this returns `Ok(())`.
    pub fn place(&mut self) -> Result<(), BarrierError> {
        barriers_to_state(self.barriers)?;
        self.write_fd(BARRIER_SINGLE as u64)?;
        barriers_to_state(self.barriers).map(drop)
    }

    /// Abort the synchronization.
    ///
    /// If `abort()` was already called on this side this is a no-op.
    /// Returns `Ok(BarrierState::IAborted)` if only we aborted,
    /// `Ok(BarrierState::WeAborted)` if both sides aborted, or
    /// `Err(BarrierError::Aborted(..))` if the other side already
    /// aborted and we haven't yet.
    pub fn abort(&mut self) -> Result<BarrierState, BarrierError> {
        let was_i = self.i_aborted();
        self.write_fd(BARRIER_ABORTION as u64)?;
        Ok(self.state())
    }

    /// Wait for the next barrier from the other side, regardless of
    /// barrier links.
    ///
    /// If either side aborted, returns `Err(BarrierError::Aborted(..))`.
    pub fn wait_next(&mut self) -> Result<(), BarrierError> {
        barriers_to_state(self.barriers)?;
        self.read_fd(self.barriers - 1)?;
        barriers_to_state(self.barriers).map(drop)
    }

    /// Wait for the other side to call [`abort`](Self::abort).
    ///
    /// Can be called regardless of whether the local side already aborted.
    /// Returns `Ok(BarrierState::TheyAborted)` (or `WeAborted` if we
    /// also aborted).
    pub fn wait_abortion(&mut self) -> Result<BarrierState, BarrierError> {
        self.read_fd(BARRIER_THEY_ABORTED)?;
        let state = self.state();
        if self.i_aborted() {
            Err(BarrierError::Aborted(state))
        } else {
            Ok(state)
        }
    }

    /// Wait for the other side to place a linked barrier.
    ///
    /// If the other side already placed at least as many barriers as we
    /// did, returns immediately.
    pub fn sync_next(&mut self) -> Result<(), BarrierError> {
        barriers_to_state(self.barriers)?;
        let comp = std::cmp::max(0, self.barriers - 1);
        self.read_fd(comp)?;
        barriers_to_state(self.barriers).map(drop)
    }

    /// Wait for both sides to have placed the same number of barriers.
    ///
    /// If the other side already placed as many barriers as we did (or
    /// more), returns immediately.
    pub fn sync(&mut self) -> Result<(), BarrierError> {
        barriers_to_state(self.barriers)?;
        self.read_fd(0)?;
        barriers_to_state(self.barriers).map(drop)
    }

    /// Place a barrier and then sync (equivalent to C
    /// `barrier_place_and_sync`).
    ///
    /// The place is best-effort (aborted barriers are silently ignored).
    /// Returns the sync result.
    pub fn place_and_sync(&mut self) -> Result<(), BarrierError> {
        let _ = self.place();
        self.sync()
    }
}

impl Drop for Barrier {
    fn drop(&mut self) {
        self.destroy();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::error::Error;

    // ── Constant sanity ───────────────────────────────────────────────

    #[test]
    fn test_abort_constants_invariant() {
        // C comment: "keep @WE < @THEY < @I"
        const { assert!(BARRIER_WE_ABORTED < BARRIER_THEY_ABORTED) };
        const { assert!(BARRIER_THEY_ABORTED < BARRIER_I_ABORTED) };
        // All abort sentinels are negative
        const { assert!(BARRIER_WE_ABORTED < 0) };
        const { assert!(BARRIER_THEY_ABORTED < 0) };
        const { assert!(BARRIER_I_ABORTED < 0) };
    }

    #[test]
    fn test_barrier_null_is_safe() {
        let b = BARRIER_NULL;
        assert!(!b.i_aborted());
        assert!(!b.they_aborted());
        assert!(!b.we_aborted());
        assert!(!b.is_aborted());
        assert_eq!(b.state(), BarrierState::Active);
    }

    // ── State decoding ────────────────────────────────────────────────

    #[test]
    fn test_decode_state_i_aborted() {
        let mut b = BARRIER_NULL;
        b.barriers = BARRIER_I_ABORTED;
        assert!(b.i_aborted());
        assert!(!b.they_aborted());
        assert!(!b.we_aborted());
        assert!(b.is_aborted());
        assert_eq!(b.state(), BarrierState::IAborted);
    }

    #[test]
    fn test_decode_state_they_aborted() {
        let mut b = BARRIER_NULL;
        b.barriers = BARRIER_THEY_ABORTED;
        assert!(!b.i_aborted());
        assert!(b.they_aborted());
        assert!(!b.we_aborted());
        assert!(b.is_aborted());
        assert_eq!(b.state(), BarrierState::TheyAborted);
    }

    #[test]
    fn test_decode_state_we_aborted() {
        let mut b = BARRIER_NULL;
        b.barriers = BARRIER_WE_ABORTED;
        assert!(b.i_aborted());
        assert!(b.they_aborted());
        assert!(b.we_aborted());
        assert!(b.is_aborted());
        assert_eq!(b.state(), BarrierState::WeAborted);
    }

    #[test]
    fn test_decode_state_normal_values() {
        let mut b = BARRIER_NULL;
        for val in [0i64, 1, 5, -1, -3, 100, -100] {
            b.barriers = val;
            assert!(!b.i_aborted());
            assert!(!b.they_aborted());
            assert!(!b.we_aborted());
            assert!(!b.is_aborted());
            assert_eq!(b.state(), BarrierState::Active);
        }
    }

    // ── barriers_to_state ─────────────────────────────────────────────

    #[test]
    fn test_barriers_to_state_active() {
        assert!(barriers_to_state(0).is_ok());
        assert!(barriers_to_state(5).is_ok());
        assert!(barriers_to_state(-3).is_ok());
    }

    #[test]
    fn test_barriers_to_state_aborted() {
        assert!(barriers_to_state(BARRIER_I_ABORTED).is_err());
        assert!(barriers_to_state(BARRIER_THEY_ABORTED).is_err());
        assert!(barriers_to_state(BARRIER_WE_ABORTED).is_err());
    }

    // ── Place / abort on null barrier (no real fds) ───────────────────

    #[test]
    fn test_place_returns_err_when_aborted() {
        let mut b = BARRIER_NULL;
        for &state in &[BARRIER_I_ABORTED, BARRIER_THEY_ABORTED, BARRIER_WE_ABORTED] {
            b.barriers = state;
            let err = b.place().unwrap_err();
            assert!(matches!(err, BarrierError::Aborted(_)));
            assert_eq!(b.barriers, state, "barriers counter must not change");
        }
    }

    #[test]
    fn test_abort_noop_when_already_i_aborted() {
        let mut b = BARRIER_NULL;
        b.barriers = BARRIER_I_ABORTED;
        let state = b.abort().unwrap();
        assert_eq!(state, BarrierState::IAborted);
        assert_eq!(b.barriers, BARRIER_I_ABORTED);
    }

    #[test]
    fn test_abort_transitions_to_we_aborted() {
        let mut b = BARRIER_NULL;
        b.barriers = BARRIER_THEY_ABORTED;
        let state = b.abort().unwrap();
        assert_eq!(state, BarrierState::WeAborted);
    }

    #[test]
    fn test_wait_next_returns_err_when_aborted() {
        let mut b = BARRIER_NULL;
        for &state in &[BARRIER_I_ABORTED, BARRIER_THEY_ABORTED, BARRIER_WE_ABORTED] {
            b.barriers = state;
            assert!(b.wait_next().is_err());
        }
    }

    #[test]
    fn test_sync_next_returns_err_when_aborted() {
        let mut b = BARRIER_NULL;
        b.barriers = BARRIER_THEY_ABORTED;
        assert!(b.sync_next().is_err());
    }

    #[test]
    fn test_sync_returns_err_when_aborted() {
        let mut b = BARRIER_NULL;
        b.barriers = BARRIER_I_ABORTED;
        assert!(b.sync().is_err());
    }

    #[test]
    fn test_wait_abortion_when_they_aborted() {
        let mut b = BARRIER_NULL;
        b.barriers = BARRIER_THEY_ABORTED;
        let state = b.wait_abortion().unwrap();
        assert_eq!(state, BarrierState::TheyAborted);
    }

    #[test]
    fn test_wait_abortion_when_we_aborted() {
        let mut b = BARRIER_NULL;
        b.barriers = BARRIER_WE_ABORTED;
        let err = b.wait_abortion().unwrap_err();
        assert!(matches!(
            err,
            BarrierError::Aborted(BarrierState::WeAborted)
        ));
    }

    #[test]
    fn test_wait_abortion_when_i_aborted() {
        let mut b = BARRIER_NULL;
        b.barriers = BARRIER_I_ABORTED;
        let err = b.wait_abortion().unwrap_err();
        assert!(matches!(err, BarrierError::Aborted(BarrierState::IAborted)));
    }

    #[test]
    fn test_place_and_sync_returns_err_when_aborted() {
        let mut b = BARRIER_NULL;
        b.barriers = BARRIER_I_ABORTED;
        assert!(b.place_and_sync().is_err());
    }

    // ── Destroy ───────────────────────────────────────────────────────

    #[test]
    fn test_destroy_resets_state() {
        let mut b = BARRIER_NULL;
        b.barriers = BARRIER_I_ABORTED;
        b.destroy();
        assert_eq!(b.barriers, 0);
        assert_eq!(b.me, INVALID_FD);
        assert!(!b.is_aborted());
    }

    #[test]
    fn test_destroy_is_idempotent() {
        let mut b = BARRIER_NULL;
        b.destroy();
        b.destroy();
        assert_eq!(b.barriers, 0);
    }

    // ── set_role validation ───────────────────────────────────────────

    #[test]
    fn test_set_role_invalid_role() {
        let mut b = BARRIER_NULL;
        assert!(matches!(b.set_role(99), Err(BarrierError::InvalidRole(99))));
    }

    #[test]
    fn test_set_role_already_assigned() {
        let mut b = BARRIER_NULL;
        // BARRIER_NULL has both pipe fds set to INVALID_FD, so any
        // set_role call should fail with AlreadyAssigned.
        assert!(matches!(
            b.set_role(BARRIER_PARENT),
            Err(BarrierError::AlreadyAssigned)
        ));
        assert!(matches!(
            b.set_role(BARRIER_CHILD),
            Err(BarrierError::AlreadyAssigned)
        ));
    }

    // ── Error display ─────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let err = BarrierError::Aborted(BarrierState::IAborted);
        let s = format!("{err}");
        assert!(s.contains("I aborted"));

        let err = BarrierError::InvalidRole(42);
        let s = format!("{err}");
        assert!(s.contains("42"));

        let err = BarrierError::AlreadyAssigned;
        let s = format!("{err}");
        assert!(s.contains("already"));
    }

    #[test]
    fn test_error_source_chain() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "broken");
        let err = BarrierError::Io(io_err);
        assert!(err.source().is_some());

        let err = BarrierError::Aborted(BarrierState::WeAborted);
        assert!(err.source().is_none());
    }

    // ── BarrierState display ──────────────────────────────────────────

    #[test]
    fn test_barrier_state_display() {
        assert_eq!(format!("{}", BarrierState::Active), "active");
        assert_eq!(format!("{}", BarrierState::IAborted), "I aborted");
        assert_eq!(format!("{}", BarrierState::TheyAborted), "they aborted");
        assert_eq!(format!("{}", BarrierState::WeAborted), "we aborted");
    }

    // ── Linux-specific integration tests (require fork) ───────────────

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::error::Error;
        use std::process;

        fn reap(pid: libc::pid_t) {
            let mut status: i32 = 0;
            // SAFETY: pid is a valid child process id.
            unsafe {
                libc::waitpid(pid, &mut status, 0);
            }
        }

        #[test]
        fn test_create_destroy() {
            let mut b = Barrier::create().expect("eventfd on linux");
            assert!(b.me >= 0);
            assert!(b.them >= 0);
            assert!(b.pipe[0] >= 0);
            assert!(b.pipe[1] >= 0);
            assert_eq!(b.barriers, 0);
            assert_eq!(b.state(), BarrierState::Active);
            b.destroy();
        }

        #[test]
        fn test_set_role_parent() {
            let mut b = Barrier::create().unwrap();
            b.set_role(BARRIER_PARENT).unwrap();
            assert!(b.pipe[0] >= 0);
            assert_eq!(b.pipe[1], INVALID_FD);
            b.destroy();
        }

        #[test]
        fn test_set_role_child() {
            let mut b = Barrier::create().unwrap();
            let orig_me = b.me;
            let orig_them = b.them;
            b.set_role(BARRIER_CHILD).unwrap();
            assert_eq!(b.me, orig_them);
            assert_eq!(b.them, orig_me);
            assert_eq!(b.pipe[0], INVALID_FD);
            assert!(b.pipe[1] >= 0);
            b.destroy();
        }

        #[test]
        fn test_set_role_invalid_then_valid() {
            let mut b = Barrier::create().unwrap();
            assert!(b.set_role(99).is_err());
            // Barrier should still be usable after invalid role
            b.set_role(BARRIER_PARENT).unwrap();
            assert!(b.pipe[0] >= 0);
            b.destroy();
        }

        #[test]
        fn test_place_increments_counter() {
            let mut b = Barrier::create().unwrap();
            b.place().unwrap();
            assert_eq!(b.barriers, 1);
            b.place().unwrap();
            assert_eq!(b.barriers, 2);
            b.place().unwrap();
            assert_eq!(b.barriers, 3);
            b.destroy();
        }

        #[test]
        fn test_abort_transitions_to_i_aborted() {
            let mut b = Barrier::create().unwrap();
            assert!(!b.i_aborted());
            assert!(!b.they_aborted());

            let state = b.abort().unwrap();
            assert_eq!(state, BarrierState::IAborted);
            assert!(b.i_aborted());
            assert!(!b.they_aborted());

            // Second abort is a no-op.
            let state2 = b.abort().unwrap();
            assert_eq!(state2, BarrierState::IAborted);
            b.destroy();
        }

        #[test]
        fn test_fork_place_wait_next() {
            let mut b = Barrier::create().unwrap();
            // SAFETY: fork() is the standard POSIX syscall.
            match unsafe { libc::fork() } {
                -1 => panic!("fork failed"),
                0 => {
                    b.set_role(BARRIER_CHILD).unwrap();
                    b.place().unwrap();
                    process::exit(0);
                }
                child_pid => {
                    b.set_role(BARRIER_PARENT).unwrap();
                    b.wait_next().unwrap();
                    assert_eq!(b.barriers, -1);
                    b.wait_abortion().unwrap();
                    assert!(b.they_aborted());
                    b.destroy();
                    reap(child_pid);
                }
            }
        }

        #[test]
        fn test_fork_abort_both_sides() {
            let mut b = Barrier::create().unwrap();
            // SAFETY: the test forks before creating additional threads and handles both processes.
            match unsafe { libc::fork() } {
                -1 => panic!("fork failed"),
                0 => {
                    b.set_role(BARRIER_CHILD).unwrap();
                    b.abort().unwrap();
                    process::exit(0);
                }
                child_pid => {
                    b.set_role(BARRIER_PARENT).unwrap();
                    b.wait_abortion().unwrap();
                    assert!(b.they_aborted());

                    let state = b.abort().unwrap();
                    assert_eq!(state, BarrierState::WeAborted);
                    assert!(b.we_aborted());
                    b.destroy();
                    reap(child_pid);
                }
            }
        }

        #[test]
        fn test_fork_sync_roundtrip() {
            let mut b = Barrier::create().unwrap();
            // SAFETY: the test forks before creating additional threads and handles both processes.
            match unsafe { libc::fork() } {
                -1 => panic!("fork failed"),
                0 => {
                    b.set_role(BARRIER_CHILD).unwrap();
                    for _ in 0..3 {
                        b.place().unwrap();
                    }
                    b.sync().unwrap();
                    process::exit(0);
                }
                child_pid => {
                    b.set_role(BARRIER_PARENT).unwrap();
                    for _ in 0..3 {
                        b.place().unwrap();
                    }
                    b.sync().unwrap();
                    assert_eq!(b.state(), BarrierState::Active);
                    b.destroy();
                    reap(child_pid);
                }
            }
        }

        #[test]
        fn test_fork_place_and_sync() {
            let mut b = Barrier::create().unwrap();
            // SAFETY: the test forks before creating additional threads and handles both processes.
            match unsafe { libc::fork() } {
                -1 => panic!("fork failed"),
                0 => {
                    b.set_role(BARRIER_CHILD).unwrap();
                    b.place_and_sync().unwrap();
                    process::exit(0);
                }
                child_pid => {
                    b.set_role(BARRIER_PARENT).unwrap();
                    b.place_and_sync().unwrap();
                    b.destroy();
                    reap(child_pid);
                }
            }
        }

        #[test]
        fn test_fork_sync_next_no_wait() {
            let mut b = Barrier::create().unwrap();
            // SAFETY: the test forks before creating additional threads and handles both processes.
            match unsafe { libc::fork() } {
                -1 => panic!("fork failed"),
                0 => {
                    b.set_role(BARRIER_CHILD).unwrap();
                    for _ in 0..3 {
                        b.place().unwrap();
                    }
                    b.sync_next().unwrap();
                    process::exit(0);
                }
                child_pid => {
                    b.set_role(BARRIER_PARENT).unwrap();
                    b.place().unwrap();
                    // Parent placed 1, child placed 3 — sync_next should
                    // return immediately since child already has more.
                    b.sync_next().unwrap();
                    b.destroy();
                    reap(child_pid);
                }
            }
        }

        #[test]
        fn test_fork_abort_cancels_sync() {
            let mut b = Barrier::create().unwrap();
            // SAFETY: the test forks before creating additional threads and handles both processes.
            match unsafe { libc::fork() } {
                -1 => panic!("fork failed"),
                0 => {
                    b.set_role(BARRIER_CHILD).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    b.abort().unwrap();
                    process::exit(0);
                }
                child_pid => {
                    b.set_role(BARRIER_PARENT).unwrap();
                    b.place().unwrap();
                    let err = b.sync().unwrap_err();
                    assert!(matches!(err, BarrierError::Aborted(_)));
                    assert!(b.is_aborted());
                    b.destroy();
                    reap(child_pid);
                }
            }
        }

        #[test]
        fn test_drop_cleans_up() {
            // Barrier::drop calls destroy internally — verify no double-close.
            {
                let _b = Barrier::create().unwrap();
            }
            // If we reach here, Drop succeeded without panicking.
        }
    }
}
