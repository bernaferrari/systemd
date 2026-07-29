// SPDX-License-Identifier: LGPL-2.1-or-later

use nix::errno::Errno;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::signalfd::{self, SfdFlags};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

/// Block the given signals on the current thread, returning the previous signal set.
pub fn block_signals(signals: &[Signal]) -> nix::Result<SigSet> {
    let mut mask = SigSet::empty();
    for &sig in signals {
        mask.add(sig);
    }
    let old = SigSet::thread_get_mask().unwrap_or_else(|_| SigSet::empty());
    mask.thread_block()?;
    Ok(old)
}

/// Unblock the given signals on the current thread.
pub fn unblock_signals(signals: &[Signal]) -> nix::Result<()> {
    let mut mask = SigSet::empty();
    for &sig in signals {
        mask.add(sig);
    }
    mask.thread_unblock()
}

/// Build the signal mask owned by the system manager.
///
/// This mirrors `manager_setup_signals()` rather than limiting the manager to
/// the subset representable by nix's non-realtime `Signal` enum.
#[cfg(target_os = "linux")]
pub fn manager_signal_mask() -> nix::Result<SigSet> {
    let standard = [
        libc::SIGCHLD,
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGINT,
        libc::SIGWINCH,
        libc::SIGPWR,
    ];
    let realtime_offsets = [
        0, 1, 2, 3, 4, 5, 6, 7, 13, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    ];

    let mut raw = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: raw points to writable, correctly aligned storage. sigemptyset
    // initializes it before any read, and every added signal is either a libc
    // constant or within the runtime-reported realtime signal range.
    unsafe {
        if libc::sigemptyset(raw.as_mut_ptr()) != 0 {
            return Err(Errno::last());
        }
        let mask = raw.as_mut_ptr();
        for signal in standard {
            if libc::sigaddset(mask, signal) != 0 {
                return Err(Errno::last());
            }
        }

        let (realtime_min, realtime_max) = realtime_signal_range()?;
        for offset in realtime_offsets {
            let signal = realtime_min + offset;
            if signal <= realtime_max && libc::sigaddset(mask, signal) != 0 {
                return Err(Errno::last());
            }
        }

        Ok(SigSet::from_sigset_t_unchecked(raw.assume_init()))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn manager_signal_mask() -> nix::Result<SigSet> {
    Err(Errno::ENOSYS)
}

#[cfg(target_os = "linux")]
pub fn realtime_signal_range() -> nix::Result<(i32, i32)> {
    // libc exposes these as safe target-specific functions because glibc may
    // reserve implementation signals dynamically.
    let realtime_min = libc::SIGRTMIN();
    let realtime_max = libc::SIGRTMAX();
    if realtime_min < 0 || realtime_max < realtime_min {
        Err(Errno::EINVAL)
    } else {
        Ok((realtime_min, realtime_max))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn realtime_signal_range() -> nix::Result<(i32, i32)> {
    Err(Errno::ENOSYS)
}

/// Reset SIGCHLD to the disposition required for manager child accounting.
pub fn reset_sigchld() -> nix::Result<()> {
    let action = SigAction::new(
        SigHandler::SigDfl,
        SaFlags::SA_NOCLDSTOP | SaFlags::SA_RESTART,
        SigSet::empty(),
    );
    // SAFETY: the action contains SIG_DFL and an initialized empty mask. No
    // Rust function pointer or borrowed storage is installed as a handler.
    unsafe { nix::sys::signal::sigaction(Signal::SIGCHLD, &action) }?;
    Ok(())
}

/// A file descriptor for receiving signals via `signalfd`.
pub struct SignalFd {
    inner: signalfd::SignalFd,
}

impl SignalFd {
    /// Create a new signalfd listening for the given signals.
    pub fn new(signals: &[Signal]) -> nix::Result<Self> {
        let mut mask = SigSet::empty();
        for &sig in signals {
            mask.add(sig);
        }
        Self::from_mask(&mask)
    }

    /// Create a close-on-exec, nonblocking signalfd for an existing mask.
    pub fn from_mask(mask: &SigSet) -> nix::Result<Self> {
        let inner =
            signalfd::SignalFd::with_flags(mask, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)?;
        Ok(Self { inner })
    }

    /// Read a pending signal. Returns `Ok(None)` if no signal is available.
    pub fn read_signal(&self) -> nix::Result<Option<signalfd::siginfo>> {
        self.inner.read_signal()
    }
}

impl std::fmt::Debug for SignalFd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalFd")
            .field("fd", &self.inner.as_raw_fd())
            .finish()
    }
}

impl AsRawFd for SignalFd {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl AsFd for SignalFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}
