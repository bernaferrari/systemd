// SPDX-License-Identifier: LGPL-2.1-or-later

//! Safe operating-system clock adapters.

use std::io;

#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, BorrowedFd};

#[cfg(target_os = "linux")]
pub fn boottime_usec() -> io::Result<u64> {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `timestamp` is a live, writable timespec for the duration of the
    // call. CLOCK_BOOTTIME requires no additional caller-owned resources.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut timestamp) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if timestamp.tv_sec < 0 || !(0..1_000_000_000).contains(&timestamp.tv_nsec) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CLOCK_BOOTTIME returned an invalid timespec",
        ));
    }

    let seconds = u64::try_from(timestamp.tv_sec)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative boot time"))?;
    let nanoseconds = u64::try_from(timestamp.tv_nsec)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative nanoseconds"))?;
    seconds
        .checked_mul(1_000_000)
        .and_then(|usec| usec.checked_add(nanoseconds / 1_000))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "boot time overflow"))
}

/// Owned, nonblocking Linux timer capability for absolute `CLOCK_BOOTTIME`
/// deadlines. Policy remains in the manager; this type only owns the kernel
/// object and validates timestamp conversion.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct BoottimeTimerFd {
    fd: nix::sys::timerfd::TimerFd,
}

#[cfg(target_os = "linux")]
impl BoottimeTimerFd {
    pub fn new() -> io::Result<Self> {
        use nix::sys::timerfd::{ClockId, TimerFd, TimerFlags};

        TimerFd::new(
            ClockId::CLOCK_BOOTTIME,
            TimerFlags::TFD_CLOEXEC | TimerFlags::TFD_NONBLOCK,
        )
        .map(|fd| Self { fd })
        .map_err(io::Error::from)
    }

    pub fn arm_absolute_usec(&self, deadline_usec: Option<u64>) -> io::Result<()> {
        use nix::sys::time::{TimeSpec, TimeValLike};
        use nix::sys::timerfd::{Expiration, TimerSetTimeFlags};

        let Some(deadline_usec) = deadline_usec else {
            return self.fd.unset().map_err(io::Error::from);
        };
        let deadline_usec = i64::try_from(deadline_usec)
            .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        self.fd
            .set(
                Expiration::OneShot(TimeSpec::microseconds(deadline_usec)),
                TimerSetTimeFlags::TFD_TIMER_ABSTIME,
            )
            .map_err(io::Error::from)
    }

    pub fn consume(&self) -> io::Result<()> {
        self.fd.wait().map_err(io::Error::from)
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(not(target_os = "linux"))]
pub fn boottime_usec() -> io::Result<u64> {
    use std::sync::OnceLock;
    use std::time::Instant;

    static PROCESS_EPOCH: OnceLock<Instant> = OnceLock::new();
    let elapsed = PROCESS_EPOCH
        .get_or_init(Instant::now)
        .elapsed()
        .as_micros();
    u64::try_from(elapsed)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "monotonic time overflow"))
}
