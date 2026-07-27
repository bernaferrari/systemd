// SPDX-License-Identifier: LGPL-2.1-or-later

use crate::Result;

#[cfg(target_os = "linux")]
pub use nix::sys::timerfd::TimerFd;

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct TimerFd;

#[cfg(target_os = "linux")]
pub fn timerfd_create() -> Result<TimerFd> {
    use nix::sys::timerfd::{ClockId, TimerFlags};

    TimerFd::new(ClockId::CLOCK_MONOTONIC, TimerFlags::empty())
}

#[cfg(not(target_os = "linux"))]
pub fn timerfd_create() -> Result<TimerFd> {
    Err(nix::errno::Errno::ENOSYS)
}

#[cfg(target_os = "linux")]
pub fn timerfd_settime(fd: &TimerFd, relative_usec: u64) -> Result<()> {
    use nix::sys::timerfd::{Expiration, TimerSetTimeFlags};
    use nix::time::{TimeSpec, TimeValLike};

    let relative_usec = i64::try_from(relative_usec).map_err(|_| nix::errno::Errno::EOVERFLOW)?;
    fd.set(
        Expiration::OneShot(TimeSpec::microseconds(relative_usec)),
        TimerSetTimeFlags::empty(),
    )
}

#[cfg(not(target_os = "linux"))]
pub fn timerfd_settime(_fd: &TimerFd, _relative_usec: u64) -> Result<()> {
    Err(nix::errno::Errno::ENOSYS)
}

#[cfg(target_os = "linux")]
pub fn timerfd_read(fd: &TimerFd) -> Result<()> {
    fd.wait()
}

#[cfg(not(target_os = "linux"))]
pub fn timerfd_read(_fd: &TimerFd) -> Result<()> {
    Err(nix::errno::Errno::ENOSYS)
}
