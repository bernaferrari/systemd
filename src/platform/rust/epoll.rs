// SPDX-License-Identifier: LGPL-2.1-or-later

use nix::sys::epoll::{EpollCreateFlags, EpollEvent, EpollFlags};
use std::os::unix::io::{AsFd, AsRawFd, RawFd};

pub struct Epoll {
    inner: nix::sys::epoll::Epoll,
}

impl Epoll {
    pub fn new() -> nix::Result<Self> {
        let inner = nix::sys::epoll::Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?;
        Ok(Self { inner })
    }

    pub fn add<F: AsFd>(&self, fd: F, events: EpollFlags, data: u64) -> nix::Result<()> {
        let event = EpollEvent::new(events, data);
        self.inner.add(fd, event)
    }

    pub fn modify<F: AsFd>(&self, fd: F, events: EpollFlags, data: u64) -> nix::Result<()> {
        let mut event = EpollEvent::new(events, data);
        self.inner.modify(fd, &mut event)
    }

    pub fn delete<F: AsFd>(&self, fd: F) -> nix::Result<()> {
        self.inner.delete(fd)
    }

    pub fn wait(&self, events: &mut [EpollEvent], timeout_ms: u16) -> nix::Result<usize> {
        self.inner.wait(events, timeout_ms)
    }
}

impl std::fmt::Debug for Epoll {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Epoll")
            .field("fd", &self.inner.0.as_raw_fd())
            .finish()
    }
}

impl AsRawFd for Epoll {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.0.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use nix::sys::eventfd::{EfdFlags, EventFd};

    #[test]
    fn test_epoll_create() {
        let epoll = Epoll::new();
        assert!(epoll.is_ok());
    }

    #[test]
    fn test_epoll_is_close_on_exec() {
        let epoll = Epoll::new().unwrap();
        let flags = fcntl(&epoll.inner.0, FcntlArg::F_GETFD).unwrap();

        assert!(FdFlag::from_bits_retain(flags).contains(FdFlag::FD_CLOEXEC));
    }

    #[test]
    fn test_epoll_add_and_wait() {
        let epoll = Epoll::new().unwrap();
        let efd = EventFd::from_flags(EfdFlags::EFD_NONBLOCK).unwrap();

        epoll.add(&efd, EpollFlags::EPOLLIN, 42).unwrap();

        let mut events = [EpollEvent::empty()];
        let count = epoll.wait(&mut events, 0).unwrap();
        assert_eq!(count, 0);
    }
}
