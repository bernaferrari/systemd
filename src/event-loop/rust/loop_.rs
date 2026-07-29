// SPDX-License-Identifier: LGPL-2.1-or-later

use std::os::fd::{AsFd, AsRawFd, RawFd};

use crate::Result;

#[cfg(target_os = "linux")]
use nix::errno::Errno;
#[cfg(target_os = "linux")]
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};

// sd-event dispatches sources on the thread running the event loop. Requiring
// callbacks to be Send forced PID 1's single-owner manager state behind a
// poisonable Mutex even though callbacks never cross a thread boundary.
type Callback = Box<dyn FnMut(u32, u64) -> Result<()>>;

#[cfg(target_os = "linux")]
struct Source {
    fd: RawFd,
    callback: Callback,
}

pub struct EventLoop {
    #[cfg(target_os = "linux")]
    epoll: Epoll,
    running: bool,
    exit_code: i32,
    #[cfg(target_os = "linux")]
    // The data value is a stable source identity, not merely epoll payload. Keeping its
    // descriptor alongside the callback prevents a remove/modify call for one source from
    // accidentally changing another source that happens to have a colliding ID.
    sources: std::collections::HashMap<u64, Source>,
}

#[derive(Debug, Clone, Copy)]
pub enum Event {
    Io { fd: RawFd, events: u32 },
    Timer { id: usize },
    Signal { signo: i32, pid: u32, uid: u32 },
}

impl EventLoop {
    #[cfg(target_os = "linux")]
    pub fn new() -> Result<Self> {
        Ok(Self {
            // Match sd-event: the loop descriptor must not leak into services launched by PID 1.
            epoll: Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?,
            running: false,
            exit_code: 0,
            sources: std::collections::HashMap::new(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: false,
            exit_code: 0,
        })
    }

    #[cfg(target_os = "linux")]
    pub fn add_source<Fd: AsFd>(
        &mut self,
        fd: Fd,
        events: EpollFlags,
        data: u64,
        cb: Callback,
    ) -> Result<()> {
        // An epoll event carries only this u64. Reusing it would silently replace the first
        // callback and route queued events from the old descriptor to the new source.
        if self.sources.contains_key(&data) {
            return Err(Errno::EEXIST);
        }

        let fd = fd.as_fd();
        let raw_fd = fd.as_raw_fd();
        let event = EpollEvent::new(events, data);
        self.epoll.add(fd, event)?;
        self.sources.insert(
            data,
            Source {
                fd: raw_fd,
                callback: cb,
            },
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn modify_source<Fd: AsFd>(&self, fd: Fd, events: EpollFlags, data: u64) -> Result<()> {
        let fd = fd.as_fd();
        let source = self.sources.get(&data).ok_or(Errno::ENOENT)?;
        if source.fd != fd.as_raw_fd() {
            return Err(Errno::EINVAL);
        }

        let mut event = EpollEvent::new(events, data);
        self.epoll.modify(fd, &mut event)
    }

    #[cfg(target_os = "linux")]
    pub fn remove_source<Fd: AsFd>(&mut self, fd: Fd, data: u64) -> Result<()> {
        let fd = fd.as_fd();
        let source = self.sources.get(&data).ok_or(Errno::ENOENT)?;
        if source.fd != fd.as_raw_fd() {
            return Err(Errno::EINVAL);
        }

        // Clear the callback even if the kernel has already detached an externally closed
        // descriptor. epoll may still have a queued readiness event; dispatching it after the
        // source was removed would be less safe than reporting the removal error to the caller.
        self.sources.remove(&data);
        self.epoll.delete(fd)
    }

    #[cfg(target_os = "linux")]
    pub fn run_once(&mut self, timeout_ms: isize) -> Result<bool> {
        // The old nix API silently truncated isize to c_int. Reject values which would turn a
        // finite wait into an infinite one (or vice versa) on 64-bit callers.
        if !(-1..=i32::MAX as isize).contains(&timeout_ms) {
            return Err(Errno::EINVAL);
        }

        let mut events = [EpollEvent::empty(); 64];
        let timeout = EpollTimeout::try_from(timeout_ms as i32).map_err(|_| Errno::EINVAL)?;
        let n = self.epoll.wait(&mut events, timeout)?;

        for event in &events[..n] {
            let data = event.data();
            // EpollFlags is a 32-bit bitset; this conversion preserves every flag bit,
            // including the high-bit flags represented by a negative signed c_int.
            let events_bits = event.events().bits() as u32;
            if let Some(source) = self.sources.get_mut(&data) {
                (source.callback)(events_bits, data)?;
            }
            // Missing callbacks are expected for events queued before remove_source(). They
            // must be ignored rather than dispatched through a recycled ID.
        }

        Ok(n > 0)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn run_once(&mut self, _timeout_ms: isize) -> Result<bool> {
        std::thread::sleep(std::time::Duration::from_millis(100));
        Ok(false)
    }

    pub fn run(&mut self) -> Result<i32> {
        self.running = true;
        while self.running {
            self.run_once(-1)?;
        }
        Ok(self.exit_code)
    }

    pub fn exit(&mut self, code: i32) {
        self.running = false;
        self.exit_code = code;
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn epoll_fd(&self) -> RawFd {
        #[cfg(target_os = "linux")]
        {
            self.epoll.0.as_fd().as_raw_fd()
        }
        #[cfg(not(target_os = "linux"))]
        {
            -1
        }
    }
}
