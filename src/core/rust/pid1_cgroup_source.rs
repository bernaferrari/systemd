// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/core/cgroup.c (manager cgroup inotify event-source lifetime).

//! PID 1 epoll ownership for manager-wide cgroup notifications.
//!
//! C registers one inotify instance with sd-event, then defers cgroup-empty
//! state transitions until notification messages and SIGCHLD metadata have
//! been handled. The Rust callback similarly records only a bounded readiness
//! bit. `RuntimeManager` retains the inotify instance and performs all reads
//! and unit mutations from the outer manager turn.

#[cfg(target_os = "linux")]
use std::cell::RefCell;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::rc::Rc;

#[cfg(target_os = "linux")]
use nix::errno::Errno;
#[cfg(target_os = "linux")]
use nix::sys::epoll::EpollFlags;
#[cfg(target_os = "linux")]
use systemd_event_loop_rs::loop_::EventLoop;

#[cfg(target_os = "linux")]
use crate::runtime_manager::CgroupEventDescriptor;

/// Keep the identity disjoint from fixed main-loop sources and dynamically
/// allocated socket/exec-status ranges. EventLoop additionally rejects any
/// accidental collision before installing a callback.
#[cfg(target_os = "linux")]
const CGROUP_INOTIFY_SOURCE_ID: u64 = (1 << 33) + 1;

/// Owns the duplicate descriptor used by epoll and its one-bit inbox.
#[cfg(target_os = "linux")]
pub struct CgroupSourceOwner {
    ready: Rc<RefCell<bool>>,
    registered: Option<OwnedFd>,
}

#[cfg(target_os = "linux")]
impl Default for CgroupSourceOwner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl CgroupSourceOwner {
    pub fn new() -> Self {
        Self {
            ready: Rc::new(RefCell::new(false)),
            registered: None,
        }
    }

    /// Register the runtime's lazily allocated manager-wide inotify instance.
    ///
    /// RuntimeManager never replaces a live instance: it transitions only
    /// from `None` to `Some` and closes it during manager teardown. Therefore
    /// an already registered source may discard later duplicate snapshots.
    pub fn reconcile(
        &mut self,
        event_loop: &mut EventLoop,
        descriptor: Option<CgroupEventDescriptor>,
    ) -> Result<(), Errno> {
        if self.registered.is_some() {
            if descriptor.is_none() {
                self.unregister(event_loop)?;
            }
            return Ok(());
        }

        let Some(descriptor) = descriptor else {
            return Ok(());
        };
        let fd = descriptor.into_fd();
        let callback_ready = Rc::clone(&self.ready);
        event_loop.add_source(
            &fd,
            EpollFlags::EPOLLIN | EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP,
            CGROUP_INOTIFY_SOURCE_ID,
            Box::new(move |events, _data| {
                let events = EpollFlags::from_bits_truncate(events as i32);
                if events
                    .intersects(EpollFlags::EPOLLIN | EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP)
                {
                    *callback_ready.try_borrow_mut().map_err(|_| Errno::EBUSY)? = true;
                }
                Ok(())
            }),
        )?;
        self.registered = Some(fd);
        Ok(())
    }

    /// Consume the coalesced readiness notification. The caller must drain
    /// the inotify queue before blocking in epoll again.
    pub fn take_ready(&self) -> Result<bool, Errno> {
        let mut ready = self.ready.try_borrow_mut().map_err(|_| Errno::EBUSY)?;
        let value = *ready;
        *ready = false;
        Ok(value)
    }

    /// Remove the event source before either descriptor owner is dropped.
    pub fn unregister(&mut self, event_loop: &mut EventLoop) -> Result<(), Errno> {
        *self.ready.try_borrow_mut().map_err(|_| Errno::EBUSY)? = false;
        let Some(fd) = self.registered.take() else {
            return Ok(());
        };
        event_loop.remove_source(&fd, CGROUP_INOTIFY_SOURCE_ID)
    }

    pub fn registered(&self) -> bool {
        self.registered.is_some()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use nix::unistd::{pipe, write};
    use systemd_event_loop_rs::loop_::EventLoop;

    #[test]
    fn readiness_is_coalesced_and_teardown_removes_the_source() {
        let (reader, writer) = pipe().unwrap();
        let descriptor = CgroupEventDescriptor::from_fd(reader);
        let mut event_loop = EventLoop::new().unwrap();
        let mut source = CgroupSourceOwner::new();

        source.reconcile(&mut event_loop, Some(descriptor)).unwrap();
        assert!(source.registered());
        assert_eq!(write(&writer, b"x").unwrap(), 1);
        assert!(event_loop.run_once(100).unwrap());
        assert!(source.take_ready().unwrap());
        assert!(!source.take_ready().unwrap());

        source.unregister(&mut event_loop).unwrap();
        assert!(!source.registered());
        assert!(!event_loop.run_once(0).unwrap());
    }
}
