// SPDX-License-Identifier: LGPL-2.1-or-later

//! PID 1 ownership of asynchronous child exec-status event sources.
//!
//! The runtime manager owns every status protocol channel. This module owns a
//! duplicated descriptor for each epoll registration plus a bounded pid inbox;
//! callbacks never borrow the manager, read a pipe, or advance a unit state
//! machine. That keeps the post-fork protocol single-threaded and prevents
//! descriptor reuse from being mistaken for a different service's exec
//! acknowledgement.

#[cfg(target_os = "linux")]
use std::cell::RefCell;
#[cfg(target_os = "linux")]
use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::rc::{Rc, Weak};

#[cfg(target_os = "linux")]
use nix::errno::Errno;
#[cfg(target_os = "linux")]
use nix::sys::epoll::EpollFlags;
#[cfg(target_os = "linux")]
use systemd_event_loop_rs::loop_::EventLoop;
#[cfg(target_os = "linux")]
use systemd_platform_rs::spawn::ExecStatusHandle;

/// Keep this range disjoint from signal/timer and practical socket-source IDs.
/// `EventLoop` still rejects an accidental collision rather than replacing a
/// callback, so this is defense in depth rather than an identity mechanism.
#[cfg(target_os = "linux")]
const FIRST_EXEC_STATUS_SOURCE_ID: u64 = 1 << 32;

/// A callback inbox must not turn an event storm into unbounded PID 1 memory
/// growth. One pid is queued at most once, and a full inbox is a hard source
/// failure rather than silently dropping an exec failure acknowledgement.
#[cfg(target_os = "linux")]
const EXEC_STATUS_INBOX_CAPACITY: usize = 64;

#[cfg(target_os = "linux")]
struct RegisteredExecStatusSource {
    fd: OwnedFd,
    data_id: u64,
    owner: Weak<RefCell<ExecStatusHandle>>,
}

/// Single-threaded owner of exec-status epoll registrations and their bounded
/// readiness inbox.
#[cfg(target_os = "linux")]
pub struct ExecStatusSourceOwner {
    inbox: Rc<RefCell<VecDeque<crate::runtime_manager::PendingExecStatusDescriptor>>>,
    registered: HashMap<u32, RegisteredExecStatusSource>,
    next_data_id: u64,
}

/// Keep the executable's import surface cfg-stable; non-Linux PID 1 does not
/// use Linux post-fork exec-status pipes.
#[cfg(not(target_os = "linux"))]
pub struct ExecStatusSourceOwner;

#[cfg(target_os = "linux")]
impl Default for ExecStatusSourceOwner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl ExecStatusSourceOwner {
    pub fn new() -> Self {
        Self {
            inbox: Rc::new(RefCell::new(VecDeque::new())),
            registered: HashMap::new(),
            next_data_id: FIRST_EXEC_STATUS_SOURCE_ID,
        }
    }

    /// Synchronize epoll sources with the manager's immutable weak snapshot.
    ///
    /// Pid alone is not a stable descriptor identity: it may be reused after a
    /// child exits. A source survives only if both its pid and the manager's
    /// `Rc` allocation identity still match. Each registration owns a
    /// duplicated descriptor so an old raw number cannot be recycled and make
    /// `EPOLL_CTL_DEL` detach an unrelated new source.
    pub fn reconcile(
        &mut self,
        event_loop: &mut EventLoop,
        statuses: Vec<crate::runtime_manager::PendingExecStatusDescriptor>,
    ) -> Result<(), Errno> {
        let mut current = HashMap::with_capacity(statuses.len());
        for status in statuses {
            if current.insert(status.pid(), status).is_some() {
                return Err(Errno::EINVAL);
            }
        }

        let stale: Vec<u32> = self
            .registered
            .iter()
            .filter_map(|(&pid, source)| {
                let unchanged = current
                    .get(&pid)
                    .is_some_and(|status| Weak::ptr_eq(&source.owner, status.weak_owner()));
                (!unchanged).then_some(pid)
            })
            .collect();

        for pid in stale {
            let Some(source) = self.registered.remove(&pid) else {
                continue;
            };
            event_loop.remove_source(&source.fd, source.data_id)?;
        }

        for (pid, status) in current {
            if self.registered.contains_key(&pid) {
                continue;
            }

            let Some(fd) = status
                .clone_fd_for_registration()
                .map_err(|error| Errno::from_raw(error.raw_os_error().unwrap_or(libc::EIO)))?
            else {
                // The child was reaped between snapshot and reconciliation.
                continue;
            };
            let data_id = self.next_data_id;
            self.next_data_id = self.next_data_id.checked_add(1).ok_or(Errno::EOVERFLOW)?;

            let callback_status = status.clone();
            let callback_inbox = Rc::clone(&self.inbox);
            event_loop.add_source(
                &fd,
                EpollFlags::EPOLLIN | EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP,
                data_id,
                Box::new(move |events, _data| {
                    // Epoll reports this as an unsigned event mask, while nix models the
                    // identical kernel bit pattern with c_int-backed EpollFlags.
                    let ready = EpollFlags::from_bits_truncate(events as i32).intersects(
                        EpollFlags::EPOLLIN | EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP,
                    );
                    if ready && callback_status.is_live() {
                        let mut inbox =
                            callback_inbox.try_borrow_mut().map_err(|_| Errno::EBUSY)?;
                        if !inbox.iter().any(|queued| {
                            queued.pid() == pid
                                && Weak::ptr_eq(queued.weak_owner(), callback_status.weak_owner())
                        }) {
                            if inbox.len() == EXEC_STATUS_INBOX_CAPACITY {
                                return Err(Errno::ENOBUFS);
                            }
                            inbox.push_back(callback_status.clone());
                        }
                    }
                    Ok(())
                }),
            )?;

            self.registered.insert(
                pid,
                RegisteredExecStatusSource {
                    fd,
                    data_id,
                    owner: status.weak_owner().clone(),
                },
            );
        }

        Ok(())
    }

    /// Take one epoll-ready child status notification. Unit transitions remain
    /// with `RuntimeManager::observe_exec_status_ready`.
    pub fn pop_ready(
        &self,
    ) -> Result<Option<crate::runtime_manager::PendingExecStatusDescriptor>, Errno> {
        self.inbox
            .try_borrow_mut()
            .map_err(|_| Errno::EBUSY)
            .map(|mut inbox| inbox.pop_front())
    }

    /// True when a dispatch budget was exhausted. The main loop must perform
    /// another nonblocking manager turn instead of sleeping in epoll for its
    /// normal timeout while an already-delivered exec acknowledgement waits in
    /// this inbox.
    pub fn has_ready(&self) -> Result<bool, Errno> {
        self.inbox
            .try_borrow()
            .map_err(|_| Errno::EBUSY)
            .map(|inbox| !inbox.is_empty())
    }

    pub fn registered_count(&self) -> usize {
        self.registered.len()
    }
}
