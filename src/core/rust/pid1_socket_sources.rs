// SPDX-License-Identifier: LGPL-2.1-or-later

//! PID 1 ownership of socket readiness event sources.
//!
//! `RuntimeManager` owns listener FDs and this type owns duplicated descriptors
//! for their epoll registrations. Readiness callbacks do exactly one thing:
//! enqueue a socket-unit activation request. They never accept a connection,
//! mutate the manager, or spawn a process.

#[cfg(target_os = "linux")]
use std::cell::RefCell;
#[cfg(target_os = "linux")]
use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::rc::Rc;
#[cfg(target_os = "linux")]
use std::sync::Weak;

#[cfg(target_os = "linux")]
use nix::errno::Errno;
#[cfg(target_os = "linux")]
use nix::sys::epoll::EpollFlags;
#[cfg(target_os = "linux")]
use systemd_event_loop_rs::loop_::EventLoop;

#[allow(unused_imports)]
use crate::socket_activation::ListenerDescriptor;

#[cfg(target_os = "linux")]
const FIRST_SOCKET_SOURCE_ID: u64 = 100;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SourceKey {
    unit_name: String,
    port_index: usize,
}

#[cfg(target_os = "linux")]
impl From<&ListenerDescriptor> for SourceKey {
    fn from(listener: &ListenerDescriptor) -> Self {
        Self {
            unit_name: listener.unit_name().to_string(),
            port_index: listener.port_index(),
        }
    }
}

#[cfg(target_os = "linux")]
struct RegisteredSocketSource {
    fd: OwnedFd,
    data_id: u64,
    owner: Weak<OwnedFd>,
}

/// Single-threaded owner of PID 1 socket-source registrations and readiness inbox.
///
/// The event loop itself dispatches callbacks synchronously on one thread, so `Rc<RefCell<_>>`
/// keeps that fact visible in the type model. No manager state is captured by a callback.
#[cfg(target_os = "linux")]
pub struct SocketSourceOwner {
    inbox: Rc<RefCell<VecDeque<String>>>,
    registered: HashMap<SourceKey, RegisteredSocketSource>,
    next_data_id: u64,
}

/// The executable's non-Linux polling loop does not register socket sources,
/// but the public name remains available so the binary has one cfg-stable
/// import surface.
#[cfg(not(target_os = "linux"))]
pub struct SocketSourceOwner;

#[cfg(target_os = "linux")]
impl Default for SocketSourceOwner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl SocketSourceOwner {
    pub fn new() -> Self {
        Self {
            inbox: Rc::new(RefCell::new(VecDeque::new())),
            registered: HashMap::new(),
            next_data_id: FIRST_SOCKET_SOURCE_ID,
        }
    }

    /// Synchronize epoll sources with an immutable listener snapshot.
    ///
    /// Listener identity includes both the socket unit/port position and the `Weak<OwnedFd>`
    /// allocation identity. Replacing a listener at the same position removes the old callback
    /// before a fresh, monotonically numbered source is registered.
    pub fn reconcile(
        &mut self,
        event_loop: &mut EventLoop,
        listeners: Vec<ListenerDescriptor>,
    ) -> Result<(), Errno> {
        let mut current = HashMap::with_capacity(listeners.len());
        for listener in listeners {
            let key = SourceKey::from(&listener);
            if current.insert(key, listener).is_some() {
                // A duplicate `(unit, port)` would make later remove/replacement behavior
                // ambiguous. The runtime snapshot is invalid rather than "last one wins".
                return Err(Errno::EINVAL);
            }
        }

        let stale: Vec<SourceKey> = self
            .registered
            .iter()
            .filter_map(|(key, source)| {
                let unchanged = current
                    .get(key)
                    .is_some_and(|listener| Weak::ptr_eq(&source.owner, listener.weak_fd()));
                (!unchanged).then(|| key.clone())
            })
            .collect();

        for key in stale {
            let Some(source) = self.registered.remove(&key) else {
                continue;
            };
            event_loop.remove_source(&source.fd, source.data_id)?;
        }

        for (key, listener) in current {
            if self.registered.contains_key(&key) {
                continue;
            }

            let Some(owner) = listener.upgrade() else {
                // The manager removed this listener between snapshot construction and
                // reconciliation. Its eventual callback must remain inert, so skip it.
                continue;
            };
            // Retain a duplicate, not merely the manager's raw descriptor
            // number. Otherwise manager-side close followed by kernel FD
            // reuse could make stale EPOLL_CTL_DEL detach an unrelated source.
            let fd = owner
                .as_fd()
                .try_clone_to_owned()
                .map_err(|error| Errno::from_raw(error.raw_os_error().unwrap_or(libc::EIO)))?;
            let data_id = self.next_data_id;
            self.next_data_id = self.next_data_id.checked_add(1).ok_or(Errno::EOVERFLOW)?;

            let callback_listener = listener.clone();
            let callback_inbox = Rc::clone(&self.inbox);
            let unit_name = listener.unit_name().to_string();
            event_loop.add_source(
                &fd,
                EpollFlags::EPOLLIN,
                data_id,
                Box::new(move |events, _data| {
                    if events & EpollFlags::EPOLLIN.bits() as u32 != 0
                        && callback_listener.upgrade().is_some()
                    {
                        let mut inbox =
                            callback_inbox.try_borrow_mut().map_err(|_| Errno::EBUSY)?;
                        if !inbox.iter().any(|queued| queued == &unit_name) {
                            inbox.push_back(unit_name.clone());
                        }
                    }
                    Ok(())
                }),
            )?;

            self.registered.insert(
                key,
                RegisteredSocketSource {
                    fd,
                    data_id,
                    owner: listener.weak_fd().clone(),
                },
            );
        }

        Ok(())
    }

    /// Removes one pending unit request. A callback may enqueue at most one request per unit
    /// while it is waiting, even if several listener ports become ready at once.
    pub fn pop_activation(&self) -> Result<Option<String>, Errno> {
        Ok(self
            .inbox
            .try_borrow_mut()
            .map_err(|_| Errno::EBUSY)?
            .pop_front())
    }

    pub fn registered_count(&self) -> usize {
        self.registered.len()
    }
}
