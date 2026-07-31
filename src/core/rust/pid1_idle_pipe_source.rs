// SPDX-License-Identifier: LGPL-2.1-or-later

//! PID 1 epoll ownership for the manager's `Type=idle` alert pipe.
//!
//! C registers `idle_pipe[2]` with sd-event and, on a child's bounded-wait
//! alert, closes both pipe pairs. The runtime owns pipe lifetime; this source
//! owns only a duplicated registration descriptor and a one-bit inbox. The
//! callback never reads a pipe, starts a service, or mutates manager state.

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
use crate::runtime_manager::IdlePipeAlertDescriptor;

#[cfg(target_os = "linux")]
const IDLE_PIPE_SOURCE_ID: u64 = 1 << 33;

#[cfg(target_os = "linux")]
struct RegisteredIdlePipeSource {
    fd: OwnedFd,
    generation: u64,
}

/// Single-threaded owner of the idle alert's epoll registration.
#[cfg(target_os = "linux")]
pub struct IdlePipeSourceOwner {
    alerted: Rc<RefCell<bool>>,
    registered: Option<RegisteredIdlePipeSource>,
}

/// The non-Linux polling manager does not have the C pipe protocol.
#[cfg(not(target_os = "linux"))]
pub struct IdlePipeSourceOwner;

#[cfg(target_os = "linux")]
impl Default for IdlePipeSourceOwner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl IdlePipeSourceOwner {
    pub fn new() -> Self {
        Self {
            alerted: Rc::new(RefCell::new(false)),
            registered: None,
        }
    }

    /// Reconcile the one manager-owned alert descriptor. The generation is a
    /// pipe allocation identity, not a raw descriptor number: every gate
    /// replacement removes its previous epoll source before registration.
    pub fn reconcile(
        &mut self,
        event_loop: &mut EventLoop,
        descriptor: Option<IdlePipeAlertDescriptor>,
    ) -> Result<(), Errno> {
        let replacement_needed = match (&self.registered, &descriptor) {
            (Some(registered), Some(descriptor)) => {
                registered.generation != descriptor.generation()
            }
            (None, None) => false,
            _ => true,
        };

        if replacement_needed {
            if let Some(registered) = self.registered.take() {
                event_loop.remove_source(&registered.fd, IDLE_PIPE_SOURCE_ID)?;
            }
            *self.alerted.borrow_mut() = false;
        }

        if self.registered.is_some() {
            return Ok(());
        }
        let Some(descriptor) = descriptor else {
            return Ok(());
        };

        let generation = descriptor.generation();
        let fd = descriptor.into_fd();
        let callback_alerted = Rc::clone(&self.alerted);
        event_loop.add_source(
            &fd,
            EpollFlags::EPOLLIN,
            IDLE_PIPE_SOURCE_ID,
            Box::new(move |events, _data| {
                if events & EpollFlags::EPOLLIN.bits() as u32 != 0 {
                    *callback_alerted
                        .try_borrow_mut()
                        .map_err(|_| Errno::EBUSY)? = true;
                }
                Ok(())
            }),
        )?;
        self.registered = Some(RegisteredIdlePipeSource { fd, generation });
        Ok(())
    }

    /// Consume one advisory child timeout alert. Runtime ownership performs
    /// the close/acknowledgement after this method returns.
    pub fn take_alert(&self) -> Result<bool, Errno> {
        let mut alerted = self.alerted.try_borrow_mut().map_err(|_| Errno::EBUSY)?;
        let value = *alerted;
        *alerted = false;
        Ok(value)
    }

    pub fn registered(&self) -> bool {
        self.registered.is_some()
    }
}

#[cfg(not(target_os = "linux"))]
impl IdlePipeSourceOwner {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::runtime_manager::RuntimeManager;
    use systemd_event_loop_rs::loop_::EventLoop;

    #[test]
    fn epoll_alert_is_delivered_without_runtime_mutation_in_callback() {
        let mut runtime = RuntimeManager::new();
        let pipe = runtime.idle_pipe_for_spawn().unwrap();
        let descriptor = runtime.idle_pipe_alert_descriptor().unwrap();
        let mut event_loop = EventLoop::new().unwrap();
        let mut source = IdlePipeSourceOwner::new();
        source.reconcile(&mut event_loop, descriptor).unwrap();
        assert!(source.registered());

        // SAFETY: the manager owns child_alert_fd for the duration of this
        // test and the static byte slice is valid for the requested length.
        let wrote = unsafe { libc::write(pipe.child_alert_fd, b"x".as_ptr().cast(), 1) };
        assert_eq!(wrote, 1);
        assert!(event_loop.run_once(100).unwrap());
        assert!(source.take_alert().unwrap());
        assert!(!source.take_alert().unwrap());

        runtime.close_idle_pipe();
        source.reconcile(&mut event_loop, None).unwrap();
        assert!(!source.registered());
    }
}
