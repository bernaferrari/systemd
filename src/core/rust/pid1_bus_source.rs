// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/core/dbus.c (manager event-loop wake ownership).

//! Same-thread wake source for authenticated manager-bus commands.
//!
//! This is deliberately smaller than a D-Bus transport. It does not open a
//! socket, authenticate peers, decode messages, or claim ownership of
//! `org.freedesktop.systemd1`. It gives such a transport one safe property the
//! C manager gets from `sd_bus_attach_event()`: submitting work makes the PID 1
//! epoll loop runnable, while the one live [`RuntimeManager`] remains owned and
//! mutated by that loop.
//!
//! On Linux, the sender and inbox share a semaphore-mode `eventfd`. The sender
//! is intentionally `!Send` because it contains an [`std::rc::Rc`]; a transport
//! using it must therefore run on the PID 1 event-loop thread. Every accepted
//! command owns exactly one wake token. A failed bounded-channel submission
//! rolls its token back before returning, and dispatch consumes exactly the
//! tokens for commands it removed.

use std::num::NonZeroUsize;

use crate::pid1_manager_commands::{
    Pid1CommandAuthorizer, Pid1CommandError, Pid1CommandInbox, Pid1CommandReplyReceiver,
    Pid1DispatchOutcome, Pid1ManagerCommand, SenderIdentity, pid1_manager_command_channel,
};
use crate::runtime_manager::RuntimeManager;

#[cfg(target_os = "linux")]
mod imp {
    use std::os::fd::AsFd;
    use std::rc::Rc;

    use nix::errno::Errno;
    use nix::sys::epoll::EpollFlags;
    use nix::sys::eventfd::{EfdFlags, EventFd};
    use systemd_event_loop_rs::loop_::EventLoop;

    use super::*;

    /// Kept disjoint from PID 1's signal/timer IDs, socket-source range, and
    /// exec-status range. `EventLoop` also rejects collisions.
    const PID1_BUS_COMMAND_SOURCE_ID: u64 = 4;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Pid1BusSendError {
        Command(Pid1CommandError),
        Wake(Errno),
    }

    fn write_token(wake: &EventFd) -> Result<(), Errno> {
        loop {
            match wake.write(1) {
                Ok(size) if size == size_of::<u64>() => return Ok(()),
                Ok(_) => return Err(Errno::EIO),
                Err(Errno::EINTR) => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn read_token(wake: &EventFd) -> Result<(), Errno> {
        loop {
            match wake.read() {
                Ok(1) => return Ok(()),
                Ok(_) => return Err(Errno::EIO),
                Err(Errno::EINTR) => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Cloneable only within the PID 1 thread. The `Rc<EventFd>` makes moving
    /// this sender into a detached executor or worker thread a type error.
    #[derive(Clone)]
    pub struct Pid1BusCommandSender {
        inner: crate::pid1_manager_commands::Pid1CommandSender,
        wake: Rc<EventFd>,
    }

    impl Pid1BusCommandSender {
        /// Queue one semantic manager operation and make the PID 1 event loop
        /// runnable. A returned receiver means both operations succeeded.
        pub fn try_send(
            &self,
            sender: SenderIdentity,
            command: Pid1ManagerCommand,
        ) -> Result<Pid1CommandReplyReceiver, Pid1BusSendError> {
            // Reserve the wake token first. Because this sender is !Send, the
            // same-thread event loop cannot consume it between this write and
            // a possible rollback.
            write_token(&self.wake).map_err(Pid1BusSendError::Wake)?;

            match self.inner.try_send(sender, command) {
                Ok(receiver) => Ok(receiver),
                Err(error) => {
                    // The command was not accepted, so it must not leave a
                    // readable token that would spin epoll forever.
                    read_token(&self.wake).map_err(Pid1BusSendError::Wake)?;
                    Err(Pid1BusSendError::Command(error))
                }
            }
        }
    }

    /// Event-loop-owned half of the manager-bus command seam.
    pub struct Pid1BusCommandInbox {
        inner: Pid1CommandInbox,
        wake: Rc<EventFd>,
    }

    impl Pid1BusCommandInbox {
        /// Attach the command wake descriptor to one PID 1 event-loop
        /// invocation. The callback never captures or mutates RuntimeManager.
        pub fn register(&self, event_loop: &mut EventLoop) -> Result<(), Errno> {
            let keep_alive = Rc::clone(&self.wake);
            event_loop.add_source(
                self.wake.as_fd(),
                EpollFlags::EPOLLIN | EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP,
                PID1_BUS_COMMAND_SOURCE_ID,
                Box::new(move |events, _data| {
                    // Retain descriptor ownership for the callback's complete
                    // registration lifetime. Tokens are consumed only after
                    // their commands have actually left the bounded inbox.
                    let _ = &keep_alive;
                    let flags = EpollFlags::from_bits_truncate(events as i32);
                    if flags.intersects(EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP) {
                        return Err(Errno::EIO);
                    }
                    Ok(())
                }),
            )
        }

        pub fn dispatch_pending<A: Pid1CommandAuthorizer + ?Sized>(
            &mut self,
            runtime: &mut RuntimeManager,
            authorizer: &mut A,
            budget: NonZeroUsize,
        ) -> Result<Pid1DispatchOutcome, Errno> {
            let outcome = self.inner.dispatch_pending(runtime, authorizer, budget);
            for _ in 0..outcome.dispatched {
                read_token(&self.wake)?;
            }
            Ok(outcome)
        }
    }

    pub fn pid1_bus_command_channel(
        capacity: NonZeroUsize,
    ) -> Result<(Pid1BusCommandSender, Pid1BusCommandInbox), Errno> {
        let wake = Rc::new(EventFd::from_flags(
            EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK | EfdFlags::EFD_SEMAPHORE,
        )?);
        let (sender, inbox) = pid1_manager_command_channel(capacity);
        Ok((
            Pid1BusCommandSender {
                inner: sender,
                wake: Rc::clone(&wake),
            },
            Pid1BusCommandInbox { inner: inbox, wake },
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::pid1_manager_commands::{
            AuthenticatedPeer, DenyAllPid1CommandAuthorizer, Pid1CommandError,
        };

        fn root_sender() -> SenderIdentity {
            SenderIdentity::from_authenticated_peer(
                AuthenticatedPeer::from_kernel_peer_credentials(1, 0, 0),
            )
        }

        #[test]
        fn accepted_command_wakes_epoll_and_dispatch_consumes_its_token() {
            let (sender, mut inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            let reply = sender
                .try_send(
                    root_sender(),
                    Pid1ManagerCommand::LoadUnit {
                        name: "one.service".to_string(),
                    },
                )
                .unwrap();

            let mut event_loop = EventLoop::new().unwrap();
            inbox.register(&mut event_loop).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));

            let mut runtime = RuntimeManager::new();
            let mut authorizer = DenyAllPid1CommandAuthorizer;
            let outcome = inbox
                .dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap())
                .unwrap();
            assert_eq!(outcome.dispatched, 1);
            assert_eq!(reply.try_recv(), Ok(Err(Pid1CommandError::Unauthorized)));
            assert_eq!(event_loop.run_once(0), Ok(false));
        }

        #[test]
        fn rejected_full_inbox_rolls_back_its_wake_token() {
            let (sender, mut inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            let first = sender
                .try_send(
                    root_sender(),
                    Pid1ManagerCommand::LoadUnit {
                        name: "one.service".to_string(),
                    },
                )
                .unwrap();
            assert!(matches!(
                sender.try_send(
                    root_sender(),
                    Pid1ManagerCommand::LoadUnit {
                        name: "two.service".to_string(),
                    },
                ),
                Err(Pid1BusSendError::Command(Pid1CommandError::InboxFull))
            ));

            let mut event_loop = EventLoop::new().unwrap();
            inbox.register(&mut event_loop).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));

            let mut runtime = RuntimeManager::new();
            let mut authorizer = DenyAllPid1CommandAuthorizer;
            let outcome = inbox
                .dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap())
                .unwrap();
            assert_eq!(outcome.dispatched, 1);
            assert_eq!(first.try_recv(), Ok(Err(Pid1CommandError::Unauthorized)));
            assert_eq!(event_loop.run_once(0), Ok(false));
        }

        #[test]
        fn dispatch_budget_leaves_one_readable_token_per_queued_command() {
            let (sender, mut inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(2).unwrap()).unwrap();
            let first = sender
                .try_send(
                    root_sender(),
                    Pid1ManagerCommand::LoadUnit {
                        name: "one.service".to_string(),
                    },
                )
                .unwrap();
            let second = sender
                .try_send(
                    root_sender(),
                    Pid1ManagerCommand::LoadUnit {
                        name: "two.service".to_string(),
                    },
                )
                .unwrap();

            let mut event_loop = EventLoop::new().unwrap();
            inbox.register(&mut event_loop).unwrap();
            let mut runtime = RuntimeManager::new();
            let mut authorizer = DenyAllPid1CommandAuthorizer;

            assert_eq!(event_loop.run_once(0), Ok(true));
            let first_outcome = inbox
                .dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap())
                .unwrap();
            assert_eq!(first_outcome.dispatched, 1);
            assert_eq!(first.try_recv(), Ok(Err(Pid1CommandError::Unauthorized)));

            assert_eq!(event_loop.run_once(0), Ok(true));
            let second_outcome = inbox
                .dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap())
                .unwrap();
            assert_eq!(second_outcome.dispatched, 1);
            assert_eq!(second.try_recv(), Ok(Err(Pid1CommandError::Unauthorized)));
            assert_eq!(event_loop.run_once(0), Ok(false));
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Pid1BusSendError {
        Command(Pid1CommandError),
    }

    #[derive(Clone)]
    pub struct Pid1BusCommandSender {
        inner: crate::pid1_manager_commands::Pid1CommandSender,
    }

    impl Pid1BusCommandSender {
        pub fn try_send(
            &self,
            sender: SenderIdentity,
            command: Pid1ManagerCommand,
        ) -> Result<Pid1CommandReplyReceiver, Pid1BusSendError> {
            self.inner
                .try_send(sender, command)
                .map_err(Pid1BusSendError::Command)
        }
    }

    pub struct Pid1BusCommandInbox {
        inner: Pid1CommandInbox,
    }

    impl Pid1BusCommandInbox {
        pub fn dispatch_pending<A: Pid1CommandAuthorizer + ?Sized>(
            &mut self,
            runtime: &mut RuntimeManager,
            authorizer: &mut A,
            budget: NonZeroUsize,
        ) -> Result<Pid1DispatchOutcome, crate::ffi::Errno> {
            Ok(self.inner.dispatch_pending(runtime, authorizer, budget))
        }
    }

    pub fn pid1_bus_command_channel(
        capacity: NonZeroUsize,
    ) -> Result<(Pid1BusCommandSender, Pid1BusCommandInbox), crate::ffi::Errno> {
        let (sender, inbox) = pid1_manager_command_channel(capacity);
        Ok((
            Pid1BusCommandSender { inner: sender },
            Pid1BusCommandInbox { inner: inbox },
        ))
    }
}

#[allow(unused_imports)]
pub use imp::{
    Pid1BusCommandInbox, Pid1BusCommandSender, Pid1BusSendError, pid1_bus_command_channel,
};
