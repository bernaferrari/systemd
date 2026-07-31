// SPDX-License-Identifier: LGPL-2.1-or-later

// PORT-SYNC: src/core/dbus.c (the `sd_bus_attach_event()` lifecycle).
//!
//! Bounded epoll ownership for already-authenticated private D-Bus wire slots.
//!
//! C lets `sd_bus_attach_event()` own the read/write interest of each direct
//! private-bus connection. Rust keeps that ownership explicit instead: this
//! adapter owns only duplicate descriptors, source IDs, and coalesced
//! readiness. [`PrivateBusWireSlot`] remains the sole owner of the original
//! stream, peer identity, bounded input, and reply queue. Callbacks never read
//! a socket, decode a message, submit a manager command, or mutate a manager.
//!
//! This deliberately remains disconnected from the production PID 1 loop and
//! `/run/systemd/private`. A future integration must register a slot only
//! after promotion from authentication, consume a finite number of events in
//! its outer manager turn, update interest from the slot's checked readiness,
//! and call [`PrivateBusWireSourceOwner::unregister`] before closing slots.

#[cfg(target_os = "linux")]
mod imp {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::os::fd::{AsFd, OwnedFd};
    use std::rc::Rc;

    use nix::errno::Errno;
    use nix::sys::epoll::EpollFlags;
    use systemd_event_loop_rs::loop_::EventLoop;

    use crate::pid1_dbus_listener::PrivateBusConnectionId;
    use crate::pid1_dbus_transport::PrivateBusWireSlot;

    // Kept disjoint from the authentication listener/source range (1 << 34)
    // and from all PID 1 sources currently registered by main.rs.
    const FIRST_PRIVATE_BUS_WIRE_SOURCE_ID: u64 = 1 << 35;
    const TERMINAL_EVENTS: EpollFlags = EpollFlags::EPOLLERR
        .union(EpollFlags::EPOLLHUP)
        .union(EpollFlags::EPOLLRDHUP);

    /// Checked epoll interest for one already-authenticated wire slot.
    ///
    /// Terminal conditions are always retained. A dispatcher normally starts
    /// in [`Self::read_only`], enables writing only after a reply frame is
    /// queued, and disables reading while the slot reports input backpressure.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PrivateBusWireInterest {
        read: bool,
        write: bool,
    }

    impl PrivateBusWireInterest {
        pub const fn new(read: bool, write: bool) -> Self {
            Self { read, write }
        }

        pub const fn read_only() -> Self {
            Self::new(true, false)
        }

        pub const fn write_only() -> Self {
            Self::new(false, true)
        }

        pub const fn read_write() -> Self {
            Self::new(true, true)
        }

        /// Keep only disconnect/error observation while the manager has no
        /// safe I/O work for this peer.
        pub const fn terminal_only() -> Self {
            Self::new(false, false)
        }

        pub const fn reads(self) -> bool {
            self.read
        }

        pub const fn writes(self) -> bool {
            self.write
        }

        const fn epoll_flags(self) -> EpollFlags {
            let mut flags = TERMINAL_EVENTS;
            if self.read {
                flags = flags.union(EpollFlags::EPOLLIN);
            }
            if self.write {
                flags = flags.union(EpollFlags::EPOLLOUT);
            }
            flags
        }
    }

    /// One coalesced readiness observation for a wire slot.
    ///
    /// Multiple epoll notifications before the outer manager turn are ORed
    /// into one value per connection. The owner retains no unbounded event
    /// list even under a noisy peer.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PrivateBusWireEvent {
        pub readable: bool,
        pub writable: bool,
        pub terminal: bool,
    }

    impl PrivateBusWireEvent {
        fn from_epoll(flags: EpollFlags) -> Self {
            Self {
                readable: flags.contains(EpollFlags::EPOLLIN),
                writable: flags.contains(EpollFlags::EPOLLOUT),
                terminal: flags.intersects(TERMINAL_EVENTS),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PrivateBusWireSourceError {
        EventLoop(Errno),
        AlreadyRegistered(PrivateBusConnectionId),
        UnknownWireSlot(PrivateBusConnectionId),
        SlotIdentityMismatch {
            requested: PrivateBusConnectionId,
            actual: PrivateBusConnectionId,
        },
        SourceIdExhausted,
    }

    impl From<Errno> for PrivateBusWireSourceError {
        fn from(error: Errno) -> Self {
            Self::EventLoop(error)
        }
    }

    #[derive(Default)]
    struct PendingWireEvents {
        order: VecDeque<PrivateBusConnectionId>,
        flags: BTreeMap<PrivateBusConnectionId, EpollFlags>,
    }

    impl PendingWireEvents {
        fn push(&mut self, id: PrivateBusConnectionId, flags: EpollFlags) {
            if let Some(pending) = self.flags.get_mut(&id) {
                *pending |= flags;
                return;
            }

            self.order.push_back(id);
            self.flags.insert(id, flags);
        }

        fn pop(&mut self) -> Option<(PrivateBusConnectionId, PrivateBusWireEvent)> {
            while let Some(id) = self.order.pop_front() {
                if let Some(flags) = self.flags.remove(&id) {
                    return Some((id, PrivateBusWireEvent::from_epoll(flags)));
                }
            }
            None
        }

        fn remove(&mut self, id: PrivateBusConnectionId) {
            self.flags.remove(&id);
        }
    }

    struct RegisteredWireSource {
        fd: OwnedFd,
        source_id: u64,
        interest: PrivateBusWireInterest,
    }

    /// Same-thread owner for private-bus wire event sources.
    ///
    /// Every registration duplicates the slot's descriptor, which means a
    /// future slot close cannot make an epoll deletion target a recycled raw
    /// descriptor. `Rc<RefCell<_>>` makes callback-local, same-thread
    /// readiness ownership explicit without pretending this is thread-safe.
    pub struct PrivateBusWireSourceOwner {
        pending: Rc<RefCell<PendingWireEvents>>,
        registered: BTreeMap<PrivateBusConnectionId, RegisteredWireSource>,
        next_source_id: u64,
    }

    impl Default for PrivateBusWireSourceOwner {
        fn default() -> Self {
            Self::new()
        }
    }

    impl PrivateBusWireSourceOwner {
        pub fn new() -> Self {
            Self {
                pending: Rc::new(RefCell::new(PendingWireEvents::default())),
                registered: BTreeMap::new(),
                next_source_id: FIRST_PRIVATE_BUS_WIRE_SOURCE_ID,
            }
        }

        pub fn registered_count(&self) -> usize {
            self.registered.len()
        }

        pub fn interest(&self, id: PrivateBusConnectionId) -> Option<PrivateBusWireInterest> {
            self.registered.get(&id).map(|source| source.interest)
        }

        /// Register one authenticated wire slot for coalesced readiness.
        ///
        /// The `PrivateBusWireSlot` argument prevents accidentally attaching
        /// a stream still in the authentication lifecycle. This routine only
        /// duplicates and registers the descriptor; it never performs I/O.
        pub fn register(
            &mut self,
            event_loop: &mut EventLoop,
            id: PrivateBusConnectionId,
            slot: &PrivateBusWireSlot,
            interest: PrivateBusWireInterest,
        ) -> Result<(), PrivateBusWireSourceError> {
            if self.registered.contains_key(&id) {
                return Err(PrivateBusWireSourceError::AlreadyRegistered(id));
            }
            if slot.id() != id {
                return Err(PrivateBusWireSourceError::SlotIdentityMismatch {
                    requested: id,
                    actual: slot.id(),
                });
            }

            let source_id = self.next_source_id;
            let Some(next_source_id) = self.next_source_id.checked_add(1) else {
                return Err(PrivateBusWireSourceError::SourceIdExhausted);
            };
            let fd = slot
                .connection()
                .stream()
                .as_fd()
                .try_clone_to_owned()
                .map_err(|error| {
                    PrivateBusWireSourceError::EventLoop(Errno::from_raw(
                        error.raw_os_error().unwrap_or(libc::EIO),
                    ))
                })?;

            let pending = Rc::clone(&self.pending);
            event_loop.add_source(
                &fd,
                interest.epoll_flags(),
                source_id,
                Box::new(move |events, _data| {
                    pending
                        .try_borrow_mut()
                        .map_err(|_| Errno::EBUSY)?
                        .push(id, EpollFlags::from_bits_truncate(events as i32));
                    Ok(())
                }),
            )?;

            self.next_source_id = next_source_id;
            self.registered.insert(
                id,
                RegisteredWireSource {
                    fd,
                    source_id,
                    interest,
                },
            );
            Ok(())
        }

        /// Update a slot's I/O interest while retaining error/disconnect
        /// observation. This is the only epoll-interest mutation path.
        pub fn set_interest(
            &mut self,
            event_loop: &EventLoop,
            id: PrivateBusConnectionId,
            interest: PrivateBusWireInterest,
        ) -> Result<(), PrivateBusWireSourceError> {
            let source = self
                .registered
                .get_mut(&id)
                .ok_or(PrivateBusWireSourceError::UnknownWireSlot(id))?;
            if source.interest == interest {
                return Ok(());
            }

            event_loop.modify_source(&source.fd, interest.epoll_flags(), source.source_id)?;
            source.interest = interest;
            Ok(())
        }

        /// Remove one coalesced event. A future dispatcher must use a finite
        /// per-turn pop budget so a busy peer cannot monopolize PID 1.
        pub fn pop_ready(
            &self,
        ) -> Result<Option<(PrivateBusConnectionId, PrivateBusWireEvent)>, PrivateBusWireSourceError>
        {
            Ok(self
                .pending
                .try_borrow_mut()
                .map_err(|_| PrivateBusWireSourceError::EventLoop(Errno::EBUSY))?
                .pop())
        }

        /// Remove every registration and discard queued readiness before the
        /// associated wire slots are closed. It is safe to call after a prior
        /// successful teardown.
        pub fn unregister(
            &mut self,
            event_loop: &mut EventLoop,
        ) -> Result<(), PrivateBusWireSourceError> {
            let mut first_error = None;
            let registered = std::mem::take(&mut self.registered);
            for (id, source) in registered {
                match self.pending.try_borrow_mut() {
                    Ok(mut pending) => pending.remove(id),
                    Err(_) => {
                        first_error
                            .get_or_insert(PrivateBusWireSourceError::EventLoop(Errno::EBUSY));
                    }
                }
                if let Err(error) = event_loop.remove_source(&source.fd, source.source_id) {
                    first_error.get_or_insert(PrivateBusWireSourceError::EventLoop(error));
                }
            }

            match first_error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io::{Read, Write};
        use std::num::NonZeroUsize;
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::path::PathBuf;
        use std::time::{SystemTime, UNIX_EPOCH};

        use nix::unistd::geteuid;

        use super::*;
        use crate::pid1_dbus_listener::PrivateBusListener;
        use crate::pid1_dbus_transport::{PrivateBusTransportOwner, PrivateBusWireSlotConfig};

        fn socket_path(name: &str) -> PathBuf {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            std::env::temp_dir().join(format!(
                "systemd-rust-private-bus-wire-source-{name}-{}-{stamp}.socket",
                std::process::id()
            ))
        }

        fn external_token() -> Vec<u8> {
            geteuid()
                .as_raw()
                .to_string()
                .bytes()
                .flat_map(|byte| {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0xf)]]
                })
                .collect()
        }

        fn wire_slot(
            event_loop: &mut EventLoop,
            name: &str,
        ) -> (
            PathBuf,
            UnixStream,
            PrivateBusTransportOwner,
            PrivateBusConnectionId,
        ) {
            let path = socket_path(name);
            let listener = UnixListener::bind(&path).unwrap();
            let listener =
                PrivateBusListener::from_bound_listener(listener, geteuid().as_raw()).unwrap();
            let mut owner = PrivateBusTransportOwner::register(
                event_loop,
                listener,
                NonZeroUsize::new(1).unwrap(),
            )
            .unwrap();
            let mut client = UnixStream::connect(&path).unwrap();

            event_loop.run_once(0).unwrap();
            owner
                .dispatch_ready(
                    event_loop,
                    NonZeroUsize::new(4).unwrap(),
                    NonZeroUsize::new(4).unwrap(),
                    || Ok([0x5a; 16]),
                )
                .unwrap();
            client.write_all(b"\0AUTH EXTERNAL\r\n").unwrap();
            for _ in 0..2 {
                event_loop.run_once(0).unwrap();
                owner
                    .dispatch_ready(
                        event_loop,
                        NonZeroUsize::new(4).unwrap(),
                        NonZeroUsize::new(4).unwrap(),
                        || Ok([0x5a; 16]),
                    )
                    .unwrap();
            }
            let mut challenge = [0_u8; 6];
            client.read_exact(&mut challenge).unwrap();
            assert_eq!(&challenge, b"DATA\r\n");

            let mut response = b"DATA ".to_vec();
            response.extend_from_slice(&external_token());
            response.extend_from_slice(b"\r\nBEGIN\r\n");
            client.write_all(&response).unwrap();
            for _ in 0..2 {
                event_loop.run_once(0).unwrap();
                owner
                    .dispatch_ready(
                        event_loop,
                        NonZeroUsize::new(4).unwrap(),
                        NonZeroUsize::new(4).unwrap(),
                        || Ok([0x5a; 16]),
                    )
                    .unwrap();
            }

            let id = owner
                .promote_authenticated_to_wire(PrivateBusWireSlotConfig::new(
                    256,
                    NonZeroUsize::new(2).unwrap(),
                    512,
                    1024,
                ))
                .unwrap()
                .unwrap();
            (path, client, owner, id)
        }

        #[test]
        fn wire_readiness_is_coalesced_and_interest_is_explicit() {
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut client, mut transport, id) = wire_slot(&mut event_loop, "coalesced");
            let mut sources = PrivateBusWireSourceOwner::new();

            sources
                .register(
                    &mut event_loop,
                    id,
                    transport.wire_slot(id).unwrap(),
                    PrivateBusWireInterest::read_only(),
                )
                .unwrap();
            assert_eq!(sources.registered_count(), 1);
            assert_eq!(
                sources.interest(id),
                Some(PrivateBusWireInterest::read_only())
            );

            client.write_all(b"first").unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            assert_eq!(event_loop.run_once(0), Ok(true));
            assert_eq!(
                sources.pop_ready(),
                Ok(Some((
                    id,
                    PrivateBusWireEvent {
                        readable: true,
                        writable: false,
                        terminal: false,
                    }
                )))
            );
            assert_eq!(sources.pop_ready(), Ok(None));

            sources
                .set_interest(&event_loop, id, PrivateBusWireInterest::write_only())
                .unwrap();
            assert_eq!(
                sources.interest(id),
                Some(PrivateBusWireInterest::write_only())
            );
            assert_eq!(
                sources.register(
                    &mut event_loop,
                    id,
                    transport.wire_slot(id).unwrap(),
                    PrivateBusWireInterest::read_only(),
                ),
                Err(PrivateBusWireSourceError::AlreadyRegistered(id))
            );

            sources.unregister(&mut event_loop).unwrap();
            assert_eq!(sources.registered_count(), 0);
            assert_eq!(
                sources.set_interest(&event_loop, id, PrivateBusWireInterest::read_only()),
                Err(PrivateBusWireSourceError::UnknownWireSlot(id))
            );
            assert_eq!(event_loop.run_once(0), Ok(false));
            transport.unregister(&mut event_loop).unwrap();
            drop((client, transport));
            std::fs::remove_file(path).unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::*;
