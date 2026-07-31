// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/core/dbus.c (`bus_init_private()`, `bus_on_connection()`)

//! Bounded PID 1 event-source orchestration for private D-Bus authentication.
//!
//! This is the bridge between [`crate::pid1_dbus_listener::PrivateBusListener`]
//! and the same-thread epoll loop. Callbacks only coalesce readiness; the outer
//! manager turn accepts connections, advances authentication by at most one
//! socket operation per ready connection, changes EPOLLIN/EPOLLOUT interest,
//! and removes dead or rejected peers.
//!
//! Authenticated streams are deliberately taken out of epoll and exposed only
//! through a handoff queue. No D-Bus messages are decoded or dispatched here,
//! and this module is not wired into the production Rust PID 1. A future wire
//! owner must explicitly take each authenticated connection, retain its
//! kernel-derived identity, and register a new source before the private
//! manager API can be advertised.

#[cfg(target_os = "linux")]
mod imp {
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, VecDeque};
    use std::num::NonZeroUsize;
    use std::rc::Rc;

    use nix::errno::Errno;
    use nix::sys::epoll::EpollFlags;
    use systemd_event_loop_rs::loop_::EventLoop;

    use crate::pid1_dbus_listener::{
        AdmittedPrivateBusConnection, PrivateBusAcceptError, PrivateBusAuthIoProgress,
        PrivateBusConnectionId, PrivateBusListener,
    };

    const PRIVATE_BUS_LISTENER_SOURCE_ID: u64 = 1 << 34;
    const FIRST_PRIVATE_BUS_CONNECTION_SOURCE_ID: u64 = PRIVATE_BUS_LISTENER_SOURCE_ID + 1;
    const LISTENER_EVENTS: EpollFlags = EpollFlags::EPOLLIN
        .union(EpollFlags::EPOLLERR)
        .union(EpollFlags::EPOLLHUP);
    const READ_EVENTS: EpollFlags = EpollFlags::EPOLLIN
        .union(EpollFlags::EPOLLERR)
        .union(EpollFlags::EPOLLHUP)
        .union(EpollFlags::EPOLLRDHUP);
    const WRITE_EVENTS: EpollFlags = EpollFlags::EPOLLOUT
        .union(EpollFlags::EPOLLERR)
        .union(EpollFlags::EPOLLHUP)
        .union(EpollFlags::EPOLLRDHUP);
    const TERMINAL_EVENTS: EpollFlags = EpollFlags::EPOLLERR
        .union(EpollFlags::EPOLLHUP)
        .union(EpollFlags::EPOLLRDHUP);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PrivateBusEventSourceError {
        EventLoop(Errno),
        ListenerUnavailable,
        /// `sd_id128_randomize()`'s equivalent failed after accepting a
        /// peer, so the stream was dropped without a server ID.
        ServerIdGeneration(Errno),
        SourceIdExhausted,
        InconsistentOwnership,
    }

    impl From<Errno> for PrivateBusEventSourceError {
        fn from(error: Errno) -> Self {
            Self::EventLoop(error)
        }
    }

    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct PrivateBusDispatchOutcome {
        pub accepted: usize,
        pub refused: usize,
        pub authentication_steps: usize,
        pub authenticated: usize,
        pub disconnected: usize,
        pub accept_budget_exhausted: bool,
        /// The caller's retained-connection limit prevented another accept.
        ///
        /// This is distinct from `refused`: no descriptor was accepted and
        /// immediately dropped, so the listener remains level-triggered for a
        /// later turn after a wire slot is released.
        pub connection_limit_reached: bool,
        pub authentication_budget_exhausted: bool,
    }

    #[derive(Default)]
    struct PendingConnections {
        order: VecDeque<PrivateBusConnectionId>,
        flags: BTreeMap<PrivateBusConnectionId, EpollFlags>,
    }

    impl PendingConnections {
        fn push(&mut self, id: PrivateBusConnectionId, flags: EpollFlags) {
            if let Some(pending) = self.flags.get_mut(&id) {
                *pending |= flags;
                return;
            }

            self.order.push_back(id);
            self.flags.insert(id, flags);
        }

        fn pop(&mut self) -> Option<(PrivateBusConnectionId, EpollFlags)> {
            while let Some(id) = self.order.pop_front() {
                if let Some(flags) = self.flags.remove(&id) {
                    return Some((id, flags));
                }
            }
            None
        }

        fn remove(&mut self, id: PrivateBusConnectionId) {
            self.flags.remove(&id);
        }

        fn is_empty(&self) -> bool {
            self.flags.is_empty()
        }
    }

    struct RegisteredConnection {
        source_id: u64,
        interest: EpollFlags,
    }

    /// Same-thread owner for one private listener's authentication sources.
    ///
    /// `Rc`/`RefCell` are intentional: [`EventLoop`] invokes every callback on
    /// its dispatch thread, and no callback captures manager state. The shared
    /// readiness queue contains at most one entry per registered connection.
    pub struct PrivateBusEventSourceOwner {
        listener: PrivateBusListener,
        listener_events: Rc<Cell<EpollFlags>>,
        pending_connections: Rc<RefCell<PendingConnections>>,
        registered: BTreeMap<PrivateBusConnectionId, RegisteredConnection>,
        authenticated: VecDeque<PrivateBusConnectionId>,
        next_source_id: u64,
    }

    impl PrivateBusEventSourceOwner {
        /// Register an already-bound listener with the PID 1 event loop.
        ///
        /// The returned owner must outlive the registration. It deliberately
        /// does not bind `/run/systemd/private`; production lifecycle policy
        /// remains with the future manager integration.
        pub fn register(
            event_loop: &mut EventLoop,
            listener: PrivateBusListener,
        ) -> Result<Self, PrivateBusEventSourceError> {
            let listener_events = Rc::new(Cell::new(EpollFlags::empty()));
            let callback_events = Rc::clone(&listener_events);
            event_loop.add_source(
                listener.listener_fd(),
                LISTENER_EVENTS,
                PRIVATE_BUS_LISTENER_SOURCE_ID,
                Box::new(move |events, _data| {
                    callback_events
                        .set(callback_events.get() | EpollFlags::from_bits_truncate(events as i32));
                    Ok(())
                }),
            )?;

            Ok(Self {
                listener,
                listener_events,
                pending_connections: Rc::new(RefCell::new(PendingConnections::default())),
                registered: BTreeMap::new(),
                authenticated: VecDeque::new(),
                next_source_id: FIRST_PRIVATE_BUS_CONNECTION_SOURCE_ID,
            })
        }

        pub const fn listener(&self) -> &PrivateBusListener {
            &self.listener
        }

        pub fn registered_connection_count(&self) -> usize {
            self.registered.len()
        }

        pub fn authenticated_connection_count(&self) -> usize {
            self.authenticated.len()
        }

        /// Total streams this owner retains across authentication and the
        /// authenticated handoff queue.
        pub fn retained_connection_count(&self) -> usize {
            self.listener.connection_count()
        }

        /// Return the next authenticated connection to a future wire owner.
        ///
        /// Its authentication source has already been removed from epoll, so
        /// leaving it in this queue cannot spin the manager loop.
        pub fn pop_authenticated(
            &mut self,
        ) -> Option<(PrivateBusConnectionId, AdmittedPrivateBusConnection)> {
            while let Some(id) = self.authenticated.pop_front() {
                if let Some(connection) = self.listener.remove_connection(id) {
                    return Some((id, connection));
                }
            }
            None
        }

        /// Handle coalesced listener and authentication readiness with finite
        /// per-turn budgets.
        ///
        /// `server_id` is called only for a connection which passed accept,
        /// the table limit, and `SO_PEERCRED`. Production integration must use
        /// the same cryptographically strong, fallible random-id contract as
        /// `sd_id128_randomize()`. On failure the accepted peer is closed and
        /// [`PrivateBusEventSourceError::ServerIdGeneration`] is returned;
        /// deterministic generators are useful only to test this disconnected
        /// adapter.
        pub fn dispatch_ready(
            &mut self,
            event_loop: &mut EventLoop,
            accept_budget: NonZeroUsize,
            authentication_budget: NonZeroUsize,
            server_id: impl FnMut() -> Result<[u8; 16], Errno>,
        ) -> Result<PrivateBusDispatchOutcome, PrivateBusEventSourceError> {
            self.dispatch_ready_with_connection_limit(
                event_loop,
                accept_budget,
                authentication_budget,
                self.listener.connection_limit(),
                server_id,
            )
        }

        /// Like [`Self::dispatch_ready`], but cap every connection retained by
        /// this owner at `connection_limit`.
        ///
        /// The limit is checked before `accept()`. A composite transport owner
        /// supplies the number of slots not occupied by later wire stages,
        /// which preserves one cap across every ownership transfer without
        /// accepting and dropping peers merely because a downstream slot is
        /// full.
        pub fn dispatch_ready_with_connection_limit(
            &mut self,
            event_loop: &mut EventLoop,
            accept_budget: NonZeroUsize,
            authentication_budget: NonZeroUsize,
            connection_limit: usize,
            mut server_id: impl FnMut() -> Result<[u8; 16], Errno>,
        ) -> Result<PrivateBusDispatchOutcome, PrivateBusEventSourceError> {
            let mut outcome = PrivateBusDispatchOutcome::default();
            let listener_events = self.listener_events.replace(EpollFlags::empty());
            if listener_events.intersects(EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP) {
                return Err(PrivateBusEventSourceError::ListenerUnavailable);
            }

            if listener_events.contains(EpollFlags::EPOLLIN) {
                for attempt in 0..accept_budget.get() {
                    if self.listener.connection_count() >= connection_limit {
                        outcome.connection_limit_reached = true;
                        break;
                    }
                    match self.listener.try_accept_one_with(&mut server_id) {
                        Ok(id) => {
                            self.register_connection(event_loop, id)?;
                            outcome.accepted += 1;
                        }
                        Err(PrivateBusAcceptError::Io(error))
                            if error.kind() == std::io::ErrorKind::WouldBlock =>
                        {
                            break;
                        }
                        Err(PrivateBusAcceptError::ServerIdGeneration(error)) => {
                            return Err(PrivateBusEventSourceError::ServerIdGeneration(error));
                        }
                        Err(_) => {
                            // The accepted descriptor is already dropped by
                            // `try_accept_one_with()`. Like C, one malformed or
                            // unauthorized peer does not disable the listener.
                            outcome.refused += 1;
                        }
                    }

                    if attempt + 1 == accept_budget.get() {
                        outcome.accept_budget_exhausted = true;
                    }
                }
            }

            for attempt in 0..authentication_budget.get() {
                let ready = self
                    .pending_connections
                    .try_borrow_mut()
                    .map_err(|_| PrivateBusEventSourceError::EventLoop(Errno::EBUSY))?
                    .pop();
                let Some((id, events)) = ready else {
                    break;
                };
                if !self.registered.contains_key(&id) {
                    continue;
                }

                outcome.authentication_steps += 1;
                let progress = self
                    .listener
                    .connection_mut(id)
                    .ok_or(PrivateBusEventSourceError::InconsistentOwnership)?
                    .drive_authentication();

                if events.intersects(TERMINAL_EVENTS) {
                    self.drop_connection(event_loop, id)?;
                    outcome.disconnected += 1;
                    continue;
                }

                match progress {
                    Ok(PrivateBusAuthIoProgress::NeedsRead) => {
                        self.set_interest(event_loop, id, READ_EVENTS)?;
                    }
                    Ok(PrivateBusAuthIoProgress::NeedsWrite) => {
                        self.set_interest(event_loop, id, WRITE_EVENTS)?;
                    }
                    Ok(PrivateBusAuthIoProgress::Authenticated) => {
                        self.remove_registration(event_loop, id)?;
                        self.authenticated.push_back(id);
                        outcome.authenticated += 1;
                    }
                    Ok(PrivateBusAuthIoProgress::PeerClosed) | Err(_) => {
                        self.drop_connection(event_loop, id)?;
                        outcome.disconnected += 1;
                    }
                }

                if attempt + 1 == authentication_budget.get()
                    && !self
                        .pending_connections
                        .try_borrow()
                        .map_err(|_| PrivateBusEventSourceError::EventLoop(Errno::EBUSY))?
                        .is_empty()
                {
                    outcome.authentication_budget_exhausted = true;
                }
            }

            Ok(outcome)
        }

        /// Remove every event source owned by this adapter and close all of
        /// its retained streams.
        ///
        /// This explicit lifecycle step is required before a manager drops or
        /// replaces the private transport. It removes callbacks even if an
        /// epoll deletion reports an error, so queued readiness can never call
        /// back into abandoned ownership state. Calling it again is harmless
        /// after a successful teardown.
        pub fn unregister(
            &mut self,
            event_loop: &mut EventLoop,
        ) -> Result<(), PrivateBusEventSourceError> {
            let registered_ids: Vec<_> = self.registered.keys().copied().collect();
            let mut first_error = None;

            for id in registered_ids {
                let source_id = self.registered.get(&id).map(|entry| entry.source_id);
                let removal = match (source_id, self.listener.connection(id)) {
                    (Some(source_id), Some(connection)) => {
                        event_loop.remove_source(connection.stream(), source_id)
                    }
                    _ => Err(Errno::ENOENT),
                };
                self.registered.remove(&id);
                match self.pending_connections.try_borrow_mut() {
                    Ok(mut pending) => pending.remove(id),
                    Err(_) => {
                        // Still release every descriptor and event source
                        // below. The queue is callback-private state and will
                        // be dropped with this owner, so retaining a stale id
                        // there cannot revive a removed connection.
                        first_error
                            .get_or_insert(PrivateBusEventSourceError::EventLoop(Errno::EBUSY));
                    }
                }
                self.listener.remove_connection(id);
                if let Err(error) = removal {
                    first_error.get_or_insert(PrivateBusEventSourceError::EventLoop(error));
                }
            }

            while let Some(id) = self.authenticated.pop_front() {
                self.listener.remove_connection(id);
            }

            // Registered streams and the handoff queue normally comprise the
            // complete listener table. Clear any inconsistent residual entry
            // defensively: it must not outlive the listener source.
            self.listener.clear_connections();

            self.listener_events.set(EpollFlags::empty());
            match event_loop
                .remove_source(self.listener.listener_fd(), PRIVATE_BUS_LISTENER_SOURCE_ID)
            {
                Ok(()) => {}
                Err(Errno::ENOENT) => {}
                Err(error) => {
                    first_error.get_or_insert(PrivateBusEventSourceError::EventLoop(error));
                }
            }

            match first_error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        fn register_connection(
            &mut self,
            event_loop: &mut EventLoop,
            id: PrivateBusConnectionId,
        ) -> Result<(), PrivateBusEventSourceError> {
            let source_id = self.next_source_id;
            let Some(next_source_id) = self.next_source_id.checked_add(1) else {
                self.listener.remove_connection(id);
                return Err(PrivateBusEventSourceError::SourceIdExhausted);
            };
            self.next_source_id = next_source_id;

            let pending = Rc::clone(&self.pending_connections);
            let connection = self
                .listener
                .connection(id)
                .ok_or(PrivateBusEventSourceError::InconsistentOwnership)?;
            if let Err(error) = event_loop.add_source(
                connection.stream(),
                READ_EVENTS,
                source_id,
                Box::new(move |events, _data| {
                    pending
                        .try_borrow_mut()
                        .map_err(|_| Errno::EBUSY)?
                        .push(id, EpollFlags::from_bits_truncate(events as i32));
                    Ok(())
                }),
            ) {
                self.listener.remove_connection(id);
                return Err(PrivateBusEventSourceError::EventLoop(error));
            }

            self.registered.insert(
                id,
                RegisteredConnection {
                    source_id,
                    interest: READ_EVENTS,
                },
            );
            Ok(())
        }

        fn set_interest(
            &mut self,
            event_loop: &EventLoop,
            id: PrivateBusConnectionId,
            interest: EpollFlags,
        ) -> Result<(), PrivateBusEventSourceError> {
            let registration = self
                .registered
                .get_mut(&id)
                .ok_or(PrivateBusEventSourceError::InconsistentOwnership)?;
            if registration.interest == interest {
                return Ok(());
            }

            let connection = self
                .listener
                .connection(id)
                .ok_or(PrivateBusEventSourceError::InconsistentOwnership)?;
            event_loop.modify_source(connection.stream(), interest, registration.source_id)?;
            registration.interest = interest;
            Ok(())
        }

        fn remove_registration(
            &mut self,
            event_loop: &mut EventLoop,
            id: PrivateBusConnectionId,
        ) -> Result<(), PrivateBusEventSourceError> {
            let source_id = self
                .registered
                .get(&id)
                .ok_or(PrivateBusEventSourceError::InconsistentOwnership)?
                .source_id;
            let connection = self
                .listener
                .connection(id)
                .ok_or(PrivateBusEventSourceError::InconsistentOwnership)?;
            event_loop.remove_source(connection.stream(), source_id)?;
            self.registered.remove(&id);
            self.pending_connections
                .try_borrow_mut()
                .map_err(|_| PrivateBusEventSourceError::EventLoop(Errno::EBUSY))?
                .remove(id);
            Ok(())
        }

        fn drop_connection(
            &mut self,
            event_loop: &mut EventLoop,
            id: PrivateBusConnectionId,
        ) -> Result<(), PrivateBusEventSourceError> {
            self.remove_registration(event_loop, id)?;
            self.listener.remove_connection(id);
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io::{Read, Write};
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::path::PathBuf;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        use nix::unistd::geteuid;

        use super::*;

        fn socket_path(name: &str) -> PathBuf {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            std::env::temp_dir().join(format!(
                "systemd-rust-private-bus-events-{name}-{}-{stamp}.socket",
                std::process::id()
            ))
        }

        fn owner(name: &str) -> (PathBuf, EventLoop, PrivateBusEventSourceOwner) {
            let path = socket_path(name);
            let listener = UnixListener::bind(&path).unwrap();
            let listener =
                PrivateBusListener::from_bound_listener(listener, geteuid().as_raw()).unwrap();
            let mut event_loop = EventLoop::new().unwrap();
            let owner = PrivateBusEventSourceOwner::register(&mut event_loop, listener).unwrap();
            (path, event_loop, owner)
        }

        fn dispatch(
            owner: &mut PrivateBusEventSourceOwner,
            event_loop: &mut EventLoop,
        ) -> PrivateBusDispatchOutcome {
            owner
                .dispatch_ready(
                    event_loop,
                    NonZeroUsize::new(8).unwrap(),
                    NonZeroUsize::new(8).unwrap(),
                    || Ok([0x5a; 16]),
                )
                .unwrap()
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

        #[test]
        fn event_loop_accepts_and_hands_off_an_authenticated_stream() {
            let (path, mut event_loop, mut owner) = owner("auth");
            let mut client = UnixStream::connect(&path).unwrap();

            assert_eq!(event_loop.run_once(0), Ok(true));
            assert_eq!(dispatch(&mut owner, &mut event_loop).accepted, 1);
            assert_eq!(owner.registered_connection_count(), 1);

            client.write_all(b"\0AUTH EXTERNAL\r\n").unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            assert_eq!(
                dispatch(&mut owner, &mut event_loop).authentication_steps,
                1
            );
            assert_eq!(event_loop.run_once(0), Ok(true));
            dispatch(&mut owner, &mut event_loop);
            let mut challenge = [0_u8; 6];
            client.read_exact(&mut challenge).unwrap();
            assert_eq!(&challenge, b"DATA\r\n");

            let mut response = b"DATA ".to_vec();
            response.extend_from_slice(&external_token());
            response.extend_from_slice(b"\r\nBEGIN\r\nwire");
            client.write_all(&response).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            dispatch(&mut owner, &mut event_loop);
            assert_eq!(event_loop.run_once(0), Ok(true));
            let outcome = dispatch(&mut owner, &mut event_loop);
            assert_eq!(outcome.authenticated, 1);
            assert_eq!(owner.registered_connection_count(), 0);
            assert_eq!(owner.authenticated_connection_count(), 1);
            assert_eq!(event_loop.run_once(0), Ok(false));

            let mut ok = [0_u8; 37];
            client.read_exact(&mut ok).unwrap();
            assert_eq!(&ok[..3], b"OK ");
            let (_, connection) = owner.pop_authenticated().unwrap();
            assert_eq!(connection.authenticated().unwrap().buffered(), b"wire");
            assert_eq!(owner.listener().connection_count(), 0);

            drop((client, connection, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn closed_peer_is_unregistered_and_dropped() {
            let (path, mut event_loop, mut owner) = owner("close");
            let client = UnixStream::connect(&path).unwrap();
            event_loop.run_once(0).unwrap();
            dispatch(&mut owner, &mut event_loop);
            assert_eq!(owner.listener().connection_count(), 1);
            drop(client);

            assert_eq!(event_loop.run_once(0), Ok(true));
            let outcome = dispatch(&mut owner, &mut event_loop);
            assert_eq!(outcome.disconnected, 1);
            assert_eq!(owner.registered_connection_count(), 0);
            assert_eq!(owner.listener().connection_count(), 0);
            assert_eq!(event_loop.run_once(0), Ok(false));

            drop(owner);
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn server_id_failure_closes_the_accepted_peer_and_is_propagated() {
            let (path, mut event_loop, mut owner) = owner("server-id-failure");
            let mut client = UnixStream::connect(&path).unwrap();

            assert_eq!(event_loop.run_once(0), Ok(true));
            assert_eq!(
                owner.dispatch_ready(
                    &mut event_loop,
                    NonZeroUsize::new(1).unwrap(),
                    NonZeroUsize::new(1).unwrap(),
                    || Err(nix::errno::Errno::EIO),
                ),
                Err(PrivateBusEventSourceError::ServerIdGeneration(
                    nix::errno::Errno::EIO
                ))
            );
            assert_eq!(owner.listener().connection_count(), 0);
            assert_eq!(owner.registered_connection_count(), 0);
            assert_eq!(owner.authenticated_connection_count(), 0);

            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            assert_eq!(client.read(&mut [0_u8; 1]).unwrap(), 0);

            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn authentication_error_is_unregistered_without_disabling_listener() {
            let (path, mut event_loop, mut owner) = owner("bad-auth");
            let mut rejected = UnixStream::connect(&path).unwrap();
            event_loop.run_once(0).unwrap();
            dispatch(&mut owner, &mut event_loop);

            rejected.write_all(b"AUTH EXTERNAL\r\n").unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            let outcome = dispatch(&mut owner, &mut event_loop);
            assert_eq!(outcome.disconnected, 1);
            assert_eq!(owner.registered_connection_count(), 0);
            assert_eq!(owner.listener().connection_count(), 0);

            let replacement = UnixStream::connect(&path).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            assert_eq!(dispatch(&mut owner, &mut event_loop).accepted, 1);
            assert_eq!(owner.registered_connection_count(), 1);

            drop((rejected, replacement, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn accept_budget_bounds_each_outer_manager_turn() {
            let (path, mut event_loop, mut owner) = owner("budget");
            let first = UnixStream::connect(&path).unwrap();
            let second = UnixStream::connect(&path).unwrap();

            event_loop.run_once(0).unwrap();
            let outcome = owner
                .dispatch_ready(
                    &mut event_loop,
                    NonZeroUsize::new(1).unwrap(),
                    NonZeroUsize::new(1).unwrap(),
                    || Ok([0x31; 16]),
                )
                .unwrap();
            assert_eq!(outcome.accepted, 1);
            assert!(outcome.accept_budget_exhausted);
            assert_eq!(owner.listener().connection_count(), 1);

            assert_eq!(event_loop.run_once(0), Ok(true));
            let outcome = owner
                .dispatch_ready(
                    &mut event_loop,
                    NonZeroUsize::new(1).unwrap(),
                    NonZeroUsize::new(1).unwrap(),
                    || Ok([0x32; 16]),
                )
                .unwrap();
            assert_eq!(outcome.accepted, 1);
            assert_eq!(owner.listener().connection_count(), 2);

            drop((first, second, owner));
            std::fs::remove_file(path).unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::*;
