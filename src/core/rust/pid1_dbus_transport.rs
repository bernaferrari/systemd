// SPDX-License-Identifier: LGPL-2.1-or-later

//! Same-thread ownership boundary for PID 1's private D-Bus transport.
//!
//! [`PrivateBusEventSourceOwner`] owns a listener plus streams which are still
//! authenticating or waiting for handoff. This type adds the next ownership
//! stage: authenticated streams are promoted into explicitly tracked wire
//! slots. Consequently one connection cap applies continuously while a stream
//! moves from accept, through authentication and handoff, into the future
//! D-Bus wire dispatcher.
//!
//! There is deliberately no message decoding, manager callback, pathname
//! binding, or production PID 1 wiring here. A later wire implementation must
//! operate on `wire_connection_mut()` and close its slot through
//! `close_wire_slot()`; it must not take a stream out of this owner and evade
//! the global admission limit.

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::BTreeMap;
    use std::num::NonZeroUsize;
    use std::rc::Rc;

    use systemd_event_loop_rs::loop_::EventLoop;

    use crate::pid1_dbus_event_source::{
        PrivateBusDispatchOutcome, PrivateBusEventSourceError, PrivateBusEventSourceOwner,
    };
    use crate::pid1_dbus_listener::{
        AdmittedPrivateBusConnection, PrivateBusConnectionId, PrivateBusListener,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PrivateBusTransportError {
        EventSource(PrivateBusEventSourceError),
        InconsistentOwnership,
    }

    impl From<PrivateBusEventSourceError> for PrivateBusTransportError {
        fn from(error: PrivateBusEventSourceError) -> Self {
            Self::EventSource(error)
        }
    }

    /// Owns every private-bus connection retained by the disconnected Rust
    /// transport, from authentication through the future wire stage.
    ///
    /// The `Rc` marker makes the manager-thread constraint explicit even if a
    /// later implementation changes one of the contained owners. `sd-bus`
    /// itself is attached and dispatched on this same manager event thread.
    pub struct PrivateBusTransportOwner {
        event_sources: PrivateBusEventSourceOwner,
        connection_limit: NonZeroUsize,
        wire_slots: BTreeMap<PrivateBusConnectionId, AdmittedPrivateBusConnection>,
        same_thread: Rc<()>,
    }

    impl PrivateBusTransportOwner {
        /// Register a private listener with an event loop and establish one
        /// cap which covers all subsequent ownership stages.
        ///
        /// If the adopted listener has a smaller local limit, it remains an
        /// additional defensive bound. A larger local listener limit cannot
        /// allow this transport to exceed `connection_limit`.
        pub fn register(
            event_loop: &mut EventLoop,
            listener: PrivateBusListener,
            connection_limit: NonZeroUsize,
        ) -> Result<Self, PrivateBusTransportError> {
            Ok(Self {
                event_sources: PrivateBusEventSourceOwner::register(event_loop, listener)?,
                connection_limit,
                wire_slots: BTreeMap::new(),
                same_thread: Rc::new(()),
            })
        }

        pub const fn connection_limit(&self) -> NonZeroUsize {
            self.connection_limit
        }

        /// Connections retained in every stage: authentication, handoff, and
        /// wire slots. This is the number enforced by `dispatch_ready()`.
        pub fn retained_connection_count(&self) -> usize {
            self.event_sources.retained_connection_count() + self.wire_slots.len()
        }

        pub fn authentication_connection_count(&self) -> usize {
            self.event_sources.registered_connection_count()
        }

        pub fn handoff_connection_count(&self) -> usize {
            self.event_sources.authenticated_connection_count()
        }

        pub fn wire_connection_count(&self) -> usize {
            self.wire_slots.len()
        }

        pub fn wire_connection(
            &self,
            id: PrivateBusConnectionId,
        ) -> Option<&AdmittedPrivateBusConnection> {
            self.wire_slots.get(&id)
        }

        /// Borrow a wire slot for future nonblocking D-Bus decoding.
        ///
        /// The stream stays owned by this transport while borrowed, retaining
        /// both its kernel-derived identity and its place in the global cap.
        pub fn wire_connection_mut(
            &mut self,
            id: PrivateBusConnectionId,
        ) -> Option<&mut AdmittedPrivateBusConnection> {
            self.wire_slots.get_mut(&id)
        }

        /// Advance accepted streams with bounded work while enforcing the
        /// global cap across authentication, handoff, and wire stages.
        pub fn dispatch_ready(
            &mut self,
            event_loop: &mut EventLoop,
            accept_budget: NonZeroUsize,
            authentication_budget: NonZeroUsize,
            server_id: impl FnMut() -> Result<[u8; 16], nix::errno::Errno>,
        ) -> Result<PrivateBusDispatchOutcome, PrivateBusTransportError> {
            let available_for_event_sources = self
                .connection_limit
                .get()
                .checked_sub(self.wire_slots.len())
                .ok_or(PrivateBusTransportError::InconsistentOwnership)?;

            if self.event_sources.retained_connection_count() > available_for_event_sources {
                return Err(PrivateBusTransportError::InconsistentOwnership);
            }

            self.event_sources
                .dispatch_ready_with_connection_limit(
                    event_loop,
                    accept_budget,
                    authentication_budget,
                    available_for_event_sources,
                    server_id,
                )
                .map_err(Into::into)
        }

        /// Move one complete, authenticated handoff into a retained wire slot.
        ///
        /// The global connection count is unchanged by this transfer. The
        /// method intentionally returns only an ID, not the stream, so future
        /// wire processing cannot accidentally release cap accounting.
        pub fn promote_authenticated_to_wire(
            &mut self,
        ) -> Result<Option<PrivateBusConnectionId>, PrivateBusTransportError> {
            if self.event_sources.authenticated_connection_count() == 0 {
                return Ok(None);
            }
            if self.retained_connection_count() > self.connection_limit.get() {
                return Err(PrivateBusTransportError::InconsistentOwnership);
            }

            let (id, connection) = self
                .event_sources
                .pop_authenticated()
                .ok_or(PrivateBusTransportError::InconsistentOwnership)?;
            if self.wire_slots.insert(id, connection).is_some() {
                return Err(PrivateBusTransportError::InconsistentOwnership);
            }
            Ok(Some(id))
        }

        /// Close one future wire slot, freeing exactly one global admission
        /// slot for a later listener turn.
        pub fn close_wire_slot(&mut self, id: PrivateBusConnectionId) -> bool {
            self.wire_slots.remove(&id).is_some()
        }

        /// Unregister every private-bus source and close all retained streams.
        ///
        /// This is the composite teardown operation a future manager reload,
        /// reexec, or shutdown path must call before dropping the transport.
        /// It leaves the event loop reusable for a later transport owner.
        pub fn unregister(
            &mut self,
            event_loop: &mut EventLoop,
        ) -> Result<(), PrivateBusTransportError> {
            self.wire_slots.clear();
            self.event_sources
                .unregister(event_loop)
                .map_err(Into::into)
        }
    }

    impl std::fmt::Debug for PrivateBusTransportOwner {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("PrivateBusTransportOwner")
                .field("connection_limit", &self.connection_limit)
                .field(
                    "retained_connection_count",
                    &self.retained_connection_count(),
                )
                .field(
                    "authentication_connection_count",
                    &self.authentication_connection_count(),
                )
                .field("handoff_connection_count", &self.handoff_connection_count())
                .field("wire_connection_count", &self.wire_connection_count())
                .field("same_thread_owners", &Rc::strong_count(&self.same_thread))
                .finish_non_exhaustive()
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io::{Read, Write};
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::path::PathBuf;
        use std::time::{SystemTime, UNIX_EPOCH};

        use nix::unistd::geteuid;

        use super::*;

        fn socket_path(name: &str) -> PathBuf {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            std::env::temp_dir().join(format!(
                "systemd-rust-private-bus-transport-{name}-{}-{stamp}.socket",
                std::process::id()
            ))
        }

        fn owner(
            event_loop: &mut EventLoop,
            name: &str,
            limit: usize,
        ) -> (PathBuf, PrivateBusTransportOwner) {
            let path = socket_path(name);
            let listener = UnixListener::bind(&path).unwrap();
            let listener =
                PrivateBusListener::from_bound_listener(listener, geteuid().as_raw()).unwrap();
            let owner = PrivateBusTransportOwner::register(
                event_loop,
                listener,
                NonZeroUsize::new(limit).unwrap(),
            )
            .unwrap();
            (path, owner)
        }

        fn dispatch(
            owner: &mut PrivateBusTransportOwner,
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

        fn authenticate_to_handoff(
            owner: &mut PrivateBusTransportOwner,
            event_loop: &mut EventLoop,
            client: &mut UnixStream,
        ) {
            event_loop.run_once(0).unwrap();
            assert_eq!(dispatch(owner, event_loop).accepted, 1);

            client.write_all(b"\0AUTH EXTERNAL\r\n").unwrap();
            event_loop.run_once(0).unwrap();
            dispatch(owner, event_loop);
            event_loop.run_once(0).unwrap();
            dispatch(owner, event_loop);
            let mut challenge = [0_u8; 6];
            client.read_exact(&mut challenge).unwrap();
            assert_eq!(&challenge, b"DATA\r\n");

            let mut response = b"DATA ".to_vec();
            response.extend_from_slice(&external_token());
            response.extend_from_slice(b"\r\nBEGIN\r\nwire");
            client.write_all(&response).unwrap();
            event_loop.run_once(0).unwrap();
            dispatch(owner, event_loop);
            event_loop.run_once(0).unwrap();
            assert_eq!(dispatch(owner, event_loop).authenticated, 1);
        }

        #[test]
        fn tiny_global_cap_covers_wire_slots_before_the_next_accept() {
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "global-cap", 1);
            let mut first = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff(&mut owner, &mut event_loop, &mut first);

            let wire_id = owner.promote_authenticated_to_wire().unwrap().unwrap();
            assert_eq!(owner.retained_connection_count(), 1);
            assert_eq!(owner.wire_connection_count(), 1);
            assert_eq!(
                owner
                    .wire_connection(wire_id)
                    .unwrap()
                    .authenticated()
                    .unwrap()
                    .buffered(),
                b"wire"
            );

            let second = UnixStream::connect(&path).unwrap();
            event_loop.run_once(0).unwrap();
            let outcome = dispatch(&mut owner, &mut event_loop);
            assert_eq!(outcome.accepted, 0);
            assert!(outcome.connection_limit_reached);
            assert_eq!(owner.retained_connection_count(), 1);

            assert!(owner.close_wire_slot(wire_id));
            assert_eq!(event_loop.run_once(0), Ok(true));
            assert_eq!(dispatch(&mut owner, &mut event_loop).accepted, 1);
            assert_eq!(owner.retained_connection_count(), 1);

            drop((first, second, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn server_id_failure_is_propagated_without_retaining_a_stream() {
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "server-id-failure", 1);
            let client = UnixStream::connect(&path).unwrap();

            assert_eq!(event_loop.run_once(0), Ok(true));
            assert_eq!(
                owner.dispatch_ready(
                    &mut event_loop,
                    NonZeroUsize::new(1).unwrap(),
                    NonZeroUsize::new(1).unwrap(),
                    || Err(nix::errno::Errno::EIO),
                ),
                Err(PrivateBusTransportError::EventSource(
                    PrivateBusEventSourceError::ServerIdGeneration(nix::errno::Errno::EIO)
                ))
            );
            assert_eq!(owner.retained_connection_count(), 0);
            assert_eq!(owner.authentication_connection_count(), 0);
            assert_eq!(owner.handoff_connection_count(), 0);
            assert_eq!(owner.wire_connection_count(), 0);

            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn explicit_teardown_releases_sources_for_a_new_owner() {
            let mut event_loop = EventLoop::new().unwrap();
            let (first_path, mut first_owner) = owner(&mut event_loop, "teardown-first", 1);
            let first_client = UnixStream::connect(&first_path).unwrap();
            event_loop.run_once(0).unwrap();
            assert_eq!(dispatch(&mut first_owner, &mut event_loop).accepted, 1);
            assert_eq!(first_owner.retained_connection_count(), 1);

            first_owner.unregister(&mut event_loop).unwrap();
            assert_eq!(first_owner.retained_connection_count(), 0);
            assert_eq!(event_loop.run_once(0), Ok(false));
            drop((first_client, first_owner));
            std::fs::remove_file(first_path).unwrap();

            let (second_path, mut second_owner) = owner(&mut event_loop, "teardown-second", 1);
            let second_client = UnixStream::connect(&second_path).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            assert_eq!(dispatch(&mut second_owner, &mut event_loop).accepted, 1);

            drop((second_client, second_owner));
            std::fs::remove_file(second_path).unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::*;
