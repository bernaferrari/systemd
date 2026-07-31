// SPDX-License-Identifier: LGPL-2.1-or-later

//! Same-thread ownership boundary for PID 1's private D-Bus transport.
//!
//! [`PrivateBusEventSourceOwner`] owns a listener plus streams which are still
//! authenticating or waiting for handoff. This type adds the next ownership
//! stage: authenticated streams are promoted into explicitly tracked wire
//! slots. Each slot owns its kernel-authenticated stream, its bounded input
//! accumulator, and its bounded reply queue together. Consequently one
//! connection cap applies continuously while a stream moves from accept,
//! through authentication and handoff, into the future D-Bus wire dispatcher.
//!
//! There is deliberately no message decoding, manager callback, pathname
//! binding, or production PID 1 wiring here. A later wire implementation must
//! operate on the explicit slot APIs and close a slot through
//! `close_wire_slot()`; it must not take a stream out of this owner and evade
//! the global admission limit. This remains deliberately disconnected from
//! both `/run/systemd/private` and PID 1's live event loop.

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
    use crate::pid1_dbus_reply_queue::{
        PrivateBusReplyPollOutcome, PrivateBusReplyQueue, PrivateBusReplyQueueError,
    };
    use crate::pid1_dbus_wire::{
        MethodCall, PrivateBusWireAccumulator, PrivateBusWireAccumulatorError,
    };

    /// Explicit memory and reply bounds for one authenticated wire slot.
    ///
    /// Production integration must select these from its total private-bus
    /// resource policy rather than relying on an implicit transport default.
    /// No allocation is performed by this configuration value.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PrivateBusWireSlotConfig {
        input_capacity: usize,
        max_pending_replies: NonZeroUsize,
        reply_frame_capacity: usize,
        reply_outbound_capacity: usize,
    }

    impl PrivateBusWireSlotConfig {
        /// Create bounds which will be checked again when a concrete
        /// authenticated handoff is promoted. The latter check accounts for
        /// binary bytes pipelined immediately after D-Bus `BEGIN`.
        pub const fn new(
            input_capacity: usize,
            max_pending_replies: NonZeroUsize,
            reply_frame_capacity: usize,
            reply_outbound_capacity: usize,
        ) -> Self {
            Self {
                input_capacity,
                max_pending_replies,
                reply_frame_capacity,
                reply_outbound_capacity,
            }
        }

        pub const fn input_capacity(self) -> usize {
            self.input_capacity
        }

        pub const fn max_pending_replies(self) -> NonZeroUsize {
            self.max_pending_replies
        }

        pub const fn reply_frame_capacity(self) -> usize {
            self.reply_frame_capacity
        }

        pub const fn reply_outbound_capacity(self) -> usize {
            self.reply_outbound_capacity
        }
    }

    /// Non-I/O readiness observed for one retained wire slot.
    ///
    /// `read_budget == 0` is intentional backpressure: the dispatcher must
    /// consume the complete first method call before attempting another stream
    /// read. `reply_write_pending` only describes already-polled manager
    /// replies; callers must periodically call [`PrivateBusWireSlot::poll_replies`]
    /// with their own bounded work budget.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PrivateBusWireSlotReadiness {
        pub read_budget: usize,
        pub reply_write_pending: bool,
        pub can_track_reply: bool,
        pub terminal: bool,
    }

    /// Failure while constructing or operating the ownership state of one
    /// authenticated private-bus connection.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PrivateBusWireSlotError {
        /// An event-source invariant was violated: only a completed D-Bus
        /// authentication handoff may be promoted to a wire slot.
        UnauthenticatedHandoff,
        Input(PrivateBusWireAccumulatorError),
        Reply(PrivateBusReplyQueueError),
    }

    impl From<PrivateBusWireAccumulatorError> for PrivateBusWireSlotError {
        fn from(error: PrivateBusWireAccumulatorError) -> Self {
            Self::Input(error)
        }
    }

    impl From<PrivateBusReplyQueueError> for PrivateBusWireSlotError {
        fn from(error: PrivateBusReplyQueueError) -> Self {
            Self::Reply(error)
        }
    }

    /// All non-event-loop state that must live and die with one authenticated
    /// private-bus peer.
    ///
    /// The raw stream never leaves this slot. It may be borrowed through
    /// [`Self::connection_mut`] for a future nonblocking read/write callback,
    /// while the accumulator and reply queue retain the associated protocol
    /// state and its resource bounds.
    pub struct PrivateBusWireSlot {
        connection: AdmittedPrivateBusConnection,
        input: PrivateBusWireAccumulator,
        replies: PrivateBusReplyQueue,
    }

    impl PrivateBusWireSlot {
        fn from_authenticated(
            connection: AdmittedPrivateBusConnection,
            config: PrivateBusWireSlotConfig,
        ) -> Result<Self, PrivateBusWireSlotError> {
            let buffered = connection
                .authenticated()
                .ok_or(PrivateBusWireSlotError::UnauthenticatedHandoff)?
                .buffered();
            let input = PrivateBusWireAccumulator::from_buffered(config.input_capacity, buffered)?;
            let replies = PrivateBusReplyQueue::new(
                config.max_pending_replies,
                config.reply_frame_capacity,
                config.reply_outbound_capacity,
            )?;
            Ok(Self {
                connection,
                input,
                replies,
            })
        }

        pub fn connection(&self) -> &AdmittedPrivateBusConnection {
            &self.connection
        }

        /// Borrow only the still-owned socket connection for a future
        /// nonblocking I/O callback. The slot's identity, input, and replies
        /// remain retained by this transport.
        pub fn connection_mut(&mut self) -> &mut AdmittedPrivateBusConnection {
            &mut self.connection
        }

        pub const fn input(&self) -> &PrivateBusWireAccumulator {
            &self.input
        }

        pub fn input_mut(&mut self) -> &mut PrivateBusWireAccumulator {
            &mut self.input
        }

        pub const fn replies(&self) -> &PrivateBusReplyQueue {
            &self.replies
        }

        pub fn replies_mut(&mut self) -> &mut PrivateBusReplyQueue {
            &mut self.replies
        }

        /// Return the exact number of input bytes a callback may retain now.
        /// A zero result is input backpressure, not EOF.
        pub fn read_budget(&self) -> Result<usize, PrivateBusWireSlotError> {
            self.input.read_budget().map_err(Into::into)
        }

        /// Retain one checked bounded read from this peer.
        pub fn receive(&mut self, input: &[u8]) -> Result<(), PrivateBusWireSlotError> {
            self.input.receive(input).map_err(Into::into)
        }

        /// Decode and remove one complete request, leaving following
        /// pipelined bytes retained for a later bounded dispatch turn.
        pub fn take_next_method_call(
            &mut self,
        ) -> Result<Option<MethodCall>, PrivateBusWireSlotError> {
            self.input.take_next_method_call().map_err(Into::into)
        }

        /// Poll a bounded number of accepted manager operations and enqueue
        /// their completed replies without performing stream I/O.
        pub fn poll_replies(
            &mut self,
            budget: NonZeroUsize,
        ) -> Result<PrivateBusReplyPollOutcome, PrivateBusWireSlotError> {
            self.replies.poll_completed(budget).map_err(Into::into)
        }

        /// Bytes of the first completed response which a nonblocking writer
        /// may attempt. The callback must report its exact successful count
        /// through [`Self::acknowledge_reply_written`].
        pub fn current_reply_frame(&self) -> Option<&[u8]> {
            self.replies.current_frame()
        }

        pub fn acknowledge_reply_written(
            &mut self,
            written: usize,
        ) -> Result<bool, PrivateBusWireSlotError> {
            self.replies
                .acknowledge_written(written)
                .map_err(Into::into)
        }

        pub fn readiness(&self) -> Result<PrivateBusWireSlotReadiness, PrivateBusWireSlotError> {
            Ok(PrivateBusWireSlotReadiness {
                read_budget: self.read_budget()?,
                reply_write_pending: self.current_reply_frame().is_some(),
                can_track_reply: self.replies.can_track_reply(),
                terminal: self.replies.is_terminal(),
            })
        }

        /// Explicit disconnect/reexec/reload teardown. Dropping pending
        /// one-shot receivers cancels replies which cannot be delivered to
        /// this peer; clearing the input removes every peer-controlled byte.
        fn clear(&mut self) {
            self.replies.clear();
            self.input = PrivateBusWireAccumulator::new(self.input.capacity())
                .expect("an existing accumulator capacity remains valid");
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PrivateBusTransportError {
        EventSource(PrivateBusEventSourceError),
        WireSlot(PrivateBusWireSlotError),
        UnknownWireSlot(PrivateBusConnectionId),
        InconsistentOwnership,
    }

    impl From<PrivateBusEventSourceError> for PrivateBusTransportError {
        fn from(error: PrivateBusEventSourceError) -> Self {
            Self::EventSource(error)
        }
    }

    impl From<PrivateBusWireSlotError> for PrivateBusTransportError {
        fn from(error: PrivateBusWireSlotError) -> Self {
            Self::WireSlot(error)
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
        wire_slots: BTreeMap<PrivateBusConnectionId, PrivateBusWireSlot>,
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
            self.wire_slots.get(&id).map(PrivateBusWireSlot::connection)
        }

        /// Borrow a wire slot for future nonblocking D-Bus decoding.
        ///
        /// The stream stays owned by this transport while borrowed, retaining
        /// both its kernel-derived identity and its place in the global cap.
        pub fn wire_connection_mut(
            &mut self,
            id: PrivateBusConnectionId,
        ) -> Option<&mut AdmittedPrivateBusConnection> {
            self.wire_slots
                .get_mut(&id)
                .map(PrivateBusWireSlot::connection_mut)
        }

        /// Protocol state retained with the authenticated stream. Future
        /// event-loop integration uses this instead of owning separate input
        /// and reply maps keyed by a peer-controlled descriptor.
        pub fn wire_slot(&self, id: PrivateBusConnectionId) -> Option<&PrivateBusWireSlot> {
            self.wire_slots.get(&id)
        }

        pub fn wire_slot_mut(
            &mut self,
            id: PrivateBusConnectionId,
        ) -> Option<&mut PrivateBusWireSlot> {
            self.wire_slots.get_mut(&id)
        }

        /// Query input/reply readiness without doing stream I/O. An input
        /// `read_budget` of zero is explicit D-Bus frame backpressure.
        pub fn wire_slot_readiness(
            &self,
            id: PrivateBusConnectionId,
        ) -> Result<PrivateBusWireSlotReadiness, PrivateBusTransportError> {
            self.wire_slots
                .get(&id)
                .ok_or(PrivateBusTransportError::UnknownWireSlot(id))?
                .readiness()
                .map_err(Into::into)
        }

        /// Poll manager reply receivers for one slot with a finite per-turn
        /// budget. This does not write the socket or weaken authorization.
        pub fn poll_wire_slot_replies(
            &mut self,
            id: PrivateBusConnectionId,
            budget: NonZeroUsize,
        ) -> Result<PrivateBusReplyPollOutcome, PrivateBusTransportError> {
            self.wire_slots
                .get_mut(&id)
                .ok_or(PrivateBusTransportError::UnknownWireSlot(id))?
                .poll_replies(budget)
                .map_err(Into::into)
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
            config: PrivateBusWireSlotConfig,
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
            // Configuration and post-BEGIN bytes are both bounded before the
            // stream becomes externally visible as a wire slot. On failure,
            // dropping the just-popped peer is deliberate fail-closed cleanup:
            // it cannot be safely reinserted into the authenticated queue.
            match self.wire_slots.entry(id) {
                std::collections::btree_map::Entry::Occupied(_) => {
                    // Keep the existing live slot intact if an ownership
                    // invariant is ever violated. The newly popped peer is
                    // dropped fail-closed below without replacing it.
                    Err(PrivateBusTransportError::InconsistentOwnership)
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let slot = PrivateBusWireSlot::from_authenticated(connection, config)?;
                    entry.insert(slot);
                    Ok(Some(id))
                }
            }
        }

        /// Close one future wire slot, freeing exactly one global admission
        /// slot for a later listener turn.
        pub fn close_wire_slot(&mut self, id: PrivateBusConnectionId) -> bool {
            let Some(mut slot) = self.wire_slots.remove(&id) else {
                return false;
            };
            slot.clear();
            true
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
            for slot in self.wire_slots.values_mut() {
                slot.clear();
            }
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
        use std::num::NonZeroUsize;
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::path::PathBuf;
        use std::time::{SystemTime, UNIX_EPOCH};

        use nix::unistd::geteuid;

        use super::*;
        use crate::pid1_dbus_wire::Endian;
        use crate::pid1_manager_commands::{
            AuthenticatedPeer, DenyAllPid1CommandAuthorizer, Pid1ManagerCommand, SenderIdentity,
            pid1_manager_command_channel,
        };

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

        fn wire_slot_config(input_capacity: usize) -> PrivateBusWireSlotConfig {
            PrivateBusWireSlotConfig::new(input_capacity, NonZeroUsize::new(2).unwrap(), 512, 1024)
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

            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(16))
                .unwrap()
                .unwrap();
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
        fn wire_slot_retains_input_replies_and_explicit_backpressure_state() {
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "slot-state", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff(&mut owner, &mut event_loop, &mut client);
            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(16))
                .unwrap()
                .unwrap();

            // The four bytes pipelined after BEGIN are retained by the slot,
            // so the exact nonblocking read allowance reflects them.
            assert_eq!(
                owner.wire_slot_readiness(wire_id).unwrap(),
                PrivateBusWireSlotReadiness {
                    read_budget: 12,
                    reply_write_pending: false,
                    can_track_reply: true,
                    terminal: false,
                }
            );

            let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
            let receiver = sender
                .try_send(
                    SenderIdentity::from_authenticated_peer(
                        AuthenticatedPeer::from_kernel_peer_credentials(1, 0, 0),
                    ),
                    Pid1ManagerCommand::ResetFailed {
                        name: "demo.service".into(),
                    },
                )
                .unwrap();
            let mut runtime = crate::runtime_manager::RuntimeManager::new();
            let mut authorizer = DenyAllPid1CommandAuthorizer;
            inbox.dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap());

            owner
                .wire_slot_mut(wire_id)
                .unwrap()
                .replies_mut()
                .track(Endian::Little, 17, false, receiver)
                .unwrap();
            assert_eq!(
                owner
                    .poll_wire_slot_replies(wire_id, NonZeroUsize::new(1).unwrap())
                    .unwrap()
                    .enqueued,
                1
            );
            let frame_len = owner
                .wire_slot(wire_id)
                .unwrap()
                .current_reply_frame()
                .unwrap()
                .len();
            assert!(
                owner
                    .wire_slot_readiness(wire_id)
                    .unwrap()
                    .reply_write_pending
            );
            assert!(
                owner
                    .wire_slot_mut(wire_id)
                    .unwrap()
                    .acknowledge_reply_written(frame_len)
                    .unwrap()
            );
            assert!(
                !owner
                    .wire_slot_readiness(wire_id)
                    .unwrap()
                    .reply_write_pending
            );

            assert!(owner.close_wire_slot(wire_id));
            assert_eq!(
                owner.wire_slot_readiness(wire_id),
                Err(PrivateBusTransportError::UnknownWireSlot(wire_id))
            );

            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn promotion_failures_drop_the_popped_peer_without_replacing_slots() {
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut first_owner) = owner(&mut event_loop, "slot-invalid-input", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff(&mut first_owner, &mut event_loop, &mut client);

            assert_eq!(
                first_owner.promote_authenticated_to_wire(PrivateBusWireSlotConfig::new(
                    15,
                    NonZeroUsize::new(1).unwrap(),
                    512,
                    512,
                )),
                Err(PrivateBusTransportError::WireSlot(
                    PrivateBusWireSlotError::Input(
                        PrivateBusWireAccumulatorError::InvalidCapacity { capacity: 15 }
                    )
                ))
            );
            assert_eq!(first_owner.retained_connection_count(), 0);
            assert_eq!(first_owner.wire_connection_count(), 0);

            drop((client, first_owner));
            std::fs::remove_file(path).unwrap();

            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut second_owner) = owner(&mut event_loop, "slot-invalid-output", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff(&mut second_owner, &mut event_loop, &mut client);
            assert_eq!(
                second_owner.promote_authenticated_to_wire(PrivateBusWireSlotConfig::new(
                    16,
                    NonZeroUsize::new(1).unwrap(),
                    512,
                    511,
                )),
                Err(PrivateBusTransportError::WireSlot(
                    PrivateBusWireSlotError::Reply(
                        PrivateBusReplyQueueError::OutboundCapacityTooSmall {
                            capacity: 511,
                            minimum_frame_capacity: 512,
                        }
                    )
                ))
            );
            assert_eq!(second_owner.retained_connection_count(), 0);
            assert_eq!(second_owner.wire_connection_count(), 0);

            drop((client, second_owner));
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
