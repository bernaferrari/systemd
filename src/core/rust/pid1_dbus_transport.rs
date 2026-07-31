// SPDX-License-Identifier: LGPL-2.1-or-later

//! Same-thread ownership boundary for PID 1's private D-Bus transport.
// PORT-SYNC: src/core/dbus.c (the `bus_on_connection()` private-bus lifecycle).
//!
//! [`PrivateBusEventSourceOwner`] owns a listener plus streams which are still
//! authenticating or waiting for handoff. This type adds the next ownership
//! stage: authenticated streams are promoted into explicitly tracked wire
//! slots. Each slot owns its kernel-authenticated stream, its bounded input
//! accumulator, and its bounded reply queue together. Consequently one
//! connection cap applies continuously while a stream moves from accept,
//! through authentication and handoff, into the future D-Bus wire dispatcher.
//!
//! A slot can perform one bounded decode/command/reply handoff through
//! [`PrivateBusWireSlot::dispatch_one`]. It remains deliberately disconnected
//! from pathname binding and the production PID 1 loop: a future lifecycle
//! owner must still provide socket I/O, event-source registration, complete
//! D-Bus error/vtable semantics, and teardown around that checked turn.

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::num::NonZeroUsize;
    use std::rc::Rc;

    use nix::errno::Errno;
    use systemd_event_loop_rs::loop_::EventLoop;

    use crate::pid1_bus_source::Pid1BusSendError;
    use crate::pid1_dbus_command_adapter::{Pid1DbusCommandAdapter, Pid1DbusCommandAdapterError};
    use crate::pid1_dbus_event_source::{
        PrivateBusDispatchOutcome, PrivateBusEventSourceError, PrivateBusEventSourceOwner,
    };
    use crate::pid1_dbus_listener::{
        AdmittedPrivateBusConnection, PrivateBusConnectionId, PrivateBusListener,
    };
    use crate::pid1_dbus_reply_adapter::Pid1DbusProtocolError;
    use crate::pid1_dbus_reply_queue::{
        PrivateBusReplyPollOutcome, PrivateBusReplyQueue, PrivateBusReplyQueueError,
        PrivateBusReplyTracking,
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
        /// The slot has failed closed and must be detached before any more
        /// protocol state is accessed.
        Terminal,
        Io(Errno),
        Input(PrivateBusWireAccumulatorError),
        Reply(PrivateBusReplyQueueError),
    }

    /// Progress from one bounded nonblocking read on an authenticated slot.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PrivateBusWireReadOutcome {
        /// A complete first frame is already buffered and must be dispatched
        /// before another byte may be retained.
        Backpressured,
        WouldBlock,
        Read {
            bytes: usize,
        },
        PeerClosed,
    }

    /// Progress from one bounded nonblocking write of the current reply frame.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PrivateBusWireWriteOutcome {
        Idle,
        WouldBlock,
        Written { bytes: usize, frame_complete: bool },
        PeerClosed,
    }

    /// One bounded private-bus wire-dispatch result.
    ///
    /// A successful submission owns either a pending reply receiver or the
    /// explicit `NO_REPLY_EXPECTED` disposition. `RejectedNoReply` is limited
    /// to invalid/unavailable calls which explicitly requested no reply; no
    /// manager command was accepted in that case.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PrivateBusWireDispatchOutcome {
        /// The first buffered frame is incomplete, so no manager work was
        /// submitted and the caller may wait for a later readable event.
        NoMessage,
        /// Exactly one validated manager command was submitted.
        Submitted { reply: PrivateBusReplyTracking },
        /// An invalid or unavailable no-reply call was discarded. Its error
        /// is retained for logging/metrics, but the peer requested that no
        /// protocol response be sent.
        RejectedNoReply { cause: Pid1DbusCommandAdapterError },
        /// A decoded request was rejected before manager work was accepted,
        /// and a bounded typed D-Bus error frame was retained for this peer.
        /// This is intentionally not a claim of full sd-bus/vtable parity.
        RejectedWithError { error: Pid1DbusProtocolError },
    }

    /// Failure in a dispatch turn which cannot safely be represented by the
    /// current deliberately narrow reply surface.
    ///
    /// The slot marks itself terminal before returning any of these errors.
    /// A future complete D-Bus server may replace selected cases with a
    /// protocol error frame, but it must never submit a reply-producing
    /// command until it can retain the response correlation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PrivateBusWireDispatchError {
        Terminal,
        Input(PrivateBusWireAccumulatorError),
        Adapter(Pid1DbusCommandAdapterError),
        ReplyReservation {
            reply_serial: u32,
            cause: PrivateBusReplyQueueError,
        },
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
        id: PrivateBusConnectionId,
        connection: AdmittedPrivateBusConnection,
        input: PrivateBusWireAccumulator,
        replies: PrivateBusReplyQueue,
        dispatch_terminal: bool,
    }

    impl PrivateBusWireSlot {
        fn from_authenticated(
            id: PrivateBusConnectionId,
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
                id,
                connection,
                input,
                replies,
                dispatch_terminal: false,
            })
        }

        /// The transport-assigned identity which stays bound to this slot for
        /// its entire authenticated wire lifetime. Event-source ownership must
        /// use this exact value; callers may not supply an unrelated key.
        pub const fn id(&self) -> PrivateBusConnectionId {
            self.id
        }

        pub fn connection(&self) -> &AdmittedPrivateBusConnection {
            &self.connection
        }

        /// Borrow only the still-owned socket connection for a future
        /// nonblocking I/O callback. The slot's identity, input, and replies
        /// remain retained by this transport.
        pub(crate) fn connection_mut(&mut self) -> &mut AdmittedPrivateBusConnection {
            &mut self.connection
        }

        pub const fn input(&self) -> &PrivateBusWireAccumulator {
            &self.input
        }

        pub(crate) fn input_mut(&mut self) -> &mut PrivateBusWireAccumulator {
            &mut self.input
        }

        pub const fn replies(&self) -> &PrivateBusReplyQueue {
            &self.replies
        }

        pub(crate) fn replies_mut(&mut self) -> &mut PrivateBusReplyQueue {
            &mut self.replies
        }

        /// Return the exact number of input bytes a callback may retain now.
        /// A zero result is input backpressure, not EOF.
        pub fn read_budget(&self) -> Result<usize, PrivateBusWireSlotError> {
            if self.is_terminal() {
                return Err(PrivateBusWireSlotError::Terminal);
            }
            self.input.read_budget().map_err(Into::into)
        }

        /// Retain one checked bounded read from this peer.
        pub fn receive(&mut self, input: &[u8]) -> Result<(), PrivateBusWireSlotError> {
            if self.is_terminal() {
                return Err(PrivateBusWireSlotError::Terminal);
            }
            self.input.receive(input).map_err(Into::into)
        }

        /// Read at most one bounded chunk from the nonblocking peer stream.
        ///
        /// The accumulator's current-frame allowance and strict total cap are
        /// applied before the syscall. Before a complete primary header is
        /// known, a peer may pipeline following bytes only within that fixed
        /// cap; once known, the read stops exactly at the first frame. EOF and
        /// fatal I/O/framing failures mark the slot terminal; the lifecycle
        /// owner must then detach its event source and close it.
        pub fn read_from_stream_once(
            &mut self,
        ) -> Result<PrivateBusWireReadOutcome, PrivateBusWireSlotError> {
            const READ_CHUNK: usize = 8 * 1024;

            if self.is_terminal() {
                return Err(PrivateBusWireSlotError::Terminal);
            }
            let budget = match self.input.read_budget() {
                Ok(0) => return Ok(PrivateBusWireReadOutcome::Backpressured),
                Ok(budget) => budget,
                Err(error) => return self.slot_failure(PrivateBusWireSlotError::Input(error)),
            };
            let mut bytes = [0_u8; READ_CHUNK];
            let mut stream = self.connection.stream();
            match stream.read(&mut bytes[..budget.min(READ_CHUNK)]) {
                Ok(0) => {
                    self.dispatch_terminal = true;
                    Ok(PrivateBusWireReadOutcome::PeerClosed)
                }
                Ok(read) => {
                    if let Err(error) = self.input.receive(&bytes[..read]) {
                        return self.slot_failure(PrivateBusWireSlotError::Input(error));
                    }
                    Ok(PrivateBusWireReadOutcome::Read { bytes: read })
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    Ok(PrivateBusWireReadOutcome::WouldBlock)
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    Ok(PrivateBusWireReadOutcome::WouldBlock)
                }
                Err(error) => self.slot_failure(PrivateBusWireSlotError::Io(io_errno(&error))),
            }
        }

        /// Decode and remove one complete request, leaving following
        /// pipelined bytes retained for a later bounded dispatch turn.
        pub fn take_next_method_call(
            &mut self,
        ) -> Result<Option<MethodCall>, PrivateBusWireSlotError> {
            if self.is_terminal() {
                return Err(PrivateBusWireSlotError::Terminal);
            }
            self.input.take_next_method_call().map_err(Into::into)
        }

        /// Decode and submit at most one complete request from this slot.
        ///
        /// The command's identity comes only from the peer credentials
        /// retained with the accepted socket. For reply-producing calls, the
        /// bounded correlation slot is checked *before* submitting manager
        /// work. If any later boundary fails, this connection becomes
        /// terminal rather than accepting a command whose result could not be
        /// delivered safely. Callers must close it through
        /// [`PrivateBusTransportOwner::close_wire_slot`].
        ///
        /// This does not read or write a socket. A future event-loop owner
        /// performs bounded I/O, invokes this turn from readable readiness,
        /// polls replies, and writes current reply frames separately.
        pub fn dispatch_one(
            &mut self,
            adapter: &Pid1DbusCommandAdapter,
        ) -> Result<PrivateBusWireDispatchOutcome, PrivateBusWireDispatchError> {
            if self.is_terminal() {
                return Err(PrivateBusWireDispatchError::Terminal);
            }

            let call = match self.input.take_next_method_call() {
                Ok(Some(call)) => call,
                Ok(None) => return Ok(PrivateBusWireDispatchOutcome::NoMessage),
                Err(error) => {
                    return self.dispatch_failure(PrivateBusWireDispatchError::Input(error));
                }
            };
            let no_reply_expected = call.no_reply_expected();
            let command = match Pid1DbusCommandAdapter::command_for(&call) {
                Ok(command) => command,
                Err(cause) if no_reply_expected => {
                    return Ok(PrivateBusWireDispatchOutcome::RejectedNoReply { cause });
                }
                Err(cause) => {
                    let error = protocol_error_for_adapter(&cause);
                    return self
                        .replies
                        .enqueue_protocol_error(call.endian, call.serial, error)
                        .map(|()| PrivateBusWireDispatchOutcome::RejectedWithError { error })
                        .map_err(PrivateBusWireDispatchError::Reply)
                        .or_else(|error| self.dispatch_failure(error));
                }
            };

            let reservation = if no_reply_expected {
                None
            } else {
                Some(self.replies.reserve_reply(call.serial).map_err(|cause| {
                    PrivateBusWireDispatchError::ReplyReservation {
                        reply_serial: call.serial,
                        cause,
                    }
                })?)
            };

            let receiver = match adapter.try_send_command(
                crate::pid1_manager_commands::SenderIdentity::from_authenticated_peer(
                    self.connection.peer(),
                ),
                command,
            ) {
                Ok(receiver) => receiver,
                Err(cause) if no_reply_expected => {
                    // A bounded inbox-full rejection is safe to discard for
                    // a no-reply call. Wake accounting failure or a closed
                    // manager, however, means this slot can no longer trust
                    // the command handoff lifecycle and must be detached.
                    let terminal = matches!(
                        &cause,
                        Pid1DbusCommandAdapterError::Ingress(
                            Pid1BusSendError::Wake(_)
                                | Pid1BusSendError::Command(
                                    crate::pid1_manager_commands::Pid1CommandError::InboxClosed,
                                ),
                        )
                    );
                    if terminal {
                        return self.dispatch_failure(PrivateBusWireDispatchError::Adapter(cause));
                    }
                    return Ok(PrivateBusWireDispatchOutcome::RejectedNoReply { cause });
                }
                Err(cause) => {
                    if let Some(reservation) = reservation {
                        self.replies.cancel_reply(reservation);
                    }
                    let error = protocol_error_for_adapter(&cause);
                    return self
                        .replies
                        .enqueue_protocol_error(call.endian, call.serial, error)
                        .map(|()| PrivateBusWireDispatchOutcome::RejectedWithError { error })
                        .map_err(PrivateBusWireDispatchError::Reply)
                        .or_else(|error| self.dispatch_failure(error));
                }
            };

            let reply = match reservation {
                Some(reservation) => self
                    .replies
                    .commit_reply(reservation, call.endian, receiver),
                None => {
                    drop(receiver);
                    Ok(PrivateBusReplyTracking::NoReplyExpected)
                }
            };
            match reply {
                Ok(reply) => Ok(PrivateBusWireDispatchOutcome::Submitted { reply }),
                Err(error) => self.dispatch_failure(PrivateBusWireDispatchError::Reply(error)),
            }
        }

        /// Poll a bounded number of accepted manager operations and enqueue
        /// their completed replies without performing stream I/O.
        pub fn poll_replies(
            &mut self,
            budget: NonZeroUsize,
        ) -> Result<PrivateBusReplyPollOutcome, PrivateBusWireSlotError> {
            if self.is_terminal() {
                return Err(PrivateBusWireSlotError::Terminal);
            }
            self.replies.poll_completed(budget).map_err(Into::into)
        }

        /// Bytes of the first completed response which a nonblocking writer
        /// may attempt. The callback must report its exact successful count
        /// through [`Self::acknowledge_reply_written`].
        pub fn current_reply_frame(&self) -> Option<&[u8]> {
            if self.is_terminal() {
                return None;
            }
            self.replies.current_frame()
        }

        pub fn acknowledge_reply_written(
            &mut self,
            written: usize,
        ) -> Result<bool, PrivateBusWireSlotError> {
            if self.is_terminal() {
                return Err(PrivateBusWireSlotError::Terminal);
            }
            self.replies
                .acknowledge_written(written)
                .map_err(Into::into)
        }

        /// Write at most one nonblocking chunk from the current reply frame.
        ///
        /// Reply ownership remains in the queue until the exact successful
        /// byte count is acknowledged. This means `WouldBlock`, short writes,
        /// and disconnects cannot lose correlation or duplicate bytes.
        pub fn write_reply_to_stream_once(
            &mut self,
        ) -> Result<PrivateBusWireWriteOutcome, PrivateBusWireSlotError> {
            if self.is_terminal() {
                return Err(PrivateBusWireSlotError::Terminal);
            }
            let Some(frame) = self.replies.current_frame() else {
                return Ok(PrivateBusWireWriteOutcome::Idle);
            };
            let mut stream = self.connection.stream();
            let result = stream.write(frame);
            self.finish_reply_write(result)
        }

        #[cfg(test)]
        fn write_reply_with(
            &mut self,
            writer: impl FnOnce(&[u8]) -> std::io::Result<usize>,
        ) -> Result<PrivateBusWireWriteOutcome, PrivateBusWireSlotError> {
            if self.is_terminal() {
                return Err(PrivateBusWireSlotError::Terminal);
            }
            let Some(frame) = self.replies.current_frame() else {
                return Ok(PrivateBusWireWriteOutcome::Idle);
            };
            let result = writer(frame);
            self.finish_reply_write(result)
        }

        fn finish_reply_write(
            &mut self,
            result: std::io::Result<usize>,
        ) -> Result<PrivateBusWireWriteOutcome, PrivateBusWireSlotError> {
            match result {
                Ok(0) => {
                    self.dispatch_terminal = true;
                    Ok(PrivateBusWireWriteOutcome::PeerClosed)
                }
                Ok(written) => {
                    let frame_complete = match self.replies.acknowledge_written(written) {
                        Ok(complete) => complete,
                        Err(error) => {
                            return self.slot_failure(PrivateBusWireSlotError::Reply(error));
                        }
                    };
                    Ok(PrivateBusWireWriteOutcome::Written {
                        bytes: written,
                        frame_complete,
                    })
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    Ok(PrivateBusWireWriteOutcome::WouldBlock)
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    Ok(PrivateBusWireWriteOutcome::WouldBlock)
                }
                Err(error) => self.slot_failure(PrivateBusWireSlotError::Io(io_errno(&error))),
            }
        }

        pub fn readiness(&self) -> Result<PrivateBusWireSlotReadiness, PrivateBusWireSlotError> {
            if self.is_terminal() {
                return Ok(PrivateBusWireSlotReadiness {
                    read_budget: 0,
                    reply_write_pending: false,
                    can_track_reply: false,
                    terminal: true,
                });
            }
            Ok(PrivateBusWireSlotReadiness {
                read_budget: self.read_budget()?,
                reply_write_pending: self.current_reply_frame().is_some(),
                can_track_reply: self.replies.can_track_reply(),
                terminal: self.is_terminal(),
            })
        }

        /// A terminal slot must only be detached. This includes reply-queue
        /// terminal state and failures detected during a checked dispatch
        /// turn before a protocol error surface is available.
        pub const fn is_terminal(&self) -> bool {
            self.dispatch_terminal || self.replies.is_terminal()
        }

        fn dispatch_failure<T>(
            &mut self,
            error: PrivateBusWireDispatchError,
        ) -> Result<T, PrivateBusWireDispatchError> {
            self.dispatch_terminal = true;
            Err(error)
        }

        fn slot_failure<T>(
            &mut self,
            error: PrivateBusWireSlotError,
        ) -> Result<T, PrivateBusWireSlotError> {
            self.dispatch_terminal = true;
            Err(error)
        }

        /// Explicit disconnect/reexec/reload teardown. Dropping pending
        /// one-shot receivers cancels replies which cannot be delivered to
        /// this peer; clearing the input removes every peer-controlled byte.
        fn clear(&mut self) {
            self.replies.clear();
            self.input = PrivateBusWireAccumulator::new(self.input.capacity())
                .expect("an existing accumulator capacity remains valid");
            self.dispatch_terminal = false;
        }
    }

    fn protocol_error_for_adapter(error: &Pid1DbusCommandAdapterError) -> Pid1DbusProtocolError {
        match error {
            Pid1DbusCommandAdapterError::WrongPath { .. } => Pid1DbusProtocolError::UnknownObject,
            Pid1DbusCommandAdapterError::WrongInterface { .. } => {
                Pid1DbusProtocolError::UnknownInterface
            }
            Pid1DbusCommandAdapterError::UnsupportedMember { .. } => {
                Pid1DbusProtocolError::UnknownMethod
            }
            Pid1DbusCommandAdapterError::WrongSignature { .. }
            | Pid1DbusCommandAdapterError::InvalidPayload { .. }
            | Pid1DbusCommandAdapterError::InvalidJobMode { .. }
            | Pid1DbusCommandAdapterError::UnsupportedJobMode { .. } => {
                Pid1DbusProtocolError::InvalidArgs
            }
            Pid1DbusCommandAdapterError::Ingress(Pid1BusSendError::Command(
                crate::pid1_manager_commands::Pid1CommandError::InboxFull,
            )) => Pid1DbusProtocolError::LimitsExceeded,
            Pid1DbusCommandAdapterError::Ingress(Pid1BusSendError::Command(
                crate::pid1_manager_commands::Pid1CommandError::InboxClosed,
            )) => Pid1DbusProtocolError::Disconnected,
            Pid1DbusCommandAdapterError::Ingress(
                Pid1BusSendError::Wake(_)
                | Pid1BusSendError::Command(
                    crate::pid1_manager_commands::Pid1CommandError::Unauthorized
                    | crate::pid1_manager_commands::Pid1CommandError::NoSuchUnit { .. }
                    | crate::pid1_manager_commands::Pid1CommandError::NoUnitForPid { .. }
                    | crate::pid1_manager_commands::Pid1CommandError::NoUnitForInvocationId {
                        ..
                    }
                    | crate::pid1_manager_commands::Pid1CommandError::NoUnitForCallerPid { .. }
                    | crate::pid1_manager_commands::Pid1CommandError::Runtime(_),
                ),
            ) => Pid1DbusProtocolError::Failed,
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PrivateBusTransportError {
        EventSource(PrivateBusEventSourceError),
        WireSlot(PrivateBusWireSlotError),
        WireDispatch(PrivateBusWireDispatchError),
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

    impl From<PrivateBusWireDispatchError> for PrivateBusTransportError {
        fn from(error: PrivateBusWireDispatchError) -> Self {
            Self::WireDispatch(error)
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
        pub(crate) fn wire_connection_mut(
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

        pub(crate) fn wire_slot_mut(
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

        /// Run one bounded nonblocking socket read for a retained wire slot.
        pub fn read_wire_slot_once(
            &mut self,
            id: PrivateBusConnectionId,
        ) -> Result<PrivateBusWireReadOutcome, PrivateBusTransportError> {
            self.wire_slots
                .get_mut(&id)
                .ok_or(PrivateBusTransportError::UnknownWireSlot(id))?
                .read_from_stream_once()
                .map_err(Into::into)
        }

        /// Run one bounded nonblocking reply write for a retained wire slot.
        pub fn write_wire_slot_once(
            &mut self,
            id: PrivateBusConnectionId,
        ) -> Result<PrivateBusWireWriteOutcome, PrivateBusTransportError> {
            self.wire_slots
                .get_mut(&id)
                .ok_or(PrivateBusTransportError::UnknownWireSlot(id))?
                .write_reply_to_stream_once()
                .map_err(Into::into)
        }

        /// Return the first wire-slot ID strictly after `after`, or the first
        /// retained ID when `after` is `None`. This supports bounded
        /// allocation-free round-robin scans by the lifecycle owner.
        pub fn next_wire_slot_id(
            &self,
            after: Option<PrivateBusConnectionId>,
        ) -> Option<PrivateBusConnectionId> {
            use std::ops::Bound::{Excluded, Unbounded};

            match after {
                Some(id) => self
                    .wire_slots
                    .range((Excluded(id), Unbounded))
                    .next()
                    .map(|(&id, _)| id),
                None => self.wire_slots.keys().next().copied(),
            }
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

        /// Run one bounded decode/command/reply ownership turn for a retained
        /// slot. Socket I/O stays outside this method, but successful manager
        /// commands are already wake-aware through `adapter` and their reply
        /// receivers are retained by the same slot that owns the peer.
        pub fn dispatch_wire_slot_once(
            &mut self,
            id: PrivateBusConnectionId,
            adapter: &Pid1DbusCommandAdapter,
        ) -> Result<PrivateBusWireDispatchOutcome, PrivateBusTransportError> {
            self.wire_slots
                .get_mut(&id)
                .ok_or(PrivateBusTransportError::UnknownWireSlot(id))?
                .dispatch_one(adapter)
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
                    let slot = PrivateBusWireSlot::from_authenticated(id, connection, config)?;
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

    fn io_errno(error: &std::io::Error) -> Errno {
        Errno::from_raw(error.raw_os_error().unwrap_or(libc::EIO))
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
        use crate::pid1_bus_source::pid1_bus_command_channel;
        use crate::pid1_dbus_command_adapter::Pid1DbusCommandAdapter;
        use crate::pid1_dbus_wire::Endian;
        use crate::pid1_manager_commands::{
            AuthenticatedPeer, DenyAllPid1CommandAuthorizer, Pid1CommandAuthorizer,
            Pid1CommandError, Pid1ManagerCommand, SenderIdentity, pid1_manager_command_channel,
        };

        #[derive(Default)]
        struct CaptureAuthorizer {
            sender: Option<SenderIdentity>,
        }

        impl Pid1CommandAuthorizer for CaptureAuthorizer {
            fn authorize(
                &mut self,
                sender: SenderIdentity,
                _command: &Pid1ManagerCommand,
            ) -> Result<(), Pid1CommandError> {
                self.sender = Some(sender);
                Err(Pid1CommandError::Unauthorized)
            }
        }

        #[derive(Default)]
        struct AllowAuthorizer;

        impl Pid1CommandAuthorizer for AllowAuthorizer {
            fn authorize(
                &mut self,
                _sender: SenderIdentity,
                _command: &Pid1ManagerCommand,
            ) -> Result<(), Pid1CommandError> {
                Ok(())
            }
        }

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
            // The bounded Introspect reply is currently ~750 bytes. Keep the
            // fixture above that protocol minimum while preserving a small,
            // deterministic cap for malformed/oversized-frame tests below.
            PrivateBusWireSlotConfig::new(input_capacity, NonZeroUsize::new(2).unwrap(), 1024, 2048)
        }

        fn push_padding(bytes: &mut Vec<u8>, alignment: usize) {
            let padding = (alignment - bytes.len() % alignment) % alignment;
            bytes.resize(bytes.len() + padding, 0);
        }

        fn push_text(bytes: &mut Vec<u8>, value: &str, signature: bool) {
            if signature {
                bytes.push(u8::try_from(value.len()).unwrap());
            } else {
                push_padding(bytes, 4);
                bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
            }
            bytes.extend_from_slice(value.as_bytes());
            bytes.push(0);
        }

        fn push_header(fields: &mut Vec<u8>, code: u8, kind: u8, value: &str) {
            push_padding(fields, 8);
            fields.extend_from_slice(&[code, 1, kind, 0]);
            push_text(fields, value, kind == b'g');
        }

        fn interface_call_with_flags(
            serial: u32,
            flags: u8,
            interface: &str,
            member: &str,
            values: &[&str],
        ) -> Vec<u8> {
            let mut fields = Vec::new();
            push_header(&mut fields, 1, b'o', "/org/freedesktop/systemd1");
            push_header(&mut fields, 2, b's', interface);
            push_header(&mut fields, 3, b's', member);
            let signature = "s".repeat(values.len());
            if !signature.is_empty() {
                push_header(&mut fields, 8, b'g', &signature);
            }

            let mut body = Vec::new();
            for value in values {
                push_text(&mut body, value, false);
            }
            let mut output = vec![b'l', 1, flags, 1];
            output.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
            output.extend_from_slice(&serial.to_le_bytes());
            output.extend_from_slice(&u32::try_from(fields.len()).unwrap().to_le_bytes());
            output.extend_from_slice(&fields);
            push_padding(&mut output, 8);
            output.extend_from_slice(&body);
            output
        }

        fn manager_call_with_flags(
            serial: u32,
            flags: u8,
            member: &str,
            values: &[&str],
        ) -> Vec<u8> {
            interface_call_with_flags(
                serial,
                flags,
                "org.freedesktop.systemd1.Manager",
                member,
                values,
            )
        }

        fn manager_call(serial: u32, member: &str, values: &[&str]) -> Vec<u8> {
            manager_call_with_flags(serial, 0, member, values)
        }

        fn manager_pid_call(serial: u32, pid: u32) -> Vec<u8> {
            let mut fields = Vec::new();
            push_header(&mut fields, 1, b'o', "/org/freedesktop/systemd1");
            push_header(&mut fields, 2, b's', "org.freedesktop.systemd1.Manager");
            push_header(&mut fields, 3, b's', "GetUnitByPID");
            push_header(&mut fields, 8, b'g', "u");
            let body = pid.to_le_bytes();
            let mut output = vec![b'l', 1, 0, 1];
            output.extend_from_slice(&(body.len() as u32).to_le_bytes());
            output.extend_from_slice(&serial.to_le_bytes());
            output.extend_from_slice(&(fields.len() as u32).to_le_bytes());
            output.extend_from_slice(&fields);
            push_padding(&mut output, 8);
            output.extend_from_slice(&body);
            output
        }

        fn manager_invocation_id_call(serial: u32, invocation_id: [u8; 16]) -> Vec<u8> {
            let mut fields = Vec::new();
            push_header(&mut fields, 1, b'o', "/org/freedesktop/systemd1");
            push_header(&mut fields, 2, b's', "org.freedesktop.systemd1.Manager");
            push_header(&mut fields, 3, b's', "GetUnitByInvocationID");
            push_header(&mut fields, 8, b'g', "ay");
            let mut body = Vec::with_capacity(4 + invocation_id.len());
            body.extend_from_slice(&(invocation_id.len() as u32).to_le_bytes());
            body.extend_from_slice(&invocation_id);
            let mut output = vec![b'l', 1, 0, 1];
            output.extend_from_slice(&(body.len() as u32).to_le_bytes());
            output.extend_from_slice(&serial.to_le_bytes());
            output.extend_from_slice(&(fields.len() as u32).to_le_bytes());
            output.extend_from_slice(&fields);
            push_padding(&mut output, 8);
            output.extend_from_slice(&body);
            output
        }

        fn introspect_call(serial: u32) -> Vec<u8> {
            interface_call_with_flags(
                serial,
                0,
                "org.freedesktop.DBus.Introspectable",
                "Introspect",
                &[],
            )
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
            authenticate_to_handoff_with_initial(owner, event_loop, client, b"wire");
        }

        fn authenticate_to_handoff_with_initial(
            owner: &mut PrivateBusTransportOwner,
            event_loop: &mut EventLoop,
            client: &mut UnixStream,
            initial_wire_bytes: &[u8],
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
            response.extend_from_slice(b"\r\nBEGIN\r\n");
            response.extend_from_slice(initial_wire_bytes);
            client.write_all(&response).unwrap();
            event_loop.run_once(0).unwrap();
            dispatch(owner, event_loop);
            event_loop.run_once(0).unwrap();
            assert_eq!(dispatch(owner, event_loop).authenticated, 1);
        }

        fn queue_denied_reply(
            owner: &mut PrivateBusTransportOwner,
            id: PrivateBusConnectionId,
            reply_serial: u32,
        ) {
            let (sender, mut inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
            let receiver = sender
                .try_send(
                    SenderIdentity::from_authenticated_peer(
                        AuthenticatedPeer::from_kernel_peer_credentials(1, 0, 0),
                    ),
                    Pid1ManagerCommand::LoadUnit {
                        name: "missing.service".into(),
                    },
                )
                .unwrap();
            let mut runtime = crate::runtime_manager::RuntimeManager::new();
            let mut authorizer = DenyAllPid1CommandAuthorizer;
            inbox.dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap());
            owner
                .wire_slot_mut(id)
                .unwrap()
                .replies_mut()
                .track(Endian::Little, reply_serial, false, receiver)
                .unwrap();
            assert_eq!(
                owner
                    .poll_wire_slot_replies(id, NonZeroUsize::new(1).unwrap())
                    .unwrap()
                    .enqueued,
                1
            );
        }

        #[test]
        fn one_wire_turn_preserves_kernel_identity_wakes_pid1_and_queues_its_reply() {
            let call = manager_call(17, "LoadUnit", &["missing.service"]);
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "dispatch-one", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, &call);
            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(call.len()))
                .unwrap()
                .unwrap();
            let expected_sender = SenderIdentity::from_authenticated_peer(
                owner.wire_slot(wire_id).unwrap().connection().peer(),
            );
            let (command_sender, mut inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            let adapter = Pid1DbusCommandAdapter::new(command_sender);

            assert_eq!(
                owner.dispatch_wire_slot_once(wire_id, &adapter),
                Ok(PrivateBusWireDispatchOutcome::Submitted {
                    reply: PrivateBusReplyTracking::Queued,
                })
            );
            assert_eq!(
                owner
                    .wire_slot(wire_id)
                    .unwrap()
                    .replies()
                    .pending_reply_count(),
                1
            );

            inbox.register(&mut event_loop).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            let mut runtime = crate::runtime_manager::RuntimeManager::new();
            let mut authorizer = CaptureAuthorizer::default();
            assert_eq!(
                inbox
                    .dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap())
                    .unwrap()
                    .dispatched,
                1
            );
            assert_eq!(authorizer.sender, Some(expected_sender));
            assert_eq!(
                owner
                    .poll_wire_slot_replies(wire_id, NonZeroUsize::new(1).unwrap())
                    .unwrap()
                    .enqueued,
                1
            );
            assert!(
                owner
                    .wire_slot(wire_id)
                    .unwrap()
                    .current_reply_frame()
                    .is_some()
            );

            owner.unregister(&mut event_loop).unwrap();
            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn get_unit_wire_call_returns_exact_object_path_without_loading() {
            let call = manager_call(29, "GetUnit", &["example.target"]);
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "get-unit", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, &call);
            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(call.len()))
                .unwrap()
                .unwrap();
            let (command_sender, mut inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            let adapter = Pid1DbusCommandAdapter::new(command_sender);

            assert_eq!(
                owner.dispatch_wire_slot_once(wire_id, &adapter),
                Ok(PrivateBusWireDispatchOutcome::Submitted {
                    reply: PrivateBusReplyTracking::Queued,
                })
            );
            inbox.register(&mut event_loop).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            let mut runtime = crate::runtime_manager::RuntimeManager::new();
            runtime.inject_test_unit(
                "example.target",
                "Example Target",
                crate::unit::ActiveState::Inactive,
                "dead",
            );
            assert_eq!(
                inbox
                    .dispatch_pending(
                        &mut runtime,
                        &mut AllowAuthorizer,
                        NonZeroUsize::new(1).unwrap(),
                    )
                    .unwrap()
                    .dispatched,
                1
            );
            assert_eq!(runtime.unit_count(), 1);
            assert_eq!(
                owner
                    .poll_wire_slot_replies(wire_id, NonZeroUsize::new(1).unwrap())
                    .unwrap()
                    .enqueued,
                1
            );
            let frame = owner
                .wire_slot(wire_id)
                .unwrap()
                .current_reply_frame()
                .unwrap();
            assert_eq!(frame[1], 2, "GetUnit must return, not error");
            assert!(
                frame.windows(b"o\0".len()).any(|window| window == b"o\0"),
                "GetUnit return signature must be one object path"
            );
            assert!(
                frame
                    .windows(b"/org/freedesktop/systemd1/unit/example_2etarget".len())
                    .any(|window| window == b"/org/freedesktop/systemd1/unit/example_2etarget")
            );

            owner.unregister(&mut event_loop).unwrap();
            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn get_unit_missing_wire_call_returns_no_such_unit_without_loading() {
            let call = manager_call(30, "GetUnit", &["missing.target"]);
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "get-unit-missing", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, &call);
            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(call.len()))
                .unwrap()
                .unwrap();
            let (command_sender, mut inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            let adapter = Pid1DbusCommandAdapter::new(command_sender);

            assert!(matches!(
                owner.dispatch_wire_slot_once(wire_id, &adapter),
                Ok(PrivateBusWireDispatchOutcome::Submitted { .. })
            ));
            inbox.register(&mut event_loop).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            let mut runtime = crate::runtime_manager::RuntimeManager::new();
            assert_eq!(
                inbox
                    .dispatch_pending(
                        &mut runtime,
                        &mut AllowAuthorizer,
                        NonZeroUsize::new(1).unwrap(),
                    )
                    .unwrap()
                    .dispatched,
                1
            );
            assert_eq!(runtime.unit_count(), 0);
            assert_eq!(
                owner
                    .poll_wire_slot_replies(wire_id, NonZeroUsize::new(1).unwrap())
                    .unwrap()
                    .enqueued,
                1
            );
            let frame = owner
                .wire_slot(wire_id)
                .unwrap()
                .current_reply_frame()
                .unwrap();
            assert_eq!(frame[1], 3, "missing GetUnit must return an error");
            assert!(
                frame
                    .windows(b"org.freedesktop.systemd1.NoSuchUnit".len())
                    .any(|window| window == b"org.freedesktop.systemd1.NoSuchUnit")
            );
            assert!(
                frame
                    .windows(b"Unit missing.target not loaded.".len())
                    .any(|window| window == b"Unit missing.target not loaded.")
            );

            owner.unregister(&mut event_loop).unwrap();
            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn get_unit_by_pid_wire_call_returns_loaded_unit_path() {
            let call = manager_pid_call(32, 4242);
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "get-unit-by-pid", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, &call);
            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(call.len()))
                .unwrap()
                .unwrap();
            let (command_sender, mut inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            let adapter = Pid1DbusCommandAdapter::new(command_sender);

            assert!(matches!(
                owner.dispatch_wire_slot_once(wire_id, &adapter),
                Ok(PrivateBusWireDispatchOutcome::Submitted { .. })
            ));
            inbox.register(&mut event_loop).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            let mut runtime = crate::runtime_manager::RuntimeManager::new();
            runtime.inject_test_unit(
                "example.service",
                "Example Service",
                crate::unit::ActiveState::Active,
                "running",
            );
            runtime.inject_test_main_pid("example.service", 4242);
            assert_eq!(
                inbox
                    .dispatch_pending(
                        &mut runtime,
                        &mut AllowAuthorizer,
                        NonZeroUsize::new(1).unwrap(),
                    )
                    .unwrap()
                    .dispatched,
                1
            );
            assert_eq!(
                owner
                    .poll_wire_slot_replies(wire_id, NonZeroUsize::new(1).unwrap())
                    .unwrap()
                    .enqueued,
                1
            );
            let frame = owner
                .wire_slot(wire_id)
                .unwrap()
                .current_reply_frame()
                .unwrap();
            assert_eq!(frame[1], 2, "GetUnitByPID must return, not error");
            assert!(
                frame
                    .windows(b"/org/freedesktop/systemd1/unit/example_2eservice".len())
                    .any(|window| window == b"/org/freedesktop/systemd1/unit/example_2eservice")
            );

            owner.unregister(&mut event_loop).unwrap();
            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn get_unit_by_invocation_id_wire_call_returns_id_stable_path() {
            let invocation_id = [0xab; 16];
            let call = manager_invocation_id_call(33, invocation_id);
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "get-unit-by-invocation-id", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, &call);
            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(call.len()))
                .unwrap()
                .unwrap();
            let (command_sender, mut inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            let adapter = Pid1DbusCommandAdapter::new(command_sender);

            assert!(matches!(
                owner.dispatch_wire_slot_once(wire_id, &adapter),
                Ok(PrivateBusWireDispatchOutcome::Submitted { .. })
            ));
            inbox.register(&mut event_loop).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            let mut runtime = crate::runtime_manager::RuntimeManager::new();
            runtime.inject_test_unit(
                "example.service",
                "Example Service",
                crate::unit::ActiveState::Active,
                "running",
            );
            runtime.inject_test_invocation_id("example.service", invocation_id);
            assert_eq!(
                inbox
                    .dispatch_pending(
                        &mut runtime,
                        &mut AllowAuthorizer,
                        NonZeroUsize::new(1).unwrap(),
                    )
                    .unwrap()
                    .dispatched,
                1
            );
            assert_eq!(
                owner
                    .poll_wire_slot_replies(wire_id, NonZeroUsize::new(1).unwrap())
                    .unwrap()
                    .enqueued,
                1
            );
            let frame = owner
                .wire_slot(wire_id)
                .unwrap()
                .current_reply_frame()
                .unwrap();
            assert_eq!(frame[1], 2, "GetUnitByInvocationID must return, not error");
            assert!(
                frame
                    .windows(
                        b"/org/freedesktop/systemd1/unit/abababababababababababababababab".len()
                    )
                    .any(|window| {
                        window == b"/org/freedesktop/systemd1/unit/abababababababababababababababab"
                    })
            );

            owner.unregister(&mut event_loop).unwrap();
            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn introspect_wire_call_returns_bounded_shadow_xml() {
            let call = introspect_call(31);
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "introspect", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, &call);
            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(call.len()))
                .unwrap()
                .unwrap();
            let (command_sender, mut inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            let adapter = Pid1DbusCommandAdapter::new(command_sender);

            assert!(matches!(
                owner.dispatch_wire_slot_once(wire_id, &adapter),
                Ok(PrivateBusWireDispatchOutcome::Submitted {
                    reply: PrivateBusReplyTracking::Queued,
                })
            ));
            inbox.register(&mut event_loop).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            let mut runtime = crate::runtime_manager::RuntimeManager::new();
            assert_eq!(
                inbox
                    .dispatch_pending(
                        &mut runtime,
                        &mut AllowAuthorizer,
                        NonZeroUsize::new(1).unwrap(),
                    )
                    .unwrap()
                    .dispatched,
                1
            );
            assert_eq!(
                owner
                    .poll_wire_slot_replies(wire_id, NonZeroUsize::new(1).unwrap())
                    .unwrap()
                    .enqueued,
                1
            );
            let frame = owner
                .wire_slot(wire_id)
                .unwrap()
                .current_reply_frame()
                .unwrap();
            assert_eq!(frame[1], 2, "Introspect must return, not error");
            assert!(frame.windows(b"s\0".len()).any(|window| window == b"s\0"));
            assert!(
                frame
                    .windows(b"org.freedesktop.DBus.Introspectable".len())
                    .any(|window| window == b"org.freedesktop.DBus.Introspectable")
            );
            assert!(
                frame
                    .windows(b"org.freedesktop.DBus.Properties".len())
                    .all(|window| window != b"org.freedesktop.DBus.Properties")
            );

            owner.unregister(&mut event_loop).unwrap();
            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn incomplete_first_frame_is_retained_without_submitting_or_waking_pid1() {
            let call = manager_call(17, "LoadUnit", &["missing.service"]);
            let incomplete = &call[..call.len() - 1];
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "dispatch-incomplete", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff_with_initial(
                &mut owner,
                &mut event_loop,
                &mut client,
                incomplete,
            );
            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(call.len()))
                .unwrap()
                .unwrap();
            let (command_sender, inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            let adapter = Pid1DbusCommandAdapter::new(command_sender);

            assert_eq!(
                owner.dispatch_wire_slot_once(wire_id, &adapter),
                Ok(PrivateBusWireDispatchOutcome::NoMessage)
            );
            assert_eq!(
                owner.wire_slot(wire_id).unwrap().input().buffered(),
                incomplete
            );
            assert_eq!(owner.wire_slot_readiness(wire_id).unwrap().read_budget, 1);

            inbox.register(&mut event_loop).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(false));
            owner.unregister(&mut event_loop).unwrap();
            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn invalid_no_reply_call_does_not_wake_pid1_or_poison_the_slot() {
            let call = manager_call_with_flags(17, 1, "NotImplemented", &[]);
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "dispatch-no-reply", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, &call);
            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(call.len()))
                .unwrap()
                .unwrap();
            let (command_sender, inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            let adapter = Pid1DbusCommandAdapter::new(command_sender);

            assert!(matches!(
                owner.dispatch_wire_slot_once(wire_id, &adapter),
                Ok(PrivateBusWireDispatchOutcome::RejectedNoReply {
                    cause: Pid1DbusCommandAdapterError::UnsupportedMember { .. }
                })
            ));
            assert!(!owner.wire_slot(wire_id).unwrap().is_terminal());

            inbox.register(&mut event_loop).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(false));
            owner.unregister(&mut event_loop).unwrap();
            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn closed_manager_terminalizes_a_no_reply_handoff() {
            let call = manager_call_with_flags(17, 1, "LoadUnit", &["missing.service"]);
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "dispatch-closed-inbox", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, &call);
            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(call.len()))
                .unwrap()
                .unwrap();
            let (command_sender, inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            drop(inbox);
            let adapter = Pid1DbusCommandAdapter::new(command_sender);

            assert!(matches!(
                owner.dispatch_wire_slot_once(wire_id, &adapter),
                Err(PrivateBusTransportError::WireDispatch(
                    PrivateBusWireDispatchError::Adapter(Pid1DbusCommandAdapterError::Ingress(
                        Pid1BusSendError::Command(Pid1CommandError::InboxClosed)
                    ))
                ))
            ));
            assert!(owner.wire_slot(wire_id).unwrap().is_terminal());

            owner.unregister(&mut event_loop).unwrap();
            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn reply_reservation_is_checked_before_a_second_manager_command_is_accepted() {
            let first = manager_call(17, "LoadUnit", &["first.service"]);
            let second = manager_call(18, "LoadUnit", &["second.service"]);
            let mut calls = first;
            calls.extend_from_slice(&second);
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "dispatch-reply-bound", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, &calls);
            let wire_id = owner
                .promote_authenticated_to_wire(PrivateBusWireSlotConfig::new(
                    calls.len(),
                    NonZeroUsize::new(1).unwrap(),
                    512,
                    1024,
                ))
                .unwrap()
                .unwrap();
            let (command_sender, mut inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(2).unwrap()).unwrap();
            let adapter = Pid1DbusCommandAdapter::new(command_sender);

            assert!(matches!(
                owner.dispatch_wire_slot_once(wire_id, &adapter),
                Ok(PrivateBusWireDispatchOutcome::Submitted {
                    reply: PrivateBusReplyTracking::Queued,
                })
            ));
            assert_eq!(
                owner.dispatch_wire_slot_once(wire_id, &adapter),
                Err(PrivateBusTransportError::WireDispatch(
                    PrivateBusWireDispatchError::ReplyReservation {
                        reply_serial: 18,
                        cause: crate::pid1_dbus_reply_queue::PrivateBusReplyQueueError::PendingReplyLimitReached {
                            capacity: 1,
                        },
                    }
                ))
            );
            assert!(owner.wire_slot(wire_id).unwrap().is_terminal());

            inbox.register(&mut event_loop).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            let mut runtime = crate::runtime_manager::RuntimeManager::new();
            let mut authorizer = DenyAllPid1CommandAuthorizer;
            assert_eq!(
                inbox
                    .dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(2).unwrap())
                    .unwrap()
                    .dispatched,
                1
            );

            assert!(owner.close_wire_slot(wire_id));
            assert_eq!(owner.retained_connection_count(), 0);
            owner.unregister(&mut event_loop).unwrap();
            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn reply_expected_unsupported_call_is_a_typed_error_without_waking_pid1() {
            let call = manager_call(17, "NotImplemented", &[]);
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "dispatch-invalid", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, &call);
            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(call.len()))
                .unwrap()
                .unwrap();
            let (command_sender, inbox) =
                pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
            let adapter = Pid1DbusCommandAdapter::new(command_sender);

            assert!(matches!(
                owner.dispatch_wire_slot_once(wire_id, &adapter),
                Ok(PrivateBusWireDispatchOutcome::RejectedWithError {
                    error: Pid1DbusProtocolError::UnknownMethod,
                })
            ));
            assert!(!owner.wire_slot(wire_id).unwrap().is_terminal());
            let frame = owner
                .wire_slot(wire_id)
                .unwrap()
                .current_reply_frame()
                .unwrap();
            assert_eq!(frame[1], 3);
            assert!(
                frame
                    .windows(b"org.freedesktop.DBus.Error.UnknownMethod".len())
                    .any(|window| window == b"org.freedesktop.DBus.Error.UnknownMethod")
            );

            inbox.register(&mut event_loop).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(false));
            let frame_len = owner
                .wire_slot(wire_id)
                .unwrap()
                .current_reply_frame()
                .unwrap()
                .len();
            assert!(
                owner
                    .wire_slot_mut(wire_id)
                    .unwrap()
                    .acknowledge_reply_written(frame_len)
                    .unwrap()
            );
            assert!(!owner.wire_slot(wire_id).unwrap().is_terminal());
            owner.unregister(&mut event_loop).unwrap();
            drop((client, owner));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn decoded_adapter_failures_map_to_narrow_protocol_errors() {
            assert_eq!(
                protocol_error_for_adapter(&Pid1DbusCommandAdapterError::WrongPath {
                    actual: "/other".into(),
                }),
                Pid1DbusProtocolError::UnknownObject
            );
            assert_eq!(
                protocol_error_for_adapter(&Pid1DbusCommandAdapterError::WrongInterface {
                    actual: Some("org.example.Other".into()),
                }),
                Pid1DbusProtocolError::UnknownInterface
            );
            assert_eq!(
                protocol_error_for_adapter(&Pid1DbusCommandAdapterError::WrongSignature {
                    member: "LoadUnit".into(),
                    expected: "s",
                    actual: "ss".into(),
                }),
                Pid1DbusProtocolError::InvalidArgs
            );
            assert_eq!(
                protocol_error_for_adapter(&Pid1DbusCommandAdapterError::Ingress(
                    Pid1BusSendError::Command(Pid1CommandError::InboxFull),
                )),
                Pid1DbusProtocolError::LimitsExceeded
            );
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
        fn bounded_stream_read_reports_would_block_progress_and_eof() {
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "stream-read", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, b"");
            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(64))
                .unwrap()
                .unwrap();

            assert_eq!(
                owner.read_wire_slot_once(wire_id),
                Ok(PrivateBusWireReadOutcome::WouldBlock)
            );
            client.write_all(b"abc").unwrap();
            assert_eq!(
                owner.read_wire_slot_once(wire_id),
                Ok(PrivateBusWireReadOutcome::Read { bytes: 3 })
            );
            assert_eq!(owner.wire_slot(wire_id).unwrap().input().buffered(), b"abc");

            let mut auth_ok = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                client.read_exact(&mut byte).unwrap();
                auth_ok.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            assert!(auth_ok.starts_with(b"OK "));
            drop(client);
            assert_eq!(
                owner.read_wire_slot_once(wire_id),
                Ok(PrivateBusWireReadOutcome::PeerClosed)
            );
            assert!(owner.wire_slot(wire_id).unwrap().is_terminal());

            owner.unregister(&mut event_loop).unwrap();
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn reply_write_preserves_bytes_across_would_block_short_write_and_eof() {
            let mut event_loop = EventLoop::new().unwrap();
            let (path, mut owner) = owner(&mut event_loop, "stream-write", 1);
            let mut client = UnixStream::connect(&path).unwrap();
            authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, b"");
            let wire_id = owner
                .promote_authenticated_to_wire(wire_slot_config(64))
                .unwrap()
                .unwrap();
            queue_denied_reply(&mut owner, wire_id, 17);
            let frame_len = owner
                .wire_slot(wire_id)
                .unwrap()
                .current_reply_frame()
                .unwrap()
                .len();
            assert!(frame_len > 1);

            assert_eq!(
                owner.wire_slot_mut(wire_id).unwrap().write_reply_with(|_| {
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                }),
                Ok(PrivateBusWireWriteOutcome::WouldBlock)
            );
            assert_eq!(
                owner
                    .wire_slot(wire_id)
                    .unwrap()
                    .current_reply_frame()
                    .unwrap()
                    .len(),
                frame_len
            );
            assert_eq!(
                owner
                    .wire_slot_mut(wire_id)
                    .unwrap()
                    .write_reply_with(|_| Ok(frame_len - 1)),
                Ok(PrivateBusWireWriteOutcome::Written {
                    bytes: frame_len - 1,
                    frame_complete: false,
                })
            );
            assert_eq!(
                owner
                    .wire_slot_mut(wire_id)
                    .unwrap()
                    .write_reply_with(|_| Ok(1)),
                Ok(PrivateBusWireWriteOutcome::Written {
                    bytes: 1,
                    frame_complete: true,
                })
            );
            assert!(
                owner
                    .wire_slot(wire_id)
                    .unwrap()
                    .current_reply_frame()
                    .is_none()
            );

            queue_denied_reply(&mut owner, wire_id, 18);
            assert_eq!(
                owner
                    .wire_slot_mut(wire_id)
                    .unwrap()
                    .write_reply_with(|_| Ok(0)),
                Ok(PrivateBusWireWriteOutcome::PeerClosed)
            );
            assert!(owner.wire_slot(wire_id).unwrap().is_terminal());

            owner.unregister(&mut event_loop).unwrap();
            drop(client);
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
