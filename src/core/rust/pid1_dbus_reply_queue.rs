// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/core/dbus.c

//! Bounded, transport-neutral reply ownership for one private D-Bus peer.
//!
//! A future private-bus wire slot owns one [`PrivateBusReplyQueue`] alongside
//! its authenticated stream. It records the original call's endian and
//! serial, retains the one-shot manager reply receiver, and turns completed
//! results into bounded wire frames. The socket callback then writes at most
//! [`Self::current_frame`] and reports the exact number of bytes through
//! [`Self::acknowledge_written`].
//!
//! This intentionally does not perform I/O, create a socket, or authorize a
//! command. In particular, [`Self::track_call`] only models a reply that has
//! *already* been accepted by the command adapter. On disconnect, call
//! [`Self::clear`] before releasing the wire slot: dropping the receivers is
//! the correct cancellation mechanism for manager results that can no longer
//! be delivered to a peer.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::mpsc::TryRecvError;

use crate::pid1_dbus_reply_adapter::{
    Pid1DbusProtocolError, Pid1DbusReplyAdapter, Pid1DbusReplyAdapterError,
};
use crate::pid1_dbus_wire::{Endian, MethodCall};
use crate::pid1_manager_commands::{Pid1CommandReplyReceiver, Pid1ManagerReply};

/// Result of handing one manager reply receiver to a connection queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateBusReplyTracking {
    /// The call expects exactly one method return or error frame.
    Queued,
    /// The caller set D-Bus' `NO_REPLY_EXPECTED` flag. The receiver was
    /// dropped immediately and its future result must not produce a frame.
    NoReplyExpected,
}

/// A reply-correlation slot reserved before manager work is submitted.
///
/// The reservation owns capacity already obtained from the pending queue and
/// therefore lets the transport commit a receiver without an allocation after
/// the command has been accepted. It is intentionally opaque: only the queue
/// that created it may commit or cancel the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateBusReplyReservation {
    reply_serial: u32,
}

/// Bounded polling progress from [`PrivateBusReplyQueue::poll_completed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateBusReplyPollOutcome {
    /// Pending receivers inspected this turn, including ones that were not
    /// complete yet. This is capped by the caller-supplied poll budget.
    pub inspected: usize,
    /// Completed manager results turned into retained outbound frames.
    pub enqueued: usize,
}

/// Failures at the explicit private-bus reply ownership boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateBusReplyQueueError {
    /// The outgoing byte cap must always admit one individually valid frame;
    /// otherwise a completed manager result could not be represented.
    OutboundCapacityTooSmall {
        capacity: usize,
        minimum_frame_capacity: usize,
    },
    /// A peer reused a method-call serial while its prior response was still
    /// pending or partially written. Keeping both would make correlation
    /// ambiguous, so the wire slot must reject the later request.
    DuplicateReplySerial { reply_serial: u32 },
    /// The caller attempted to track an invalid zero method-call serial.
    /// Checked wire decoding never yields this value, but the scalar helper
    /// also defends its public boundary.
    InvalidReplySerial,
    /// A manager command was accepted after this connection had already
    /// reached its bounded pending-reply limit. The slot is terminal and must
    /// be closed, because dropping the new receiver would lose its response.
    PendingReplyLimitReached { capacity: usize },
    /// A caller attempted to hold more than one in-flight reservation for a
    /// queue. The wire dispatcher is single-turn, so this indicates a broken
    /// ownership protocol rather than peer backpressure.
    ReplyReservationInProgress { reply_serial: u32 },
    /// A reservation token no longer belongs to this queue. This is terminal
    /// because the caller can no longer prove reply correlation ownership.
    ReplyReservationNotFound { reply_serial: u32 },
    /// Retaining an already accepted manager reply required an allocation
    /// that failed. The receiver cannot be returned to the caller, so this is
    /// terminal and the wire slot must be closed.
    PendingAllocationFailed,
    /// Reserving outbound frame bookkeeping failed before a pending receiver
    /// was consumed. The caller may retry polling or close the peer.
    OutboundAllocationFailed,
    /// A local protocol rejection would exceed the remaining retained output
    /// budget. No manager operation was accepted, but omitting a required
    /// D-Bus error would leave the peer waiting, so the slot must be closed.
    OutboundCapacityExceeded { required: usize, available: usize },
    /// The PID 1 command owner disappeared without producing the reply it
    /// promised. The connection is terminal and must be torn down.
    ReplyChannelClosed { reply_serial: u32 },
    /// A completed manager result could not be encoded within the configured
    /// per-frame bound. The connection is terminal and must be torn down.
    ReplyEncoding(Pid1DbusReplyAdapterError),
    /// The queue has observed a terminal failure. Call [`PrivateBusReplyQueue::clear`]
    /// as part of disconnect teardown before reusing it.
    TerminalFailure,
    /// A socket write acknowledgement exceeds the only frame currently made
    /// available to the transport. This is terminal: the queue can no longer
    /// prove which reply bytes reached the peer.
    WriteBeyondCurrentFrame { written: usize, available: usize },
}

struct PendingReply {
    endian: Endian,
    reply_serial: u32,
    receiver: Pid1CommandReplyReceiver,
}

struct OutboundFrame {
    reply_serial: u32,
    bytes: Vec<u8>,
    offset: usize,
}

impl OutboundFrame {
    fn remaining(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }
}

/// One connection's bounded pending and outbound private-bus reply state.
///
/// The queue never allocates based on a peer-controlled unbounded length:
/// `max_pending` caps retained manager receivers, `frame_capacity` bounds a
/// single encoded reply, and `outbound_capacity` caps all unflushed bytes.
/// Reply serials remain reserved until the last byte of their response has
/// been acknowledged, preventing correlation ambiguity during partial writes.
pub struct PrivateBusReplyQueue {
    adapter: Pid1DbusReplyAdapter,
    max_pending: NonZeroUsize,
    outbound_capacity: usize,
    pending: VecDeque<PendingReply>,
    outbound: VecDeque<OutboundFrame>,
    outbound_bytes: usize,
    reserved_reply: Option<u32>,
    next_outgoing_serial: u32,
    terminal: bool,
}

impl PrivateBusReplyQueue {
    /// Create reply state for one authenticated wire slot.
    ///
    /// `outbound_capacity` must fit a worst-case single encoded frame. The
    /// initial outgoing serial is one, and wraps from `u32::MAX` back to one;
    /// zero is never emitted because D-Bus reserves it as invalid.
    pub fn new(
        max_pending: NonZeroUsize,
        frame_capacity: usize,
        outbound_capacity: usize,
    ) -> Result<Self, PrivateBusReplyQueueError> {
        let adapter = Pid1DbusReplyAdapter::new(frame_capacity)
            .map_err(PrivateBusReplyQueueError::ReplyEncoding)?;
        if outbound_capacity < frame_capacity {
            return Err(PrivateBusReplyQueueError::OutboundCapacityTooSmall {
                capacity: outbound_capacity,
                minimum_frame_capacity: frame_capacity,
            });
        }
        Ok(Self {
            adapter,
            max_pending,
            outbound_capacity,
            pending: VecDeque::new(),
            outbound: VecDeque::new(),
            outbound_bytes: 0,
            reserved_reply: None,
            next_outgoing_serial: 1,
            terminal: false,
        })
    }

    pub const fn max_pending(&self) -> NonZeroUsize {
        self.max_pending
    }

    pub const fn frame_capacity(&self) -> usize {
        self.adapter.capacity()
    }

    pub const fn outbound_capacity(&self) -> usize {
        self.outbound_capacity
    }

    pub fn pending_reply_count(&self) -> usize {
        self.pending.len()
    }

    /// Whether a reply-producing call may be submitted without exceeding the
    /// configured pending-receiver cap.
    ///
    /// A future dispatcher should consult this before it enqueues a command
    /// that expects a reply. This avoids accepting manager work which it
    /// already knows it cannot retain a correlation slot for. Calls with
    /// `NO_REPLY_EXPECTED` do not need a slot.
    pub fn can_track_reply(&self) -> bool {
        !self.terminal
            && self.reserved_reply.is_none()
            && self.pending.len() < self.max_pending.get()
    }

    /// Whether `reply_serial` can be reserved for a newly accepted call.
    ///
    /// The future dispatcher should check this before it asks the command
    /// adapter to enqueue a reply-producing method. Once a command receiver
    /// has been handed to [`Self::track`], rejecting it would otherwise mean
    /// that its one-shot reply cannot be delivered.
    pub fn can_track_reply_serial(&self, reply_serial: u32) -> bool {
        reply_serial != 0 && self.can_track_reply() && !self.reply_serial_is_reserved(reply_serial)
    }

    /// Reserve one reply-correlation slot before submitting manager work.
    ///
    /// `pending.try_reserve(1)` happens here, before the command sender can
    /// accept the operation. The subsequent [`Self::commit_reply`] therefore
    /// only moves an already-owned receiver into the queue and cannot fail due
    /// to allocation.
    pub fn reserve_reply(
        &mut self,
        reply_serial: u32,
    ) -> Result<PrivateBusReplyReservation, PrivateBusReplyQueueError> {
        if self.terminal {
            return Err(PrivateBusReplyQueueError::TerminalFailure);
        }
        if reply_serial == 0 {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::InvalidReplySerial);
        }
        if self.reserved_reply.is_some() {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::ReplyReservationInProgress { reply_serial });
        }
        if self.reply_serial_is_reserved(reply_serial) {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::DuplicateReplySerial { reply_serial });
        }
        if !self.can_track_reply() {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::PendingReplyLimitReached {
                capacity: self.max_pending.get(),
            });
        }
        self.pending.try_reserve(1).map_err(|_| {
            self.terminal = true;
            PrivateBusReplyQueueError::PendingAllocationFailed
        })?;
        self.reserved_reply = Some(reply_serial);
        Ok(PrivateBusReplyReservation { reply_serial })
    }

    /// Commit a previously reserved correlation slot after manager submission.
    pub fn commit_reply(
        &mut self,
        reservation: PrivateBusReplyReservation,
        endian: Endian,
        receiver: Pid1CommandReplyReceiver,
    ) -> Result<PrivateBusReplyTracking, PrivateBusReplyQueueError> {
        if self.terminal {
            return Err(PrivateBusReplyQueueError::TerminalFailure);
        }
        if self.reserved_reply != Some(reservation.reply_serial) {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::ReplyReservationNotFound {
                reply_serial: reservation.reply_serial,
            });
        }
        self.reserved_reply = None;
        self.pending.push_back(PendingReply {
            endian,
            reply_serial: reservation.reply_serial,
            receiver,
        });
        Ok(PrivateBusReplyTracking::Queued)
    }

    /// Cancel a reservation when manager submission was rejected.
    pub fn cancel_reply(&mut self, reservation: PrivateBusReplyReservation) {
        if self.reserved_reply == Some(reservation.reply_serial) {
            self.reserved_reply = None;
        }
    }

    pub fn outbound_frame_count(&self) -> usize {
        self.outbound.len()
    }

    pub const fn outbound_byte_count(&self) -> usize {
        self.outbound_bytes
    }

    pub const fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Retain a bounded D-Bus error for a decoded request that was rejected
    /// before any manager work was accepted.
    ///
    /// The exact request serial remains reserved in the outbound queue until
    /// the final byte is written. This gives locally generated errors the same
    /// duplicate-serial and partial-write guarantees as manager replies. A
    /// caller that cannot retain this frame must detach the peer rather than
    /// silently discard a reply-expected request.
    pub fn enqueue_protocol_error(
        &mut self,
        endian: Endian,
        reply_serial: u32,
        error: Pid1DbusProtocolError,
    ) -> Result<(), PrivateBusReplyQueueError> {
        self.prepare_immediate_reply(reply_serial)?;

        let serial = self.next_outgoing_serial;
        let bytes = self
            .adapter
            .encode_protocol_error(endian, serial, reply_serial, error)
            .map_err(PrivateBusReplyQueueError::ReplyEncoding)?;
        self.enqueue_immediate_frame(reply_serial, bytes)
    }

    /// Retain a completed transport-local reply without involving the manager.
    ///
    /// Standard peer methods are handled by sd-bus itself in C. Their Rust
    /// equivalents still use this queue so duplicate call serials, total
    /// outbound bytes, short writes, and teardown have exactly one owner.
    pub fn enqueue_local_reply(
        &mut self,
        endian: Endian,
        reply_serial: u32,
        no_reply_expected: bool,
        reply: Pid1ManagerReply,
    ) -> Result<PrivateBusReplyTracking, PrivateBusReplyQueueError> {
        if self.terminal {
            return Err(PrivateBusReplyQueueError::TerminalFailure);
        }
        if no_reply_expected {
            return Ok(PrivateBusReplyTracking::NoReplyExpected);
        }
        self.prepare_immediate_reply(reply_serial)?;

        let serial = self.next_outgoing_serial;
        let bytes = self
            .adapter
            .encode(endian, serial, reply_serial, Ok(reply))
            .map_err(PrivateBusReplyQueueError::ReplyEncoding)?;
        self.enqueue_immediate_frame(reply_serial, bytes)?;
        Ok(PrivateBusReplyTracking::Queued)
    }

    /// Retain a checked connection-local string reply without treating it as
    /// a manager result. This is used for standard peer methods such as
    /// `GetMachineId`, whose successful response must not consume a manager
    /// reply receiver or command-inbox capacity.
    pub fn enqueue_local_text_reply(
        &mut self,
        endian: Endian,
        reply_serial: u32,
        no_reply_expected: bool,
        value: &str,
    ) -> Result<PrivateBusReplyTracking, PrivateBusReplyQueueError> {
        if self.terminal {
            return Err(PrivateBusReplyQueueError::TerminalFailure);
        }
        if no_reply_expected {
            return Ok(PrivateBusReplyTracking::NoReplyExpected);
        }
        self.prepare_immediate_reply(reply_serial)?;
        let bytes = self
            .adapter
            .encode_local_text_reply(endian, self.next_outgoing_serial, reply_serial, value)
            .map_err(PrivateBusReplyQueueError::ReplyEncoding)?;
        self.enqueue_immediate_frame(reply_serial, bytes)?;
        Ok(PrivateBusReplyTracking::Queued)
    }

    fn prepare_immediate_reply(
        &mut self,
        reply_serial: u32,
    ) -> Result<(), PrivateBusReplyQueueError> {
        if self.terminal {
            return Err(PrivateBusReplyQueueError::TerminalFailure);
        }
        if reply_serial == 0 {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::InvalidReplySerial);
        }
        if let Some(reserved_reply) = self.reserved_reply {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::ReplyReservationInProgress {
                reply_serial: reserved_reply,
            });
        }
        if self.reply_serial_is_reserved(reply_serial) {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::DuplicateReplySerial { reply_serial });
        }
        Ok(())
    }

    fn enqueue_immediate_frame(
        &mut self,
        reply_serial: u32,
        bytes: Vec<u8>,
    ) -> Result<(), PrivateBusReplyQueueError> {
        let available = self.outbound_capacity - self.outbound_bytes;
        if bytes.len() > available {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::OutboundCapacityExceeded {
                required: bytes.len(),
                available,
            });
        }
        if self.outbound.try_reserve(1).is_err() {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::OutboundAllocationFailed);
        }
        self.outbound_bytes += bytes.len();
        self.outbound.push_back(OutboundFrame {
            reply_serial,
            bytes,
            offset: 0,
        });
        self.take_outgoing_serial();
        Ok(())
    }

    /// Retain a reply receiver using correlation from one decoded call.
    pub fn track_call(
        &mut self,
        call: &MethodCall,
        receiver: Pid1CommandReplyReceiver,
    ) -> Result<PrivateBusReplyTracking, PrivateBusReplyQueueError> {
        self.track(call.endian, call.serial, call.no_reply_expected(), receiver)
    }

    /// Retain a reply receiver using explicitly supplied checked correlation.
    ///
    /// This form exists for the future stream dispatcher, which may retain
    /// only the three scalar correlation fields after it has released the
    /// decoded request body. `reply_serial` must originate from the checked
    /// method-call primary header and must therefore be nonzero.
    pub fn track(
        &mut self,
        endian: Endian,
        reply_serial: u32,
        no_reply_expected: bool,
        receiver: Pid1CommandReplyReceiver,
    ) -> Result<PrivateBusReplyTracking, PrivateBusReplyQueueError> {
        if self.terminal {
            return Err(PrivateBusReplyQueueError::TerminalFailure);
        }
        if no_reply_expected {
            drop(receiver);
            return Ok(PrivateBusReplyTracking::NoReplyExpected);
        }
        if let Some(reply_serial) = self.reserved_reply {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::ReplyReservationInProgress { reply_serial });
        }
        if reply_serial == 0 {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::InvalidReplySerial);
        }
        if self.reply_serial_is_reserved(reply_serial) {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::DuplicateReplySerial { reply_serial });
        }
        if !self.can_track_reply() {
            // The command was already accepted by the manager. Dropping this
            // receiver would silently lose its reply, so make the connection
            // terminal and require its owner to close the peer instead.
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::PendingReplyLimitReached {
                capacity: self.max_pending.get(),
            });
        }
        if self.pending.try_reserve(1).is_err() {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::PendingAllocationFailed);
        }
        self.pending.push_back(PendingReply {
            endian,
            reply_serial,
            receiver,
        });
        Ok(PrivateBusReplyTracking::Queued)
    }

    /// Poll a bounded number of manager reply receivers fairly.
    ///
    /// Pending receivers that are not ready rotate to the back, so a slow
    /// earlier job cannot starve a later completed job. Once fewer than one
    /// full reply-frame budget remains, the queue stops before consuming any
    /// result; this preserves a reply in its one-slot manager channel until
    /// the socket makes space. A disconnected receiver or encoder failure is
    /// terminal because no protocol-correct response can then be delivered.
    pub fn poll_completed(
        &mut self,
        budget: NonZeroUsize,
    ) -> Result<PrivateBusReplyPollOutcome, PrivateBusReplyQueueError> {
        if self.terminal {
            return Err(PrivateBusReplyQueueError::TerminalFailure);
        }

        let mut outcome = PrivateBusReplyPollOutcome {
            inspected: 0,
            enqueued: 0,
        };
        let to_inspect = self.pending.len().min(budget.get());
        for _ in 0..to_inspect {
            if self.outbound_capacity - self.outbound_bytes < self.adapter.capacity() {
                break;
            }
            self.outbound
                .try_reserve(1)
                .map_err(|_| PrivateBusReplyQueueError::OutboundAllocationFailed)?;
            let Some(pending) = self.pending.pop_front() else {
                break;
            };
            outcome.inspected += 1;
            match pending.receiver.try_recv() {
                Ok(result) => {
                    let serial = self.take_outgoing_serial();
                    let bytes = match self.adapter.encode(
                        pending.endian,
                        serial,
                        pending.reply_serial,
                        result,
                    ) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            self.terminal = true;
                            return Err(PrivateBusReplyQueueError::ReplyEncoding(error));
                        }
                    };
                    debug_assert!(bytes.len() <= self.adapter.capacity());
                    debug_assert!(
                        self.outbound_bytes.checked_add(bytes.len())
                            <= Some(self.outbound_capacity)
                    );
                    self.outbound_bytes += bytes.len();
                    self.outbound.push_back(OutboundFrame {
                        reply_serial: pending.reply_serial,
                        bytes,
                        offset: 0,
                    });
                    outcome.enqueued += 1;
                }
                Err(TryRecvError::Empty) => self.pending.push_back(pending),
                Err(TryRecvError::Disconnected) => {
                    self.terminal = true;
                    return Err(PrivateBusReplyQueueError::ReplyChannelClosed {
                        reply_serial: pending.reply_serial,
                    });
                }
            }
        }
        Ok(outcome)
    }

    /// The next contiguous bytes a nonblocking stream writer may attempt.
    ///
    /// The caller must pass the exact successful write count to
    /// [`Self::acknowledge_written`]. A `None` result means no completed reply
    /// is waiting to be written.
    pub fn current_frame(&self) -> Option<&[u8]> {
        self.outbound.front().map(OutboundFrame::remaining)
    }

    /// Account for bytes written from [`Self::current_frame`].
    ///
    /// Returns `true` only when that acknowledgement flushes the frame and
    /// releases its reply serial for later reuse. Zero-byte acknowledgements
    /// are accepted to represent an `EAGAIN`-style write attempt that made no
    /// progress.
    pub fn acknowledge_written(
        &mut self,
        written: usize,
    ) -> Result<bool, PrivateBusReplyQueueError> {
        if self.terminal {
            return Err(PrivateBusReplyQueueError::TerminalFailure);
        }
        let Some(frame) = self.outbound.front_mut() else {
            if written == 0 {
                return Ok(false);
            }
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::WriteBeyondCurrentFrame {
                written,
                available: 0,
            });
        };
        let available = frame.remaining().len();
        if written > available {
            self.terminal = true;
            return Err(PrivateBusReplyQueueError::WriteBeyondCurrentFrame { written, available });
        }
        frame.offset += written;
        self.outbound_bytes -= written;
        if frame.offset != frame.bytes.len() {
            return Ok(false);
        }
        self.outbound.pop_front();
        Ok(true)
    }

    /// Drop every pending result receiver and every unflushed frame.
    ///
    /// This is intentionally explicit so a wire-slot owner can use the same
    /// operation for peer disconnect, manager reload, reexec, and shutdown.
    /// It also clears a terminal state after the old peer is fully detached.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.outbound.clear();
        self.outbound_bytes = 0;
        self.reserved_reply = None;
        self.terminal = false;
    }

    fn reply_serial_is_reserved(&self, reply_serial: u32) -> bool {
        self.reserved_reply == Some(reply_serial)
            || self
                .pending
                .iter()
                .any(|pending| pending.reply_serial == reply_serial)
            || self
                .outbound
                .iter()
                .any(|frame| frame.reply_serial == reply_serial)
    }

    fn take_outgoing_serial(&mut self) -> u32 {
        let serial = self.next_outgoing_serial;
        self.next_outgoing_serial = self.next_outgoing_serial.checked_add(1).unwrap_or(1);
        serial
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;
    use crate::pid1_manager_commands::{
        AuthenticatedPeer, Pid1ManagerCommand, SenderIdentity, pid1_manager_command_channel,
    };

    const FRAME_CAPACITY: usize = 512;

    fn queue(pending: usize, outbound: usize) -> PrivateBusReplyQueue {
        PrivateBusReplyQueue::new(
            NonZeroUsize::new(pending).unwrap(),
            FRAME_CAPACITY,
            outbound,
        )
        .unwrap()
    }

    fn receiver_from_closed_channel() -> Pid1CommandReplyReceiver {
        let (sender, _inbox) = pid1_manager_command_channel(NonZeroUsize::new(1).unwrap());
        sender
            .try_send(
                SenderIdentity::from_authenticated_peer(
                    AuthenticatedPeer::from_kernel_peer_credentials(1, 0, 0),
                ),
                Pid1ManagerCommand::ResetFailed {
                    name: "demo.service".into(),
                },
            )
            .unwrap()
    }

    #[test]
    fn completed_reply_preserves_correlation_and_partial_write_accounting() {
        let receiver = receiver_from_closed_channel();
        let mut queue = queue(2, FRAME_CAPACITY * 2);
        queue.track(Endian::Big, 17, false, receiver).unwrap();

        assert_eq!(
            queue.poll_completed(NonZeroUsize::new(1).unwrap()),
            Err(PrivateBusReplyQueueError::ReplyChannelClosed { reply_serial: 17 })
        );
        assert!(queue.is_terminal());
        queue.clear();

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
        let mut authorizer = crate::pid1_manager_commands::DenyAllPid1CommandAuthorizer;
        inbox.dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap());

        queue.track(Endian::Big, 17, false, receiver).unwrap();
        assert_eq!(
            queue.poll_completed(NonZeroUsize::new(2).unwrap()),
            Ok(PrivateBusReplyPollOutcome {
                inspected: 1,
                enqueued: 1,
            })
        );
        let full = queue.current_frame().unwrap().to_vec();
        assert_eq!(full[0], b'B');
        assert_eq!(full[1], 3);
        assert_eq!(u32::from_be_bytes(full[8..12].try_into().unwrap()), 1);
        assert!(
            full.windows(4)
                .any(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()) == 17)
        );

        assert!(!queue.acknowledge_written(3).unwrap());
        assert_eq!(queue.outbound_byte_count(), full.len() - 3);
        assert!(matches!(
            queue.track(Endian::Big, 17, false, receiver_from_closed_channel()),
            Err(PrivateBusReplyQueueError::DuplicateReplySerial { reply_serial: 17 })
        ));
        assert!(queue.is_terminal());
        assert!(queue.acknowledge_written(full.len() - 3).unwrap());
        assert_eq!(queue.outbound_byte_count(), 0);
        assert!(queue.current_frame().is_none());
    }

    #[test]
    fn no_reply_expected_drops_receiver_without_retaining_or_allocating_a_serial() {
        let receiver = receiver_from_closed_channel();
        let mut queue = queue(1, FRAME_CAPACITY);
        assert_eq!(
            queue.track(Endian::Little, 22, true, receiver),
            Ok(PrivateBusReplyTracking::NoReplyExpected)
        );
        assert_eq!(queue.pending_reply_count(), 0);
        assert_eq!(
            queue
                .poll_completed(NonZeroUsize::new(1).unwrap())
                .unwrap()
                .enqueued,
            0
        );

        let receiver = receiver_from_closed_channel();
        queue.track(Endian::Little, 22, false, receiver).unwrap();
        assert_eq!(queue.pending_reply_count(), 1);
    }

    #[test]
    fn reservation_commits_a_reply_without_post_submit_capacity_work() {
        let mut queue = queue(1, FRAME_CAPACITY);
        let reservation = queue.reserve_reply(17).unwrap();
        assert!(!queue.can_track_reply());
        assert_eq!(
            queue.commit_reply(reservation, Endian::Little, receiver_from_closed_channel()),
            Ok(PrivateBusReplyTracking::Queued)
        );
        assert_eq!(queue.pending_reply_count(), 1);
        assert!(!queue.is_terminal());
    }

    #[test]
    fn rejected_submission_can_cancel_a_reply_reservation() {
        let mut queue = queue(1, FRAME_CAPACITY);
        let reservation = queue.reserve_reply(17).unwrap();
        queue.cancel_reply(reservation);
        assert!(queue.can_track_reply());
        queue
            .track(Endian::Little, 17, false, receiver_from_closed_channel())
            .unwrap();
        assert_eq!(queue.pending_reply_count(), 1);
    }

    #[test]
    fn outbound_backpressure_keeps_completed_reply_in_its_bounded_channel() {
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
        let mut authorizer = crate::pid1_manager_commands::DenyAllPid1CommandAuthorizer;
        inbox.dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap());

        let mut queue = queue(1, FRAME_CAPACITY);
        queue.track(Endian::Little, 7, false, receiver).unwrap();
        // A full-size first frame budget is available, so it can enqueue.
        queue.poll_completed(NonZeroUsize::new(1).unwrap()).unwrap();
        assert!(queue.current_frame().is_some());

        let receiver = receiver_from_closed_channel();
        queue.track(Endian::Little, 8, false, receiver).unwrap();
        assert_eq!(
            queue.poll_completed(NonZeroUsize::new(1).unwrap()).unwrap(),
            PrivateBusReplyPollOutcome {
                inspected: 0,
                enqueued: 0,
            }
        );
        assert_eq!(queue.pending_reply_count(), 1);
    }

    #[test]
    fn clear_drops_pending_and_outbound_state_after_disconnect() {
        let receiver = receiver_from_closed_channel();
        let mut queue = queue(1, FRAME_CAPACITY);
        queue.track(Endian::Little, 9, false, receiver).unwrap();
        queue.clear();
        assert_eq!(queue.pending_reply_count(), 0);
        assert_eq!(queue.outbound_frame_count(), 0);
        assert_eq!(queue.outbound_byte_count(), 0);
        assert!(!queue.is_terminal());
    }

    #[test]
    fn protocol_error_reserves_correlation_until_its_frame_is_flushed() {
        let mut queue = queue(1, FRAME_CAPACITY);
        queue
            .enqueue_protocol_error(Endian::Big, 19, Pid1DbusProtocolError::UnknownMethod)
            .unwrap();
        assert_eq!(queue.pending_reply_count(), 0);
        assert_eq!(queue.outbound_frame_count(), 1);
        let frame = queue.current_frame().unwrap().to_vec();
        assert_eq!(frame[0], b'B');
        assert_eq!(frame[1], 3);
        assert!(
            frame
                .windows(b"org.freedesktop.DBus.Error.UnknownMethod".len())
                .any(|window| window == b"org.freedesktop.DBus.Error.UnknownMethod")
        );
        assert_eq!(
            queue.enqueue_protocol_error(Endian::Big, 19, Pid1DbusProtocolError::UnknownMethod,),
            Err(PrivateBusReplyQueueError::DuplicateReplySerial { reply_serial: 19 })
        );
        assert!(queue.is_terminal());

        queue.clear();
        queue
            .enqueue_protocol_error(Endian::Little, 19, Pid1DbusProtocolError::InvalidArgs)
            .unwrap();
        let frame_len = queue.current_frame().unwrap().len();
        assert!(queue.acknowledge_written(frame_len).unwrap());
        queue
            .enqueue_protocol_error(Endian::Little, 19, Pid1DbusProtocolError::InvalidArgs)
            .unwrap();
    }

    #[test]
    fn local_empty_reply_is_bounded_correlated_and_honors_no_reply() {
        let mut queue = queue(1, FRAME_CAPACITY);
        assert_eq!(
            queue.enqueue_local_reply(Endian::Little, 23, false, Pid1ManagerReply::Completed,),
            Ok(PrivateBusReplyTracking::Queued)
        );
        assert_eq!(queue.pending_reply_count(), 0);
        let frame = queue.current_frame().unwrap();
        assert_eq!(frame[0], b'l');
        assert_eq!(frame[1], 2);
        assert_eq!(u32::from_le_bytes(frame[4..8].try_into().unwrap()), 0);
        assert!(
            frame
                .windows(4)
                .any(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) == 23)
        );
        assert_eq!(
            queue.enqueue_local_reply(Endian::Little, 23, false, Pid1ManagerReply::Completed,),
            Err(PrivateBusReplyQueueError::DuplicateReplySerial { reply_serial: 23 })
        );

        queue.clear();
        assert_eq!(
            queue.enqueue_local_reply(Endian::Little, 23, true, Pid1ManagerReply::Completed,),
            Ok(PrivateBusReplyTracking::NoReplyExpected)
        );
        assert_eq!(queue.outbound_frame_count(), 0);
    }

    #[test]
    fn configuration_and_write_bounds_are_checked() {
        assert!(matches!(
            PrivateBusReplyQueue::new(
                NonZeroUsize::new(1).unwrap(),
                FRAME_CAPACITY,
                FRAME_CAPACITY - 1,
            ),
            Err(PrivateBusReplyQueueError::OutboundCapacityTooSmall {
                capacity,
                minimum_frame_capacity: FRAME_CAPACITY,
            }) if capacity == FRAME_CAPACITY - 1
        ));

        let mut queue = queue(1, FRAME_CAPACITY);
        assert_eq!(
            queue.acknowledge_written(1),
            Err(PrivateBusReplyQueueError::WriteBeyondCurrentFrame {
                written: 1,
                available: 0,
            })
        );
        assert!(queue.is_terminal());
        assert_eq!(
            queue.acknowledge_written(0),
            Err(PrivateBusReplyQueueError::TerminalFailure)
        );
        queue.clear();
        assert!(!queue.acknowledge_written(0).unwrap());
        assert_eq!(
            queue.track(Endian::Little, 0, false, receiver_from_closed_channel(),),
            Err(PrivateBusReplyQueueError::InvalidReplySerial)
        );
        assert!(queue.is_terminal());
        queue.clear();

        queue
            .track(Endian::Little, 1, false, receiver_from_closed_channel())
            .unwrap();
        assert_eq!(
            queue.track(Endian::Little, 2, false, receiver_from_closed_channel(),),
            Err(PrivateBusReplyQueueError::PendingReplyLimitReached { capacity: 1 })
        );
        assert!(queue.is_terminal());
        assert!(!queue.can_track_reply());
    }

    #[test]
    fn overreported_partial_write_is_terminal_before_a_reply_can_be_reused() {
        let mut queue = queue(1, FRAME_CAPACITY);
        queue
            .enqueue_local_reply(Endian::Little, 17, false, Pid1ManagerReply::Completed)
            .unwrap();
        let frame_len = queue.current_frame().unwrap().len();

        assert_eq!(
            queue.acknowledge_written(frame_len + 1),
            Err(PrivateBusReplyQueueError::WriteBeyondCurrentFrame {
                written: frame_len + 1,
                available: frame_len,
            })
        );
        assert!(queue.is_terminal());
        assert_eq!(
            queue.acknowledge_written(0),
            Err(PrivateBusReplyQueueError::TerminalFailure)
        );
    }
}
