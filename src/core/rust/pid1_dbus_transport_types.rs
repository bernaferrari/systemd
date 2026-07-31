// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/core/dbus.c (`bus_on_connection()` private-bus lifecycle)

//! Shared result vocabulary for the bounded private-bus dispatch seam.
//!
//! Keeping these protocol outcomes separate from the owner implementation
//! lets the transport remain focused on same-thread ownership and lifecycle
//! while callers still get an explicit, typed result for every dispatch turn.

use crate::pid1_dbus_command_adapter::Pid1DbusCommandAdapterError;
use crate::pid1_dbus_reply_adapter::Pid1DbusProtocolError;
use crate::pid1_dbus_reply_queue::{PrivateBusReplyQueueError, PrivateBusReplyTracking};
use crate::pid1_dbus_wire::PrivateBusWireAccumulatorError;
use nix::errno::Errno;
use std::num::NonZeroUsize;

/// Explicit memory and reply bounds for one authenticated private-bus wire slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateBusWireSlotConfig {
    input_capacity: usize,
    max_pending_replies: NonZeroUsize,
    reply_frame_capacity: usize,
    reply_outbound_capacity: usize,
}

impl PrivateBusWireSlotConfig {
    /// Create bounds which will be checked again when a concrete authenticated
    /// handoff is promoted. The latter check accounts for binary bytes
    /// pipelined immediately after D-Bus `BEGIN`.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateBusWireSlotReadiness {
    pub read_budget: usize,
    pub reply_write_pending: bool,
    pub can_track_reply: bool,
    pub terminal: bool,
}

/// Failure while constructing or operating one authenticated private-bus
/// connection's ownership state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateBusWireSlotError {
    UnauthenticatedHandoff,
    Terminal,
    Io(Errno),
    Input(PrivateBusWireAccumulatorError),
    Reply(PrivateBusReplyQueueError),
}

/// Progress from one bounded nonblocking read on an authenticated slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateBusWireReadOutcome {
    Backpressured,
    WouldBlock,
    Read { bytes: usize },
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

/// One bounded private-bus wire-dispatch result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateBusWireDispatchOutcome {
    /// The first buffered frame is incomplete; no manager work was submitted.
    NoMessage,
    /// Exactly one validated manager command was submitted.
    Submitted { reply: PrivateBusReplyTracking },
    /// A standard connection-local method was handled without manager work.
    HandledLocally { reply: PrivateBusReplyTracking },
    /// An invalid or unavailable no-reply call was discarded.
    RejectedNoReply { cause: Pid1DbusCommandAdapterError },
    /// A bounded typed D-Bus error frame was retained for the peer.
    RejectedWithError { error: Pid1DbusProtocolError },
}

/// Failure in a dispatch turn which cannot safely be represented by the
/// current deliberately narrow reply surface.
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
