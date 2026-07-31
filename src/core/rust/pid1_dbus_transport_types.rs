// SPDX-License-Identifier: LGPL-2.1-or-later

//! Shared result vocabulary for the bounded private-bus dispatch seam.
//!
//! Keeping these protocol outcomes separate from the owner implementation
//! lets the transport remain focused on same-thread ownership and lifecycle
//! while callers still get an explicit, typed result for every dispatch turn.

use crate::pid1_dbus_command_adapter::Pid1DbusCommandAdapterError;
use crate::pid1_dbus_reply_adapter::Pid1DbusProtocolError;
use crate::pid1_dbus_reply_queue::{PrivateBusReplyQueueError, PrivateBusReplyTracking};
use crate::pid1_dbus_wire::PrivateBusWireAccumulatorError;

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
