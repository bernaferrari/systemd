// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/libsystemd/sd-varlink/sd-varlink.c, src/libsystemd/sd-varlink/varlink-internal.h

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarlinkState {
    IdleClient = 0,
    AwaitingReply = 1,
    AwaitingReplyMore = 2,
    Calling = 3,
    Called = 4,
    Collecting = 5,
    CollectingReply = 6,
    ProcessingReply = 7,
    IdleServer = 8,
    ProcessingMethod = 9,
    ProcessingMethodMore = 10,
    ProcessingMethodOneway = 11,
    ProcessedMethod = 12,
    PendingMethod = 13,
    PendingMethodMore = 14,
    PendingDisconnect = 15,
    PendingTimeout = 16,
    ProcessingDisconnect = 17,
    ProcessingTimeout = 18,
    ProcessingFailure = 19,
    Disconnected = 20,
}

impl VarlinkState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdleClient => "idle-client",
            Self::AwaitingReply => "awaiting-reply",
            Self::AwaitingReplyMore => "awaiting-reply-more",
            Self::Calling => "calling",
            Self::Called => "called",
            Self::Collecting => "collecting",
            Self::CollectingReply => "collecting-reply",
            Self::ProcessingReply => "processing-reply",
            Self::IdleServer => "idle-server",
            Self::ProcessingMethod => "processing-method",
            Self::ProcessingMethodMore => "processing-method-more",
            Self::ProcessingMethodOneway => "processing-method-oneway",
            Self::ProcessedMethod => "processed-method",
            Self::PendingMethod => "pending-method",
            Self::PendingMethodMore => "pending-method-more",
            Self::PendingDisconnect => "pending-disconnect",
            Self::PendingTimeout => "pending-timeout",
            Self::ProcessingDisconnect => "processing-disconnect",
            Self::ProcessingTimeout => "processing-timeout",
            Self::ProcessingFailure => "processing-failure",
            Self::Disconnected => "disconnected",
        }
    }

    pub fn is_alive(self) -> bool {
        matches!(
            self,
            Self::IdleClient
                | Self::AwaitingReply
                | Self::AwaitingReplyMore
                | Self::Calling
                | Self::Called
                | Self::Collecting
                | Self::CollectingReply
                | Self::ProcessingReply
                | Self::IdleServer
                | Self::ProcessingMethod
                | Self::ProcessingMethodMore
                | Self::ProcessingMethodOneway
                | Self::ProcessedMethod
                | Self::PendingMethod
                | Self::PendingMethodMore
        )
    }

    pub fn wants_reply(self) -> bool {
        matches!(self, Self::ProcessingMethod | Self::ProcessingMethodMore)
    }
}

pub fn varlink_state_from_string(s: &str) -> Result<VarlinkState> {
    match s {
        "idle-client" => Ok(VarlinkState::IdleClient),
        "awaiting-reply" => Ok(VarlinkState::AwaitingReply),
        "awaiting-reply-more" => Ok(VarlinkState::AwaitingReplyMore),
        "calling" => Ok(VarlinkState::Calling),
        "called" => Ok(VarlinkState::Called),
        "collecting" => Ok(VarlinkState::Collecting),
        "collecting-reply" => Ok(VarlinkState::CollectingReply),
        "processing-reply" => Ok(VarlinkState::ProcessingReply),
        "idle-server" => Ok(VarlinkState::IdleServer),
        "processing-method" => Ok(VarlinkState::ProcessingMethod),
        "processing-method-more" => Ok(VarlinkState::ProcessingMethodMore),
        "processing-method-oneway" => Ok(VarlinkState::ProcessingMethodOneway),
        "processed-method" => Ok(VarlinkState::ProcessedMethod),
        "pending-method" => Ok(VarlinkState::PendingMethod),
        "pending-method-more" => Ok(VarlinkState::PendingMethodMore),
        "pending-disconnect" => Ok(VarlinkState::PendingDisconnect),
        "pending-timeout" => Ok(VarlinkState::PendingTimeout),
        "processing-disconnect" => Ok(VarlinkState::ProcessingDisconnect),
        "processing-timeout" => Ok(VarlinkState::ProcessingTimeout),
        "processing-failure" => Ok(VarlinkState::ProcessingFailure),
        "disconnected" => Ok(VarlinkState::Disconnected),
        _ => Err(NEG_EINVAL),
    }
}

pub fn varlink_state_to_string(state: VarlinkState) -> &'static str {
    state.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats_state() {
        assert_eq!(
            varlink_state_to_string(VarlinkState::IdleClient),
            "idle-client"
        );
    }
    #[test]
    fn parses_state() {
        assert_eq!(
            varlink_state_from_string("processing-method-more"),
            Ok(VarlinkState::ProcessingMethodMore)
        );
    }
    #[test]
    fn rejects_unknown_state() {
        assert_eq!(varlink_state_from_string("broken"), Err(NEG_EINVAL));
    }
    #[test]
    fn alive_state_is_alive() {
        assert!(VarlinkState::Calling.is_alive());
    }
    #[test]
    fn disconnected_state_is_not_alive() {
        assert!(!VarlinkState::Disconnected.is_alive());
    }
    #[test]
    fn processing_method_wants_reply() {
        assert!(VarlinkState::ProcessingMethod.wants_reply());
    }
    #[test]
    fn processing_method_more_wants_reply() {
        assert!(VarlinkState::ProcessingMethodMore.wants_reply());
    }
    #[test]
    fn oneway_does_not_want_reply() {
        assert!(!VarlinkState::ProcessingMethodOneway.wants_reply());
    }
    #[test]
    fn pending_disconnect_does_not_want_reply() {
        assert!(!VarlinkState::PendingDisconnect.wants_reply());
    }
}
