// SPDX-License-Identifier: LGPL-2.1-or-later

//! Disconnected, bounded mapping from PID 1 command results to D-Bus replies.
//!
//! The transport retains responsibility for allocating its own outgoing D-Bus
//! serial and for keeping the method-call serial to which that reply belongs.
//! This module merely preserves those caller-supplied values while selecting a
//! checked wire encoding. It has no socket, event-loop, or manager ownership.

use crate::pid1_dbus_wire::{
    Endian, WireError, encode_empty_reply, encode_error_reply, encode_text_reply,
};
use crate::pid1_manager_commands::{Pid1CommandError, Pid1CommandResult, Pid1ManagerReply};

const JOB_PATH_PREFIX: &str = "/org/freedesktop/systemd1/job/";

const ERROR_ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";
const ERROR_FAILED: &str = "org.freedesktop.DBus.Error.Failed";
const ERROR_LIMITS_EXCEEDED: &str = "org.freedesktop.DBus.Error.LimitsExceeded";
const ERROR_DISCONNECTED: &str = "org.freedesktop.DBus.Error.Disconnected";

const MESSAGE_ACCESS_DENIED: &str = "Permission denied.";
const MESSAGE_RUNTIME_FAILED: &str = "PID 1 manager command failed.";
const MESSAGE_INBOX_FULL: &str = "PID 1 command inbox is full.";
const MESSAGE_INBOX_CLOSED: &str = "PID 1 command inbox is closed.";

/// Failure while encoding a manager result for one bounded connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pid1DbusReplyAdapterError {
    /// A connection cannot have a zero-byte outbound-frame limit.
    InvalidCapacity { capacity: usize },
    /// The checked frame would not fit in the connection's reply budget.
    ReplyTooLarge {
        frame_length: usize,
        capacity: usize,
    },
    /// The checked D-Bus encoder rejected the supplied serial or payload.
    Wire(WireError),
}

impl From<WireError> for Pid1DbusReplyAdapterError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

/// Converts one completed PID 1 command into a single bounded D-Bus frame.
///
/// The configured capacity is an explicit per-frame budget. The adapter never
/// substitutes a serial: `serial` and `reply_serial` are passed unchanged to
/// the checked wire encoder, which also rejects zero values.
#[derive(Debug, Clone, Copy)]
pub struct Pid1DbusReplyAdapter {
    capacity: usize,
}

impl Pid1DbusReplyAdapter {
    pub const fn new(capacity: usize) -> Result<Self, Pid1DbusReplyAdapterError> {
        if capacity == 0 {
            return Err(Pid1DbusReplyAdapterError::InvalidCapacity { capacity });
        }
        Ok(Self { capacity })
    }

    pub const fn capacity(self) -> usize {
        self.capacity
    }

    /// Encode one command result using the caller's exact D-Bus correlation.
    pub fn encode(
        self,
        endian: Endian,
        serial: u32,
        reply_serial: u32,
        result: Pid1CommandResult,
    ) -> Result<Vec<u8>, Pid1DbusReplyAdapterError> {
        let frame = match result {
            Ok(Pid1ManagerReply::UnitLoaded { path }) => {
                encode_text_reply(endian, serial, reply_serial, b'o', &path)
            }
            Ok(Pid1ManagerReply::JobQueued { id }) => {
                let path = format!("{JOB_PATH_PREFIX}{id}");
                encode_text_reply(endian, serial, reply_serial, b'o', &path)
            }
            Ok(Pid1ManagerReply::Completed) => encode_empty_reply(endian, serial, reply_serial),
            Err(error) => {
                let (name, message) = error_details(error);
                encode_error_reply(endian, serial, reply_serial, name, message)
            }
        }?;

        if frame.len() > self.capacity {
            return Err(Pid1DbusReplyAdapterError::ReplyTooLarge {
                frame_length: frame.len(),
                capacity: self.capacity,
            });
        }
        Ok(frame)
    }
}

fn error_details(error: Pid1CommandError) -> (&'static str, &'static str) {
    match error {
        Pid1CommandError::Unauthorized => (ERROR_ACCESS_DENIED, MESSAGE_ACCESS_DENIED),
        Pid1CommandError::Runtime(_) => (ERROR_FAILED, MESSAGE_RUNTIME_FAILED),
        Pid1CommandError::InboxFull => (ERROR_LIMITS_EXCEEDED, MESSAGE_INBOX_FULL),
        Pid1CommandError::InboxClosed => (ERROR_DISCONNECTED, MESSAGE_INBOX_CLOSED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::Errno;

    const CAPACITY: usize = 1024;

    fn u32_at(endian: Endian, bytes: &[u8], offset: usize) -> u32 {
        let bytes: [u8; 4] = bytes[offset..offset + 4].try_into().unwrap();
        match endian {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        }
    }

    fn assert_correlation(bytes: &[u8], endian: Endian, message_type: u8) {
        let marker = match endian {
            Endian::Little => b'l',
            Endian::Big => b'B',
        };
        assert_eq!(bytes[0], marker);
        assert_eq!(bytes[1], message_type);
        assert_eq!(u32_at(endian, bytes, 8), 73);
        assert!(
            bytes
                .windows(4)
                .any(|window| { u32_at(endian, window, 0) == 41 })
        );
    }

    #[test]
    fn maps_each_manager_reply_with_the_callers_correlation() {
        let adapter = Pid1DbusReplyAdapter::new(CAPACITY).unwrap();
        let loaded = adapter
            .encode(
                Endian::Little,
                73,
                41,
                Ok(Pid1ManagerReply::UnitLoaded {
                    path: "/org/freedesktop/systemd1/unit/demo_2eservice".into(),
                }),
            )
            .unwrap();
        assert_correlation(&loaded, Endian::Little, 2);
        assert!(loaded.windows(b"o\0".len()).any(|window| window == b"o\0"));
        assert!(
            loaded
                .windows(b"/org/freedesktop/systemd1/unit/demo_2eservice".len())
                .any(|window| window == b"/org/freedesktop/systemd1/unit/demo_2eservice")
        );

        let queued = adapter
            .encode(
                Endian::Big,
                73,
                41,
                Ok(Pid1ManagerReply::JobQueued { id: 27 }),
            )
            .unwrap();
        assert_correlation(&queued, Endian::Big, 2);
        assert!(
            queued
                .windows(b"/org/freedesktop/systemd1/job/27".len())
                .any(|window| window == b"/org/freedesktop/systemd1/job/27")
        );

        let completed = adapter
            .encode(Endian::Little, 73, 41, Ok(Pid1ManagerReply::Completed))
            .unwrap();
        assert_correlation(&completed, Endian::Little, 2);
        assert_eq!(u32_at(Endian::Little, &completed, 4), 0);
    }

    #[test]
    fn maps_every_command_error_to_a_typed_dbus_error() {
        let adapter = Pid1DbusReplyAdapter::new(CAPACITY).unwrap();
        for (error, name, message) in [
            (
                Pid1CommandError::Unauthorized,
                ERROR_ACCESS_DENIED,
                MESSAGE_ACCESS_DENIED,
            ),
            (
                Pid1CommandError::Runtime(Errno::ENOENT),
                ERROR_FAILED,
                MESSAGE_RUNTIME_FAILED,
            ),
            (
                Pid1CommandError::InboxFull,
                ERROR_LIMITS_EXCEEDED,
                MESSAGE_INBOX_FULL,
            ),
            (
                Pid1CommandError::InboxClosed,
                ERROR_DISCONNECTED,
                MESSAGE_INBOX_CLOSED,
            ),
        ] {
            let frame = adapter.encode(Endian::Big, 73, 41, Err(error)).unwrap();
            assert_correlation(&frame, Endian::Big, 3);
            assert!(
                frame
                    .windows(name.len())
                    .any(|window| window == name.as_bytes())
            );
            assert!(
                frame
                    .windows(message.len())
                    .any(|window| window == message.as_bytes())
            );
        }
    }

    #[test]
    fn rejects_unbounded_capacity_and_frames_without_fabricating_a_serial() {
        assert!(matches!(
            Pid1DbusReplyAdapter::new(0),
            Err(Pid1DbusReplyAdapterError::InvalidCapacity { capacity: 0 })
        ));
        let adapter = Pid1DbusReplyAdapter::new(1).unwrap();
        assert!(matches!(
            adapter.encode(Endian::Little, 73, 41, Ok(Pid1ManagerReply::Completed)),
            Err(Pid1DbusReplyAdapterError::ReplyTooLarge { capacity: 1, .. })
        ));

        let adapter = Pid1DbusReplyAdapter::new(CAPACITY).unwrap();
        assert_eq!(
            adapter.encode(Endian::Little, 0, 41, Ok(Pid1ManagerReply::Completed)),
            Err(Pid1DbusReplyAdapterError::Wire(WireError::InvalidSerial))
        );
        assert_eq!(
            adapter.encode(Endian::Little, 73, 0, Ok(Pid1ManagerReply::Completed)),
            Err(Pid1DbusReplyAdapterError::Wire(WireError::InvalidSerial))
        );
    }
}
