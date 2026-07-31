// SPDX-License-Identifier: LGPL-2.1-or-later

// PORT-SYNC: src/core/dbus.c (direct private-bus method replies).

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
const ERROR_NO_SUCH_UNIT: &str = "org.freedesktop.systemd1.NoSuchUnit";
const ERROR_NO_UNIT_FOR_PID: &str = "org.freedesktop.systemd1.NoUnitForPID";
const ERROR_NO_UNIT_FOR_INVOCATION_ID: &str = "org.freedesktop.systemd1.NoUnitForInvocationID";

const MESSAGE_ACCESS_DENIED: &str = "Permission denied.";
const MESSAGE_RUNTIME_FAILED: &str = "PID 1 manager command failed.";
const MESSAGE_INBOX_FULL: &str = "PID 1 command inbox is full.";
const MESSAGE_INBOX_CLOSED: &str = "PID 1 command inbox is closed.";

/// The bounded developer-shadow interface exposed by `Introspect`.
///
/// This is deliberately not a copy of the production C vtable: it advertises
/// only a bounded subset of the disconnected Rust private-bus seam. In
/// particular, it must not grow a `Properties` declaration before a checked
/// property-value/result encoder exists.
const PID1_SHADOW_INTROSPECTION_XML: &str = concat!(
    "<node>",
    "<interface name=\"org.freedesktop.DBus.Introspectable\">",
    "<method name=\"Introspect\"/>",
    "</interface>",
    "<interface name=\"org.freedesktop.DBus.Peer\">",
    "<method name=\"Ping\"/>",
    "<method name=\"GetMachineId\"><arg type=\"s\" name=\"machine_uuid\" direction=\"out\"/></method>",
    "</interface>",
    "<interface name=\"org.freedesktop.systemd1.Manager\">",
    "<method name=\"GetUnit\"/><method name=\"GetUnitByPID\"/>",
    "<method name=\"GetUnitByInvocationID\"/><method name=\"LoadUnit\"/>",
    "<method name=\"StartUnit\"/><method name=\"StopUnit\"/>",
    "<method name=\"ReloadUnit\"/><method name=\"RestartUnit\"/>",
    "<method name=\"ResetFailedUnit\"/>",
    "<method name=\"ResetFailed\"/>",
    "</interface>",
    "</node>"
);

/// A checked D-Bus error generated before a manager command is accepted.
///
/// These errors are deliberately narrower than systemd's full sd-bus error
/// surface. They let the private wire reject a decoded manager request with
/// reliable correlation, without pretending to provide the complete manager
/// vtable or property contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pid1DbusProtocolError {
    UnknownMethod,
    UnknownObject,
    UnknownInterface,
    InvalidArgs,
    LimitsExceeded,
    Disconnected,
    Failed,
}

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
            Ok(Pid1ManagerReply::IntrospectionXml) => encode_text_reply(
                endian,
                serial,
                reply_serial,
                b's',
                PID1_SHADOW_INTROSPECTION_XML,
            ),
            Ok(Pid1ManagerReply::UnitLoaded { path }) => {
                encode_text_reply(endian, serial, reply_serial, b'o', &path)
            }
            Ok(Pid1ManagerReply::JobQueued { id }) => {
                let path = format!("{JOB_PATH_PREFIX}{id}");
                encode_text_reply(endian, serial, reply_serial, b'o', &path)
            }
            Ok(Pid1ManagerReply::Completed) => encode_empty_reply(endian, serial, reply_serial),
            Err(Pid1CommandError::NoSuchUnit { name }) => {
                let message = format!("Unit {name} not loaded.");
                encode_error_reply(endian, serial, reply_serial, ERROR_NO_SUCH_UNIT, &message)
            }
            Err(Pid1CommandError::NoUnitForPid { pid }) => {
                let message = format!("PID {pid} does not belong to any loaded unit.");
                encode_error_reply(
                    endian,
                    serial,
                    reply_serial,
                    ERROR_NO_UNIT_FOR_PID,
                    &message,
                )
            }
            Err(Pid1CommandError::NoUnitForInvocationId { invocation_id }) => {
                let id = invocation_id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let message = format!("No unit with the specified invocation ID {id} known.");
                encode_error_reply(
                    endian,
                    serial,
                    reply_serial,
                    ERROR_NO_UNIT_FOR_INVOCATION_ID,
                    &message,
                )
            }
            Err(Pid1CommandError::NoUnitForCallerPid { pid }) => {
                let message = format!("Client {pid} not member of any unit.");
                encode_error_reply(endian, serial, reply_serial, ERROR_NO_SUCH_UNIT, &message)
            }
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

    /// Encode one bounded local protocol rejection using the caller's exact
    /// D-Bus serial correlation. Unlike [`Self::encode`], this never accepts
    /// or waits for manager work.
    pub fn encode_protocol_error(
        self,
        endian: Endian,
        serial: u32,
        reply_serial: u32,
        error: Pid1DbusProtocolError,
    ) -> Result<Vec<u8>, Pid1DbusReplyAdapterError> {
        let (name, message) = protocol_error_details(error);
        let frame = encode_error_reply(endian, serial, reply_serial, name, message)?;
        if frame.len() > self.capacity {
            return Err(Pid1DbusReplyAdapterError::ReplyTooLarge {
                frame_length: frame.len(),
                capacity: self.capacity,
            });
        }
        Ok(frame)
    }

    /// Encode the string reply used by standard connection-local D-Bus peer
    /// methods. This intentionally bypasses manager-result typing: the
    /// caller has not accepted manager work and must preserve that fact.
    pub fn encode_local_text_reply(
        self,
        endian: Endian,
        serial: u32,
        reply_serial: u32,
        value: &str,
    ) -> Result<Vec<u8>, Pid1DbusReplyAdapterError> {
        let frame = encode_text_reply(endian, serial, reply_serial, b's', value)?;
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
        Pid1CommandError::NoSuchUnit { .. } => unreachable!("handled with its unit name"),
        Pid1CommandError::NoUnitForPid { .. } => unreachable!("handled with its PID"),
        Pid1CommandError::NoUnitForInvocationId { .. } => {
            unreachable!("handled with its invocation ID")
        }
        Pid1CommandError::NoUnitForCallerPid { .. } => {
            unreachable!("handled with its caller PID")
        }
        Pid1CommandError::Runtime(_) => (ERROR_FAILED, MESSAGE_RUNTIME_FAILED),
        Pid1CommandError::InboxFull => (ERROR_LIMITS_EXCEEDED, MESSAGE_INBOX_FULL),
        Pid1CommandError::InboxClosed => (ERROR_DISCONNECTED, MESSAGE_INBOX_CLOSED),
    }
}

fn protocol_error_details(error: Pid1DbusProtocolError) -> (&'static str, &'static str) {
    match error {
        Pid1DbusProtocolError::UnknownMethod => (
            "org.freedesktop.DBus.Error.UnknownMethod",
            "Unknown manager method.",
        ),
        Pid1DbusProtocolError::UnknownObject => (
            "org.freedesktop.DBus.Error.UnknownObject",
            "Unknown manager object path.",
        ),
        Pid1DbusProtocolError::UnknownInterface => (
            "org.freedesktop.DBus.Error.UnknownInterface",
            "Unknown manager interface.",
        ),
        Pid1DbusProtocolError::InvalidArgs => (
            "org.freedesktop.DBus.Error.InvalidArgs",
            "Invalid manager method arguments.",
        ),
        Pid1DbusProtocolError::LimitsExceeded => (
            "org.freedesktop.DBus.Error.LimitsExceeded",
            "PID 1 command inbox is full.",
        ),
        Pid1DbusProtocolError::Disconnected => (
            "org.freedesktop.DBus.Error.Disconnected",
            "PID 1 command inbox is closed.",
        ),
        Pid1DbusProtocolError::Failed => (
            "org.freedesktop.DBus.Error.Failed",
            "PID 1 could not accept the manager command.",
        ),
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
        let introspection = adapter
            .encode(
                Endian::Little,
                73,
                41,
                Ok(Pid1ManagerReply::IntrospectionXml),
            )
            .unwrap();
        assert_correlation(&introspection, Endian::Little, 2);
        assert!(
            introspection
                .windows(b"s\0".len())
                .any(|window| window == b"s\0")
        );
        assert!(
            introspection
                .windows(b"org.freedesktop.DBus.Introspectable".len())
                .any(|window| window == b"org.freedesktop.DBus.Introspectable")
        );
        assert!(
            introspection
                .windows(b"<method name=\"ResetFailed\"/>".len())
                .any(|window| window == b"<method name=\"ResetFailed\"/>")
        );
        assert!(
            introspection
                .windows(b"<method name=\"ResetFailedUnit\"/>".len())
                .any(|window| window == b"<method name=\"ResetFailedUnit\"/>")
        );
        assert!(
            introspection
                .windows(b"org.freedesktop.DBus.Properties".len())
                .all(|window| window != b"org.freedesktop.DBus.Properties")
        );
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
                Pid1CommandError::NoSuchUnit {
                    name: "missing.service".into(),
                },
                ERROR_NO_SUCH_UNIT,
                "Unit missing.service not loaded.",
            ),
            (
                Pid1CommandError::NoUnitForPid { pid: 4242 },
                ERROR_NO_UNIT_FOR_PID,
                "PID 4242 does not belong to any loaded unit.",
            ),
            (
                Pid1CommandError::NoUnitForInvocationId {
                    invocation_id: [0x42; 16],
                },
                ERROR_NO_UNIT_FOR_INVOCATION_ID,
                "No unit with the specified invocation ID 42424242424242424242424242424242 known.",
            ),
            (
                Pid1CommandError::NoUnitForCallerPid { pid: 4242 },
                ERROR_NO_SUCH_UNIT,
                "Client 4242 not member of any unit.",
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

    #[test]
    fn encodes_local_protocol_rejections_with_exact_correlation() {
        let adapter = Pid1DbusReplyAdapter::new(CAPACITY).unwrap();
        for (error, name) in [
            (
                Pid1DbusProtocolError::UnknownMethod,
                "org.freedesktop.DBus.Error.UnknownMethod",
            ),
            (
                Pid1DbusProtocolError::UnknownObject,
                "org.freedesktop.DBus.Error.UnknownObject",
            ),
            (
                Pid1DbusProtocolError::UnknownInterface,
                "org.freedesktop.DBus.Error.UnknownInterface",
            ),
            (
                Pid1DbusProtocolError::InvalidArgs,
                "org.freedesktop.DBus.Error.InvalidArgs",
            ),
            (
                Pid1DbusProtocolError::LimitsExceeded,
                "org.freedesktop.DBus.Error.LimitsExceeded",
            ),
            (
                Pid1DbusProtocolError::Disconnected,
                "org.freedesktop.DBus.Error.Disconnected",
            ),
            (
                Pid1DbusProtocolError::Failed,
                "org.freedesktop.DBus.Error.Failed",
            ),
        ] {
            let frame = adapter
                .encode_protocol_error(Endian::Little, 73, 41, error)
                .unwrap();
            assert_correlation(&frame, Endian::Little, 3);
            assert!(
                frame
                    .windows(name.len())
                    .any(|window| window == name.as_bytes())
            );
        }
    }
}
