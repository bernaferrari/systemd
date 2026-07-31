// SPDX-License-Identifier: LGPL-2.1-or-later

//! Disconnected mapping from the checked private D-Bus wire format to PID 1 commands.
// PORT-SYNC: src/core/dbus.c (the direct private-bus manager method dispatch).
//!
//! This adapter handles the standard connection-local `Peer.Ping` and
//! `Peer.GetMachineId`, supports `Introspectable.Introspect`, and only `GetUnit`, `GetUnitByPID`,
//! `GetUnitByInvocationID`, `LoadUnit`, `StartUnit`, `StopUnit`,
//! `ReloadUnit`, `RestartUnit`, and `ResetFailed` at the manager object path.
//! It deliberately has no socket, reply, event-loop, or authorization policy:
//! callers must supply the `SenderIdentity` derived from the connection's
//! kernel credentials, and command dispatch still invokes its authorizer.
//! In particular, the D-Bus `sender` header is never consulted as identity.
//!
//! `ReloadUnit` has an `ss` D-Bus signature, but the existing typed command
//! intentionally has no job mode because its runtime operation always uses
//! `replace`. Therefore this adapter accepts `ReloadUnit` only with the
//! explicit `replace` mode instead of silently changing the request. The
//! public manager's no-argument `ResetFailed` method is deliberately mapped
//! to a distinct all-units command rather than being misrepresented as a
//! named reset.

use crate::pid1_bus_source::{Pid1BusCommandSender, Pid1BusSendError};
use crate::pid1_dbus_wire::{MethodCall, WireError};
use crate::pid1_manager_commands::{Pid1CommandReplyReceiver, Pid1ManagerCommand, SenderIdentity};
use crate::transaction::JobMode;
use systemd_libsystemd_rs::sd_id128_api::sd_id128_get_machine;
use systemd_libsystemd_rs::sd_id128_strings::sd_id128_to_string;

pub const PID1_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
pub const PID1_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
pub const DBUS_INTROSPECTABLE_INTERFACE: &str = "org.freedesktop.DBus.Introspectable";
pub const DBUS_PEER_INTERFACE: &str = "org.freedesktop.DBus.Peer";

/// Replies owned entirely by one authenticated D-Bus connection.
///
/// sd-bus handles the standard peer interface before vtable dispatch. Keeping
/// these replies distinct from [`Pid1ManagerCommand`] prevents protocol-local
/// work from consuming manager-inbox capacity or borrowing `RuntimeManager`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pid1DbusLocalReply {
    Empty,
    /// The canonical 32-digit machine ID returned by D-Bus' standard peer
    /// interface. This stays connection-local and never consumes manager
    /// command capacity.
    MachineId(String),
}

/// The checked destination of one decoded private-bus call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pid1DbusRequest {
    Local(Pid1DbusLocalReply),
    Manager(Pid1ManagerCommand),
}

/// Typed validation and bounded-ingress failures for [`Pid1DbusCommandAdapter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pid1DbusCommandAdapterError {
    WrongPath {
        actual: String,
    },
    WrongInterface {
        actual: Option<String>,
    },
    UnsupportedMember {
        member: String,
    },
    WrongSignature {
        member: String,
        expected: &'static str,
        actual: String,
    },
    InvalidPayload {
        member: String,
        cause: WireError,
    },
    InvalidJobMode {
        mode: String,
    },
    UnsupportedJobMode {
        member: String,
        mode: String,
    },
    /// Reading the local machine ID failed before any manager operation was
    /// accepted. The transport turns this into its bounded local failure
    /// reply, matching sd-bus' fallible built-in peer-method path.
    MachineIdLookup(i32),
    Ingress(Pid1BusSendError),
}

impl From<Pid1BusSendError> for Pid1DbusCommandAdapterError {
    fn from(error: Pid1BusSendError) -> Self {
        Self::Ingress(error)
    }
}

/// Convert checked manager method calls and enqueue the resulting semantic command.
///
/// Constructing this adapter does not grant authority. It only retains the
/// bounded, event-loop-waking [`Pid1BusCommandSender`] supplied by the PID 1
/// command owner. Using the wake-aware sender is required: the PID 1 loop
/// registers its eventfd, so a plain channel enqueue would otherwise leave
/// valid work sleeping until an unrelated timer or signal.
#[derive(Clone)]
pub struct Pid1DbusCommandAdapter {
    command_sender: Pid1BusCommandSender,
}

impl Pid1DbusCommandAdapter {
    pub const fn new(command_sender: Pid1BusCommandSender) -> Self {
        Self { command_sender }
    }

    /// Classify a decoded call before it crosses the manager-command seam.
    ///
    /// C's sd-bus transport consumes `org.freedesktop.DBus.Peer` itself. The
    /// Rust transport does the same for the implemented `Ping` method, on any
    /// object path, and leaves manager methods on the existing authenticated,
    /// wake-aware command path. `GetMachineId` uses the same checked,
    /// connection-local reply path as `Ping`; a lookup failure is returned to
    /// the transport before any manager work is accepted.
    pub fn request_for(call: &MethodCall) -> Result<Pid1DbusRequest, Pid1DbusCommandAdapterError> {
        if call.interface.as_deref() == Some(DBUS_PEER_INTERFACE) {
            return match call.member.as_str() {
                "Ping" => {
                    decode_no_args(call)?;
                    Ok(Pid1DbusRequest::Local(Pid1DbusLocalReply::Empty))
                }
                "GetMachineId" => {
                    decode_no_args(call)?;
                    local_machine_id_reply(sd_id128_get_machine).map(Pid1DbusRequest::Local)
                }
                _ => Err(Pid1DbusCommandAdapterError::UnsupportedMember {
                    member: call.member.clone(),
                }),
            };
        }

        Self::command_for(call).map(Pid1DbusRequest::Manager)
    }

    /// Validate and translate one already-decoded D-Bus method call.
    pub fn command_for(
        call: &MethodCall,
    ) -> Result<Pid1ManagerCommand, Pid1DbusCommandAdapterError> {
        validate_path(call)?;

        if call.interface.as_deref() == Some(DBUS_INTROSPECTABLE_INTERFACE) {
            return match call.member.as_str() {
                "Introspect" => {
                    decode_no_args(call)?;
                    Ok(Pid1ManagerCommand::Introspect)
                }
                _ => Err(Pid1DbusCommandAdapterError::UnsupportedMember {
                    member: call.member.clone(),
                }),
            };
        }

        validate_manager_interface(call)?;

        match call.member.as_str() {
            "GetUnit" => Ok(Pid1ManagerCommand::GetUnit {
                name: decode_one_string(call)?,
            }),
            "GetUnitByPID" => Ok(Pid1ManagerCommand::GetUnitByPid {
                pid: decode_one_u32(call)?,
            }),
            "GetUnitByInvocationID" => Ok(Pid1ManagerCommand::GetUnitByInvocationId {
                invocation_id: decode_invocation_id(call)?,
            }),
            "LoadUnit" => Ok(Pid1ManagerCommand::LoadUnit {
                name: decode_one_string(call)?,
            }),
            "StartUnit" => {
                let (name, mode) = decode_unit_and_mode(call)?;
                Ok(Pid1ManagerCommand::StartUnit { name, mode })
            }
            "StopUnit" => {
                let (name, mode) = decode_unit_and_mode(call)?;
                Ok(Pid1ManagerCommand::StopUnit { name, mode })
            }
            "ReloadUnit" => {
                let (name, mode) = decode_unit_and_mode(call)?;
                if mode != JobMode::Replace {
                    return Err(Pid1DbusCommandAdapterError::UnsupportedJobMode {
                        member: call.member.clone(),
                        mode: job_mode_name(mode).to_string(),
                    });
                }
                Ok(Pid1ManagerCommand::ReloadUnit { name })
            }
            "RestartUnit" => {
                let (name, mode) = decode_unit_and_mode(call)?;
                Ok(Pid1ManagerCommand::RestartUnit { name, mode })
            }
            "ResetFailed" => {
                decode_no_args(call)?;
                Ok(Pid1ManagerCommand::ResetAllFailed)
            }
            _ => Err(Pid1DbusCommandAdapterError::UnsupportedMember {
                member: call.member.clone(),
            }),
        }
    }

    /// Enqueue a validated manager operation without inspecting or replacing
    /// the caller's kernel-derived identity.
    pub fn try_send(
        &self,
        sender: SenderIdentity,
        call: &MethodCall,
    ) -> Result<Pid1CommandReplyReceiver, Pid1DbusCommandAdapterError> {
        let command = Self::command_for(call)?;
        self.try_send_command(sender, command)
    }

    /// Enqueue a command which has already passed [`Self::command_for`].
    ///
    /// This is the narrow handoff used by a wire-slot dispatcher: it first
    /// validates the decoded call and reserves reply correlation, then submits
    /// this semantic command without decoding the same peer-controlled body a
    /// second time. This method is not an authorization bypass: the manager
    /// inbox still authorizes the supplied kernel-derived identity when it
    /// owns and executes the command.
    pub(crate) fn try_send_command(
        &self,
        sender: SenderIdentity,
        command: Pid1ManagerCommand,
    ) -> Result<Pid1CommandReplyReceiver, Pid1DbusCommandAdapterError> {
        self.command_sender
            .try_send(sender, command)
            .map_err(Into::into)
    }
}

fn local_machine_id_reply(
    lookup: impl FnOnce() -> Result<systemd_libsystemd_rs::id128_util::SdId128, i32>,
) -> Result<Pid1DbusLocalReply, Pid1DbusCommandAdapterError> {
    lookup()
        .map(sd_id128_to_string)
        .map(Pid1DbusLocalReply::MachineId)
        .map_err(Pid1DbusCommandAdapterError::MachineIdLookup)
}

fn validate_path(call: &MethodCall) -> Result<(), Pid1DbusCommandAdapterError> {
    if call.path != PID1_MANAGER_PATH {
        return Err(Pid1DbusCommandAdapterError::WrongPath {
            actual: call.path.clone(),
        });
    }
    Ok(())
}

fn validate_manager_interface(call: &MethodCall) -> Result<(), Pid1DbusCommandAdapterError> {
    if call.interface.as_deref() != Some(PID1_MANAGER_INTERFACE) {
        return Err(Pid1DbusCommandAdapterError::WrongInterface {
            actual: call.interface.clone(),
        });
    }
    Ok(())
}

fn decode_one_string(call: &MethodCall) -> Result<String, Pid1DbusCommandAdapterError> {
    require_signature(call, "s")?;
    call.decode_one_string()
        .map_err(|cause| Pid1DbusCommandAdapterError::InvalidPayload {
            member: call.member.clone(),
            cause,
        })
}

fn decode_one_u32(call: &MethodCall) -> Result<u32, Pid1DbusCommandAdapterError> {
    require_signature(call, "u")?;
    call.decode_one_u32()
        .map_err(|cause| Pid1DbusCommandAdapterError::InvalidPayload {
            member: call.member.clone(),
            cause,
        })
}

fn decode_invocation_id(call: &MethodCall) -> Result<[u8; 16], Pid1DbusCommandAdapterError> {
    require_signature(call, "ay")?;
    let bytes = call.decode_one_byte_array().map_err(|cause| {
        Pid1DbusCommandAdapterError::InvalidPayload {
            member: call.member.clone(),
            cause,
        }
    })?;
    bytes
        .try_into()
        .map_err(|_| Pid1DbusCommandAdapterError::InvalidPayload {
            member: call.member.clone(),
            cause: WireError::InvalidBody,
        })
}

fn decode_no_args(call: &MethodCall) -> Result<(), Pid1DbusCommandAdapterError> {
    require_signature(call, "")?;
    call.decode_no_args()
        .map_err(|cause| Pid1DbusCommandAdapterError::InvalidPayload {
            member: call.member.clone(),
            cause,
        })
}

fn decode_unit_and_mode(
    call: &MethodCall,
) -> Result<(String, JobMode), Pid1DbusCommandAdapterError> {
    require_signature(call, "ss")?;
    let (name, mode) =
        call.decode_two_strings()
            .map_err(|cause| Pid1DbusCommandAdapterError::InvalidPayload {
                member: call.member.clone(),
                cause,
            })?;
    let mode = parse_job_mode(&mode).ok_or(Pid1DbusCommandAdapterError::InvalidJobMode { mode })?;
    Ok((name, mode))
}

fn require_signature(
    call: &MethodCall,
    expected: &'static str,
) -> Result<(), Pid1DbusCommandAdapterError> {
    if call.signature == expected {
        return Ok(());
    }
    Err(Pid1DbusCommandAdapterError::WrongSignature {
        member: call.member.clone(),
        expected,
        actual: call.signature.clone(),
    })
}

fn parse_job_mode(mode: &str) -> Option<JobMode> {
    Some(match mode {
        "replace" => JobMode::Replace,
        "replace-irreversibly" => JobMode::ReplaceIrreversibly,
        "fail" => JobMode::Fail,
        "isolate" => JobMode::Isolate,
        "flush" => JobMode::Flush,
        "ignore-dependencies" => JobMode::IgnoreDependencies,
        "ignore-requirements" => JobMode::IgnoreRequirements,
        "triggering" => JobMode::Triggering,
        "restart-dependencies" => JobMode::RestartDependencies,
        _ => return None,
    })
}

fn job_mode_name(mode: JobMode) -> &'static str {
    match mode {
        JobMode::Replace => "replace",
        JobMode::ReplaceIrreversibly => "replace-irreversibly",
        JobMode::Fail => "fail",
        JobMode::Lenient => "lenient",
        JobMode::Isolate => "isolate",
        JobMode::Flush => "flush",
        JobMode::IgnoreDependencies => "ignore-dependencies",
        JobMode::IgnoreRequirements => "ignore-requirements",
        JobMode::Triggering => "triggering",
        JobMode::RestartDependencies => "restart-dependencies",
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;
    use crate::pid1_bus_source::pid1_bus_command_channel;
    use crate::pid1_dbus_wire::{Endian, decode_method_call};
    use crate::pid1_manager_commands::{
        AuthenticatedPeer, Pid1CommandAuthorizer, Pid1CommandError,
    };
    use crate::runtime_manager::RuntimeManager;

    fn push_padding(bytes: &mut Vec<u8>, alignment: usize) {
        let aligned = (bytes.len() + alignment - 1) & !(alignment - 1);
        bytes.resize(aligned, 0);
    }

    fn push_text(endian: Endian, bytes: &mut Vec<u8>, value: &str, signature: bool) {
        if signature {
            bytes.push(u8::try_from(value.len()).unwrap());
        } else {
            push_padding(bytes, 4);
            bytes.extend_from_slice(&match endian {
                Endian::Little => u32::try_from(value.len()).unwrap().to_le_bytes(),
                Endian::Big => u32::try_from(value.len()).unwrap().to_be_bytes(),
            });
        }
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }

    fn push_header(endian: Endian, fields: &mut Vec<u8>, code: u8, kind: u8, value: &str) {
        push_padding(fields, 8);
        fields.extend_from_slice(&[code, 1, kind, 0]);
        push_text(endian, fields, value, kind == b'g');
    }

    fn call(member: &str, signature: &str, values: &[&str]) -> MethodCall {
        let endian = Endian::Little;
        let mut fields = Vec::new();
        push_header(endian, &mut fields, 1, b'o', PID1_MANAGER_PATH);
        push_header(endian, &mut fields, 2, b's', PID1_MANAGER_INTERFACE);
        push_header(endian, &mut fields, 3, b's', member);
        if !signature.is_empty() {
            push_header(endian, &mut fields, 8, b'g', signature);
        }
        let mut body = Vec::new();
        for value in values {
            push_text(endian, &mut body, value, false);
        }
        let mut bytes = vec![b'l', 1, 0, 1];
        bytes.extend_from_slice(&(u32::try_from(body.len()).unwrap()).to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&(u32::try_from(fields.len()).unwrap()).to_le_bytes());
        bytes.extend_from_slice(&fields);
        push_padding(&mut bytes, 8);
        bytes.extend_from_slice(&body);
        decode_method_call(&bytes).unwrap().unwrap().0
    }

    fn pid_call(member: &str, pid: u32) -> MethodCall {
        let endian = Endian::Little;
        let mut fields = Vec::new();
        push_header(endian, &mut fields, 1, b'o', PID1_MANAGER_PATH);
        push_header(endian, &mut fields, 2, b's', PID1_MANAGER_INTERFACE);
        push_header(endian, &mut fields, 3, b's', member);
        push_header(endian, &mut fields, 8, b'g', "u");
        let body = pid.to_le_bytes();
        let mut bytes = vec![b'l', 1, 0, 1];
        bytes.extend_from_slice(&(u32::try_from(body.len()).unwrap()).to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&(u32::try_from(fields.len()).unwrap()).to_le_bytes());
        bytes.extend_from_slice(&fields);
        push_padding(&mut bytes, 8);
        bytes.extend_from_slice(&body);
        decode_method_call(&bytes).unwrap().unwrap().0
    }

    fn invocation_id_call(invocation_id: [u8; 16]) -> MethodCall {
        let endian = Endian::Little;
        let mut fields = Vec::new();
        push_header(endian, &mut fields, 1, b'o', PID1_MANAGER_PATH);
        push_header(endian, &mut fields, 2, b's', PID1_MANAGER_INTERFACE);
        push_header(endian, &mut fields, 3, b's', "GetUnitByInvocationID");
        push_header(endian, &mut fields, 8, b'g', "ay");
        let mut body = Vec::with_capacity(4 + invocation_id.len());
        body.extend_from_slice(&(invocation_id.len() as u32).to_le_bytes());
        body.extend_from_slice(&invocation_id);
        let mut bytes = vec![b'l', 1, 0, 1];
        bytes.extend_from_slice(&(u32::try_from(body.len()).unwrap()).to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&(u32::try_from(fields.len()).unwrap()).to_le_bytes());
        bytes.extend_from_slice(&fields);
        push_padding(&mut bytes, 8);
        bytes.extend_from_slice(&body);
        decode_method_call(&bytes).unwrap().unwrap().0
    }

    #[test]
    fn maps_the_bounded_manager_method_subset() {
        assert_eq!(
            Pid1DbusCommandAdapter::command_for(&call("Introspect", "", &[])),
            Err(Pid1DbusCommandAdapterError::UnsupportedMember {
                member: "Introspect".into(),
            })
        );
        let mut introspect = call("Introspect", "", &[]);
        introspect.interface = Some(DBUS_INTROSPECTABLE_INTERFACE.into());
        assert_eq!(
            Pid1DbusCommandAdapter::command_for(&introspect),
            Ok(Pid1ManagerCommand::Introspect)
        );
        assert_eq!(
            Pid1DbusCommandAdapter::command_for(&call("GetUnit", "s", &["a.service"])),
            Ok(Pid1ManagerCommand::GetUnit {
                name: "a.service".into()
            })
        );
        assert_eq!(
            Pid1DbusCommandAdapter::command_for(&pid_call("GetUnitByPID", 42)),
            Ok(Pid1ManagerCommand::GetUnitByPid { pid: 42 })
        );
        assert_eq!(
            Pid1DbusCommandAdapter::command_for(&invocation_id_call([0x42; 16])),
            Ok(Pid1ManagerCommand::GetUnitByInvocationId {
                invocation_id: [0x42; 16],
            })
        );
        assert_eq!(
            Pid1DbusCommandAdapter::command_for(&call("LoadUnit", "s", &["a.service"])),
            Ok(Pid1ManagerCommand::LoadUnit {
                name: "a.service".into()
            })
        );
        assert_eq!(
            Pid1DbusCommandAdapter::command_for(&call("StartUnit", "ss", &["a.service", "fail"])),
            Ok(Pid1ManagerCommand::StartUnit {
                name: "a.service".into(),
                mode: JobMode::Fail
            })
        );
        assert_eq!(
            Pid1DbusCommandAdapter::command_for(&call("StopUnit", "ss", &["a.service", "flush"])),
            Ok(Pid1ManagerCommand::StopUnit {
                name: "a.service".into(),
                mode: JobMode::Flush
            })
        );
        assert_eq!(
            Pid1DbusCommandAdapter::command_for(&call(
                "ReloadUnit",
                "ss",
                &["a.service", "replace"]
            )),
            Ok(Pid1ManagerCommand::ReloadUnit {
                name: "a.service".into()
            })
        );
        assert_eq!(
            Pid1DbusCommandAdapter::command_for(&call(
                "RestartUnit",
                "ss",
                &["a.service", "restart-dependencies"]
            )),
            Ok(Pid1ManagerCommand::RestartUnit {
                name: "a.service".into(),
                mode: JobMode::RestartDependencies
            })
        );
        assert_eq!(
            Pid1DbusCommandAdapter::command_for(&call("ResetFailed", "", &[])),
            Ok(Pid1ManagerCommand::ResetAllFailed)
        );
    }

    #[test]
    fn classifies_peer_ping_as_connection_local_on_any_object_path() {
        let mut ping = call("Ping", "", &[]);
        ping.interface = Some(DBUS_PEER_INTERFACE.into());
        ping.path = "/arbitrary/peer/object".into();
        assert_eq!(
            Pid1DbusCommandAdapter::request_for(&ping),
            Ok(Pid1DbusRequest::Local(Pid1DbusLocalReply::Empty))
        );

        let mut invalid = ping.clone();
        invalid.signature = "s".into();
        assert!(matches!(
            Pid1DbusCommandAdapter::request_for(&invalid),
            Err(Pid1DbusCommandAdapterError::WrongSignature {
                member,
                expected: "",
                actual,
            }) if member == "Ping" && actual == "s"
        ));

        let mut get_machine_id = ping;
        get_machine_id.member = "GetMachineId".into();
        assert_eq!(
            local_machine_id_reply(|| {
                Ok(systemd_libsystemd_rs::id128_util::SdId128([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10,
                ]))
            }),
            Ok(Pid1DbusLocalReply::MachineId(
                "0102030405060708090a0b0c0d0e0f10".into()
            ))
        );
        assert_eq!(
            local_machine_id_reply(|| Err(-libc::EIO)),
            Err(Pid1DbusCommandAdapterError::MachineIdLookup(-libc::EIO))
        );

        // The externally visible request path uses the same fallible local
        // helper. Do not assert the host's actual machine ID in this unit
        // test; the formatter/lookup contract above is deterministic.
        let request = Pid1DbusCommandAdapter::request_for(&get_machine_id);
        assert!(
            matches!(
                &request,
                Ok(Pid1DbusRequest::Local(Pid1DbusLocalReply::MachineId(value)))
                    if value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            ) || matches!(
                &request,
                Err(Pid1DbusCommandAdapterError::MachineIdLookup(_))
            )
        );
    }

    #[test]
    fn rejects_wrong_endpoint_signature_member_and_mode() {
        let mut wrong_path = call("LoadUnit", "s", &["a.service"]);
        wrong_path.path = "/wrong".into();
        assert!(matches!(
            Pid1DbusCommandAdapter::command_for(&wrong_path),
            Err(Pid1DbusCommandAdapterError::WrongPath { .. })
        ));
        let mut wrong_interface = call("LoadUnit", "s", &["a.service"]);
        wrong_interface.interface = None;
        assert!(matches!(
            Pid1DbusCommandAdapter::command_for(&wrong_interface),
            Err(Pid1DbusCommandAdapterError::WrongInterface { .. })
        ));
        assert!(matches!(
            Pid1DbusCommandAdapter::command_for(&call("LoadUnit", "ss", &["a", "replace"])),
            Err(Pid1DbusCommandAdapterError::WrongSignature { .. })
        ));
        assert!(matches!(
            Pid1DbusCommandAdapter::command_for(&call("Nope", "", &[])),
            Err(Pid1DbusCommandAdapterError::UnsupportedMember { .. })
        ));
        assert!(matches!(
            Pid1DbusCommandAdapter::command_for(&call("StartUnit", "ss", &["a", "nope"])),
            Err(Pid1DbusCommandAdapterError::InvalidJobMode { .. })
        ));
        assert!(matches!(
            Pid1DbusCommandAdapter::command_for(&call("ReloadUnit", "ss", &["a", "fail"])),
            Err(Pid1DbusCommandAdapterError::UnsupportedJobMode { .. })
        ));
        assert!(matches!(
            Pid1DbusCommandAdapter::command_for(&call("ResetFailed", "s", &["unexpected"])),
            Err(Pid1DbusCommandAdapterError::WrongSignature { .. })
        ));
        let mut introspect_with_body = call("Introspect", "s", &["unexpected"]);
        introspect_with_body.interface = Some(DBUS_INTROSPECTABLE_INTERFACE.into());
        assert!(matches!(
            Pid1DbusCommandAdapter::command_for(&introspect_with_body),
            Err(Pid1DbusCommandAdapterError::WrongSignature { .. })
        ));
    }

    #[derive(Default)]
    struct CaptureAuthorizer {
        sender: Option<SenderIdentity>,
    }

    impl Pid1CommandAuthorizer for CaptureAuthorizer {
        fn authorize(
            &mut self,
            sender: SenderIdentity,
            _: &Pid1ManagerCommand,
        ) -> Result<(), Pid1CommandError> {
            self.sender = Some(sender);
            Err(Pid1CommandError::Unauthorized)
        }
    }

    #[test]
    fn sending_preserves_the_kernel_identity_not_the_wire_sender() {
        let (command_sender, mut inbox) =
            pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
        let adapter = Pid1DbusCommandAdapter::new(command_sender);
        let identity = SenderIdentity::from_authenticated_peer(
            AuthenticatedPeer::from_kernel_peer_credentials(42, 1000, 1001),
        );
        let mut wire_call = call("LoadUnit", "s", &["missing.service"]);
        wire_call.sender = Some(":123.456".into());
        let reply = adapter.try_send(identity, &wire_call).unwrap();
        let mut authorizer = CaptureAuthorizer::default();
        let mut runtime = RuntimeManager::new();

        #[cfg(target_os = "linux")]
        {
            use systemd_event_loop_rs::loop_::EventLoop;

            let mut event_loop = EventLoop::new().unwrap();
            inbox.register(&mut event_loop).unwrap();
            assert_eq!(event_loop.run_once(0), Ok(true));
            assert_eq!(
                inbox
                    .dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap())
                    .unwrap()
                    .dispatched,
                1
            );
            assert_eq!(event_loop.run_once(0), Ok(false));
        }

        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            inbox
                .dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap())
                .unwrap()
                .dispatched,
            1
        );
        assert_eq!(authorizer.sender, Some(identity));
        assert_eq!(reply.try_recv(), Ok(Err(Pid1CommandError::Unauthorized)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejected_wire_call_does_not_make_the_pid1_event_loop_runnable() {
        use systemd_event_loop_rs::loop_::EventLoop;

        let (command_sender, inbox) =
            pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
        let adapter = Pid1DbusCommandAdapter::new(command_sender);
        let mut wrong_path = call("LoadUnit", "s", &["a.service"]);
        wrong_path.path = "/wrong".into();
        assert!(matches!(
            adapter.try_send(
                SenderIdentity::from_authenticated_peer(
                    AuthenticatedPeer::from_kernel_peer_credentials(1, 0, 0),
                ),
                &wrong_path,
            ),
            Err(Pid1DbusCommandAdapterError::WrongPath { .. })
        ));

        let mut event_loop = EventLoop::new().unwrap();
        inbox.register(&mut event_loop).unwrap();
        assert_eq!(event_loop.run_once(0), Ok(false));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn full_inbox_rejection_rolls_back_the_adapter_wake_token() {
        use systemd_event_loop_rs::loop_::EventLoop;

        let (command_sender, mut inbox) =
            pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
        let adapter = Pid1DbusCommandAdapter::new(command_sender);
        let identity = SenderIdentity::from_authenticated_peer(
            AuthenticatedPeer::from_kernel_peer_credentials(1, 0, 0),
        );
        let first = adapter.try_send(identity, &call("LoadUnit", "s", &["one.service"]));
        assert!(first.is_ok());
        assert!(matches!(
            adapter.try_send(identity, &call("LoadUnit", "s", &["two.service"])),
            Err(Pid1DbusCommandAdapterError::Ingress(
                Pid1BusSendError::Command(Pid1CommandError::InboxFull)
            ))
        ));

        let mut event_loop = EventLoop::new().unwrap();
        inbox.register(&mut event_loop).unwrap();
        assert_eq!(event_loop.run_once(0), Ok(true));

        let mut runtime = RuntimeManager::new();
        let mut authorizer = CaptureAuthorizer::default();
        let _ = inbox
            .dispatch_pending(&mut runtime, &mut authorizer, NonZeroUsize::new(1).unwrap())
            .unwrap();
        assert_eq!(event_loop.run_once(0), Ok(false));
    }
}
