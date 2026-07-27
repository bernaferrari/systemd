// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bus-util.c, src/shared/bus-util.h
//
// General D-Bus utility functions.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use crate::ffi::Errno;

const SD_BUS_ERROR_SERVICE_UNKNOWN: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
const SD_BUS_ERROR_NAME_HAS_NO_OWNER: &str = "org.freedesktop.DBus.Error.NameHasNoOwner";
const BUS_ERROR_NO_SUCH_UNIT: &str = "org.freedesktop.systemd1.NoSuchUnit";

const SD_BUS_ERROR_NO_REPLY: &str = "org.freedesktop.DBus.Error.NoReply";
const SD_BUS_ERROR_DISCONNECTED: &str = "org.freedesktop.DBus.Error.Disconnected";
const SD_BUS_ERROR_TIMED_OUT: &str = "org.freedesktop.DBus.Error.TimedOut";

pub const SYSTEM_SYSTEMD_ADDRESS: &str = "unix:path=/run/systemd/private";
pub const DEFAULT_SYSTEM_BUS_ADDRESS: &str = "unix:path=/run/dbus/system_bus_socket";

static UNKNOWN_SERVICE_ERRORS: &[&str] = &[
    SD_BUS_ERROR_SERVICE_UNKNOWN,
    SD_BUS_ERROR_NAME_HAS_NO_OWNER,
    BUS_ERROR_NO_SUCH_UNIT,
];

static CONNECTION_ERRORS: &[&str] = &[
    SD_BUS_ERROR_NO_REPLY,
    SD_BUS_ERROR_DISCONNECTED,
    SD_BUS_ERROR_TIMED_OUT,
];

static IDLE_ALLOWED: OnceLock<bool> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BusTransport {
    Local,
    Remote,
    Machine,
    Capsule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeScope {
    User,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusLogLevel {
    Debug,
    Error,
    Custom(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventState {
    Initial,
    Running,
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusLogRecord {
    pub level: BusLogLevel,
    pub errno: i32,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniquePathParts {
    pub sender: String,
    pub external: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleSocket {
    pub path: String,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleAddress {
    pub address: String,
    pub pinned_socket: CapsuleSocket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncUnregisterPlan {
    pub release_name: String,
    pub match_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemWatchBind {
    pub address: String,
    pub description: Option<String>,
    pub watch_bind: bool,
    pub connected_signal: bool,
    pub negotiate_creds: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidRef {
    pub pid: u32,
    pub fd: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusCreds {
    pub pid: u32,
    pub pidfd: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusMessage {
    pub sender: String,
    pub creds: Option<BusCreds>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BusTracker {
    names: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionKind {
    DefaultUser,
    DefaultSystem,
    RemoteSystem { host: String },
    UserMachine { host: String },
    SystemMachine { host: String },
    Address { address: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusConnectionRequest {
    pub kind: ConnectionKind,
    pub exit_on_disconnect: bool,
    pub check_peercred: bool,
    pub bus_client: bool,
}

pub trait EventLoopController {
    fn state(&self) -> Result<EventState, Errno>;
    fn pending_method_calls(&self) -> usize;
    fn run(&mut self, timeout: u64) -> Result<(), Errno>;
    fn unregister_and_exit(&mut self, name: &str) -> Result<(), Errno>;
    fn notify_stopping(&mut self);
    fn exit_code(&self) -> Result<i32, Errno>;
}

impl BusTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Machine => "machine",
            Self::Capsule => "capsule",
        }
    }
}

pub fn name_owner_change_callback() -> bool {
    true
}

pub fn idle_allowed() -> bool {
    *IDLE_ALLOWED.get_or_init(|| {
        idle_allowed_from_env(std::env::var("SYSTEMD_EXIT_ON_IDLE").ok().as_deref())
    })
}

pub fn idle_allowed_from_env(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(value) => parse_env_bool(value).unwrap_or(true),
    }
}

pub fn pin_capsule_socket(
    capsule: &str,
    suffix: &str,
    uid: u32,
    gid: u32,
) -> Result<CapsuleSocket, Errno> {
    if !capsule_name_is_valid(capsule) || suffix.is_empty() || suffix.starts_with('/') {
        return Err(Errno::EINVAL);
    }

    Ok(CapsuleSocket {
        path: format!("/run/capsules/{capsule}/{suffix}"),
        uid,
        gid,
    })
}

pub fn bus_set_address_capsule(capsule: &str, suffix: &str) -> Result<CapsuleAddress, Errno> {
    let pinned_socket = pin_capsule_socket(capsule, suffix, 0, 0)?;
    let escaped = bus_address_escape(&pinned_socket.path);

    Ok(CapsuleAddress {
        address: format!(
            "unix:path={escaped},uid={},gid={}",
            pinned_socket.uid, pinned_socket.gid
        ),
        pinned_socket,
    })
}

pub fn method_dump_memory_state_by_fd(memory_state: &str) -> Result<Vec<u8>, Errno> {
    if memory_state.is_empty() {
        return Err(Errno::EINVAL);
    }

    Ok(memory_state.as_bytes().to_vec())
}

pub fn dummy_install_callback() -> bool {
    true
}

pub fn bus_log_address_error(r: i32, transport: BusTransport) -> BusLogRecord {
    let message = if transport == BusTransport::Local && r == Errno::ENOMEDIUM.to_neg_errno() {
        "Failed to set bus address: $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined (consider using --machine=<user>@.host --user to connect to bus of other user)".to_string()
    } else {
        format!("Failed to set bus address: errno {}", -r)
    };

    BusLogRecord {
        level: BusLogLevel::Error,
        errno: r,
        message,
    }
}

pub fn bus_log_connect_full(
    level: BusLogLevel,
    r: i32,
    transport: BusTransport,
    scope: RuntimeScope,
) -> BusLogRecord {
    let scope_name = match scope {
        RuntimeScope::User => "user",
        RuntimeScope::System => "system",
    };

    let message = if transport == BusTransport::Local && r == Errno::ENOMEDIUM.to_neg_errno() {
        format!(
            "Failed to connect to {scope_name} scope bus via local transport: $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined"
        )
    } else if transport == BusTransport::Local && r == Errno::EACCES.to_neg_errno() {
        format!("Failed to connect to {scope_name} scope bus via local transport: access denied")
    } else {
        format!(
            "Failed to connect to {scope_name} scope bus via {} transport: errno {}",
            transport.as_str(),
            -r,
        )
    };

    BusLogRecord {
        level,
        errno: r,
        message,
    }
}

pub fn bus_log_connect_error(
    r: i32,
    transport: BusTransport,
    scope: RuntimeScope,
) -> BusLogRecord {
    bus_log_connect_full(BusLogLevel::Error, r, transport, scope)
}

pub fn bus_async_unregister_and_exit(
    unique_name: &str,
    name: &str,
) -> Result<AsyncUnregisterPlan, Errno> {
    if unique_name.is_empty() || name.is_empty() {
        return Err(Errno::EINVAL);
    }

    Ok(AsyncUnregisterPlan {
        release_name: name.to_string(),
        match_rule: format!(
            "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='{name}',arg1='{unique_name}',arg2=''"
        ),
    })
}

pub fn bus_event_loop_with_idle<C, F>(
    controller: &mut C,
    name: &str,
    timeout: u64,
    mut check_idle: F,
) -> Result<i32, Errno>
where
    C: EventLoopController,
    F: FnMut() -> bool,
{
    let mut unregister_scheduled = false;

    loop {
        match controller.state()? {
            EventState::Exit => return controller.exit_code(),
            EventState::Initial | EventState::Running => {}
        }

        let idle = idle_allowed() && controller.pending_method_calls() == 0 && check_idle();
        controller.run(if idle { timeout } else { u64::MAX })?;

        if idle && !unregister_scheduled {
            controller.notify_stopping();
            controller.unregister_and_exit(name)?;
            unregister_scheduled = true;
        }
    }
}

pub fn bus_name_has_owner(owners: &BTreeSet<String>, name: &str) -> Result<bool, Errno> {
    if name.is_empty() {
        return Err(Errno::EINVAL);
    }

    Ok(owners.contains(name))
}

pub fn bus_error_is_unknown_service(error_name: Option<&str>) -> bool {
    error_name.is_some_and(|name| UNKNOWN_SERVICE_ERRORS.contains(&name))
}

pub fn bus_error_is_connection(error_name: Option<&str>) -> bool {
    error_name.is_some_and(|name| CONNECTION_ERRORS.contains(&name))
}

pub fn bus_check_peercred(peer_uid: u32, effective_uid: u32) -> Result<(), Errno> {
    if peer_uid == 0 || peer_uid == effective_uid {
        Ok(())
    } else {
        Err(Errno::EPERM)
    }
}

pub fn bus_connect_system_systemd() -> Result<BusConnectionRequest, Errno> {
    Ok(BusConnectionRequest {
        kind: ConnectionKind::Address {
            address: SYSTEM_SYSTEMD_ADDRESS.to_string(),
        },
        exit_on_disconnect: false,
        check_peercred: true,
        bus_client: false,
    })
}

pub fn user_systemd_address(xdg_runtime_dir: &str) -> Result<String, Errno> {
    if xdg_runtime_dir.is_empty() {
        return Err(Errno::ENOMEDIUM);
    }

    Ok(format!(
        "unix:path={}/systemd/private",
        bus_address_escape(xdg_runtime_dir)
    ))
}

pub fn bus_connect_user_systemd(xdg_runtime_dir: &str) -> Result<BusConnectionRequest, Errno> {
    Ok(BusConnectionRequest {
        kind: ConnectionKind::Address {
            address: user_systemd_address(xdg_runtime_dir)?,
        },
        exit_on_disconnect: false,
        check_peercred: true,
        bus_client: false,
    })
}

pub fn bus_set_address_capsule_bus(capsule: &str) -> Result<CapsuleAddress, Errno> {
    bus_set_address_capsule(capsule, "bus")
}

pub fn bus_connect_capsule_systemd(capsule: &str) -> Result<BusConnectionRequest, Errno> {
    Ok(BusConnectionRequest {
        kind: ConnectionKind::Address {
            address: bus_set_address_capsule(capsule, "systemd/private")?.address,
        },
        exit_on_disconnect: false,
        check_peercred: false,
        bus_client: false,
    })
}

pub fn bus_connect_capsule_bus(capsule: &str) -> Result<BusConnectionRequest, Errno> {
    Ok(BusConnectionRequest {
        kind: ConnectionKind::Address {
            address: bus_set_address_capsule_bus(capsule)?.address,
        },
        exit_on_disconnect: false,
        check_peercred: false,
        bus_client: true,
    })
}

pub fn bus_connect_transport(
    transport: BusTransport,
    host: Option<&str>,
    runtime_scope: RuntimeScope,
    systemd_booted: bool,
) -> Result<BusConnectionRequest, Errno> {
    match transport {
        BusTransport::Local => {
            if host.is_some() {
                return Err(Errno::EINVAL);
            }

            let kind = match runtime_scope {
                RuntimeScope::User => ConnectionKind::DefaultUser,
                RuntimeScope::System => {
                    if !systemd_booted {
                        return Err(Errno::EHOSTDOWN);
                    }
                    ConnectionKind::DefaultSystem
                }
            };

            Ok(BusConnectionRequest {
                kind,
                exit_on_disconnect: true,
                check_peercred: false,
                bus_client: false,
            })
        }
        BusTransport::Remote => {
            let host = required_host(host)?;
            if runtime_scope != RuntimeScope::System {
                return Err(Errno::EOPNOTSUPP);
            }

            Ok(BusConnectionRequest {
                kind: ConnectionKind::RemoteSystem { host },
                exit_on_disconnect: true,
                check_peercred: false,
                bus_client: false,
            })
        }
        BusTransport::Machine => {
            let host = required_host(host)?;
            let kind = match runtime_scope {
                RuntimeScope::User => ConnectionKind::UserMachine { host },
                RuntimeScope::System => ConnectionKind::SystemMachine { host },
            };

            Ok(BusConnectionRequest {
                kind,
                exit_on_disconnect: true,
                check_peercred: false,
                bus_client: false,
            })
        }
        BusTransport::Capsule => {
            if runtime_scope != RuntimeScope::User {
                return Err(Errno::EINVAL);
            }

            bus_connect_capsule_bus(required_host(host)?.as_str()).map(|mut request| {
                request.exit_on_disconnect = true;
                request
            })
        }
    }
}

pub fn bus_connect_transport_systemd(
    transport: BusTransport,
    host: Option<&str>,
    runtime_scope: RuntimeScope,
    systemd_booted: bool,
    running_as_root: bool,
    xdg_runtime_dir: Option<&str>,
    dbus_session_bus_address: Option<&str>,
) -> Result<BusConnectionRequest, Errno> {
    match transport {
        BusTransport::Local => match runtime_scope {
            RuntimeScope::User => match xdg_runtime_dir {
                Some(dir) => bus_connect_user_systemd(dir),
                None if dbus_session_bus_address.is_some() => Ok(BusConnectionRequest {
                    kind: ConnectionKind::DefaultUser,
                    exit_on_disconnect: true,
                    check_peercred: false,
                    bus_client: false,
                }),
                None => Err(Errno::ENOMEDIUM),
            },
            RuntimeScope::System => {
                if host.is_some() {
                    return Err(Errno::EINVAL);
                }
                if !systemd_booted {
                    return Err(Errno::EHOSTDOWN);
                }
                if running_as_root {
                    bus_connect_system_systemd()
                } else {
                    Ok(BusConnectionRequest {
                        kind: ConnectionKind::DefaultSystem,
                        exit_on_disconnect: true,
                        check_peercred: false,
                        bus_client: false,
                    })
                }
            }
        },
        BusTransport::Remote => {
            if runtime_scope != RuntimeScope::System {
                return Err(Errno::EOPNOTSUPP);
            }
            Ok(BusConnectionRequest {
                kind: ConnectionKind::RemoteSystem {
                    host: required_host(host)?,
                },
                exit_on_disconnect: true,
                check_peercred: false,
                bus_client: false,
            })
        }
        BusTransport::Machine => {
            if runtime_scope != RuntimeScope::System {
                return Err(Errno::EOPNOTSUPP);
            }
            Ok(BusConnectionRequest {
                kind: ConnectionKind::SystemMachine {
                    host: required_host(host)?,
                },
                exit_on_disconnect: true,
                check_peercred: false,
                bus_client: false,
            })
        }
        BusTransport::Capsule => {
            if runtime_scope != RuntimeScope::User {
                return Err(Errno::EINVAL);
            }
            bus_connect_capsule_systemd(required_host(host)?.as_str()).map(|mut request| {
                request.exit_on_disconnect = true;
                request
            })
        }
    }
}

pub fn bus_path_encode_unique(
    prefix: &str,
    sender_id: Option<&str>,
    external_id: Option<&str>,
    fallback_sender: Option<&str>,
    cookie: &mut u64,
) -> Result<String, Errno> {
    if !bus_object_path_is_valid(prefix) {
        return Err(Errno::EINVAL);
    }

    let sender = sender_id.or(fallback_sender).ok_or(Errno::EINVAL)?;
    let external = match external_id {
        Some(external) => external.to_string(),
        None => {
            *cookie = cookie.checked_add(1).ok_or(Errno::EOVERFLOW)?;
            cookie.to_string()
        }
    };

    Ok(format!(
        "{prefix}/{}/{}",
        bus_label_escape(sender),
        bus_label_escape(&external)
    ))
}

pub fn bus_path_decode_unique(path: &str, prefix: &str) -> Result<Option<UniquePathParts>, Errno> {
    if !bus_object_path_is_valid(path) || !bus_object_path_is_valid(prefix) {
        return Err(Errno::EINVAL);
    }

    let remainder = match object_path_startswith(path, prefix) {
        Some(remainder) => remainder.strip_prefix('/').ok_or(Errno::EINVAL)?,
        None => return Ok(None),
    };

    let mut parts = remainder.split('/');
    let sender = match parts.next() {
        Some(part) if !part.is_empty() => part,
        _ => return Ok(None),
    };
    let external = match parts.next() {
        Some(part) if !part.is_empty() => part,
        _ => return Ok(None),
    };
    if parts.next().is_some() {
        return Ok(None);
    }

    Ok(Some(UniquePathParts {
        sender: bus_label_unescape(sender).ok_or(Errno::EINVAL)?,
        external: bus_label_unescape(external).ok_or(Errno::EINVAL)?,
    }))
}

pub fn bus_track_add_name_many(tracker: &mut BusTracker, names: &[&str]) -> Result<(), Errno> {
    for name in names {
        if name.is_empty() {
            return Err(Errno::EINVAL);
        }
        *tracker.names.entry((*name).to_string()).or_default() += 1;
    }

    Ok(())
}

pub fn bus_track_to_strv(tracker: &BusTracker) -> Vec<String> {
    let mut result = Vec::new();

    for (name, count) in &tracker.names {
        for _ in 0..*count {
            result.push(name.clone());
        }
    }

    result
}

pub fn bus_open_system_watch_bind_with_description(
    description: Option<&str>,
) -> Result<SystemWatchBind, Errno> {
    if matches!(description, Some("")) {
        return Err(Errno::EINVAL);
    }

    Ok(SystemWatchBind {
        address: std::env::var("DBUS_SYSTEM_BUS_ADDRESS")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_SYSTEM_BUS_ADDRESS.to_string()),
        description: description.map(str::to_string),
        watch_bind: true,
        connected_signal: true,
        negotiate_creds: true,
    })
}

pub fn bus_reply_pair_array(entries: &[&str]) -> Result<Vec<(String, String)>, Errno> {
    if !entries.len().is_multiple_of(2) {
        return Err(Errno::EINVAL);
    }

    Ok(entries
        .chunks_exact(2)
        .map(|chunk| (chunk[0].to_string(), chunk[1].to_string()))
        .collect())
}

pub fn bus_register_malloc_status(destination: &str) -> Result<String, Errno> {
    if destination.is_empty() {
        return Err(Errno::EINVAL);
    }

    Ok(format!(
        "type='method_call',sender='{}',path='/org/freedesktop/MemoryAllocation1',interface='org.freedesktop.MemoryAllocation1',member='GetMallocInfo'",
        destination
    ))
}

pub fn bus_creds_get_pidref(creds: &BusCreds) -> Result<PidRef, Errno> {
    Ok(PidRef {
        pid: creds.pid,
        fd: creds.pidfd.unwrap_or(Errno::EBADF.to_neg_errno()),
    })
}

pub fn bus_query_sender_pidref(message: &BusMessage) -> Result<PidRef, Errno> {
    let creds = message.creds.as_ref().ok_or(Errno::ENODATA)?;
    bus_creds_get_pidref(creds)
}

pub fn bus_get_instance_id(id: &str) -> Result<[u8; 16], Errno> {
    parse_uuid(id)
}

fn parse_env_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

fn capsule_name_is_valid(capsule: &str) -> bool {
    !capsule.is_empty()
        && capsule != "."
        && capsule != ".."
        && !capsule.contains('/')
        && capsule
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn required_host(host: Option<&str>) -> Result<String, Errno> {
    match host {
        Some(host) if !host.is_empty() => Ok(host.to_string()),
        _ => Err(Errno::EINVAL),
    }
}

fn bus_label_escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());

    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' => output.push(byte as char),
            _ => output.push_str(&format!("_{byte:02X}")),
        }
    }

    output
}

fn bus_label_unescape(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'_' {
            let hi = *bytes.get(index + 1)?;
            let lo = *bytes.get(index + 2)?;
            output.push((hex_nibble(hi)? << 4) | hex_nibble(lo)?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(output).ok()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn bus_object_path_is_valid(path: &str) -> bool {
    if path.is_empty() || !path.starts_with('/') {
        return false;
    }
    if path == "/" {
        return true;
    }

    path[1..].split('/').all(|component| {
        !component.is_empty()
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn object_path_startswith<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if !path.starts_with(prefix) {
        return None;
    }

    let remainder = &path[prefix.len()..];
    if remainder.is_empty() || remainder.starts_with('/') {
        Some(remainder)
    } else {
        None
    }
}

fn bus_address_escape(path: &str) -> String {
    let mut output = String::with_capacity(path.len());

    for byte in path.bytes() {
        match byte {
            b'\\' => output.push_str("\\\\"),
            b'\'' => output.push_str("\\'"),
            _ => output.push(byte as char),
        }
    }

    output
}

fn parse_uuid(id: &str) -> Result<[u8; 16], Errno> {
    let hex: String = id.chars().filter(|ch| *ch != '-').collect();
    if hex.len() != 32 {
        return Err(Errno::EINVAL);
    }

    let mut bytes = [0_u8; 16];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(chunk[0]).ok_or(Errno::EINVAL)? << 4)
            | hex_nibble(chunk[1]).ok_or(Errno::EINVAL)?;
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct MockEventLoop {
        state: EventState,
        pending: usize,
        runs: usize,
        unregisters: usize,
        stopping_notified: bool,
        exit_code: i32,
    }

    impl EventLoopController for MockEventLoop {
        fn state(&self) -> Result<EventState, Errno> {
            Ok(self.state)
        }

        fn pending_method_calls(&self) -> usize {
            self.pending
        }

        fn run(&mut self, _timeout: u64) -> Result<(), Errno> {
            self.runs += 1;
            self.state = EventState::Exit;
            Ok(())
        }

        fn unregister_and_exit(&mut self, _name: &str) -> Result<(), Errno> {
            self.unregisters += 1;
            Ok(())
        }

        fn notify_stopping(&mut self) {
            self.stopping_notified = true;
        }

        fn exit_code(&self) -> Result<i32, Errno> {
            Ok(self.exit_code)
        }
    }

    #[test]
    fn test_bus_error_is_unknown_service() {
        assert!(bus_error_is_unknown_service(Some(
            SD_BUS_ERROR_SERVICE_UNKNOWN
        )));
        assert!(bus_error_is_unknown_service(Some(BUS_ERROR_NO_SUCH_UNIT)));
        assert!(!bus_error_is_unknown_service(Some(SD_BUS_ERROR_TIMED_OUT)));
    }

    #[test]
    fn test_bus_error_is_connection() {
        assert!(bus_error_is_connection(Some(SD_BUS_ERROR_NO_REPLY)));
        assert!(bus_error_is_connection(Some(SD_BUS_ERROR_DISCONNECTED)));
        assert!(!bus_error_is_connection(Some(BUS_ERROR_NO_SUCH_UNIT)));
    }

    #[test]
    fn test_idle_allowed_from_env() {
        assert!(idle_allowed_from_env(None));
        assert!(idle_allowed_from_env(Some("yes")));
        assert!(!idle_allowed_from_env(Some("0")));
        assert!(idle_allowed_from_env(Some("garbage")));
    }

    #[test]
    fn test_bus_label_roundtrip() {
        let encoded = bus_label_escape(":1.42/foo");
        assert_eq!(encoded, "_3A1_2E42_2Ffoo");
        assert_eq!(bus_label_unescape(&encoded), Some(":1.42/foo".to_string()));
    }

    #[test]
    fn test_object_path_validation() {
        assert!(bus_object_path_is_valid("/org/freedesktop/systemd1"));
        assert!(!bus_object_path_is_valid("org/freedesktop"));
        assert!(!bus_object_path_is_valid("/org/freedesktop/systemd.1"));
    }

    #[test]
    fn test_bus_path_encode_decode_unique() {
        let mut cookie = 0;
        let path = bus_path_encode_unique(
            "/org/example",
            Some(":1.9"),
            Some("unit-1"),
            None,
            &mut cookie,
        )
        .unwrap();
        let decoded = bus_path_decode_unique(&path, "/org/example")
            .unwrap()
            .unwrap();

        assert_eq!(decoded.sender, ":1.9");
        assert_eq!(decoded.external, "unit-1");
    }

    #[test]
    fn test_bus_path_encode_uses_cookie_fallback() {
        let mut cookie = 7;
        let path =
            bus_path_encode_unique("/org/example", None, None, Some(":1.5"), &mut cookie).unwrap();

        assert_eq!(cookie, 8);
        assert!(path.ends_with("/_3A1_2E5/8"));
    }

    #[test]
    fn test_bus_log_address_error_hint() {
        let record = bus_log_address_error(Errno::ENOMEDIUM.to_neg_errno(), BusTransport::Local);
        assert!(record.message.contains("$DBUS_SESSION_BUS_ADDRESS"));
    }

    #[test]
    fn test_bus_async_unregister_and_exit() {
        let plan = bus_async_unregister_and_exit(":1.4", "org.example.Service").unwrap();
        assert!(plan.match_rule.contains("NameOwnerChanged"));
        assert_eq!(plan.release_name, "org.example.Service");
    }

    #[test]
    fn test_bus_event_loop_with_idle() {
        let mut loop_state = MockEventLoop {
            state: EventState::Running,
            pending: 0,
            runs: 0,
            unregisters: 0,
            stopping_notified: false,
            exit_code: 17,
        };
        let idle_checks = Cell::new(0);

        let result = bus_event_loop_with_idle(&mut loop_state, "org.example.Service", 5, || {
            idle_checks.set(idle_checks.get() + 1);
            true
        })
        .unwrap();

        assert_eq!(result, 17);
        assert_eq!(loop_state.runs, 1);
        assert_eq!(loop_state.unregisters, 1);
        assert!(loop_state.stopping_notified);
        assert_eq!(idle_checks.get(), 1);
    }

    #[test]
    fn test_bus_connect_transport_local_system_requires_boot() {
        assert_eq!(
            bus_connect_transport(BusTransport::Local, None, RuntimeScope::System, false),
            Err(Errno::EHOSTDOWN)
        );
    }

    #[test]
    fn test_bus_connect_transport_capsule() {
        let request = bus_connect_transport(
            BusTransport::Capsule,
            Some("demo"),
            RuntimeScope::User,
            true,
        )
        .unwrap();

        assert!(matches!(request.kind, ConnectionKind::Address { .. }));
        assert!(request.bus_client);
        assert!(request.exit_on_disconnect);
    }

    #[test]
    fn test_bus_connect_transport_systemd_user_fallback() {
        let request = bus_connect_transport_systemd(
            BusTransport::Local,
            None,
            RuntimeScope::User,
            true,
            false,
            None,
            Some("unix:path=/tmp/bus"),
        )
        .unwrap();

        assert_eq!(request.kind, ConnectionKind::DefaultUser);
    }

    #[test]
    fn test_bus_set_address_capsule_bus() {
        let address = bus_set_address_capsule_bus("demo").unwrap();
        assert!(address.address.contains("/run/capsules/demo/bus"));
        assert_eq!(address.pinned_socket.path, "/run/capsules/demo/bus");
    }

    #[test]
    fn test_bus_track_roundtrip() {
        let mut tracker = BusTracker::default();
        bus_track_add_name_many(&mut tracker, &["a", "b", "a"]).unwrap();
        assert_eq!(bus_track_to_strv(&tracker), vec!["a", "a", "b"]);
    }

    #[test]
    fn test_bus_reply_pair_array() {
        let pairs = bus_reply_pair_array(&["A", "1", "B", "2"]).unwrap();
        assert_eq!(
            pairs,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "2".to_string())
            ]
        );
        assert_eq!(bus_reply_pair_array(&["A"]).unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn test_bus_creds_get_pidref() {
        let pidref = bus_creds_get_pidref(&BusCreds {
            pid: 55,
            pidfd: None,
        })
        .unwrap();
        assert_eq!(pidref.pid, 55);
        assert_eq!(pidref.fd, Errno::EBADF.to_neg_errno());
    }

    #[test]
    fn test_bus_get_instance_id() {
        let id = bus_get_instance_id("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert_eq!(id[0], 0x00);
        assert_eq!(id[15], 0xff);
    }

    #[test]
    fn test_bus_open_system_watch_bind_with_description() {
        let bind = bus_open_system_watch_bind_with_description(Some("test-bus")).unwrap();
        assert!(bind.watch_bind);
        assert!(bind.connected_signal);
        assert_eq!(bind.description.as_deref(), Some("test-bus"));
    }

    #[test]
    fn test_bus_name_has_owner() {
        let owners = BTreeSet::from(["org.example.Service".to_string()]);
        assert!(bus_name_has_owner(&owners, "org.example.Service").unwrap());
        assert!(!bus_name_has_owner(&owners, "org.example.Other").unwrap());
    }
}
