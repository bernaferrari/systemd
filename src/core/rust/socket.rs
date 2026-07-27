// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/socket.c
//
use std::fmt;

pub const SOURCE_PATH: &str = "src/core/socket.c";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketError {
    InvalidState(&'static str),
    InvalidInput(&'static str),
    MissingPort,
}

impl fmt::Display for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState(msg) => write!(f, "invalid state: {msg}"),
            Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            Self::MissingPort => write!(f, "missing socket port"),
        }
    }
}

impl std::error::Error for SocketError {}

pub type Result<T> = std::result::Result<T, SocketError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitActiveState {
    Inactive,
    Activating,
    Active,
    Deactivating,
    Failed,
    Maintenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Dead,
    StartPre,
    StartOpen,
    StartChown,
    StartPost,
    Listening,
    Deferred,
    Running,
    StopPre,
    StopPreSigterm,
    StopPreSigkill,
    StopPost,
    FinalSigterm,
    FinalSigkill,
    Failed,
    Cleaning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketPortType {
    Socket,
    Fifo,
    Special,
    UsbFunction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketPort {
    pub fd: i32,
    pub path: Option<String>,
    pub address: Option<String>,
    pub kind: SocketPortType,
    pub auxiliary_fds: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketPeer {
    pub refs: usize,
    pub socket_name: String,
    pub address: String,
    pub peer_cred_uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketSnapshot {
    pub state: SocketState,
    pub active_state: UnitActiveState,
    pub listening_fds: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketUnit {
    pub name: String,
    pub state: SocketState,
    pub accept: bool,
    pub ports: Vec<SocketPort>,
    pub peers: Vec<SocketPeer>,
    pub backlog: u32,
    pub timeout_usec: u64,
    pub directory_mode: u32,
    pub socket_mode: u32,
    pub max_connections: u32,
    pub pass_rights: bool,
    pub priority: i32,
    pub ip_tos: i32,
    pub ip_ttl: i32,
    pub mark: i32,
    pub service_active: bool,
    pub fd_name: String,
    pub cleaning: bool,
    pub extrinsic: bool,
    pub actions: Vec<String>,
}

impl Default for SocketUnit {
    fn default() -> Self {
        Self {
            name: "example.socket".into(),
            state: SocketState::Dead,
            accept: false,
            ports: Vec::new(),
            peers: Vec::new(),
            backlog: 4096,
            timeout_usec: 0,
            directory_mode: 0o755,
            socket_mode: 0o666,
            max_connections: 64,
            pass_rights: true,
            priority: -1,
            ip_tos: -1,
            ip_ttl: -1,
            mark: -1,
            service_active: false,
            fd_name: "socket".into(),
            cleaning: false,
            extrinsic: false,
            actions: Vec::new(),
        }
    }
}

impl SocketUnit {
    fn record(&mut self, op: &str) {
        self.actions.push(op.to_string());
    }
}

pub fn socket_state_with_process(state: SocketState) -> bool {
    matches!(
        state,
        SocketState::StartPre
            | SocketState::StartChown
            | SocketState::StartPost
            | SocketState::StopPre
            | SocketState::StopPreSigterm
            | SocketState::StopPreSigkill
            | SocketState::StopPost
            | SocketState::FinalSigterm
            | SocketState::FinalSigkill
            | SocketState::Cleaning
    )
}

pub fn socket_service_is_active(
    service_active: bool,
    allow_finalize: bool,
    state: SocketState,
) -> bool {
    if !service_active {
        return false;
    }
    if allow_finalize
        && matches!(
            state,
            SocketState::FinalSigterm | SocketState::FinalSigkill | SocketState::Cleaning
        )
    {
        return false;
    }
    true
}

pub fn socket_init(unit: &mut SocketUnit) -> Result<()> {
    *unit = SocketUnit::default();
    unit.record("socket_init");
    Ok(())
}

pub fn socket_done(unit: &mut SocketUnit) -> Result<()> {
    unit.ports.clear();
    unit.peers.clear();
    unit.service_active = false;
    unit.record("socket_done");
    Ok(())
}

pub fn socket_load(unit: &mut SocketUnit) -> Result<()> {
    unit.record("socket_load");
    Ok(())
}

pub fn socket_coldplug(unit: &mut SocketUnit) -> Result<()> {
    unit.record("socket_coldplug");
    Ok(())
}

pub fn socket_dump(unit: &SocketUnit, prefix: &str) -> Result<String> {
    Ok(format!("{prefix}{} {:?}", unit.name, unit.state))
}

pub fn socket_start(unit: &mut SocketUnit) -> Result<SocketState> {
    socket_verify(unit)?;
    unit.state = SocketState::Listening;
    unit.record("socket_start");
    Ok(unit.state)
}

pub fn socket_stop(unit: &mut SocketUnit) -> Result<SocketState> {
    unit.state = SocketState::Dead;
    unit.record("socket_stop");
    Ok(unit.state)
}

pub fn socket_serialize(unit: &SocketUnit) -> Result<String> {
    Ok(format!("state={:?};ports={}", unit.state, unit.ports.len()))
}

pub fn socket_deserialize_item(unit: &mut SocketUnit, key: &str, value: &str) -> Result<()> {
    match key {
        "fdname" => unit.fd_name = value.into(),
        "accept" => unit.accept = matches!(value, "1" | "yes" | "true"),
        _ => {}
    }
    unit.record("socket_deserialize_item");
    Ok(())
}

pub fn socket_active_state(unit: &SocketUnit) -> UnitActiveState {
    match unit.state {
        SocketState::Dead => UnitActiveState::Inactive,
        SocketState::StartPre
        | SocketState::StartOpen
        | SocketState::StartChown
        | SocketState::StartPost => UnitActiveState::Activating,
        SocketState::Listening | SocketState::Deferred | SocketState::Running => {
            UnitActiveState::Active
        }
        SocketState::StopPre
        | SocketState::StopPreSigterm
        | SocketState::StopPreSigkill
        | SocketState::StopPost
        | SocketState::FinalSigterm
        | SocketState::FinalSigkill => UnitActiveState::Deactivating,
        SocketState::Failed => UnitActiveState::Failed,
        SocketState::Cleaning => UnitActiveState::Maintenance,
    }
}

pub fn socket_sub_state_to_string(unit: &SocketUnit) -> &'static str {
    match unit.state {
        SocketState::Dead => "dead",
        SocketState::StartPre => "start-pre",
        SocketState::StartOpen => "start-open",
        SocketState::StartChown => "start-chown",
        SocketState::StartPost => "start-post",
        SocketState::Listening => "listening",
        SocketState::Deferred => "deferred",
        SocketState::Running => "running",
        SocketState::StopPre => "stop-pre",
        SocketState::StopPreSigterm => "stop-pre-sigterm",
        SocketState::StopPreSigkill => "stop-pre-sigkill",
        SocketState::StopPost => "stop-post",
        SocketState::FinalSigterm => "final-sigterm",
        SocketState::FinalSigkill => "final-sigkill",
        SocketState::Failed => "failed",
        SocketState::Cleaning => "cleaning",
    }
}

pub fn socket_dispatch_io(unit: &mut SocketUnit, fd: i32, revents: u32) -> Result<()> {
    if fd < 0 || revents == 0 {
        return Err(SocketError::InvalidInput(
            "fd must be non-negative and revents non-zero",
        ));
    }
    unit.record("socket_dispatch_io");
    if unit.state == SocketState::Deferred {
        unit.state = SocketState::Running;
    }
    Ok(())
}

pub fn socket_dispatch_timer(unit: &mut SocketUnit, usec: u64) -> Result<()> {
    unit.timeout_usec = usec;
    unit.record("socket_dispatch_timer");
    Ok(())
}

pub fn socket_socket_snapshot(unit: &SocketUnit) -> Result<SocketSnapshot> {
    Ok(SocketSnapshot {
        state: unit.state,
        active_state: socket_active_state(unit),
        listening_fds: unit.ports.iter().map(|p| p.fd).collect(),
    })
}

pub fn socket_add_default_dependencies(unit: &mut SocketUnit) -> Result<()> {
    unit.record("socket_add_default_dependencies");
    Ok(())
}

pub fn socket_verify(unit: &SocketUnit) -> Result<()> {
    if unit.ports.is_empty() {
        return Err(SocketError::MissingPort);
    }
    Ok(())
}

pub fn socket_set_state(unit: &mut SocketUnit, state: SocketState) {
    unit.state = state;
    unit.record("socket_set_state");
}

pub fn socket_enter_signal(
    unit: &mut SocketUnit,
    state: SocketState,
    success: bool,
) -> Result<SocketState> {
    unit.state = if success { state } else { SocketState::Failed };
    unit.record("socket_enter_signal");
    Ok(unit.state)
}

pub fn socket_enter_stop_post(unit: &mut SocketUnit, success: bool) -> Result<SocketState> {
    unit.state = if success {
        SocketState::StopPost
    } else {
        SocketState::Failed
    };
    unit.record("socket_enter_stop_post");
    Ok(unit.state)
}

pub fn socket_enter_stop_pre(unit: &mut SocketUnit, success: bool) -> Result<SocketState> {
    unit.state = if success {
        SocketState::StopPre
    } else {
        SocketState::Failed
    };
    unit.record("socket_enter_stop_pre");
    Ok(unit.state)
}

pub fn socket_enter_listening(unit: &mut SocketUnit) -> Result<SocketState> {
    socket_verify(unit)?;
    unit.state = SocketState::Listening;
    unit.record("socket_enter_listening");
    Ok(unit.state)
}

pub fn socket_enter_start_pre(unit: &mut SocketUnit) -> Result<SocketState> {
    unit.state = SocketState::StartPre;
    unit.record("socket_enter_start_pre");
    Ok(unit.state)
}

pub fn socket_enter_start_post(unit: &mut SocketUnit) -> Result<SocketState> {
    unit.state = SocketState::StartPost;
    unit.record("socket_enter_start_post");
    Ok(unit.state)
}

pub fn socket_enter_start_chown(unit: &mut SocketUnit) -> Result<SocketState> {
    unit.state = SocketState::StartChown;
    unit.record("socket_enter_start_chown");
    Ok(unit.state)
}

pub fn socket_enter_deferred(unit: &mut SocketUnit) -> Result<SocketState> {
    unit.state = SocketState::Deferred;
    unit.record("socket_enter_deferred");
    Ok(unit.state)
}

pub fn socket_enter_running(unit: &mut SocketUnit) -> Result<SocketState> {
    unit.state = SocketState::Running;
    unit.record("socket_enter_running");
    Ok(unit.state)
}

pub fn socket_start_cleaning(unit: &mut SocketUnit) {
    unit.cleaning = true;
    unit.state = SocketState::Cleaning;
    unit.record("socket_start_cleaning");
}

pub fn socket_enter_dead(unit: &mut SocketUnit, success: bool) {
    unit.state = if success {
        SocketState::Dead
    } else {
        SocketState::Failed
    };
    unit.record("socket_enter_dead");
}

pub fn socket_may_gc(unit: &SocketUnit) -> bool {
    unit.state == SocketState::Dead && unit.peers.is_empty()
}

pub fn socket_is_extrinsic(unit: &SocketUnit) -> bool {
    unit.extrinsic
}

pub fn socket_check_fds(unit: &SocketUnit, fd: i32, revents: u32) -> Result<bool> {
    if revents == 0 {
        return Err(SocketError::InvalidInput("revents must be non-zero"));
    }
    Ok(unit.ports.iter().any(|p| p.fd == fd))
}

pub fn socket_close_fds(unit: &mut SocketUnit) {
    for port in &mut unit.ports {
        port.fd = -1;
        port.auxiliary_fds.clear();
    }
    unit.record("socket_close_fds");
}

pub fn socket_add_mount_link_deps(unit: &mut SocketUnit) -> Result<()> {
    unit.record("socket_add_mount_link_deps");
    Ok(())
}

pub fn socket_fix_timeout(unit: &mut SocketUnit) -> Result<()> {
    if unit.timeout_usec == 0 {
        unit.timeout_usec = 1;
    }
    unit.record("socket_fix_timeout");
    Ok(())
}

pub fn socket_confirm(unit: &mut SocketUnit) -> Result<()> {
    unit.record("socket_confirm");
    Ok(())
}

pub fn socket_inotify_event(unit: &mut SocketUnit, fd: i32, revents: u32) -> Result<()> {
    socket_dispatch_io(unit, fd, revents)?;
    unit.record("socket_inotify_event");
    Ok(())
}

pub fn socket_collect_fds(unit: &SocketUnit) -> Result<Vec<i32>> {
    socket_verify(unit)?;
    Ok(unit.ports.iter().map(|p| p.fd).collect())
}

pub fn socket_connection_unref(unit: &mut SocketUnit) {
    unit.peers.pop();
    unit.record("socket_connection_unref");
}

pub fn socket_peer_ref(peer: &mut SocketPeer) -> usize {
    peer.refs += 1;
    peer.refs
}

pub fn socket_peer_unref(peer: &mut SocketPeer) -> usize {
    peer.refs = peer.refs.saturating_sub(1);
    peer.refs
}

pub fn socket_acquire_peer(unit: &mut SocketUnit, fd: i32, address: &str) -> Result<SocketPeer> {
    if fd < 0 || address.is_empty() {
        return Err(SocketError::InvalidInput("fd/address"));
    }
    let peer = SocketPeer {
        refs: 1,
        socket_name: unit.name.clone(),
        address: address.into(),
        peer_cred_uid: 0,
    };
    unit.peers.push(peer.clone());
    unit.record("socket_acquire_peer");
    Ok(peer)
}

pub fn socket_port_free(port: SocketPort) -> Option<SocketPort> {
    if port.fd < 0 && port.path.is_none() && port.address.is_none() {
        None
    } else {
        Some(SocketPort {
            fd: -1,
            auxiliary_fds: Vec::new(),
            ..port
        })
    }
}

pub fn socket_free_ports(unit: &mut SocketUnit) {
    unit.ports.clear();
    unit.record("socket_free_ports");
}

pub fn socket_port_to_address(port: &SocketPort) -> Result<String> {
    if let Some(address) = &port.address {
        return Ok(address.clone());
    }
    if let Some(path) = &port.path {
        return Ok(path.clone());
    }
    Err(SocketError::InvalidInput(
        "port has neither address nor path",
    ))
}

pub fn socket_load_service_unit(unit: &SocketUnit, cfd: i32) -> Result<String> {
    if cfd < 0 {
        return Err(SocketError::InvalidInput("cfd must be non-negative"));
    }
    Ok(unit.name.replace(".socket", ".service"))
}

pub fn socket_fdname(unit: &SocketUnit) -> &str {
    &unit.fd_name
}

pub fn socket_dispatch_io_for_defer(unit: &mut SocketUnit) -> Result<()> {
    if unit.state != SocketState::Deferred {
        return Err(SocketError::InvalidState("socket is not deferred"));
    }
    unit.state = SocketState::Running;
    unit.record("socket_dispatch_io_for_defer");
    Ok(())
}

pub fn socket_trigger_notify(unit: &mut SocketUnit, other: &str) {
    unit.record(&format!("socket_trigger_notify:{other}"));
}

pub fn socket_reset_failed(unit: &mut SocketUnit) {
    if unit.state == SocketState::Failed {
        unit.state = SocketState::Dead;
    }
    unit.record("socket_reset_failed");
}

pub fn socket_notify_socket_path(unit: &SocketUnit) -> Option<String> {
    unit.ports.iter().find_map(|p| p.path.clone())
}

pub fn socket_can_clean(unit: &SocketUnit) -> Result<bool> {
    Ok(!unit.ports.is_empty())
}

pub fn socket_clean(unit: &mut SocketUnit, _mask: i32) -> Result<()> {
    unit.cleaning = true;
    unit.record("socket_clean");
    Ok(())
}

pub fn socket_test_startable(unit: &SocketUnit) -> Result<bool> {
    socket_verify(unit)?;
    Ok(!socket_service_is_active(
        unit.service_active,
        true,
        unit.state,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_unit() -> SocketUnit {
        let mut unit = SocketUnit::default();
        unit.ports.push(SocketPort {
            fd: 3,
            path: Some("/run/test.sock".into()),
            address: None,
            kind: SocketPortType::Socket,
            auxiliary_fds: vec![4],
        });
        unit
    }

    #[test]
    fn test_socket_active_state_translation() {
        let mut unit = sample_unit();
        unit.state = SocketState::Listening;
        assert_eq!(socket_active_state(&unit), UnitActiveState::Active);
    }

    #[test]
    fn test_socket_verify_requires_port() {
        let unit = SocketUnit::default();
        assert!(matches!(
            socket_verify(&unit),
            Err(SocketError::MissingPort)
        ));
    }

    #[test]
    fn test_socket_collect_fds() {
        let unit = sample_unit();
        assert_eq!(socket_collect_fds(&unit).unwrap(), vec![3]);
    }

    #[test]
    fn test_socket_deferred_to_running() {
        let mut unit = sample_unit();
        socket_enter_deferred(&mut unit).unwrap();
        socket_dispatch_io_for_defer(&mut unit).unwrap();
        assert_eq!(unit.state, SocketState::Running);
    }

    #[test]
    fn test_socket_peer_refcount() {
        let mut peer = SocketPeer {
            refs: 1,
            socket_name: "x.socket".into(),
            address: "127.0.0.1".into(),
            peer_cred_uid: 0,
        };
        assert_eq!(socket_peer_ref(&mut peer), 2);
        assert_eq!(socket_peer_unref(&mut peer), 1);
    }
}
