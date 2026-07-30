// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-login/sd-login.c
//
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EBADF: i32 = -libc::EBADF;
pub const NEG_EINVAL: i32 = -libc::EINVAL;
pub const NEG_ENODATA: i32 = -libc::ENODATA;
pub const NEG_ENXIO: i32 = -libc::ENXIO;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub id: String,
    pub uid: libc::uid_t,
    pub seat: Option<String>,
    pub vt: Option<i32>,
    pub session_type: Option<String>,
    pub class: Option<String>,
    pub desktop: Option<String>,
    pub display: Option<String>,
    pub remote: bool,
    pub remote_user: Option<String>,
    pub service: Option<String>,
    pub tty: Option<String>,
    pub pid: Option<libc::pid_t>,
    pub leader: Option<libc::uid_t>,
    pub audit_id: Option<i32>,
    pub machine: Option<String>,
    pub active: bool,
    pub multi_session: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatRecord {
    pub id: String,
    pub can_multi_session: bool,
    pub can_tty: bool,
    pub can_graphical: bool,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineRecord {
    pub name: String,
    pub class: Option<String>,
    pub ifindices: Vec<i32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoginRegistry {
    sessions: BTreeMap<String, SessionRecord>,
    seats: BTreeMap<String, SeatRecord>,
    machines: BTreeMap<String, MachineRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    pub uid: libc::uid_t,
    pub seat: Option<String>,
    pub vt: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginMonitor {
    category: Option<String>,
    fd: i32,
    events: libc::c_short,
    timeout_usec: u64,
    generation: u64,
    closed: bool,
}

impl LoginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_seat(&mut self, seat: SeatRecord) -> Result<()> {
        validate_name(&seat.id)?;
        self.seats.insert(seat.id.clone(), seat);
        Ok(())
    }

    pub fn add_machine(&mut self, machine: MachineRecord) -> Result<()> {
        validate_name(&machine.name)?;
        self.machines.insert(machine.name.clone(), machine);
        Ok(())
    }

    pub fn add_session(&mut self, session: SessionRecord) -> Result<()> {
        validate_name(&session.id)?;
        if let Some(seat) = &session.seat {
            validate_name(seat)?;
        }
        if let Some(machine) = &session.machine {
            validate_name(machine)?;
        }
        self.sessions.insert(session.id.clone(), session);
        Ok(())
    }

    fn session(&self, id: &str) -> Result<&SessionRecord> {
        validate_name(id)?;
        self.sessions.get(id).ok_or(NEG_ENXIO)
    }

    fn seat(&self, id: &str) -> Result<&SeatRecord> {
        validate_name(id)?;
        self.seats.get(id).ok_or(NEG_ENXIO)
    }

    fn machine(&self, name: &str) -> Result<&MachineRecord> {
        validate_name(name)?;
        self.machines.get(name).ok_or(NEG_ENXIO)
    }
}

pub fn sd_get_seats(registry: &LoginRegistry) -> Result<Vec<String>> {
    Ok(registry.seats.keys().cloned().collect())
}

pub fn sd_get_sessions(registry: &LoginRegistry) -> Result<Vec<String>> {
    Ok(registry.sessions.keys().cloned().collect())
}

pub fn sd_get_uids(registry: &LoginRegistry) -> Result<Vec<libc::uid_t>> {
    Ok(registry
        .sessions
        .values()
        .map(|session| session.uid)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

pub fn sd_get_machine_names(registry: &LoginRegistry) -> Result<Vec<String>> {
    Ok(registry.machines.keys().cloned().collect())
}

pub fn sd_get_sessions_for_uid(registry: &LoginRegistry, uid: libc::uid_t) -> Result<Vec<String>> {
    Ok(registry
        .sessions
        .values()
        .filter(|session| session.uid == uid)
        .map(|session| session.id.clone())
        .collect())
}

pub fn sd_get_seats_for_session(registry: &LoginRegistry, session: &str) -> Result<Vec<String>> {
    Ok(registry
        .session(session)?
        .seat
        .clone()
        .into_iter()
        .collect())
}

pub fn sd_get_sessions_for_seat(registry: &LoginRegistry, seat: &str) -> Result<Vec<String>> {
    registry.seat(seat)?;
    Ok(registry
        .sessions
        .values()
        .filter(|session| session.seat.as_deref() == Some(seat))
        .map(|session| session.id.clone())
        .collect())
}

pub fn sd_get_uids_for_seat(registry: &LoginRegistry, seat: &str) -> Result<Vec<libc::uid_t>> {
    registry.seat(seat)?;
    Ok(registry
        .sessions
        .values()
        .filter(|session| session.seat.as_deref() == Some(seat))
        .map(|session| session.uid)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

pub fn sd_get_machine_for_session(registry: &LoginRegistry, session: &str) -> Result<String> {
    registry
        .session(session)?
        .machine
        .clone()
        .ok_or(NEG_ENODATA)
}

pub fn sd_get_session(registry: &LoginRegistry, session: &str) -> Result<SessionSummary> {
    let session = registry.session(session)?;
    Ok(SessionSummary {
        uid: session.uid,
        seat: session.seat.clone(),
        vt: session.vt,
    })
}

pub fn sd_get_session_type(registry: &LoginRegistry, session: &str) -> Result<String> {
    registry
        .session(session)?
        .session_type
        .clone()
        .ok_or(NEG_ENODATA)
}

pub fn sd_get_session_class(registry: &LoginRegistry, session: &str) -> Result<String> {
    registry.session(session)?.class.clone().ok_or(NEG_ENODATA)
}

pub fn sd_get_session_desktop(registry: &LoginRegistry, session: &str) -> Result<String> {
    registry
        .session(session)?
        .desktop
        .clone()
        .ok_or(NEG_ENODATA)
}

pub fn sd_get_session_display(registry: &LoginRegistry, session: &str) -> Result<String> {
    registry
        .session(session)?
        .display
        .clone()
        .ok_or(NEG_ENODATA)
}

pub fn sd_get_session_remote(registry: &LoginRegistry, session: &str) -> Result<bool> {
    Ok(registry.session(session)?.remote)
}

pub fn sd_get_session_remote_user(registry: &LoginRegistry, session: &str) -> Result<String> {
    registry
        .session(session)?
        .remote_user
        .clone()
        .ok_or(NEG_ENODATA)
}

pub fn sd_get_session_service(registry: &LoginRegistry, session: &str) -> Result<String> {
    registry
        .session(session)?
        .service
        .clone()
        .ok_or(NEG_ENODATA)
}

pub fn sd_get_session_tty(registry: &LoginRegistry, session: &str) -> Result<String> {
    registry.session(session)?.tty.clone().ok_or(NEG_ENODATA)
}

pub fn sd_get_session_vt(registry: &LoginRegistry, session: &str) -> Result<i32> {
    registry.session(session)?.vt.ok_or(NEG_ENODATA)
}

pub fn sd_get_session_pid(registry: &LoginRegistry, session: &str) -> Result<libc::pid_t> {
    registry.session(session)?.pid.ok_or(NEG_ENODATA)
}

pub fn sd_get_session_leader(registry: &LoginRegistry, session: &str) -> Result<libc::uid_t> {
    registry.session(session)?.leader.ok_or(NEG_ENODATA)
}

pub fn sd_get_session_audit(registry: &LoginRegistry, session: &str) -> Result<i32> {
    registry.session(session)?.audit_id.ok_or(NEG_ENODATA)
}

pub fn sd_get_uid_state(registry: &LoginRegistry, uid: libc::uid_t) -> Result<String> {
    let sessions: Vec<_> = registry
        .sessions
        .values()
        .filter(|session| session.uid == uid)
        .collect();

    if sessions.is_empty() {
        return Err(NEG_ENXIO);
    }
    if sessions.iter().any(|session| session.active) {
        return Ok("active".to_string());
    }
    if sessions.iter().any(|session| session.remote) {
        return Ok("online".to_string());
    }
    Ok("closing".to_string())
}

pub fn sd_get_seat_active(registry: &LoginRegistry, seat: &str) -> Result<bool> {
    Ok(registry.seat(seat)?.active)
}

pub fn sd_get_seat_can_multi_session(registry: &LoginRegistry, seat: &str) -> Result<bool> {
    Ok(registry.seat(seat)?.can_multi_session)
}

pub fn sd_get_seat_can_tty(registry: &LoginRegistry, seat: &str) -> Result<bool> {
    Ok(registry.seat(seat)?.can_tty)
}

pub fn sd_get_seat_can_graphical(registry: &LoginRegistry, seat: &str) -> Result<bool> {
    Ok(registry.seat(seat)?.can_graphical)
}

pub fn sd_get_machine(registry: &LoginRegistry, machine: &str) -> Result<String> {
    Ok(registry.machine(machine)?.name.clone())
}

pub fn sd_get_machine_class(registry: &LoginRegistry, machine: &str) -> Result<String> {
    registry.machine(machine)?.class.clone().ok_or(NEG_ENODATA)
}

pub fn sd_get_machine_ifindices(registry: &LoginRegistry, machine: &str) -> Result<Vec<i32>> {
    Ok(registry.machine(machine)?.ifindices.clone())
}

pub fn sd_is_multi_session(registry: &LoginRegistry, session: &str) -> Result<bool> {
    Ok(registry.session(session)?.multi_session)
}

pub fn sd_session_is_active(registry: &LoginRegistry, session: &str) -> Result<bool> {
    Ok(registry.session(session)?.active)
}

pub fn sd_uid_is_on_seat(registry: &LoginRegistry, uid: libc::uid_t, seat: &str) -> Result<bool> {
    registry.seat(seat)?;
    Ok(registry
        .sessions
        .values()
        .any(|session| session.uid == uid && session.seat.as_deref() == Some(seat)))
}

pub fn sd_seat_can_multi_session(registry: &LoginRegistry, seat: &str) -> Result<bool> {
    sd_get_seat_can_multi_session(registry, seat)
}

pub fn sd_seat_is_active(registry: &LoginRegistry, seat: &str) -> Result<bool> {
    sd_get_seat_active(registry, seat)
}

pub fn sd_uid_get_sessions(registry: &LoginRegistry, uid: libc::uid_t) -> Result<Vec<String>> {
    sd_get_sessions_for_uid(registry, uid)
}

pub fn sd_uid_get_seats(registry: &LoginRegistry, uid: libc::uid_t) -> Result<Vec<String>> {
    Ok(registry
        .sessions
        .values()
        .filter(|session| session.uid == uid)
        .filter_map(|session| session.seat.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

pub fn sd_uid_get_display(registry: &LoginRegistry, uid: libc::uid_t) -> Result<String> {
    registry
        .sessions
        .values()
        .find(|session| session.uid == uid && session.display.is_some())
        .and_then(|session| session.display.clone())
        .ok_or(NEG_ENODATA)
}

pub fn sd_uid_get_machine_name(registry: &LoginRegistry, uid: libc::uid_t) -> Result<String> {
    registry
        .sessions
        .values()
        .find(|session| session.uid == uid && session.machine.is_some())
        .and_then(|session| session.machine.clone())
        .ok_or(NEG_ENODATA)
}

pub fn sd_login_monitor_new(category: Option<&str>) -> Result<LoginMonitor> {
    if let Some(category) = category {
        validate_name(category)?;
    }

    Ok(LoginMonitor {
        category: category.map(str::to_string),
        fd: 3,
        events: libc::POLLIN,
        timeout_usec: u64::MAX,
        generation: 0,
        closed: false,
    })
}

pub fn sd_login_monitor_unref(mut monitor: LoginMonitor) -> LoginMonitor {
    monitor.closed = true;
    monitor.fd = -1;
    monitor
}

pub fn sd_login_monitor_ref(monitor: &LoginMonitor) -> LoginMonitor {
    monitor.clone()
}

pub fn sd_login_monitor_get_fd(monitor: &LoginMonitor) -> Result<i32> {
    if monitor.closed {
        return Err(NEG_EBADF);
    }
    Ok(monitor.fd)
}

pub fn sd_login_monitor_get_events(monitor: &LoginMonitor) -> libc::c_short {
    if monitor.closed { 0 } else { monitor.events }
}

pub fn sd_login_monitor_get_timeout(monitor: &LoginMonitor) -> Result<u64> {
    if monitor.closed {
        return Err(NEG_EBADF);
    }
    Ok(monitor.timeout_usec)
}

pub fn sd_login_monitor_flush(monitor: &mut LoginMonitor) -> Result<()> {
    if monitor.closed {
        return Err(NEG_EBADF);
    }
    monitor.generation = monitor.generation.saturating_add(1);
    Ok(())
}

fn validate_name(value: &str) -> Result<()> {
    if value.is_empty() || value.contains('/') || value.chars().any(char::is_whitespace) {
        return Err(NEG_EINVAL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> LoginRegistry {
        let mut registry = LoginRegistry::new();
        registry
            .add_seat(SeatRecord {
                id: "seat0".into(),
                can_multi_session: true,
                can_tty: true,
                can_graphical: true,
                active: true,
            })
            .unwrap();
        registry
            .add_machine(MachineRecord {
                name: "vm-01".into(),
                class: Some("vm".into()),
                ifindices: vec![2, 5],
            })
            .unwrap();
        registry
            .add_session(SessionRecord {
                id: "c1".into(),
                uid: 1000,
                seat: Some("seat0".into()),
                vt: Some(1),
                session_type: Some("wayland".into()),
                class: Some("user".into()),
                desktop: Some("gnome".into()),
                display: Some(":0".into()),
                remote: false,
                remote_user: None,
                service: Some("gdm".into()),
                tty: Some("tty1".into()),
                pid: Some(42),
                leader: Some(1000),
                audit_id: Some(7),
                machine: Some("vm-01".into()),
                active: true,
                multi_session: true,
            })
            .unwrap();
        registry
            .add_session(SessionRecord {
                id: "c2".into(),
                uid: 1001,
                seat: Some("seat0".into()),
                vt: Some(2),
                session_type: Some("tty".into()),
                class: Some("greeter".into()),
                desktop: None,
                display: None,
                remote: true,
                remote_user: Some("root".into()),
                service: Some("sshd".into()),
                tty: Some("pts/0".into()),
                pid: Some(43),
                leader: Some(1001),
                audit_id: Some(8),
                machine: None,
                active: false,
                multi_session: false,
            })
            .unwrap();
        registry
    }

    #[test]
    fn lists_seats_sessions_and_uids() {
        let registry = fixture();
        assert_eq!(sd_get_seats(&registry).unwrap(), vec!["seat0"]);
        assert_eq!(sd_get_sessions(&registry).unwrap(), vec!["c1", "c2"]);
        assert_eq!(sd_get_uids(&registry).unwrap(), vec![1000, 1001]);
    }

    #[test]
    fn finds_sessions_for_uid_and_seat() {
        let registry = fixture();
        assert_eq!(
            sd_get_sessions_for_uid(&registry, 1000).unwrap(),
            vec!["c1"]
        );
        assert_eq!(
            sd_get_sessions_for_seat(&registry, "seat0").unwrap(),
            vec!["c1", "c2"]
        );
    }

    #[test]
    fn returns_session_metadata() {
        let registry = fixture();
        assert_eq!(sd_get_session_type(&registry, "c1").unwrap(), "wayland");
        assert_eq!(sd_get_session_display(&registry, "c1").unwrap(), ":0");
        assert_eq!(sd_get_session_vt(&registry, "c1").unwrap(), 1);
    }

    #[test]
    fn missing_optional_metadata_yields_enodata() {
        let registry = fixture();
        assert_eq!(sd_get_session_desktop(&registry, "c2"), Err(NEG_ENODATA));
        assert_eq!(sd_uid_get_machine_name(&registry, 1001), Err(NEG_ENODATA));
    }

    #[test]
    fn machine_queries_work() {
        let registry = fixture();
        assert_eq!(sd_get_machine(&registry, "vm-01").unwrap(), "vm-01");
        assert_eq!(sd_get_machine_class(&registry, "vm-01").unwrap(), "vm");
        assert_eq!(
            sd_get_machine_ifindices(&registry, "vm-01").unwrap(),
            vec![2, 5]
        );
    }

    #[test]
    fn seat_queries_work() {
        let registry = fixture();
        assert!(sd_get_seat_active(&registry, "seat0").unwrap());
        assert!(sd_seat_can_multi_session(&registry, "seat0").unwrap());
        assert!(sd_uid_is_on_seat(&registry, 1000, "seat0").unwrap());
    }

    #[test]
    fn uid_state_prefers_active_sessions() {
        let registry = fixture();
        assert_eq!(sd_get_uid_state(&registry, 1000).unwrap(), "active");
        assert_eq!(sd_get_uid_state(&registry, 1001).unwrap(), "online");
    }

    #[test]
    fn monitor_reports_fd_and_flushes() {
        let mut monitor = sd_login_monitor_new(Some("session")).unwrap();
        assert_eq!(sd_login_monitor_get_fd(&monitor).unwrap(), 3);
        assert_eq!(sd_login_monitor_get_events(&monitor), libc::POLLIN);
        sd_login_monitor_flush(&mut monitor).unwrap();
        assert_eq!(sd_login_monitor_get_timeout(&monitor).unwrap(), u64::MAX);
    }

    #[test]
    fn monitor_unref_closes_monitor() {
        let monitor = sd_login_monitor_unref(sd_login_monitor_new(None).unwrap());
        assert_eq!(sd_login_monitor_get_fd(&monitor), Err(NEG_EBADF));
    }
}
