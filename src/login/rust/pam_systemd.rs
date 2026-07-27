// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/pam_systemd.c

use crate::logind_core::{SessionClass, SessionType};
use crate::logind_session::Session;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PamFlags: u32 {
        const DEBUG = 1 << 0;
        const CREATE_SESSION = 1 << 1;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PamSessionContext {
    pub service: String,
    pub user_name: String,
    pub uid: u32,
    pub class: SessionClass,
    pub session_type: SessionType,
    pub seat: Option<String>,
    pub tty: Option<String>,
}

pub fn build_session(context: &PamSessionContext) -> Result<Session, String> {
    let mut session = Session::new("pam-session".into(), context.user_name.clone(), context.uid);
    session.class = context.class;
    session.session_type = context.session_type;
    session.seat = context.seat.clone();
    session.tty = context.tty.clone();
    Ok(session)
}

pub fn parse_handle_parameter(value: &str) -> Result<SessionType, String> {
    SessionType::from_str(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pam_context_builds_session() {
        let session = build_session(&PamSessionContext {
            service: "login".into(),
            user_name: "alice".into(),
            uid: 1000,
            class: SessionClass::User,
            session_type: SessionType::Wayland,
            seat: Some("seat0".into()),
            tty: Some("tty2".into()),
        })
        .unwrap();

        assert_eq!(session.session_type, SessionType::Wayland);
        assert_eq!(session.seat.as_deref(), Some("seat0"));
    }
}
