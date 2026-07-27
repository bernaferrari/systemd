// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-session.c

use crate::logind_core::{SessionClass, SessionType};

pub const RELEASE_USEC: u64 = 20_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Opening,
    Online,
    Active,
    Closing,
}

impl SessionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Online => "online",
            Self::Active => "active",
            Self::Closing => "closing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub user_name: String,
    pub uid: u32,
    pub class: SessionClass,
    pub session_type: SessionType,
    pub state: SessionState,
    pub seat: Option<String>,
    pub tty: Option<String>,
    pub display: Option<String>,
    pub remote: bool,
    pub controller: Option<String>,
    original_session_type: Option<SessionType>,
    original_display: Option<Option<String>>,
}

impl Session {
    pub fn new(id: String, user_name: String, uid: u32) -> Self {
        Self {
            id,
            user_name,
            uid,
            class: SessionClass::User,
            session_type: SessionType::Tty,
            state: SessionState::Opening,
            seat: None,
            tty: None,
            display: None,
            remote: false,
            controller: None,
            original_session_type: None,
            original_display: None,
        }
    }

    pub fn set_type(&mut self, session_type: SessionType) {
        self.session_type = session_type;
    }

    pub fn set_display(&mut self, display: impl Into<String>) {
        self.display = Some(display.into());
    }

    pub fn take_control(&mut self, controller: impl Into<String>) {
        if self.controller.is_none() {
            self.original_session_type = Some(self.session_type);
            self.original_display = Some(self.display.clone());
        }
        self.controller = Some(controller.into());
    }

    pub fn release_control(&mut self) {
        self.controller = None;
        if let Some(session_type) = self.original_session_type.take() {
            self.session_type = session_type;
        }
        if let Some(display) = self.original_display.take() {
            self.display = display;
        }
    }

    pub fn activate(&mut self) {
        self.state = SessionState::Active;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_control_restores_original_type_and_display() {
        let mut session = Session::new("c1".into(), "alice".into(), 1000);
        session.set_type(SessionType::Wayland);
        session.set_display(":1");
        session.take_control("greeter");
        session.set_type(SessionType::Tty);
        session.display = None;

        session.release_control();

        assert_eq!(session.controller, None);
        assert_eq!(session.session_type, SessionType::Wayland);
        assert_eq!(session.display.as_deref(), Some(":1"));
    }

    #[test]
    fn nested_take_control_keeps_first_snapshot() {
        let mut session = Session::new("c2".into(), "alice".into(), 1000);
        session.set_type(SessionType::X11);
        session.set_display(":0");
        session.take_control("first");
        session.set_type(SessionType::Wayland);
        session.set_display(":1");
        session.take_control("second");

        session.release_control();

        assert_eq!(session.session_type, SessionType::X11);
        assert_eq!(session.display.as_deref(), Some(":0"));
    }
}
