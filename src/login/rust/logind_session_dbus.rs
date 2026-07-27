// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-session-dbus.c

use crate::logind_dbus::BUS_PATH;
use crate::logind_session::Session;

pub fn session_bus_path(session_id: &str) -> String {
    format!("{BUS_PATH}/session/{session_id}")
}

pub fn session_to_bus_properties(session: &Session) -> Vec<(String, String)> {
    vec![
        ("Id".into(), session.id.clone()),
        ("User".into(), session.user_name.clone()),
        ("Type".into(), session.session_type.as_str().to_string()),
        ("Class".into(), session.class.as_str().to_string()),
        ("State".into(), session.state.as_str().to_string()),
        (
            "Display".into(),
            session.display.clone().unwrap_or_default(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logind_core::{SessionClass, SessionType};
    use crate::logind_session::SessionState;

    #[test]
    fn session_bus_path_has_expected_shape() {
        assert_eq!(session_bus_path("c1"), "/org/freedesktop/login1/session/c1");
    }

    #[test]
    fn session_properties_include_core_fields() {
        let mut session = Session::new("c2".into(), "alice".into(), 1000);
        session.class = SessionClass::User;
        session.session_type = SessionType::Wayland;
        session.state = SessionState::Active;
        session.set_display(":1");
        let properties = session_to_bus_properties(&session);

        assert!(properties.contains(&("Id".into(), "c2".into())));
        assert!(properties.contains(&("User".into(), "alice".into())));
        assert!(properties.contains(&("Type".into(), "wayland".into())));
        assert!(properties.contains(&("State".into(), "active".into())));
        assert!(properties.contains(&("Display".into(), ":1".into())));
    }
}
