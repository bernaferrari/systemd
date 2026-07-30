// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/test-session-properties.c

use crate::logind_core::SessionType;
use crate::logind_session::Session;
use std::str::FromStr;

pub fn all_session_types() -> [SessionType; 5] {
    [
        SessionType::Tty,
        SessionType::X11,
        SessionType::Wayland,
        SessionType::Mir,
        SessionType::Web,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_types_round_trip() {
        for ty in all_session_types() {
            assert_eq!(SessionType::from_str(ty.as_str()), Ok(ty));
        }
    }

    #[test]
    fn display_is_empty_by_default() {
        let session = Session::new("c1".into(), "alice".into(), 1000);
        assert_eq!(session.display.as_deref(), None);
    }

    #[test]
    fn control_release_restores_prior_display_and_type() {
        let mut session = Session::new("c1".into(), "alice".into(), 1000);
        session.set_type(SessionType::Wayland);
        session.set_display(":1");
        session.take_control("greeter");
        session.set_type(SessionType::Tty);
        session.display = None;

        session.release_control();

        assert_eq!(session.session_type, SessionType::Wayland);
        assert_eq!(session.display.as_deref(), Some(":1"));
    }
}
