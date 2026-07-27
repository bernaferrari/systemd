// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/test-login-tables.c

use crate::logind_action::HandleAction;
use crate::logind_core::{KillWho, SessionClass, SessionType};
use crate::logind_session::SessionState;
use crate::logind_user::UserState;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_actions_have_expected_strings() {
        assert_eq!(HandleAction::PowerOff.as_str(), "poweroff");
        assert_eq!(HandleAction::Suspend.as_str(), "suspend");
        assert_eq!(HandleAction::HybridSleep.as_str(), "hybrid-sleep");
    }

    #[test]
    fn shared_tables_match_expected_strings() {
        assert_eq!(SessionClass::User.as_str(), "user");
        assert_eq!(SessionType::Wayland.as_str(), "wayland");
        assert_eq!(KillWho::Leader.as_str(), "leader");
        assert_eq!(SessionState::Active.as_str(), "active");
        assert_eq!(UserState::Online.as_str(), "online");
    }
}
