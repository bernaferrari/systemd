// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-user-dbus.c

use crate::logind_dbus::BUS_PATH;
use crate::logind_user::User;

pub fn user_bus_path(uid: u32) -> String {
    format!("{BUS_PATH}/user/_{uid}")
}

pub fn user_to_bus_properties(user: &User) -> Vec<(String, String)> {
    vec![
        ("UID".into(), user.uid.to_string()),
        ("GID".into(), user.gid.to_string()),
        ("Name".into(), user.user_name.clone()),
        ("State".into(), user.state.as_str().to_string()),
        ("Display".into(), user.display.clone().unwrap_or_default()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logind_user::UserState;

    #[test]
    fn user_bus_path_has_expected_shape() {
        assert_eq!(user_bus_path(1000), "/org/freedesktop/login1/user/_1000");
    }

    #[test]
    fn user_properties_include_identity_and_state() {
        let mut user = User::new(1000, 1000, "alice");
        user.state = UserState::Active;
        user.display = Some(":1".into());
        let properties = user_to_bus_properties(&user);

        assert!(properties.contains(&("UID".into(), "1000".into())));
        assert!(properties.contains(&("GID".into(), "1000".into())));
        assert!(properties.contains(&("Name".into(), "alice".into())));
        assert!(properties.contains(&("State".into(), "active".into())));
        assert!(properties.contains(&("Display".into(), ":1".into())));
    }
}
