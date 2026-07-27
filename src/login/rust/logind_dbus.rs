// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-dbus.c

pub const BUS_LOGIN_INTERFACE: &str = "org.freedesktop.login1.Manager";
pub const BUS_SEAT_INTERFACE: &str = "org.freedesktop.login1.Seat";
pub const BUS_SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
pub const BUS_USER_INTERFACE: &str = "org.freedesktop.login1.User";
pub const BUS_PATH: &str = "/org/freedesktop/login1";

pub fn manager_bus_path() -> &'static str {
    BUS_PATH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interfaces_share_namespace() {
        assert!(BUS_LOGIN_INTERFACE.starts_with("org.freedesktop.login1"));
        assert!(BUS_SEAT_INTERFACE.starts_with("org.freedesktop.login1"));
        assert!(BUS_SESSION_INTERFACE.starts_with("org.freedesktop.login1"));
        assert!(BUS_USER_INTERFACE.starts_with("org.freedesktop.login1"));
    }
}
