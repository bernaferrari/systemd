// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-seat-dbus.c

use crate::logind_dbus::BUS_PATH;
use crate::logind_seat::Seat;

pub fn seat_bus_path(seat_id: &str) -> String {
    format!("{BUS_PATH}/seat/{seat_id}")
}

pub fn seat_to_bus_properties(seat: &Seat) -> Vec<(String, String)> {
    vec![
        ("Id".into(), seat.id.clone()),
        (
            "ActiveSession".into(),
            seat.active_session.clone().unwrap_or_default(),
        ),
        ("CanTTY".into(), seat.can_tty.to_string()),
        ("CanGraphical".into(), seat.can_graphical.to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logind_seat::SeatState;

    #[test]
    fn seat_bus_path_has_expected_shape() {
        assert_eq!(seat_bus_path("seat0"), "/org/freedesktop/login1/seat/seat0");
    }

    #[test]
    fn seat_properties_include_runtime_fields() {
        let mut seat = Seat::new("seat0").expect("valid seat");
        seat.state = SeatState::Active;
        seat.attach_session("c1");
        seat.can_graphical = true;

        let properties = seat_to_bus_properties(&seat);
        assert!(properties.contains(&("Id".into(), "seat0".into())));
        assert!(properties.contains(&("ActiveSession".into(), "c1".into())));
        assert!(properties.contains(&("CanTTY".into(), "true".into())));
        assert!(properties.contains(&("CanGraphical".into(), "true".into())));
    }
}
