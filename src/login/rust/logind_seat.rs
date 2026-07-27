// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-seat.c

use crate::logind_core::seat_name_is_valid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatState {
    Online,
    Active,
    Closing,
}

impl SeatState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Active => "active",
            Self::Closing => "closing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seat {
    pub id: String,
    pub state: SeatState,
    pub sessions: Vec<String>,
    pub active_session: Option<String>,
    pub can_tty: bool,
    pub can_graphical: bool,
}

impl Seat {
    pub fn new(id: impl Into<String>) -> Result<Self, String> {
        let id = id.into();
        if !seat_name_is_valid(&id) {
            return Err(format!("invalid seat name: {id}"));
        }

        Ok(Self {
            id,
            state: SeatState::Online,
            sessions: Vec::new(),
            active_session: None,
            can_tty: true,
            can_graphical: false,
        })
    }

    pub fn attach_session(&mut self, session_id: impl Into<String>) {
        let session_id = session_id.into();
        if !self.sessions.contains(&session_id) {
            self.sessions.push(session_id.clone());
        }
        self.active_session = Some(session_id);
        self.state = SeatState::Active;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_session_sets_active_state_and_session() {
        let mut seat = Seat::new("seat0").expect("seat should be valid");
        seat.attach_session("c1");

        assert_eq!(seat.state, SeatState::Active);
        assert_eq!(seat.active_session.as_deref(), Some("c1"));
        assert_eq!(seat.sessions, vec!["c1".to_string()]);
    }

    #[test]
    fn attach_session_deduplicates_entries() {
        let mut seat = Seat::new("seat0").expect("seat should be valid");
        seat.attach_session("c1");
        seat.attach_session("c1");

        assert_eq!(seat.sessions, vec!["c1".to_string()]);
    }
}
