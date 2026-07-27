// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-user.c

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserState {
    Linger,
    Online,
    Active,
    Closing,
}

impl UserState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linger => "linger",
            Self::Online => "online",
            Self::Active => "active",
            Self::Closing => "closing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub user_name: String,
    pub state: UserState,
    pub linger: bool,
    pub display: Option<String>,
    pub sessions: Vec<String>,
}

impl User {
    pub fn new(uid: u32, gid: u32, user_name: impl Into<String>) -> Self {
        Self {
            uid,
            gid,
            user_name: user_name.into(),
            state: UserState::Online,
            linger: false,
            display: None,
            sessions: Vec::new(),
        }
    }

    pub fn add_session(&mut self, session_id: impl Into<String>) {
        let session_id = session_id.into();
        if !self.sessions.contains(&session_id) {
            self.sessions.push(session_id);
        }
        self.state = UserState::Active;
    }

    pub fn remove_session(&mut self, session_id: &str) {
        self.sessions.retain(|current| current != session_id);
        self.state = if self.sessions.is_empty() {
            if self.linger {
                UserState::Linger
            } else {
                UserState::Closing
            }
        } else {
            UserState::Active
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_session_deduplicates_and_activates() {
        let mut user = User::new(1000, 1000, "alice");
        user.add_session("c1");
        user.add_session("c1");

        assert_eq!(user.sessions, vec!["c1".to_string()]);
        assert_eq!(user.state, UserState::Active);
    }

    #[test]
    fn remove_session_transitions_to_closing_without_linger() {
        let mut user = User::new(1000, 1000, "alice");
        user.add_session("c1");
        user.remove_session("c1");

        assert!(user.sessions.is_empty());
        assert_eq!(user.state, UserState::Closing);
    }

    #[test]
    fn remove_session_transitions_to_linger_when_enabled() {
        let mut user = User::new(1000, 1000, "alice");
        user.linger = true;
        user.add_session("c1");
        user.remove_session("c1");

        assert!(user.sessions.is_empty());
        assert_eq!(user.state, UserState::Linger);
    }
}
