// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Login.c
//
// Varlink interface definition for io.systemd.Login
// APIs for managing login sessions.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface name for the Login service
pub const INTERFACE_NAME: &str = "io.systemd.Login";

/// Method name for CreateSession
pub const METHOD_CREATE_SESSION: &str = "io.systemd.Login.CreateSession";

/// Method name for ReleaseSession
pub const METHOD_RELEASE_SESSION: &str = "io.systemd.Login.ReleaseSession";

/// Error name for NoSuchSession
pub const ERROR_NO_SUCH_SESSION: &str = "io.systemd.Login.NoSuchSession";

/// Error name for NoSuchSeat
pub const ERROR_NO_SUCH_SEAT: &str = "io.systemd.Login.NoSuchSeat";

/// Error name for AlreadySessionMember
pub const ERROR_ALREADY_SESSION_MEMBER: &str = "io.systemd.Login.AlreadySessionMember";

/// Error name for VirtualTerminalAlreadyTaken
pub const ERROR_VIRTUAL_TERMINAL_ALREADY_TAKEN: &str =
    "io.systemd.Login.VirtualTerminalAlreadyTaken";

/// Error name for TooManySessions
pub const ERROR_TOO_MANY_SESSIONS: &str = "io.systemd.Login.TooManySessions";

/// Error name for UnitAllocationFailed
pub const ERROR_UNIT_ALLOCATION_FAILED: &str = "io.systemd.Login.UnitAllocationFailed";

/// Error name for NoSessionPIDFD
pub const ERROR_NO_SESSION_PIDFD: &str = "io.systemd.Login.NoSessionPIDFD";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Session type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    Unspecified,
    Tty,
    X11,
    Wayland,
    Mir,
    Web,
}

impl SessionType {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "unspecified" => Ok(SessionType::Unspecified),
            "tty" => Ok(SessionType::Tty),
            "x11" => Ok(SessionType::X11),
            "wayland" => Ok(SessionType::Wayland),
            "mir" => Ok(SessionType::Mir),
            "web" => Ok(SessionType::Web),
            _ => Err(-22),
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionType::Unspecified => "unspecified",
            SessionType::Tty => "tty",
            SessionType::X11 => "x11",
            SessionType::Wayland => "wayland",
            SessionType::Mir => "mir",
            SessionType::Web => "web",
        }
    }
}

/// Session class enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionClass {
    User,
    UserEarly,
    UserIncomplete,
    UserLight,
    UserEarlyLight,
    Greeter,
    LockScreen,
    Background,
    BackgroundLight,
    Manager,
    ManagerEarly,
}

impl SessionClass {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "user" => Ok(SessionClass::User),
            "user_early" => Ok(SessionClass::UserEarly),
            "user_incomplete" => Ok(SessionClass::UserIncomplete),
            "user_light" => Ok(SessionClass::UserLight),
            "user_early_light" => Ok(SessionClass::UserEarlyLight),
            "greeter" => Ok(SessionClass::Greeter),
            "lock_screen" => Ok(SessionClass::LockScreen),
            "background" => Ok(SessionClass::Background),
            "background_light" => Ok(SessionClass::BackgroundLight),
            "manager" => Ok(SessionClass::Manager),
            "manager_early" => Ok(SessionClass::ManagerEarly),
            _ => Err(-22),
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionClass::User => "user",
            SessionClass::UserEarly => "user_early",
            SessionClass::UserIncomplete => "user_incomplete",
            SessionClass::UserLight => "user_light",
            SessionClass::UserEarlyLight => "user_early_light",
            SessionClass::Greeter => "greeter",
            SessionClass::LockScreen => "lock_screen",
            SessionClass::Background => "background",
            SessionClass::BackgroundLight => "background_light",
            SessionClass::Manager => "manager",
            SessionClass::ManagerEarly => "manager_early",
        }
    }

    /// Check if this is a user session class
    pub fn is_user(&self) -> bool {
        matches!(
            self,
            SessionClass::User
                | SessionClass::UserEarly
                | SessionClass::UserIncomplete
                | SessionClass::UserLight
                | SessionClass::UserEarlyLight
        )
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Parameters for CreateSession method
#[derive(Debug, Clone, Default)]
pub struct CreateSessionParams {
    pub uid: i64,
    pub service: Option<String>,
    pub session_type: SessionType,
    pub session_class: SessionClass,
    pub desktop: Option<String>,
    pub seat: Option<String>,
    pub vt_nr: Option<i64>,
    pub tty: Option<String>,
    pub display: Option<String>,
    pub remote: Option<bool>,
    pub remote_user: Option<String>,
    pub remote_host: Option<String>,
}

/// Result of CreateSession
#[derive(Debug, Clone)]
pub struct CreateSessionResult {
    pub id: String,
    pub runtime_path: String,
    pub uid: i64,
    pub seat: Option<String>,
    pub vt_nr: Option<i64>,
    pub session_type: SessionType,
    pub session_class: SessionClass,
}

/// Parameters for ReleaseSession method
#[derive(Debug, Clone, Default)]
pub struct ReleaseSessionParams {
    pub id: Option<String>,
}

impl ReleaseSessionParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Get all known error names
pub fn error_names() -> &'static [&'static str] {
    &[
        ERROR_NO_SUCH_SESSION,
        ERROR_NO_SUCH_SEAT,
        ERROR_ALREADY_SESSION_MEMBER,
        ERROR_VIRTUAL_TERMINAL_ALREADY_TAKEN,
        ERROR_TOO_MANY_SESSIONS,
        ERROR_UNIT_ALLOCATION_FAILED,
        ERROR_NO_SESSION_PIDFD,
    ]
}

/// Check if an error name belongs to this interface
pub fn is_known_error(name: &str) -> bool {
    error_names().contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Login");
    }

    #[test]
    fn test_method_names() {
        assert_eq!(METHOD_CREATE_SESSION, "io.systemd.Login.CreateSession");
        assert_eq!(METHOD_RELEASE_SESSION, "io.systemd.Login.ReleaseSession");
    }

    #[test]
    fn test_error_names() {
        assert_eq!(ERROR_NO_SUCH_SESSION, "io.systemd.Login.NoSuchSession");
        assert_eq!(ERROR_NO_SUCH_SEAT, "io.systemd.Login.NoSuchSeat");
        assert_eq!(
            ERROR_ALREADY_SESSION_MEMBER,
            "io.systemd.Login.AlreadySessionMember"
        );
    }

    #[test]
    fn test_session_type_from_str() {
        assert_eq!(SessionType::from_str("tty"), Ok(SessionType::Tty));
        assert_eq!(SessionType::from_str("wayland"), Ok(SessionType::Wayland));
        assert!(SessionType::from_str("unknown").is_err());
    }

    #[test]
    fn test_session_type_as_str() {
        assert_eq!(SessionType::Tty.as_str(), "tty");
        assert_eq!(SessionType::Wayland.as_str(), "wayland");
        assert_eq!(SessionType::Unspecified.as_str(), "unspecified");
    }

    #[test]
    fn test_session_class_from_str() {
        assert_eq!(SessionClass::from_str("user"), Ok(SessionClass::User));
        assert_eq!(SessionClass::from_str("greeter"), Ok(SessionClass::Greeter));
        assert_eq!(
            SessionClass::from_str("lock_screen"),
            Ok(SessionClass::LockScreen)
        );
        assert!(SessionClass::from_str("unknown").is_err());
    }

    #[test]
    fn test_session_class_as_str() {
        assert_eq!(SessionClass::User.as_str(), "user");
        assert_eq!(SessionClass::Manager.as_str(), "manager");
        assert_eq!(SessionClass::UserEarlyLight.as_str(), "user_early_light");
    }

    #[test]
    fn test_session_class_is_user() {
        assert!(SessionClass::User.is_user());
        assert!(SessionClass::UserEarly.is_user());
        assert!(SessionClass::UserLight.is_user());
        assert!(!SessionClass::Greeter.is_user());
        assert!(!SessionClass::Manager.is_user());
    }

    #[test]
    fn test_session_type_equality() {
        assert_eq!(SessionType::Tty, SessionType::Tty);
        assert_ne!(SessionType::Tty, SessionType::X11);
    }

    #[test]
    fn test_error_names_list() {
        let names = error_names();
        assert_eq!(names.len(), 7);
        assert!(names.contains(&ERROR_NO_SUCH_SESSION));
        assert!(names.contains(&ERROR_NO_SESSION_PIDFD));
    }

    #[test]
    fn test_is_known_error() {
        assert!(is_known_error("io.systemd.Login.NoSuchSession"));
        assert!(is_known_error("io.systemd.Login.TooManySessions"));
        assert!(!is_known_error("io.systemd.Login.Unknown"));
    }

    #[test]
    fn test_release_session_params() {
        let params = ReleaseSessionParams::new().id("session1");
        assert_eq!(params.id, Some("session1".to_string()));

        let params = ReleaseSessionParams::new();
        assert!(params.id.is_none());
    }

    #[test]
    fn test_create_session_params_default() {
        let params = CreateSessionParams::default();
        assert_eq!(params.uid, 0);
        assert!(params.service.is_none());
        assert!(params.seat.is_none());
    }
}
