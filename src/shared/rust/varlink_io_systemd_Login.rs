// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Login.c
//
// Varlink interface definition for io.systemd.Login.
//
// APIs for managing login sessions, including session creation,
// session type/classification, and session release.

// ── Interface metadata ─────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.Login";

pub const METHOD_CREATE_SESSION: &str = "CreateSession";
pub const METHOD_RELEASE_SESSION: &str = "ReleaseSession";

pub const METHODS: &[&str] = &[METHOD_CREATE_SESSION, METHOD_RELEASE_SESSION];

// ── Enums ──────────────────────────────────────────────────────────────────

/// Session display type
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
    pub const ALL: &[SessionType] = &[
        SessionType::Unspecified,
        SessionType::Tty,
        SessionType::X11,
        SessionType::Wayland,
        SessionType::Mir,
        SessionType::Web,
    ];

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

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "unspecified" => Some(SessionType::Unspecified),
            "tty" => Some(SessionType::Tty),
            "x11" => Some(SessionType::X11),
            "wayland" => Some(SessionType::Wayland),
            "mir" => Some(SessionType::Mir),
            "web" => Some(SessionType::Web),
            _ => None,
        }
    }

    /// Returns true if this session type is graphical
    pub fn is_graphical(&self) -> bool {
        matches!(
            self,
            SessionType::X11 | SessionType::Wayland | SessionType::Mir | SessionType::Web
        )
    }
}

/// Session classification
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
    pub const ALL: &[SessionClass] = &[
        SessionClass::User,
        SessionClass::UserEarly,
        SessionClass::UserIncomplete,
        SessionClass::UserLight,
        SessionClass::UserEarlyLight,
        SessionClass::Greeter,
        SessionClass::LockScreen,
        SessionClass::Background,
        SessionClass::BackgroundLight,
        SessionClass::Manager,
        SessionClass::ManagerEarly,
    ];

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

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "user" => Some(SessionClass::User),
            "user_early" => Some(SessionClass::UserEarly),
            "user_incomplete" => Some(SessionClass::UserIncomplete),
            "user_light" => Some(SessionClass::UserLight),
            "user_early_light" => Some(SessionClass::UserEarlyLight),
            "greeter" => Some(SessionClass::Greeter),
            "lock_screen" => Some(SessionClass::LockScreen),
            "background" => Some(SessionClass::Background),
            "background_light" => Some(SessionClass::BackgroundLight),
            "manager" => Some(SessionClass::Manager),
            "manager_early" => Some(SessionClass::ManagerEarly),
            _ => None,
        }
    }

    /// Returns true if this is a user-type session
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

    /// Returns true if this is a manager-type session
    pub fn is_manager(&self) -> bool {
        matches!(self, SessionClass::Manager | SessionClass::ManagerEarly)
    }

    /// Returns true if this session class is "light" (no per-user service manager)
    pub fn is_light(&self) -> bool {
        matches!(
            self,
            SessionClass::User
                | SessionClass::UserLight
                | SessionClass::UserEarlyLight
                | SessionClass::BackgroundLight
        )
    }
}

// ── Structs ────────────────────────────────────────────────────────────────

/// Input for the CreateSession method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSessionInput {
    /// Numeric UNIX UID of the session owner
    pub uid: i64,
    /// Session type
    pub session_type: SessionType,
    /// Session class
    pub session_class: SessionClass,
    /// PAM service name
    pub service: Option<String>,
    /// Desktop identifier
    pub desktop: Option<String>,
    /// Seat assignment
    pub seat: Option<String>,
    /// Virtual terminal number
    pub vt_nr: Option<i64>,
    /// TTY device
    pub tty: Option<String>,
    /// X11 display
    pub display: Option<String>,
    /// Whether this is a remote session
    pub remote: Option<bool>,
    /// Remote user name
    pub remote_user: Option<String>,
    /// Remote host name
    pub remote_host: Option<String>,
    /// Additional device access IDs
    pub extra_device_access: Vec<String>,
}

impl CreateSessionInput {
    /// Validate session creation parameters
    pub fn validate(&self) -> Result<(), LoginError> {
        if self.uid < 0 {
            return Err(LoginError::NoSuchSession);
        }
        if let Some(vt) = self.vt_nr {
            if vt < 0 {
                return Err(LoginError::VirtualTerminalAlreadyTaken);
            }
        }
        Ok(())
    }
}

/// Output from the CreateSession method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSessionOutput {
    /// Session identifier string
    pub id: String,
    /// Runtime path ($XDG_RUNTIME_DIR)
    pub runtime_path: String,
    /// Original UID of this session
    pub uid: i64,
    /// Assigned seat
    pub seat: Option<String>,
    /// Assigned VT number
    pub vt_nr: Option<i64>,
    /// Assigned session type
    pub session_type: SessionType,
    /// Assigned session class
    pub session_class: SessionClass,
}

/// Input for the ReleaseSession method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseSessionInput {
    /// Session identifier to release (None or "self" for caller's session)
    pub id: Option<String>,
}

impl ReleaseSessionInput {
    /// Create input for releasing the caller's own session
    pub fn self_session() -> Self {
        Self { id: None }
    }

    /// Create input for releasing a specific session
    pub fn specific(id: String) -> Self {
        Self { id: Some(id) }
    }

    /// Returns true if this targets the caller's own session
    pub fn is_self(&self) -> bool {
        self.id.as_deref() == Some("self") || self.id.is_none()
    }
}

// ── Error types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginError {
    NoSuchSession,
    NoSuchSeat,
    AlreadySessionMember,
    VirtualTerminalAlreadyTaken,
    TooManySessions,
    UnitAllocationFailed,
    NoSessionPIDFD,
}

impl LoginError {
    pub fn error_id(&self) -> &'static str {
        match self {
            LoginError::NoSuchSession => "io.systemd.Login.NoSuchSession",
            LoginError::NoSuchSeat => "io.systemd.Login.NoSuchSeat",
            LoginError::AlreadySessionMember => "io.systemd.Login.AlreadySessionMember",
            LoginError::VirtualTerminalAlreadyTaken => {
                "io.systemd.Login.VirtualTerminalAlreadyTaken"
            }
            LoginError::TooManySessions => "io.systemd.Login.TooManySessions",
            LoginError::UnitAllocationFailed => "io.systemd.Login.UnitAllocationFailed",
            LoginError::NoSessionPIDFD => "io.systemd.Login.NoSessionPIDFD",
        }
    }
}

pub const ERROR_IDS: &[&str] = &[
    "io.systemd.Login.NoSuchSession",
    "io.systemd.Login.NoSuchSeat",
    "io.systemd.Login.AlreadySessionMember",
    "io.systemd.Login.VirtualTerminalAlreadyTaken",
    "io.systemd.Login.TooManySessions",
    "io.systemd.Login.UnitAllocationFailed",
    "io.systemd.Login.NoSessionPIDFD",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Login");
    }

    #[test]
    fn test_session_type_roundtrip() {
        for st in SessionType::ALL {
            assert_eq!(SessionType::from_str(st.as_str()), Some(*st));
        }
        assert_eq!(SessionType::ALL.len(), 6);
    }

    #[test]
    fn test_session_type_is_graphical() {
        assert!(SessionType::X11.is_graphical());
        assert!(SessionType::Wayland.is_graphical());
        assert!(!SessionType::Tty.is_graphical());
        assert!(!SessionType::Unspecified.is_graphical());
    }

    #[test]
    fn test_session_class_roundtrip() {
        for sc in SessionClass::ALL {
            assert_eq!(SessionClass::from_str(sc.as_str()), Some(*sc));
        }
        assert_eq!(SessionClass::ALL.len(), 11);
    }

    #[test]
    fn test_session_class_is_user() {
        assert!(SessionClass::User.is_user());
        assert!(SessionClass::UserEarly.is_user());
        assert!(SessionClass::UserLight.is_user());
        assert!(!SessionClass::Manager.is_user());
        assert!(!SessionClass::Greeter.is_user());
    }

    #[test]
    fn test_session_class_is_manager() {
        assert!(SessionClass::Manager.is_manager());
        assert!(SessionClass::ManagerEarly.is_manager());
        assert!(!SessionClass::User.is_manager());
    }

    #[test]
    fn test_session_class_is_light() {
        assert!(SessionClass::UserLight.is_light());
        assert!(SessionClass::UserEarlyLight.is_light());
        assert!(SessionClass::User.is_light());
    }

    #[test]
    fn test_create_session_input_validate() {
        let input = CreateSessionInput {
            uid: 1000,
            session_type: SessionType::Tty,
            session_class: SessionClass::User,
            service: None,
            desktop: None,
            seat: None,
            vt_nr: None,
            tty: None,
            display: None,
            remote: None,
            remote_user: None,
            remote_host: None,
            extra_device_access: vec![],
        };
        assert!(input.validate().is_ok());

        let bad_input = CreateSessionInput {
            uid: -1,
            ..input.clone()
        };
        assert_eq!(bad_input.validate(), Err(LoginError::NoSuchSession));
    }

    #[test]
    fn test_release_session_self() {
        let input = ReleaseSessionInput::self_session();
        assert!(input.is_self());
        assert!(input.id.is_none());
    }

    #[test]
    fn test_release_session_specific() {
        let input = ReleaseSessionInput::specific("c1".into());
        assert!(!input.is_self());
        assert_eq!(input.id.as_deref(), Some("c1"));
    }

    #[test]
    fn test_release_session_self_string() {
        let input = ReleaseSessionInput {
            id: Some("self".into()),
        };
        assert!(input.is_self());
    }

    #[test]
    fn test_error_ids() {
        assert_eq!(ERROR_IDS.len(), 7);
        assert!(
            LoginError::NoSuchSession
                .error_id()
                .contains("NoSuchSession")
        );
        assert!(
            LoginError::TooManySessions
                .error_id()
                .contains("TooManySessions")
        );
    }

    #[test]
    fn test_session_type_invalid() {
        assert_eq!(SessionType::from_str("invalid"), None);
        assert_eq!(SessionClass::from_str("invalid"), None);
    }
}
