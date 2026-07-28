// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Machine.c
//
// Varlink interface definition for io.systemd.Machine.
//
// APIs for managing local and virtual machines/containers, including
// registration, lifecycle control, ID mapping, file operations, and more.

// ── Interface metadata ─────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.Machine";

pub const METHOD_REGISTER: &str = "Register";
pub const METHOD_UNREGISTER: &str = "Unregister";
pub const METHOD_TERMINATE: &str = "Terminate";
pub const METHOD_KILL: &str = "Kill";
pub const METHOD_LIST: &str = "List";
pub const METHOD_OPEN: &str = "Open";
pub const METHOD_MAP_FROM: &str = "MapFrom";
pub const METHOD_MAP_TO: &str = "MapTo";
pub const METHOD_BIND_MOUNT: &str = "BindMount";
pub const METHOD_COPY_FROM: &str = "CopyFrom";
pub const METHOD_COPY_TO: &str = "CopyTo";
pub const METHOD_OPEN_ROOT_DIRECTORY: &str = "OpenRootDirectory";

pub const METHODS: &[&str] = &[
    METHOD_REGISTER,
    METHOD_UNREGISTER,
    METHOD_TERMINATE,
    METHOD_KILL,
    METHOD_LIST,
    METHOD_OPEN,
    METHOD_MAP_FROM,
    METHOD_MAP_TO,
    METHOD_BIND_MOUNT,
    METHOD_COPY_FROM,
    METHOD_COPY_TO,
    METHOD_OPEN_ROOT_DIRECTORY,
];

// ── Enums ──────────────────────────────────────────────────────────────────

/// Controls metadata inclusion in output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireMetadata {
    /// Do not include metadata
    No,
    /// Include metadata
    Yes,
    /// Include metadata, gracefully eat errors
    Graceful,
}

impl AcquireMetadata {
    pub fn as_str(&self) -> &'static str {
        match self {
            AcquireMetadata::No => "no",
            AcquireMetadata::Yes => "yes",
            AcquireMetadata::Graceful => "graceful",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "no" => Some(AcquireMetadata::No),
            "yes" => Some(AcquireMetadata::Yes),
            "graceful" => Some(AcquireMetadata::Graceful),
            _ => None,
        }
    }

    /// Whether to actually include metadata
    pub fn should_include(&self) -> bool {
        !matches!(self, AcquireMetadata::No)
    }
}

/// Kill target specification for the Kill method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillWhom {
    Leader,
    Supervisor,
    All,
}

impl KillWhom {
    pub fn as_str(&self) -> &'static str {
        match self {
            KillWhom::Leader => "leader",
            KillWhom::Supervisor => "supervisor",
            KillWhom::All => "all",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "leader" => Some(KillWhom::Leader),
            "supervisor" => Some(KillWhom::Supervisor),
            "all" => Some(KillWhom::All),
            _ => None,
        }
    }
}

/// Machine open mode for TTY allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineOpenMode {
    /// Allocate a pseudo TTY
    Tty,
    /// Allocate a PTY with a login prompt
    Login,
    /// Allocate a PTY and invoke a shell/command
    Shell,
}

impl MachineOpenMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MachineOpenMode::Tty => "tty",
            MachineOpenMode::Login => "login",
            MachineOpenMode::Shell => "shell",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "tty" => Some(MachineOpenMode::Tty),
            "login" => Some(MachineOpenMode::Login),
            "shell" => Some(MachineOpenMode::Shell),
            _ => None,
        }
    }
}

// ── Structs ────────────────────────────────────────────────────────────────

/// Network address of a machine
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Interface index
    pub ifindex: Option<i64>,
    /// Address family (AF_INET, AF_INET6, etc.)
    pub family: i64,
    /// Address bytes
    pub address: Vec<u8>,
}

impl Address {
    pub fn new_ipv4(addr: [u8; 4]) -> Self {
        Self {
            ifindex: None,
            family: 2, // AF_INET
            address: addr.to_vec(),
        }
    }

    pub fn new_ipv6(addr: [u8; 16]) -> Self {
        Self {
            ifindex: None,
            family: 10, // AF_INET6
            address: addr.to_vec(),
        }
    }

    pub fn is_ipv4(&self) -> bool {
        self.family == 2
    }

    pub fn is_ipv6(&self) -> bool {
        self.family == 10
    }
}

/// Machine lookup parameters used by multiple methods
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineLookup {
    /// Machine name
    pub name: Option<String>,
    /// Machine PID (0 = caller's machine)
    pub pid: Option<i64>,
}

impl MachineLookup {
    /// Lookup by name
    pub fn by_name(name: String) -> Self {
        Self {
            name: Some(name),
            pid: None,
        }
    }

    /// Lookup by PID
    pub fn by_pid(pid: i64) -> Self {
        Self {
            name: None,
            pid: Some(pid),
        }
    }

    /// Validate lookup has at least one identifier
    pub fn validate(&self) -> Result<(), MachineError> {
        if self.name.is_none() && self.pid.is_none() {
            return Err(MachineError::NoSuchMachine);
        }
        if let Some(ref name) = self.name {
            if name.is_empty() {
                return Err(MachineError::NoSuchMachine);
            }
        }
        Ok(())
    }
}

/// Input for the Kill method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillInput {
    pub lookup: MachineLookup,
    pub whom: Option<KillWhom>,
    pub signal: i64,
}

impl KillInput {
    /// Validate kill parameters
    pub fn validate(&self) -> Result<(), MachineError> {
        self.lookup.validate()?;
        if !(1..=31).contains(&self.signal) {
            return Err(MachineError::NotSupported);
        }
        Ok(())
    }
}

// ── Error types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineError {
    NoSuchMachine,
    MachineExists,
    NoPrivateNetworking,
    NoOSReleaseInformation,
    NoUIDShift,
    NotAvailable,
    NotSupported,
    NoIPC,
    NoSuchUser,
    NoSuchGroup,
    UserInHostRange,
    GroupInHostRange,
}

impl MachineError {
    pub fn error_id(&self) -> &'static str {
        match self {
            MachineError::NoSuchMachine => "io.systemd.Machine.NoSuchMachine",
            MachineError::MachineExists => "io.systemd.Machine.MachineExists",
            MachineError::NoPrivateNetworking => "io.systemd.Machine.NoPrivateNetworking",
            MachineError::NoOSReleaseInformation => "io.systemd.Machine.NoOSReleaseInformation",
            MachineError::NoUIDShift => "io.systemd.Machine.NoUIDShift",
            MachineError::NotAvailable => "io.systemd.Machine.NotAvailable",
            MachineError::NotSupported => "io.systemd.Machine.NotSupported",
            MachineError::NoIPC => "io.systemd.Machine.NoIPC",
            MachineError::NoSuchUser => "io.systemd.Machine.NoSuchUser",
            MachineError::NoSuchGroup => "io.systemd.Machine.NoSuchGroup",
            MachineError::UserInHostRange => "io.systemd.Machine.UserInHostRange",
            MachineError::GroupInHostRange => "io.systemd.Machine.GroupInHostRange",
        }
    }
}

pub const ERROR_IDS: &[&str] = &[
    "io.systemd.Machine.NoSuchMachine",
    "io.systemd.Machine.MachineExists",
    "io.systemd.Machine.NoPrivateNetworking",
    "io.systemd.Machine.NoOSReleaseInformation",
    "io.systemd.Machine.NoUIDShift",
    "io.systemd.Machine.NotAvailable",
    "io.systemd.Machine.NotSupported",
    "io.systemd.Machine.NoIPC",
    "io.systemd.Machine.NoSuchUser",
    "io.systemd.Machine.NoSuchGroup",
    "io.systemd.Machine.UserInHostRange",
    "io.systemd.Machine.GroupInHostRange",
];

// ── Helper functions ───────────────────────────────────────────────────────

/// Validate a UNIX signal number
pub fn is_valid_signal(sig: i64) -> bool {
    (1..=31).contains(&sig)
}

/// Validate a machine name
pub fn is_valid_machine_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('\0') && name.len() <= 255
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Machine");
        assert_eq!(METHODS.len(), 12);
    }

    #[test]
    fn test_acquire_metadata_roundtrip() {
        assert_eq!(AcquireMetadata::from_str("no"), Some(AcquireMetadata::No));
        assert_eq!(AcquireMetadata::from_str("yes"), Some(AcquireMetadata::Yes));
        assert_eq!(
            AcquireMetadata::from_str("graceful"),
            Some(AcquireMetadata::Graceful)
        );
        assert_eq!(AcquireMetadata::from_str("maybe"), None);
    }

    #[test]
    fn test_acquire_metadata_should_include() {
        assert!(!AcquireMetadata::No.should_include());
        assert!(AcquireMetadata::Yes.should_include());
        assert!(AcquireMetadata::Graceful.should_include());
    }

    #[test]
    fn test_kill_whom_roundtrip() {
        assert_eq!(KillWhom::from_str("leader"), Some(KillWhom::Leader));
        assert_eq!(KillWhom::from_str("supervisor"), Some(KillWhom::Supervisor));
        assert_eq!(KillWhom::from_str("all"), Some(KillWhom::All));
        assert_eq!(KillWhom::from_str("none"), None);
    }

    #[test]
    fn test_machine_open_mode_roundtrip() {
        assert_eq!(MachineOpenMode::from_str("tty"), Some(MachineOpenMode::Tty));
        assert_eq!(
            MachineOpenMode::from_str("login"),
            Some(MachineOpenMode::Login)
        );
        assert_eq!(
            MachineOpenMode::from_str("shell"),
            Some(MachineOpenMode::Shell)
        );
        assert_eq!(MachineOpenMode::from_str("invalid"), None);
    }

    #[test]
    fn test_address_ipv4() {
        let addr = Address::new_ipv4([127, 0, 0, 1]);
        assert!(addr.is_ipv4());
        assert!(!addr.is_ipv6());
        assert_eq!(addr.address.len(), 4);
    }

    #[test]
    fn test_address_ipv6() {
        let addr = Address::new_ipv6([0; 16]);
        assert!(addr.is_ipv6());
        assert!(!addr.is_ipv4());
        assert_eq!(addr.address.len(), 16);
    }

    #[test]
    fn test_machine_lookup_by_name() {
        let lookup = MachineLookup::by_name("test-machine".into());
        assert_eq!(lookup.name.as_deref(), Some("test-machine"));
        assert!(lookup.pid.is_none());
        assert!(lookup.validate().is_ok());
    }

    #[test]
    fn test_machine_lookup_by_pid() {
        let lookup = MachineLookup::by_pid(1234);
        assert!(lookup.name.is_none());
        assert_eq!(lookup.pid, Some(1234));
        assert!(lookup.validate().is_ok());
    }

    #[test]
    fn test_machine_lookup_empty_fails() {
        let lookup = MachineLookup {
            name: None,
            pid: None,
        };
        assert_eq!(lookup.validate(), Err(MachineError::NoSuchMachine));

        let empty_name = MachineLookup {
            name: Some(String::new()),
            pid: None,
        };
        assert_eq!(empty_name.validate(), Err(MachineError::NoSuchMachine));
    }

    #[test]
    fn test_kill_input_validate() {
        let input = KillInput {
            lookup: MachineLookup::by_name("test".into()),
            whom: Some(KillWhom::All),
            signal: 9,
        };
        assert!(input.validate().is_ok());

        let bad_signal = KillInput {
            lookup: MachineLookup::by_name("test".into()),
            whom: None,
            signal: 99,
        };
        assert_eq!(bad_signal.validate(), Err(MachineError::NotSupported));
    }

    #[test]
    fn test_is_valid_signal() {
        assert!(is_valid_signal(1)); // SIGHUP
        assert!(is_valid_signal(9)); // SIGKILL
        assert!(is_valid_signal(15)); // SIGTERM
        assert!(is_valid_signal(31));
        assert!(!is_valid_signal(0));
        assert!(!is_valid_signal(32));
        assert!(!is_valid_signal(-1));
    }

    #[test]
    fn test_is_valid_machine_name() {
        assert!(is_valid_machine_name("my-container"));
        assert!(is_valid_machine_name("machine1"));
        assert!(!is_valid_machine_name(""));
        assert!(!is_valid_machine_name("has\0null"));
    }

    #[test]
    fn test_error_ids() {
        assert_eq!(ERROR_IDS.len(), 12);
        assert!(
            MachineError::NoSuchMachine
                .error_id()
                .contains("NoSuchMachine")
        );
        assert!(
            MachineError::GroupInHostRange
                .error_id()
                .contains("GroupInHostRange")
        );
    }
}
