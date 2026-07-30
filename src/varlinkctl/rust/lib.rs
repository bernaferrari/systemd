// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/varlinkctl/varlinkctl.c
//
// Varlink service introspection and method invocation tool.
//
// Implements the varlinkctl command-line tool for connecting to Varlink
// services, introspecting their interfaces, invoking methods, and validating
// interface descriptions. Supports multiple connection modes (AF_UNIX sockets,
// executable binaries, URLs) and output formats (text, JSON).

// ── Constants ─────────────────────────────────────────────────────────────

/// Default method call timeout in microseconds (0 = no timeout).
pub const DEFAULT_TIMEOUT_USEC: u64 = 0;

/// Exit code for OS errors from setfont (EX_OSERR).
pub const EX_OSERR: i32 = 71;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Varlink method call flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodFlags {
    /// Standard request-response call
    None,
    /// Request multiple responses (streaming)
    More,
    /// Fire-and-forget, no response expected
    Oneway,
}

impl MethodFlags {
    /// Check if the more flag is set.
    pub fn is_more(self) -> bool {
        self == Self::More
    }

    /// Check if the oneway flag is set.
    pub fn is_oneway(self) -> bool {
        self == Self::Oneway
    }
}

/// Varlink connection type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// AF_UNIX socket connection
    Socket,
    /// Spawn an executable binary
    Executable,
    /// URL-based connection
    Url,
}

/// Action verbs for varlinkctl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarlinkAction {
    /// Show service information
    Info,
    /// List interfaces implemented by service
    ListInterfaces,
    /// Show interface definition (or list methods)
    Introspect,
    /// List methods implemented by service
    ListMethods,
    /// Invoke a method
    Call,
    /// List services in the service registry
    ListRegistry,
    /// Validate an interface description file
    ValidateIdl,
    /// Show help
    Help,
}

impl std::str::FromStr for VarlinkAction {
    type Err = i32;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(Self::Info),
            "list-interfaces" => Ok(Self::ListInterfaces),
            "introspect" => Ok(Self::Introspect),
            "list-methods" => Ok(Self::ListMethods),
            "call" => Ok(Self::Call),
            "list-registry" => Ok(Self::ListRegistry),
            "validate-idl" => Ok(Self::ValidateIdl),
            "help" => Ok(Self::Help),
            _ => Err(-libc::EINVAL),
        }
    }
}

/// Verb definitions for varlinkctl command dispatch.
pub struct VerbDef {
    /// Command name
    pub name: &'static str,
    /// Minimum argument count
    pub min_args: usize,
    /// Maximum argument count (None = unlimited)
    pub max_args: Option<usize>,
    /// The action to dispatch
    pub action: VarlinkAction,
}

/// Static verb table matching the C tool's verbs[] array.
pub static VERBS: &[VerbDef] = &[
    VerbDef {
        name: "info",
        min_args: 2,
        max_args: Some(2),
        action: VarlinkAction::Info,
    },
    VerbDef {
        name: "list-interfaces",
        min_args: 2,
        max_args: Some(2),
        action: VarlinkAction::ListInterfaces,
    },
    VerbDef {
        name: "introspect",
        min_args: 2,
        max_args: None,
        action: VarlinkAction::Introspect,
    },
    VerbDef {
        name: "list-methods",
        min_args: 2,
        max_args: None,
        action: VarlinkAction::ListMethods,
    },
    VerbDef {
        name: "call",
        min_args: 3,
        max_args: None,
        action: VarlinkAction::Call,
    },
    VerbDef {
        name: "list-registry",
        min_args: 1,
        max_args: Some(1),
        action: VarlinkAction::ListRegistry,
    },
    VerbDef {
        name: "validate-idl",
        min_args: 1,
        max_args: Some(2),
        action: VarlinkAction::ValidateIdl,
    },
    VerbDef {
        name: "help",
        min_args: 0,
        max_args: None,
        action: VarlinkAction::Help,
    },
];

// ── Connection address parsing ────────────────────────────────────────────

/// Parse a Varlink address to determine the connection type.
pub fn parse_connection_type(address: &str) -> ConnectionType {
    if address.starts_with('/') || address.starts_with("./") {
        // Could be socket or executable - need stat to distinguish
        // For now, treat as socket if it looks like a path
        ConnectionType::Socket
    } else {
        ConnectionType::Url
    }
}

/// Determine if an address looks like a filesystem path.
pub fn address_is_path(address: &str) -> bool {
    address.starts_with('/') || address.starts_with("./")
}

// ── PushFds tracking ──────────────────────────────────────────────────────

/// Track file descriptors to push with method calls.
#[derive(Debug, Clone, Default)]
pub struct PushFds {
    /// Raw file descriptor numbers
    pub fds: Vec<i32>,
}

impl PushFds {
    /// Create an empty PushFds.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a file descriptor.
    pub fn push(&mut self, fd: i32) {
        self.fds.push(fd);
    }

    /// Number of file descriptors.
    pub fn len(&self) -> usize {
        self.fds.len()
    }

    /// Whether there are no file descriptors.
    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }
}

// ── Runtime scope ─────────────────────────────────────────────────────────

/// Runtime scope for service registry enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeScope {
    /// System-level registry
    System,
    /// User-level registry
    User,
}

impl RuntimeScope {
    /// Parse from a string.
    pub fn from_str_arg(s: &str) -> Result<Self, i32> {
        match s {
            "system" => Ok(Self::System),
            "user" => Ok(Self::User),
            _ => Err(-libc::EINVAL),
        }
    }
}

// ── Argument parsing result ───────────────────────────────────────────────

/// Parsed command-line arguments for varlinkctl.
#[derive(Debug, Clone)]
pub struct VarlinkctlArgs {
    /// The action to perform
    pub action: VarlinkAction,
    /// Method call flags
    pub method_flags: MethodFlags,
    /// Timeout in microseconds
    pub timeout_usec: u64,
    /// Whether to collect multiple responses
    pub collect: bool,
    /// Whether to suppress method reply output
    pub quiet: bool,
    /// Whether to exec a command with the response.
    ///
    /// PORT-GAP: C's `--exec` state is consumed by `verb_call()` and its
    /// executor in `src/varlinkctl/varlinkctl.c`. This Rust shadow does not
    /// yet parse or dispatch commands, so retaining the state is more
    /// faithful than pretending the feature is implemented.
    #[expect(
        dead_code,
        reason = "the C --exec parser and call executor must be ported together"
    )]
    exec: bool,
    /// Whether to ask for password
    pub ask_password: bool,
    /// Error names to treat as success
    pub graceful: Vec<String>,
    /// File descriptors to push
    pub push_fds: PushFds,
    /// Runtime scope for list-registry
    pub runtime_scope: RuntimeScope,
}

impl Default for VarlinkctlArgs {
    fn default() -> Self {
        Self {
            action: VarlinkAction::Help,
            method_flags: MethodFlags::None,
            timeout_usec: DEFAULT_TIMEOUT_USEC,
            collect: false,
            quiet: false,
            exec: false,
            ask_password: true,
            graceful: Vec::new(),
            push_fds: PushFds::new(),
            runtime_scope: RuntimeScope::System,
        }
    }
}

// ── Qualified symbol name validation ──────────────────────────────────────

/// Check if a string is a valid Varlink qualified symbol name.
/// A qualified name is "Interface.Name" where both parts follow Varlink naming rules.
pub fn qualified_symbol_name_is_valid(name: &str) -> bool {
    let dot_pos = match name.rfind('.') {
        Some(pos) => pos,
        None => return false,
    };
    let interface = &name[..dot_pos];
    let symbol = &name[dot_pos + 1..];
    !interface.is_empty()
        && !symbol.is_empty()
        && interface_name_is_valid(interface)
        && symbol_name_is_valid(symbol)
}

/// Check if a string is a valid Varlink interface name (e.g., "org.example.Service").
pub fn interface_name_is_valid(name: &str) -> bool {
    if name.is_empty() || name.starts_with('.') || name.ends_with('.') {
        return false;
    }
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// Check if a string is a valid Varlink symbol name.
pub fn symbol_name_is_valid(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    name.chars().all(|c| c.is_ascii_alphanumeric())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varlink_action_from_str() {
        assert_eq!("info".parse(), Ok(VarlinkAction::Info));
        assert_eq!("call".parse(), Ok(VarlinkAction::Call));
        assert_eq!("help".parse(), Ok(VarlinkAction::Help));
        assert_eq!("unknown".parse::<VarlinkAction>(), Err(-libc::EINVAL));
    }

    #[test]
    fn test_method_flags() {
        assert!(!MethodFlags::None.is_more());
        assert!(!MethodFlags::None.is_oneway());
        assert!(MethodFlags::More.is_more());
        assert!(MethodFlags::Oneway.is_oneway());
        assert!(!MethodFlags::More.is_oneway());
    }

    #[test]
    fn test_connection_type() {
        assert_eq!(parse_connection_type("/run/foo"), ConnectionType::Socket);
        assert_eq!(parse_connection_type("./foo"), ConnectionType::Socket);
        assert_eq!(parse_connection_type("unix:/run/foo"), ConnectionType::Url);
        assert_eq!(
            parse_connection_type("tcp:localhost:1234"),
            ConnectionType::Url
        );
    }

    #[test]
    fn test_address_is_path() {
        assert!(address_is_path("/run/systemd/resolved"));
        assert!(address_is_path("./local.sock"));
        assert!(!address_is_path("unix:/run/foo"));
        assert!(!address_is_path("tcp:host:1234"));
    }

    #[test]
    fn test_interface_name_is_valid() {
        assert!(interface_name_is_valid("org.varlink.service"));
        assert!(interface_name_is_valid("com.example.Foo"));
        assert!(!interface_name_is_valid(""));
        assert!(!interface_name_is_valid("single"));
        assert!(!interface_name_is_valid(".starts.dot"));
        assert!(!interface_name_is_valid("ends.dot."));
        assert!(!interface_name_is_valid("has empty.part"));
    }

    #[test]
    fn test_symbol_name_is_valid() {
        assert!(symbol_name_is_valid("GetInfo"));
        assert!(symbol_name_is_valid("Ping"));
        assert!(!symbol_name_is_valid(""));
        assert!(!symbol_name_is_valid("has space"));
        assert!(!symbol_name_is_valid("has.dot"));
    }

    #[test]
    fn test_qualified_symbol_name_is_valid() {
        assert!(qualified_symbol_name_is_valid(
            "org.varlink.service.GetInfo"
        ));
        assert!(qualified_symbol_name_is_valid("com.example.Service.Method"));
        assert!(!qualified_symbol_name_is_valid("NoDot"));
        assert!(!qualified_symbol_name_is_valid("org.Method")); // interface too short (single part ok actually with 2+)
        assert!(qualified_symbol_name_is_valid("org.Foo.Bar")); // 3 parts is fine
        assert!(!qualified_symbol_name_is_valid("org.varlink."));
        assert!(!qualified_symbol_name_is_valid(".Method"));
    }

    #[test]
    fn test_push_fds() {
        let mut pfds = PushFds::new();
        assert!(pfds.is_empty());
        assert_eq!(pfds.len(), 0);
        pfds.push(3);
        pfds.push(4);
        assert!(!pfds.is_empty());
        assert_eq!(pfds.len(), 2);
        assert_eq!(pfds.fds, vec![3, 4]);
    }

    #[test]
    fn test_runtime_scope() {
        assert_eq!(
            RuntimeScope::from_str_arg("system"),
            Ok(RuntimeScope::System)
        );
        assert_eq!(RuntimeScope::from_str_arg("user"), Ok(RuntimeScope::User));
        assert!(RuntimeScope::from_str_arg("invalid").is_err());
    }

    #[test]
    fn test_varlinkctl_args_default() {
        let args = VarlinkctlArgs::default();
        assert_eq!(args.action, VarlinkAction::Help);
        assert_eq!(args.method_flags, MethodFlags::None);
        assert_eq!(args.timeout_usec, 0);
        assert!(!args.collect);
        assert!(!args.quiet);
        assert!(args.graceful.is_empty());
        assert!(args.push_fds.is_empty());
        assert_eq!(args.runtime_scope, RuntimeScope::System);
    }

    #[test]
    fn test_verb_table_completeness() {
        let actions: Vec<&str> = VERBS.iter().map(|v| v.name).collect();
        assert!(actions.contains(&"info"));
        assert!(actions.contains(&"call"));
        assert!(actions.contains(&"list-registry"));
        assert!(actions.contains(&"validate-idl"));
        assert!(actions.contains(&"help"));
    }
}
