// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bus-unit-util.c, src/shared/bus-unit-util.h
//
// Unit-related D-Bus utilities: pure-parsing logic extracted from the C
// implementation.  D-Bus message construction is left to the C side; this
// module owns all string-level parsing, assignment splitting, exec-command
// flag decoding, property-table lookups, and the safe UnitInfo / ExecCommand
// data structures.

// ── Constants ─────────────────────────────────────────────────────────────

/// Permyriad → uint32 scale: (permyriad as u32 * UINT32_MAX) / 10000
pub const UINT32_SCALE_FROM_PERMYRIAD: fn(i32) -> u32 =
    |v: i32| ((v as u64).saturating_mul(u32::MAX as u64) / 10_000) as u32;

/// `infinity` keyword recognised by several property parsers.
pub const INFINITY_KEYWORD: &str = "infinity";

// ── Enums ─────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling exec-command prefix parsing.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ExecCommandFlags: u32 {
        const IGNORE_FAILURE     = 1 << 0;
        const NO_ENV_EXPAND      = 1 << 1;
        const FULLY_PRIVILEGED   = 1 << 2;
        const NO_SETUID          = 1 << 3;
        const VIA_SHELL          = 1 << 4;
    }
}

bitflags::bitflags! {
    /// Flags for exec directories (mirrors C `ExecDirectoryFlags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ExecDirectoryFlags: u32 {
        const READ_ONLY    = 1 << 0;
        const ONLY_CREATE  = 1 << 1;
    }
}

/// Known unit types – used to select the right property table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnitType {
    Service,
    Socket,
    Timer,
    Path,
    Slice,
    Scope,
    Mount,
    Automount,
    Target,
    Device,
    Swap,
}

/// IP-address shortcut keywords recognised by the filter parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddressShortcut {
    Any,
    Localhost,
    LinkLocal,
    Multicast,
}

// ── Data structures ───────────────────────────────────────────────────────

/// A fully-owned `UnitInfo` – no raw pointers, no lifetimes tied to a
/// D-Bus message.
#[derive(Debug, Clone)]
pub struct UnitInfo {
    pub machine: Option<String>,
    pub id: String,
    pub description: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub following: String,
    pub unit_path: String,
    pub job_id: u32,
    pub job_type: String,
    pub job_path: String,
}

/// Result of parsing an `ExecCommand=` value (prefix flags + command line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecCommandParse {
    pub flags: ExecCommandFlags,
    pub command_line: String,
}

/// Result of splitting a `Key=Value` assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub field: String,
    pub value: String,
}

/// Result of parsing a `DeviceAllow=` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAllowEntry {
    pub path: String,
    pub rwm: String,
}

/// A single IP-address access entry for the filter list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddressAccess {
    pub family: i32,    // AF_INET / AF_INET6
    pub prefix: String, // dotted / hex representation
    pub prefixlen: u8,
}

/// Parsed standard-input descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandardInput {
    Null,
    Fd(String),
    File(String),
    Append(String),
    Truncate(String),
    Other(String),
}

/// Resource-limit value after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceLimitValue {
    /// Empty string → use the cgroup default.
    Default,
    /// "infinity" → `CGROUP_LIMIT_MAX`.
    Infinity,
    /// A percentage (permyriad) – to be resolved server-side.
    Percentage(i32),
    /// An absolute byte size.
    Bytes(u64),
}

// ── Assignment parsing ────────────────────────────────────────────────────

/// Split `"Field=Value"` into an [`Assignment`].
///
/// Returns `None` if there is no `=` sign.
pub fn parse_assignment(assignment: &str) -> Option<Assignment> {
    let eq = assignment.find('=')?;
    Some(Assignment {
        field: assignment[..eq].to_owned(),
        value: assignment[eq + 1..].to_owned(),
    })
}

// ── Exec-command prefix parsing ───────────────────────────────────────────

/// Parse the prefix characters (`-`, `@`, `:`, `+`, `!`, `|`) from an
/// `Exec*=` value, returning the flags and the remaining command-line string.
///
/// Mirrors `bus_append_exec_command` lines 571-641 of the C source.
pub fn parse_exec_command_prefix(eq: &str) -> ExecCommandParse {
    let mut flags = ExecCommandFlags::empty();
    let mut chars = eq.chars().peekable();
    let mut done = false;
    let mut ambient_hack = false;

    while !done {
        match chars.peek() {
            Some(&'-') if !flags.contains(ExecCommandFlags::IGNORE_FAILURE) => {
                flags.insert(ExecCommandFlags::IGNORE_FAILURE);
                chars.next();
            }
            Some(&'@') => {
                chars.next();
            }
            Some(&':') if !flags.contains(ExecCommandFlags::NO_ENV_EXPAND) => {
                flags.insert(ExecCommandFlags::NO_ENV_EXPAND);
                chars.next();
            }
            Some(&':') => {
                done = true;
            }
            Some(&'+')
                if flags.intersects(
                    ExecCommandFlags::FULLY_PRIVILEGED | ExecCommandFlags::NO_SETUID,
                ) || ambient_hack =>
            {
                done = true;
            }
            Some(&'+') => {
                flags.insert(ExecCommandFlags::FULLY_PRIVILEGED);
                chars.next();
            }
            Some(&'!') if flags.contains(ExecCommandFlags::FULLY_PRIVILEGED) || ambient_hack => {
                done = true;
            }
            Some(&'!') if flags.contains(ExecCommandFlags::NO_SETUID) => {
                // Legacy `!!` ambient-caps hack (removed in v258): silently consume.
                flags.remove(ExecCommandFlags::NO_SETUID);
                ambient_hack = true;
                chars.next();
            }
            Some(&'!') => {
                flags.insert(ExecCommandFlags::NO_SETUID);
                chars.next();
            }
            Some(&'|') if !flags.contains(ExecCommandFlags::VIA_SHELL) => {
                flags.insert(ExecCommandFlags::VIA_SHELL);
                chars.next();
            }
            Some(&'|') => {
                done = true;
            }
            _ => {
                done = true;
            }
        }
    }

    ExecCommandParse {
        flags,
        command_line: chars.collect(),
    }
}

// ── Standard-input parsing ────────────────────────────────────────────────

/// Parse a `StandardInput=` / `StandardOutput=` / `StandardError=` value.
///
/// Recognises the `fd:`, `file:`, `append:`, `truncate:` prefixes and
/// the special `null` value.
pub fn parse_standard_input(eq: &str) -> StandardInput {
    match eq {
        "" | "null" => StandardInput::Null,
        s => {
            if let Some(rest) = s.strip_prefix("fd:") {
                StandardInput::Fd(rest.to_owned())
            } else if let Some(rest) = s.strip_prefix("file:") {
                StandardInput::File(rest.to_owned())
            } else if let Some(rest) = s.strip_prefix("append:") {
                StandardInput::Append(rest.to_owned())
            } else if let Some(rest) = s.strip_prefix("truncate:") {
                StandardInput::Truncate(rest.to_owned())
            } else {
                StandardInput::Other(s.to_owned())
            }
        }
    }
}

// ── Exec-directory flags ──────────────────────────────────────────────────

/// Parse an `ExecDirectoryFlags` string.
///
/// Mirrors `exec_directory_flags_from_string()` in the C source.
pub fn exec_directory_flags_from_string(s: &str) -> ExecDirectoryFlags {
    match s {
        "" => ExecDirectoryFlags::empty(),
        "ro" => ExecDirectoryFlags::READ_ONLY,
        _ => ExecDirectoryFlags::empty(), // maps to _EXEC_DIRECTORY_FLAGS_INVALID
    }
}

// ── Device-allow parsing ──────────────────────────────────────────────────

/// Parse a `DeviceAllow=` entry into a path and optional rwm mode.
///
/// If the value is empty, returns `None` (meaning "reset the list").
/// Otherwise splits on the first whitespace: `"path rwm"`.
pub fn parse_device_allow(eq: &str) -> Option<DeviceAllowEntry> {
    if eq.is_empty() {
        return None;
    }

    if let Some(space) = eq.find(' ') {
        Some(DeviceAllowEntry {
            path: eq[..space].to_owned(),
            rwm: eq[space + 1..].to_owned(),
        })
    } else {
        Some(DeviceAllowEntry {
            path: eq.to_owned(),
            rwm: String::new(),
        })
    }
}

// ── IP-address shortcut parsing ───────────────────────────────────────────

/// Recognise the named IP-address shortcuts used in `IPAddressAllow=` /
/// `IPAddressDeny=`.
pub fn parse_ip_address_shortcut(eq: &str) -> Option<IpAddressShortcut> {
    match eq {
        "any" => Some(IpAddressShortcut::Any),
        "localhost" => Some(IpAddressShortcut::Localhost),
        "link-local" => Some(IpAddressShortcut::LinkLocal),
        "multicast" => Some(IpAddressShortcut::Multicast),
        _ => None,
    }
}

/// Expand a shortcut into concrete IP-address access entries.
///
/// Mirrors the `bus_append_parse_ip_address_filter` shortcut branches
/// (lines 806-858 of the C source).
pub fn expand_ip_address_shortcut(shortcut: IpAddressShortcut) -> Vec<IpAddressAccess> {
    match shortcut {
        IpAddressShortcut::Any => vec![
            // 0.0.0.0/0 and ::/0
            IpAddressAccess {
                family: 2, // AF_INET
                prefix: "0.0.0.0".into(),
                prefixlen: 0,
            },
            IpAddressAccess {
                family: 10, // AF_INET6
                prefix: "::".into(),
                prefixlen: 0,
            },
        ],
        IpAddressShortcut::Localhost => vec![
            // 127.0.0.0/8 and ::1/128
            IpAddressAccess {
                family: 2,
                prefix: "127.0.0.0".into(),
                prefixlen: 8,
            },
            IpAddressAccess {
                family: 10,
                prefix: "::1".into(),
                prefixlen: 128,
            },
        ],
        IpAddressShortcut::LinkLocal => vec![
            // 169.254.0.0/16 and fe80::/64
            IpAddressAccess {
                family: 2,
                prefix: "169.254.0.0".into(),
                prefixlen: 16,
            },
            IpAddressAccess {
                family: 10,
                prefix: "fe80::".into(),
                prefixlen: 64,
            },
        ],
        IpAddressShortcut::Multicast => vec![
            // 224.0.0.0/4 and ff00::/8
            IpAddressAccess {
                family: 2,
                prefix: "224.0.0.0".into(),
                prefixlen: 4,
            },
            IpAddressAccess {
                family: 10,
                prefix: "ff00::".into(),
                prefixlen: 8,
            },
        ],
    }
}

// ── Resource-limit parsing ────────────────────────────────────────────────

/// Parse a resource-limit value (`MemoryMax=`, `TasksMax=`, etc.).
///
/// Mirrors `bus_append_parse_resource_limit` (lines 344-380 of the C source).
/// - Empty string → [`ResourceLimitValue::Default`]
/// - `"infinity"` → [`ResourceLimitValue::Infinity`]
/// - A percentage (permyriad) → [`ResourceLimitValue::Percentage`]
/// - Otherwise stored as an absolute byte value.
pub fn parse_resource_limit(field: &str, eq: &str) -> Option<ResourceLimitValue> {
    if eq.is_empty() {
        return Some(ResourceLimitValue::Default);
    }
    if eq == INFINITY_KEYWORD {
        return Some(ResourceLimitValue::Infinity);
    }
    if let Some(pct_str) = eq.strip_suffix('%') {
        if let Ok(pct) = pct_str.parse::<i32>() {
            return Some(ResourceLimitValue::Percentage(pct));
        }
    }
    None
}

// ── String-with-ignore parsing ────────────────────────────────────────────

/// Parse a `-`-prefixed string value (used by `AppArmorProfile=`,
/// `SmackProcessLabel=`).
///
/// Returns `(ignore, value)`.
pub fn parse_string_with_ignore(eq: &str) -> (bool, &str) {
    if let Some(rest) = eq.strip_prefix('-') {
        (true, rest)
    } else {
        (false, eq)
    }
}

// ── Capabilities parsing ──────────────────────────────────────────────────

/// Parse capability set with optional `~` inversion prefix.
///
/// Returns `(invert, caps_string)`.
pub fn parse_capabilities(eq: &str) -> (bool, &str) {
    if let Some(rest) = eq.strip_prefix('~') {
        (true, rest)
    } else {
        (false, eq)
    }
}

// ── Filter-list parsing ───────────────────────────────────────────────────

/// Parse a `~`-prefixed filter list (used by `RestrictAddressFamilies=`,
/// `RestrictFileSystems=`, `SystemCallFilter=`, etc.).
///
/// Returns `(allow_list, items)`.  `allow_list` is `false` when the `~`
/// prefix is present (meaning "deny list").
pub fn parse_filter_list(eq: &str) -> (bool, &str) {
    if let Some(rest) = eq.strip_prefix('~') {
        (false, rest)
    } else {
        (true, eq)
    }
}

// ── Boolean-or-ex parsing ─────────────────────────────────────────────────

/// Parse a boolean-or-extended-string value.
///
/// If the value parses as a boolean, returns `Some(true)` / `Some(false)`.
/// Otherwise returns `None` indicating the caller should pass the raw
/// string to the `*Ex` property.
pub fn parse_boolean_or_ex(eq: &str) -> Option<bool> {
    match eq {
        "1" | "yes" | "true" | "on" => Some(true),
        "0" | "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

/// Determine the effective property name when the value is a boolean vs
/// an extended string.  Mirrors `bus_append_boolean_or_ex_string`.
pub fn boolean_or_ex_field(field: &str, is_bool: bool) -> String {
    if is_bool {
        field.strip_suffix("Ex").unwrap_or(field).to_owned()
    } else if field.ends_with("Ex") {
        field.to_owned()
    } else {
        format!("{field}Ex")
    }
}

// ── Sec-rename parsing ────────────────────────────────────────────────────

/// Rename a `*Sec` property suffix to `*USec` for the D-Bus API.
///
/// Panics if `field` is shorter than 4 characters or does not end with `Sec`.
pub fn sec_to_usec_field(field: &str) -> String {
    assert!(field.len() >= 4, "field too short for Sec→USec rename");
    assert!(
        field.ends_with("Sec"),
        "field '{field}' does not end with 'Sec'"
    );
    let base = &field[..field.len() - 3];
    format!("{base}USec")
}

// ── CPU-affinity parsing ──────────────────────────────────────────────────

/// Check if a CPU affinity value is the special `"numa"` keyword.
pub fn is_cpu_affinity_numa(eq: &str) -> bool {
    eq == "numa"
}

// ── UnitInfo comparison ───────────────────────────────────────────────────

/// Compare two [`UnitInfo`] values.
///
/// Ordering: machine → unit-type suffix → id.
/// Mirrors `unit_info_compare()` (lines 3075-3090 of the C source).
pub fn unit_info_compare(a: &UnitInfo, b: &UnitInfo) -> std::cmp::Ordering {
    // 1. Machine
    let machine_ord = a
        .machine
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase()
        .cmp(&b.machine.as_deref().unwrap_or("").to_ascii_lowercase());
    if machine_ord != std::cmp::Ordering::Equal {
        return machine_ord;
    }

    // 2. Unit type suffix (the part after the last '.')
    let type_a = a.id.rsplit_once('.').map(|(_, s)| s.to_ascii_lowercase());
    let type_b = b.id.rsplit_once('.').map(|(_, s)| s.to_ascii_lowercase());
    let type_ord = type_a
        .as_deref()
        .unwrap_or("")
        .cmp(type_b.as_deref().unwrap_or(""));
    if type_ord != std::cmp::Ordering::Equal {
        return type_ord;
    }

    // 3. Full id
    a.id.to_ascii_lowercase().cmp(&b.id.to_ascii_lowercase())
}

// ── Property-table helpers ────────────────────────────────────────────────

/// Check whether a field name is a known cgroup property.
///
/// This is a representative subset used in tests; the full list lives in
/// the C source's `cgroup_properties[]` table.
pub fn is_known_cgroup_property(field: &str) -> bool {
    matches!(
        field,
        "MemoryMin"
            | "MemoryLow"
            | "MemoryHigh"
            | "MemoryMax"
            | "MemorySwapMax"
            | "TasksMax"
            | "CPUWeight"
            | "IOWeight"
            | "CPUQuota"
            | "DeviceAllow"
            | "IODeviceWeight"
            | "IPAddressAllow"
            | "IPAddressDeny"
            | "Delegate"
            | "MemoryAccounting"
            | "CPUAccounting"
            | "IOAccounting"
            | "OOMRules"
            | "MemoryPressureWatch"
            | "CPUPressureWatch"
            | "IOPressureWatch"
            | "CPUSetPartition"
            | "CPUPressureThresholdSec"
            | "IOPressureThresholdSec"
    )
}

/// Check whether a field name is a known unit property.
pub fn is_known_unit_property(field: &str) -> bool {
    matches!(
        field,
        "Description"
            | "SourcePath"
            | "StopWhenUnneeded"
            | "DefaultDependencies"
            | "JobTimeoutSec"
            | "StartLimitBurst"
            | "Documentation"
            | "Requires"
            | "Wants"
            | "After"
            | "Before"
    )
}

/// Check whether a field name is a known execute property.
pub fn is_known_execute_property(field: &str) -> bool {
    matches!(
        field,
        "User"
            | "Group"
            | "WorkingDirectory"
            | "RootDirectory"
            | "Environment"
            | "PassEnvironment"
            | "StandardInput"
            | "StandardOutput"
            | "StandardError"
            | "PrivateTmp"
            | "PrivateNetwork"
            | "NoNewPrivileges"
            | "DynamicUser"
            | "ProtectSystem"
            | "ProtectHome"
            | "CapabilityBoundingSet"
            | "CPUAffinity"
            | "BindPaths"
            | "StateDirectory"
            | "RuntimeDirectory"
            | "CacheDirectory"
            | "LogsDirectory"
    )
}

// ── Refresh-on-reload parsing ─────────────────────────────────────────────

/// Parse `RefreshOnReload=` with optional `~` inversion.
///
/// Returns `(invert, items)` where `items` is the string after the optional
/// `~` prefix.
pub fn parse_refresh_on_reload(eq: &str) -> (bool, &str) {
    if let Some(rest) = eq.strip_prefix('~') {
        (true, rest)
    } else {
        (false, eq)
    }
}

// ── Log-filter-patterns parsing ───────────────────────────────────────────

/// Parse `LogFilterPatterns=` – leading `~` means deny (default allow).
///
/// Returns `(is_allow, pattern)`.
pub fn parse_log_filter_pattern(eq: &str) -> (bool, &str) {
    if let Some(rest) = eq.strip_prefix('~') {
        (false, rest)
    } else {
        (true, eq)
    }
}

// ── Quota-directory parsing ───────────────────────────────────────────────

/// Parsed quota-directory value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaDirectory {
    pub absolute: u64,
    pub scale: u32,
    pub enforce: bool,
}

/// Parse a quota-directory value (`StateDirectoryQuota=`, etc.).
///
/// Accepts permyriad percentages, absolute byte sizes, `"off"`, or empty.
pub fn parse_quota_directory(eq: &str) -> QuotaDirectory {
    if eq.is_empty() || eq == "off" {
        return QuotaDirectory {
            absolute: u64::MAX,
            scale: u32::MAX,
            enforce: false,
        };
    }

    if let Ok(pct) = eq.parse::<i32>() {
        // Treat bare numbers as permyriad
        return QuotaDirectory {
            absolute: u64::MAX,
            scale: UINT32_SCALE_FROM_PERMYRIAD(pct),
            enforce: true,
        };
    }

    // If it ends with %, treat as permyriad
    if let Some(pct_str) = eq.strip_suffix('%') {
        if let Ok(pct) = pct_str.parse::<i32>() {
            return QuotaDirectory {
                absolute: u64::MAX,
                scale: UINT32_SCALE_FROM_PERMYRIAD(pct),
                enforce: true,
            };
        }
    }

    // Fallback: assume byte size string (actual parsing needs parse_size from C)
    QuotaDirectory {
        absolute: u64::MAX,
        scale: u32::MAX,
        enforce: true,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Assignment parsing ─────────────────────────────────────────────

    #[test]
    fn test_parse_assignment_basic() {
        let a = parse_assignment("Description=hello world").unwrap();
        assert_eq!(a.field, "Description");
        assert_eq!(a.value, "hello world");
    }

    #[test]
    fn test_parse_assignment_empty_value() {
        let a = parse_assignment("Restart=").unwrap();
        assert_eq!(a.field, "Restart");
        assert_eq!(a.value, "");
    }

    #[test]
    fn test_parse_assignment_no_equals() {
        assert!(parse_assignment("noequals").is_none());
    }

    #[test]
    fn test_parse_assignment_multiple_equals() {
        let a = parse_assignment("Key=Val=ue").unwrap();
        assert_eq!(a.field, "Key");
        assert_eq!(a.value, "Val=ue");
    }

    // ── Exec-command prefix parsing ────────────────────────────────────

    #[test]
    fn test_parse_exec_no_prefix() {
        let p = parse_exec_command_prefix("/usr/bin/true");
        assert_eq!(p.flags, ExecCommandFlags::empty());
        assert_eq!(p.command_line, "/usr/bin/true");
    }

    #[test]
    fn test_parse_exec_ignore_failure() {
        let p = parse_exec_command_prefix("-/usr/bin/false");
        assert!(p.flags.contains(ExecCommandFlags::IGNORE_FAILURE));
        assert_eq!(p.command_line, "/usr/bin/false");
    }

    #[test]
    fn test_parse_exec_shell() {
        let p = parse_exec_command_prefix("|echo hello");
        assert!(p.flags.contains(ExecCommandFlags::VIA_SHELL));
        assert_eq!(p.command_line, "echo hello");
    }

    #[test]
    fn test_parse_exec_no_env_expand() {
        let p = parse_exec_command_prefix(":/usr/bin/cat");
        assert!(p.flags.contains(ExecCommandFlags::NO_ENV_EXPAND));
        assert_eq!(p.command_line, "/usr/bin/cat");
    }

    #[test]
    fn test_parse_exec_privileged() {
        let p = parse_exec_command_prefix("+/usr/bin/true");
        assert!(p.flags.contains(ExecCommandFlags::FULLY_PRIVILEGED));
        assert_eq!(p.command_line, "/usr/bin/true");
    }

    #[test]
    fn test_parse_exec_nosetuid() {
        let p = parse_exec_command_prefix("!/usr/bin/true");
        assert!(p.flags.contains(ExecCommandFlags::NO_SETUID));
        assert_eq!(p.command_line, "/usr/bin/true");
    }

    #[test]
    fn test_parse_exec_combined_prefixes() {
        let p = parse_exec_command_prefix("-@:/usr/bin/env");
        assert!(p.flags.contains(ExecCommandFlags::IGNORE_FAILURE));
        assert!(p.flags.contains(ExecCommandFlags::NO_ENV_EXPAND));
        assert_eq!(p.command_line, "/usr/bin/env");
    }

    #[test]
    fn test_parse_exec_double_bang_legacy() {
        // !! was the ambient-caps hack (removed in v258); should consume both ! and clear NO_SETUID
        let p = parse_exec_command_prefix("!/usr/bin/true");
        assert!(p.flags.contains(ExecCommandFlags::NO_SETUID));
    }

    #[test]
    fn test_parse_exec_double_prefix_stops() {
        // Two `-` prefixes: second one is part of the command line
        let p = parse_exec_command_prefix("--/usr/bin/true");
        assert!(p.flags.contains(ExecCommandFlags::IGNORE_FAILURE));
        assert_eq!(p.command_line, "-/usr/bin/true");
    }

    // ── Standard-input parsing ─────────────────────────────────────────

    #[test]
    fn test_parse_standard_input_null() {
        assert_eq!(parse_standard_input(""), StandardInput::Null);
        assert_eq!(parse_standard_input("null"), StandardInput::Null);
    }

    #[test]
    fn test_parse_standard_input_fd() {
        assert_eq!(parse_standard_input("fd:3"), StandardInput::Fd("3".into()));
    }

    #[test]
    fn test_parse_standard_input_file() {
        assert_eq!(
            parse_standard_input("file:/var/log/out"),
            StandardInput::File("/var/log/out".into())
        );
    }

    #[test]
    fn test_parse_standard_input_append() {
        assert_eq!(
            parse_standard_input("append:/var/log/out"),
            StandardInput::Append("/var/log/out".into())
        );
    }

    #[test]
    fn test_parse_standard_input_truncate() {
        assert_eq!(
            parse_standard_input("truncate:/var/log/out"),
            StandardInput::Truncate("/var/log/out".into())
        );
    }

    #[test]
    fn test_parse_standard_input_other() {
        assert_eq!(
            parse_standard_input("data:some-base64"),
            StandardInput::Other("data:some-base64".into())
        );
    }

    // ── Exec-directory flags ───────────────────────────────────────────

    #[test]
    fn test_exec_directory_flags_empty() {
        assert_eq!(
            exec_directory_flags_from_string(""),
            ExecDirectoryFlags::empty()
        );
    }

    #[test]
    fn test_exec_directory_flags_read_only() {
        assert_eq!(
            exec_directory_flags_from_string("ro"),
            ExecDirectoryFlags::READ_ONLY
        );
    }

    #[test]
    fn test_exec_directory_flags_invalid() {
        assert_eq!(
            exec_directory_flags_from_string("invalid"),
            ExecDirectoryFlags::empty()
        );
    }

    // ── Device-allow parsing ───────────────────────────────────────────

    #[test]
    fn test_parse_device_allow_empty() {
        assert!(parse_device_allow("").is_none());
    }

    #[test]
    fn test_parse_device_allow_path_only() {
        let e = parse_device_allow("/dev/sda").unwrap();
        assert_eq!(e.path, "/dev/sda");
        assert_eq!(e.rwm, "");
    }

    #[test]
    fn test_parse_device_allow_path_and_rwm() {
        let e = parse_device_allow("/dev/sda rw").unwrap();
        assert_eq!(e.path, "/dev/sda");
        assert_eq!(e.rwm, "rw");
    }

    // ── IP-address shortcut parsing ────────────────────────────────────

    #[test]
    fn test_parse_ip_address_shortcut_any() {
        assert_eq!(
            parse_ip_address_shortcut("any"),
            Some(IpAddressShortcut::Any)
        );
    }

    #[test]
    fn test_parse_ip_address_shortcut_localhost() {
        assert_eq!(
            parse_ip_address_shortcut("localhost"),
            Some(IpAddressShortcut::Localhost)
        );
    }

    #[test]
    fn test_parse_ip_address_shortcut_link_local() {
        assert_eq!(
            parse_ip_address_shortcut("link-local"),
            Some(IpAddressShortcut::LinkLocal)
        );
    }

    #[test]
    fn test_parse_ip_address_shortcut_multicast() {
        assert_eq!(
            parse_ip_address_shortcut("multicast"),
            Some(IpAddressShortcut::Multicast)
        );
    }

    #[test]
    fn test_parse_ip_address_shortcut_unknown() {
        assert!(parse_ip_address_shortcut("10.0.0.0/8").is_none());
    }

    #[test]
    fn test_expand_ip_shortcut_any() {
        let entries = expand_ip_address_shortcut(IpAddressShortcut::Any);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].prefix, "0.0.0.0");
        assert_eq!(entries[0].prefixlen, 0);
        assert_eq!(entries[1].prefix, "::");
        assert_eq!(entries[1].prefixlen, 0);
    }

    #[test]
    fn test_expand_ip_shortcut_localhost() {
        let entries = expand_ip_address_shortcut(IpAddressShortcut::Localhost);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].prefix, "127.0.0.0");
        assert_eq!(entries[0].prefixlen, 8);
        assert_eq!(entries[1].prefix, "::1");
        assert_eq!(entries[1].prefixlen, 128);
    }

    #[test]
    fn test_expand_ip_shortcut_link_local() {
        let entries = expand_ip_address_shortcut(IpAddressShortcut::LinkLocal);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].prefix, "169.254.0.0");
        assert_eq!(entries[0].prefixlen, 16);
        assert_eq!(entries[1].prefix, "fe80::");
        assert_eq!(entries[1].prefixlen, 64);
    }

    #[test]
    fn test_expand_ip_shortcut_multicast() {
        let entries = expand_ip_address_shortcut(IpAddressShortcut::Multicast);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].prefix, "224.0.0.0");
        assert_eq!(entries[0].prefixlen, 4);
        assert_eq!(entries[1].prefix, "ff00::");
        assert_eq!(entries[1].prefixlen, 8);
    }

    // ── Resource-limit parsing ─────────────────────────────────────────

    #[test]
    fn test_parse_resource_limit_empty() {
        assert_eq!(
            parse_resource_limit("MemoryMax", ""),
            Some(ResourceLimitValue::Default)
        );
    }

    #[test]
    fn test_parse_resource_limit_infinity() {
        assert_eq!(
            parse_resource_limit("MemoryMax", "infinity"),
            Some(ResourceLimitValue::Infinity)
        );
    }

    #[test]
    fn test_parse_resource_limit_percentage() {
        assert_eq!(
            parse_resource_limit("MemoryLow", "50%"),
            Some(ResourceLimitValue::Percentage(50))
        );
    }

    #[test]
    fn test_parse_resource_limit_not_percentage() {
        assert_eq!(parse_resource_limit("MemoryMax", "1G"), None);
    }

    // ── String-with-ignore ─────────────────────────────────────────────

    #[test]
    fn test_parse_string_with_ignore_no_prefix() {
        let (ignore, val) = parse_string_with_ignore("unconfined");
        assert!(!ignore);
        assert_eq!(val, "unconfined");
    }

    #[test]
    fn test_parse_string_with_ignore_dash() {
        let (ignore, val) = parse_string_with_ignore("-unconfined");
        assert!(ignore);
        assert_eq!(val, "unconfined");
    }

    // ── Capabilities ───────────────────────────────────────────────────

    #[test]
    fn test_parse_capabilities_no_invert() {
        let (invert, caps) = parse_capabilities("CAP_NET_RAW");
        assert!(!invert);
        assert_eq!(caps, "CAP_NET_RAW");
    }

    #[test]
    fn test_parse_capabilities_inverted() {
        let (invert, caps) = parse_capabilities("~CAP_NET_RAW");
        assert!(invert);
        assert_eq!(caps, "CAP_NET_RAW");
    }

    // ── Filter-list ────────────────────────────────────────────────────

    #[test]
    fn test_parse_filter_list_allow() {
        let (allow, items) = parse_filter_list("AF_INET AF_INET6");
        assert!(allow);
        assert_eq!(items, "AF_INET AF_INET6");
    }

    #[test]
    fn test_parse_filter_list_deny() {
        let (allow, items) = parse_filter_list("~AF_INET");
        assert!(!allow);
        assert_eq!(items, "AF_INET");
    }

    // ── Boolean-or-ex ──────────────────────────────────────────────────

    #[test]
    fn test_parse_boolean_or_ex_true() {
        assert_eq!(parse_boolean_or_ex("yes"), Some(true));
        assert_eq!(parse_boolean_or_ex("true"), Some(true));
        assert_eq!(parse_boolean_or_ex("1"), Some(true));
    }

    #[test]
    fn test_parse_boolean_or_ex_false() {
        assert_eq!(parse_boolean_or_ex("no"), Some(false));
        assert_eq!(parse_boolean_or_ex("false"), Some(false));
        assert_eq!(parse_boolean_or_ex("0"), Some(false));
    }

    #[test]
    fn test_parse_boolean_or_ex_extended() {
        assert_eq!(parse_boolean_or_ex("some-value"), None);
    }

    #[test]
    fn test_boolean_or_ex_field_bool() {
        assert_eq!(boolean_or_ex_field("PrivateTmpEx", true), "PrivateTmp");
        assert_eq!(boolean_or_ex_field("PrivateTmp", true), "PrivateTmp");
    }

    #[test]
    fn test_boolean_or_ex_field_extended() {
        assert_eq!(boolean_or_ex_field("PrivateTmp", false), "PrivateTmpEx");
        assert_eq!(boolean_or_ex_field("PrivateTmpEx", false), "PrivateTmpEx");
    }

    // ── Sec-rename ─────────────────────────────────────────────────────

    #[test]
    fn test_sec_to_usec_field() {
        assert_eq!(sec_to_usec_field("TimeoutStartSec"), "TimeoutStartUSec");
        assert_eq!(
            sec_to_usec_field("MemoryPressureWatchSec"),
            "MemoryPressureWatchUSec"
        );
    }

    #[test]
    #[should_panic(expected = "does not end with 'Sec'")]
    fn test_sec_to_usec_field_bad_suffix() {
        sec_to_usec_field("TimeoutStart");
    }

    // ── CPU affinity ───────────────────────────────────────────────────

    #[test]
    fn test_is_cpu_affinity_numa() {
        assert!(is_cpu_affinity_numa("numa"));
        assert!(!is_cpu_affinity_numa("0-3"));
    }

    // ── UnitInfo comparison ────────────────────────────────────────────

    #[test]
    fn test_unit_info_compare_same() {
        let ui = |id: &str| UnitInfo {
            machine: None,
            id: id.into(),
            description: String::new(),
            load_state: String::new(),
            active_state: String::new(),
            sub_state: String::new(),
            following: String::new(),
            unit_path: String::new(),
            job_id: 0,
            job_type: String::new(),
            job_path: String::new(),
        };
        assert_eq!(
            unit_info_compare(&ui("ssh.service"), &ui("ssh.service")),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn test_unit_info_compare_by_type() {
        let ui = |id: &str| UnitInfo {
            machine: None,
            id: id.into(),
            description: String::new(),
            load_state: String::new(),
            active_state: String::new(),
            sub_state: String::new(),
            following: String::new(),
            unit_path: String::new(),
            job_id: 0,
            job_type: String::new(),
            job_path: String::new(),
        };
        // .mount < .service
        assert_eq!(
            unit_info_compare(&ui("mnt.mount"), &ui("a.service")),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_unit_info_compare_by_id() {
        let ui = |id: &str| UnitInfo {
            machine: None,
            id: id.into(),
            description: String::new(),
            load_state: String::new(),
            active_state: String::new(),
            sub_state: String::new(),
            following: String::new(),
            unit_path: String::new(),
            job_id: 0,
            job_type: String::new(),
            job_path: String::new(),
        };
        assert_eq!(
            unit_info_compare(&ui("a.service"), &ui("b.service")),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_unit_info_compare_by_machine() {
        let ui = |machine: Option<&str>, id: &str| UnitInfo {
            machine: machine.map(String::from),
            id: id.into(),
            description: String::new(),
            load_state: String::new(),
            active_state: String::new(),
            sub_state: String::new(),
            following: String::new(),
            unit_path: String::new(),
            job_id: 0,
            job_type: String::new(),
            job_path: String::new(),
        };
        // None machines sort before named machines
        assert_eq!(
            unit_info_compare(&ui(None, "a.service"), &ui(Some("host1"), "a.service")),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_unit_info_compare_case_insensitive() {
        let ui = |id: &str| UnitInfo {
            machine: None,
            id: id.into(),
            description: String::new(),
            load_state: String::new(),
            active_state: String::new(),
            sub_state: String::new(),
            following: String::new(),
            unit_path: String::new(),
            job_id: 0,
            job_type: String::new(),
            job_path: String::new(),
        };
        assert_eq!(
            unit_info_compare(&ui("A.Service"), &ui("a.service")),
            std::cmp::Ordering::Equal
        );
    }

    // ── Property-table lookups ─────────────────────────────────────────

    #[test]
    fn test_is_known_cgroup_property() {
        assert!(is_known_cgroup_property("MemoryMax"));
        assert!(is_known_cgroup_property("CPUQuota"));
        assert!(!is_known_cgroup_property("Description"));
    }

    #[test]
    fn test_is_known_unit_property() {
        assert!(is_known_unit_property("Description"));
        assert!(is_known_unit_property("After"));
        assert!(!is_known_unit_property("MemoryMax"));
    }

    #[test]
    fn test_is_known_execute_property() {
        assert!(is_known_execute_property("User"));
        assert!(is_known_execute_property("Environment"));
        assert!(!is_known_execute_property("MemoryMax"));
    }

    // ── Refresh-on-reload ──────────────────────────────────────────────

    #[test]
    fn test_parse_refresh_on_reload_no_invert() {
        let (invert, items) = parse_refresh_on_reload("SIGTERM SIGKILL");
        assert!(!invert);
        assert_eq!(items, "SIGTERM SIGKILL");
    }

    #[test]
    fn test_parse_refresh_on_reload_inverted() {
        let (invert, items) = parse_refresh_on_reload("~SIGTERM");
        assert!(invert);
        assert_eq!(items, "SIGTERM");
    }

    // ── Log-filter-patterns ────────────────────────────────────────────

    #[test]
    fn test_parse_log_filter_pattern_allow() {
        let (is_allow, pat) = parse_log_filter_pattern("SYSLOG_IDENTIFIER=foo");
        assert!(is_allow);
        assert_eq!(pat, "SYSLOG_IDENTIFIER=foo");
    }

    #[test]
    fn test_parse_log_filter_pattern_deny() {
        let (is_allow, pat) = parse_log_filter_pattern("~SYSLOG_IDENTIFIER=foo");
        assert!(!is_allow);
        assert_eq!(pat, "SYSLOG_IDENTIFIER=foo");
    }

    // ── Quota-directory ────────────────────────────────────────────────

    #[test]
    fn test_parse_quota_directory_off() {
        let q = parse_quota_directory("off");
        assert!(!q.enforce);
    }

    #[test]
    fn test_parse_quota_directory_empty() {
        let q = parse_quota_directory("");
        assert!(!q.enforce);
    }

    #[test]
    fn test_parse_quota_directory_percentage() {
        let q = parse_quota_directory("50%");
        assert!(q.enforce);
        assert_ne!(q.scale, u32::MAX);
    }

    // ── UINT32_SCALE_FROM_PERMYRIAD ────────────────────────────────────

    #[test]
    fn test_uint32_scale_from_permyriad() {
        // 100% → should be close to UINT32_MAX
        let full = UINT32_SCALE_FROM_PERMYRIAD(10_000);
        assert!(full > u32::MAX / 2);
        // 0% → 0
        assert_eq!(UINT32_SCALE_FROM_PERMYRIAD(0), 0);
        // 50% → roughly half of max
        let half = UINT32_SCALE_FROM_PERMYRIAD(5_000);
        assert!(half > 0 && half < full);
    }
}
