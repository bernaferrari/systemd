// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/vpick/vpick-tool.c
//
// Versioned directory entry picker tool.
//
// Provides types and logic for selecting entries from versioned directories
// based on filters such as basename, version, architecture, suffix, and
// inode type. The picker supports multiple output formats (path, filename,
// version, type, architecture, tries, or all fields).

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum number of virtual consoles to scan.
pub const VC_MAX: u32 = 63;

/// Maximum console font dimensions.
pub const FONT_MAX_WIDTH: u32 = 32;
pub const FONT_MAX_HEIGHT: u32 = 32;
pub const FONT_MAX_CHARS: u32 = 512;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Output format selection for the pick tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintMode {
    /// Print the resolved absolute path
    Path,
    /// Print only the filename component
    Filename,
    /// Print the version string
    Version,
    /// Print the inode type (e.g. reg, dir, lnk)
    Type,
    /// Print the architecture identifier
    Architecture,
    /// Print tries left/tries done as +N-M
    Tries,
    /// Print all fields in a vertical table
    All,
}

impl PrintMode {
    /// Default print mode.
    pub const DEFAULT: Self = Self::Path;

    /// Convert to the string representation used in the print_table lookup.
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Filename => "filename",
            Self::Version => "version",
            Self::Type => "type",
            Self::Architecture => "architecture",
            Self::Tries => "tries",
            Self::All => "all",
        }
    }
}

impl std::str::FromStr for PrintMode {
    type Err = i32;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "path" => Ok(Self::Path),
            "filename" => Ok(Self::Filename),
            "version" => Ok(Self::Version),
            "type" => Ok(Self::Type),
            "architecture" | "arch" => Ok(Self::Architecture),
            "tries" => Ok(Self::Tries),
            "all" => Ok(Self::All),
            _ => Err(-libc::EINVAL),
        }
    }
}

/// C-shaped compatibility facade for `print_from_string()`.
pub fn print_mode_from_string(s: &str) -> Result<PrintMode, i32> {
    s.parse()
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    /// Bitflags controlling pick behavior.
    pub struct PickFlags: u64 {
        /// Automatically resolve architecture filter
        const ARCHITECTURE = 1 << 0;
        /// Respect tries left/tries done metadata
        const TRIES = 1 << 1;
        /// Canonicalize the result path
        const RESOLVE = 1 << 2;
    }
}

impl PickFlags {
    /// Default flags used by the tool.
    pub const DEFAULT: Self = Self::ARCHITECTURE.union(Self::TRIES);
}

// ── Filter configuration ──────────────────────────────────────────────────

/// Filter criteria for the version picker.
#[derive(Debug, Clone, Default)]
pub struct PickFilter {
    /// Optional basename to match
    pub basename: Option<String>,
    /// Optional version string to match
    pub version: Option<String>,
    /// Optional architecture to match (-1 = invalid/unset)
    pub architecture: i32,
    /// Optional suffix to match
    pub suffix: Option<String>,
    /// Bitmask of inode types to accept (DT_* bits)
    pub type_mask: u32,
}

/// Inode type constants matching Linux DT_* values.
pub mod inode_type {
    pub const DT_UNKNOWN: u8 = 0;
    pub const DT_FIFO: u8 = 1;
    pub const DT_CHR: u8 = 2;
    pub const DT_DIR: u8 = 4;
    pub const DT_BLK: u8 = 6;
    pub const DT_REG: u8 = 8;
    pub const DT_LNK: u8 = 10;
    pub const DT_SOCK: u8 = 12;
    pub const DT_WHT: u8 = 14;
}

// ── Result of a pick operation ────────────────────────────────────────────

/// The result of a successful versioned directory pick.
#[derive(Debug, Clone)]
pub struct PickResult {
    /// Resolved path to the selected entry
    pub path: String,
    /// Version string, if discovered
    pub version: Option<String>,
    /// Architecture identifier, if discovered (-1 = unknown)
    pub architecture: i32,
    /// Tries remaining
    pub tries_left: u32,
    /// Tries already consumed
    pub tries_done: u32,
    /// Whether the entry is a directory
    pub is_dir: bool,
}

/// Sentinel value indicating tries information is not available.
pub const TRIES_INVALID: u32 = u32::MAX;

impl Default for PickResult {
    fn default() -> Self {
        Self {
            path: String::new(),
            version: None,
            architecture: -1,
            tries_left: TRIES_INVALID,
            tries_done: TRIES_INVALID,
            is_dir: false,
        }
    }
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Check if a string is a valid filename component (no slashes, not empty,
/// no control characters).
pub fn filename_part_is_valid(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    !s.chars().any(|c| c == '/' || c == '\0' || c.is_control())
}

/// Check if a version string is valid (non-empty, no slashes or newlines).
pub fn version_is_valid(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    !s.chars().any(|c| c == '/' || c == '\n' || c == '\0')
}

/// Validate that a type mask string represents a known inode type.
/// Returns the DT_* value for the type, or an error.
pub fn inode_type_from_string(s: &str) -> Result<u32, i32> {
    match s {
        "reg" | "file" => Ok(1u32 << inode_type::DT_REG),
        "dir" | "directory" => Ok(1u32 << inode_type::DT_DIR),
        "lnk" | "symlink" => Ok(1u32 << inode_type::DT_LNK),
        "fifo" | "pipe" => Ok(1u32 << inode_type::DT_FIFO),
        "sock" | "socket" => Ok(1u32 << inode_type::DT_SOCK),
        "blk" | "block" => Ok(1u32 << inode_type::DT_BLK),
        "chr" | "char" | "character" => Ok(1u32 << inode_type::DT_CHR),
        _ => Err(-libc::EINVAL),
    }
}

// ── Architecture helpers ──────────────────────────────────────────────────

/// Special architecture identifiers matching systemd's architecture.h.
pub const ARCHITECTURE_INVALID: i32 = -1;

/// Resolve an architecture argument string.
/// Returns the architecture value or an error.
pub fn resolve_architecture_arg(arg: &str) -> Result<i32, i32> {
    match arg {
        "native" => Ok(native_architecture()),
        "secondary" => {
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            {
                Ok(secondary_architecture())
            }
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            {
                Err(-libc::EOPNOTSUPP)
            }
        }
        "uname" => Ok(uname_architecture()),
        "auto" => Ok(ARCHITECTURE_INVALID),
        s => architecture_from_string(s),
    }
}

/// Returns the native architecture constant.
pub fn native_architecture() -> i32 {
    #[cfg(target_arch = "x86_64")]
    {
        0
    }
    #[cfg(target_arch = "aarch64")]
    {
        1
    }
    #[cfg(target_arch = "arm")]
    {
        2
    }
    #[cfg(target_arch = "riscv64")]
    {
        3
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64"
    )))]
    {
        ARCHITECTURE_INVALID
    }
}

/// Returns the secondary architecture constant (for multiarch systems).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn secondary_architecture() -> i32 {
    #[cfg(target_arch = "x86_64")]
    {
        2 // x86 (32-bit)
    }
    #[cfg(target_arch = "aarch64")]
    {
        2 // arm (32-bit)
    }
}

/// Returns the architecture determined from uname.
pub fn uname_architecture() -> i32 {
    native_architecture()
}

/// Architecture name lookup table.
static ARCH_TABLE: &[(&str, i32); 23] = &[
    ("x86-64", 0),
    ("x86_64", 0),
    ("aarch64", 1),
    ("arm64", 1),
    ("arm", 2),
    ("armv7l", 2),
    ("armv6l", 2),
    ("armv5tel", 2),
    ("riscv64", 3),
    ("riscv", 3),
    ("i386", 4),
    ("i686", 4),
    ("ia64", 5),
    ("mips-le", 6),
    ("mips64-le", 7),
    ("mips", 8),
    ("mips64", 9),
    ("ppc", 10),
    ("ppc64", 11),
    ("ppc64-le", 12),
    ("ppc-le", 13),
    ("s390", 14),
    ("s390x", 15),
];

/// Parse an architecture from a string.
pub fn architecture_from_string(s: &str) -> Result<i32, i32> {
    for (name, arch) in ARCH_TABLE {
        if *name == s {
            return Ok(*arch);
        }
    }
    Err(-libc::EINVAL)
}

/// Convert an architecture value to its string name.
pub fn architecture_to_string(arch: i32) -> Option<&'static str> {
    for (name, a) in ARCH_TABLE {
        if *a == arch {
            return Some(*name);
        }
    }
    None
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parsed command-line arguments for the vpick tool.
#[derive(Debug, Clone)]
pub struct VpickArgs {
    /// Output format
    pub print: PrintMode,
    /// Pick behavior flags
    pub flags: PickFlags,
    /// Filter criteria
    pub filter: PickFilter,
    /// Paths to resolve
    pub paths: Vec<String>,
}

impl Default for VpickArgs {
    fn default() -> Self {
        Self {
            print: PrintMode::DEFAULT,
            flags: PickFlags::DEFAULT,
            filter: PickFilter::default(),
            paths: Vec::new(),
        }
    }
}

/// Parse the boolean-like resolve argument.
pub fn parse_resolve(s: &str) -> Result<bool, i32> {
    match s {
        "yes" | "true" | "1" | "on" => Ok(true),
        "no" | "false" | "0" | "off" => Ok(false),
        _ => Err(-libc::EINVAL),
    }
}

// ── Output formatting ─────────────────────────────────────────────────────

/// Format a pick result according to the specified print mode.
/// Returns the formatted output string.
pub fn format_result(result: &PickResult, mode: PrintMode) -> Result<String, i32> {
    match mode {
        PrintMode::Path => {
            let mut out = result.path.clone();
            if result.is_dir && !out.ends_with('/') {
                out.push('/');
            }
            Ok(out)
        }
        PrintMode::Filename => {
            let fname = result.path.rsplit('/').next().unwrap_or(&result.path);
            Ok(fname.to_string())
        }
        PrintMode::Version => result.version.as_ref().cloned().ok_or(-libc::EINVAL),
        PrintMode::Type => {
            if result.is_dir {
                Ok("directory".to_string())
            } else {
                Ok("regular".to_string())
            }
        }
        PrintMode::Architecture => architecture_to_string(result.architecture)
            .map(|s| s.to_string())
            .ok_or(-libc::EINVAL),
        PrintMode::Tries => {
            if result.tries_left == TRIES_INVALID {
                return Err(-libc::EINVAL);
            }
            Ok(format!("+{}-{}", result.tries_left, result.tries_done))
        }
        PrintMode::All => {
            let mut lines = Vec::new();
            lines.push(format!("Path:         {}", result.path));
            if let Some(ref v) = result.version {
                lines.push(format!("Version:      {}", v));
            }
            let type_str = if result.is_dir {
                "directory"
            } else {
                "regular"
            };
            lines.push(format!("Type:         {}", type_str));
            if let Some(arch_str) = architecture_to_string(result.architecture) {
                lines.push(format!("Architecture: {}", arch_str));
            }
            if result.tries_left != TRIES_INVALID {
                lines.push(format!("Tries left:   {}", result.tries_left));
                lines.push(format!("Tries done:   {}", result.tries_done));
            }
            Ok(lines.join("\n"))
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_mode_from_str() {
        assert_eq!(print_mode_from_string("path"), Ok(PrintMode::Path));
        assert_eq!(print_mode_from_string("filename"), Ok(PrintMode::Filename));
        assert_eq!(print_mode_from_string("version"), Ok(PrintMode::Version));
        assert_eq!(print_mode_from_string("type"), Ok(PrintMode::Type));
        assert_eq!(
            print_mode_from_string("architecture"),
            Ok(PrintMode::Architecture)
        );
        assert_eq!(print_mode_from_string("arch"), Ok(PrintMode::Architecture));
        assert_eq!(print_mode_from_string("tries"), Ok(PrintMode::Tries));
        assert_eq!(print_mode_from_string("all"), Ok(PrintMode::All));
        assert_eq!(print_mode_from_string("invalid"), Err(-libc::EINVAL));
        assert_eq!("path".parse(), Ok(PrintMode::Path));
        assert_eq!("invalid".parse::<PrintMode>(), Err(-libc::EINVAL));
    }

    #[test]
    fn test_print_mode_to_str() {
        assert_eq!(PrintMode::Path.to_str(), "path");
        assert_eq!(PrintMode::Filename.to_str(), "filename");
        assert_eq!(PrintMode::Version.to_str(), "version");
        assert_eq!(PrintMode::Architecture.to_str(), "architecture");
        assert_eq!(PrintMode::Tries.to_str(), "tries");
        assert_eq!(PrintMode::All.to_str(), "all");
    }

    #[test]
    fn test_pick_flags_default() {
        let flags = PickFlags::DEFAULT;
        assert!(flags.contains(PickFlags::ARCHITECTURE));
        assert!(flags.contains(PickFlags::TRIES));
        assert!(!flags.contains(PickFlags::RESOLVE));
    }

    #[test]
    fn test_filename_part_is_valid() {
        assert!(filename_part_is_valid("systemd"));
        assert!(filename_part_is_valid("libfoo.so"));
        assert!(!filename_part_is_valid(""));
        assert!(!filename_part_is_valid("has/slash"));
        assert!(!filename_part_is_valid("has\0null"));
        assert!(!filename_part_is_valid("has\nnewline"));
    }

    #[test]
    fn test_version_is_valid() {
        assert!(version_is_valid("1.0"));
        assert!(version_is_valid("255.3.1"));
        assert!(!version_is_valid(""));
        assert!(!version_is_valid("1.0/2"));
        assert!(!version_is_valid("1.0\n"));
    }

    #[test]
    fn test_inode_type_from_string() {
        assert_eq!(
            inode_type_from_string("reg"),
            Ok(1u32 << inode_type::DT_REG)
        );
        assert_eq!(
            inode_type_from_string("dir"),
            Ok(1u32 << inode_type::DT_DIR)
        );
        assert_eq!(
            inode_type_from_string("lnk"),
            Ok(1u32 << inode_type::DT_LNK)
        );
        assert_eq!(
            inode_type_from_string("sock"),
            Ok(1u32 << inode_type::DT_SOCK)
        );
        assert!(inode_type_from_string("unknown").is_err());
    }

    #[test]
    fn test_architecture_from_string() {
        assert_eq!(architecture_from_string("x86-64"), Ok(0));
        assert_eq!(architecture_from_string("x86_64"), Ok(0));
        assert_eq!(architecture_from_string("aarch64"), Ok(1));
        assert!(architecture_from_string("unknown-arch").is_err());
        assert!(architecture_from_string("native").is_err());
    }

    #[test]
    fn test_resolve_architecture_arg() {
        assert_eq!(resolve_architecture_arg("auto"), Ok(ARCHITECTURE_INVALID));
        assert_eq!(resolve_architecture_arg("uname"), Ok(uname_architecture()));
        assert!(resolve_architecture_arg("unknown").is_err());
    }

    #[test]
    fn test_format_result_path() {
        let result = PickResult {
            path: "/usr/lib/systemd".to_string(),
            is_dir: true,
            ..Default::default()
        };
        assert_eq!(
            format_result(&result, PrintMode::Path),
            Ok("/usr/lib/systemd/".to_string())
        );

        let result_file = PickResult {
            path: "/usr/lib/systemd/systemd".to_string(),
            is_dir: false,
            ..Default::default()
        };
        assert_eq!(
            format_result(&result_file, PrintMode::Path),
            Ok("/usr/lib/systemd/systemd".to_string())
        );
    }

    #[test]
    fn test_format_result_filename() {
        let result = PickResult {
            path: "/usr/lib/foo.txt".to_string(),
            ..Default::default()
        };
        assert_eq!(
            format_result(&result, PrintMode::Filename),
            Ok("foo.txt".to_string())
        );
    }

    #[test]
    fn test_format_result_version() {
        let result_ok = PickResult {
            version: Some("255.1".to_string()),
            ..Default::default()
        };
        assert_eq!(
            format_result(&result_ok, PrintMode::Version),
            Ok("255.1".to_string())
        );

        let result_none = PickResult {
            version: None,
            ..Default::default()
        };
        assert!(format_result(&result_none, PrintMode::Version).is_err());
    }

    #[test]
    fn test_format_result_tries() {
        let result_ok = PickResult {
            tries_left: 3,
            tries_done: 1,
            ..Default::default()
        };
        assert_eq!(
            format_result(&result_ok, PrintMode::Tries),
            Ok("+3-1".to_string())
        );

        let result_none = PickResult {
            tries_left: TRIES_INVALID,
            ..Default::default()
        };
        assert!(format_result(&result_none, PrintMode::Tries).is_err());
    }

    #[test]
    fn test_format_result_all() {
        let result = PickResult {
            path: "/usr/lib/foo".to_string(),
            version: Some("1.0".to_string()),
            architecture: 0,
            tries_left: 2,
            tries_done: 0,
            is_dir: false,
        };
        let output = format_result(&result, PrintMode::All).unwrap();
        assert!(output.contains("Path:"));
        assert!(output.contains("Version:"));
        assert!(output.contains("Type:"));
        assert!(output.contains("Architecture:"));
        assert!(output.contains("Tries left:"));
    }

    #[test]
    fn test_parse_resolve() {
        assert_eq!(parse_resolve("yes"), Ok(true));
        assert_eq!(parse_resolve("true"), Ok(true));
        assert_eq!(parse_resolve("1"), Ok(true));
        assert_eq!(parse_resolve("no"), Ok(false));
        assert_eq!(parse_resolve("false"), Ok(false));
        assert_eq!(parse_resolve("0"), Ok(false));
        assert!(parse_resolve("maybe").is_err());
    }

    #[test]
    fn test_vpick_args_default() {
        let args = VpickArgs::default();
        assert_eq!(args.print, PrintMode::Path);
        assert!(args.flags.contains(PickFlags::ARCHITECTURE));
        assert!(args.flags.contains(PickFlags::TRIES));
        assert!(args.filter.basename.is_none());
        assert!(args.paths.is_empty());
    }
}
