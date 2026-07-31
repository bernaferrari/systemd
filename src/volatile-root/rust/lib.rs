// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/volatile-root/volatile-root.c
//
// Volatile root filesystem setup tool.
//
// Implements the systemd-volatile-root tool which makes the root filesystem
// volatile by either mounting a tmpfs over it (VOLATILE_YES mode) or
// creating an overlayfs on top of it (VOLATILE_OVERLAY mode). This allows
// the system to boot with a transient root filesystem while preserving
// the original contents.

// ── Constants ─────────────────────────────────────────────────────────────

use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "linux")]
use std::path::Path;

/// Mode value for a persistent root.
pub const VOLATILE_NO: i32 = 0;
/// Mode value for fully volatile root (tmpfs mount).
pub const VOLATILE_YES: i32 = 1;
/// Mode value for a persistent /usr with volatile state directories.
///
/// `systemd-volatile-root` itself deliberately does not act on this mode;
/// fstab-generator owns the corresponding `/var` and `/home` setup.
pub const VOLATILE_STATE: i32 = 2;
/// Mode value for overlayfs volatile root.
pub const VOLATILE_OVERLAY: i32 = 3;
/// Sentinel for invalid/unset volatile mode.
pub const VOLATILE_MODE_INVALID: i32 = -1;

/// Default sysroot path.
pub const DEFAULT_SYSROOT: &str = "/sysroot";

/// Volatile sysroot staging directory.
pub const VOLATILE_SYSROOT_DIR: &str = "/run/systemd/volatile-sysroot";

/// Overlay sysroot staging directory.
pub const OVERLAY_SYSROOT_DIR: &str = "/run/systemd/overlay-sysroot";

/// Symlink recording the original backing device.
pub const VOLATILE_ROOT_LINK: &str = "/run/systemd/volatile-root";

/// Tmpfs mount options for volatile root.
pub const TMPFS_OPTIONS: &str = "mode=0755,size=25%,nr_inodes=1m";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Volatile mode determines how the root filesystem is made volatile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolatileMode {
    /// Persistent root — do nothing.
    No,
    /// Fully volatile — mount a tmpfs, bind-mount /usr read-only
    Yes,
    /// Only state directories are volatile. This tool does nothing.
    State,
    /// Overlay — mount an overlayfs on top of the existing root
    Overlay,
}

impl VolatileMode {
    /// Parse from a raw integer value as used in the C code.
    pub fn from_raw(v: i32) -> Result<Self, i32> {
        match v {
            VOLATILE_NO => Ok(Self::No),
            VOLATILE_YES => Ok(Self::Yes),
            VOLATILE_STATE => Ok(Self::State),
            VOLATILE_OVERLAY => Ok(Self::Overlay),
            VOLATILE_MODE_INVALID => Err(-libc::EINVAL),
            _ => Err(-libc::EINVAL),
        }
    }

    /// Convert to the raw integer value.
    pub fn to_raw(self) -> i32 {
        match self {
            Self::No => VOLATILE_NO,
            Self::Yes => VOLATILE_YES,
            Self::State => VOLATILE_STATE,
            Self::Overlay => VOLATILE_OVERLAY,
        }
    }

    /// Parse from a string argument.
    pub fn from_str_arg(s: &str) -> Result<Self, i32> {
        match s {
            "yes" | "true" | "on" | "1" => Ok(Self::Yes),
            "state" => Ok(Self::State),
            "overlay" => Ok(Self::Overlay),
            "no" | "false" | "off" | "0" => Ok(Self::No),
            _ => Err(-libc::EINVAL),
        }
    }
}

// ── Path validation ───────────────────────────────────────────────────────

/// Validate a path argument for volatile-root.
/// The path must be absolute, non-empty, and not the root directory.
pub fn validate_path(path: &str) -> Result<(), i32> {
    if path.is_empty() {
        return Err(-libc::EINVAL);
    }
    if !path.starts_with('/') {
        return Err(-libc::EINVAL);
    }
    if path_is_root(path) {
        return Err(-libc::EINVAL);
    }
    Ok(())
}

/// Match `path_equal(path, "/")` for the path spellings relevant here.
///
/// `path_equal()` ignores repeated separators and `.` components. Rejecting
/// only the literal string `/` would allow `//` or `/./` to bypass the guard
/// immediately before a root mount transition.
fn path_is_root(path: &str) -> bool {
    path.starts_with('/')
        && path
            .split('/')
            .all(|component| component.is_empty() || component == ".")
}

// ── Overlayfs options builder ─────────────────────────────────────────────

/// Build overlayfs mount options for the given lower directory path.
/// Escapes characters that are special to overlayfs (comma, colon).
pub fn build_overlay_options(lower_dir: &str, upper_dir: &str, work_dir: &str) -> String {
    let escaped_lower = shell_escape(lower_dir);
    format!(
        "lowerdir={},upperdir={},workdir={}",
        escaped_lower, upper_dir, work_dir
    )
}

/// Shell-escape characters that are special for overlayfs options (comma and colon).
pub fn shell_escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        if c == ',' || c == ':' {
            result.push('\\');
        }
        result.push(c);
    }
    result
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parsed arguments for the volatile-root tool.
#[derive(Debug, Clone)]
pub struct VolatileRootArgs {
    /// Volatile mode (from kernel cmdline or argument)
    pub mode: VolatileMode,
    /// Path to operate on (defaults to /sysroot)
    pub path: String,
}

impl Default for VolatileRootArgs {
    fn default() -> Self {
        Self {
            mode: VolatileMode::No,
            path: DEFAULT_SYSROOT.to_string(),
        }
    }
}

/// Parse command-line arguments for volatile-root.
/// The argc/argv convention matches the C tool:
///   argv[0] = program name
///   argv[1] = optional mode string
///   argv[2] = optional path
pub fn parse_args(args: &[&str]) -> Result<VolatileRootArgs, i32> {
    if args.len() > 3 {
        return Err(-libc::EINVAL);
    }

    let mut result = VolatileRootArgs::default();

    // Mode from argument
    if args.len() >= 2 {
        result.mode = VolatileMode::from_str_arg(args[1])?;
    }

    // Path from argument
    if args.len() >= 3 {
        validate_path(args[2])?;
        result.path = args[2].to_string();
    }

    Ok(result)
}

/// Parse the command-line spelling used by `proc_cmdline_get_key()` for the
/// `systemd.volatile` setting.
///
/// The C helper scans every matching word and therefore uses the final
/// `key=value` occurrence. A later bare key only marks the option present; it
/// does not discard an already collected value. Keeping that slightly unusual
/// rule matters for the optional-value API used by `query_volatile_mode()`.
pub fn mode_from_cmdline(cmdline: &str) -> Result<Option<VolatileMode>, i32> {
    let mut found = false;
    let mut value = None;

    for word in split_cmdline_words(cmdline) {
        let Some(suffix) = word.strip_prefix("systemd.volatile") else {
            continue;
        };

        if suffix.is_empty() {
            found = true;
        } else if let Some(raw_value) = suffix.strip_prefix('=') {
            found = true;
            value = Some(raw_value.to_owned());
        }
    }

    if !found {
        return Ok(None);
    }

    match value {
        Some(value) => VolatileMode::from_str_arg(&value).map(Some),
        None => Ok(Some(VolatileMode::Yes)),
    }
}

/// Resolve the effective mode with the same precedence as the C tool.
///
/// Kernel command line settings always win. The positional mode argument is
/// considered only when the setting is absent. Path validation intentionally
/// happens before the caller decides whether the resolved mode is active,
/// matching `run()` in `volatile-root.c`.
pub fn resolve_args_from_cmdline(args: &[&str], cmdline: &str) -> Result<VolatileRootArgs, i32> {
    if args.len() > 3 {
        return Err(-libc::EINVAL);
    }

    let path = if let Some(path) = args.get(2) {
        validate_path(path)?;
        (*path).to_owned()
    } else {
        DEFAULT_SYSROOT.to_owned()
    };

    let mode = match mode_from_cmdline(cmdline)? {
        Some(mode) => mode,
        None => match args.get(1) {
            Some(mode) => VolatileMode::from_str_arg(mode)?,
            None => VolatileMode::No,
        },
    };

    Ok(VolatileRootArgs { mode, path })
}

/// Return `true` exactly for the modes that perform a root mount transition.
pub const fn mode_requires_root_transition(mode: VolatileMode) -> bool {
    matches!(mode, VolatileMode::Yes | VolatileMode::Overlay)
}

// ── Read-only sysroot preflight ───────────────────────────────────────────

/// Result of the side-effect-free checks which precede C's backing-device
/// link and mount transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysrootState {
    /// The requested path already resides on a temporary filesystem. C treats
    /// this as success and performs no backing-device or mount operations.
    AlreadyTemporary,
    /// The path is a mount point backed by a non-temporary filesystem.
    ///
    /// The caller must not create `/run/systemd/volatile-root` until it can
    /// immediately continue with the complete C-compatible mount transition.
    NeedsTransition {
        /// Filesystem type reported for the mount in `/proc/self/mountinfo`.
        filesystem_type: String,
    },
}

/// Validate the active-mode sysroot without changing the filesystem.
///
/// This is the safe, read-only prefix of `run()` in `volatile-root.c`: the
/// target must be a mount point, and an existing tmpfs/ramfs root is an
/// immediate success. Linux mount IDs are read through retained file
/// descriptors, so bind mounts are recognized even when their device number
/// is identical to the parent filesystem.
#[cfg(target_os = "linux")]
pub fn inspect_sysroot(path: &str) -> io::Result<SysrootState> {
    validate_path(path).map_err(|errno| io::Error::from_raw_os_error(-errno))?;

    let canonical = std::fs::canonicalize(path)?;
    let parent = canonical
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "sysroot path has no parent"))?;

    let target = open_directory(&canonical)?;
    let parent = open_directory(parent)?;

    let target_mount_id = mount_id_for_fd(&target)?;
    let parent_mount_id = mount_id_for_fd(&parent)?;
    if target_mount_id == parent_mount_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sysroot path is not a mount point",
        ));
    }

    let filesystem_type = filesystem_type_for_mount_id(target_mount_id)?;
    if matches!(filesystem_type.as_str(), "tmpfs" | "ramfs" | "devtmpfs") {
        Ok(SysrootState::AlreadyTemporary)
    } else {
        Ok(SysrootState::NeedsTransition { filesystem_type })
    }
}

/// Volatile-root is Linux-specific; preserve a clear diagnostic if the crate
/// is inspected on another host.
#[cfg(not(target_os = "linux"))]
pub fn inspect_sysroot(_path: &str) -> io::Result<SysrootState> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "volatile-root sysroot inspection requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn open_directory(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(target_os = "linux")]
fn mount_id_for_fd(file: &std::fs::File) -> io::Result<u64> {
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    parse_mount_id(&fdinfo).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "fdinfo does not contain a mount ID",
        )
    })
}

#[cfg(target_os = "linux")]
fn filesystem_type_for_mount_id(mount_id: u64) -> io::Result<String> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    parse_filesystem_type(&mountinfo, mount_id)
        .map(str::to_owned)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "mount ID is absent from mountinfo"))
}

fn parse_mount_id(fdinfo: &str) -> Option<u64> {
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:\t")?.trim().parse().ok())
}

fn parse_filesystem_type(mountinfo: &str, wanted_mount_id: u64) -> Option<&str> {
    mountinfo.lines().find_map(|line| {
        let mut fields = line.split_ascii_whitespace();
        let mount_id = fields.next()?.parse::<u64>().ok()?;
        if mount_id != wanted_mount_id {
            return None;
        }

        // `find()` consumes the separator. The first field after it is the
        // filesystem type.
        fields.find(|field| *field == "-")?;
        fields.next()
    })
}

/// Split `/proc/cmdline` into words with the quoting semantics needed by the
/// `systemd.volatile` lookup. This is deliberately small, but supports both
/// quote styles and retained backslash escapes so quoted values remain one
/// argument without accidentally accepting an escaped mode spelling.
fn split_cmdline_words(cmdline: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;

    for character in cmdline.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }

        if character == '\\' {
            // `proc_cmdline_strv()` uses EXTRACT_RETAIN_ESCAPE. Preserve the
            // slash while still preventing an escaped quote from closing this
            // word.
            current.push(character);
            escaped = true;
            continue;
        }

        if let Some(active_quote) = quote {
            if character == active_quote {
                quote = None;
            } else {
                current.push(character);
            }
            continue;
        }

        if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character.is_ascii_whitespace() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }

    if !current.is_empty() {
        words.push(current);
    }
    words
}

// ── Device symlink path ───────────────────────────────────────────────────

/// Generate the device node symlink path for recording the original backing device.
pub fn device_link_content(major: u32, minor: u32) -> String {
    format!("/dev/block/{}:{}", major, minor)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volatile_mode_from_raw() {
        assert_eq!(VolatileMode::from_raw(VOLATILE_NO), Ok(VolatileMode::No));
        assert_eq!(VolatileMode::from_raw(VOLATILE_YES), Ok(VolatileMode::Yes));
        assert_eq!(
            VolatileMode::from_raw(VOLATILE_STATE),
            Ok(VolatileMode::State)
        );
        assert_eq!(
            VolatileMode::from_raw(VOLATILE_OVERLAY),
            Ok(VolatileMode::Overlay)
        );
        assert!(VolatileMode::from_raw(VOLATILE_MODE_INVALID).is_err());
        assert!(VolatileMode::from_raw(99).is_err());
    }

    #[test]
    fn test_volatile_mode_from_str_arg() {
        assert_eq!(VolatileMode::from_str_arg("yes"), Ok(VolatileMode::Yes));
        assert_eq!(VolatileMode::from_str_arg("state"), Ok(VolatileMode::State));
        assert_eq!(
            VolatileMode::from_str_arg("overlay"),
            Ok(VolatileMode::Overlay)
        );
        assert_eq!(VolatileMode::from_str_arg("no"), Ok(VolatileMode::No));
        assert_eq!(VolatileMode::from_str_arg("true"), Ok(VolatileMode::Yes));
        assert_eq!(VolatileMode::from_str_arg("off"), Ok(VolatileMode::No));
        assert!(VolatileMode::from_str_arg("invalid").is_err());
    }

    #[test]
    fn test_volatile_mode_to_raw() {
        assert_eq!(VolatileMode::Yes.to_raw(), VOLATILE_YES);
        assert_eq!(VolatileMode::State.to_raw(), VOLATILE_STATE);
        assert_eq!(VolatileMode::Overlay.to_raw(), VOLATILE_OVERLAY);
        assert_eq!(VolatileMode::No.to_raw(), VOLATILE_NO);
    }

    #[test]
    fn test_validate_path() {
        assert!(validate_path("/sysroot").is_ok());
        assert!(validate_path("/mnt/root").is_ok());
        assert!(validate_path("").is_err());
        assert!(validate_path("relative").is_err());
        assert!(validate_path("/").is_err());
        assert!(validate_path("//").is_err());
        assert!(validate_path("/./").is_err());
        assert!(validate_path("/../").is_ok());
    }

    #[test]
    fn test_shell_escape() {
        assert_eq!(shell_escape("/sysroot"), "/sysroot");
        assert_eq!(shell_escape("/path,with,commas"), "/path\\,with\\,commas");
        assert_eq!(shell_escape("/path:with:colons"), "/path\\:with\\:colons");
        assert_eq!(shell_escape("/mix:ed,path"), "/mix\\:ed\\,path");
    }

    #[test]
    fn test_build_overlay_options() {
        let opts = build_overlay_options("/sysroot", "/run/upper", "/run/work");
        assert!(opts.starts_with("lowerdir=/sysroot,upperdir=/run/upper,workdir=/run/work"));
    }

    #[test]
    fn test_parse_args_defaults() {
        let args = parse_args(&["prog"]).unwrap();
        assert_eq!(args.mode, VolatileMode::No);
        assert_eq!(args.path, DEFAULT_SYSROOT);
    }

    #[test]
    fn test_parse_args_with_mode() {
        let args = parse_args(&["prog", "overlay"]).unwrap();
        assert_eq!(args.mode, VolatileMode::Overlay);
        assert_eq!(args.path, DEFAULT_SYSROOT);
    }

    #[test]
    fn test_parse_args_with_path() {
        let args = parse_args(&["prog", "yes", "/mnt/volatile"]).unwrap();
        assert_eq!(args.mode, VolatileMode::Yes);
        assert_eq!(args.path, "/mnt/volatile");
    }

    #[test]
    fn test_parse_args_too_many() {
        assert!(parse_args(&["prog", "yes", "/path", "extra"]).is_err());
    }

    #[test]
    fn test_parse_args_invalid_path() {
        assert!(parse_args(&["prog", "yes", "relative"]).is_err());
        assert!(parse_args(&["prog", "yes", "/"]).is_err());
        assert!(parse_args(&["prog", "yes", ""]).is_err());
    }

    #[test]
    fn test_device_link_content() {
        assert_eq!(device_link_content(8, 0), "/dev/block/8:0");
        assert_eq!(device_link_content(259, 1), "/dev/block/259:1");
    }

    #[test]
    fn cmdline_mode_uses_last_value() {
        assert_eq!(
            mode_from_cmdline("systemd.volatile=no systemd.volatile=overlay").unwrap(),
            Some(VolatileMode::Overlay)
        );
    }

    #[test]
    fn bare_cmdline_key_enables_volatile_mode() {
        assert_eq!(
            mode_from_cmdline("quiet systemd.volatile").unwrap(),
            Some(VolatileMode::Yes)
        );
    }

    #[test]
    fn bare_key_does_not_discard_an_earlier_value() {
        assert_eq!(
            mode_from_cmdline("systemd.volatile=overlay systemd.volatile").unwrap(),
            Some(VolatileMode::Overlay)
        );
    }

    #[test]
    fn cmdline_mode_ignores_key_prefixes() {
        assert_eq!(
            mode_from_cmdline("systemd.volatile-mode=yes").unwrap(),
            None
        );
    }

    #[test]
    fn cmdline_mode_accepts_an_unquoted_value_inside_quotes() {
        assert_eq!(
            mode_from_cmdline("systemd.volatile=\"overlay\"").unwrap(),
            Some(VolatileMode::Overlay)
        );
    }

    #[test]
    fn escaped_cmdline_mode_is_not_silently_unescaped() {
        assert!(mode_from_cmdline(r"systemd.volatile=over\\lay").is_err());
    }

    #[test]
    fn cmdline_value_beats_invalid_positional_mode() {
        let args =
            resolve_args_from_cmdline(&["prog", "not-a-mode", "/sysroot"], "systemd.volatile=no")
                .unwrap();
        assert_eq!(args.mode, VolatileMode::No);
    }

    #[test]
    fn path_is_validated_even_when_cmdline_mode_is_inactive() {
        assert!(
            resolve_args_from_cmdline(&["prog", "yes", "relative"], "systemd.volatile=no").is_err()
        );
    }

    #[test]
    fn only_yes_and_overlay_change_the_root() {
        assert!(!mode_requires_root_transition(VolatileMode::No));
        assert!(!mode_requires_root_transition(VolatileMode::State));
        assert!(mode_requires_root_transition(VolatileMode::Yes));
        assert!(mode_requires_root_transition(VolatileMode::Overlay));
    }

    #[test]
    fn tmpfs_limits_match_the_c_rootfs_policy() {
        assert_eq!(TMPFS_OPTIONS, "mode=0755,size=25%,nr_inodes=1m");
    }

    #[test]
    fn parses_mount_id_from_fdinfo() {
        assert_eq!(
            parse_mount_id("pos:\t0\nflags:\t0100000\nmnt_id:\t731\n"),
            Some(731)
        );
        assert_eq!(parse_mount_id("pos:\t0\n"), None);
    }

    #[test]
    fn finds_filesystem_type_by_mount_id() {
        let mountinfo = "\
29 23 0:26 / /sys rw,nosuid - sysfs sysfs rw
37 23 0:33 / /run rw,nosuid,nodev - tmpfs tmpfs rw,size=1m
";
        assert_eq!(parse_filesystem_type(mountinfo, 37), Some("tmpfs"));
        assert_eq!(parse_filesystem_type(mountinfo, 29), Some("sysfs"));
        assert_eq!(parse_filesystem_type(mountinfo, 999), None);
    }
}
