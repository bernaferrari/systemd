// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/cgls/cgls.c
//
// Recursively show control group contents.
// Supports unit filtering, cgroup paths, and machine containers.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default cgroup path prefix.
pub const CGROUP_PATH_PREFIX: &str = "/sys/fs/cgroup";

// ── Types ─────────────────────────────────────────────────────────────────

/// Which type of unit to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowUnit {
    /// No unit filtering (default).
    None,
    /// Show system units.
    System,
    /// Show user units.
    User,
}

impl Default for ShowUnit {
    fn default() -> Self {
        ShowUnit::None
    }
}

/// Output flags for cgroup display (mirrors OutputFlags from C).
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OutputFlags: u32 {
        const SHOW_ALL       = 1 << 0;
        const KERNEL_THREADS = 1 << 1;
        const CGROUP_XATTRS  = 1 << 2;
        const CGROUP_ID      = 1 << 3;
        const FULL_WIDTH     = 1 << 4;
    }
}

/// Parsed command-line arguments for `systemd-cgls`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CglsArgs {
    /// Output display flags.
    pub output_flags: OutputFlags,
    /// Unit display mode.
    pub show_unit: ShowUnit,
    /// Unit/cgroup names to display.
    pub names: Vec<String>,
    /// Whether to use full-width output (-1 = auto, 0 = no, 1 = yes).
    pub full: i32,
    /// Container name to inspect.
    pub machine: Option<String>,
}

impl Default for CglsArgs {
    fn default() -> Self {
        Self {
            output_flags: OutputFlags::empty(),
            show_unit: ShowUnit::None,
            names: Vec::new(),
            full: -1,
            machine: None,
        }
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parse command-line arguments for `systemd-cgls`.
pub fn parse_cgls_args(args: &[&str]) -> Result<CglsArgs, i32> {
    let mut result = CglsArgs::default();
    let mut i = 0;

    while i < args.len() {
        match args[i] {
            "--help" | "-h" => return Err(0),
            "--version" => return Err(0),
            "--no-pager" => {}
            "--all" | "-a" => {
                result.output_flags |= OutputFlags::SHOW_ALL;
            }
            "--unit" | "-u" => {
                if result.show_unit == ShowUnit::User {
                    return Err(-libc::EINVAL);
                }
                result.show_unit = ShowUnit::System;
                i += 1;
                if i < args.len() && !args[i].starts_with('-') {
                    result.names.push(args[i].to_string());
                }
            }
            "--user-unit" => {
                if result.show_unit == ShowUnit::System {
                    return Err(-libc::EINVAL);
                }
                result.show_unit = ShowUnit::User;
                i += 1;
                if i < args.len() && !args[i].starts_with('-') {
                    result.names.push(args[i].to_string());
                }
            }
            "--full" | "-l" => {
                result.full = 1;
            }
            "-k" => {
                result.output_flags |= OutputFlags::KERNEL_THREADS;
            }
            "--machine" | "-M" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.machine = Some(args[i].to_string());
            }
            s if s.starts_with("--xattr") => {
                result.output_flags |= OutputFlags::CGROUP_XATTRS;
            }
            s if s.starts_with("--cgroup-id") => {
                result.output_flags |= OutputFlags::CGROUP_ID;
            }
            s if s.starts_with('-') => return Err(-libc::EINVAL),
            other => {
                result.names.push(other.to_string());
            }
        }
        i += 1;
    }

    if result.machine.is_some() && result.show_unit != ShowUnit::None {
        return Err(-libc::EINVAL);
    }

    Ok(result)
}

// ── Core logic ────────────────────────────────────────────────────────────

/// Check if a path is within the cgroup filesystem.
pub fn is_cgroup_path(path: &str) -> bool {
    path.starts_with(CGROUP_PATH_PREFIX)
}

/// Format the cgroup header display string.
pub fn format_cgroup_header(path: &str) -> String {
    let display = if path.is_empty() { "/" } else { path };
    format!("CGroup {}:", display)
}

/// Resolve the effective full-width mode based on pager state.
pub fn resolve_full_mode(full: i32, pager_active: bool) -> bool {
    match full {
        1 => true,
        0 => false,
        _ => pager_active,
    }
}

/// Map show_unit to a runtime scope string.
pub fn show_unit_to_scope(unit: ShowUnit) -> &'static str {
    match unit {
        ShowUnit::System => "system",
        ShowUnit::User => "user",
        ShowUnit::None => "system",
    }
}

/// Check if combining --unit/--user-unit with --machine is valid.
pub fn validate_unit_machine_combo(show_unit: ShowUnit, machine: Option<&str>) -> bool {
    if machine.is_some() && show_unit != ShowUnit::None {
        return false;
    }
    true
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_args() {
        let args = CglsArgs::default();
        assert!(args.output_flags.is_empty());
        assert_eq!(args.show_unit, ShowUnit::None);
        assert!(args.names.is_empty());
        assert_eq!(args.full, -1);
        assert!(args.machine.is_none());
    }

    #[test]
    fn test_parse_empty_args() {
        let args = parse_cgls_args(&[]).unwrap();
        assert_eq!(args.show_unit, ShowUnit::None);
    }

    #[test]
    fn test_parse_all_flag() {
        let args = parse_cgls_args(&["--all"]).unwrap();
        assert!(args.output_flags.contains(OutputFlags::SHOW_ALL));
    }

    #[test]
    fn test_parse_unit_system() {
        let args = parse_cgls_args(&["--unit", "nginx.service"]).unwrap();
        assert_eq!(args.show_unit, ShowUnit::System);
        assert_eq!(args.names, vec!["nginx.service"]);
    }

    #[test]
    fn test_parse_user_unit() {
        let args = parse_cgls_args(&["--user-unit", "app.service"]).unwrap();
        assert_eq!(args.show_unit, ShowUnit::User);
        assert_eq!(args.names, vec!["app.service"]);
    }

    #[test]
    fn test_parse_unit_conflict() {
        assert!(parse_cgls_args(&["--unit", "a", "--user-unit", "b"]).is_err());
    }

    #[test]
    fn test_parse_machine_conflict() {
        assert!(parse_cgls_args(&["--machine", "m", "--unit", "a"]).is_err());
    }

    #[test]
    fn test_parse_full() {
        let args = parse_cgls_args(&["--full"]).unwrap();
        assert_eq!(args.full, 1);
    }

    #[test]
    fn test_parse_kernel_threads() {
        let args = parse_cgls_args(&["-k"]).unwrap();
        assert!(args.output_flags.contains(OutputFlags::KERNEL_THREADS));
    }

    #[test]
    fn test_parse_machine() {
        let args = parse_cgls_args(&["--machine", "mycontainer"]).unwrap();
        assert_eq!(args.machine.as_deref(), Some("mycontainer"));
    }

    #[test]
    fn test_parse_positional() {
        let args = parse_cgls_args(&["system.slice"]).unwrap();
        assert_eq!(args.names, vec!["system.slice"]);
    }

    #[test]
    fn test_is_cgroup_path() {
        assert!(is_cgroup_path("/sys/fs/cgroup/system.slice"));
        assert!(!is_cgroup_path("/home/user"));
    }

    #[test]
    fn test_format_cgroup_header() {
        assert_eq!(
            format_cgroup_header("/system.slice"),
            "CGroup /system.slice:"
        );
        assert_eq!(format_cgroup_header(""), "CGroup /:");
    }

    #[test]
    fn test_resolve_full_mode_auto() {
        assert!(resolve_full_mode(-1, true));
        assert!(!resolve_full_mode(-1, false));
    }

    #[test]
    fn test_resolve_full_mode_explicit() {
        assert!(resolve_full_mode(1, false));
        assert!(!resolve_full_mode(0, true));
    }

    #[test]
    fn test_show_unit_to_scope() {
        assert_eq!(show_unit_to_scope(ShowUnit::System), "system");
        assert_eq!(show_unit_to_scope(ShowUnit::User), "user");
        assert_eq!(show_unit_to_scope(ShowUnit::None), "system");
    }

    #[test]
    fn test_validate_unit_machine_combo() {
        assert!(validate_unit_machine_combo(ShowUnit::None, Some("m")));
        assert!(!validate_unit_machine_combo(ShowUnit::System, Some("m")));
        assert!(validate_unit_machine_combo(ShowUnit::None, None));
    }
}
