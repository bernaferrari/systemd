// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/cgroup-show.c, src/shared/cgroup-show.h
//
// Cgroup hierarchy display and tree rendering.
//
// Reads cgroup.procs files to enumerate PIDs, renders them in a tree
// structure with Unicode box-drawing glyphs, and optionally shows
// delegation status, cgroup IDs, and extended attributes.

use crate::ffi::*;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default cgroup v2 mount point.
pub const CGROUP_V2_MOUNT: &str = "/sys/fs/cgroup";

// ── Tree glyphs ───────────────────────────────────────────────────────────

/// Tree-drawing characters used in cgroup display.
pub mod glyph {
    pub const TREE_BRANCH: &str = "├─";
    pub const TREE_RIGHT: &str = "└─";
    pub const TREE_VERTICAL: &str = "│ ";
    pub const TRIANGULAR_BULLET: &str = "▸ ";
    pub const ARROW_RIGHT: &str = "→";
    pub const ELLIPSIS: &str = "…";
}

// ── Output flags ──────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling cgroup display output.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OutputFlags: u32 {
        /// Use full terminal width (ignore column limit).
        const FULL_WIDTH       = 1 << 0;
        /// Include kernel threads in PID listing.
        const KERNEL_THREADS   = 1 << 1;
        /// Show all cgroups, even empty ones.
        const SHOW_ALL         = 1 << 2;
        /// Display cgroup IDs.
        const SHOW_CGROUP_ID   = 1 << 3;
        /// Display extended attributes.
        const SHOW_CGROUP_XATTRS = 1 << 4;
    }
}

impl Default for OutputFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// ── Process info ──────────────────────────────────────────────────────────

/// Information about a single process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: i32,
    pub cmdline: Option<String>,
}

// ── Cgroup name display info ──────────────────────────────────────────────

/// Display metadata for a cgroup entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupDisplayInfo {
    pub name: String,
    pub delegated: bool,
    pub cgroup_id: Option<u64>,
    pub xattrs: Vec<(String, String)>,
}

// ── Decimal width calculation ─────────────────────────────────────────────

/// Calculate the number of decimal digits needed to display a number.
///
/// Equivalent to C's `DECIMAL_STR_WIDTH` macro.
pub fn decimal_str_width(mut val: i32) -> usize {
    if val <= 0 {
        return 1;
    }
    let mut width = 0;
    while val != 0 {
        val /= 10;
        width += 1;
    }
    width
}

// ── PID array processing ──────────────────────────────────────────────────

/// Sort PIDs numerically and remove duplicates in-place.
pub fn sort_and_dedup_pids(pids: &mut Vec<i32>) {
    pids.sort_unstable();
    pids.dedup();
}

/// Format a sorted, deduplicated PID array for display.
///
/// Each line includes the tree prefix, PID (right-aligned), and command line.
/// `more` indicates whether more siblings follow after this entry.
pub fn format_pid_array(
    pids: &[i32],
    prefix: &str,
    extra: bool,
    more: bool,
    n_columns: usize,
) -> String {
    if pids.is_empty() {
        return String::new();
    }

    let pid_width = decimal_str_width(pids.last().copied().unwrap_or(0));
    let mut output = String::new();

    for (i, &pid) in pids.iter().enumerate() {
        let is_last = !more && i == pids.len() - 1;
        let tree = if extra {
            glyph::TRIANGULAR_BULLET
        } else if more || i < pids.len() - 1 {
            glyph::TREE_BRANCH
        } else {
            glyph::TREE_RIGHT
        };

        // Truncate cmdline to fit available columns
        let max_cmdline = if n_columns > pid_width + 3 {
            n_columns - pid_width - 3
        } else {
            20
        };

        let cmdline = read_process_cmdline(pid)
            .unwrap_or_default()
            .unwrap_or_else(|| "?".to_string());

        let truncated = if cmdline.len() > max_cmdline {
            format!("{}…", &cmdline[..max_cmdline.saturating_sub(1)])
        } else {
            cmdline
        };

        let _ = writeln!(
            output,
            "{}{} {:>width$} {}",
            prefix,
            tree,
            pid,
            truncated,
            width = pid_width
        );
    }

    output
}

// ── Read cgroup.procs ─────────────────────────────────────────────────────

/// Read PIDs from a cgroup's `cgroup.procs` file.
pub fn read_cgroup_procs(path: &Path) -> io::Result<Vec<i32>> {
    let procs_path = path.join("cgroup.procs");
    let content = match fs::read_to_string(&procs_path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut pids = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match trimmed.parse::<i32>() {
            Ok(pid) if pid > 0 => pids.push(pid),
            _ => continue,
        }
    }
    Ok(pids)
}

/// Read a single PID from a cgroup.procs file reader.
///
/// Returns `Ok(Some(pid))` on success, `Ok(None)` on EOF,
/// or an error. Mirrors `cg_read_pid()`.
pub fn cg_read_pid(content: &str, offset: &mut usize) -> io::Result<Option<i32>> {
    let bytes = content.as_bytes();
    let mut start = *offset;

    // Skip whitespace/newlines
    while start < bytes.len() && (bytes[start] == b'\n' || bytes[start] == b'\r') {
        start += 1;
    }

    if start >= bytes.len() {
        *offset = start;
        return Ok(None);
    }

    let mut end = start;
    while end < bytes.len() && bytes[end] != b'\n' && bytes[end] != b'\r' {
        end += 1;
    }

    *offset = end;

    let line = &content[start..end];
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    trimmed
        .parse::<i32>()
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid PID in cgroup.procs"))
}

// ── Process cmdline ───────────────────────────────────────────────────────

/// Read the command line of a process from `/proc/<pid>/cmdline`.
pub fn read_process_cmdline(pid: i32) -> io::Result<Option<String>> {
    let path = PathBuf::from(format!("/proc/{}/cmdline", pid));
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    let args: Vec<&str> = content.split('\0').filter(|s| !s.is_empty()).collect();
    if args.is_empty() {
        Ok(None)
    } else {
        Ok(Some(args.join(" ")))
    }
}

// ── Cgroup path utilities ─────────────────────────────────────────────────

/// Get the cgroup path for a given PID.
///
/// Parses `/proc/<pid>/cgroup` and returns the path under the cgroup mount.
pub fn cg_pid_get_path(pid: i32) -> io::Result<PathBuf> {
    let path = PathBuf::from(format!("/proc/{}/cgroup", pid));
    let content = fs::read_to_string(&path)?;

    // Parse cgroup v2 entries (hierarchy-id:controller-list:cgroup-path)
    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() >= 3 {
            // cgroup v2 has empty controller list (or no controllers)
            if parts[1].is_empty() || parts[1] == "" {
                let cgroup_path = parts[2].trim_start_matches('/');
                return Ok(PathBuf::from(CGROUP_V2_MOUNT).join(cgroup_path));
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Cgroup path not found for PID",
    ))
}

/// Get the root cgroup path.
pub fn cg_get_root_path() -> io::Result<PathBuf> {
    Ok(PathBuf::from(CGROUP_V2_MOUNT))
}

/// Check if a cgroup is empty (has no processes).
pub fn cg_is_empty(path: &Path) -> io::Result<bool> {
    let pids = read_cgroup_procs(path)?;
    Ok(pids.is_empty())
}

/// Read subgroups of a cgroup directory.
///
/// Returns sorted subgroup names. Mirrors `cg_read_subgroup()`.
pub fn cg_read_subgroups(path: &Path) -> io::Result<Vec<String>> {
    let mut entries = Vec::new();

    let entries_iter = match fs::read_dir(path) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    for entry in entries_iter {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_dir() {
            continue;
        }

        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == "." || name_str == ".." {
            continue;
        }

        // Only include directories that look like cgroups (have cgroup.procs)
        if entry.path().join("cgroup.procs").exists() {
            entries.push(name_str.into_owned());
        }
    }

    entries.sort();
    Ok(entries)
}

/// Extract the filename component of a path.
pub fn path_extract_filename(path: &Path) -> io::Result<String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot extract filename from path",
            )
        })
}

/// Unescape cgroup name (replaces `\x2d` with `-`, etc.).
pub fn cg_unescape(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    let mut chars = name.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if chars.peek() == Some(&'x') {
                chars.next();
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                        continue;
                    }
                }
                result.push(c);
                result.push('x');
                result.push_str(&hex);
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    result
}

// ── Cgroup display: show one by path ──────────────────────────────────────

/// Show PIDs belonging to a single cgroup.
pub fn show_cgroup_one_by_path<W: FmtWrite>(
    path: &Path,
    prefix: &str,
    n_columns: usize,
    more: bool,
    flags: OutputFlags,
    out: &mut W,
) -> io::Result<()> {
    let mut pids = read_cgroup_procs(path)?;

    if flags.contains(OutputFlags::FULL_WIDTH) {
        // Don't filter kernel threads if FULL_WIDTH
    } else if !flags.contains(OutputFlags::KERNEL_THREADS) {
        pids.retain(|&pid| !pid_is_kernel_thread(pid));
    }

    sort_and_dedup_pids(&mut pids);
    let rendered = format_pid_array(&pids, prefix, false, more, n_columns);
    write!(out, "{}", rendered).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(())
}

/// Check if a PID is a kernel thread.
///
/// Reads /proc/<pid>/stat and checks if the process has no associated user-space memory.
fn pid_is_kernel_thread(pid: i32) -> bool {
    let stat_path = format!("/proc/{}/stat", pid);
    let content = match fs::read_to_string(&stat_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Parse: pid (comm) state ppid ...
    // Field 3 (after comm) is the state. vmlinux threads often have name starting with '['
    let after_paren = match content.rfind(')') {
        Some(pos) => &content[pos + 1..],
        None => return false,
    };

    let fields: Vec<&str> = after_paren.split_whitespace().collect();
    // fields[0] is state, fields[1] is ppid
    // A kernel thread typically has ppid == 2 (kthreadd)
    if fields.len() > 1 {
        if let Ok(ppid) = fields[1].parse::<i32>() {
            if ppid == 2 {
                return true;
            }
        }
    }

    // Also check if comm starts with '[' (kernel thread convention)
    if let Some(start) = content.find('(') {
        if let Some(end) = content[start..].find(')') {
            let comm = &content[start + 1..start + end];
            if comm.starts_with('[') {
                return true;
            }
        }
    }

    false
}

// ── Cgroup display: show name ─────────────────────────────────────────────

/// Show a cgroup name with optional decoration (delegation, ID, xattrs).
pub fn show_cgroup_name<W: FmtWrite>(
    path: &Path,
    prefix: &str,
    tree_branch: bool,
    flags: OutputFlags,
    out: &mut W,
) -> io::Result<()> {
    let name = path_extract_filename(path)?;
    let unescaped = cg_unescape(&name);

    // Check delegation
    let delegated = is_cgroup_delegated(path).unwrap_or(false);

    // Get cgroup ID if requested
    let cgroup_id = if flags.contains(OutputFlags::SHOW_CGROUP_ID) {
        get_cgroup_id(path).ok()
    } else {
        None
    };

    // Tree glyph
    let tree_char = if tree_branch {
        glyph::TREE_BRANCH
    } else {
        glyph::TREE_RIGHT
    };

    let _ = write!(out, "{}{}", prefix, tree_char);

    if delegated {
        let _ = write!(out, "\x1b[4m{}\x1b[0m", unescaped);
        let _ = write!(out, " \x1b[1m{}\x1b[0m", glyph::ELLIPSIS);
    } else {
        let _ = write!(out, "{}", unescaped);
    }

    if let Some(id) = cgroup_id {
        let _ = write!(out, " \x1b[2m(#{}))\x1b[0m", id);
    }

    let _ = writeln!(out);

    // Show extended attributes if requested
    if flags.contains(OutputFlags::SHOW_CGROUP_XATTRS) {
        let xattrs = read_cgroup_xattrs(path)?;
        let indent = if tree_branch {
            format!("{}{} ", prefix, glyph::TREE_VERTICAL)
        } else {
            format!("{}  ", prefix)
        };

        for (key, value) in &xattrs {
            let _ = writeln!(
                out,
                "{}{} \x1b[34m{}\x1b[0m: {}",
                indent,
                glyph::ARROW_RIGHT,
                key,
                value
            );
        }
    }

    Ok(())
}

/// Check if a cgroup is delegated.
fn is_cgroup_delegated(_path: &Path) -> io::Result<bool> {
    // In a full implementation this would check /sys/fs/cgroup/<path>/cgroup.controllers
    // and other delegation markers. For now, check for the delegate flag file.
    let delegate_file = _path.join("cgroup.controllers");
    Ok(delegate_file.exists())
}

/// Get a cgroup's ID (file handle as u64).
fn get_cgroup_id(_path: &Path) -> io::Result<u64> {
    // This requires fstatx with STATX_ATTR_CGROUP_ID or name_to_handle_at,
    // which needs unsafe. Stub for safe Rust.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "cgroup ID retrieval not available in safe Rust",
    ))
}

/// Read extended attributes from a cgroup directory.
fn read_cgroup_xattrs(_path: &Path) -> io::Result<Vec<(String, String)>> {
    // Requires unsafe for fgetxattr/flistxattr syscalls.
    // Stub for safe Rust implementation.
    Ok(Vec::new())
}

// ── Cgroup display: by path (recursive) ───────────────────────────────────

/// Show a cgroup and its subgroups recursively as a tree.
pub fn show_cgroup_by_path<W: FmtWrite>(
    path: &Path,
    prefix: &str,
    n_columns: usize,
    flags: OutputFlags,
    out: &mut W,
) -> io::Result<()> {
    let effective_columns = if n_columns == 0 { 80 } else { n_columns };
    let prefix = if prefix.is_empty() { "" } else { prefix };

    let subgroups = cg_read_subgroups(path)?;

    // Determine which subgroups to show
    let mut visible: Vec<&String> = Vec::new();
    for sg in &subgroups {
        if flags.contains(OutputFlags::SHOW_ALL) {
            visible.push(sg);
        } else {
            let sg_path = path.join(sg);
            if !cg_is_empty(&sg_path)? {
                visible.push(sg);
            }
        }
    }

    let mut shown_pids = false;

    // Show PIDs before subgroups (if any subgroups exist)
    if !visible.is_empty() {
        show_cgroup_one_by_path(path, prefix, effective_columns, true, flags, out)?;
        shown_pids = true;
    }

    // Show subgroups
    for (i, sg) in visible.iter().enumerate() {
        let is_last = i == visible.len() - 1;
        let sg_path = path.join(sg);

        show_cgroup_name(&sg_path, prefix, !is_last, flags, out)?;

        let child_prefix = if is_last {
            format!("{}  ", prefix)
        } else {
            format!("{}{}", prefix, glyph::TREE_VERTICAL)
        };

        show_cgroup_by_path(
            &sg_path,
            &child_prefix,
            effective_columns.saturating_sub(2),
            flags,
            out,
        )?;
    }

    // Show PIDs if no subgroups were found
    if !shown_pids {
        show_cgroup_one_by_path(path, prefix, effective_columns, false, flags, out)?;
    }

    Ok(())
}

// ── Cgroup display: by name ───────────────────────────────────────────────

/// Resolve a cgroup name to its filesystem path and display it.
pub fn show_cgroup<W: FmtWrite>(
    name: &str,
    prefix: &str,
    n_columns: usize,
    flags: OutputFlags,
    out: &mut W,
) -> io::Result<()> {
    let path = if name.starts_with('/') {
        PathBuf::from(name)
    } else {
        PathBuf::from(CGROUP_V2_MOUNT).join(name)
    };

    show_cgroup_by_path(&path, prefix, n_columns, flags, out)
}

// ── Extra PIDs ────────────────────────────────────────────────────────────

/// Show PIDs that belong to the cgroup tree but are in different subgroups.
pub fn show_extra_pids<W: FmtWrite>(
    cgroup_path: &Path,
    prefix: &str,
    n_columns: usize,
    pids: &[i32],
    flags: OutputFlags,
    out: &mut W,
) -> io::Result<()> {
    if pids.is_empty() {
        return Ok(());
    }

    let effective_columns = if n_columns == 0 { 80 } else { n_columns };

    let mut extra: Vec<i32> = Vec::new();
    for &pid in pids {
        match cg_pid_get_path(pid) {
            Ok(pid_cgroup) => {
                if !pid_cgroup.starts_with(cgroup_path) {
                    extra.push(pid);
                }
            }
            Err(_) => {
                extra.push(pid);
            }
        }
    }

    sort_and_dedup_pids(&mut extra);
    let rendered = format_pid_array(&extra, prefix, true, false, effective_columns);
    write!(out, "{}", rendered).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(())
}

/// Show a cgroup tree and any extra PIDs not belonging to it.
pub fn show_cgroup_and_extra<W: FmtWrite>(
    path: &Path,
    prefix: &str,
    n_columns: usize,
    extra_pids: &[i32],
    flags: OutputFlags,
    out: &mut W,
) -> io::Result<()> {
    show_cgroup_by_path(path, prefix, n_columns, flags, out)?;
    show_extra_pids(path, prefix, n_columns, extra_pids, flags, out)?;
    Ok(())
}

// ── Path resolution helpers ───────────────────────────────────────────────

/// Resolve a cgroup name to a full filesystem path.
pub fn cg_get_path(name: &str) -> io::Result<PathBuf> {
    if name.starts_with('/') {
        Ok(PathBuf::from(name))
    } else {
        Ok(PathBuf::from(CGROUP_V2_MOUNT).join(name))
    }
}

/// Join paths, returning None if either argument is empty.
pub fn path_join_optional(base: Option<&Path>, suffix: &str) -> Option<PathBuf> {
    base.map(|b| b.join(suffix))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decimal_str_width() {
        assert_eq!(decimal_str_width(0), 1);
        assert_eq!(decimal_str_width(1), 1);
        assert_eq!(decimal_str_width(9), 1);
        assert_eq!(decimal_str_width(10), 2);
        assert_eq!(decimal_str_width(99), 2);
        assert_eq!(decimal_str_width(100), 3);
        assert_eq!(decimal_str_width(999999), 6);
    }

    #[test]
    fn test_sort_and_dedup_pids() {
        let mut pids = vec![5, 3, 5, 1, 3, 2];
        sort_and_dedup_pids(&mut pids);
        assert_eq!(pids, vec![1, 2, 3, 5]);
    }

    #[test]
    fn test_sort_and_dedup_pids_empty() {
        let mut pids: Vec<i32> = vec![];
        sort_and_dedup_pids(&mut pids);
        assert!(pids.is_empty());
    }

    #[test]
    fn test_sort_and_dedup_pids_single() {
        let mut pids = vec![42];
        sort_and_dedup_pids(&mut pids);
        assert_eq!(pids, vec![42]);
    }

    #[test]
    fn test_sort_and_dedup_pids_all_same() {
        let mut pids = vec![7, 7, 7, 7];
        sort_and_dedup_pids(&mut pids);
        assert_eq!(pids, vec![7]);
    }

    #[test]
    fn test_format_pid_array_empty() {
        let result = format_pid_array(&[], "", false, false, 80);
        assert!(result.is_empty());
    }

    #[test]
    fn test_format_pid_array_basic() {
        let pids = vec![1, 2, 3];
        let result = format_pid_array(&pids, "", false, false, 80);
        assert!(result.contains("1"));
        assert!(result.contains("2"));
        assert!(result.contains("3"));
        // Last entry uses └─
        assert!(result.contains("└─"));
    }

    #[test]
    fn test_format_pid_array_with_more() {
        let pids = vec![100, 200];
        let result = format_pid_array(&pids, "  ", false, true, 80);
        // With more=true, all entries use ├─
        let branch_count = result.matches("├─").count();
        assert_eq!(branch_count, 2);
    }

    #[test]
    fn test_format_pid_array_extra() {
        let pids = vec![42];
        let result = format_pid_array(&pids, "", true, false, 80);
        // Extra mode uses triangular bullet
        assert!(result.contains("▸"));
    }

    #[test]
    fn test_cg_read_pid() {
        let content = "123\n456\n789\n";
        let mut offset = 0;

        let pid = cg_read_pid(content, &mut offset).unwrap();
        assert_eq!(pid, Some(123));

        let pid = cg_read_pid(content, &mut offset).unwrap();
        assert_eq!(pid, Some(456));

        let pid = cg_read_pid(content, &mut offset).unwrap();
        assert_eq!(pid, Some(789));

        let pid = cg_read_pid(content, &mut offset).unwrap();
        assert_eq!(pid, None);
    }

    #[test]
    fn test_cg_read_pid_empty() {
        let content = "";
        let mut offset = 0;
        let pid = cg_read_pid(content, &mut offset).unwrap();
        assert_eq!(pid, None);
    }

    #[test]
    fn test_cg_read_pid_trailing_newlines() {
        let content = "42\n\n\n";
        let mut offset = 0;
        let pid = cg_read_pid(content, &mut offset).unwrap();
        assert_eq!(pid, Some(42));
        let pid = cg_read_pid(content, &mut offset).unwrap();
        assert_eq!(pid, None);
    }

    #[test]
    fn test_cg_read_pid_invalid() {
        let content = "abc\n";
        let mut offset = 0;
        let result = cg_read_pid(content, &mut offset);
        assert!(result.is_err());
    }

    #[test]
    fn test_path_extract_filename() {
        assert_eq!(
            path_extract_filename(Path::new("/sys/fs/cgroup/user.slice")).unwrap(),
            "user.slice"
        );
        assert_eq!(
            path_extract_filename(Path::new("mygroup")).unwrap(),
            "mygroup"
        );
    }

    #[test]
    fn test_path_extract_filename_root() {
        // Root path has no filename
        assert!(path_extract_filename(Path::new("/")).is_err());
    }

    #[test]
    fn test_cg_unescape_no_escape() {
        assert_eq!(cg_unescape("user.slice"), "user.slice");
    }

    #[test]
    fn test_cg_unescape_hex() {
        // \x2d should become '-'
        assert_eq!(cg_unescape("user\\x2dslice"), "user-slice");
    }

    #[test]
    fn test_cg_unescape_hex_uppercase() {
        assert_eq!(cg_unescape("foo\\x5fbar"), "foo_bar");
    }

    #[test]
    fn test_cg_unescape_incomplete_hex() {
        // Incomplete hex escape stays as-is
        assert_eq!(cg_unescape("foo\\x"), "foo\\x");
    }

    #[test]
    fn test_output_flags_default() {
        let flags = OutputFlags::default();
        assert!(flags.is_empty());
    }

    #[test]
    fn test_output_flags_bitflags() {
        let flags = OutputFlags::SHOW_ALL | OutputFlags::KERNEL_THREADS;
        assert!(flags.contains(OutputFlags::SHOW_ALL));
        assert!(flags.contains(OutputFlags::KERNEL_THREADS));
        assert!(!flags.contains(OutputFlags::FULL_WIDTH));
    }

    #[test]
    fn test_cg_get_path_absolute() {
        let path = cg_get_path("/sys/fs/cgroup/user.slice").unwrap();
        assert_eq!(path, PathBuf::from("/sys/fs/cgroup/user.slice"));
    }

    #[test]
    fn test_cg_get_path_relative() {
        let path = cg_get_path("user.slice").unwrap();
        assert_eq!(path, PathBuf::from("/sys/fs/cgroup/user.slice"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_cg_is_empty_nonexistent() {
        // Non-existent path should error
        let result = cg_is_empty(Path::new("/nonexistent/path/cgroup"));
        assert!(result.is_err());
    }

    #[test]
    fn test_path_join_optional() {
        assert_eq!(
            path_join_optional(Some(Path::new("/base")), "sub"),
            Some(PathBuf::from("/base/sub"))
        );
        assert_eq!(path_join_optional(None, "sub"), None);
    }

    #[test]
    fn test_cgroup_display_info() {
        let info = CgroupDisplayInfo {
            name: "user.slice".to_string(),
            delegated: true,
            cgroup_id: Some(12345),
            xattrs: vec![("user.data".to_string(), "value".to_string())],
        };
        assert_eq!(info.name, "user.slice");
        assert!(info.delegated);
        assert_eq!(info.cgroup_id, Some(12345));
        assert_eq!(info.xattrs.len(), 1);
    }

    #[test]
    fn test_process_info() {
        let info = ProcessInfo {
            pid: 1,
            cmdline: Some("init".to_string()),
        };
        assert_eq!(info.pid, 1);
        assert_eq!(info.cmdline.as_deref(), Some("init"));
    }

    #[test]
    fn test_glyph_constants() {
        assert!(!glyph::TREE_BRANCH.is_empty());
        assert!(!glyph::TREE_RIGHT.is_empty());
        assert!(!glyph::TREE_VERTICAL.is_empty());
        assert!(!glyph::TRIANGULAR_BULLET.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_show_cgroup_by_path_nonexistent() {
        let mut output = String::new();
        let flags = OutputFlags::default();
        let result = show_cgroup_by_path(
            Path::new("/nonexistent/cgroup/path"),
            "",
            80,
            flags,
            &mut output,
        );
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_show_cgroup_nonexistent() {
        let mut output = String::new();
        let flags = OutputFlags::default();
        let result = show_cgroup("nonexistent_cgroup_xyz", "", 80, flags, &mut output);
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_show_cgroup_and_extra_no_extra() {
        let mut output = String::new();
        let flags = OutputFlags::default();
        let result =
            show_cgroup_and_extra(Path::new("/nonexistent"), "", 80, &[], flags, &mut output);
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_read_cgroup_procs_nonexistent() {
        let result = read_cgroup_procs(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }

    #[test]
    fn test_read_process_cmdline_nonexistent() {
        let result = read_process_cmdline(9999999);
        // Either error or None depending on /proc availability
        match result {
            Ok(None) => {}
            Err(_) => {}
            Ok(Some(_)) => panic!("Unexpected success for nonexistent PID"),
        }
    }

    #[test]
    fn test_pid_is_kernel_thread_nonexistent() {
        // Should not panic on nonexistent PID
        let result = pid_is_kernel_thread(9999999);
        assert!(!result);
    }
}
