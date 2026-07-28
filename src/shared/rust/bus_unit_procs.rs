// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bus-unit-procs.c, src/shared/bus-unit-procs.h
//
// Unit process listing via D-Bus.
//
// Builds a cgroup tree from `GetUnitProcesses` D-Bus replies and renders
// the process list as a tree-formatted table.  Extra processes (those in
// cgroups not part of the displayed tree) are shown in a flat list with
// a triangular-bullet prefix.

use crate::ffi::*;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as FmtWrite;
use std::io;

// ── Tree-drawing glyphs ────────────────────────────────────────────────────

/// Unicode glyphs used for drawing the process tree.
#[derive(Debug)]
pub struct Glyphs {
    pub tree_branch: &'static str,
    pub tree_right: &'static str,
    pub tree_vertical: &'static str,
    pub tree_space: &'static str,
    pub triangular_bullet: &'static str,
}

/// Default Unicode glyphs for tree rendering.
pub const GLYPHS_UNICODE: Glyphs = Glyphs {
    tree_branch: "├─",
    tree_right: "└─",
    tree_vertical: "│ ",
    tree_space: "  ",
    triangular_bullet: "•",
};

/// ASCII-only fallback glyphs.
pub const GLYPHS_ASCII: Glyphs = Glyphs {
    tree_branch: "|-",
    tree_right: "`-",
    tree_vertical: "| ",
    tree_space: "  ",
    triangular_bullet: "*",
};

// ── Error types ────────────────────────────────────────────────────────────

/// Errors that can occur during unit process listing.
#[derive(Debug)]
pub enum BusUnitProcsError {
    /// A provided path was invalid (e.g. no '/' separator where expected).
    InvalidPath(String),
    /// A required entry was not found.
    NotFound(String),
    /// I/O error during output.
    Io(io::Error),
}

impl std::fmt::Display for BusUnitProcsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BusUnitProcsError::InvalidPath(p) => write!(f, "invalid cgroup path: {p}"),
            BusUnitProcsError::NotFound(s) => write!(f, "not found: {s}"),
            BusUnitProcsError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for BusUnitProcsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BusUnitProcsError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for BusUnitProcsError {
    fn from(e: io::Error) -> Self {
        BusUnitProcsError::Io(e)
    }
}

// ── CGroup tree data model ────────────────────────────────────────────────

/// A single node in the cgroup tree.
///
/// Each node tracks its path, the set of processes (PID → command name)
/// it owns, and parent/child relationships for tree traversal.
#[derive(Debug, Clone)]
pub struct CGroupNode {
    /// Absolute cgroup path (e.g. "/user.slice/user-1000.slice/session-1.scope").
    pub cgroup_path: String,
    /// Processes directly in this cgroup, keyed by PID.
    pub pids: BTreeMap<u32, String>,
    /// Whether this node has been visited during tree output (for extra-process detection).
    pub done: bool,
}

/// The full cgroup forest produced from a `GetUnitProcesses` reply.
///
/// Internally stores all nodes indexed by path and tracks parent→children
/// edges so that the tree can be rendered top-down.
#[derive(Debug, Default)]
pub struct CGroupForest {
    nodes: HashMap<String, CGroupNode>,
    children: HashMap<String, Vec<String>>,
}

impl CGroupForest {
    /// Create an empty forest.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or look up a cgroup node for the given `path`.
    ///
    /// If the path does not yet exist a node is created.  If the path is
    /// not root (`"/"`) the parent cgroup is also ensured to exist.
    ///
    /// Returns the cgroup path of the (possibly new) node.
    pub fn add_cgroup(&mut self, path: &str) -> Result<String, BusUnitProcsError> {
        let path = empty_to_root(path);

        if self.nodes.contains_key(path) {
            return Ok(path.to_owned());
        }

        let mut parent: Option<String> = None;
        if !path.is_empty() && path != "/" {
            let e = path
                .rfind('/')
                .ok_or_else(|| BusUnitProcsError::InvalidPath(path.to_owned()))?;
            let pp = &path[..e];
            parent = Some(self.add_cgroup(pp)?);
        }

        self.nodes.insert(
            path.to_owned(),
            CGroupNode {
                cgroup_path: path.to_owned(),
                pids: BTreeMap::new(),
                done: false,
            },
        );

        if let Some(ref parent_path) = parent {
            self.children
                .entry(parent_path.clone())
                .or_default()
                .push(path.to_owned());
        }

        Ok(path.to_owned())
    }

    /// Register a process in the cgroup identified by `path`.
    ///
    /// The cgroup node is created if it does not exist yet.  Returns `Ok(())`
    /// on success or an error if `pid` is zero or the path is invalid.
    pub fn add_process(
        &mut self,
        path: &str,
        pid: u32,
        name: &str,
    ) -> Result<(), BusUnitProcsError> {
        if pid == 0 {
            return Err(BusUnitProcsError::InvalidPath(format!(
                "PID must be > 0, got {pid}"
            )));
        }

        let cg_path = self.add_cgroup(path)?;
        if let Some(node) = self.nodes.get_mut(&cg_path) {
            node.pids.insert(pid, name.to_owned());
        }
        Ok(())
    }

    /// Look up a node by its cgroup path.
    pub fn get(&self, path: &str) -> Option<&CGroupNode> {
        self.nodes.get(empty_to_root(path))
    }

    /// Look up a node mutably by its cgroup path.
    pub fn get_mut(&mut self, path: &str) -> Option<&mut CGroupNode> {
        self.nodes.get_mut(empty_to_root(path))
    }

    /// Return an iterator over child paths of the given node.
    pub fn children_of(&self, path: &str) -> &[String] {
        self.children
            .get(empty_to_root(path))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Return the number of registered nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Return true if the forest has no nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

// ── Path utilities ─────────────────────────────────────────────────────────

/// Convert an empty string to "/" (root cgroup), otherwise return the path unchanged.
pub fn empty_to_root(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}

/// Compute the number of decimal digits needed to display `value`.
pub fn decimal_str_width(value: u32) -> usize {
    if value == 0 {
        1
    } else {
        let mut w = 0;
        let mut v = value;
        while v > 0 {
            v /= 10;
            w += 1;
        }
        w
    }
}

/// Simple ellipsize: truncate `text` to at most `max_len` characters,
/// appending "…" when truncation occurs.
pub fn ellipsize(text: &str, max_len: usize) -> String {
    if text.chars().count() <= max_len {
        text.to_owned()
    } else {
        let ellipsis = "…";
        let keep_chars = max_len.saturating_sub(1);
        let end_byte = text
            .char_indices()
            .nth(keep_chars)
            .map(|(i, _)| i)
            .unwrap_or(text.len());
        format!("{}{}", &text[..end_byte], ellipsis)
    }
}

// ── Process entry (parsed from D-Bus reply) ────────────────────────────────

/// A single process entry returned by `GetUnitProcesses`.
///
/// Corresponds to the `(sus)` struct in the D-Bus reply: a cgroup path,
/// a PID, and the process command-line string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitProcess {
    /// Cgroup path the process belongs to.
    pub cgroup_path: String,
    /// Process ID.
    pub pid: u32,
    /// Process command-line / name.
    pub name: String,
}

impl PartialOrd for UnitProcess {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.pid.cmp(&other.pid))
    }
}

impl Ord for UnitProcess {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pid.cmp(&other.pid)
    }
}

// ── Output formatting ──────────────────────────────────────────────────────

/// Options controlling how the process tree is rendered.
#[derive(Debug, Clone, Copy)]
pub struct ShowProcessesOptions {
    /// Number of terminal columns available (0 = unlimited).
    pub n_columns: u32,
    /// Output flags (full-width, hide-extra, etc.).
    pub flags: ShowProcessesFlags,
    /// Glyph set for tree drawing.
    pub glyphs: &'static Glyphs,
}

impl Default for ShowProcessesOptions {
    fn default() -> Self {
        Self {
            n_columns: 0,
            flags: ShowProcessesFlags::empty(),
            glyphs: &GLYPHS_UNICODE,
        }
    }
}

bitflags::bitflags! {
    /// Flags that modify process tree output.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ShowProcessesFlags: u32 {
        /// Ignore column width limit (print everything).
        const FULL_WIDTH  = 1 << 0;
        /// Do not show extra processes (those in non-displayed cgroups).
        const HIDE_EXTRA  = 1 << 1;
    }
}

/// Render the process tree into a string.
///
/// This is the pure-Rust equivalent of `unit_show_processes()` —
/// it builds a [`CGroupForest`] from the provided process list, renders
/// the tree starting at `cgroup_path`, and optionally appends extra
/// processes.
///
/// # Arguments
///
/// * `processes` – Process entries (cgroup_path, pid, name).
/// * `cgroup_path` – Root cgroup path to start rendering from.
/// * `prefix` – Text prepended to every output line.
/// * `opts` – Formatting and display options.
///
/// # Returns
///
/// The rendered output as a `String`, or an error.
pub fn show_unit_processes(
    processes: &[UnitProcess],
    cgroup_path: &str,
    prefix: &str,
    opts: &ShowProcessesOptions,
) -> Result<String, BusUnitProcsError> {
    let mut forest = CGroupForest::new();
    for proc_entry in processes {
        if let Err(e) =
            forest.add_process(&proc_entry.cgroup_path, proc_entry.pid, &proc_entry.name)
        {
            // Log-style: skip invalid entries rather than failing outright.
            continue;
        }
    }

    let mut output = String::new();
    let effective_columns = effective_columns(opts.n_columns, opts.flags);

    dump_processes(
        &mut forest,
        cgroup_path,
        prefix,
        effective_columns,
        opts,
        &mut output,
    )?;

    if !opts.flags.contains(ShowProcessesFlags::HIDE_EXTRA) {
        dump_extra_processes(&forest, prefix, effective_columns, opts, &mut output)?;
    }

    Ok(output)
}

/// Determine effective column width: 0 means unlimited.
fn effective_columns(n_columns: u32, flags: ShowProcessesFlags) -> u32 {
    if flags.contains(ShowProcessesFlags::FULL_WIDTH) {
        0
    } else {
        n_columns
    }
}

// ── Tree rendering internals ───────────────────────────────────────────────

fn dump_processes(
    forest: &mut CGroupForest,
    cgroup_path: &str,
    prefix: &str,
    n_columns: u32,
    opts: &ShowProcessesOptions,
    out: &mut String,
) -> Result<(), BusUnitProcsError> {
    let cgroup_path = empty_to_root(cgroup_path);

    let child_paths_owned: Vec<String> = forest
        .children_of(cgroup_path)
        .iter()
        .map(|s| s.to_owned())
        .collect();

    let has_children = !child_paths_owned.is_empty();

    let pids_data: Vec<(u32, String)> = match forest.get_mut(cgroup_path) {
        Some(node) => {
            let mut sorted_pids: Vec<u32> = node.pids.keys().copied().collect();
            sorted_pids.sort();
            sorted_pids
                .iter()
                .filter_map(|&pid| node.pids.get(&pid).map(|name| (pid, name.clone())))
                .collect()
        }
        None => Vec::new(),
    };

    if !pids_data.is_empty() {
        let max_pid = pids_data.iter().map(|(pid, _)| *pid).max().unwrap();
        let width = decimal_str_width(max_pid);

        for (i, (pid, name)) in pids_data.iter().enumerate() {
            let display_name = if n_columns != 0 {
                let max_name_len = (n_columns as usize).saturating_sub(2 + width + 1).max(20);
                ellipsize(name, max_name_len)
            } else {
                name.clone()
            };

            let has_more = i + 1 < pids_data.len() || has_children;
            let special = if has_more {
                opts.glyphs.tree_branch
            } else {
                opts.glyphs.tree_right
            };

            writeln!(out, "{prefix}{special}{width}{pid} {display_name}")
                .map_err(|e| BusUnitProcsError::Io(io::Error::new(io::ErrorKind::Other, e)))?;
        }
    }

    let mut child_paths: Vec<&str> = child_paths_owned.iter().map(|s| s.as_str()).collect();
    child_paths.sort();

    let child_columns = if n_columns != 0 {
        n_columns.saturating_sub(2).max(20)
    } else {
        0
    };

    for (i, &child_path) in child_paths.iter().enumerate() {
        let leaf_name = child_path
            .rfind('/')
            .and_then(|pos| child_path.get(pos + 1..))
            .ok_or_else(|| BusUnitProcsError::InvalidPath(child_path.to_owned()))?;

        let has_more = i + 1 < child_paths.len();
        let special = if has_more {
            opts.glyphs.tree_branch
        } else {
            opts.glyphs.tree_right
        };

        writeln!(out, "{prefix}{special}{leaf_name}")
            .map_err(|e| BusUnitProcsError::Io(io::Error::new(io::ErrorKind::Other, e)))?;

        let cont = if has_more {
            opts.glyphs.tree_vertical
        } else {
            opts.glyphs.tree_space
        };
        let child_prefix = format!("{prefix}{cont}");

        dump_processes(forest, child_path, &child_prefix, child_columns, opts, out)?;
    }

    if let Some(n) = forest.get_mut(cgroup_path) {
        n.done = true;
    }

    Ok(())
}

fn dump_extra_processes(
    forest: &CGroupForest,
    prefix: &str,
    n_columns: u32,
    opts: &ShowProcessesOptions,
    out: &mut String,
) -> Result<(), BusUnitProcsError> {
    // Collect all PIDs from non-done cgroups
    let mut extra: Vec<(u32, String)> = Vec::new();

    for node in forest.nodes.values() {
        if node.done || node.pids.is_empty() {
            continue;
        }
        for (&pid, name) in &node.pids {
            extra.push((pid, name.clone()));
        }
    }

    if extra.is_empty() {
        return Ok(());
    }

    extra.sort_by_key(|(pid, _)| *pid);
    let width = decimal_str_width(extra.last().unwrap().0);

    for (pid, name) in &extra {
        let display_name = if n_columns != 0 {
            let max_name_len = (n_columns as usize).saturating_sub(2 + width + 1).max(20);
            ellipsize(name, max_name_len)
        } else {
            name.clone()
        };

        writeln!(
            out,
            "{prefix}{} {width}{pid} {display_name}",
            opts.glyphs.triangular_bullet
        )
        .map_err(|e| BusUnitProcsError::Io(io::Error::new(io::ErrorKind::Other, e)))?;
    }

    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- Utility tests --

    #[test]
    fn test_empty_to_root() {
        assert_eq!(empty_to_root(""), "/");
        assert_eq!(empty_to_root("/"), "/");
        assert_eq!(empty_to_root("/user.slice"), "/user.slice");
    }

    #[test]
    fn test_decimal_str_width() {
        assert_eq!(decimal_str_width(0), 1);
        assert_eq!(decimal_str_width(1), 1);
        assert_eq!(decimal_str_width(9), 1);
        assert_eq!(decimal_str_width(10), 2);
        assert_eq!(decimal_str_width(99), 2);
        assert_eq!(decimal_str_width(100), 3);
        assert_eq!(decimal_str_width(9999), 4);
    }

    #[test]
    fn test_ellipsize_no_truncate() {
        assert_eq!(ellipsize("hello", 10), "hello");
        assert_eq!(ellipsize("hello", 5), "hello");
    }

    #[test]
    fn test_ellipsize_truncate() {
        let result = ellipsize("abcdefghij", 5);
        assert_eq!(result.chars().count(), 5);
        assert!(result.ends_with('…'));
        assert!(result.starts_with("abcd"));
    }

    #[test]
    fn test_ellipsize_empty() {
        assert_eq!(ellipsize("", 5), "");
    }

    #[test]
    fn test_ellipsize_short() {
        assert_eq!(ellipsize("ab", 5), "ab");
    }

    // -- CGroupForest tests --

    #[test]
    fn test_forest_new() {
        let forest = CGroupForest::new();
        assert!(forest.is_empty());
        assert_eq!(forest.len(), 0);
    }

    #[test]
    fn test_forest_add_cgroup_root() {
        let mut forest = CGroupForest::new();
        let path = forest.add_cgroup("/").unwrap();
        assert_eq!(path, "/");
        assert_eq!(forest.len(), 1);
        assert!(forest.get("/").is_some());
    }

    #[test]
    fn test_forest_add_cgroup_nested() {
        let mut forest = CGroupForest::new();
        forest.add_cgroup("/user.slice").unwrap();
        forest.add_cgroup("/user.slice/user-1000.slice").unwrap();

        assert_eq!(forest.len(), 3); // root + user.slice + user-1000.slice
        assert!(forest.get("/").is_some());
        assert!(forest.get("/user.slice").is_some());
        assert!(forest.get("/user.slice/user-1000.slice").is_some());
        assert_eq!(forest.children_of("/user.slice").len(), 1);
    }

    #[test]
    fn test_forest_add_cgroup_idempotent() {
        let mut forest = CGroupForest::new();
        let p1 = forest.add_cgroup("/a.slice").unwrap();
        let p2 = forest.add_cgroup("/a.slice").unwrap();
        assert_eq!(p1, p2);
        assert_eq!(forest.len(), 2); // "/" + "/a.slice"
    }

    #[test]
    fn test_forest_add_cgroup_empty_path() {
        let mut forest = CGroupForest::new();
        let path = forest.add_cgroup("").unwrap();
        assert_eq!(path, "/");
    }

    #[test]
    fn test_forest_add_process() {
        let mut forest = CGroupForest::new();
        forest
            .add_process("/user.slice", 1234, "/usr/bin/bash")
            .unwrap();
        forest
            .add_process("/user.slice", 5678, "/usr/bin/sleep")
            .unwrap();

        let node = forest.get("/user.slice").unwrap();
        assert_eq!(node.pids.len(), 2);
        assert_eq!(node.pids.get(&1234).unwrap(), "/usr/bin/bash");
        assert_eq!(node.pids.get(&5678).unwrap(), "/usr/bin/sleep");
    }

    #[test]
    fn test_forest_add_process_zero_pid_rejected() {
        let mut forest = CGroupForest::new();
        let result = forest.add_process("/a", 0, "cmd");
        assert!(result.is_err());
    }

    #[test]
    fn test_forest_add_process_creates_cgroup() {
        let mut forest = CGroupForest::new();
        forest
            .add_process("/new.slice/scope", 42, "process")
            .unwrap();
        assert!(forest.get("/new.slice/scope").is_some());
        assert!(forest.get("/new.slice").is_some());
        assert!(forest.get("/").is_some());
    }

    #[test]
    fn test_forest_children_ordering() {
        let mut forest = CGroupForest::new();
        forest.add_cgroup("/b.slice").unwrap();
        forest.add_cgroup("/a.slice").unwrap();
        forest.add_cgroup("/c.slice").unwrap();

        // children_of returns insertion order; sorting is done at render time
        let children = forest.children_of("/");
        assert_eq!(children.len(), 3);
    }

    // -- UnitProcess tests --

    #[test]
    fn test_unit_process_ord() {
        let a = UnitProcess {
            cgroup_path: "/a".into(),
            pid: 1,
            name: "init".into(),
        };
        let b = UnitProcess {
            cgroup_path: "/a".into(),
            pid: 100,
            name: "big".into(),
        };
        assert!(a < b);
        assert_eq!(a.cmp(&a), Ordering::Equal);
    }

    // -- Show processes integration tests --

    fn default_opts() -> ShowProcessesOptions {
        ShowProcessesOptions::default()
    }

    fn full_width_opts() -> ShowProcessesOptions {
        ShowProcessesOptions {
            n_columns: 0,
            flags: ShowProcessesFlags::FULL_WIDTH,
            glyphs: &GLYPHS_ASCII,
        }
    }

    #[test]
    fn test_show_unit_processes_empty() {
        let result = show_unit_processes(&[], "/", "", &default_opts()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_show_unit_processes_single_pid() {
        let procs = vec![UnitProcess {
            cgroup_path: "/app.scope".into(),
            pid: 100,
            name: "/usr/bin/app".into(),
        }];
        let result = show_unit_processes(&procs, "/app.scope", "", &full_width_opts()).unwrap();
        assert!(result.contains("100"));
        assert!(result.contains("/usr/bin/app"));
    }

    #[test]
    fn test_show_unit_processes_sorted_pids() {
        let procs = vec![
            UnitProcess {
                cgroup_path: "/s.scope".into(),
                pid: 500,
                name: "third".into(),
            },
            UnitProcess {
                cgroup_path: "/s.scope".into(),
                pid: 100,
                name: "first".into(),
            },
            UnitProcess {
                cgroup_path: "/s.scope".into(),
                pid: 300,
                name: "second".into(),
            },
        ];
        let result = show_unit_processes(&procs, "/s.scope", "", &full_width_opts()).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3);
        // PIDs should appear in sorted order
        assert!(lines[0].contains("100"));
        assert!(lines[1].contains("300"));
        assert!(lines[2].contains("500"));
    }

    #[test]
    fn test_show_unit_processes_with_prefix() {
        let procs = vec![UnitProcess {
            cgroup_path: "/x.scope".into(),
            pid: 42,
            name: "cmd".into(),
        }];
        let opts = ShowProcessesOptions {
            n_columns: 0,
            flags: ShowProcessesFlags::FULL_WIDTH,
            glyphs: &GLYPHS_ASCII,
        };
        let result = show_unit_processes(&procs, "/x.scope", "  ", &opts).unwrap();
        assert!(result.starts_with("  "));
    }

    #[test]
    fn test_show_unit_processes_nested_cgroups() {
        let procs = vec![
            UnitProcess {
                cgroup_path: "/parent.scope".into(),
                pid: 10,
                name: "parent-proc".into(),
            },
            UnitProcess {
                cgroup_path: "/parent.scope/child.scope".into(),
                pid: 20,
                name: "child-proc".into(),
            },
        ];
        let opts = ShowProcessesOptions {
            n_columns: 0,
            flags: ShowProcessesFlags::FULL_WIDTH,
            glyphs: &GLYPHS_ASCII,
        };
        let result = show_unit_processes(&procs, "/parent.scope", "", &opts).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        // Should have at least 2 lines: parent PID + child cgroup heading + child PID
        assert!(lines.len() >= 3);
        assert!(result.contains("parent-proc"));
        assert!(result.contains("child-proc"));
        assert!(result.contains("child.scope"));
    }

    #[test]
    fn test_show_unit_processes_extra_processes() {
        let procs = vec![
            UnitProcess {
                cgroup_path: "/main.scope".into(),
                pid: 1,
                name: "main".into(),
            },
            UnitProcess {
                cgroup_path: "/other.scope".into(),
                pid: 99,
                name: "extra".into(),
            },
        ];
        let opts = ShowProcessesOptions {
            n_columns: 0,
            flags: ShowProcessesFlags::FULL_WIDTH,
            glyphs: &GLYPHS_ASCII,
        };
        // Display main.scope — other.scope processes should appear as extras
        let result = show_unit_processes(&procs, "/main.scope", "", &opts).unwrap();
        assert!(result.contains("main"));
        assert!(result.contains("extra"));
        assert!(result.contains("*")); // ASCII triangular bullet
    }

    #[test]
    fn test_show_unit_processes_hide_extra() {
        let procs = vec![
            UnitProcess {
                cgroup_path: "/main.scope".into(),
                pid: 1,
                name: "main".into(),
            },
            UnitProcess {
                cgroup_path: "/other.scope".into(),
                pid: 99,
                name: "extra".into(),
            },
        ];
        let opts = ShowProcessesOptions {
            n_columns: 0,
            flags: ShowProcessesFlags::HIDE_EXTRA,
            glyphs: &GLYPHS_ASCII,
        };
        let result = show_unit_processes(&procs, "/main.scope", "", &opts).unwrap();
        assert!(result.contains("main"));
        assert!(!result.contains("extra"));
    }

    #[test]
    fn test_show_unit_processes_unknown_cgroup() {
        let result = show_unit_processes(&[], "/nonexistent.scope", "", &default_opts()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_show_unit_processes_column_truncation() {
        let procs = vec![UnitProcess {
            cgroup_path: "/s.scope".into(),
            pid: 1,
            name: "/usr/lib/systemd/systemd --user --listen-timestamp=1234567890".into(),
        }];
        let opts = ShowProcessesOptions {
            n_columns: 40,
            flags: ShowProcessesFlags::empty(),
            glyphs: &GLYPHS_ASCII,
        };
        let result = show_unit_processes(&procs, "/s.scope", "", &opts).unwrap();
        // The name should be truncated with ellipsis
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 1);
        // The line should not be excessively long
        assert!(lines[0].len() <= 60);
    }

    #[test]
    fn test_show_unit_processes_invalid_pid_skipped() {
        let procs = vec![
            UnitProcess {
                cgroup_path: "/s.scope".into(),
                pid: 0,
                name: "invalid".into(),
            },
            UnitProcess {
                cgroup_path: "/s.scope".into(),
                pid: 1,
                name: "valid".into(),
            },
        ];
        let result = show_unit_processes(&procs, "/s.scope", "", &full_width_opts()).unwrap();
        assert!(result.contains("valid"));
        assert!(!result.contains("invalid"));
    }

    // -- Glyph tests --

    #[test]
    fn test_glyphs_unicode_fields() {
        assert!(!GLYPHS_UNICODE.tree_branch.is_empty());
        assert!(!GLYPHS_UNICODE.tree_right.is_empty());
        assert!(!GLYPHS_UNICODE.tree_vertical.is_empty());
        assert!(!GLYPHS_UNICODE.tree_space.is_empty());
        assert!(!GLYPHS_UNICODE.triangular_bullet.is_empty());
    }

    #[test]
    fn test_glyphs_ascii_fields() {
        assert!(!GLYPHS_ASCII.tree_branch.is_empty());
        assert!(!GLYPHS_ASCII.tree_right.is_empty());
        assert!(!GLYPHS_ASCII.tree_vertical.is_empty());
        assert!(!GLYPHS_ASCII.tree_space.is_empty());
        assert!(!GLYPHS_ASCII.triangular_bullet.is_empty());
    }

    // -- Error tests --

    #[test]
    fn test_error_display() {
        let e = BusUnitProcsError::InvalidPath("bad".into());
        assert_eq!(format!("{e}"), "invalid cgroup path: bad");

        let e = BusUnitProcsError::NotFound("missing".into());
        assert_eq!(format!("{e}"), "not found: missing");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe broke");
        let err = BusUnitProcsError::from(io_err);
        assert!(matches!(err, BusUnitProcsError::Io(_)));
    }

    // -- ShowProcessesFlags tests --

    #[test]
    fn test_flags_default_empty() {
        let flags = ShowProcessesFlags::empty();
        assert!(!flags.contains(ShowProcessesFlags::FULL_WIDTH));
        assert!(!flags.contains(ShowProcessesFlags::HIDE_EXTRA));
    }

    #[test]
    fn test_flags_combined() {
        let flags = ShowProcessesFlags::FULL_WIDTH | ShowProcessesFlags::HIDE_EXTRA;
        assert!(flags.contains(ShowProcessesFlags::FULL_WIDTH));
        assert!(flags.contains(ShowProcessesFlags::HIDE_EXTRA));
    }

    #[test]
    fn test_effective_columns_full_width() {
        assert_eq!(effective_columns(80, ShowProcessesFlags::FULL_WIDTH), 0);
    }

    #[test]
    fn test_effective_columns_normal() {
        assert_eq!(effective_columns(80, ShowProcessesFlags::empty()), 80);
    }

    #[test]
    fn test_effective_columns_zero() {
        assert_eq!(effective_columns(0, ShowProcessesFlags::empty()), 0);
    }
}
