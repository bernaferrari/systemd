// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/hwdb-util.c, src/shared/hwdb-util.h,
//            src/libsystemd/sd-hwdb/hwdb-internal.h
//
// Hardware Database (hwdb) utilities for udev.
//
// Generic udev properties, key-value database based on modalias strings.
// Uses a Patricia/radix trie to index all matches for efficient lookup.
// Supports building hwdb.bin from .hwdb source files, writing the
// on-disk binary format, reading it back, and querying properties by
// modalias string.
//
// All operations are pure Rust. No FFI blocks or no_mangle attributes remain.

use crate::ffi::*;
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::io::{self, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// ── Constants ─────────────────────────────────────────────────────────────

/// Magic signature for hwdb binary files: "KSPLPHHR".
const HWDB_SIGNATURE: [u8; 8] = *b"KSLPHHRH";

/// On-disk header size: 8 (sig) + 9×8 (le64 fields) = 80 bytes.
const HWDB_HEADER_SIZE: u64 = 80;

/// On-disk trie node size: 8+1+7+8 = 24 bytes.
const HWDB_NODE_SIZE: u64 = 24;

/// On-disk child entry size: 1+7+8 = 16 bytes.
const HWDB_CHILD_ENTRY_SIZE: u64 = 16;

/// On-disk value entry v1 size: 8+8 = 16 bytes.
const HWDB_VALUE_ENTRY_SIZE_V1: u64 = 16;

/// On-disk value entry v2 size: 8+8+8+4+2+2 = 32 bytes.
const HWDB_VALUE_ENTRY_SIZE_V2: u64 = 32;

/// Search paths for the hwdb binary database.
pub const HWDB_BIN_PATHS: &[&str] = &[
    "/etc/systemd/hwdb/hwdb.bin",
    "/etc/udev/hwdb.bin",
    "/usr/lib/systemd/hwdb/hwdb.bin",
];

/// Default hwdb source configuration directories.
pub const HWDB_CONF_DIRS: &[&str] = &["/etc/udev/hwdb.d"];

/// Environment variable that, when set, bypasses hwdb update.
const HWDB_BYPASS_ENV: &str = "SYSTEMD_HWDB_UPDATE";

// ── Errors ────────────────────────────────────────────────────────────────

/// Unified error type for hwdb operations.
#[derive(Debug)]
pub enum HwdbError {
    /// A POSIX errno occurred during a syscall.
    Errno(i32),
    /// The hwdb binary has an invalid format.
    InvalidFormat(String),
    /// An I/O error occurred.
    Io(io::Error),
    /// A parse error in a .hwdb source file.
    Parse {
        message: String,
        file: Option<String>,
        line: u32,
    },
    /// Requested resource not found.
    NotFound,
}

impl fmt::Display for HwdbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HwdbError::Errno(e) => write!(f, "errno {e}"),
            HwdbError::InvalidFormat(s) => write!(f, "invalid hwdb format: {s}"),
            HwdbError::Io(e) => write!(f, "I/O error: {e}"),
            HwdbError::Parse {
                message,
                file,
                line,
            } => {
                if let Some(file) = file {
                    write!(f, "{file}:{line}: {message}")
                } else {
                    write!(f, "parse error: {message}")
                }
            }
            HwdbError::NotFound => write!(f, "not found"),
        }
    }
}

impl std::error::Error for HwdbError {}

impl HwdbError {
    /// Create from a raw negative errno (systemd convention).
    pub fn from_neg_errno(errno: i32) -> Self {
        HwdbError::Errno(-errno)
    }

    /// Create from `std::io::Error`.
    pub fn from_io(err: io::Error) -> Self {
        HwdbError::Io(err)
    }
}

/// Convenient `Result` alias used throughout this module.
pub type HwdbResult<T> = Result<T, HwdbError>;

// ── In-memory trie structures ─────────────────────────────────────────────

/// A key-value entry stored in a trie node, with source metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieValueEntry {
    /// Property key (e.g. `ID_MODEL_FROM_DATABASE`).
    pub key: String,
    /// Property value.
    pub value: String,
    /// Source .hwdb filename (empty in compat mode).
    pub filename: String,
    /// Line number in the source file.
    pub line_number: u32,
    /// File priority (lower value = higher priority).
    pub file_priority: u16,
}

/// A node in the Patricia/radix trie.
#[derive(Debug, Clone)]
pub struct TrieNode {
    /// Prefix shared by all entries below this node.
    pub prefix: String,
    /// Child nodes, kept sorted by the leading byte for binary search.
    pub children: Vec<(u8, Box<TrieNode>)>,
    /// Key-value entries stored at this node, sorted by key.
    pub values: Vec<TrieValueEntry>,
}

impl TrieNode {
    /// Create a new empty trie node.
    fn new() -> Self {
        TrieNode {
            prefix: String::new(),
            children: Vec::new(),
            values: Vec::new(),
        }
    }

    /// Create a trie node with the given prefix.
    fn with_prefix(prefix: String) -> Self {
        TrieNode {
            prefix,
            children: Vec::new(),
            values: Vec::new(),
        }
    }

    /// Look up a child node by leading character (binary search).
    fn lookup_child(&self, c: u8) -> Option<&TrieNode> {
        self.children
            .binary_search_by_key(&c, |entry| entry.0)
            .ok()
            .map(|idx| self.children[idx].1.as_ref())
    }

    /// Add a child, maintaining sort order by character.
    fn add_child(&mut self, c: u8, child: Box<TrieNode>) {
        let idx = self
            .children
            .binary_search_by_key(&c, |entry| entry.0)
            .unwrap_err();
        self.children.insert(idx, (c, child));
    }

    /// Add or update a value entry.  Existing entries with the same key are
    /// replaced (later files override earlier ones).
    fn add_or_update_value(&mut self, entry: TrieValueEntry) -> bool {
        if let Some(existing) = self.values.iter_mut().find(|v| v.key == entry.key) {
            *existing = entry;
            false // updated, not new
        } else {
            self.values.push(entry);
            self.values.sort_by(|a, b| a.key.cmp(&b.key));
            true // newly inserted
        }
    }
}

/// The Patricia/radix trie used for indexing modalias strings.
#[derive(Debug)]
pub struct Trie {
    /// Root node.
    root: Box<TrieNode>,
    /// Total number of nodes.
    pub nodes_count: usize,
    /// Total number of child entries across all nodes.
    pub children_count: usize,
    /// Total number of value entries across all nodes.
    pub values_count: usize,
}

impl Trie {
    /// Create a new empty trie.
    pub fn new() -> Self {
        Trie {
            root: Box::new(TrieNode::new()),
            nodes_count: 1,
            children_count: 0,
            values_count: 0,
        }
    }

    // ── Insertion ─────────────────────────────────────────────────────────

    /// Insert a new entry into the trie.
    ///
    /// * `search` — the modalias pattern (e.g. `"usb:v046DpC312d*"`)
    /// * `key` / `value` — the property pair
    /// * `filename`, `file_priority`, `line_number` — source provenance
    /// * `compat` — when true, `filename` is not stored
    pub fn insert(
        &mut self,
        search: &str,
        key: &str,
        value: &str,
        filename: &str,
        file_priority: u16,
        line_number: u32,
        compat: bool,
    ) {
        let entry = TrieValueEntry {
            key: key.to_string(),
            value: value.to_string(),
            filename: if compat {
                String::new()
            } else {
                filename.to_string()
            },
            line_number,
            file_priority,
        };
        self.insert_into_root(search.as_bytes(), entry);
    }

    fn insert_into_root(&mut self, search: &[u8], entry: TrieValueEntry) {
        let mut counts = (self.nodes_count, self.children_count, self.values_count);
        fn insert_recursive(
            node: &mut TrieNode,
            search: &[u8],
            mut i: usize,
            entry: TrieValueEntry,
            counts: &mut (usize, usize, usize),
        ) {
            let prefix_bytes = node.prefix.as_bytes();
            let mut p = 0usize;

            // Walk the current node's prefix, matching against the search string.
            while p < prefix_bytes.len() {
                // Search string exhausted while prefix still has characters.
                if i + p >= search.len() {
                    let split_char = prefix_bytes[p];
                    let mut new_child = TrieNode::with_prefix(node.prefix[p + 1..].to_string());
                    new_child.children = std::mem::take(&mut node.children);
                    new_child.values = std::mem::take(&mut node.values);

                    node.prefix = node.prefix[..p].to_string();
                    node.add_child(split_char, Box::new(new_child));
                    counts.0 += 1;
                    counts.1 += 1;

                    let is_new = node.add_or_update_value(entry);
                    if is_new {
                        counts.2 += 1;
                    }
                    return;
                }

                // Character mismatch — split the node.
                if prefix_bytes[p] != search[i + p] {
                    let split_char = prefix_bytes[p];
                    let mut remainder_child =
                        TrieNode::with_prefix(node.prefix[p + 1..].to_string());
                    remainder_child.children = std::mem::take(&mut node.children);
                    remainder_child.values = std::mem::take(&mut node.values);

                    node.prefix = node.prefix[..p].to_string();
                    node.add_child(split_char, Box::new(remainder_child));
                    counts.0 += 1;
                    counts.1 += 1;

                    // New branch for the diverging search string.
                    let remaining = String::from_utf8_lossy(&search[i + p + 1..]).to_string();
                    let mut search_child = TrieNode::with_prefix(remaining);
                    search_child.values.push(entry.clone());
                    search_child.values.sort_by(|a, b| a.key.cmp(&b.key));
                    counts.2 += 1;
                    node.add_child(search[i + p], Box::new(search_child));
                    counts.0 += 1;
                    counts.1 += 1;
                    return;
                }

                p += 1;
            }

            // Entire prefix matched.
            i += p;

            // Search string exhausted — store value at this node.
            if i >= search.len() {
                let is_new = node.add_or_update_value(entry);
                if is_new {
                    counts.2 += 1;
                }
                return;
            }

            // Look for an existing child that matches the next search character.
            let next_char = search[i];
            match node.children.binary_search_by_key(&next_char, |e| e.0) {
                Ok(child_idx) => {
                    insert_recursive(
                        &mut node.children[child_idx].1,
                        search,
                        i + 1,
                        entry,
                        counts,
                    );
                }
                Err(child_idx) => {
                    // No existing child — create a new leaf.
                    let remaining = String::from_utf8_lossy(&search[i + 1..]).to_string();
                    let mut new_child = TrieNode::with_prefix(remaining);
                    new_child.values.push(entry.clone());
                    new_child.values.sort_by(|a, b| a.key.cmp(&b.key));
                    counts.2 += 1;
                    node.children
                        .insert(child_idx, (next_char, Box::new(new_child)));
                    counts.0 += 1;
                    counts.1 += 1;
                }
            }
        }
        insert_recursive(&mut self.root, search, 0, entry, &mut counts);
        self.nodes_count = counts.0;
        self.children_count = counts.1;
        self.values_count = counts.2;
    }

    // ── Query ─────────────────────────────────────────────────────────────

    /// Walk the trie matching `modalias` and collect all key-value pairs
    /// from every node visited along the matching prefix path.
    pub fn query(&self, modalias: &str) -> Vec<(String, String)> {
        let mut results = Vec::new();
        let search = modalias.as_bytes();
        let mut node = &*self.root;
        let mut pos = 0usize;

        loop {
            let prefix_bytes = node.prefix.as_bytes();
            let mut p = 0usize;

            while p < prefix_bytes.len() && pos + p < search.len() {
                if prefix_bytes[p] == b'*' {
                    for v in &node.values {
                        results.push((v.key.clone(), v.value.clone()));
                    }
                    return results;
                }
                if prefix_bytes[p] != search[pos + p] {
                    return results;
                }
                p += 1;
            }

            // Collect values from this node (all visited nodes contribute).
            for v in &node.values {
                results.push((v.key.clone(), v.value.clone()));
            }

            pos += p;

            if p < prefix_bytes.len() {
                if prefix_bytes[p] == b'*' {
                    return results;
                }
                break;
            }

            if pos >= search.len() {
                break;
            }

            let next_char = search[pos];
            match node.lookup_child(next_char) {
                Some(child) => {
                    node = child;
                    pos += 1;
                }
                None => {
                    // Check for wildcard child
                    if let Some(wc) = node.lookup_child(b'*') {
                        for v in &wc.values {
                            results.push((v.key.clone(), v.value.clone()));
                        }
                    }
                    break;
                }
            }
        }

        results
    }

    /// Return statistics about the trie.
    pub fn stats(&self) -> TrieStats {
        TrieStats {
            nodes_count: self.nodes_count,
            children_count: self.children_count,
            values_count: self.values_count,
        }
    }
}

impl Default for Trie {
    fn default() -> Self {
        Self::new()
    }
}

/// Trie statistics snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrieStats {
    pub nodes_count: usize,
    pub children_count: usize,
    pub values_count: usize,
}

// ── .hwdb file parser ─────────────────────────────────────────────────────

/// Parser state machine for reading .hwdb source files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    /// Outside a record.
    None,
    /// Accumulating match patterns (modalias lines).
    Match,
    /// Reading property data (indented `KEY=VALUE` lines).
    Data,
}

/// Parse a single .hwdb file and insert all entries into `trie`.
///
/// Returns a list of warnings for non-fatal issues encountered.
pub fn import_hwdb_file<R: io::BufRead>(
    reader: R,
    filename: &str,
    trie: &mut Trie,
    file_priority: u16,
    compat: bool,
) -> HwdbResult<Vec<String>> {
    let mut state = ParseState::None;
    let mut match_list: Vec<String> = Vec::new();
    let mut warnings = Vec::new();
    let mut line_number = 0u32;

    for line_result in reader.lines() {
        let raw_line = line_result.map_err(HwdbError::from_io)?;
        line_number += 1;

        // Trim trailing whitespace.
        let trimmed = raw_line.trim_end();

        // Empty line — terminates current record.
        if trimmed.is_empty() {
            match state {
                ParseState::Match => {
                    warnings.push(format!(
                        "{filename}:{line_number}: property expected, \
                         ignoring record with no properties"
                    ));
                }
                _ => {}
            }
            match_list.clear();
            state = ParseState::None;
            continue;
        }

        // Comment line.
        if trimmed.starts_with('#') {
            continue;
        }

        // Strip inline comment and re-trim.
        let mut content = trimmed.to_string();
        if let Some(pos) = content.find('#') {
            content.truncate(pos);
        }
        let content = content.trim_end();
        if content.is_empty() {
            continue;
        }

        match state {
            ParseState::None => {
                if content.starts_with(' ') {
                    warnings.push(format!(
                        "{filename}:{line_number}: match expected but got \
                         indented property, ignoring line"
                    ));
                    continue;
                }
                state = ParseState::Match;
                match_list.push(content.to_string());
            }
            ParseState::Match => {
                if !content.starts_with(' ') {
                    // Another match pattern.
                    match_list.push(content.to_string());
                    continue;
                }
                // First data line.
                state = ParseState::Data;
                if let Err(e) = insert_data_line(
                    trie,
                    &match_list,
                    content,
                    filename,
                    file_priority,
                    line_number,
                    compat,
                ) {
                    warnings.push(e.to_string());
                }
            }
            ParseState::Data => {
                if !content.starts_with(' ') {
                    warnings.push(format!(
                        "{filename}:{line_number}: property or empty line \
                         expected, got \"{content}\", ignoring record"
                    ));
                    match_list.clear();
                    state = ParseState::None;
                    continue;
                }
                if let Err(e) = insert_data_line(
                    trie,
                    &match_list,
                    content,
                    filename,
                    file_priority,
                    line_number,
                    compat,
                ) {
                    warnings.push(e.to_string());
                }
            }
        }
    }

    // File ended while still in match state.
    if state == ParseState::Match {
        warnings.push(format!(
            "{filename}:{line_number}: property expected, \
             ignoring record with no properties"
        ));
    }

    Ok(warnings)
}

/// Parse a single property line and insert it for every current match pattern.
fn insert_data_line(
    trie: &mut Trie,
    match_list: &[String],
    line: &str,
    filename: &str,
    file_priority: u16,
    line_number: u32,
    compat: bool,
) -> HwdbResult<()> {
    let eq_pos = line.find('=').ok_or_else(|| HwdbError::Parse {
        message: format!("key-value pair expected but got \"{}\"", line.trim()),
        file: Some(filename.to_string()),
        line: line_number,
    })?;

    let raw_key = &line[..eq_pos];
    let value = &line[eq_pos + 1..];

    // Collapse multiple leading spaces to a single space.
    let key = raw_key.trim_start();
    if key.is_empty() {
        return Err(HwdbError::Parse {
            message: format!("empty key in \"{}={value}\", ignoring", raw_key.trim()),
            file: Some(filename.to_string()),
            line: line_number,
        });
    }

    for pattern in match_list {
        trie.insert(
            pattern,
            key,
            value,
            filename,
            file_priority,
            line_number,
            compat,
        );
    }

    Ok(())
}

// ── Little-endian helpers ─────────────────────────────────────────────────

mod le {
    #[inline]
    pub fn read_u64(data: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
    }

    #[inline]
    pub fn read_u32(data: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
    }

    #[inline]
    pub fn read_u16(data: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
    }

    #[inline]
    pub fn write_u64(buf: &mut Vec<u8>, val: u64) {
        buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_u32(buf: &mut Vec<u8>, val: u32) {
        buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_u16(buf: &mut Vec<u8>, val: u16) {
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// Read a NUL-terminated C string from `data` at `offset`.
fn read_cstring(data: &[u8], offset: usize) -> &str {
    if offset >= data.len() {
        return "";
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(data.len());
    std::str::from_utf8(&data[offset..end]).unwrap_or("")
}

// ── Binary format: on-disk header ─────────────────────────────────────────

/// Parsed representation of the hwdb binary file header.
#[derive(Debug, Clone)]
pub struct HwdbHeader {
    pub tool_version: u64,
    pub file_size: u64,
    pub header_size: u64,
    pub node_size: u64,
    pub child_entry_size: u64,
    pub value_entry_size: u64,
    pub nodes_root_off: u64,
    pub nodes_len: u64,
    pub strings_len: u64,
}

/// Statistics from serialising the trie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreStats {
    pub nodes_count: u64,
    pub children_count: u64,
    pub values_count: u64,
    pub strings_len: usize,
    pub total_size: u64,
}

// ── Binary format writer ──────────────────────────────────────────────────

impl Trie {
    /// Collect every unique string that appears in the trie (prefixes, keys,
    /// values, filenames) into a deduplicated string table.
    fn build_string_table(&self) -> (Vec<u8>, HashMap<String, u64>) {
        let mut strings: Vec<String> = Vec::new();
        self.collect_strings(&self.root, &mut strings);
        strings.sort();
        strings.dedup();

        let mut table = Vec::new();
        let mut offsets = HashMap::new();

        // Offset 0 is reserved for the empty string (used by the root node).
        table.push(0u8);
        offsets.insert(String::new(), 0);

        for s in &strings {
            if s.is_empty() {
                continue;
            }
            offsets.insert(s.clone(), table.len() as u64);
            table.extend_from_slice(s.as_bytes());
            table.push(0);
        }

        (table, offsets)
    }

    fn collect_strings(&self, node: &TrieNode, out: &mut Vec<String>) {
        if !node.prefix.is_empty() {
            out.push(node.prefix.clone());
        }
        for v in &node.values {
            out.push(v.key.clone());
            out.push(v.value.clone());
            if !v.filename.is_empty() {
                out.push(v.filename.clone());
            }
        }
        for (_, child) in &node.children {
            self.collect_strings(child, out);
        }
    }

    /// Serialise the trie to the hwdb binary format.
    ///
    /// * `compat` — when true, value entries omit filename / line-number /
    ///   file-priority metadata (v1 format).
    pub fn store(&self, compat: bool) -> HwdbResult<(Vec<u8>, StoreStats)> {
        let (string_table, string_offsets) = self.build_string_table();
        let strings_off = HWDB_HEADER_SIZE;
        let nodes_off = HWDB_HEADER_SIZE + string_table.len() as u64;
        let value_entry_size = if compat {
            HWDB_VALUE_ENTRY_SIZE_V1
        } else {
            HWDB_VALUE_ENTRY_SIZE_V2
        };

        let mut nodes_buf: Vec<u8> = Vec::new();
        let mut stats = StoreStats {
            nodes_count: 0,
            children_count: 0,
            values_count: 0,
            strings_len: string_table.len(),
            total_size: 0,
        };

        let root_off = self.store_node_inner(
            &self.root,
            strings_off,
            nodes_off,
            &string_offsets,
            &mut nodes_buf,
            &mut stats,
            compat,
        );

        let total_size = HWDB_HEADER_SIZE + string_table.len() as u64 + nodes_buf.len() as u64;
        stats.total_size = total_size;

        let mut header = Vec::with_capacity(HWDB_HEADER_SIZE as usize);
        header.extend_from_slice(&HWDB_SIGNATURE);
        le::write_u64(&mut header, 0);
        le::write_u64(&mut header, total_size);
        le::write_u64(&mut header, HWDB_HEADER_SIZE);
        le::write_u64(&mut header, HWDB_NODE_SIZE);
        le::write_u64(&mut header, HWDB_CHILD_ENTRY_SIZE);
        le::write_u64(&mut header, value_entry_size);
        le::write_u64(&mut header, root_off);
        le::write_u64(&mut header, nodes_buf.len() as u64);
        le::write_u64(&mut header, string_table.len() as u64);

        let mut result = header;
        result.extend_from_slice(&string_table);
        result.extend_from_slice(&nodes_buf);
        Ok((result, stats))
    }

    fn store_node_inner(
        &self,
        node: &TrieNode,
        strings_off: u64,
        nodes_off: u64,
        string_offsets: &HashMap<String, u64>,
        buf: &mut Vec<u8>,
        stats: &mut StoreStats,
        compat: bool,
    ) -> u64 {
        let mut child_entries: Vec<(u8, u64)> = Vec::with_capacity(node.children.len());
        for &(c, ref child) in &node.children {
            let child_off = self.store_node_inner(
                child,
                strings_off,
                nodes_off,
                string_offsets,
                buf,
                stats,
                compat,
            );
            child_entries.push((c, child_off));
        }

        let node_off = nodes_off + buf.len() as u64;
        stats.nodes_count += 1;

        let prefix_off = strings_off + string_offsets.get(&node.prefix).copied().unwrap_or(0);

        le::write_u64(buf, prefix_off);
        buf.push(node.children.len() as u8);
        buf.extend_from_slice(&[0u8; 7]);
        le::write_u64(buf, node.values.len() as u64);

        for (c, child_off) in &child_entries {
            buf.push(*c);
            buf.extend_from_slice(&[0u8; 7]);
            le::write_u64(buf, *child_off);
            stats.children_count += 1;
        }

        for entry in &node.values {
            let key_off = strings_off + string_offsets.get(&entry.key).copied().unwrap_or(0);
            let val_off = strings_off + string_offsets.get(&entry.value).copied().unwrap_or(0);

            if compat {
                le::write_u64(buf, key_off);
                le::write_u64(buf, val_off);
            } else {
                let fn_off = if entry.filename.is_empty() {
                    strings_off
                } else {
                    strings_off + string_offsets.get(&entry.filename).copied().unwrap_or(0)
                };
                le::write_u64(buf, key_off);
                le::write_u64(buf, val_off);
                le::write_u64(buf, fn_off);
                le::write_u32(buf, entry.line_number);
                le::write_u16(buf, entry.file_priority);
                le::write_u16(buf, 0);
            }
            stats.values_count += 1;
        }

        node_off
    }
}

// ── Hwdb: runtime query context ──────────────────────────────────────────

/// A handle to an open hwdb binary database.
///
/// Holds the memory-mapped file contents and parsed header.  Use
/// [`Hwdb::new_from_path`] or [`Hwdb::new_default`] to open a database,
/// then [`Hwdb::query`] to look up properties.
pub struct Hwdb {
    /// Raw file contents.
    data: Vec<u8>,
    /// Parsed header.
    header: HwdbHeader,
    /// Path the file was loaded from (for reload detection).
    path: Option<PathBuf>,
    /// Modification time at load time.
    modified: Option<SystemTime>,
}

impl Hwdb {
    /// Open the hwdb database from the default search paths.
    pub fn new_default() -> HwdbResult<Self> {
        for path in HWDB_BIN_PATHS {
            match Self::new_from_path(Path::new(path)) {
                Ok(hwdb) => return Ok(hwdb),
                Err(HwdbError::Io(_) | HwdbError::NotFound) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(HwdbError::NotFound)
    }

    /// Open the hwdb database from a specific file path.
    pub fn new_from_path(path: &Path) -> HwdbResult<Self> {
        let metadata = fs::metadata(path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                HwdbError::NotFound
            } else {
                HwdbError::from_io(e)
            }
        })?;
        let modified = metadata.modified().ok();

        let data = fs::read(path).map_err(HwdbError::from_io)?;
        let header = parse_header(&data)?;

        Ok(Hwdb {
            data,
            header,
            path: Some(path.to_path_buf()),
            modified,
        })
    }

    /// Query properties for the given modalias string.
    ///
    /// Walks the on-disk trie and returns all key-value pairs from nodes
    /// visited along the matching prefix path.
    pub fn query(&self, modalias: &str) -> Vec<(String, String)> {
        let mut results = Vec::new();
        let search = modalias.as_bytes();
        let mut node_off = self.header.nodes_root_off as usize;
        let mut pos = 0usize;

        loop {
            // Safety: checked below.
            if node_off.saturating_add(HWDB_NODE_SIZE as usize) > self.data.len() {
                break;
            }

            // Read trie_node_f.
            let prefix_off = le::read_u64(&self.data, node_off) as usize;
            let children_count = self.data[node_off + 8] as usize;
            let values_count = le::read_u64(&self.data, node_off + 16) as usize;

            let prefix = read_cstring(&self.data, prefix_off);
            let prefix_bytes = prefix.as_bytes();

            // Match prefix.
            let mut p = 0usize;
            let mut wildcard_hit = false;
            while p < prefix_bytes.len() && pos + p < search.len() {
                if prefix_bytes[p] == b'*' {
                    wildcard_hit = true;
                    break;
                }
                if prefix_bytes[p] != search[pos + p] {
                    return results;
                }
                p += 1;
            }

            // Collect values.
            let is_compat = self.header.value_entry_size == HWDB_VALUE_ENTRY_SIZE_V1;
            let value_entry_size = self.header.value_entry_size as usize;
            let child_area_size = children_count * HWDB_CHILD_ENTRY_SIZE as usize;
            let values_start = node_off + HWDB_NODE_SIZE as usize + child_area_size;

            for i in 0..values_count {
                let voff = values_start + i * value_entry_size;
                if voff.saturating_add(16) > self.data.len() {
                    break;
                }
                let key_off = le::read_u64(&self.data, voff) as usize;
                let val_off = le::read_u64(&self.data, voff + 8) as usize;
                let key = read_cstring(&self.data, key_off).to_string();
                let value = read_cstring(&self.data, val_off).to_string();
                results.push((key, value));
            }

            if wildcard_hit {
                return results;
            }

            pos += p;

            if pos >= search.len() || p < prefix_bytes.len() {
                break;
            }

            // Follow child.
            let next_char = search[pos];
            let child_start = node_off + HWDB_NODE_SIZE as usize;
            let mut found = false;
            for i in 0..children_count {
                let coff = child_start + i * HWDB_CHILD_ENTRY_SIZE as usize;
                if coff.saturating_add(HWDB_CHILD_ENTRY_SIZE as usize) > self.data.len() {
                    break;
                }
                if self.data[coff] == next_char {
                    node_off = le::read_u64(&self.data, coff + 8) as usize;
                    pos += 1;
                    found = true;
                    break;
                }
            }
            if !found {
                for i in 0..children_count {
                    let coff = child_start + i * HWDB_CHILD_ENTRY_SIZE as usize;
                    if coff.saturating_add(HWDB_CHILD_ENTRY_SIZE as usize) > self.data.len() {
                        break;
                    }
                    if self.data[coff] == b'*' {
                        let wc_off = le::read_u64(&self.data, coff + 8) as usize;
                        if wc_off.saturating_add(HWDB_NODE_SIZE as usize) <= self.data.len() {
                            let wc_children_count = self.data[wc_off + 8] as usize;
                            let wc_values_count = le::read_u64(&self.data, wc_off + 16) as usize;
                            let wc_child_area = wc_children_count * HWDB_CHILD_ENTRY_SIZE as usize;
                            let wc_values_start = wc_off + HWDB_NODE_SIZE as usize + wc_child_area;
                            let vsize = self.header.value_entry_size as usize;
                            for vi in 0..wc_values_count {
                                let voff = wc_values_start + vi * vsize;
                                if voff.saturating_add(16) > self.data.len() {
                                    break;
                                }
                                let key = read_cstring(
                                    &self.data,
                                    le::read_u64(&self.data, voff) as usize,
                                )
                                .to_string();
                                let value = read_cstring(
                                    &self.data,
                                    le::read_u64(&self.data, voff + 8) as usize,
                                )
                                .to_string();
                                results.push((key, value));
                            }
                        }
                    }
                }
                break;
            }
        }

        results
    }

    /// Query properties, returning them as a `HashMap`.
    pub fn query_map(&self, modalias: &str) -> HashMap<String, String> {
        self.query(modalias).into_iter().collect()
    }

    /// Check whether the on-disk database has been modified since this
    /// `Hwdb` was loaded, indicating a reload is needed.
    pub fn should_reload(&self) -> bool {
        let path = match &self.path {
            Some(p) => p,
            None => return false,
        };
        let current_mtime = match fs::metadata(path).ok().and_then(|m| m.modified().ok()) {
            Some(t) => t,
            None => return true, // file disappeared → needs reload
        };
        let loaded_mtime = match self.modified {
            Some(t) => t,
            None => return true,
        };
        current_mtime != loaded_mtime
    }

    /// Return a reference to the parsed header.
    pub fn header(&self) -> &HwdbHeader {
        &self.header
    }
}

/// Parse and validate the header from raw binary data.
fn parse_header(data: &[u8]) -> HwdbResult<HwdbHeader> {
    if data.len() < HWDB_HEADER_SIZE as usize {
        return Err(HwdbError::InvalidFormat(
            "file too small for hwdb header".into(),
        ));
    }
    if data[..8] != HWDB_SIGNATURE {
        return Err(HwdbError::InvalidFormat("invalid hwdb signature".into()));
    }

    Ok(HwdbHeader {
        tool_version: le::read_u64(data, 8),
        file_size: le::read_u64(data, 16),
        header_size: le::read_u64(data, 24),
        node_size: le::read_u64(data, 32),
        child_entry_size: le::read_u64(data, 40),
        value_entry_size: le::read_u64(data, 48),
        nodes_root_off: le::read_u64(data, 56),
        nodes_len: le::read_u64(data, 64),
        strings_len: le::read_u64(data, 72),
    })
}

// ── Public API ───────────────────────────────────────────────────────────

/// Check whether the hwdb update should be bypassed.
///
/// Returns `true` when the environment variable `SYSTEMD_HWDB_UPDATE`
/// is set to a value indicating the update should be skipped (e.g. `"0"`).
pub fn hwdb_bypass() -> bool {
    match env::var(HWDB_BYPASS_ENV) {
        Ok(val) => val == "0",
        Err(_) => false,
    }
}

/// Build the hwdb binary database from .hwdb source files.
///
/// * `root` — optional root directory prefix (for testing)
/// * `hwdb_bin_dir` — output directory (defaults to `/etc/udev`)
/// * `strict` — if true, return an error on any parse warning
/// * `compat` — if true, use the compact v1 value entry format
///
/// On success, writes `hwdb.bin` to the target directory and returns
/// statistics about the generated database.
pub fn hwdb_update(
    root: Option<&str>,
    hwdb_bin_dir: Option<&str>,
    strict: bool,
    compat: bool,
) -> HwdbResult<StoreStats> {
    let mut trie = Trie::new();

    let base = root.unwrap_or("");
    let out_dir = hwdb_bin_dir.unwrap_or("/etc/udev");

    // Collect .hwdb files from configuration directories.
    let mut hwdb_files: Vec<(PathBuf, u16)> = Vec::new();
    let mut priority: u16 = 1;
    for conf_dir in HWDB_CONF_DIRS {
        let dir = Path::new(base).join(conf_dir);
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("hwdb") {
                    hwdb_files.push((path, priority));
                    priority += 1;
                }
            }
        }
    }

    // Sort for deterministic ordering (by path).
    hwdb_files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut all_warnings = Vec::new();
    for (path, prio) in &hwdb_files {
        let file = fs::File::open(path).map_err(HwdbError::from_io)?;
        let reader = io::BufReader::new(file);
        let filename = path.to_string_lossy().to_string();
        match import_hwdb_file(reader, &filename, &mut trie, *prio, compat) {
            Ok(warnings) => all_warnings.extend(warnings),
            Err(e) => {
                if strict {
                    return Err(e);
                }
                all_warnings.push(e.to_string());
            }
        }
    }

    if strict && !all_warnings.is_empty() {
        return Err(HwdbError::Parse {
            message: all_warnings.join("\n"),
            file: None,
            line: 0,
        });
    }

    // Serialise.
    let (data, stats) = trie.store(compat)?;

    // Write output.
    let out_path = Path::new(out_dir).join("hwdb.bin");
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(HwdbError::from_io)?;
    }
    let mut file = fs::File::create(&out_path).map_err(HwdbError::from_io)?;
    file.write_all(&data).map_err(HwdbError::from_io)?;

    Ok(stats)
}

/// Query the compiled hwdb database for properties matching `modalias`.
///
/// Searches the default hwdb binary paths and returns all matching
/// key-value pairs.
pub fn hwdb_query(modalias: &str, root: Option<&str>) -> HwdbResult<Vec<(String, String)>> {
    if let Some(r) = root {
        let path = Path::new(r).join("etc/systemd/hwdb/hwdb.bin");
        if let Ok(hwdb) = Hwdb::new_from_path(&path) {
            return Ok(hwdb.query(modalias));
        }
    }

    let hwdb = Hwdb::new_default()?;
    Ok(hwdb.query(modalias))
}

/// Check whether the hwdb binary database should be reloaded.
///
/// `last_modified` is the modification time when the database was last
/// loaded.  Returns `true` when the on-disk file is newer or has been
/// deleted.
pub fn hwdb_should_reload(last_modified: Option<SystemTime>) -> bool {
    for path in HWDB_BIN_PATHS {
        let p = Path::new(path);
        match fs::metadata(p) {
            Ok(meta) => {
                if let Ok(current) = meta.modified() {
                    if let Some(last) = last_modified {
                        if current != last {
                            return true;
                        }
                    } else {
                        return true;
                    }
                    return false;
                }
            }
            Err(_) => continue,
        }
    }
    // No hwdb.bin found anywhere — needs update.
    true
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::TestEnvironment;
    use std::io::Cursor;

    // ── Trie basics ───────────────────────────────────────────────────

    #[test]
    fn test_trie_new() {
        let trie = Trie::new();
        assert_eq!(trie.nodes_count, 1);
        assert_eq!(trie.children_count, 0);
        assert_eq!(trie.values_count, 0);
    }

    #[test]
    fn test_trie_insert_single() {
        let mut trie = Trie::new();
        trie.insert(
            "usb:v046DpC312d*",
            "ID_MODEL",
            "Keyboard",
            "test.hwdb",
            1,
            10,
            false,
        );

        assert_eq!(trie.values_count, 1);
        assert!(trie.nodes_count >= 1);

        let results = trie.query("usb:v046DpC312d1234");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], ("ID_MODEL".to_string(), "Keyboard".to_string()));
    }

    #[test]
    fn test_trie_insert_multiple() {
        let mut trie = Trie::new();
        trie.insert(
            "usb:v046DpC312d*",
            "ID_MODEL",
            "Keyboard",
            "f.hwdb",
            1,
            5,
            false,
        );
        trie.insert(
            "usb:v046DpC312d*",
            "ID_VENDOR",
            "Logitech",
            "f.hwdb",
            1,
            6,
            false,
        );

        let results = trie.query("usb:v046DpC312d1234");
        assert_eq!(results.len(), 2);
        assert!(results.contains(&("ID_MODEL".into(), "Keyboard".into())));
        assert!(results.contains(&("ID_VENDOR".into(), "Logitech".into())));
    }

    #[test]
    fn test_trie_insert_prefix_sharing() {
        let mut trie = Trie::new();
        trie.insert("usb:v046DpC312d*", "KEY1", "val1", "a.hwdb", 1, 1, false);
        trie.insert(
            "usb:v046DpC312d5001*",
            "KEY2",
            "val2",
            "a.hwdb",
            1,
            2,
            false,
        );

        // Both entries should share the "usb:v046DpC312d" prefix.
        let r1 = trie.query("usb:v046DpC312d1234");
        assert!(r1.iter().any(|(k, _)| k == "KEY1"));

        let r2 = trie.query("usb:v046DpC312d5001ABCD");
        assert!(r2.iter().any(|(k, _)| k == "KEY2"));
    }

    #[test]
    fn test_trie_insert_different_roots() {
        let mut trie = Trie::new();
        trie.insert("usb:v046DpC312d*", "KEY_USB", "v1", "a.hwdb", 1, 1, false);
        trie.insert("acpi:PNP0303:*", "KEY_ACPI", "v2", "a.hwdb", 1, 2, false);

        assert_eq!(trie.query("usb:v046DpC312d1234")[0].1, "v1");
        assert_eq!(trie.query("acpi:PNP0303:FOO")[0].1, "v2");
    }

    #[test]
    fn test_trie_query_no_match() {
        let mut trie = Trie::new();
        trie.insert("usb:v046DpC312d*", "KEY", "val", "a.hwdb", 1, 1, false);

        let results = trie.query("acpi:PNP0303:*");
        assert!(results.is_empty());
    }

    #[test]
    fn test_trie_query_empty_string() {
        let trie = Trie::new();
        let results = trie.query("");
        assert!(results.is_empty());
    }

    #[test]
    fn test_trie_update_duplicate_key() {
        let mut trie = Trie::new();
        trie.insert("usb:v046DpC312d*", "KEY", "old", "a.hwdb", 1, 1, false);
        trie.insert("usb:v046DpC312d*", "KEY", "new", "b.hwdb", 2, 1, false);

        // Duplicate key should be updated, not duplicated.
        assert_eq!(trie.values_count, 1);
        let results = trie.query("usb:v046DpC312d1234");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, "new");
    }

    #[test]
    fn test_trie_compat_mode() {
        let mut trie = Trie::new();
        trie.insert(
            "usb:v*p*", "KEY", "val", "a.hwdb", 1, 1, true, // compat
        );
        let entry = &trie.root.children[0].1.values[0];
        assert!(entry.filename.is_empty());
    }

    #[test]
    fn test_trie_stats() {
        let mut trie = Trie::new();
        trie.insert("abc", "K", "V", "f", 1, 1, false);
        let stats = trie.stats();
        assert!(stats.nodes_count >= 2);
        assert!(stats.children_count >= 1);
        assert_eq!(stats.values_count, 1);
    }

    // ── .hwdb parser ──────────────────────────────────────────────────

    #[test]
    fn test_import_hwdb_basic() {
        let hwdb_content = b"\
# comment
usb:v046DpC312d*
 ID_MODEL=Keyboard
 ID_VENDOR=Logitech

acpi:PNP0303:*
 ID_MODEL_FROM_DATABASE=AT Set 2 keyboard
";
        let mut trie = Trie::new();
        let warnings = import_hwdb_file(
            Cursor::new(&hwdb_content[..]),
            "test.hwdb",
            &mut trie,
            1,
            false,
        )
        .unwrap();

        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(trie.values_count, 3);

        let r = trie.query("usb:v046DpC312d1234");
        assert_eq!(r.len(), 2);

        let r = trie.query("acpi:PNP0303:serial-0");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn test_import_hwdb_multiple_matches() {
        let hwdb_content = b"\
usb:v046DpC312d*
usb:v046DpC312d5001*
 ID_MODEL=Keyboard

";
        let mut trie = Trie::new();
        import_hwdb_file(
            Cursor::new(&hwdb_content[..]),
            "test.hwdb",
            &mut trie,
            1,
            false,
        )
        .unwrap();

        // Same property inserted for both match patterns.
        assert_eq!(trie.values_count, 2);
        let r = trie.query("usb:v046DpC312d1234");
        assert_eq!(r.len(), 1);
        let r = trie.query("usb:v046DpC312d5001FOO");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn test_import_hwdb_match_no_properties() {
        let hwdb_content = b"\
usb:v046DpC312d*

";
        let mut trie = Trie::new();
        let warnings = import_hwdb_file(
            Cursor::new(&hwdb_content[..]),
            "test.hwdb",
            &mut trie,
            1,
            false,
        )
        .unwrap();

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("no properties"));
    }

    #[test]
    fn test_import_hwdb_trailing_comment_stripped() {
        let hwdb_content = b"\
usb:v046DpC312d*
 ID_MODEL=Keyboard # this is a comment

";
        let mut trie = Trie::new();
        import_hwdb_file(
            Cursor::new(&hwdb_content[..]),
            "test.hwdb",
            &mut trie,
            1,
            false,
        )
        .unwrap();

        let r = trie.query("usb:v046DpC312d1234");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].0, "ID_MODEL");
        // The value should NOT contain the comment.
        assert!(!r[0].1.contains("comment"));
    }

    #[test]
    fn test_import_hwdb_inline_comment() {
        let hwdb_content = b"\
usb:v046DpC312d*
 ID_MODEL=Keyboard # trailing

";
        let mut trie = Trie::new();
        import_hwdb_file(
            Cursor::new(&hwdb_content[..]),
            "test.hwdb",
            &mut trie,
            1,
            false,
        )
        .unwrap();

        let r = trie.query("usb:v046DpC312d1234");
        assert_eq!(r[0].1, "Keyboard");
    }

    #[test]
    fn test_import_hwdb_indented_at_start_warning() {
        let hwdb_content = b" ID_MODEL=Keyboard\n\n";
        let mut trie = Trie::new();
        let warnings = import_hwdb_file(
            Cursor::new(&hwdb_content[..]),
            "test.hwdb",
            &mut trie,
            1,
            false,
        )
        .unwrap();

        assert!(warnings.iter().any(|w| w.contains("match expected")));
    }

    // ── Binary format ─────────────────────────────────────────────────

    #[test]
    fn test_store_and_load_roundtrip() {
        let mut trie = Trie::new();
        trie.insert(
            "usb:v046DpC312d*",
            "ID_MODEL",
            "Keyboard",
            "test.hwdb",
            1,
            10,
            false,
        );
        trie.insert(
            "usb:v046DpC312d*",
            "ID_VENDOR",
            "Logitech",
            "test.hwdb",
            1,
            11,
            false,
        );
        trie.insert("acpi:PNP0303:*", "KEY", "val", "other.hwdb", 2, 5, false);

        let (data, stats) = trie.store(false).unwrap();

        // Verify header.
        assert_eq!(&data[..8], HWDB_SIGNATURE);
        assert!(stats.total_size > 0);
        assert_eq!(stats.values_count, 3);

        // Load back.
        let hwdb = Hwdb::from_raw(data).unwrap();
        let r = hwdb.query("usb:v046DpC312d1234");
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn test_store_compat_format() {
        let mut trie = Trie::new();
        trie.insert("usb:v*p*", "KEY", "val", "f.hwdb", 1, 1, false);

        let (data, stats) = trie.store(true).unwrap();
        let header = parse_header(&data).unwrap();
        assert_eq!(header.value_entry_size, HWDB_VALUE_ENTRY_SIZE_V1);

        // Should still be loadable and queryable.
        let hwdb = Hwdb::from_raw(data).unwrap();
        let r = hwdb.query("usb:v1234p5678");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn test_parse_header_invalid_signature() {
        let bad_data = vec![0u8; 80];
        let result = parse_header(&bad_data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid hwdb signature"));
    }

    #[test]
    fn test_parse_header_too_small() {
        let result = parse_header(&[0u8; 10]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too small"));
    }

    // ── Public API ────────────────────────────────────────────────────

    #[test]
    fn test_hwdb_bypass_env() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe_ffi!(TestEnvironment::lock());
        environment.remove(HWDB_BYPASS_ENV);
        assert!(!hwdb_bypass());

        environment.set(HWDB_BYPASS_ENV, "0");
        assert!(hwdb_bypass());

        environment.set(HWDB_BYPASS_ENV, "1");
        assert!(!hwdb_bypass());
    }

    #[test]
    fn test_hwdb_should_reload_no_mtime() {
        assert!(hwdb_should_reload(None));
    }

    #[test]
    fn test_hwdb_should_reload_old_mtime() {
        let old = SystemTime::UNIX_EPOCH;
        // Unless hwdb.bin was literally last modified at epoch, this should be true.
        let result = hwdb_should_reload(Some(old));
        // We can't assert true/false since we don't control the filesystem.
        // Just verify it doesn't panic.
        let _ = result;
    }

    #[test]
    fn test_le_helpers_roundtrip() {
        let mut buf = Vec::new();
        le::write_u64(&mut buf, 0x0102030405060708);
        le::write_u32(&mut buf, 0xAABBCCDD);
        le::write_u16(&mut buf, 0xEEFF);

        assert_eq!(le::read_u64(&buf, 0), 0x0102030405060708);
        assert_eq!(le::read_u32(&buf, 8), 0xAABBCCDD);
        assert_eq!(le::read_u16(&buf, 12), 0xEEFF);
    }

    #[test]
    fn test_read_cstring() {
        let data = b"hello\0world\0";
        assert_eq!(read_cstring(data, 0), "hello");
        assert_eq!(read_cstring(data, 6), "world");
        assert_eq!(read_cstring(data, 12), ""); // past end → empty
    }

    #[test]
    fn test_hwdb_header_constants() {
        assert_eq!(HWDB_SIGNATURE.len(), 8);
        assert_eq!(HWDB_HEADER_SIZE, 80);
        assert_eq!(HWDB_NODE_SIZE, 24);
        assert_eq!(HWDB_CHILD_ENTRY_SIZE, 16);
        assert_eq!(HWDB_VALUE_ENTRY_SIZE_V1, 16);
        assert_eq!(HWDB_VALUE_ENTRY_SIZE_V2, 32);
    }
}

// ── Hwdb from-raw helper (test support) ──────────────────────────────────

#[cfg_attr(
    test,
    expect(
        clippy::items_after_test_module,
        reason = "The test-only raw-data constructor stays next to the tests that exercise binary parsing."
    )
)]
impl Hwdb {
    /// Create an `Hwdb` from raw binary data (useful for testing without
    /// touching the filesystem).
    pub(crate) fn from_raw(data: Vec<u8>) -> HwdbResult<Self> {
        let header = parse_header(&data)?;
        Ok(Hwdb {
            data,
            header,
            path: None,
            modified: None,
        })
    }
}
