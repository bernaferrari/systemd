// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udev-watch.c
//
// Inotify watch management for udev devices.
//
// Manages bidirectional symlinks between watch handles (wd) and device IDs
// under /run/udev/watch/. Provides watch handle parsing, symlink chain
// validation, synthesized event tracking, and directory cleanup logic.

// ── Constants ─────────────────────────────────────────────────────────────

/// Base directory for inotify watch symlinks.
pub const WATCH_DIR: &str = "/run/udev/watch";

/// Old watch directory used during restoration.
pub const WATCH_OLD_DIR: &str = "/run/udev/watch.old";

/// Maximum number of pending synthesized events to track.
pub const MAX_SYNTHESIZED_EVENTS: usize = 1024;

/// Timeout (in microseconds) for clearing synthesized event UUIDs.
pub const SYNTHESIZED_EVENTS_CLEAR_INTERVAL_USEC: u64 = 60_000_000; // 1 minute

/// Inotify mask for write-close events on watched device nodes.
pub const INOTIFY_WATCH_MASK: u32 = 0x00000008; // IN_CLOSE_WRITE

/// Inotify mask for ignored watch descriptors.
pub const IN_IGNORED_MASK: u32 = 0x00008000;

// ── Types ─────────────────────────────────────────────────────────────────

/// A watch handle returned by inotify_add_watch().
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WatchHandle(pub i32);

impl WatchHandle {
    /// Returns true if the watch handle is valid (non-negative).
    pub fn is_valid(self) -> bool {
        self.0 >= 0
    }

    /// Format the watch handle as a string for use as a symlink name.
    pub fn to_symlink_name(self) -> String {
        format!("{}", self.0)
    }

    /// Parse a watch handle from a symlink name string.
    pub fn from_symlink_name(s: &str) -> Option<WatchHandle> {
        let val: i32 = s.parse().ok()?;
        if val >= 0 {
            Some(WatchHandle(val))
        } else {
            None
        }
    }
}

/// Represents a symlink entry in the watch directory.
/// Either a wd→ID mapping or an ID→wd mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchSymlink {
    /// Watch handle number → device ID symlink.
    WatchToId { wd: WatchHandle, id: String },
    /// Device ID → watch handle number symlink.
    IdToWatch { id: String, wd: WatchHandle },
}

/// Result of validating a bidirectional symlink chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchChainValidation {
    /// The chain wd → id → wd is valid and self-consistent.
    Valid { wd: WatchHandle, id: String },
    /// The chain is broken: wd → id points to a different wd on the return.
    BrokenChain {
        wd: WatchHandle,
        id: String,
        wd_returned: String,
    },
    /// The forward symlink (wd → id) could not be read.
    ForwardMissing { wd: WatchHandle },
    /// The reverse symlink (id → wd) could not be read.
    ReverseMissing { wd: WatchHandle, id: String },
}

// ── Symlink chain validation ──────────────────────────────────────────────

/// Validates a bidirectional symlink chain: wd_str → id_str → wd_str.
/// This mirrors the validation done in udev_watch_clear_by_wd() in C.
pub fn validate_watch_chain(
    wd: WatchHandle,
    read_forward: impl Fn(&str) -> Option<String>,
    read_reverse: impl Fn(&str) -> Option<String>,
) -> WatchChainValidation {
    let wd_str = wd.to_symlink_name();

    let id = match read_forward(&wd_str) {
        Some(id) => id,
        None => return WatchChainValidation::ForwardMissing { wd },
    };

    let wd_returned = match read_reverse(&id) {
        Some(w) => w,
        None => return WatchChainValidation::ReverseMissing { wd, id },
    };

    if wd_str == wd_returned {
        WatchChainValidation::Valid { wd, id: id.clone() }
    } else {
        WatchChainValidation::BrokenChain {
            wd,
            id,
            wd_returned,
        }
    }
}

// ── Symlink naming helpers ────────────────────────────────────────────────

/// Determine whether a directory entry name looks like a watch handle (numeric).
pub fn is_watch_handle_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_digit()) && name != "." && name != ".."
}

/// Determine whether a directory entry name looks like a device ID.
/// Device IDs contain non-numeric characters like 'c', 'b', 'n', '+' etc.
pub fn is_device_id_name(name: &str) -> bool {
    !name.is_empty() && !is_watch_handle_name(name) && name != "." && name != ".."
}

// ── Synthesized event tracking ────────────────────────────────────────────

/// Tracks pending synthesized event UUIDs, bounded by MAX_SYNTHESIZED_EVENTS.
#[derive(Debug, Clone, Default)]
pub struct SynthesizedEventTracker {
    events: Vec<[u8; 16]>,
}

impl SynthesizedEventTracker {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Add a new synthesized event UUID. Evicts the oldest if at capacity.
    pub fn add(&mut self, uuid: [u8; 16]) {
        while self.events.len() >= MAX_SYNTHESIZED_EVENTS {
            self.events.remove(0);
        }
        self.events.push(uuid);
    }

    /// Returns the number of pending synthesized events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns true if no pending events exist.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Remove and return the first (oldest) event UUID.
    pub fn pop_oldest(&mut self) -> Option<[u8; 16]> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        }
    }

    /// Clear all pending events.
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

// ── Watch entry parsing for dump ──────────────────────────────────────────

/// Parsed entry from the watch directory during udev_watch_dump().
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DumpEntry {
    /// A pending watch handle whose reverse symlink hasn't been verified.
    PendingWd { wd_str: String },
    /// A verified watch: device ID with its watch handle.
    Verified { id: String, wd: String },
    /// A broken watch with mismatched symlink chain.
    Broken {
        id: String,
        wd: String,
        devnode: Option<String>,
    },
}

/// Categorize a directory entry as either a watch handle name or a device ID.
/// Returns Some(true) if it's a watch handle, Some(false) if it's a device ID,
/// None if it's "." or ".." or empty.
pub fn categorize_dir_entry(name: &str) -> Option<bool> {
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    Some(is_watch_handle_name(name))
}

// ── Watch file path helpers ───────────────────────────────────────────────

/// Build the full path for a watch symlink by name.
pub fn watch_path(name: &str) -> String {
    format!("{WATCH_DIR}/{name}")
}

/// Build the wd symlink path: /run/udev/watch/<wd>
pub fn wd_path(wd: WatchHandle) -> String {
    watch_path(&wd.to_symlink_name())
}

/// Build the id symlink path: /run/udev/watch/<id>
pub fn id_path(id: &str) -> String {
    watch_path(id)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watch_handle_validity() {
        assert!(WatchHandle(0).is_valid());
        assert!(WatchHandle(1).is_valid());
        assert!(WatchHandle(42).is_valid());
        assert!(!WatchHandle(-1).is_valid());
        assert!(!WatchHandle(-999).is_valid());
    }

    #[test]
    fn test_watch_handle_symlink_roundtrip() {
        for wd_val in [0, 1, 42, 999, i32::MAX] {
            let wh = WatchHandle(wd_val);
            let name = wh.to_symlink_name();
            assert_eq!(WatchHandle::from_symlink_name(&name), Some(wh));
        }
    }

    #[test]
    fn test_watch_handle_from_symlink_name_invalid() {
        assert_eq!(WatchHandle::from_symlink_name(""), None);
        assert_eq!(WatchHandle::from_symlink_name("abc"), None);
        assert_eq!(WatchHandle::from_symlink_name("-1"), None);
        assert_eq!(WatchHandle::from_symlink_name("12.5"), None);
    }

    #[test]
    fn test_is_watch_handle_name() {
        assert!(is_watch_handle_name("0"));
        assert!(is_watch_handle_name("42"));
        assert!(is_watch_handle_name("123456"));
        assert!(!is_watch_handle_name(""));
        assert!(!is_watch_handle_name("c1:2"));
        assert!(!is_watch_handle_name("."));
        assert!(!is_watch_handle_name(".."));
        assert!(!is_watch_handle_name("n0"));
    }

    #[test]
    fn test_is_device_id_name() {
        assert!(is_device_id_name("c1:2"));
        assert!(is_device_id_name("b8:0"));
        assert!(is_device_id_name("n2"));
        assert!(!is_device_id_name("42"));
        assert!(!is_device_id_name(""));
        assert!(!is_device_id_name("."));
    }

    #[test]
    fn test_validate_watch_chain_valid() {
        let fwd = |wd_str: &str| -> Option<String> {
            if wd_str == "5" {
                Some("c1:2".into())
            } else {
                None
            }
        };
        let rev =
            |id: &str| -> Option<String> { if id == "c1:2" { Some("5".into()) } else { None } };
        let result = validate_watch_chain(WatchHandle(5), fwd, rev);
        assert_eq!(
            result,
            WatchChainValidation::Valid {
                wd: WatchHandle(5),
                id: "c1:2".into()
            }
        );
    }

    #[test]
    fn test_validate_watch_chain_broken() {
        let fwd = |wd_str: &str| -> Option<String> {
            if wd_str == "5" {
                Some("c1:2".into())
            } else {
                None
            }
        };
        let rev = |id: &str| -> Option<String> {
            if id == "c1:2" {
                Some("99".into())
            } else {
                None
            }
        };
        let result = validate_watch_chain(WatchHandle(5), fwd, rev);
        assert_eq!(
            result,
            WatchChainValidation::BrokenChain {
                wd: WatchHandle(5),
                id: "c1:2".into(),
                wd_returned: "99".into()
            }
        );
    }

    #[test]
    fn test_validate_watch_chain_forward_missing() {
        let fwd = |_wd_str: &str| None;
        let rev = |_id: &str| None;
        let result = validate_watch_chain(WatchHandle(5), fwd, rev);
        assert_eq!(
            result,
            WatchChainValidation::ForwardMissing { wd: WatchHandle(5) }
        );
    }

    #[test]
    fn test_synthesized_event_tracker_add_and_evict() {
        let mut tracker = SynthesizedEventTracker::new();
        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);

        for i in 0..=MAX_SYNTHESIZED_EVENTS {
            let mut uuid = [0u8; 16];
            uuid[0] = (i % 256) as u8;
            tracker.add(uuid);
        }
        // Should be capped at MAX_SYNTHESIZED_EVENTS
        assert_eq!(tracker.len(), MAX_SYNTHESIZED_EVENTS);
    }

    #[test]
    fn test_synthesized_event_tracker_pop_oldest() {
        let mut tracker = SynthesizedEventTracker::new();
        let uuid1 = [1u8; 16];
        let uuid2 = [2u8; 16];
        tracker.add(uuid1);
        tracker.add(uuid2);
        assert_eq!(tracker.pop_oldest(), Some(uuid1));
        assert_eq!(tracker.pop_oldest(), Some(uuid2));
        assert_eq!(tracker.pop_oldest(), None);
        assert!(tracker.is_empty());
    }

    #[test]
    fn test_categorize_dir_entry() {
        assert_eq!(categorize_dir_entry("42"), Some(true)); // watch handle
        assert_eq!(categorize_dir_entry("c1:2"), Some(false)); // device ID
        assert_eq!(categorize_dir_entry("."), None);
        assert_eq!(categorize_dir_entry(".."), None);
        assert_eq!(categorize_dir_entry(""), None);
    }

    #[test]
    fn test_watch_paths() {
        assert_eq!(watch_path("c1:2"), "/run/udev/watch/c1:2");
        assert_eq!(wd_path(WatchHandle(5)), "/run/udev/watch/5");
        assert_eq!(id_path("b8:0"), "/run/udev/watch/b8:0");
    }
}
