// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/rfkill/rfkill.c
//
// Manages rfkill (wireless device enable/disable) state persistence.
//
// Provides rfkill event structures, type tables, and state file management
// utilities faithfully mirroring the C implementation's data types and
// constants.

// ── Constants ─────────────────────────────────────────────────────────────

/// Timeout for exiting after processing events (5 seconds).
/// Corresponds to `EXIT_USEC` in rfkill.c.
pub const EXIT_USEC: u64 = 5_000_000;

/// Base directory for rfkill state persistence.
pub const RFKILL_STATE_DIR: &str = "/var/lib/systemd/rfkill";

// ── Rfkill operation codes ────────────────────────────────────────────────

/// Rfkill event operation types, from `<linux/rfkill.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfkillOp {
    Add = 0,
    Del = 1,
    Change = 2,
    ChangeAll = 3,
}

impl RfkillOp {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(RfkillOp::Add),
            1 => Some(RfkillOp::Del),
            2 => Some(RfkillOp::Change),
            3 => Some(RfkillOp::ChangeAll),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ── Rfkill device types ───────────────────────────────────────────────────

/// Rfkill device type identifiers.
/// Corresponds to the `rfkill_type` enum in `<linux/rfkill.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfkillType {
    All = 0,
    Wlan = 1,
    Bluetooth = 2,
    Uwb = 3,
    Wimax = 4,
    Wwan = 5,
    Gps = 6,
    Fm = 7,
    Nfc = 8,
}

impl RfkillType {
    /// Parse from the kernel integer value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(RfkillType::All),
            1 => Some(RfkillType::Wlan),
            2 => Some(RfkillType::Bluetooth),
            3 => Some(RfkillType::Uwb),
            4 => Some(RfkillType::Wimax),
            5 => Some(RfkillType::Wwan),
            6 => Some(RfkillType::Gps),
            7 => Some(RfkillType::Fm),
            8 => Some(RfkillType::Nfc),
            _ => None,
        }
    }

    /// Convert to the string table name.
    /// Corresponds to `rfkill_type_to_string()` in rfkill.c.
    pub fn to_string_name(self) -> &'static str {
        match self {
            RfkillType::All => "all",
            RfkillType::Wlan => "wlan",
            RfkillType::Bluetooth => "bluetooth",
            RfkillType::Uwb => "uwb",
            RfkillType::Wimax => "wimax",
            RfkillType::Wwan => "wwan",
            RfkillType::Gps => "gps",
            RfkillType::Fm => "fm",
            RfkillType::Nfc => "nfc",
        }
    }

    /// Parse from the string table name.
    pub fn from_string_name(s: &str) -> Option<Self> {
        match s {
            "all" => Some(RfkillType::All),
            "wlan" => Some(RfkillType::Wlan),
            "bluetooth" => Some(RfkillType::Bluetooth),
            "uwb" => Some(RfkillType::Uwb),
            "wimax" => Some(RfkillType::Wimax),
            "wwan" => Some(RfkillType::Wwan),
            "gps" => Some(RfkillType::Gps),
            "fm" => Some(RfkillType::Fm),
            "nfc" => Some(RfkillType::Nfc),
            _ => None,
        }
    }
}

// ── Rfkill event ──────────────────────────────────────────────────────────

/// An rfkill event from `/dev/rfkill`.
/// Corresponds to `struct rfkill_event` in `<linux/rfkill.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfkillEvent {
    pub idx: u32,
    pub type_: u8,
    pub op: u8,
    pub soft: u8,
    pub hard: u8,
}

impl RfkillEvent {
    /// Create a new rfkill event.
    pub fn new(idx: u32, type_: RfkillType, op: RfkillOp, soft: bool, hard: bool) -> Self {
        Self {
            idx,
            type_: type_ as u8,
            op: op as u8,
            soft: if soft { 1 } else { 0 },
            hard: if hard { 1 } else { 0 },
        }
    }

    /// Parse the operation from the raw event.
    pub fn get_op(&self) -> Option<RfkillOp> {
        RfkillOp::from_u8(self.op)
    }

    /// Parse the device type from the raw event.
    pub fn get_type(&self) -> Option<RfkillType> {
        RfkillType::from_u8(self.type_)
    }

    /// Whether the device is software-blocked.
    pub fn is_soft_blocked(&self) -> bool {
        self.soft != 0
    }

    /// Whether the device is hardware-blocked.
    pub fn is_hard_blocked(&self) -> bool {
        self.hard != 0
    }
}

// ── State file path ───────────────────────────────────────────────────────

/// Build the state file path for a given rfkill type and optional path ID.
/// Corresponds to `determine_state_file()` in rfkill.c.
pub fn state_file_path(rfkill_type: RfkillType, path_id: Option<&str>) -> String {
    let type_name = rfkill_type.to_string_name();
    match path_id {
        Some(id) => format!("{}:{}:{}", RFKILL_STATE_DIR, cescape(id), type_name),
        None => format!("{}:{}", RFKILL_STATE_DIR, type_name),
    }
}

/// Simple C-style escaping for path IDs.
/// Corresponds to `cescape()` used in `determine_state_file()`.
pub fn cescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{:02x}", b)),
        }
    }
    out
}

// ── Write queue ───────────────────────────────────────────────────────────

/// A pending state write, mirroring `write_queue_item` in rfkill.c.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteQueueItem {
    pub rfkill_idx: i32,
    pub file: String,
    pub state: i32,
}

impl WriteQueueItem {
    pub fn new(rfkill_idx: i32, file: String, state: i32) -> Self {
        Self {
            rfkill_idx,
            file,
            state,
        }
    }

    /// Format the state as "0" or "1".
    /// Corresponds to `one_zero(item->state)`.
    pub fn state_str(&self) -> &'static str {
        if self.state != 0 { "1" } else { "0" }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_usec_constant() {
        assert_eq!(EXIT_USEC, 5_000_000);
    }

    #[test]
    fn rfkill_op_roundtrip() {
        for op in [
            RfkillOp::Add,
            RfkillOp::Del,
            RfkillOp::Change,
            RfkillOp::ChangeAll,
        ] {
            assert_eq!(RfkillOp::from_u8(op.to_u8()), Some(op));
        }
    }

    #[test]
    fn rfkill_op_invalid() {
        assert!(RfkillOp::from_u8(255).is_none());
    }

    #[test]
    fn rfkill_type_roundtrip() {
        for t in [
            RfkillType::All,
            RfkillType::Wlan,
            RfkillType::Bluetooth,
            RfkillType::Uwb,
            RfkillType::Wimax,
            RfkillType::Wwan,
            RfkillType::Gps,
            RfkillType::Fm,
            RfkillType::Nfc,
        ] {
            let name = t.to_string_name();
            assert_eq!(RfkillType::from_string_name(name), Some(t));
        }
    }

    #[test]
    fn rfkill_type_invalid() {
        assert!(RfkillType::from_u8(200).is_none());
        assert!(RfkillType::from_string_name("unknown").is_none());
    }

    #[test]
    fn rfkill_event_construct() {
        let event = RfkillEvent::new(3, RfkillType::Wlan, RfkillOp::Change, true, false);
        assert_eq!(event.idx, 3);
        assert_eq!(event.get_op(), Some(RfkillOp::Change));
        assert_eq!(event.get_type(), Some(RfkillType::Wlan));
        assert!(event.is_soft_blocked());
        assert!(!event.is_hard_blocked());
    }

    #[test]
    fn rfkill_event_type_names() {
        let event = RfkillEvent::new(0, RfkillType::Bluetooth, RfkillOp::Add, false, false);
        assert_eq!(event.get_type().unwrap().to_string_name(), "bluetooth");
    }

    #[test]
    fn state_file_path_without_path_id() {
        let path = state_file_path(RfkillType::Wlan, None);
        assert_eq!(path, "/var/lib/systemd/rfkill:wlan");
    }

    #[test]
    fn state_file_path_with_path_id() {
        let path = state_file_path(RfkillType::Bluetooth, Some("pci-0000:03:00.0"));
        assert!(path.starts_with(RFKILL_STATE_DIR));
        assert!(path.contains("pci-0000:03:00.0"));
        assert!(path.ends_with(":bluetooth"));
    }

    #[test]
    fn cescape_basic() {
        assert_eq!(cescape("hello"), "hello");
        assert_eq!(cescape("path with spaces"), "path with spaces");
    }

    #[test]
    fn cescape_special_chars() {
        assert!(cescape("back\\slash").contains("\\\\"));
        assert!(cescape("new\nline").contains("\\n"));
    }

    #[test]
    fn write_queue_item_state_str() {
        let on = WriteQueueItem::new(0, "file".into(), 1);
        assert_eq!(on.state_str(), "1");
        let off = WriteQueueItem::new(0, "file".into(), 0);
        assert_eq!(off.state_str(), "0");
    }

    #[test]
    fn write_queue_item_equality() {
        let a = WriteQueueItem::new(1, "f".into(), 1);
        let b = WriteQueueItem::new(1, "f".into(), 1);
        assert_eq!(a, b);
    }

    #[test]
    fn rfkill_type_ordering() {
        // From linux/rfkill.h: types are numbered sequentially
        assert!(RfkillType::Wlan as u8 < RfkillType::Bluetooth as u8);
        assert!(RfkillType::Bluetooth as u8 < RfkillType::Nfc as u8);
    }
}
