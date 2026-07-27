// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/rfkill/rfkill.c
pub const EXIT_USEC: u64 = 5_000_000;
const STATE_DIR: &str = "/var/lib/systemd/rfkill";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidBoolean(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBoolean(value) => write!(f, "invalid rfkill state {value:?}"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfkillOp {
    Add,
    Delete,
    Change,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfkillType {
    All,
    Wlan,
    Bluetooth,
    Uwb,
    Wimax,
    Wwan,
    Gps,
    Fm,
    Nfc,
}

impl RfkillType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Wlan => "wlan",
            Self::Bluetooth => "bluetooth",
            Self::Uwb => "uwb",
            Self::Wimax => "wimax",
            Self::Wwan => "wwan",
            Self::Gps => "gps",
            Self::Fm => "fm",
            Self::Nfc => "nfc",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfkillEvent {
    pub idx: u32,
    pub kind: RfkillType,
    pub op: RfkillOp,
    pub soft: bool,
    pub hard: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteQueueItem {
    pub rfkill_idx: u32,
    pub state_file: String,
    pub state: bool,
}

pub fn escape_path_id(path_id: &str) -> String {
    let mut escaped = String::with_capacity(path_id.len());
    for ch in path_id.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':') {
            escaped.push(ch);
        } else {
            for byte in ch.to_string().bytes() {
                escaped.push_str(&format!("\\x{byte:02x}"));
            }
        }
    }
    escaped
}

pub fn determine_state_file(kind: RfkillType, path_id: Option<&str>) -> String {
    match path_id.filter(|value| !value.is_empty()) {
        Some(path_id) => format!("{STATE_DIR}/{}:{}", escape_path_id(path_id), kind.as_str()),
        None => format!("{STATE_DIR}/{}", kind.as_str()),
    }
}

pub fn parse_saved_state(value: &str) -> Result<bool> {
    match value.trim() {
        "1" | "yes" | "true" | "on" => Ok(true),
        "0" | "no" | "false" | "off" => Ok(false),
        other => Err(Error::InvalidBoolean(other.to_string())),
    }
}

pub fn queue_save_state(
    queue: &mut Vec<WriteQueueItem>,
    event: &RfkillEvent,
    path_id: Option<&str>,
) -> String {
    let state_file = determine_state_file(event.kind, path_id);
    queue.retain(|item| item.rfkill_idx != event.idx && item.state_file != state_file);
    queue.push(WriteQueueItem {
        rfkill_idx: event.idx,
        state_file: state_file.clone(),
        state: event.soft,
    });
    state_file
}

pub fn drain_queue(queue: &mut Vec<WriteQueueItem>) -> Vec<WriteQueueItem> {
    std::mem::take(queue)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(idx: u32, kind: RfkillType, soft: bool) -> RfkillEvent {
        RfkillEvent {
            idx,
            kind,
            op: RfkillOp::Change,
            soft,
            hard: false,
        }
    }

    #[test]
    fn exit_usec_matches_c_constant() {
        assert_eq!(EXIT_USEC, 5_000_000);
    }

    #[test]
    fn rfkill_type_names_match_table() {
        assert_eq!(RfkillType::Bluetooth.as_str(), "bluetooth");
        assert_eq!(RfkillType::Nfc.as_str(), "nfc");
    }

    #[test]
    fn path_id_is_escaped() {
        assert_eq!(escape_path_id("pci-0000:00/1"), "pci-0000:00\\x2f1");
    }

    #[test]
    fn state_file_uses_path_id_when_available() {
        let file = determine_state_file(RfkillType::Wlan, Some("usb-1/2"));
        assert_eq!(file, "/var/lib/systemd/rfkill/usb-1\\x2f2:wlan");
    }

    #[test]
    fn state_file_falls_back_to_type_only() {
        let file = determine_state_file(RfkillType::Gps, None);
        assert_eq!(file, "/var/lib/systemd/rfkill/gps");
    }

    #[test]
    fn parse_saved_state_accepts_true_and_false() {
        assert_eq!(parse_saved_state("yes").unwrap(), true);
        assert_eq!(parse_saved_state("0").unwrap(), false);
    }

    #[test]
    fn parse_saved_state_rejects_garbage() {
        assert!(matches!(
            parse_saved_state("maybe"),
            Err(Error::InvalidBoolean(value)) if value == "maybe"
        ));
    }

    #[test]
    fn queue_save_state_replaces_matching_index() {
        let mut queue = vec![WriteQueueItem {
            rfkill_idx: 7,
            state_file: "/var/lib/systemd/rfkill/wlan".into(),
            state: false,
        }];

        queue_save_state(&mut queue, &sample_event(7, RfkillType::Wlan, true), None);

        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].state, true);
    }

    #[test]
    fn queue_save_state_replaces_matching_state_file() {
        let mut queue = vec![WriteQueueItem {
            rfkill_idx: 1,
            state_file: "/var/lib/systemd/rfkill/wlan".into(),
            state: false,
        }];

        queue_save_state(&mut queue, &sample_event(9, RfkillType::Wlan, true), None);

        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].rfkill_idx, 9);
    }

    #[test]
    fn drain_queue_returns_all_items_and_clears_source() {
        let mut queue = vec![WriteQueueItem {
            rfkill_idx: 3,
            state_file: "/var/lib/systemd/rfkill/fm".into(),
            state: true,
        }];

        let drained = drain_queue(&mut queue);
        assert_eq!(drained.len(), 1);
        assert!(queue.is_empty());
    }
}
