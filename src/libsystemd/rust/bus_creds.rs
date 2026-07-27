// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-creds.c
//
// D-Bus credential handling: capability bit manipulation, hex parsing,
// credential augmentation from /proc, and mask-based getters.
//
// Faithful Rust port of the C bus-creds logic. Pure safe idiomatic Rust.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

// ── Constants ─────────────────────────────────────────────────────────────

pub const CAP_OFFSET_INHERITABLE: usize = 0;
pub const CAP_OFFSET_PERMITTED: usize = 1;
pub const CAP_OFFSET_EFFECTIVE: usize = 2;
pub const CAP_OFFSET_BOUNDING: usize = 3;

// ── Credential mask flags ─────────────────────────────────────────────────

bitflags::bitflags! {
    /// Bitmask controlling which credential fields are queried/augmented.
    /// Mirrors the `_SD_BUS_CREDS_*` defines from sd-bus.h / bus-creds.c.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BusCredsMask: u64 {
        const PID              = 1 << 0;
        const PIDFD            = 1 << 1;
        const TID              = 1 << 2;
        const PPID             = 1 << 3;
        const UID              = 1 << 4;
        const EUID             = 1 << 5;
        const SUID             = 1 << 6;
        const FSUID            = 1 << 7;
        const GID              = 1 << 8;
        const EGID             = 1 << 9;
        const SGID             = 1 << 10;
        const FSGID            = 1 << 11;
        const SUPPLEMENTARY_GIDS = 1 << 12;
        const COMM             = 1 << 13;
        const TID_COMM         = 1 << 14;
        const EXE              = 1 << 15;
        const CGROUP           = 1 << 16;
        const CMDLINE          = 1 << 17;
        const SELINUX_CONTEXT  = 1 << 18;
        const AUDIT_SESSION_ID = 1 << 19;
        const AUDIT_LOGIN_UID  = 1 << 20;
        const TTY              = 1 << 21;
        const UNIQUE_NAME      = 1 << 22;
        const WELL_KNOWN_NAMES = 1 << 23;
        const DESCRIPTION      = 1 << 24;
        const EFFECTIVE_CAPS   = 1 << 25;
        const PERMITTED_CAPS   = 1 << 26;
        const INHERITABLE_CAPS = 1 << 27;
        const BOUNDING_CAPS    = 1 << 28;
        const UNIT             = 1 << 29;
        const USER_UNIT        = 1 << 30;
        const SLICE            = 1 << 31;
        const USER_SLICE       = 1 << 32;
        const SESSION          = 1 << 33;
        const OWNER_UID        = 1 << 34;
        const AUGMENT          = 1 << 63;
    }
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredsError {
    InvalidArgument,
    NoData,
    IoError,
    ProcessNotFound,
    ParseError,
}

impl std::fmt::Display for CredsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredsError::InvalidArgument => write!(f, "Invalid argument"),
            CredsError::NoData => write!(f, "No data available"),
            CredsError::IoError => write!(f, "I/O error"),
            CredsError::ProcessNotFound => write!(f, "Process not found"),
            CredsError::ParseError => write!(f, "Parse error"),
        }
    }
}

impl std::error::Error for CredsError {}

pub type Result<T> = std::result::Result<T, CredsError>;

// ── Capability helpers ────────────────────────────────────────────────────

/// Convert a Linux capability number to a word index in the caps array.
#[inline]
pub const fn cap_to_index(cap: u32) -> usize {
    (cap / 32) as usize
}

/// Convert a Linux capability number to a bitmask within a word.
#[inline]
pub const fn cap_to_mask(cap: u32) -> u32 {
    1 << (cap % 32)
}

/// DIV_ROUND_UP(n, d) = (n + d - 1) / d
pub const fn div_round_up(n: usize, d: usize) -> usize {
    (n + d - 1) / d
}

/// Get the last known capability number.
/// On Linux, reads from /proc/sys/kernel/cap_last_cap.
/// Falls back to 63 (CAP_LAST_CAP typical value) on error.
pub fn cap_last_cap() -> u32 {
    let path = "/proc/sys/kernel/cap_last_cap";
    fs::read_to_string(path)
        .ok()
        .and_then(|val| val.trim().parse().ok())
        .unwrap_or(63)
}

/// Get the number of 32-bit words needed to store capabilities.
pub fn cap_last_cap_words() -> usize {
    div_round_up((cap_last_cap() + 1) as usize, 32)
}

/// Parse a hex character to its numeric value.
pub fn unhexchar(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(CredsError::ParseError),
    }
}

/// Parse a capability hex string into a capability array.
///
/// The C code reads `/proc/<pid>/status` fields like `CapEff:` which are
/// hex strings of 8-char words, stored big-endian (most significant word last).
/// We reverse the word order when storing.
///
/// `capability` is a flat array organized as 4 blocks of `max_words` words:
///   [INHERITABLE block | PERMITTED block | EFFECTIVE block | BOUNDING block]
pub fn parse_caps(capability: &mut Vec<u32>, offset: usize, p: &str) -> Result<()> {
    let lc = cap_last_cap();
    let max_words = div_round_up((lc + 1) as usize, 32);

    let sz = p.len();
    if sz % 8 != 0 {
        return Err(CredsError::ParseError);
    }
    let n_words = sz / 8;
    if n_words > max_words {
        return Err(CredsError::ParseError);
    }

    if capability.is_empty() {
        capability.resize(max_words * 4, 0);
    }

    for i in 0..n_words {
        let word_str = &p[i * 8..(i + 1) * 8];
        let v = u32::from_str_radix(word_str, 16).map_err(|_| CredsError::ParseError)?;
        capability[offset * max_words + (n_words - i - 1)] = v;
    }

    Ok(())
}

/// Check if a capability is set in the creds capability array.
///
/// `capability` is a flat array: `[block_0 | block_1 | block_2 | block_3]`
/// where each block has `cap_last_cap_words()` entries.
pub fn has_cap(capability: &[u32], offset: usize, cap: i32) -> bool {
    if cap < 0 || capability.is_empty() {
        return false;
    }

    let cap = cap as u32;
    let lc = cap_last_cap();
    if cap > lc {
        return false;
    }

    let sz = div_round_up((lc + 1) as usize, 32);
    let idx = offset * sz + cap_to_index(cap);
    if idx >= capability.len() {
        return false;
    }

    capability[idx] & cap_to_mask(cap) != 0
}

// ── UID/GID validation ───────────────────────────────────────────────────

/// Check if a UID value is valid (not UID_MAX / -1).
pub fn uid_is_valid(uid: u32) -> bool {
    uid != u32::MAX
}

/// Check if a GID value is valid (not GID_MAX / -1).
pub fn gid_is_valid(gid: u32) -> bool {
    gid != u32::MAX
}

// ── BusCreds struct ───────────────────────────────────────────────────────

/// Holds D-Bus credential information.
/// Mirrors the fields of `sd_bus_creds` from the C code.
#[derive(Debug, Clone)]
pub struct BusCreds {
    pub mask: BusCredsMask,
    pub pid: Option<u32>,
    pub pidfd: Option<i32>,
    pub tid: Option<u32>,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub euid: Option<u32>,
    pub suid: Option<u32>,
    pub fsuid: Option<u32>,
    pub gid: Option<u32>,
    pub egid: Option<u32>,
    pub sgid: Option<u32>,
    pub fsgid: Option<u32>,
    pub supplementary_gids: Vec<u32>,
    pub comm: Option<String>,
    pub tid_comm: Option<String>,
    pub exe: Option<String>,
    pub cgroup: Option<String>,
    pub cmdline: Option<String>,
    pub selinux_context: Option<String>,
    pub audit_session_id: Option<u32>,
    pub audit_login_uid: Option<u32>,
    pub tty: Option<String>,
    pub unique_name: Option<String>,
    pub description: Option<String>,
    pub capability: Vec<u32>,
}

impl BusCreds {
    /// Create an empty BusCreds with the given mask.
    pub fn new(mask: BusCredsMask) -> Self {
        Self {
            mask,
            pid: None,
            pidfd: None,
            tid: None,
            ppid: None,
            uid: None,
            euid: None,
            suid: None,
            fsuid: None,
            gid: None,
            egid: None,
            sgid: None,
            fsgid: None,
            supplementary_gids: Vec::new(),
            comm: None,
            tid_comm: None,
            exe: None,
            cgroup: None,
            cmdline: None,
            selinux_context: None,
            audit_session_id: None,
            audit_login_uid: None,
            tty: None,
            unique_name: None,
            description: None,
            capability: Vec::new(),
        }
    }

    /// Get the UID if the mask includes it.
    pub fn get_uid(&self) -> Result<u32> {
        if self.mask.contains(BusCredsMask::UID) {
            self.uid.ok_or(CredsError::NoData)
        } else {
            Err(CredsError::NoData)
        }
    }

    /// Get the EUID if the mask includes it.
    pub fn get_euid(&self) -> Result<u32> {
        if self.mask.contains(BusCredsMask::EUID) {
            self.euid.ok_or(CredsError::NoData)
        } else {
            Err(CredsError::NoData)
        }
    }

    /// Get the GID if the mask includes it.
    pub fn get_gid(&self) -> Result<u32> {
        if self.mask.contains(BusCredsMask::GID) {
            self.gid.ok_or(CredsError::NoData)
        } else {
            Err(CredsError::NoData)
        }
    }

    /// Get the PID if the mask includes it.
    pub fn get_pid(&self) -> Result<u32> {
        if self.mask.contains(BusCredsMask::PID) {
            self.pid.ok_or(CredsError::NoData)
        } else {
            Err(CredsError::NoData)
        }
    }

    /// Get the PPID if the mask includes it.
    pub fn get_ppid(&self) -> Result<u32> {
        if self.mask.contains(BusCredsMask::PPID) {
            self.ppid.ok_or(CredsError::NoData)
        } else {
            Err(CredsError::NoData)
        }
    }

    /// Check if a given effective capability is present.
    pub fn has_effective_cap(&self, cap: i32) -> bool {
        has_cap(&self.capability, CAP_OFFSET_EFFECTIVE, cap)
    }

    /// Check if a given permitted capability is present.
    pub fn has_permitted_cap(&self, cap: i32) -> bool {
        has_cap(&self.capability, CAP_OFFSET_PERMITTED, cap)
    }

    /// Check if a given inheritable capability is present.
    pub fn has_inheritable_cap(&self, cap: i32) -> bool {
        has_cap(&self.capability, CAP_OFFSET_INHERITABLE, cap)
    }

    /// Check if a given bounding capability is present.
    pub fn has_bounding_cap(&self, cap: i32) -> bool {
        has_cap(&self.capability, CAP_OFFSET_BOUNDING, cap)
    }

    /// Augment credentials from /proc/<pid>/status.
    ///
    /// This faithfully mirrors the C `bus_creds_add_more()` logic,
    /// reading fields like PPid, Uid, Gid, CapEff, CapPrm, etc.
    pub fn augment_from_proc(&mut self, pid: u32) -> Result<()> {
        let status_path = format!("/proc/{}/status", pid);
        let contents = fs::read_to_string(&status_path).map_err(|_| CredsError::ProcessNotFound)?;

        for line in contents.lines() {
            if self.ppid.is_none() && self.mask.contains(BusCredsMask::PPID) {
                if let Some(val) = line.strip_prefix("PPid:") {
                    if let Ok(v) = val.trim().parse::<u32>() {
                        self.ppid = Some(v);
                    }
                    continue;
                }
            }

            if self.mask.intersects(
                BusCredsMask::UID | BusCredsMask::EUID | BusCredsMask::SUID | BusCredsMask::FSUID,
            ) {
                if let Some(val) = line.strip_prefix("Uid:") {
                    let parts: Vec<&str> = val.split_whitespace().collect();
                    if parts.len() >= 4 {
                        if self.uid.is_none() && self.mask.contains(BusCredsMask::UID) {
                            self.uid = parts[0].parse().ok();
                        }
                        if self.euid.is_none() && self.mask.contains(BusCredsMask::EUID) {
                            self.euid = parts[1].parse().ok();
                        }
                        if self.suid.is_none() && self.mask.contains(BusCredsMask::SUID) {
                            self.suid = parts[2].parse().ok();
                        }
                        if self.fsuid.is_none() && self.mask.contains(BusCredsMask::FSUID) {
                            self.fsuid = parts[3].parse().ok();
                        }
                    }
                    continue;
                }
            }

            if self.mask.intersects(
                BusCredsMask::GID | BusCredsMask::EGID | BusCredsMask::SGID | BusCredsMask::FSGID,
            ) {
                if let Some(val) = line.strip_prefix("Gid:") {
                    let parts: Vec<&str> = val.split_whitespace().collect();
                    if parts.len() >= 4 {
                        if self.gid.is_none() && self.mask.contains(BusCredsMask::GID) {
                            self.gid = parts[0].parse().ok();
                        }
                        if self.egid.is_none() && self.mask.contains(BusCredsMask::EGID) {
                            self.egid = parts[1].parse().ok();
                        }
                        if self.sgid.is_none() && self.mask.contains(BusCredsMask::SGID) {
                            self.sgid = parts[2].parse().ok();
                        }
                        if self.fsgid.is_none() && self.mask.contains(BusCredsMask::FSGID) {
                            self.fsgid = parts[3].parse().ok();
                        }
                    }
                    continue;
                }
            }

            if self.mask.contains(BusCredsMask::SUPPLEMENTARY_GIDS) {
                if let Some(val) = line.strip_prefix("Groups:") {
                    for part in val.split_whitespace() {
                        if let Ok(g) = part.parse::<u32>() {
                            self.supplementary_gids.push(g);
                        }
                    }
                    continue;
                }
            }

            if self.mask.contains(BusCredsMask::EFFECTIVE_CAPS) {
                if let Some(val) = line.strip_prefix("CapEff:") {
                    parse_caps(&mut self.capability, CAP_OFFSET_EFFECTIVE, val.trim())?;
                    continue;
                }
            }

            if self.mask.contains(BusCredsMask::PERMITTED_CAPS) {
                if let Some(val) = line.strip_prefix("CapPrm:") {
                    parse_caps(&mut self.capability, CAP_OFFSET_PERMITTED, val.trim())?;
                    continue;
                }
            }

            if self.mask.contains(BusCredsMask::INHERITABLE_CAPS) {
                if let Some(val) = line.strip_prefix("CapInh:") {
                    parse_caps(&mut self.capability, CAP_OFFSET_INHERITABLE, val.trim())?;
                    continue;
                }
            }

            if self.mask.contains(BusCredsMask::BOUNDING_CAPS) {
                if let Some(val) = line.strip_prefix("CapBnd:") {
                    parse_caps(&mut self.capability, CAP_OFFSET_BOUNDING, val.trim())?;
                    continue;
                }
            }
        }

        if self.mask.contains(BusCredsMask::COMM) && self.comm.is_none() {
            let comm_path = format!("/proc/{}/comm", pid);
            if let Ok(val) = fs::read_to_string(&comm_path) {
                self.comm = Some(val.trim().to_string());
            }
        }

        if self.mask.contains(BusCredsMask::EXE) && self.exe.is_none() {
            let exe_path = format!("/proc/{}/exe", pid);
            if let Ok(target) = fs::read_link(&exe_path) {
                self.exe = Some(target.to_string_lossy().to_string());
            }
        }

        if self.mask.contains(BusCredsMask::TTY) && self.tty.is_none() {
            let tty_path = format!("/proc/{}/fd/0", pid);
            if let Ok(target) = fs::read_link(&tty_path) {
                let s = target.to_string_lossy();
                if s.starts_with('/') {
                    self.tty = Some(s.to_string());
                }
            }
        }

        if self.mask.contains(BusCredsMask::CGROUP) && self.cgroup.is_none() {
            let cgroup_path = format!("/proc/{}/cgroup", pid);
            if let Ok(contents) = fs::read_to_string(&cgroup_path) {
                for line in contents.lines() {
                    if let Some(cg) = line.splitn(3, ':').nth(2) {
                        let cg = cg.trim_start_matches('/');
                        self.cgroup = Some(cg.to_string());
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_offset_constants() {
        assert_eq!(CAP_OFFSET_INHERITABLE, 0);
        assert_eq!(CAP_OFFSET_PERMITTED, 1);
        assert_eq!(CAP_OFFSET_EFFECTIVE, 2);
        assert_eq!(CAP_OFFSET_BOUNDING, 3);
    }

    #[test]
    fn test_cap_to_index_and_mask() {
        assert_eq!(cap_to_index(0), 0);
        assert_eq!(cap_to_mask(0), 1);
        assert_eq!(cap_to_index(31), 0);
        assert_eq!(cap_to_mask(31), 1 << 31);
        assert_eq!(cap_to_index(32), 1);
        assert_eq!(cap_to_mask(32), 1);
        assert_eq!(cap_to_index(63), 1);
        assert_eq!(cap_to_mask(63), 1 << 31);
    }

    #[test]
    fn test_div_round_up() {
        assert_eq!(div_round_up(0, 32), 0);
        assert_eq!(div_round_up(1, 32), 1);
        assert_eq!(div_round_up(32, 32), 1);
        assert_eq!(div_round_up(33, 32), 2);
        assert_eq!(div_round_up(64, 32), 2);
        assert_eq!(div_round_up(65, 32), 3);
    }

    #[test]
    fn test_unhexchar() {
        assert_eq!(unhexchar(b'0').unwrap(), 0);
        assert_eq!(unhexchar(b'9').unwrap(), 9);
        assert_eq!(unhexchar(b'a').unwrap(), 10);
        assert_eq!(unhexchar(b'f').unwrap(), 15);
        assert_eq!(unhexchar(b'A').unwrap(), 10);
        assert_eq!(unhexchar(b'F').unwrap(), 15);
        assert!(unhexchar(b'g').is_err());
        assert!(unhexchar(b' ').is_err());
    }

    #[test]
    fn test_has_cap_basic() {
        let mut caps = vec![0u32; 8];
        caps[CAP_OFFSET_EFFECTIVE * 2 + cap_to_index(1)] |= cap_to_mask(1);
        assert!(has_cap(&caps, CAP_OFFSET_EFFECTIVE, 1));
        assert!(!has_cap(&caps, CAP_OFFSET_EFFECTIVE, 0));
        assert!(!has_cap(&caps, CAP_OFFSET_PERMITTED, 1));
    }

    #[test]
    fn test_has_cap_empty() {
        let caps: Vec<u32> = vec![];
        assert!(!has_cap(&caps, CAP_OFFSET_EFFECTIVE, 0));
    }

    #[test]
    fn test_has_cap_negative() {
        let caps = vec![0u32; 8];
        assert!(!has_cap(&caps, CAP_OFFSET_EFFECTIVE, -1));
    }

    #[test]
    fn test_parse_caps_basic() {
        let mut caps = Vec::new();
        // "00000001" = word 0 with bit 0 set
        parse_caps(&mut caps, CAP_OFFSET_EFFECTIVE, "00000001").unwrap();
        assert!(has_cap(&caps, CAP_OFFSET_EFFECTIVE, 0));
        assert!(!has_cap(&caps, CAP_OFFSET_EFFECTIVE, 1));
    }

    #[test]
    fn test_parse_caps_invalid_length() {
        let mut caps = Vec::new();
        assert!(parse_caps(&mut caps, CAP_OFFSET_EFFECTIVE, "001").is_err());
    }

    #[test]
    fn test_parse_caps_two_words() {
        let mut caps = Vec::new();
        // Two 8-char words: "00000002" (word 0) followed by "00000001" (word 1)
        // In big-endian hex, word 0 is the second group, word 1 is the first
        parse_caps(&mut caps, CAP_OFFSET_EFFECTIVE, "0000000100000002").unwrap();
        assert!(has_cap(&caps, CAP_OFFSET_EFFECTIVE, 0)); // bit 0 in word 0
        assert!(has_cap(&caps, CAP_OFFSET_EFFECTIVE, 33)); // bit 1 in word 1
    }

    #[test]
    fn test_creds_mask_flags() {
        assert_eq!(BusCredsMask::PID.bits(), 1);
        assert_eq!(BusCredsMask::UID.bits(), 1 << 4);
        assert_eq!(BusCredsMask::GID.bits(), 1 << 8);
        assert_eq!(BusCredsMask::AUGMENT.bits(), 1u64 << 63);

        let combined = BusCredsMask::PID | BusCredsMask::UID | BusCredsMask::GID;
        assert!(combined.contains(BusCredsMask::PID));
        assert!(combined.contains(BusCredsMask::UID));
        assert!(!combined.contains(BusCredsMask::EUID));
    }

    #[test]
    fn test_uid_is_valid() {
        assert!(uid_is_valid(0));
        assert!(uid_is_valid(1000));
        assert!(!uid_is_valid(u32::MAX));
    }

    #[test]
    fn test_gid_is_valid() {
        assert!(gid_is_valid(0));
        assert!(gid_is_valid(1000));
        assert!(!gid_is_valid(u32::MAX));
    }

    #[test]
    fn test_bus_creds_new() {
        let creds = BusCreds::new(BusCredsMask::PID | BusCredsMask::UID);
        assert!(creds.pid.is_none());
        assert!(creds.uid.is_none());
    }

    #[test]
    fn test_bus_creds_get_uid() {
        let mut creds = BusCreds::new(BusCredsMask::UID);
        assert!(creds.get_uid().is_err()); // not set yet
        creds.uid = Some(1000);
        assert_eq!(creds.get_uid(), Ok(1000));
    }

    #[test]
    fn test_bus_creds_get_uid_no_mask() {
        let creds = BusCreds::new(BusCredsMask::PID);
        assert_eq!(creds.get_uid(), Err(CredsError::NoData));
    }

    #[test]
    fn test_bus_creds_get_pid() {
        let mut creds = BusCreds::new(BusCredsMask::PID);
        creds.pid = Some(1234);
        assert_eq!(creds.get_pid(), Ok(1234));
    }

    #[test]
    fn test_bus_creds_get_ppid() {
        let mut creds = BusCreds::new(BusCredsMask::PPID);
        creds.ppid = Some(1);
        assert_eq!(creds.get_ppid(), Ok(1));
    }

    #[test]
    fn test_bus_creds_get_gid() {
        let mut creds = BusCreds::new(BusCredsMask::GID);
        creds.gid = Some(100);
        assert_eq!(creds.get_gid(), Ok(100));
    }

    #[test]
    fn test_bus_creds_has_effective_cap() {
        let mut creds = BusCreds::new(BusCredsMask::EFFECTIVE_CAPS);
        let mut caps = vec![0u32; 8];
        caps[CAP_OFFSET_EFFECTIVE * 2] = 3; // bits 0 and 1
        creds.capability = caps;
        assert!(creds.has_effective_cap(0));
        assert!(creds.has_effective_cap(1));
        assert!(!creds.has_effective_cap(2));
    }

    #[test]
    fn test_bus_creds_no_caps() {
        let creds = BusCreds::new(BusCredsMask::PID);
        assert!(!creds.has_effective_cap(0));
    }

    #[test]
    fn test_bus_creds_get_euid() {
        let mut creds = BusCreds::new(BusCredsMask::EUID);
        creds.euid = Some(42);
        assert_eq!(creds.get_euid(), Ok(42));
    }
}
