// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/sysfail.c
//
// System failure detection for UEFI boot.
//
// Checks the EFI System Resource Table (ESRT) for failed firmware
// updates and provides human-readable error descriptions.

// ── Constants ─────────────────────────────────────────────────────────────

/// ESRT firmware type for system firmware.
pub const ESRT_FW_TYPE_SYSTEMFIRMWARE: u32 = 1;

/// Last attempt status: success.
pub const LAST_ATTEMPT_STATUS_SUCCESS: u32 = 0;

// ── Types ─────────────────────────────────────────────────────────────────

/// System failure types, mirroring the C SysFailType enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysFailType {
    /// No failure detected.
    NoFailure = 0,
    /// Firmware update has failed.
    FirmwareUpdate = 1,
}

/// A single ESRT entry describing a firmware resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsrtEntry {
    pub fw_type: u32,
    pub last_attempt_status: u32,
}

/// The EFI System Resource Table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsrtTable {
    pub entries: Vec<EsrtEntry>,
}

/// Error for sysfail operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysFailError {
    /// No ESRT table found.
    NoTable,
}

impl std::fmt::Display for SysFailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SysFailError::NoTable => write!(f, "no ESRT table found"),
        }
    }
}

impl std::error::Error for SysFailError {}

// ── Core logic ────────────────────────────────────────────────────────────

/// Check if any system firmware entry in the ESRT has a failed update.
///
/// Mirrors `firmware_update_has_failed()` in C.
pub fn firmware_update_has_failed(table: Option<&EsrtTable>) -> bool {
    let Some(table) = table else {
        return false;
    };

    table.entries.iter().any(|entry| {
        entry.fw_type == ESRT_FW_TYPE_SYSTEMFIRMWARE
            && entry.last_attempt_status != LAST_ATTEMPT_STATUS_SUCCESS
    })
}

/// Check the system for failures.
///
/// Mirrors `sysfail_check()` in C. Returns the type of failure detected.
pub fn sysfail_check(table: Option<&EsrtTable>) -> SysFailType {
    if firmware_update_has_failed(table) {
        SysFailType::FirmwareUpdate
    } else {
        SysFailType::NoFailure
    }
}

/// Get a human-readable error string for a failure type.
///
/// Mirrors `sysfail_get_error_str()` in C. Note: the C code has a typo
/// ("firmware-updare-failure" with 'r' instead of 't') which we preserve
/// for compatibility.
pub fn sysfail_get_error_str(fail_type: SysFailType) -> Option<&'static str> {
    match fail_type {
        SysFailType::NoFailure => None,
        SysFailType::FirmwareUpdate => Some("firmware-updare-failure"),
    }
}

/// Check if a single ESRT entry indicates a system firmware update failure.
pub fn is_system_firmware_failure(entry: &EsrtEntry) -> bool {
    entry.fw_type == ESRT_FW_TYPE_SYSTEMFIRMWARE
        && entry.last_attempt_status != LAST_ATTEMPT_STATUS_SUCCESS
}

/// Parse an ESRT table from raw entry data.
///
/// Each entry is assumed to have at least fw_type and last_attempt_status.
pub fn parse_esrt_entries(raw_entries: &[(u32, u32)]) -> EsrtTable {
    EsrtTable {
        entries: raw_entries
            .iter()
            .map(|&(fw_type, status)| EsrtEntry {
                fw_type,
                last_attempt_status: status,
            })
            .collect(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firmware_update_no_table() {
        assert!(!firmware_update_has_failed(None));
    }

    #[test]
    fn test_firmware_update_empty_table() {
        let table = EsrtTable { entries: vec![] };
        assert!(!firmware_update_has_failed(Some(&table)));
    }

    #[test]
    fn test_firmware_update_success() {
        let table = EsrtTable {
            entries: vec![EsrtEntry {
                fw_type: ESRT_FW_TYPE_SYSTEMFIRMWARE,
                last_attempt_status: LAST_ATTEMPT_STATUS_SUCCESS,
            }],
        };
        assert!(!firmware_update_has_failed(Some(&table)));
    }

    #[test]
    fn test_firmware_update_failed() {
        let table = EsrtTable {
            entries: vec![EsrtEntry {
                fw_type: ESRT_FW_TYPE_SYSTEMFIRMWARE,
                last_attempt_status: 1, // not success
            }],
        };
        assert!(firmware_update_has_failed(Some(&table)));
    }

    #[test]
    fn test_firmware_update_non_system_fw() {
        let table = EsrtTable {
            entries: vec![EsrtEntry {
                fw_type: 2, // not system firmware
                last_attempt_status: 1,
            }],
        };
        assert!(!firmware_update_has_failed(Some(&table)));
    }

    #[test]
    fn test_sysfail_check_no_failure() {
        assert_eq!(sysfail_check(None), SysFailType::NoFailure);
    }

    #[test]
    fn test_sysfail_check_firmware_failure() {
        let table = EsrtTable {
            entries: vec![EsrtEntry {
                fw_type: ESRT_FW_TYPE_SYSTEMFIRMWARE,
                last_attempt_status: 5,
            }],
        };
        assert_eq!(sysfail_check(Some(&table)), SysFailType::FirmwareUpdate);
    }

    #[test]
    fn test_sysfail_get_error_str_no_failure() {
        assert_eq!(sysfail_get_error_str(SysFailType::NoFailure), None);
    }

    #[test]
    fn test_sysfail_get_error_str_firmware() {
        assert_eq!(
            sysfail_get_error_str(SysFailType::FirmwareUpdate),
            Some("firmware-updare-failure")
        );
    }

    #[test]
    fn test_is_system_firmware_failure_true() {
        let entry = EsrtEntry {
            fw_type: ESRT_FW_TYPE_SYSTEMFIRMWARE,
            last_attempt_status: 1,
        };
        assert!(is_system_firmware_failure(&entry));
    }

    #[test]
    fn test_is_system_firmware_failure_false() {
        let entry = EsrtEntry {
            fw_type: ESRT_FW_TYPE_SYSTEMFIRMWARE,
            last_attempt_status: LAST_ATTEMPT_STATUS_SUCCESS,
        };
        assert!(!is_system_firmware_failure(&entry));
    }

    #[test]
    fn test_parse_esrt_entries() {
        let table = parse_esrt_entries(&[(1, 0), (2, 5)]);
        assert_eq!(table.entries.len(), 2);
        assert_eq!(table.entries[0].fw_type, 1);
        assert_eq!(table.entries[1].last_attempt_status, 5);
    }
}
