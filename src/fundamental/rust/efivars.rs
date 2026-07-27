// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/efivars.h, src/fundamental/efivars.c
//
// EFI variable feature flags and secure boot mode decoding.

use crate::macro_fundamental::cmp;

// ── Loader features ─────────────────────────────────────────────────────

pub const EFI_LOADER_FEATURE_CONFIG_TIMEOUT: u64 = 1 << 0;
pub const EFI_LOADER_FEATURE_CONFIG_TIMEOUT_ONE_SHOT: u64 = 1 << 1;
pub const EFI_LOADER_FEATURE_ENTRY_DEFAULT: u64 = 1 << 2;
pub const EFI_LOADER_FEATURE_ENTRY_ONESHOT: u64 = 1 << 3;
pub const EFI_LOADER_FEATURE_BOOT_COUNTING: u64 = 1 << 4;
pub const EFI_LOADER_FEATURE_XBOOTLDR: u64 = 1 << 5;
pub const EFI_LOADER_FEATURE_RANDOM_SEED: u64 = 1 << 6;
pub const EFI_LOADER_FEATURE_LOAD_DRIVER: u64 = 1 << 7;
pub const EFI_LOADER_FEATURE_SORT_KEY: u64 = 1 << 8;
pub const EFI_LOADER_FEATURE_SAVED_ENTRY: u64 = 1 << 9;
pub const EFI_LOADER_FEATURE_DEVICETREE: u64 = 1 << 10;
pub const EFI_LOADER_FEATURE_SECUREBOOT_ENROLL: u64 = 1 << 11;
pub const EFI_LOADER_FEATURE_RETAIN_SHIM: u64 = 1 << 12;
pub const EFI_LOADER_FEATURE_MENU_DISABLE: u64 = 1 << 13;
pub const EFI_LOADER_FEATURE_MULTI_PROFILE_UKI: u64 = 1 << 14;
pub const EFI_LOADER_FEATURE_REPORT_URL: u64 = 1 << 15;
pub const EFI_LOADER_FEATURE_TYPE1_UKI: u64 = 1 << 16;
pub const EFI_LOADER_FEATURE_TYPE1_UKI_URL: u64 = 1 << 17;
pub const EFI_LOADER_FEATURE_TPM2_ACTIVE_PCR_BANKS: u64 = 1 << 18;
pub const EFI_LOADER_FEATURE_ENTRY_PREFERRED: u64 = 1 << 19;

// ── Stub features ───────────────────────────────────────────────────────

pub const EFI_STUB_FEATURE_REPORT_BOOT_PARTITION: u64 = 1 << 0;
pub const EFI_STUB_FEATURE_PICK_UP_CREDENTIALS: u64 = 1 << 1;
pub const EFI_STUB_FEATURE_PICK_UP_SYSEXTS: u64 = 1 << 2;
pub const EFI_STUB_FEATURE_THREE_PCRS: u64 = 1 << 3;
pub const EFI_STUB_FEATURE_RANDOM_SEED: u64 = 1 << 4;
pub const EFI_STUB_FEATURE_CMDLINE_ADDONS: u64 = 1 << 5;
pub const EFI_STUB_FEATURE_CMDLINE_SMBIOS: u64 = 1 << 6;
pub const EFI_STUB_FEATURE_DEVICETREE_ADDONS: u64 = 1 << 7;
pub const EFI_STUB_FEATURE_PICK_UP_CONFEXTS: u64 = 1 << 8;
pub const EFI_STUB_FEATURE_MULTI_PROFILE_UKI: u64 = 1 << 9;
pub const EFI_STUB_FEATURE_REPORT_STUB_PARTITION: u64 = 1 << 10;
pub const EFI_STUB_FEATURE_REPORT_URL: u64 = 1 << 11;

// ── Secure boot modes ───────────────────────────────────────────────────

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootMode {
    Unsupported = 0,
    Disabled = 1,
    Unknown = 2,
    Audit = 3,
    Deployed = 4,
    Setup = 5,
    User = 6,
    Tainted = 7,
}

const SECURE_BOOT_MAX: i32 = 8;

const SECURE_BOOT_TABLE: [&str; SECURE_BOOT_MAX as usize] = [
    "unsupported",
    "disabled",
    "unknown",
    "audit",
    "deployed",
    "setup",
    "user",
    "tainted",
];

pub fn secure_boot_mode_to_string(m: SecureBootMode) -> &'static str {
    let idx = m as i32;
    if idx >= 0 && idx < SECURE_BOOT_MAX {
        SECURE_BOOT_TABLE[idx as usize]
    } else {
        SECURE_BOOT_TABLE[SecureBootMode::Unknown as usize]
    }
}

/// Decode secure boot mode from EFI variables.
pub fn decode_secure_boot_mode(
    secure: bool,
    audit: bool,
    deployed: bool,
    setup: bool,
    moksb: bool,
) -> SecureBootMode {
    if secure && moksb {
        return SecureBootMode::Tainted;
    }
    if secure && deployed && !audit && !setup {
        return SecureBootMode::Deployed;
    }
    if secure && !deployed && !audit && !setup {
        return SecureBootMode::User;
    }
    if !secure && !deployed && audit && setup {
        return SecureBootMode::Audit;
    }
    if !secure && !deployed && !audit && setup {
        return SecureBootMode::Setup;
    }
    if !secure && !deployed && !audit && !setup {
        return SecureBootMode::Disabled;
    }
    SecureBootMode::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_boot_mode_strings() {
        assert_eq!(
            secure_boot_mode_to_string(SecureBootMode::Unsupported),
            "unsupported"
        );
        assert_eq!(
            secure_boot_mode_to_string(SecureBootMode::Deployed),
            "deployed"
        );
        assert_eq!(
            secure_boot_mode_to_string(SecureBootMode::Tainted),
            "tainted"
        );
    }

    #[test]
    fn test_decode_secure_boot_deployed() {
        assert_eq!(
            decode_secure_boot_mode(true, false, true, false, false),
            SecureBootMode::Deployed
        );
    }

    #[test]
    fn test_decode_secure_boot_tainted() {
        assert_eq!(
            decode_secure_boot_mode(true, false, false, false, true),
            SecureBootMode::Tainted
        );
    }

    #[test]
    fn test_decode_secure_boot_disabled() {
        assert_eq!(
            decode_secure_boot_mode(false, false, false, false, false),
            SecureBootMode::Disabled
        );
    }

    #[test]
    fn test_decode_secure_boot_setup() {
        assert_eq!(
            decode_secure_boot_mode(false, false, false, true, false),
            SecureBootMode::Setup
        );
    }

    #[test]
    fn test_decode_secure_boot_audit() {
        assert_eq!(
            decode_secure_boot_mode(false, true, false, true, false),
            SecureBootMode::Audit
        );
    }

    #[test]
    fn test_decode_secure_boot_unknown() {
        assert_eq!(
            decode_secure_boot_mode(true, true, false, false, false),
            SecureBootMode::Unknown
        );
    }

    #[test]
    fn test_feature_flags() {
        assert_eq!(EFI_LOADER_FEATURE_CONFIG_TIMEOUT, 1);
        assert_eq!(EFI_LOADER_FEATURE_BOOT_COUNTING, 1 << 4);
        assert_eq!(EFI_STUB_FEATURE_RANDOM_SEED, 1 << 4);
    }
}
