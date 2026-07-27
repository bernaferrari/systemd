// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/net/test-link-config-tables.c
//
// Tests the mac_address_policy string table from link-config.h.
// The C source calls test_table(MACAddressPolicy, mac_address_policy, MAC_ADDRESS_POLICY)
// which verifies string-to-enum and enum-to-string conversions for:
//   "persistent" → MAC_ADDRESS_POLICY_PERSISTENT
//   "random"     → MAC_ADDRESS_POLICY_RANDOM
//   "none"       → MAC_ADDRESS_POLICY_NONE
// Uses a custom main() with test_setup_logging.

pub const SOURCE_PATH: &str = "src/udev/net/test-link-config-tables.c";
pub const SOURCE_TEXT: &str = include_str!("../../net/test-link-config-tables.c");

#[repr(C)]
pub enum MACAddressPolicy {
    Persistent = 0,
    Random = 1,
    None_ = 2,
    _Max,
    _Invalid = -22, // -EINVAL
}

unsafe extern "C" {
    fn mac_address_policy_from_string(s: *const libc::c_char) -> i32;
    fn mac_address_policy_to_string(i: i32) -> *const libc::c_char;
    fn test_setup_logging(level: i32);
}

pub const TEST_FUNCTIONS: &[&str] = &["test_table"];
pub const ENTRY_STYLE: &str = "custom_main";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_is_embedded() {
        assert!(!super::SOURCE_TEXT.is_empty());
        assert!(super::SOURCE_PATH.ends_with(".c"));
    }

    #[test]
    fn source_references_mac_address_policy() {
        assert!(super::SOURCE_TEXT.contains("MACAddressPolicy"));
        assert!(super::SOURCE_TEXT.contains("mac_address_policy"));
    }

    #[test]
    fn enum_values_match_c_header() {
        assert_eq!(MACAddressPolicy::Persistent as i32, 0);
        assert_eq!(MACAddressPolicy::Random as i32, 1);
        assert_eq!(MACAddressPolicy::None_ as i32, 2);
    }
}
