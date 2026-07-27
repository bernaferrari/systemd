// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/test-chid-match.c
//
// CHID (Computer Hardware ID) matching test harness.
//
// Provides test infrastructure for SMBIOS-based hardware identification
// and CHID matching, including mock SMBIOS info and EDID panel data.

// ── Types ─────────────────────────────────────────────────────────────────

/// Raw SMBIOS info used for CHID matching.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawSmbiosInfo {
    pub manufacturer: Option<String>,
    pub product_name: Option<String>,
    pub product_sku: Option<String>,
    pub family: Option<String>,
    pub baseboard_manufacturer: Option<String>,
    pub baseboard_product: Option<String>,
}

/// Device type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// Device tree based device.
    Devicetree = 0,
    /// UEFI firmware device.
    UefiFw = 1,
}

/// A matched device with its descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub name: String,
    pub compatible: Option<String>,
    pub fwid: Option<String>,
    pub device_type: DeviceType,
}

/// Test fixture entry for CHID matching.
#[derive(Debug, Clone)]
pub struct TestInfo {
    pub smbios_info: RawSmbiosInfo,
    pub panel_id: Option<String>,
    pub device_type: DeviceType,
}

/// Expected match result for a test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedResult {
    pub name: String,
    pub compatible: Option<String>,
    pub fwid: Option<String>,
}

/// Error for CHID match operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChidMatchError {
    /// No matching device found.
    NoMatch,
    /// Unsupported architecture (big-endian).
    UnsupportedArch,
    /// Invalid device descriptor.
    InvalidDescriptor,
}

impl std::fmt::Display for ChidMatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChidMatchError::NoMatch => write!(f, "no matching device"),
            ChidMatchError::UnsupportedArch => write!(f, "unsupported architecture"),
            ChidMatchError::InvalidDescriptor => write!(f, "invalid device descriptor"),
        }
    }
}

impl std::error::Error for ChidMatchError {}

// ── Test data ─────────────────────────────────────────────────────────────

/// Build the standard set of test fixtures matching the C test data.
pub fn build_test_info_table() -> Vec<TestInfo> {
    vec![
        TestInfo {
            smbios_info: RawSmbiosInfo {
                manufacturer: Some("First Vendor".into()),
                product_name: Some("Device 1".into()),
                product_sku: Some("KD01".into()),
                family: Some("Laptop X".into()),
                baseboard_product: Some("FODM1".into()),
                baseboard_manufacturer: Some("First ODM".into()),
            },
            panel_id: Some("TST42".into()),
            device_type: DeviceType::Devicetree,
        },
        TestInfo {
            smbios_info: RawSmbiosInfo {
                manufacturer: Some("Second Vendor".into()),
                product_name: Some("Device 2".into()),
                product_sku: Some("KD02".into()),
                family: Some("Laptop 2".into()),
                baseboard_product: Some("SODM2".into()),
                baseboard_manufacturer: Some("Second ODM".into()),
            },
            panel_id: None,
            device_type: DeviceType::Devicetree,
        },
        TestInfo {
            smbios_info: RawSmbiosInfo {
                manufacturer: Some("First Vendor".into()),
                product_name: Some("Device 3".into()),
                product_sku: Some("KD03".into()),
                family: Some("Tablet Y".into()),
                baseboard_product: Some("FODM2".into()),
                baseboard_manufacturer: Some("First ODM".into()),
            },
            panel_id: None,
            device_type: DeviceType::Devicetree,
        },
        TestInfo {
            smbios_info: RawSmbiosInfo {
                manufacturer: Some("VMware, Inc.".into()),
                product_name: Some("VMware20,1".into()),
                product_sku: Some("0000000000000001".into()),
                family: Some("VMware".into()),
                baseboard_product: Some("VBSA".into()),
                baseboard_manufacturer: Some("VMware, Inc.".into()),
            },
            panel_id: None,
            device_type: DeviceType::UefiFw,
        },
    ]
}

/// Build the expected results for the standard test fixtures.
pub fn build_expected_results() -> Vec<ExpectedResult> {
    vec![
        ExpectedResult {
            name: "Device 1".into(),
            compatible: Some("test,device-1".into()),
            fwid: None,
        },
        ExpectedResult {
            name: "Device 2".into(),
            compatible: Some("test,device-2".into()),
            fwid: None,
        },
        ExpectedResult {
            name: "Device 3".into(),
            compatible: Some("test,device-3".into()),
            fwid: None,
        },
        ExpectedResult {
            name: "Device 4".into(),
            compatible: None,
            fwid: Some("test,vmware".into()),
        },
    ]
}

// ── Intro check ───────────────────────────────────────────────────────────

/// Check if CHID matching can run on this architecture.
/// Mirrors `intro()` in C: only little-endian supported.
pub fn can_run_chid_match() -> bool {
    cfg!(target_endian = "little")
}

// ── SMBIOS mock ───────────────────────────────────────────────────────────

/// Thread-local mock SMBIOS info for testing.
#[derive(Debug, Clone, Default)]
pub struct MockSmbiosState {
    pub current_info: RawSmbiosInfo,
    pub current_panel: Option<String>,
}

impl MockSmbiosState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_info(&mut self, info: &TestInfo) {
        self.current_info = info.smbios_info.clone();
        self.current_panel = info.panel_id.clone();
    }

    pub fn get_cached_info(&self) -> RawSmbiosInfo {
        self.current_info.clone()
    }

    pub fn get_panel_id(&self) -> Option<String> {
        self.current_panel.clone()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_test_info_count() {
        let info = build_test_info_table();
        assert_eq!(info.len(), 4);
    }

    #[test]
    fn test_build_expected_results_count() {
        let results = build_expected_results();
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn test_first_vendor_device1() {
        let info = build_test_info_table();
        assert_eq!(
            info[0].smbios_info.manufacturer,
            Some("First Vendor".into())
        );
        assert_eq!(info[0].smbios_info.product_name, Some("Device 1".into()));
        assert_eq!(info[0].device_type, DeviceType::Devicetree);
    }

    #[test]
    fn test_second_vendor_device2() {
        let info = build_test_info_table();
        assert_eq!(
            info[1].smbios_info.manufacturer,
            Some("Second Vendor".into())
        );
        assert_eq!(info[1].device_type, DeviceType::Devicetree);
    }

    #[test]
    fn test_vmware_device() {
        let info = build_test_info_table();
        assert_eq!(
            info[3].smbios_info.manufacturer,
            Some("VMware, Inc.".into())
        );
        assert_eq!(info[3].device_type, DeviceType::UefiFw);
    }

    #[test]
    fn test_expected_result_device1() {
        let results = build_expected_results();
        assert_eq!(results[0].name, "Device 1");
        assert_eq!(results[0].compatible, Some("test,device-1".into()));
        assert_eq!(results[0].fwid, None);
    }

    #[test]
    fn test_expected_result_vmware() {
        let results = build_expected_results();
        assert_eq!(results[3].name, "Device 4");
        assert_eq!(results[3].compatible, None);
        assert_eq!(results[3].fwid, Some("test,vmware".into()));
    }

    #[test]
    fn test_mock_smbios_state() {
        let mut state = MockSmbiosState::new();
        let info = build_test_info_table();
        state.set_info(&info[0]);
        let cached = state.get_cached_info();
        assert_eq!(cached.manufacturer, Some("First Vendor".into()));
        assert_eq!(state.get_panel_id(), Some("TST42".into()));
    }

    #[test]
    fn test_mock_smbios_state_no_panel() {
        let mut state = MockSmbiosState::new();
        let info = build_test_info_table();
        state.set_info(&info[1]);
        assert!(state.get_panel_id().is_none());
    }

    #[test]
    fn test_can_run_chid_match() {
        // Should always return true on little-endian (x86, aarch64)
        // and false on big-endian (s390x, etc.)
        let result = can_run_chid_match();
        assert_eq!(result, cfg!(target_endian = "little"));
    }
}
