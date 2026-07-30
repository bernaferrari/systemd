// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/chid.c
//
// Compatible Hardware ID (CHID) matching for device tree selection.
//
// Based on Nikita Travkin's dtbloader and Linaro's edk2 dtbloader.
// Calculates CHIDs from SMBIOS data and matches them against hardware
// ID databases to select the correct device tree.

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum number of SMBIOS fields used for CHID calculation.
pub const CHID_SMBIOS_FIELDS_MAX: usize = 7;

/// Maximum number of CHID types calculated.
pub const CHID_TYPES_MAX: usize = 12;

/// Extra CHID base index.
pub const EXTRA_CHID_BASE: usize = 11;

/// SMBIOS field indices.
pub const CHID_SMBIOS_MANUFACTURER: usize = 0;
pub const CHID_SMBIOS_PRODUCT_NAME: usize = 1;
pub const CHID_SMBIOS_PRODUCT_SKU: usize = 2;
pub const CHID_SMBIOS_FAMILY: usize = 3;
pub const CHID_SMBIOS_BASEBOARD_PRODUCT: usize = 4;
pub const CHID_SMBIOS_BASEBOARD_MANUFACTURER: usize = 5;
pub const CHID_EDID_PANEL: usize = 6;

/// Device descriptor constants.
pub const DEVICE_DESCRIPTOR_DEVICETREE: u32 = 0x1000001C;
pub const DEVICE_DESCRIPTOR_UEFI_FW: u32 = 0x2000001C;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur during CHID matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChidError {
    /// Invalid parameter passed to function.
    InvalidParameter,
    /// The hardware ID buffer has bad alignment.
    BadAlignment,
    /// Unsupported device descriptor type.
    UnsupportedDescriptor,
    /// No devices found in the hardware ID database.
    NoDevices,
    /// No matching device found.
    NotFound,
    /// Failed to populate board CHIDs.
    PopulateFailed,
}

impl std::fmt::Display for ChidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChidError::InvalidParameter => write!(f, "invalid parameter"),
            ChidError::BadAlignment => write!(f, "bad buffer alignment"),
            ChidError::UnsupportedDescriptor => write!(f, "unsupported device descriptor"),
            ChidError::NoDevices => write!(f, "no devices found"),
            ChidError::NotFound => write!(f, "no matching device found"),
            ChidError::PopulateFailed => write!(f, "failed to populate board CHIDs"),
        }
    }
}

impl std::error::Error for ChidError {}

// ── Data structures ───────────────────────────────────────────────────────

/// Raw SMBIOS information used for CHID calculation.
#[derive(Debug, Clone, Default)]
pub struct RawSmbiosInfo {
    pub manufacturer: Option<String>,
    pub product_name: Option<String>,
    pub product_sku: Option<String>,
    pub family: Option<String>,
    pub baseboard_product: Option<String>,
    pub baseboard_manufacturer: Option<String>,
    pub panel_id: Option<String>,
}

/// SMBIOS fields as normalized strings for CHID calculation.
#[derive(Debug, Clone, Default)]
pub struct SmbiosInfo {
    pub fields: [Option<String>; CHID_SMBIOS_FIELDS_MAX],
}

/// Device descriptor type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// Device tree blob.
    Devicetree,
    /// UEFI firmware.
    UefiFw,
}

impl DeviceType {
    /// Extract the device type from a descriptor value.
    pub fn from_descriptor(descriptor: u32) -> Option<DeviceType> {
        match descriptor {
            DEVICE_DESCRIPTOR_DEVICETREE => Some(DeviceType::Devicetree),
            DEVICE_DESCRIPTOR_UEFI_FW => Some(DeviceType::UefiFw),
            _ => None,
        }
    }
}

/// A single device entry from the hardware ID database.
#[derive(Debug, Clone)]
pub struct Device {
    pub descriptor: u32,
    pub chid: [u8; 16], // EFI GUID is 16 bytes
}

impl Device {
    pub const EOL_DESCRIPTOR: u32 = 0;

    pub fn device_type(&self) -> Option<DeviceType> {
        DeviceType::from_descriptor(self.descriptor)
    }
}

/// CHID match priority order (from most to least specific).
/// This mirrors the C code's `priority[]` array.
pub const CHID_PRIORITY: [usize; 11] = [
    EXTRA_CHID_BASE + 2,
    EXTRA_CHID_BASE + 1,
    EXTRA_CHID_BASE,
    3,
    6,
    8,
    10,
    4,
    5,
    7,
    9,
];

// ── Helper functions ──────────────────────────────────────────────────────

/// Convert an ASCII SMBIOS string to a stripped, hashable form.
///
/// Strips leading spaces, leading zeroes, and trailing spaces.
/// Returns a normalized string suitable for CHID calculation.
pub fn smbios_to_hashable_string(input: Option<&str>) -> String {
    let s = match input {
        Some(s) if !s.is_empty() => s,
        _ => return String::new(),
    };

    let mut chars = s.chars();

    // Strip leading spaces
    while let Some(c) = chars.clone().next() {
        if c == ' ' {
            chars.next();
        } else {
            break;
        }
    }

    // Strip leading zeroes
    while let Some(c) = chars.clone().next() {
        if c == '0' {
            chars.next();
        } else {
            break;
        }
    }

    let result: String = chars.collect();

    // Strip trailing spaces
    result.trim_end_matches(' ').to_string()
}

/// Populate SMBIOS info fields from raw SMBIOS data.
pub fn smbios_info_populate(raw: &RawSmbiosInfo) -> SmbiosInfo {
    let mut info = SmbiosInfo::default();

    let hash_or_none = |s: Option<&str>| -> Option<String> {
        let h = smbios_to_hashable_string(s);
        if h.is_empty() { None } else { Some(h) }
    };

    info.fields[CHID_SMBIOS_MANUFACTURER] = hash_or_none(raw.manufacturer.as_deref());
    info.fields[CHID_SMBIOS_PRODUCT_NAME] = hash_or_none(raw.product_name.as_deref());
    info.fields[CHID_SMBIOS_PRODUCT_SKU] = hash_or_none(raw.product_sku.as_deref());
    info.fields[CHID_SMBIOS_FAMILY] = hash_or_none(raw.family.as_deref());
    info.fields[CHID_SMBIOS_BASEBOARD_PRODUCT] = hash_or_none(raw.baseboard_product.as_deref());
    info.fields[CHID_SMBIOS_BASEBOARD_MANUFACTURER] =
        hash_or_none(raw.baseboard_manufacturer.as_deref());
    info.fields[CHID_EDID_PANEL] = raw.panel_id.clone();

    info
}

/// Count the number of valid devices in a hardware ID buffer.
///
/// Returns the count of devices before the EOL descriptor.
pub fn count_devices(devices: &[Device]) -> Result<usize, ChidError> {
    let mut count = 0;
    for dev in devices {
        if dev.descriptor == Device::EOL_DESCRIPTOR {
            break;
        }
        match dev.device_type() {
            Some(_) => count += 1,
            None => return Err(ChidError::UnsupportedDescriptor),
        }
    }
    if count == 0 {
        Err(ChidError::NoDevices)
    } else {
        Ok(count)
    }
}

/// Find a matching device in the hardware ID database by CHID.
///
/// Searches through devices in priority order, looking for a CHID match
/// with the board's computed CHIDs. Returns the index of the matching device.
pub fn chid_match(
    devices: &[Device],
    board_chids: &[[u8; 16]; CHID_TYPES_MAX],
    match_type: u32,
) -> Result<usize, ChidError> {
    let n_devices = count_devices(devices)?;

    for &priority_idx in &CHID_PRIORITY {
        if priority_idx >= CHID_TYPES_MAX {
            continue;
        }
        for (dev_idx, dev) in devices[..n_devices].iter().enumerate() {
            if DeviceType::from_descriptor(dev.descriptor).map(|t| t as u32) != Some(match_type) {
                // Check if descriptor type matches
                let dev_type_matches = match DeviceType::from_descriptor(dev.descriptor) {
                    Some(DeviceType::Devicetree) => match_type == DEVICE_DESCRIPTOR_DEVICETREE,
                    Some(DeviceType::UefiFw) => match_type == DEVICE_DESCRIPTOR_UEFI_FW,
                    None => false,
                };
                if !dev_type_matches {
                    continue;
                }
            }
            if board_chids[priority_idx] == dev.chid {
                return Ok(dev_idx);
            }
        }
    }

    Err(ChidError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smbios_to_hashable_string_none() {
        assert_eq!(smbios_to_hashable_string(None), "");
    }

    #[test]
    fn test_smbios_to_hashable_string_empty() {
        assert_eq!(smbios_to_hashable_string(Some("")), "");
    }

    #[test]
    fn test_smbios_to_hashable_string_strips_leading_spaces() {
        assert_eq!(smbios_to_hashable_string(Some("  hello")), "hello");
    }

    #[test]
    fn test_smbios_to_hashable_string_strips_leading_zeroes() {
        assert_eq!(smbios_to_hashable_string(Some("00abc")), "abc");
    }

    #[test]
    fn test_smbios_to_hashable_string_strips_trailing_spaces() {
        assert_eq!(smbios_to_hashable_string(Some("hello  ")), "hello");
    }

    #[test]
    fn test_smbios_to_hashable_string_combined() {
        assert_eq!(smbios_to_hashable_string(Some("  00test  ")), "test");
    }

    #[test]
    fn test_smbios_to_hashable_string_only_spaces_and_zeroes() {
        assert_eq!(smbios_to_hashable_string(Some(" 00  ")), "");
    }

    #[test]
    fn test_smbios_info_populate() {
        let raw = RawSmbiosInfo {
            manufacturer: Some("  Vendor ".to_string()),
            product_name: Some("Product".to_string()),
            product_sku: None,
            family: Some("001Family".to_string()),
            baseboard_product: Some("Board".to_string()),
            baseboard_manufacturer: None,
            panel_id: None,
        };
        let info = smbios_info_populate(&raw);

        assert_eq!(
            info.fields[CHID_SMBIOS_MANUFACTURER],
            Some("Vendor".to_string())
        );
        assert_eq!(
            info.fields[CHID_SMBIOS_PRODUCT_NAME],
            Some("Product".to_string())
        );
        assert_eq!(info.fields[CHID_SMBIOS_PRODUCT_SKU], None);
        assert_eq!(info.fields[CHID_SMBIOS_FAMILY], Some("1Family".to_string()));
        assert_eq!(
            info.fields[CHID_SMBIOS_BASEBOARD_PRODUCT],
            Some("Board".to_string())
        );
    }

    #[test]
    fn test_device_type_from_descriptor() {
        assert_eq!(
            DeviceType::from_descriptor(DEVICE_DESCRIPTOR_DEVICETREE),
            Some(DeviceType::Devicetree)
        );
        assert_eq!(
            DeviceType::from_descriptor(DEVICE_DESCRIPTOR_UEFI_FW),
            Some(DeviceType::UefiFw)
        );
        assert_eq!(DeviceType::from_descriptor(0), None);
    }

    #[test]
    fn test_count_devices_empty() {
        let devices: Vec<Device> = vec![Device {
            descriptor: Device::EOL_DESCRIPTOR,
            chid: [0; 16],
        }];
        assert_eq!(count_devices(&devices), Err(ChidError::NoDevices));
    }

    #[test]
    fn test_count_devices_valid() {
        let devices = vec![
            Device {
                descriptor: DEVICE_DESCRIPTOR_DEVICETREE,
                chid: [1; 16],
            },
            Device {
                descriptor: DEVICE_DESCRIPTOR_UEFI_FW,
                chid: [2; 16],
            },
            Device {
                descriptor: Device::EOL_DESCRIPTOR,
                chid: [0; 16],
            },
        ];
        assert_eq!(count_devices(&devices), Ok(2));
    }

    #[test]
    fn test_count_devices_unsupported() {
        let devices = vec![Device {
            descriptor: 0xDEAD,
            chid: [0; 16],
        }];
        assert_eq!(
            count_devices(&devices),
            Err(ChidError::UnsupportedDescriptor)
        );
    }

    #[test]
    fn test_error_display() {
        assert!(!ChidError::NotFound.to_string().is_empty());
        assert!(!ChidError::BadAlignment.to_string().is_empty());
    }
}
