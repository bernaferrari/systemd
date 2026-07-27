// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/tpm2-event-log.c, src/shared/tpm2-event-log.h
//
// TPM2 PC Client event log type definitions and lookup utilities.
//
// Provides event type constants and bidirectional string conversion
// per the TCG PC Client Specific Platform Firmware Profile Specification,
// section 10.4.1 "Event Types".

// ── Event Type Constants ────────────────────────────────────────────────────

/// Pre-boot certificate event.
pub const EV_PREBOOT_CERT: u32 = 0x00000000;
/// POST code event.
pub const EV_POST_CODE: u32 = 0x00000001;
/// No action event.
pub const EV_NO_ACTION: u32 = 0x00000003;
/// Separator event.
pub const EV_SEPARATOR: u32 = 0x00000004;
/// Action event.
pub const EV_ACTION: u32 = 0x00000005;
/// Event tag event.
pub const EV_EVENT_TAG: u32 = 0x00000006;
/// S-CRTM contents event.
pub const EV_S_CRTM_CONTENTS: u32 = 0x00000007;
/// S-CRTM version event.
pub const EV_S_CRTM_VERSION: u32 = 0x00000008;
/// CPU microcode event.
pub const EV_CPU_MICROCODE: u32 = 0x00000009;
/// Platform config flags event.
pub const EV_PLATFORM_CONFIG_FLAGS: u32 = 0x0000000a;
/// Table of devices event.
pub const EV_TABLE_OF_DEVICES: u32 = 0x0000000b;
/// Compact hash event.
pub const EV_COMPACT_HASH: u32 = 0x0000000c;
/// IPL event.
pub const EV_IPL: u32 = 0x0000000d;
/// IPL partition data event.
pub const EV_IPL_PARTITION_DATA: u32 = 0x0000000e;
/// Non-host code event.
pub const EV_NONHOST_CODE: u32 = 0x0000000f;
/// Non-host config event.
pub const EV_NONHOST_CONFIG: u32 = 0x00000010;
/// Non-host info event.
pub const EV_NONHOST_INFO: u32 = 0x00000011;
/// Omit boot device events.
pub const EV_OMIT_BOOT_DEVICE_EVENTS: u32 = 0x00000012;

/// Base value for EFI events (not a usable event type itself).
pub const EV_EFI_EVENT_BASE: u32 = 0x80000000;
/// EFI variable driver config event.
pub const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x80000001;
/// EFI variable boot event.
pub const EV_EFI_VARIABLE_BOOT: u32 = 0x80000002;
/// EFI boot services application event.
pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x80000003;
/// EFI boot services driver event.
pub const EV_EFI_BOOT_SERVICES_DRIVER: u32 = 0x80000004;
/// EFI runtime services driver event.
pub const EV_EFI_RUNTIME_SERVICES_DRIVER: u32 = 0x80000005;
/// EFI GPT event.
pub const EV_EFI_GPT_EVENT: u32 = 0x80000006;
/// EFI action event.
pub const EV_EFI_ACTION: u32 = 0x80000007;
/// EFI platform firmware blob event.
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB: u32 = 0x80000008;
/// EFI handoff tables event.
pub const EV_EFI_HANDOFF_TABLES: u32 = 0x80000009;
/// EFI platform firmware blob2 event.
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB2: u32 = 0x8000000a;
/// EFI handoff tables2 event.
pub const EV_EFI_HANDOFF_TABLES2: u32 = 0x8000000b;
/// EFI variable boot2 event.
pub const EV_EFI_VARIABLE_BOOT2: u32 = 0x8000000c;
/// EFI HCRTM event.
pub const EV_EFI_HCRTM_EVENT: u32 = 0x80000010;
/// EFI variable authority event.
pub const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x800000e0;
/// EFI SPDM firmware blob event.
pub const EV_EFI_SPDM_FIRMWARE_BLOB: u32 = 0x800000e1;
/// EFI SPDM firmware config event.
pub const EV_EFI_SPDM_FIRMWARE_CONFIG: u32 = 0x800000e2;

/// INITRD event tag ID (from Linux kernel efistub.h).
pub const INITRD_EVENT_TAG_ID: u32 = 0x8f3b22ec;
/// Load options event tag ID (from Linux kernel efistub.h).
pub const LOAD_OPTIONS_EVENT_TAG_ID: u32 = 0x8f3b22ed;

// ── Event Type Enum ─────────────────────────────────────────────────────────

/// TPM2 log event types as defined by the TCG PC Client Platform Firmware Profile.
///
/// Note: `EV_EFI_EVENT_BASE` (0x80000000) is intentionally excluded because it
/// is a base value for other events, not a valid event type itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Tpm2EventType {
    PrebootCert = EV_PREBOOT_CERT,
    PostCode = EV_POST_CODE,
    NoAction = EV_NO_ACTION,
    Separator = EV_SEPARATOR,
    Action = EV_ACTION,
    EventTag = EV_EVENT_TAG,
    SCrtmContents = EV_S_CRTM_CONTENTS,
    SCrtmVersion = EV_S_CRTM_VERSION,
    CpuMicrocode = EV_CPU_MICROCODE,
    PlatformConfigFlags = EV_PLATFORM_CONFIG_FLAGS,
    TableOfDevices = EV_TABLE_OF_DEVICES,
    CompactHash = EV_COMPACT_HASH,
    Ipl = EV_IPL,
    IplPartitionData = EV_IPL_PARTITION_DATA,
    NonHostCode = EV_NONHOST_CODE,
    NonHostConfig = EV_NONHOST_CONFIG,
    NonHostInfo = EV_NONHOST_INFO,
    OmitBootDeviceEvents = EV_OMIT_BOOT_DEVICE_EVENTS,
    EfiVariableDriverConfig = EV_EFI_VARIABLE_DRIVER_CONFIG,
    EfiVariableBoot = EV_EFI_VARIABLE_BOOT,
    EfiBootServicesApplication = EV_EFI_BOOT_SERVICES_APPLICATION,
    EfiBootServicesDriver = EV_EFI_BOOT_SERVICES_DRIVER,
    EfiRuntimeServicesDriver = EV_EFI_RUNTIME_SERVICES_DRIVER,
    EfiGptEvent = EV_EFI_GPT_EVENT,
    EfiAction = EV_EFI_ACTION,
    EfiPlatformFirmwareBlob = EV_EFI_PLATFORM_FIRMWARE_BLOB,
    EfiHandoffTables = EV_EFI_HANDOFF_TABLES,
    EfiPlatformFirmwareBlob2 = EV_EFI_PLATFORM_FIRMWARE_BLOB2,
    EfiHandoffTables2 = EV_EFI_HANDOFF_TABLES2,
    EfiVariableBoot2 = EV_EFI_VARIABLE_BOOT2,
    EfiHcrtmEvent = EV_EFI_HCRTM_EVENT,
    EfiVariableAuthority = EV_EFI_VARIABLE_AUTHORITY,
    EfiSpdmFirmwareBlob = EV_EFI_SPDM_FIRMWARE_BLOB,
    EfiSpdmFirmwareConfig = EV_EFI_SPDM_FIRMWARE_CONFIG,
}

impl Tpm2EventType {
    /// Convert a raw `u32` event type code into a [`Tpm2EventType`] variant.
    ///
    /// Returns `None` if the code does not correspond to any known event type.
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            EV_PREBOOT_CERT => Some(Self::PrebootCert),
            EV_POST_CODE => Some(Self::PostCode),
            EV_NO_ACTION => Some(Self::NoAction),
            EV_SEPARATOR => Some(Self::Separator),
            EV_ACTION => Some(Self::Action),
            EV_EVENT_TAG => Some(Self::EventTag),
            EV_S_CRTM_CONTENTS => Some(Self::SCrtmContents),
            EV_S_CRTM_VERSION => Some(Self::SCrtmVersion),
            EV_CPU_MICROCODE => Some(Self::CpuMicrocode),
            EV_PLATFORM_CONFIG_FLAGS => Some(Self::PlatformConfigFlags),
            EV_TABLE_OF_DEVICES => Some(Self::TableOfDevices),
            EV_COMPACT_HASH => Some(Self::CompactHash),
            EV_IPL => Some(Self::Ipl),
            EV_IPL_PARTITION_DATA => Some(Self::IplPartitionData),
            EV_NONHOST_CODE => Some(Self::NonHostCode),
            EV_NONHOST_CONFIG => Some(Self::NonHostConfig),
            EV_NONHOST_INFO => Some(Self::NonHostInfo),
            EV_OMIT_BOOT_DEVICE_EVENTS => Some(Self::OmitBootDeviceEvents),
            EV_EFI_VARIABLE_DRIVER_CONFIG => Some(Self::EfiVariableDriverConfig),
            EV_EFI_VARIABLE_BOOT => Some(Self::EfiVariableBoot),
            EV_EFI_BOOT_SERVICES_APPLICATION => Some(Self::EfiBootServicesApplication),
            EV_EFI_BOOT_SERVICES_DRIVER => Some(Self::EfiBootServicesDriver),
            EV_EFI_RUNTIME_SERVICES_DRIVER => Some(Self::EfiRuntimeServicesDriver),
            EV_EFI_GPT_EVENT => Some(Self::EfiGptEvent),
            EV_EFI_ACTION => Some(Self::EfiAction),
            EV_EFI_PLATFORM_FIRMWARE_BLOB => Some(Self::EfiPlatformFirmwareBlob),
            EV_EFI_HANDOFF_TABLES => Some(Self::EfiHandoffTables),
            EV_EFI_PLATFORM_FIRMWARE_BLOB2 => Some(Self::EfiPlatformFirmwareBlob2),
            EV_EFI_HANDOFF_TABLES2 => Some(Self::EfiHandoffTables2),
            EV_EFI_VARIABLE_BOOT2 => Some(Self::EfiVariableBoot2),
            EV_EFI_HCRTM_EVENT => Some(Self::EfiHcrtmEvent),
            EV_EFI_VARIABLE_AUTHORITY => Some(Self::EfiVariableAuthority),
            EV_EFI_SPDM_FIRMWARE_BLOB => Some(Self::EfiSpdmFirmwareBlob),
            EV_EFI_SPDM_FIRMWARE_CONFIG => Some(Self::EfiSpdmFirmwareConfig),
            _ => None,
        }
    }

    /// Return the raw `u32` event type code.
    pub const fn code(self) -> u32 {
        self as u32
    }
}

impl std::fmt::Display for Tpm2EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Tpm2EventType {
    /// Return the canonical lowercase kebab-case name for this event type.
    ///
    /// These names match the strings returned by the C implementation's
    /// `tpm2_log_event_type_to_string()`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrebootCert => "preboot-cert",
            Self::PostCode => "post-code",
            Self::NoAction => "no-action",
            Self::Separator => "separator",
            Self::Action => "action",
            Self::EventTag => "event-tag",
            Self::SCrtmContents => "s-crtm-contents",
            Self::SCrtmVersion => "s-crtm-version",
            Self::CpuMicrocode => "cpu-microcode",
            Self::PlatformConfigFlags => "platform-config-flags",
            Self::TableOfDevices => "table-of-devices",
            Self::CompactHash => "compact-hash",
            Self::Ipl => "ipl",
            Self::IplPartitionData => "ipl-partition-data",
            Self::NonHostCode => "nonhost-code",
            Self::NonHostConfig => "nonhost-config",
            Self::NonHostInfo => "nonhost-info",
            Self::OmitBootDeviceEvents => "omit-boot-device-events",
            Self::EfiVariableDriverConfig => "efi-variable-driver-config",
            Self::EfiVariableBoot => "efi-variable-boot",
            Self::EfiBootServicesApplication => "efi-boot-services-application",
            Self::EfiBootServicesDriver => "efi-boot-services-driver",
            Self::EfiRuntimeServicesDriver => "efi-runtime-services-driver",
            Self::EfiGptEvent => "efi-gpt-event",
            Self::EfiAction => "efi-action",
            Self::EfiPlatformFirmwareBlob => "efi-platform-firmware-blob",
            Self::EfiHandoffTables => "efi-handoff-tables",
            Self::EfiPlatformFirmwareBlob2 => "efi-platform-firmware-blob2",
            Self::EfiHandoffTables2 => "efi-handoff-tables2",
            Self::EfiVariableBoot2 => "efi-variable-boot2",
            Self::EfiHcrtmEvent => "efi-hcrtm-event",
            Self::EfiVariableAuthority => "efi-variable-authority",
            Self::EfiSpdmFirmwareBlob => "efi-spdm-firmware-blob",
            Self::EfiSpdmFirmwareConfig => "efi-spdm-firmware-config",
        }
    }
}

// ── Event Type Lookup Table ─────────────────────────────────────────────────

/// Entry in the sorted event type lookup table.
struct EventTypeEntry {
    code: u32,
    name: &'static str,
}

/// Sorted table of event type codes to their canonical string names.
///
/// **Must remain sorted by `code`** so that `tpm2_log_event_type_to_string`
/// can perform binary search (bisection), matching the C implementation.
///
/// `EV_EFI_EVENT_BASE` (0x80000000) is intentionally excluded as it is not
/// a usable event type, just a base value.
static EVENT_TYPE_TABLE: &[EventTypeEntry] = &[
    EventTypeEntry {
        code: EV_PREBOOT_CERT,
        name: "preboot-cert",
    },
    EventTypeEntry {
        code: EV_POST_CODE,
        name: "post-code",
    },
    EventTypeEntry {
        code: EV_NO_ACTION,
        name: "no-action",
    },
    EventTypeEntry {
        code: EV_SEPARATOR,
        name: "separator",
    },
    EventTypeEntry {
        code: EV_ACTION,
        name: "action",
    },
    EventTypeEntry {
        code: EV_EVENT_TAG,
        name: "event-tag",
    },
    EventTypeEntry {
        code: EV_S_CRTM_CONTENTS,
        name: "s-crtm-contents",
    },
    EventTypeEntry {
        code: EV_S_CRTM_VERSION,
        name: "s-crtm-version",
    },
    EventTypeEntry {
        code: EV_CPU_MICROCODE,
        name: "cpu-microcode",
    },
    EventTypeEntry {
        code: EV_PLATFORM_CONFIG_FLAGS,
        name: "platform-config-flags",
    },
    EventTypeEntry {
        code: EV_TABLE_OF_DEVICES,
        name: "table-of-devices",
    },
    EventTypeEntry {
        code: EV_COMPACT_HASH,
        name: "compact-hash",
    },
    EventTypeEntry {
        code: EV_IPL,
        name: "ipl",
    },
    EventTypeEntry {
        code: EV_IPL_PARTITION_DATA,
        name: "ipl-partition-data",
    },
    EventTypeEntry {
        code: EV_NONHOST_CODE,
        name: "nonhost-code",
    },
    EventTypeEntry {
        code: EV_NONHOST_CONFIG,
        name: "nonhost-config",
    },
    EventTypeEntry {
        code: EV_NONHOST_INFO,
        name: "nonhost-info",
    },
    EventTypeEntry {
        code: EV_OMIT_BOOT_DEVICE_EVENTS,
        name: "omit-boot-device-events",
    },
    EventTypeEntry {
        code: EV_EFI_VARIABLE_DRIVER_CONFIG,
        name: "efi-variable-driver-config",
    },
    EventTypeEntry {
        code: EV_EFI_VARIABLE_BOOT,
        name: "efi-variable-boot",
    },
    EventTypeEntry {
        code: EV_EFI_BOOT_SERVICES_APPLICATION,
        name: "efi-boot-services-application",
    },
    EventTypeEntry {
        code: EV_EFI_BOOT_SERVICES_DRIVER,
        name: "efi-boot-services-driver",
    },
    EventTypeEntry {
        code: EV_EFI_RUNTIME_SERVICES_DRIVER,
        name: "efi-runtime-services-driver",
    },
    EventTypeEntry {
        code: EV_EFI_GPT_EVENT,
        name: "efi-gpt-event",
    },
    EventTypeEntry {
        code: EV_EFI_ACTION,
        name: "efi-action",
    },
    EventTypeEntry {
        code: EV_EFI_PLATFORM_FIRMWARE_BLOB,
        name: "efi-platform-firmware-blob",
    },
    EventTypeEntry {
        code: EV_EFI_HANDOFF_TABLES,
        name: "efi-handoff-tables",
    },
    EventTypeEntry {
        code: EV_EFI_PLATFORM_FIRMWARE_BLOB2,
        name: "efi-platform-firmware-blob2",
    },
    EventTypeEntry {
        code: EV_EFI_HANDOFF_TABLES2,
        name: "efi-handoff-tables2",
    },
    EventTypeEntry {
        code: EV_EFI_VARIABLE_BOOT2,
        name: "efi-variable-boot2",
    },
    EventTypeEntry {
        code: EV_EFI_HCRTM_EVENT,
        name: "efi-hcrtm-event",
    },
    EventTypeEntry {
        code: EV_EFI_VARIABLE_AUTHORITY,
        name: "efi-variable-authority",
    },
    EventTypeEntry {
        code: EV_EFI_SPDM_FIRMWARE_BLOB,
        name: "efi-spdm-firmware-blob",
    },
    EventTypeEntry {
        code: EV_EFI_SPDM_FIRMWARE_CONFIG,
        name: "efi-spdm-firmware-config",
    },
];

// ── Public Lookup Functions ─────────────────────────────────────────────────

/// Convert a TPM2 log event type code to its canonical lowercase kebab-case name.
///
/// This is the idiomatic Rust equivalent of the C function
/// `tpm2_log_event_type_to_string()`. Uses binary search over the sorted
/// event type table, matching the C implementation's bisection approach.
///
/// Returns `None` if the event type code is not recognized.
pub fn tpm2_log_event_type_to_string(event_type: u32) -> Option<&'static str> {
    EVENT_TYPE_TABLE
        .binary_search_by_key(&event_type, |entry| entry.code)
        .ok()
        .map(|idx| EVENT_TYPE_TABLE[idx].name)
}

/// Convert a canonical event type name back to its `u32` event type code.
///
/// Performs a linear scan of the event type table. Returns `None` if no
/// matching name is found.
pub fn tpm2_log_event_type_from_string(name: &str) -> Option<u32> {
    EVENT_TYPE_TABLE
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.code)
}

/// Convert a raw `u32` event type code to a [`Tpm2EventType`] enum variant.
///
/// This is a convenience wrapper around [`Tpm2EventType::from_code`].
pub fn tpm2_event_type_from_code(code: u32) -> Option<Tpm2EventType> {
    Tpm2EventType::from_code(code)
}

/// Check whether a `u32` event type code is a valid, recognized event type.
pub fn tpm2_log_event_type_is_valid(event_type: u32) -> bool {
    tpm2_log_event_type_to_string(event_type).is_some()
}

/// Return an iterator over all known event type (code, name) pairs in sorted order.
pub fn tpm2_log_event_type_iter() -> impl Iterator<Item = (u32, &'static str)> {
    EVENT_TYPE_TABLE
        .iter()
        .map(|entry| (entry.code, entry.name))
}

/// Return the number of known event types in the lookup table.
pub fn tpm2_log_event_type_count() -> usize {
    EVENT_TYPE_TABLE.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preboot_cert() {
        assert_eq!(
            tpm2_log_event_type_to_string(0x00000000),
            Some("preboot-cert")
        );
        assert_eq!(
            Tpm2EventType::from_code(0x00000000),
            Some(Tpm2EventType::PrebootCert)
        );
    }

    #[test]
    fn test_post_code() {
        assert_eq!(tpm2_log_event_type_to_string(0x00000001), Some("post-code"));
        assert_eq!(
            Tpm2EventType::from_code(0x00000001),
            Some(Tpm2EventType::PostCode)
        );
    }

    #[test]
    fn test_no_action() {
        assert_eq!(tpm2_log_event_type_to_string(0x00000003), Some("no-action"));
        assert_eq!(
            Tpm2EventType::from_code(0x00000003),
            Some(Tpm2EventType::NoAction)
        );
    }

    #[test]
    fn test_separator() {
        assert_eq!(tpm2_log_event_type_to_string(0x00000004), Some("separator"));
        assert_eq!(
            Tpm2EventType::from_code(0x00000004),
            Some(Tpm2EventType::Separator)
        );
    }

    #[test]
    fn test_efi_variable_driver_config() {
        assert_eq!(
            tpm2_log_event_type_to_string(0x80000001),
            Some("efi-variable-driver-config")
        );
        assert_eq!(
            Tpm2EventType::from_code(0x80000001),
            Some(Tpm2EventType::EfiVariableDriverConfig)
        );
    }

    #[test]
    fn test_efi_boot_services_application() {
        assert_eq!(
            tpm2_log_event_type_to_string(0x80000003),
            Some("efi-boot-services-application")
        );
    }

    #[test]
    fn test_efi_platform_firmware_blob2() {
        assert_eq!(
            tpm2_log_event_type_to_string(0x8000000a),
            Some("efi-platform-firmware-blob2")
        );
    }

    #[test]
    fn test_efi_hcrtm_event() {
        assert_eq!(
            tpm2_log_event_type_to_string(0x80000010),
            Some("efi-hcrtm-event")
        );
    }

    #[test]
    fn test_efi_variable_authority() {
        assert_eq!(
            tpm2_log_event_type_to_string(0x800000e0),
            Some("efi-variable-authority")
        );
    }

    #[test]
    fn test_efi_spdm_firmware_config() {
        assert_eq!(
            tpm2_log_event_type_to_string(0x800000e2),
            Some("efi-spdm-firmware-config")
        );
    }

    #[test]
    fn test_unknown_type_returns_none() {
        assert_eq!(tpm2_log_event_type_to_string(0x00000002), None);
        assert_eq!(tpm2_log_event_type_to_string(0x00000013), None);
        assert_eq!(tpm2_log_event_type_to_string(0x7fffffff), None);
        assert_eq!(tpm2_log_event_type_to_string(0xffffffff), None);
        // EV_EFI_EVENT_BASE is a base value, not a real event type
        assert_eq!(tpm2_log_event_type_to_string(0x80000000), None);
    }

    #[test]
    fn test_from_string_valid() {
        assert_eq!(
            tpm2_log_event_type_from_string("post-code"),
            Some(EV_POST_CODE)
        );
        assert_eq!(
            tpm2_log_event_type_from_string("no-action"),
            Some(EV_NO_ACTION)
        );
        assert_eq!(
            tpm2_log_event_type_from_string("efi-variable-boot"),
            Some(EV_EFI_VARIABLE_BOOT)
        );
        assert_eq!(
            tpm2_log_event_type_from_string("efi-spdm-firmware-blob"),
            Some(EV_EFI_SPDM_FIRMWARE_BLOB)
        );
    }

    #[test]
    fn test_from_string_invalid() {
        assert_eq!(tpm2_log_event_type_from_string(""), None);
        assert_eq!(tpm2_log_event_type_from_string("nonexistent"), None);
        assert_eq!(tpm2_log_event_type_from_string("EV_POST_CODE"), None);
        assert_eq!(tpm2_log_event_type_from_string("Post-Code"), None);
    }

    #[test]
    fn test_roundtrip_code_to_string_to_code() {
        for entry in EVENT_TYPE_TABLE {
            assert_eq!(tpm2_log_event_type_to_string(entry.code), Some(entry.name));
            assert_eq!(
                tpm2_log_event_type_from_string(entry.name),
                Some(entry.code)
            );
        }
    }

    #[test]
    fn test_enum_display() {
        assert_eq!(format!("{}", Tpm2EventType::PostCode), "post-code");
        assert_eq!(format!("{}", Tpm2EventType::NoAction), "no-action");
        assert_eq!(
            format!("{}", Tpm2EventType::EfiBootServicesApplication),
            "efi-boot-services-application"
        );
    }

    #[test]
    fn test_enum_as_str() {
        assert_eq!(Tpm2EventType::PrebootCert.as_str(), "preboot-cert");
        assert_eq!(Tpm2EventType::Ipl.as_str(), "ipl");
        assert_eq!(Tpm2EventType::EfiAction.as_str(), "efi-action");
    }

    #[test]
    fn test_enum_code_roundtrip() {
        for entry in EVENT_TYPE_TABLE {
            let variant = Tpm2EventType::from_code(entry.code).unwrap();
            assert_eq!(variant.code(), entry.code);
        }
    }

    #[test]
    fn test_is_valid() {
        assert!(tpm2_log_event_type_is_valid(EV_PREBOOT_CERT));
        assert!(tpm2_log_event_type_is_valid(EV_SEPARATOR));
        assert!(tpm2_log_event_type_is_valid(EV_EFI_SPDM_FIRMWARE_CONFIG));
        assert!(!tpm2_log_event_type_is_valid(0x00000002));
        assert!(!tpm2_log_event_type_is_valid(0x00000013));
        assert!(!tpm2_log_event_type_is_valid(0x80000000));
    }

    #[test]
    fn test_event_type_iter_count() {
        let all: Vec<_> = tpm2_log_event_type_iter().collect();
        assert_eq!(all.len(), tpm2_log_event_type_count());
        assert_eq!(all.len(), EVENT_TYPE_TABLE.len());
    }

    #[test]
    fn test_event_type_iter_sorted() {
        let codes: Vec<u32> = tpm2_log_event_type_iter().map(|(c, _)| c).collect();
        let mut sorted = codes.clone();
        sorted.sort();
        assert_eq!(
            codes, sorted,
            "event type table must be sorted for binary search"
        );
    }

    #[test]
    fn test_constants_match_enum() {
        // Verify all constant values match the enum discriminants
        let variant = Tpm2EventType::PrebootCert;
        assert_eq!(variant.code(), EV_PREBOOT_CERT);

        let variant = Tpm2EventType::EfiSpdmFirmwareConfig;
        assert_eq!(variant.code(), EV_EFI_SPDM_FIRMWARE_CONFIG);
    }

    #[test]
    fn test_kernel_event_tag_ids() {
        assert_eq!(INITRD_EVENT_TAG_ID, 0x8f3b22ec);
        assert_eq!(LOAD_OPTIONS_EVENT_TAG_ID, 0x8f3b22ed);
    }

    #[test]
    fn test_handoff_tables2_has_distinct_name() {
        assert_eq!(
            tpm2_log_event_type_to_string(EV_EFI_HANDOFF_TABLES),
            Some("efi-handoff-tables")
        );
        assert_eq!(
            tpm2_log_event_type_to_string(EV_EFI_HANDOFF_TABLES2),
            Some("efi-handoff-tables2")
        );
    }
}
