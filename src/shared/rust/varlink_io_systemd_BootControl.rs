// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.BootControl.c
//
// Rust shadow of the io.systemd.BootControl varlink interface.
//
// Types for boot-loader control APIs: boot-entry enumeration, firmware
// reboot-to-UI flag management, and boot-loader installation.

// ── Constants ─────────────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.BootControl";

// ── Enums ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootEntryType {
    Type1,
    Type2,
    Loader,
    Auto,
}

impl BootEntryType {
    pub fn from_varlink(s: &str) -> Result<BootEntryType, BootControlError> {
        match s {
            "type1" => Ok(BootEntryType::Type1),
            "type2" => Ok(BootEntryType::Type2),
            "loader" => Ok(BootEntryType::Loader),
            "auto" => Ok(BootEntryType::Auto),
            _ => Err(BootControlError::NoSuchBootEntry),
        }
    }

    pub fn to_varlink(self) -> &'static str {
        match self {
            BootEntryType::Type1 => "type1",
            BootEntryType::Type2 => "type2",
            BootEntryType::Loader => "loader",
            BootEntryType::Auto => "auto",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootEntrySource {
    Esp,
    Xbootldr,
}

impl BootEntrySource {
    pub fn from_varlink(s: &str) -> Result<BootEntrySource, BootControlError> {
        match s {
            "esp" => Ok(BootEntrySource::Esp),
            "xbootldr" => Ok(BootEntrySource::Xbootldr),
            _ => Err(BootControlError::NoSuchBootEntry),
        }
    }

    pub fn to_varlink(self) -> &'static str {
        match self {
            BootEntrySource::Esp => "esp",
            BootEntrySource::Xbootldr => "xbootldr",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    New,
    Update,
}

impl Operation {
    pub fn from_varlink(s: &str) -> Result<Operation, BootControlError> {
        match s {
            "new" => Ok(Operation::New),
            "update" => Ok(Operation::Update),
            _ => Err(BootControlError::InvalidOperation),
        }
    }

    pub fn to_varlink(self) -> &'static str {
        match self {
            Operation::New => "new",
            Operation::Update => "update",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootEntryTokenType {
    MachineId,
    OsImageId,
    OsId,
    Literal,
    Auto,
}

impl BootEntryTokenType {
    pub fn from_varlink(s: &str) -> Result<BootEntryTokenType, BootControlError> {
        match s {
            "machine_id" => Ok(BootEntryTokenType::MachineId),
            "os_image_id" => Ok(BootEntryTokenType::OsImageId),
            "os_id" => Ok(BootEntryTokenType::OsId),
            "literal" => Ok(BootEntryTokenType::Literal),
            "auto" => Ok(BootEntryTokenType::Auto),
            _ => Err(BootControlError::BootEntryTokenUnavailable),
        }
    }

    pub fn to_varlink(self) -> &'static str {
        match self {
            BootEntryTokenType::MachineId => "machine_id",
            BootEntryTokenType::OsImageId => "os_image_id",
            BootEntryTokenType::OsId => "os_id",
            BootEntryTokenType::Literal => "literal",
            BootEntryTokenType::Auto => "auto",
        }
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct BootEntryAddon {
    pub global_addon: Option<String>,
    pub local_addon: Option<String>,
    pub options: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BootEntry {
    pub entry_type: BootEntryType,
    pub source: BootEntrySource,
    pub id: Option<String>,
    pub path: Option<String>,
    pub root: Option<String>,
    pub title: Option<String>,
    pub show_title: Option<String>,
    pub sort_key: Option<String>,
    pub version: Option<String>,
    pub machine_id: Option<String>,
    pub architecture: Option<String>,
    pub options: Option<String>,
    pub linux: Option<String>,
    pub efi: Option<String>,
    pub uki: Option<String>,
    pub profile: Option<i64>,
    pub initrd: Vec<String>,
    pub devicetree: Option<String>,
    pub devicetree_overlay: Vec<String>,
    pub is_reported: bool,
    pub tries_left: Option<i64>,
    pub tries_done: Option<i64>,
    pub is_default: Option<bool>,
    pub is_selected: Option<bool>,
    pub addons: Vec<BootEntryAddon>,
    pub cmdline: Option<String>,
}

impl BootEntry {
    pub fn minimal(entry_type: BootEntryType, source: BootEntrySource) -> Self {
        BootEntry {
            entry_type,
            source,
            id: None,
            path: None,
            root: None,
            title: None,
            show_title: None,
            sort_key: None,
            version: None,
            machine_id: None,
            architecture: None,
            options: None,
            linux: None,
            efi: None,
            uki: None,
            profile: None,
            initrd: Vec::new(),
            devicetree: None,
            devicetree_overlay: Vec::new(),
            is_reported: false,
            tries_left: None,
            tries_done: None,
            is_default: None,
            is_selected: None,
            addons: Vec::new(),
            cmdline: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InstallInput {
    pub operation: Operation,
    pub graceful: Option<bool>,
    pub root_file_descriptor: Option<i64>,
    pub root_directory: Option<String>,
    pub boot_entry_token_type: Option<BootEntryTokenType>,
    pub touch_variables: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetRebootToFirmwareInput {
    pub state: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetRebootToFirmwareOutput {
    pub state: bool,
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum BootControlError {
    RebootToFirmwareNotSupported,
    NoSuchBootEntry,
    NoEspFound,
    BootEntryTokenUnavailable,
    InvalidOperation,
}

impl std::fmt::Display for BootControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootControlError::RebootToFirmwareNotSupported => {
                write!(f, "RebootToFirmwareNotSupported")
            }
            BootControlError::NoSuchBootEntry => write!(f, "NoSuchBootEntry"),
            BootControlError::NoEspFound => write!(f, "NoESPFound"),
            BootControlError::BootEntryTokenUnavailable => write!(f, "BootEntryTokenUnavailable"),
            BootControlError::InvalidOperation => write!(f, "InvalidOperation"),
        }
    }
}

impl std::error::Error for BootControlError {}

// ── Methods ───────────────────────────────────────────────────────────────

pub fn validate_install_input(input: &InstallInput) -> Result<(), BootControlError> {
    let _ = input.operation.to_varlink();
    Ok(())
}

pub fn install(input: &InstallInput) -> Result<(), BootControlError> {
    validate_install_input(input)?;
    Ok(())
}

pub fn get_reboot_to_firmware(
    supported: bool,
) -> Result<GetRebootToFirmwareOutput, BootControlError> {
    if !supported {
        return Err(BootControlError::RebootToFirmwareNotSupported);
    }
    Ok(GetRebootToFirmwareOutput { state: false })
}

pub fn set_reboot_to_firmware(supported: bool, state: bool) -> Result<(), BootControlError> {
    if !supported {
        return Err(BootControlError::RebootToFirmwareNotSupported);
    }
    let _ = state;
    Ok(())
}

pub fn list_boot_entries(entries: &[BootEntry]) -> Result<&[BootEntry], BootControlError> {
    if entries.is_empty() {
        return Err(BootControlError::NoSuchBootEntry);
    }
    Ok(entries)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_entry_type_roundtrip() {
        for (s, expected) in [
            ("type1", BootEntryType::Type1),
            ("type2", BootEntryType::Type2),
            ("loader", BootEntryType::Loader),
            ("auto", BootEntryType::Auto),
        ] {
            assert_eq!(BootEntryType::from_varlink(s).unwrap(), expected);
            assert_eq!(expected.to_varlink(), s);
        }
    }

    #[test]
    fn boot_entry_type_invalid() {
        assert!(BootEntryType::from_varlink("unknown").is_err());
    }

    #[test]
    fn boot_entry_source_roundtrip() {
        assert_eq!(
            BootEntrySource::from_varlink("esp").unwrap(),
            BootEntrySource::Esp
        );
        assert_eq!(
            BootEntrySource::from_varlink("xbootldr").unwrap(),
            BootEntrySource::Xbootldr
        );
        assert_eq!(BootEntrySource::Esp.to_varlink(), "esp");
        assert_eq!(BootEntrySource::Xbootldr.to_varlink(), "xbootldr");
    }

    #[test]
    fn operation_roundtrip() {
        assert_eq!(Operation::from_varlink("new").unwrap(), Operation::New);
        assert_eq!(
            Operation::from_varlink("update").unwrap(),
            Operation::Update
        );
        assert_eq!(Operation::New.to_varlink(), "new");
        assert_eq!(Operation::Update.to_varlink(), "update");
    }

    #[test]
    fn operation_invalid() {
        assert!(Operation::from_varlink("delete").is_err());
    }

    #[test]
    fn boot_entry_token_type_roundtrip() {
        let pairs = [
            ("machine_id", BootEntryTokenType::MachineId),
            ("os_image_id", BootEntryTokenType::OsImageId),
            ("os_id", BootEntryTokenType::OsId),
            ("literal", BootEntryTokenType::Literal),
            ("auto", BootEntryTokenType::Auto),
        ];
        for (s, expected) in pairs {
            assert_eq!(BootEntryTokenType::from_varlink(s).unwrap(), expected);
            assert_eq!(expected.to_varlink(), s);
        }
    }

    #[test]
    fn boot_entry_minimal() {
        let entry = BootEntry::minimal(BootEntryType::Type1, BootEntrySource::Esp);
        assert_eq!(entry.entry_type, BootEntryType::Type1);
        assert_eq!(entry.source, BootEntrySource::Esp);
        assert!(entry.id.is_none());
        assert!(entry.initrd.is_empty());
        assert!(!entry.is_reported);
    }

    #[test]
    fn list_boot_entries_success() {
        let entries = vec![BootEntry::minimal(
            BootEntryType::Type1,
            BootEntrySource::Esp,
        )];
        let result = list_boot_entries(&entries);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn list_boot_entries_empty() {
        let result = list_boot_entries(&[]);
        assert_eq!(result.unwrap_err(), BootControlError::NoSuchBootEntry);
    }

    #[test]
    fn get_reboot_to_firmware_supported() {
        let result = get_reboot_to_firmware(true);
        assert!(result.is_ok());
    }

    #[test]
    fn get_reboot_to_firmware_unsupported() {
        let result = get_reboot_to_firmware(false);
        assert_eq!(
            result.unwrap_err(),
            BootControlError::RebootToFirmwareNotSupported
        );
    }

    #[test]
    fn set_reboot_to_firmware_supported() {
        assert!(set_reboot_to_firmware(true, true).is_ok());
    }

    #[test]
    fn set_reboot_to_firmware_unsupported() {
        assert_eq!(
            set_reboot_to_firmware(false, true).unwrap_err(),
            BootControlError::RebootToFirmwareNotSupported
        );
    }

    #[test]
    fn install_validates_ok() {
        let input = InstallInput {
            operation: Operation::New,
            graceful: None,
            root_file_descriptor: None,
            root_directory: None,
            boot_entry_token_type: None,
            touch_variables: None,
        };
        assert!(install(&input).is_ok());
    }

    #[test]
    fn error_display() {
        assert_eq!(format!("{}", BootControlError::NoEspFound), "NoESPFound");
        assert_eq!(
            format!("{}", BootControlError::BootEntryTokenUnavailable),
            "BootEntryTokenUnavailable"
        );
    }

    #[test]
    fn interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.BootControl");
    }
}
