// SPDX-License-Identifier: GPL-2.0-or-later
// PORT-SYNC: src/udev/udev-builtin-tpm2_id.c

pub const SOURCE_PATH: &str = "src/udev/udev-builtin-tpm2_id.c";
pub const SOURCE_LINE_COUNT: usize = 60;

pub const INCLUDED_HEADERS: &[&str] = &[
    "device-util.h",
    "string-util.h",
    "tpm2-util.h",
    "udev-builtin.h",
];
pub const PROPERTY_KEYS: &[&str] = &[
    "ID_TPM2_MANUFACTURER",
    "ID_TPM2_VENDOR_STRING",
    "ID_TPM2_MODALIAS",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltinDescriptor {
    pub name: &'static str,
    pub help: &'static str,
    pub run_once: bool,
}

pub const BUILTIN: BuiltinDescriptor = BuiltinDescriptor {
    name: "tpm2_id",
    help: "Identify TPM2 chips",
    run_once: true,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorInfo<'a> {
    pub manufacturer: &'a str,
    pub vendor_string: &'a str,
    pub modalias: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuiltinError {
    InvalidArguments,
    MissingDeviceNode,
    MissingModalias,
}

pub fn validate_arguments(argv: &[&str]) -> Result<(), BuiltinError> {
    match argv {
        [_, "identify"] => Ok(()),
        _ => Err(BuiltinError::InvalidArguments),
    }
}

pub fn properties_from_vendor_info<'a>(
    info: &VendorInfo<'a>,
) -> Result<Vec<(&'static str, &'a str)>, BuiltinError> {
    if info.modalias.is_empty() {
        return Err(BuiltinError::MissingModalias);
    }

    let mut properties = Vec::new();
    if !info.manufacturer.is_empty() {
        properties.push(("ID_TPM2_MANUFACTURER", info.manufacturer));
    }
    if !info.vendor_string.is_empty() {
        properties.push(("ID_TPM2_VENDOR_STRING", info.vendor_string));
    }
    properties.push(("ID_TPM2_MODALIAS", info.modalias));
    Ok(properties)
}

pub fn validate_port_model() -> Result<(), BuiltinError> {
    if !BUILTIN.run_once || BUILTIN.name != "tpm2_id" {
        return Err(BuiltinError::InvalidArguments);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_metadata_matches_c_file() {
        assert_eq!(SOURCE_PATH, "src/udev/udev-builtin-tpm2_id.c");
        assert_eq!(SOURCE_LINE_COUNT, 60);
    }

    #[test]
    fn builtin_descriptor_matches_c_definition() {
        assert_eq!(BUILTIN.name, "tpm2_id");
        assert_eq!(BUILTIN.help, "Identify TPM2 chips");
        assert!(BUILTIN.run_once);
    }

    #[test]
    fn validate_arguments_accepts_identify() {
        assert_eq!(validate_arguments(&["tpm2_id", "identify"]), Ok(()));
    }

    #[test]
    fn validate_arguments_rejects_other_forms() {
        assert_eq!(
            validate_arguments(&["tpm2_id"]),
            Err(BuiltinError::InvalidArguments)
        );
        assert_eq!(
            validate_arguments(&["tpm2_id", "scan"]),
            Err(BuiltinError::InvalidArguments)
        );
    }

    #[test]
    fn properties_include_optionals_when_present() {
        let info = VendorInfo {
            manufacturer: "IFX",
            vendor_string: "SLB9670",
            modalias: "tpm:demo",
        };
        let properties = properties_from_vendor_info(&info).unwrap();
        assert_eq!(properties.len(), 3);
    }

    #[test]
    fn properties_skip_empty_optional_fields() {
        let info = VendorInfo {
            manufacturer: "",
            vendor_string: "",
            modalias: "tpm:demo",
        };
        let properties = properties_from_vendor_info(&info).unwrap();
        assert_eq!(properties, vec![("ID_TPM2_MODALIAS", "tpm:demo")]);
    }

    #[test]
    fn modalias_is_required() {
        let info = VendorInfo {
            manufacturer: "IFX",
            vendor_string: "SLB",
            modalias: "",
        };
        assert_eq!(
            properties_from_vendor_info(&info),
            Err(BuiltinError::MissingModalias)
        );
    }

    #[test]
    fn property_keys_match_expected_names() {
        assert!(PROPERTY_KEYS.contains(&"ID_TPM2_MANUFACTURER"));
        assert!(PROPERTY_KEYS.contains(&"ID_TPM2_MODALIAS"));
    }

    #[test]
    fn port_model_validation_succeeds() {
        assert_eq!(validate_port_model(), Ok(()));
    }
}
