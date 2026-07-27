// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-varlink/varlink-org.varlink.service.c

pub const ORG_VARLINK_SERVICE_INTERFACE_NAME: &str = "org.varlink.service";
pub const METHOD_GET_INFO: &str = "GetInfo";
pub const METHOD_GET_INTERFACE_DESCRIPTION: &str = "GetInterfaceDescription";
pub const ERROR_INTERFACE_NOT_FOUND: &str = "org.varlink.service.InterfaceNotFound";
pub const ERROR_METHOD_NOT_FOUND: &str = "org.varlink.service.MethodNotFound";
pub const ERROR_METHOD_NOT_IMPLEMENTED: &str = "org.varlink.service.MethodNotImplemented";
pub const ERROR_INVALID_PARAMETER: &str = "org.varlink.service.InvalidParameter";
pub const ERROR_PERMISSION_DENIED: &str = "org.varlink.service.PermissionDenied";
pub const ERROR_EXPECTED_MORE: &str = "org.varlink.service.ExpectedMore";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodSpec {
    pub name: &'static str,
    pub input_fields: &'static [&'static str],
    pub output_fields: &'static [&'static str],
}

pub const METHODS: &[MethodSpec] = &[
    MethodSpec {
        name: METHOD_GET_INFO,
        input_fields: &[],
        output_fields: &["vendor", "product", "version", "url", "interfaces"],
    },
    MethodSpec {
        name: METHOD_GET_INTERFACE_DESCRIPTION,
        input_fields: &["interface"],
        output_fields: &["description"],
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    InterfaceNotFound { interface: String },
    MethodNotFound { method: String },
    MethodNotImplemented { method: String },
    InvalidParameter { parameter: String },
    PermissionDenied,
    ExpectedMore,
}

impl ServiceError {
    pub fn error_id(&self) -> &'static str {
        match self {
            Self::InterfaceNotFound { .. } => ERROR_INTERFACE_NOT_FOUND,
            Self::MethodNotFound { .. } => ERROR_METHOD_NOT_FOUND,
            Self::MethodNotImplemented { .. } => ERROR_METHOD_NOT_IMPLEMENTED,
            Self::InvalidParameter { .. } => ERROR_INVALID_PARAMETER,
            Self::PermissionDenied => ERROR_PERMISSION_DENIED,
            Self::ExpectedMore => ERROR_EXPECTED_MORE,
        }
    }
}

pub fn method(name: &str) -> Option<&'static MethodSpec> {
    METHODS.iter().find(|method| method.name == name)
}

pub fn validate_get_info_input(fields: &[(&str, &str)]) -> Result<(), String> {
    if fields.is_empty() {
        Ok(())
    } else {
        Err("GetInfo takes no input parameters".into())
    }
}

pub fn validate_get_interface_description_input(interface: &str) -> Result<(), String> {
    if interface.is_empty() {
        Err("interface must not be empty".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_name_matches_spec() {
        assert_eq!(ORG_VARLINK_SERVICE_INTERFACE_NAME, "org.varlink.service");
    }

    #[test]
    fn get_info_method_has_expected_outputs() {
        assert_eq!(method(METHOD_GET_INFO).unwrap().output_fields.len(), 5);
    }

    #[test]
    fn get_interface_description_has_one_input() {
        assert_eq!(
            method(METHOD_GET_INTERFACE_DESCRIPTION)
                .unwrap()
                .input_fields,
            ["interface"]
        );
    }

    #[test]
    fn unknown_method_is_absent() {
        assert!(method("Missing").is_none());
    }

    #[test]
    fn interface_not_found_maps_correctly() {
        assert_eq!(
            ServiceError::InterfaceNotFound {
                interface: "io.test".into()
            }
            .error_id(),
            ERROR_INTERFACE_NOT_FOUND
        );
    }

    #[test]
    fn permission_denied_maps_correctly() {
        assert_eq!(
            ServiceError::PermissionDenied.error_id(),
            ERROR_PERMISSION_DENIED
        );
    }

    #[test]
    fn get_info_rejects_parameters() {
        assert!(validate_get_info_input(&[("x", "y")]).is_err());
    }

    #[test]
    fn interface_description_rejects_empty_input() {
        assert!(validate_get_interface_description_input("").is_err());
    }

    #[test]
    fn interface_description_accepts_non_empty_input() {
        assert!(validate_get_interface_description_input("io.test").is_ok());
    }
}
