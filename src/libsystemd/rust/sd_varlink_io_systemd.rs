// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-varlink/varlink-io.systemd.c

pub const SD_VARLINK_ERROR_PERMISSION_DENIED: &str = "org.varlink.service.PermissionDenied";
pub const VL_ERROR_DISCONNECTED: &str = "io.systemd.Disconnected";
pub const VL_ERROR_TIMED_OUT: &str = "io.systemd.TimedOut";
pub const VL_ERROR_PROTOCOL: &str = "io.systemd.Protocol";
pub const VL_ERROR_SYSTEM: &str = "io.systemd.System";
pub const IO_SYSTEMD_INTERFACE_NAME: &str = "io.systemd";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSpec {
    pub name: &'static str,
    pub nullable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalError {
    pub name: &'static str,
    pub fields: &'static [FieldSpec],
}

const SYSTEM_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "origin",
        nullable: true,
    },
    FieldSpec {
        name: "errnoName",
        nullable: true,
    },
    FieldSpec {
        name: "errno",
        nullable: true,
    },
];

pub const LOCAL_ERRORS: &[LocalError] = &[
    LocalError {
        name: VL_ERROR_DISCONNECTED,
        fields: &[],
    },
    LocalError {
        name: VL_ERROR_TIMED_OUT,
        fields: &[],
    },
    LocalError {
        name: VL_ERROR_PROTOCOL,
        fields: &[],
    },
    LocalError {
        name: VL_ERROR_SYSTEM,
        fields: SYSTEM_FIELDS,
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemError {
    pub origin: Option<String>,
    pub errno_name: Option<String>,
    pub errno: Option<i64>,
}

impl SystemError {
    pub fn new(errno_name: String, errno: i64) -> Self {
        Self {
            origin: Some("linux".into()),
            errno_name: Some(errno_name),
            errno: Some(errno),
        }
    }

    pub fn from_errno(errno: i32) -> Self {
        Self::new(errno_to_name(errno), errno as i64)
    }
}

pub fn errno_to_name(errno: i32) -> String {
    match errno {
        1 => "EPERM".into(),
        2 => "ENOENT".into(),
        5 => "EIO".into(),
        12 => "ENOMEM".into(),
        13 => "EACCES".into(),
        16 => "EBUSY".into(),
        17 => "EEXIST".into(),
        22 => "EINVAL".into(),
        110 => "ETIMEDOUT".into(),
        111 => "ECONNREFUSED".into(),
        _ => format!("UNKNOWN({errno})"),
    }
}

pub fn local_error(name: &str) -> Option<&'static LocalError> {
    LOCAL_ERRORS.iter().find(|error| error.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_name_is_stable() {
        assert_eq!(IO_SYSTEMD_INTERFACE_NAME, "io.systemd");
    }

    #[test]
    fn local_error_ids_are_stable() {
        assert_eq!(VL_ERROR_PROTOCOL, "io.systemd.Protocol");
    }

    #[test]
    fn errno_name_maps_einval() {
        assert_eq!(errno_to_name(22), "EINVAL");
    }

    #[test]
    fn errno_name_maps_unknown() {
        assert_eq!(errno_to_name(9999), "UNKNOWN(9999)");
    }

    #[test]
    fn system_error_new_sets_linux_origin() {
        assert_eq!(
            SystemError::new("ENOENT".into(), 2).origin.as_deref(),
            Some("linux")
        );
    }

    #[test]
    fn system_error_from_errno_uses_mapping() {
        assert_eq!(
            SystemError::from_errno(13).errno_name.as_deref(),
            Some("EACCES")
        );
    }

    #[test]
    fn local_system_error_has_three_nullable_fields() {
        let err = local_error(VL_ERROR_SYSTEM).unwrap();
        assert_eq!(err.fields.len(), 3);
        assert!(err.fields.iter().all(|field| field.nullable));
    }

    #[test]
    fn disconnected_has_no_payload() {
        assert!(
            local_error(VL_ERROR_DISCONNECTED)
                .unwrap()
                .fields
                .is_empty()
        );
    }

    #[test]
    fn unknown_local_error_is_none() {
        assert!(local_error("io.systemd.Missing").is_none());
    }
}
