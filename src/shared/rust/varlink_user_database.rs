// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.UserDatabase.c
//
// Varlink interface definition for io.systemd.UserDatabase
// APIs for querying user and group records.

pub const INTERFACE_NAME: &str = "io.systemd.UserDatabase";

pub const METHOD_GET_USER_RECORD: &str = "io.systemd.UserDatabase.GetUserRecord";
pub const METHOD_GET_GROUP_RECORD: &str = "io.systemd.UserDatabase.GetGroupRecord";
pub const METHOD_GET_MEMBERSHIPS: &str = "io.systemd.UserDatabase.GetMemberships";

pub const ERROR_NO_RECORD_FOUND: &str = "io.systemd.UserDatabase.NoRecordFound";
pub const ERROR_BAD_SERVICE: &str = "io.systemd.UserDatabase.BadService";
pub const ERROR_SERVICE_NOT_AVAILABLE: &str = "io.systemd.UserDatabase.ServiceNotAvailable";
pub const ERROR_CONFLICTING_RECORD_FOUND: &str = "io.systemd.UserDatabase.ConflictingRecordFound";
pub const ERROR_ENUMERATION_NOT_SUPPORTED: &str = "io.systemd.UserDatabase.EnumerationNotSupported";
pub const ERROR_NON_MATCHING_RECORD_FOUND: &str = "io.systemd.UserDatabase.NonMatchingRecordFound";

pub const PARAM_UID: &str = "uid";
pub const PARAM_GID: &str = "gid";
pub const PARAM_USER_NAME: &str = "userName";
pub const PARAM_GROUP_NAME: &str = "groupName";
pub const PARAM_SERVICE: &str = "service";
pub const PARAM_RECORD: &str = "record";
pub const PARAM_INCOMPLETE: &str = "incomplete";
pub const PARAM_FUZZY_NAMES: &str = "fuzzyNames";
pub const PARAM_DISPOSITION_MASK: &str = "dispositionMask";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserDatabaseError {
    MissingServiceName,
    NoUidOrUserName,
    NoGidOrGroupName,
    UnknownMethod(String),
}

impl std::fmt::Display for UserDatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserDatabaseError::MissingServiceName => write!(f, "service name is required"),
            UserDatabaseError::NoUidOrUserName => {
                write!(f, "either uid or userName must be specified")
            }
            UserDatabaseError::NoGidOrGroupName => {
                write!(f, "either gid or groupName must be specified")
            }
            UserDatabaseError::UnknownMethod(m) => write!(f, "unknown method: {m}"),
        }
    }
}

impl std::error::Error for UserDatabaseError {}

pub fn get_interface_definition() -> &'static str {
    r#"{
  "methods": {
    "GetUserRecord": {
      "parameters": {
        "uid": { "type": "int", "nullable": true },
        "userName": { "type": "string", "nullable": true },
        "fuzzyNames": { "type": "[]string", "nullable": true },
        "dispositionMask": { "type": "[]string", "nullable": true },
        "uidMin": { "type": "int", "nullable": true },
        "uidMax": { "type": "int", "nullable": true },
        "service": { "type": "string" }
      },
      "return": {
        "record": { "type": "object" },
        "incomplete": { "type": "bool", "nullable": true }
      },
      "flags": ["more"]
    },
    "GetGroupRecord": {
      "parameters": {
        "gid": { "type": "int", "nullable": true },
        "groupName": { "type": "string", "nullable": true },
        "fuzzyNames": { "type": "[]string", "nullable": true },
        "dispositionMask": { "type": "[]string", "nullable": true },
        "gidMin": { "type": "int", "nullable": true },
        "gidMax": { "type": "int", "nullable": true },
        "service": { "type": "string" }
      },
      "return": {
        "record": { "type": "object" },
        "incomplete": { "type": "bool", "nullable": true }
      },
      "flags": ["more"]
    },
    "GetMemberships": {
      "parameters": {
        "userName": { "type": "string", "nullable": true },
        "groupName": { "type": "string", "nullable": true },
        "service": { "type": "string" }
      },
      "return": {
        "userName": { "type": "string" },
        "groupName": { "type": "string" }
      },
      "flags": ["more"]
    }
  },
  "errors": {
    "NoRecordFound": { "description": "Error indicating that no matching user or group record was found." },
    "BadService": { "description": "Error indicating that the contacted service does not implement the specified service name." },
    "ServiceNotAvailable": { "description": "Error indicating that the backing service currently is not operational." },
    "ConflictingRecordFound": { "description": "Error indicating that there's a user record matching either UID/GID or the user/group name, but not both." },
    "NonMatchingRecordFound": { "description": "Error indicating that there's a user record matching the primary UID/GID but that doesn't match additional specified matches." },
    "EnumerationNotSupported": { "description": "Error indicating that retrieval of user/group records on this service is only supported if either user/group name or UID/GID are specified." }
  },
  "interface": "io.systemd.UserDatabase",
  "description": "APIs for querying user and group records."
}"#
}

#[derive(Debug, Clone, Default)]
pub struct GetUserRecordParams {
    pub uid: Option<i64>,
    pub user_name: Option<String>,
    pub fuzzy_names: Option<Vec<String>>,
    pub disposition_mask: Option<Vec<String>>,
    pub uid_min: Option<i64>,
    pub uid_max: Option<i64>,
    pub service: Option<String>,
}

impl GetUserRecordParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn uid(mut self, uid: i64) -> Self {
        self.uid = Some(uid);
        self
    }

    pub fn user_name(mut self, name: impl Into<String>) -> Self {
        self.user_name = Some(name.into());
        self
    }

    pub fn service(mut self, svc: impl Into<String>) -> Self {
        self.service = Some(svc.into());
        self
    }

    pub fn validate(&self) -> Result<(), UserDatabaseError> {
        if self.service.is_none() || self.service.as_ref().map_or(true, |s| s.is_empty()) {
            return Err(UserDatabaseError::MissingServiceName);
        }
        if self.uid.is_none() && self.user_name.is_none() {
            return Err(UserDatabaseError::NoUidOrUserName);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct GetGroupRecordParams {
    pub gid: Option<i64>,
    pub group_name: Option<String>,
    pub fuzzy_names: Option<Vec<String>>,
    pub disposition_mask: Option<Vec<String>>,
    pub gid_min: Option<i64>,
    pub gid_max: Option<i64>,
    pub service: Option<String>,
}

impl GetGroupRecordParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn gid(mut self, gid: i64) -> Self {
        self.gid = Some(gid);
        self
    }

    pub fn group_name(mut self, name: impl Into<String>) -> Self {
        self.group_name = Some(name.into());
        self
    }

    pub fn service(mut self, svc: impl Into<String>) -> Self {
        self.service = Some(svc.into());
        self
    }

    pub fn validate(&self) -> Result<(), UserDatabaseError> {
        if self.service.is_none() || self.service.as_ref().map_or(true, |s| s.is_empty()) {
            return Err(UserDatabaseError::MissingServiceName);
        }
        if self.gid.is_none() && self.group_name.is_none() {
            return Err(UserDatabaseError::NoGidOrGroupName);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct GetMembershipsParams {
    pub user_name: Option<String>,
    pub group_name: Option<String>,
    pub service: Option<String>,
}

impl GetMembershipsParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn user_name(mut self, name: impl Into<String>) -> Self {
        self.user_name = Some(name.into());
        self
    }

    pub fn group_name(mut self, name: impl Into<String>) -> Self {
        self.group_name = Some(name.into());
        self
    }

    pub fn service(mut self, svc: impl Into<String>) -> Self {
        self.service = Some(svc.into());
        self
    }

    pub fn validate(&self) -> Result<(), UserDatabaseError> {
        if self.service.is_none() || self.service.as_ref().map_or(true, |s| s.is_empty()) {
            return Err(UserDatabaseError::MissingServiceName);
        }
        Ok(())
    }
}

pub fn validate_method_name(method: &str) -> Result<&str, UserDatabaseError> {
    match method {
        METHOD_GET_USER_RECORD | METHOD_GET_GROUP_RECORD | METHOD_GET_MEMBERSHIPS => Ok(method),
        _ => Err(UserDatabaseError::UnknownMethod(method.to_string())),
    }
}

pub fn all_error_names() -> [&'static str; 6] {
    [
        ERROR_NO_RECORD_FOUND,
        ERROR_BAD_SERVICE,
        ERROR_SERVICE_NOT_AVAILABLE,
        ERROR_CONFLICTING_RECORD_FOUND,
        ERROR_ENUMERATION_NOT_SUPPORTED,
        ERROR_NON_MATCHING_RECORD_FOUND,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.UserDatabase");
    }

    #[test]
    fn test_method_names() {
        assert_eq!(
            METHOD_GET_USER_RECORD,
            "io.systemd.UserDatabase.GetUserRecord"
        );
        assert_eq!(
            METHOD_GET_GROUP_RECORD,
            "io.systemd.UserDatabase.GetGroupRecord"
        );
        assert_eq!(
            METHOD_GET_MEMBERSHIPS,
            "io.systemd.UserDatabase.GetMemberships"
        );
    }

    #[test]
    fn test_error_names() {
        assert_eq!(
            ERROR_NO_RECORD_FOUND,
            "io.systemd.UserDatabase.NoRecordFound"
        );
        assert_eq!(ERROR_BAD_SERVICE, "io.systemd.UserDatabase.BadService");
        assert_eq!(
            ERROR_SERVICE_NOT_AVAILABLE,
            "io.systemd.UserDatabase.ServiceNotAvailable"
        );
    }

    #[test]
    fn test_all_error_names_count() {
        assert_eq!(all_error_names().len(), 6);
    }

    #[test]
    fn test_interface_definition_valid() {
        let json = get_interface_definition();
        assert!(json.contains("io.systemd.UserDatabase"));
        assert!(json.contains("GetUserRecord"));
        assert!(json.contains("GetGroupRecord"));
        assert!(json.contains("GetMemberships"));
        assert!(json.contains("NoRecordFound"));
    }

    #[test]
    fn test_get_user_record_params_valid() {
        let params = GetUserRecordParams::new()
            .uid(1000)
            .service("io.systemd.Multiplexer");
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_get_user_record_params_no_service() {
        let params = GetUserRecordParams::new().uid(1000);
        assert_eq!(
            params.validate(),
            Err(UserDatabaseError::MissingServiceName)
        );
    }

    #[test]
    fn test_get_user_record_params_no_uid_or_name() {
        let params = GetUserRecordParams::new().service("test");
        assert_eq!(params.validate(), Err(UserDatabaseError::NoUidOrUserName));
    }

    #[test]
    fn test_get_group_record_params_valid() {
        let params = GetGroupRecordParams::new()
            .gid(100)
            .service("io.systemd.Multiplexer");
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_get_group_record_params_no_gid_or_name() {
        let params = GetGroupRecordParams::new().service("test");
        assert_eq!(params.validate(), Err(UserDatabaseError::NoGidOrGroupName));
    }

    #[test]
    fn test_get_memberships_params_valid() {
        let params = GetMembershipsParams::new()
            .user_name("root")
            .service("test");
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_get_memberships_params_no_service() {
        let params = GetMembershipsParams::new().user_name("root");
        assert_eq!(
            params.validate(),
            Err(UserDatabaseError::MissingServiceName)
        );
    }

    #[test]
    fn test_validate_method_name_known() {
        assert!(validate_method_name(METHOD_GET_USER_RECORD).is_ok());
        assert!(validate_method_name(METHOD_GET_GROUP_RECORD).is_ok());
        assert!(validate_method_name(METHOD_GET_MEMBERSHIPS).is_ok());
    }

    #[test]
    fn test_validate_method_name_unknown() {
        assert!(validate_method_name("io.systemd.UserDatabase.Bogus").is_err());
    }
}
