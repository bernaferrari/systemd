// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.UserDatabase.c
//
// Varlink interface definition for io.systemd.UserDatabase
// APIs for querying user and group records.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface name for the UserDatabase service
pub const INTERFACE_NAME: &str = "io.systemd.UserDatabase";

/// Method: Retrieve user records
pub const METHOD_GET_USER_RECORD: &str = "io.systemd.UserDatabase.GetUserRecord";

/// Method: Retrieve group records
pub const METHOD_GET_GROUP_RECORD: &str = "io.systemd.UserDatabase.GetGroupRecord";

/// Method: Retrieve membership relationships
pub const METHOD_GET_MEMBERSHIPS: &str = "io.systemd.UserDatabase.GetMemberships";

/// Error: No matching record found
pub const ERROR_NO_RECORD_FOUND: &str = "io.systemd.UserDatabase.NoRecordFound";

/// Error: Service name not recognized
pub const ERROR_BAD_SERVICE: &str = "io.systemd.UserDatabase.BadService";

/// Error: Service not operational
pub const ERROR_SERVICE_NOT_AVAILABLE: &str = "io.systemd.UserDatabase.ServiceNotAvailable";

/// Error: UID/GID and name both match but different records
pub const ERROR_CONFLICTING_RECORD_FOUND: &str = "io.systemd.UserDatabase.ConflictingRecordFound";

/// Error: Enumeration not supported
pub const ERROR_ENUMERATION_NOT_SUPPORTED: &str = "io.systemd.UserDatabase.EnumerationNotSupported";

/// Error: Record matches primary key but not additional filters
pub const ERROR_NON_MATCHING_RECORD_FOUND: &str = "io.systemd.UserDatabase.NonMatchingRecordFound";

// ── Structs ───────────────────────────────────────────────────────────────

/// Parameters for GetUserRecord method
#[derive(Debug, Clone, Default)]
pub struct GetUserRecordParams {
    /// UID to look up (None = look up by name)
    pub uid: Option<i64>,
    /// User name to look up (None = look up by UID)
    pub user_name: Option<String>,
    /// Fuzzy names to search for
    pub fuzzy_names: Option<Vec<String>>,
    /// Disposition mask to limit search
    pub disposition_mask: Option<Vec<String>>,
    /// Minimum UID
    pub uid_min: Option<i64>,
    /// Maximum UID
    pub uid_max: Option<i64>,
    /// Userdb provider service name
    pub service: String,
}

impl GetUserRecordParams {
    /// Create params for UID lookup
    pub fn by_uid(uid: i64, service: impl Into<String>) -> Self {
        Self {
            uid: Some(uid),
            service: service.into(),
            ..Default::default()
        }
    }

    /// Create params for name lookup
    pub fn by_name(name: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            user_name: Some(name.into()),
            service: service.into(),
            ..Default::default()
        }
    }

    /// Validate that at least one lookup key or service is provided
    pub fn validate(&self) -> Result<(), i32> {
        if self.service.is_empty() {
            return Err(-22); // -EINVAL: service is required
        }
        if self.uid.is_none() && self.user_name.is_none() {
            // Enumeration - service must still be set
            if self.service.is_empty() {
                return Err(-22);
            }
        }
        Ok(())
    }
}

/// Parameters for GetGroupRecord method
#[derive(Debug, Clone, Default)]
pub struct GetGroupRecordParams {
    /// GID to look up
    pub gid: Option<i64>,
    /// Group name to look up
    pub group_name: Option<String>,
    /// Fuzzy names to search for
    pub fuzzy_names: Option<Vec<String>>,
    /// Disposition mask to limit search
    pub disposition_mask: Option<Vec<String>>,
    /// Minimum GID
    pub gid_min: Option<i64>,
    /// Maximum GID
    pub gid_max: Option<i64>,
    /// Userdb provider service name
    pub service: String,
}

impl GetGroupRecordParams {
    /// Create params for GID lookup
    pub fn by_gid(gid: i64, service: impl Into<String>) -> Self {
        Self {
            gid: Some(gid),
            service: service.into(),
            ..Default::default()
        }
    }

    /// Create params for name lookup
    pub fn by_name(name: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            group_name: Some(name.into()),
            service: service.into(),
            ..Default::default()
        }
    }

    /// Validate parameters
    pub fn validate(&self) -> Result<(), i32> {
        if self.service.is_empty() {
            return Err(-22);
        }
        Ok(())
    }
}

/// Parameters for GetMemberships method
#[derive(Debug, Clone, Default)]
pub struct GetMembershipsParams {
    /// User name to search memberships for
    pub user_name: Option<String>,
    /// Group name to search memberships for
    pub group_name: Option<String>,
    /// Userdb provider service name
    pub service: String,
}

impl GetMembershipsParams {
    /// Create params with required service
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            ..Default::default()
        }
    }

    /// Validate parameters
    pub fn validate(&self) -> Result<(), i32> {
        if self.service.is_empty() {
            return Err(-22);
        }
        Ok(())
    }
}

/// Result of a membership lookup
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// User name
    pub user_name: String,
    /// Group name
    pub group_name: String,
}

impl Membership {
    /// Create a new Membership
    pub fn new(user_name: impl Into<String>, group_name: impl Into<String>) -> Self {
        Self {
            user_name: user_name.into(),
            group_name: group_name.into(),
        }
    }
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Get all known method names
pub fn method_names() -> &'static [&'static str] {
    &[
        METHOD_GET_USER_RECORD,
        METHOD_GET_GROUP_RECORD,
        METHOD_GET_MEMBERSHIPS,
    ]
}

/// Get all known error names
pub fn error_names() -> &'static [&'static str] {
    &[
        ERROR_NO_RECORD_FOUND,
        ERROR_BAD_SERVICE,
        ERROR_SERVICE_NOT_AVAILABLE,
        ERROR_CONFLICTING_RECORD_FOUND,
        ERROR_ENUMERATION_NOT_SUPPORTED,
        ERROR_NON_MATCHING_RECORD_FOUND,
    ]
}

/// Check if an error name belongs to this interface
pub fn is_known_error(name: &str) -> bool {
    error_names().contains(&name)
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
        assert!(ERROR_NO_RECORD_FOUND.contains("NoRecordFound"));
        assert!(ERROR_BAD_SERVICE.contains("BadService"));
        assert!(ERROR_SERVICE_NOT_AVAILABLE.contains("ServiceNotAvailable"));
        assert!(ERROR_CONFLICTING_RECORD_FOUND.contains("ConflictingRecordFound"));
        assert!(ERROR_ENUMERATION_NOT_SUPPORTED.contains("EnumerationNotSupported"));
        assert!(ERROR_NON_MATCHING_RECORD_FOUND.contains("NonMatchingRecordFound"));
    }

    #[test]
    fn test_get_user_record_by_uid() {
        let params = GetUserRecordParams::by_uid(1000, "io.systemd.Multiplexer");
        assert_eq!(params.uid, Some(1000));
        assert!(params.user_name.is_none());
        assert_eq!(params.service, "io.systemd.Multiplexer");
    }

    #[test]
    fn test_get_user_record_by_name() {
        let params = GetUserRecordParams::by_name("root", "io.systemd.Multiplexer");
        assert!(params.uid.is_none());
        assert_eq!(params.user_name, Some("root".to_string()));
    }

    #[test]
    fn test_get_user_record_validate() {
        let params = GetUserRecordParams::by_uid(1000, "service");
        assert!(params.validate().is_ok());

        let params = GetUserRecordParams::default();
        assert!(params.validate().is_err()); // empty service
    }

    #[test]
    fn test_get_group_record_by_gid() {
        let params = GetGroupRecordParams::by_gid(100, "io.systemd.Multiplexer");
        assert_eq!(params.gid, Some(100));
    }

    #[test]
    fn test_get_group_record_by_name() {
        let params = GetGroupRecordParams::by_name("wheel", "service");
        assert_eq!(params.group_name, Some("wheel".to_string()));
    }

    #[test]
    fn test_get_memberships_params() {
        let params = GetMembershipsParams::new("io.systemd.Multiplexer")
            .validate()
            .ok();
        assert!(params.is_some());

        let params = GetMembershipsParams::default();
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_membership() {
        let m = Membership::new("user", "group");
        assert_eq!(m.user_name, "user");
        assert_eq!(m.group_name, "group");

        let m2 = Membership::new("user", "group");
        assert_eq!(m, m2);
    }

    #[test]
    fn test_method_names_list() {
        let names = method_names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&METHOD_GET_USER_RECORD));
    }

    #[test]
    fn test_error_names_list() {
        let names = error_names();
        assert_eq!(names.len(), 6);
        assert!(names.contains(&ERROR_NO_RECORD_FOUND));
        assert!(names.contains(&ERROR_NON_MATCHING_RECORD_FOUND));
    }

    #[test]
    fn test_is_known_error() {
        assert!(is_known_error("io.systemd.UserDatabase.NoRecordFound"));
        assert!(is_known_error("io.systemd.UserDatabase.BadService"));
        assert!(!is_known_error("io.systemd.UserDatabase.Unknown"));
    }

    #[test]
    fn test_get_user_record_params_default() {
        let params = GetUserRecordParams::default();
        assert!(params.uid.is_none());
        assert!(params.user_name.is_none());
        assert!(params.fuzzy_names.is_none());
        assert!(params.disposition_mask.is_none());
        assert!(params.uid_min.is_none());
        assert!(params.uid_max.is_none());
        assert!(params.service.is_empty());
    }
}
