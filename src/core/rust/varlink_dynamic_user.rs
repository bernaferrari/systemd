// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/varlink-dynamic-user.c
//
// Dynamic user/group record lookups modelled after the varlink implementation.

use crate::ffi::Errno;

const DYNAMIC_UID_MIN: u32 = 61_184;
const DYNAMIC_UID_MAX: u32 = 65_519;
const DYNAMIC_USER_SERVICE: &str = "io.systemd.DynamicUser";
const NOLOGIN_SHELL: &str = "/usr/sbin/nologin";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicUserState {
    Realized(u32),
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicUser {
    pub name: String,
    pub state: DynamicUserState,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DynamicUserManager {
    pub dynamic_users: Vec<DynamicUser>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LookupParameters {
    pub user_name: Option<String>,
    pub group_name: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub service: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    pub user_name: String,
    pub uid: u32,
    pub gid: u32,
    pub real_name: String,
    pub home_directory: String,
    pub shell: String,
    pub locked: bool,
    pub service: String,
    pub disposition: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRecord {
    pub group_name: String,
    pub description: String,
    pub gid: u32,
    pub service: String,
    pub disposition: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicUserError {
    InvalidName,
    InvalidUid,
    InvalidGid,
    BadService,
    ConflictingRecordFound,
    NoRecordFound,
}

impl DynamicUserError {
    pub const fn errno(&self) -> i32 {
        match self {
            Self::InvalidName | Self::InvalidUid | Self::InvalidGid => Errno::EINVAL.to_neg_errno(),
            Self::BadService => Errno::EINVAL.to_neg_errno(),
            Self::ConflictingRecordFound => Errno::EEXIST.to_neg_errno(),
            Self::NoRecordFound => Errno::ESRCH.to_neg_errno(),
        }
    }
}

fn validate_name(name: &str) -> Result<(), DynamicUserError> {
    if name.is_empty() || name.bytes().any(|b| matches!(b, b'/' | 0)) {
        return Err(DynamicUserError::InvalidName);
    }
    Ok(())
}

fn uid_is_dynamic(uid: u32) -> bool {
    (DYNAMIC_UID_MIN..=DYNAMIC_UID_MAX).contains(&uid)
}

fn ensure_service(service: Option<&str>) -> Result<(), DynamicUserError> {
    if service == Some(DYNAMIC_USER_SERVICE) {
        Ok(())
    } else {
        Err(DynamicUserError::BadService)
    }
}

pub fn build_user_record(user_name: &str, uid: u32) -> Result<UserRecord, DynamicUserError> {
    validate_name(user_name)?;
    if !uid_is_dynamic(uid) {
        return Err(DynamicUserError::InvalidUid);
    }

    Ok(UserRecord {
        user_name: user_name.to_string(),
        uid,
        gid: uid,
        real_name: "Dynamic User".into(),
        home_directory: "/".into(),
        shell: NOLOGIN_SHELL.into(),
        locked: true,
        service: DYNAMIC_USER_SERVICE.into(),
        disposition: "dynamic".into(),
    })
}

pub fn build_group_record(group_name: &str, gid: u32) -> Result<GroupRecord, DynamicUserError> {
    validate_name(group_name)?;
    if !uid_is_dynamic(gid) {
        return Err(DynamicUserError::InvalidGid);
    }

    Ok(GroupRecord {
        group_name: group_name.to_string(),
        description: "Dynamic Group".into(),
        gid,
        service: DYNAMIC_USER_SERVICE.into(),
        disposition: "dynamic".into(),
    })
}

pub fn user_match_lookup_parameters(parameters: &LookupParameters, name: &str, uid: u32) -> bool {
    parameters
        .user_name
        .as_deref()
        .is_none_or(|candidate| candidate == name)
        && parameters.uid.is_none_or(|candidate| candidate == uid)
}

pub fn group_match_lookup_parameters(parameters: &LookupParameters, name: &str, gid: u32) -> bool {
    parameters
        .group_name
        .as_deref()
        .is_none_or(|candidate| candidate == name)
        && parameters.gid.is_none_or(|candidate| candidate == gid)
}

fn realized_dynamic_users(manager: &DynamicUserManager) -> impl Iterator<Item = (&str, u32)> {
    manager
        .dynamic_users
        .iter()
        .filter_map(|dynamic_user| match dynamic_user.state {
            DynamicUserState::Realized(uid) if uid_is_dynamic(uid) => {
                Some((dynamic_user.name.as_str(), uid))
            }
            DynamicUserState::Realized(_) | DynamicUserState::Pending => None,
        })
}

pub fn get_user_records(
    manager: &DynamicUserManager,
    parameters: &LookupParameters,
) -> Result<Vec<UserRecord>, DynamicUserError> {
    ensure_service(parameters.service.as_deref())?;

    if let Some(uid) = parameters.uid {
        if let Some((name, found_uid)) =
            realized_dynamic_users(manager).find(|(_, found_uid)| *found_uid == uid)
        {
            if !user_match_lookup_parameters(parameters, name, found_uid) {
                return Err(DynamicUserError::ConflictingRecordFound);
            }
            return Ok(vec![build_user_record(name, found_uid)?]);
        }

        if let Some(name) = parameters.user_name.as_deref() {
            if realized_dynamic_users(manager).any(|(candidate, _)| candidate == name) {
                return Err(DynamicUserError::ConflictingRecordFound);
            }
        }

        return Ok(Vec::new());
    }

    if let Some(name) = parameters.user_name.as_deref() {
        if let Some((found_name, uid)) =
            realized_dynamic_users(manager).find(|(candidate, _)| *candidate == name)
        {
            if !user_match_lookup_parameters(parameters, found_name, uid) {
                return Err(DynamicUserError::ConflictingRecordFound);
            }
            return Ok(vec![build_user_record(found_name, uid)?]);
        }
        return Ok(Vec::new());
    }

    realized_dynamic_users(manager)
        .filter(|(name, uid)| user_match_lookup_parameters(parameters, name, *uid))
        .map(|(name, uid)| build_user_record(name, uid))
        .collect()
}

pub fn get_group_records(
    manager: &DynamicUserManager,
    parameters: &LookupParameters,
) -> Result<Vec<GroupRecord>, DynamicUserError> {
    ensure_service(parameters.service.as_deref())?;

    if let Some(gid) = parameters.gid {
        if let Some((name, found_gid)) =
            realized_dynamic_users(manager).find(|(_, found_gid)| *found_gid == gid)
        {
            if !group_match_lookup_parameters(parameters, name, found_gid) {
                return Err(DynamicUserError::ConflictingRecordFound);
            }
            return Ok(vec![build_group_record(name, found_gid)?]);
        }
        return Ok(Vec::new());
    }

    if let Some(name) = parameters.group_name.as_deref() {
        if let Some((found_name, gid)) =
            realized_dynamic_users(manager).find(|(candidate, _)| *candidate == name)
        {
            if !group_match_lookup_parameters(parameters, found_name, gid) {
                return Err(DynamicUserError::ConflictingRecordFound);
            }
            return Ok(vec![build_group_record(found_name, gid)?]);
        }
        return Ok(Vec::new());
    }

    realized_dynamic_users(manager)
        .filter(|(name, gid)| group_match_lookup_parameters(parameters, name, *gid))
        .map(|(name, gid)| build_group_record(name, gid))
        .collect()
}

pub fn get_memberships(
    parameters: &LookupParameters,
) -> Result<Vec<(String, String)>, DynamicUserError> {
    ensure_service(parameters.service.as_deref())?;
    Err(DynamicUserError::NoRecordFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> DynamicUserManager {
        DynamicUserManager {
            dynamic_users: vec![
                DynamicUser {
                    name: "alpha".into(),
                    state: DynamicUserState::Realized(DYNAMIC_UID_MIN),
                },
                DynamicUser {
                    name: "beta".into(),
                    state: DynamicUserState::Pending,
                },
                DynamicUser {
                    name: "gamma".into(),
                    state: DynamicUserState::Realized(1000),
                },
            ],
        }
    }

    fn service_params() -> LookupParameters {
        LookupParameters {
            service: Some(DYNAMIC_USER_SERVICE.into()),
            ..LookupParameters::default()
        }
    }

    #[test]
    fn build_user_record_matches_c_shape() {
        let record = build_user_record("alpha", DYNAMIC_UID_MIN).unwrap();
        assert_eq!(record.user_name, "alpha");
        assert_eq!(record.uid, DYNAMIC_UID_MIN);
        assert_eq!(record.gid, DYNAMIC_UID_MIN);
        assert_eq!(record.real_name, "Dynamic User");
        assert!(record.locked);
    }

    #[test]
    fn build_group_record_matches_c_shape() {
        let record = build_group_record("alpha", DYNAMIC_UID_MIN).unwrap();
        assert_eq!(record.group_name, "alpha");
        assert_eq!(record.description, "Dynamic Group");
        assert_eq!(record.gid, DYNAMIC_UID_MIN);
    }

    #[test]
    fn invalid_names_are_rejected() {
        assert_eq!(
            build_user_record("", DYNAMIC_UID_MIN),
            Err(DynamicUserError::InvalidName)
        );
        assert_eq!(
            build_group_record("bad/name", DYNAMIC_UID_MIN),
            Err(DynamicUserError::InvalidName)
        );
    }

    #[test]
    fn user_lookup_skips_pending_and_nondynamic_entries() {
        let records = get_user_records(&manager(), &service_params()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].user_name, "alpha");
    }

    #[test]
    fn user_lookup_by_uid_returns_single_record() {
        let mut parameters = service_params();
        parameters.uid = Some(DYNAMIC_UID_MIN);
        let records = get_user_records(&manager(), &parameters).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].user_name, "alpha");
    }

    #[test]
    fn group_lookup_by_name_returns_single_record() {
        let mut parameters = service_params();
        parameters.group_name = Some("alpha".into());
        let records = get_group_records(&manager(), &parameters).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].gid, DYNAMIC_UID_MIN);
    }

    #[test]
    fn bad_service_is_reported() {
        let err = get_user_records(
            &manager(),
            &LookupParameters {
                service: Some("io.systemd.Other".into()),
                ..LookupParameters::default()
            },
        )
        .unwrap_err();
        assert_eq!(err, DynamicUserError::BadService);
        assert_eq!(err.errno(), Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn explicit_conflict_is_reported() {
        let err = get_user_records(
            &manager(),
            &LookupParameters {
                user_name: Some("alpha".into()),
                uid: Some(DYNAMIC_UID_MIN + 1),
                service: Some(DYNAMIC_USER_SERVICE.into()),
                ..LookupParameters::default()
            },
        )
        .unwrap_err();
        assert_eq!(err, DynamicUserError::ConflictingRecordFound);
    }

    #[test]
    fn membership_lookup_always_reports_no_record() {
        let err = get_memberships(&service_params()).unwrap_err();
        assert_eq!(err, DynamicUserError::NoRecordFound);
        assert_eq!(err.errno(), Errno::ESRCH.to_neg_errno());
    }
}
