// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homework-cifs.c, src/home/homework-cifs.h

use crate::homework::{HomeSetup, HomeSetupFlags, HomeworkError};
use crate::user_record_util::UserRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CifsService {
    pub host: String,
    pub service: String,
    pub directory: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CifsError {
    ParseFailed,
    MissingService,
    MissingPassword,
}

impl std::fmt::Display for CifsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseFailed => write!(f, "failed to parse CIFS service specification"),
            Self::MissingService => write!(f, "user record lacks CIFS service"),
            Self::MissingPassword => write!(
                f,
                "failed to mount home directory, supplied password(s) possibly wrong"
            ),
        }
    }
}

impl std::error::Error for CifsError {}

impl From<CifsError> for HomeworkError {
    fn from(value: CifsError) -> Self {
        HomeworkError::MountFailed(value.to_string())
    }
}

pub fn parse_cifs_service(service: &str) -> Result<CifsService, CifsError> {
    let stripped = service
        .trim()
        .strip_prefix("//")
        .ok_or(CifsError::ParseFailed)?;
    let mut parts = stripped.split('/');
    let host = parts
        .next()
        .filter(|v| !v.is_empty())
        .ok_or(CifsError::ParseFailed)?;
    let share = parts
        .next()
        .filter(|v| !v.is_empty())
        .ok_or(CifsError::ParseFailed)?;
    let remainder = parts.collect::<Vec<_>>().join("/");
    Ok(CifsService {
        host: host.into(),
        service: share.into(),
        directory: (!remainder.is_empty()).then_some(remainder),
    })
}

pub fn home_setup_cifs(record: &UserRecord, flags: HomeSetupFlags) -> Result<HomeSetup, CifsError> {
    if record.cifs_service.is_none() {
        return Err(CifsError::MissingService);
    }
    if !matches!(flags, HomeSetupFlags::AlreadyActivated) && record.password.is_empty() {
        return Err(CifsError::MissingPassword);
    }

    let parsed = parse_cifs_service(
        record
            .cifs_service
            .as_deref()
            .ok_or(CifsError::MissingService)?,
    )?;
    let mut setup = HomeSetup::default();
    setup.undo_mount = !matches!(flags, HomeSetupFlags::AlreadyActivated);
    setup.mount_point = Some(format!("//{}/{}", parsed.host, parsed.service).into());
    Ok(setup)
}

pub fn home_activate_cifs(
    record: &UserRecord,
    flags: HomeSetupFlags,
) -> Result<UserRecord, CifsError> {
    let _setup = home_setup_cifs(record, flags)?;
    let mut cloned = record.clone();
    if let Some(service) = &record.cifs_service {
        let parsed = parse_cifs_service(service)?;
        cloned.home_directory = Some(match parsed.directory {
            Some(directory) => format!("/{directory}"),
            None => "/".into(),
        });
    }
    Ok(cloned)
}

pub fn home_create_cifs(record: &UserRecord) -> Result<UserRecord, CifsError> {
    home_activate_cifs(record, HomeSetupFlags::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> UserRecord {
        let mut record = UserRecord::new();
        record.cifs_service = Some("//server/share/home".into());
        record.password.push("Secret1!".into());
        record
    }

    #[test]
    fn parse_service_requires_prefix() {
        assert_eq!(
            parse_cifs_service("server/share"),
            Err(CifsError::ParseFailed)
        );
    }

    #[test]
    fn parse_service_requires_share_name() {
        assert_eq!(parse_cifs_service("//server"), Err(CifsError::ParseFailed));
    }

    #[test]
    fn parse_service_extracts_directory() {
        let service = parse_cifs_service("//server/share/home").unwrap();
        assert_eq!(service.host, "server");
        assert_eq!(service.service, "share");
        assert_eq!(service.directory.as_deref(), Some("home"));
    }

    #[test]
    fn setup_requires_service() {
        assert_eq!(
            home_setup_cifs(&UserRecord::new(), HomeSetupFlags::None),
            Err(CifsError::MissingService)
        );
    }

    #[test]
    fn setup_requires_password_unless_already_active() {
        let mut missing = record();
        missing.password.clear();
        assert_eq!(
            home_setup_cifs(&missing, HomeSetupFlags::None),
            Err(CifsError::MissingPassword)
        );
    }

    #[test]
    fn setup_marks_undo_mount_for_new_mounts() {
        let setup = home_setup_cifs(&record(), HomeSetupFlags::None).unwrap();
        assert!(setup.undo_mount);
    }

    #[test]
    fn setup_uses_mount_path() {
        let setup = home_setup_cifs(&record(), HomeSetupFlags::None).unwrap();
        assert_eq!(
            setup.mount_point.as_deref().and_then(|p| p.to_str()),
            Some("//server/share")
        );
    }

    #[test]
    fn activate_cifs_updates_home_directory() {
        let activated = home_activate_cifs(&record(), HomeSetupFlags::None).unwrap();
        assert_eq!(activated.home_directory.as_deref(), Some("/home"));
    }

    #[test]
    fn create_cifs_reuses_activate_logic() {
        let created = home_create_cifs(&record()).unwrap();
        assert_eq!(created.home_directory.as_deref(), Some("/home"));
    }
}
