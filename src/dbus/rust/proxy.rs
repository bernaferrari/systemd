// SPDX-License-Identifier: LGPL-2.1-or-later

use zbus::zvariant::{OwnedObjectPath, Type};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zbus::zvariant::Type)]
pub struct UnitStatus {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub followed: String,
    pub path: String,
    pub job_id: u32,
    pub job_type: String,
    pub job_path: String,
}

/// Wire representation of `org.freedesktop.systemd1.Manager.ListUnits`.
///
/// Keep [`UnitStatus`] source-compatible for Rust callers that consume paths as
/// strings, but use the D-Bus `o` type at the serialization boundary, matching
/// `a(ssssssouso)` in `src/core/dbus-manager.c`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Type)]
pub(crate) struct UnitStatusWire {
    name: String,
    description: String,
    load_state: String,
    active_state: String,
    sub_state: String,
    followed: String,
    path: OwnedObjectPath,
    job_id: u32,
    job_type: String,
    job_path: OwnedObjectPath,
}

impl UnitStatusWire {
    pub(crate) fn from_status(status: UnitStatus) -> zbus::zvariant::Result<Self> {
        let job_path = if status.job_id == 0 && status.job_path.is_empty() {
            OwnedObjectPath::try_from("/")?
        } else {
            OwnedObjectPath::try_from(status.job_path)?
        };

        Ok(Self {
            name: status.name,
            description: status.description,
            load_state: status.load_state,
            active_state: status.active_state,
            sub_state: status.sub_state,
            followed: status.followed,
            path: OwnedObjectPath::try_from(status.path)?,
            job_id: status.job_id,
            job_type: status.job_type,
            job_path,
        })
    }
}

impl From<UnitStatusWire> for UnitStatus {
    fn from(status: UnitStatusWire) -> Self {
        Self {
            name: status.name,
            description: status.description,
            load_state: status.load_state,
            active_state: status.active_state,
            sub_state: status.sub_state,
            followed: status.followed,
            path: status.path.to_string(),
            job_id: status.job_id,
            job_type: status.job_type,
            job_path: status.job_path.to_string(),
        }
    }
}

/// Wire representation of one `ListJobs` row (`(usssoo)`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Type)]
pub(crate) struct JobStatusWire {
    pub(crate) id: u32,
    pub(crate) unit_name: String,
    pub(crate) job_type: String,
    pub(crate) job_state: String,
    pub(crate) job_path: OwnedObjectPath,
    pub(crate) unit_path: OwnedObjectPath,
}

impl JobStatusWire {
    pub(crate) fn new(
        id: u32,
        unit_name: String,
        job_type: String,
        job_state: String,
        job_path: String,
        unit_path: String,
    ) -> zbus::zvariant::Result<Self> {
        Ok(Self {
            id,
            unit_name,
            job_type,
            job_state,
            job_path: OwnedObjectPath::try_from(job_path)?,
            unit_path: OwnedObjectPath::try_from(unit_path)?,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManagerProperties {
    pub version: String,
    pub virtualization: String,
    pub architecture: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_structs_match_systemd_manager_signatures() {
        assert_eq!(UnitStatusWire::SIGNATURE.to_string(), "(ssssssouso)");
        assert_eq!(JobStatusWire::SIGNATURE.to_string(), "(usssoo)");
    }
}
