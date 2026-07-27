// SPDX-License-Identifier: LGPL-2.1-or-later

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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManagerProperties {
    pub version: String,
    pub virtualization: String,
    pub architecture: String,
}
