// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-blkid.c
//
// Block-device signature metadata helpers.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlkidProbe {
    pub fs_type: String,
    pub fs_uuid: Option<String>,
    pub fs_label: Option<String>,
    pub partition_table: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlkidError { MissingFilesystemType }
pub type Result<T> = std::result::Result<T, BlkidError>;

pub fn build_blkid_properties(probe: BlkidProbe) -> Result<BTreeMap<String, String>> {
    if probe.fs_type.trim().is_empty() { return Err(BlkidError::MissingFilesystemType); }
    let mut map = BTreeMap::from([("ID_FS_TYPE".into(), probe.fs_type)]);
    if let Some(uuid) = probe.fs_uuid { map.insert("ID_FS_UUID".into(), uuid); }
    if let Some(label) = probe.fs_label { map.insert("ID_FS_LABEL".into(), label); }
    if let Some(table) = probe.partition_table { map.insert("ID_PART_TABLE_TYPE".into(), table); }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn exports_detected_metadata() { let props = build_blkid_properties(BlkidProbe { fs_type: "ext4".into(), fs_uuid: Some("uuid".into()), fs_label: Some("root".into()), partition_table: Some("gpt".into()) }).unwrap(); assert_eq!(props["ID_FS_TYPE"], "ext4"); assert_eq!(props["ID_PART_TABLE_TYPE"], "gpt"); }
    #[test] fn rejects_missing_fs_type() { assert_eq!(build_blkid_properties(BlkidProbe { fs_type: " ".into(), fs_uuid: None, fs_label: None, partition_table: None }), Err(BlkidError::MissingFilesystemType)); }
}
