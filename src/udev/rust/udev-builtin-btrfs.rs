// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-btrfs.c
//
// Btrfs-specific udev property synthesis.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtrfsError { MissingUuid, EmptyValue }
pub type Result<T> = std::result::Result<T, BtrfsError>;

pub fn collect_btrfs_properties(uuid: &str, label: Option<&str>) -> Result<BTreeMap<String, String>> {
    if uuid.is_empty() { return Err(BtrfsError::MissingUuid); }
    let mut properties = BTreeMap::from([("ID_FS_TYPE".into(), "btrfs".into()), ("ID_BTRFS_UUID".into(), uuid.into())]);
    if let Some(label) = label {
        if label.is_empty() { return Err(BtrfsError::EmptyValue); }
        properties.insert("ID_BTRFS_LABEL".into(), label.into());
    }
    Ok(properties)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn emits_uuid_and_label() { let props = collect_btrfs_properties("abcd", Some("rootfs")).unwrap(); assert_eq!(props["ID_BTRFS_UUID"], "abcd"); assert_eq!(props["ID_BTRFS_LABEL"], "rootfs"); }
    #[test] fn rejects_empty_uuid() { assert_eq!(collect_btrfs_properties("", None), Err(BtrfsError::MissingUuid)); }
}
