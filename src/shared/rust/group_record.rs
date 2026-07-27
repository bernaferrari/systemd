// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/group-record.c, src/shared/group-record.h
//
// Group record handling — JSON-based group identity records.

use crate::user_record::UserDisposition;

pub const GID_INVALID: u32 = u32::MAX;
pub const GID_NOBODY: u32 = 65534;
pub const NOBODY_GROUP_NAME: &str = "nobody";

const SYSTEM_GID_MIN: u32 = 1;
const SYSTEM_GID_MAX: u32 = 999;
const DYNAMIC_GID_MIN: u32 = 61184;
const DYNAMIC_GID_MAX: u32 = 65519;
const CONTAINER_GID_MIN: u32 = 524288;
const CONTAINER_GID_MAX: u32 = 1_879_048_191;
const FOREIGN_GID_MIN: u32 = 2_147_352_576;
const FOREIGN_GID_MAX: u32 = 2_147_418_111;

pub fn gid_is_valid(gid: u32) -> bool {
    gid != GID_INVALID
}

pub fn gid_is_system(gid: u32) -> bool {
    gid >= SYSTEM_GID_MIN && gid <= SYSTEM_GID_MAX
}

pub fn gid_is_dynamic(gid: u32) -> bool {
    gid >= DYNAMIC_GID_MIN && gid <= DYNAMIC_GID_MAX
}

pub fn gid_is_container(gid: u32) -> bool {
    gid >= CONTAINER_GID_MIN && gid <= CONTAINER_GID_MAX
}

pub fn gid_is_foreign(gid: u32) -> bool {
    gid >= FOREIGN_GID_MIN && gid <= FOREIGN_GID_MAX
}

fn derive_disposition_from_gid(gid: u32) -> UserDisposition {
    if !gid_is_valid(gid) {
        return UserDisposition::Intrinsic;
    }
    if gid == 0 || gid == GID_NOBODY {
        return UserDisposition::Intrinsic;
    }
    if gid_is_system(gid) {
        return UserDisposition::System;
    }
    if gid_is_dynamic(gid) {
        return UserDisposition::Dynamic;
    }
    if gid_is_container(gid) {
        return UserDisposition::Container;
    }
    if gid_is_foreign(gid) {
        return UserDisposition::Foreign;
    }
    if gid > i32::MAX as u32 {
        return UserDisposition::Reserved;
    }
    UserDisposition::Regular
}

// ── GroupRecord ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRecord {
    pub group_name: Option<String>,
    pub realm: Option<String>,
    pub group_name_and_realm_auto: Option<String>,
    pub uuid: [u8; 16],
    pub description: Option<String>,
    pub disposition: Option<UserDisposition>,
    pub last_change_usec: u64,
    pub gid: u32,
    pub members: Vec<String>,
    pub service: Option<String>,
    pub administrators: Vec<String>,
    pub hashed_password: Vec<String>,
}

impl Default for GroupRecord {
    fn default() -> Self {
        Self {
            group_name: None,
            realm: None,
            group_name_and_realm_auto: None,
            uuid: [0u8; 16],
            description: None,
            disposition: None,
            last_change_usec: u64::MAX,
            gid: GID_INVALID,
            members: Vec::new(),
            service: None,
            administrators: Vec::new(),
            hashed_password: Vec::new(),
        }
    }
}

impl GroupRecord {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn augment(&mut self) {
        if self.group_name_and_realm_auto.is_none() {
            if let (Some(name), Some(realm)) = (&self.group_name, &self.realm) {
                self.group_name_and_realm_auto = Some(format!("{name}@{realm}"));
            }
        }
    }

    pub fn group_name_and_realm(&self) -> &str {
        match self.group_name_and_realm_auto.as_deref() {
            Some(s) => s,
            None => self.group_name.as_deref().unwrap_or(""),
        }
    }

    pub fn disposition(&self) -> UserDisposition {
        self.disposition
            .unwrap_or_else(|| derive_disposition_from_gid(self.gid))
    }

    pub fn is_root(&self) -> bool {
        self.gid == 0 || self.group_name.as_deref() == Some("root")
    }

    pub fn is_nobody(&self) -> bool {
        self.gid == GID_NOBODY
            || self.group_name.as_deref() == Some(NOBODY_GROUP_NAME)
            || self.group_name.as_deref() == Some("nobody")
    }

    pub fn matches_group_name(&self, group_name: &str) -> bool {
        self.group_name.as_deref() == Some(group_name)
            || self.group_name_and_realm_auto.as_deref() == Some(group_name)
    }

    pub fn matches_filter(
        &self,
        gid_min: Option<u32>,
        gid_max: Option<u32>,
        disposition_mask: Option<u64>,
    ) -> bool {
        if !gid_is_valid(self.gid) {
            return false;
        }
        if let Some(min) = gid_min {
            if self.gid < min {
                return false;
            }
        }
        if let Some(max) = gid_max {
            if self.gid > max {
                return false;
            }
        }
        if let Some(mask) = disposition_mask {
            if mask & (1u64 << self.disposition() as u64) == 0 {
                return false;
            }
        }
        true
    }

    pub fn clone_record(&self) -> Self {
        self.clone()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_group_record() {
        let gr = GroupRecord::new();
        assert!(gr.group_name.is_none());
        assert!(gr.members.is_empty());
        assert!(!gr.is_root());
        assert!(!gr.is_nobody());
        assert_eq!(gr.gid, GID_INVALID);
        assert_eq!(gr.last_change_usec, u64::MAX);
        assert!(gr.administrators.is_empty());
        assert!(gr.hashed_password.is_empty());
        assert!(gr.service.is_none());
        assert!(gr.realm.is_none());
        assert!(gr.description.is_none());
        assert!(gr.disposition.is_none());
        assert_eq!(gr.uuid, [0u8; 16]);
    }

    #[test]
    fn test_root_group() {
        let mut gr = GroupRecord::new();
        gr.group_name = Some("root".to_string());
        gr.gid = 0;
        assert!(gr.is_root());
    }

    #[test]
    fn test_root_group_by_gid_only() {
        let mut gr = GroupRecord::new();
        gr.gid = 0;
        assert!(gr.is_root());
    }

    #[test]
    fn test_root_group_by_name_only() {
        let mut gr = GroupRecord::new();
        gr.group_name = Some("root".to_string());
        gr.gid = GID_INVALID;
        assert!(gr.is_root());
    }

    #[test]
    fn test_nobody_group() {
        let mut gr = GroupRecord::new();
        gr.group_name = Some("nobody".to_string());
        gr.gid = GID_NOBODY;
        assert!(gr.is_nobody());
    }

    #[test]
    fn test_nobody_group_nobody_name() {
        let mut gr = GroupRecord::new();
        gr.group_name = Some(NOBODY_GROUP_NAME.to_string());
        gr.gid = 0;
        assert!(gr.is_nobody());
    }

    #[test]
    fn test_nobody_group_by_gid_only() {
        let mut gr = GroupRecord::new();
        gr.gid = GID_NOBODY;
        assert!(gr.is_nobody());
    }

    #[test]
    fn test_matches_group_name() {
        let mut gr = GroupRecord::new();
        gr.group_name = Some("wheel".to_string());
        assert!(gr.matches_group_name("wheel"));
        assert!(!gr.matches_group_name("root"));
    }

    #[test]
    fn test_matches_group_name_with_realm() {
        let mut gr = GroupRecord::new();
        gr.group_name = Some("admin".to_string());
        gr.realm = Some("example.com".to_string());
        gr.group_name_and_realm_auto = Some("admin@example.com".to_string());
        assert!(gr.matches_group_name("admin@example.com"));
        assert!(gr.matches_group_name("admin"));
    }

    #[test]
    fn test_matches_group_name_no_match() {
        let gr = GroupRecord::new();
        assert!(!gr.matches_group_name("nonexistent"));
    }

    #[test]
    fn test_disposition_from_gid() {
        assert_eq!(derive_disposition_from_gid(0), UserDisposition::Intrinsic);
        assert_eq!(
            derive_disposition_from_gid(GID_NOBODY),
            UserDisposition::Intrinsic
        );
        assert_eq!(derive_disposition_from_gid(100), UserDisposition::System);
        assert_eq!(derive_disposition_from_gid(61184), UserDisposition::Dynamic);
        assert_eq!(
            derive_disposition_from_gid(524288),
            UserDisposition::Container
        );
        assert_eq!(
            derive_disposition_from_gid(FOREIGN_GID_MIN),
            UserDisposition::Foreign
        );
        assert_eq!(derive_disposition_from_gid(1000), UserDisposition::Regular);
    }

    #[test]
    fn test_disposition_explicit() {
        let mut gr = GroupRecord::new();
        gr.disposition = Some(UserDisposition::System);
        assert_eq!(gr.disposition(), UserDisposition::System);
    }

    #[test]
    fn test_disposition_invalid_gid() {
        let gr = GroupRecord::new();
        assert_eq!(gr.disposition(), UserDisposition::Intrinsic);
    }

    #[test]
    fn test_group_name_and_realm() {
        let mut gr = GroupRecord::new();
        gr.group_name = Some("admin".to_string());
        assert_eq!(gr.group_name_and_realm(), "admin");

        gr.realm = Some("example.com".to_string());
        gr.group_name_and_realm_auto = Some("admin@example.com".to_string());
        assert_eq!(gr.group_name_and_realm(), "admin@example.com");
    }

    #[test]
    fn test_group_name_and_realm_empty() {
        let gr = GroupRecord::new();
        assert_eq!(gr.group_name_and_realm(), "");
    }

    #[test]
    fn test_gid_classification() {
        assert!(gid_is_valid(0));
        assert!(gid_is_valid(100));
        assert!(!gid_is_valid(GID_INVALID));
        assert!(gid_is_system(100));
        assert!(gid_is_system(1));
        assert!(!gid_is_system(1000));
        assert!(gid_is_dynamic(61184));
        assert!(!gid_is_dynamic(1000));
        assert!(gid_is_container(524288));
        assert!(!gid_is_container(1000));
        assert!(gid_is_foreign(FOREIGN_GID_MIN));
        assert!(!gid_is_foreign(1000));
    }

    #[test]
    fn test_gid_classification_boundaries() {
        assert!(gid_is_system(SYSTEM_GID_MIN));
        assert!(gid_is_system(SYSTEM_GID_MAX));
        assert!(!gid_is_system(SYSTEM_GID_MAX + 1));
        assert!(gid_is_dynamic(DYNAMIC_GID_MIN));
        assert!(gid_is_dynamic(DYNAMIC_GID_MAX));
        assert!(!gid_is_dynamic(DYNAMIC_GID_MAX + 1));
        assert!(gid_is_container(CONTAINER_GID_MIN));
        assert!(gid_is_container(CONTAINER_GID_MAX));
        assert!(!gid_is_container(CONTAINER_GID_MAX + 1));
        assert!(gid_is_foreign(FOREIGN_GID_MIN));
        assert!(!gid_is_foreign(FOREIGN_GID_MIN - 1));
    }

    #[test]
    fn test_augment_creates_auto_realm() {
        let mut gr = GroupRecord::new();
        gr.group_name = Some("admin".to_string());
        gr.realm = Some("example.com".to_string());
        gr.augment();
        assert_eq!(
            gr.group_name_and_realm_auto,
            Some("admin@example.com".to_string())
        );
    }

    #[test]
    fn test_augment_idempotent() {
        let mut gr = GroupRecord::new();
        gr.group_name = Some("admin".to_string());
        gr.realm = Some("example.com".to_string());
        gr.group_name_and_realm_auto = Some("preset@example.com".to_string());
        gr.augment();
        assert_eq!(
            gr.group_name_and_realm_auto,
            Some("preset@example.com".to_string())
        );
    }

    #[test]
    fn test_augment_no_realm() {
        let mut gr = GroupRecord::new();
        gr.group_name = Some("admin".to_string());
        gr.augment();
        assert!(gr.group_name_and_realm_auto.is_none());
    }

    #[test]
    fn test_clone_record() {
        let mut gr = GroupRecord::new();
        gr.group_name = Some("wheel".to_string());
        gr.gid = 10;
        gr.members.push("alice".to_string());
        gr.members.push("bob".to_string());

        let cloned = gr.clone_record();
        assert_eq!(cloned.group_name, gr.group_name);
        assert_eq!(cloned.gid, gr.gid);
        assert_eq!(cloned.members, gr.members);
        assert_eq!(cloned, gr);
    }

    #[test]
    fn test_matches_filter_no_constraints() {
        let mut gr = GroupRecord::new();
        gr.gid = 1000;
        assert!(gr.matches_filter(None, None, None));
    }

    #[test]
    fn test_matches_filter_gid_range() {
        let mut gr = GroupRecord::new();
        gr.gid = 100;
        assert!(gr.matches_filter(Some(1), Some(999), None));
        assert!(!gr.matches_filter(Some(500), Some(999), None));
        assert!(!gr.matches_filter(Some(1), Some(50), None));
    }

    #[test]
    fn test_matches_filter_disposition() {
        let mut gr = GroupRecord::new();
        gr.gid = 100;
        let mask = 1u64 << UserDisposition::System as u64;
        assert!(gr.matches_filter(None, None, Some(mask)));
        let wrong_mask = 1u64 << UserDisposition::Regular as u64;
        assert!(!gr.matches_filter(None, None, Some(wrong_mask)));
    }

    #[test]
    fn test_matches_filter_invalid_gid() {
        let gr = GroupRecord::new();
        assert!(!gr.matches_filter(None, None, None));
    }

    #[test]
    fn test_disposition_reserved() {
        assert_eq!(
            derive_disposition_from_gid(i32::MAX as u32 + 1),
            UserDisposition::Reserved
        );
        assert_eq!(
            derive_disposition_from_gid(3000000000),
            UserDisposition::Reserved
        );
    }
}
