// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dynamic-user.c
//
use std::collections::{BTreeMap, BTreeSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};

pub const SOURCE_PATH: &str = "src/core/dynamic-user.c";
pub const DYNAMIC_UID_MIN: u32 = 61184;
pub const DYNAMIC_UID_MAX: u32 = 65519;
const MAX_TRIES: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicUserError {
    InvalidName(String),
    Exhausted,
    UnknownUser(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealizedIdentity {
    pub uid: u32,
    pub gid: u32,
    pub lock_path: Option<String>,
    pub from_static_user: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicUser {
    pub name: String,
    pub reference_count: usize,
    pub cached: Option<RealizedIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicCreds {
    pub user: String,
    pub group: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealizedCreds {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Default)]
pub struct DynamicUserManager {
    users: BTreeMap<String, DynamicUser>,
    used_ids: BTreeSet<u32>,
    path_owners: BTreeMap<String, u32>,
    static_users: BTreeMap<String, u32>,
    static_groups: BTreeMap<String, u32>,
}

impl DynamicUserManager {
    pub fn with_path_owner(mut self, path: impl Into<String>, uid: u32) -> Self {
        self.path_owners.insert(path.into(), uid);
        self
    }

    pub fn with_static_user(mut self, name: impl Into<String>, uid: u32) -> Self {
        self.static_users.insert(name.into(), uid);
        self
    }

    pub fn with_static_group(mut self, name: impl Into<String>, gid: u32) -> Self {
        self.static_groups.insert(name.into(), gid);
        self
    }

    pub fn acquire(&mut self, name: &str) -> Result<bool, DynamicUserError> {
        validate_name(name)?;

        if let Some(user) = self.users.get_mut(name) {
            user.reference_count += 1;
            return Ok(false);
        }

        self.users.insert(
            name.into(),
            DynamicUser {
                name: name.into(),
                reference_count: 1,
                cached: None,
            },
        );
        Ok(true)
    }

    pub fn pick_uid(
        &self,
        suggested_paths: &[String],
        name: &str,
    ) -> Result<u32, DynamicUserError> {
        for path in suggested_paths {
            if let Some(uid) = self.path_owners.get(path).copied() {
                if uid_is_dynamic(uid) && !self.used_ids.contains(&uid) {
                    return Ok(uid);
                }
            }
        }

        let hashed = clamp_uid(hash_name(name));
        if !self.used_ids.contains(&hashed) {
            return Ok(hashed);
        }

        for salt in 0..MAX_TRIES {
            let candidate = clamp_uid(hash_name(&(name.to_owned() + ":" + &salt.to_string())));
            if !self.used_ids.contains(&candidate) {
                return Ok(candidate);
            }
        }

        Err(DynamicUserError::Exhausted)
    }

    pub fn realize(
        &mut self,
        name: &str,
        suggested_paths: &[String],
    ) -> Result<RealizedIdentity, DynamicUserError> {
        validate_name(name)?;

        if let Some(cached) = self.users.get(name).and_then(|user| user.cached.clone()) {
            return Ok(cached);
        }

        let identity = if let Some(uid) = self.static_users.get(name).copied() {
            RealizedIdentity {
                uid,
                gid: uid,
                lock_path: None,
                from_static_user: true,
            }
        } else {
            let uid = self.pick_uid(suggested_paths, name)?;
            self.used_ids.insert(uid);
            RealizedIdentity {
                uid,
                gid: uid,
                lock_path: Some(format!("/run/systemd/dynamic-uid/{uid}")),
                from_static_user: false,
            }
        };

        let user = self
            .users
            .get_mut(name)
            .ok_or_else(|| DynamicUserError::UnknownUser(name.into()))?;
        user.cached = Some(identity.clone());
        Ok(identity)
    }

    pub fn pop(&mut self, name: &str) -> Result<Option<RealizedIdentity>, DynamicUserError> {
        let user = self
            .users
            .get_mut(name)
            .ok_or_else(|| DynamicUserError::UnknownUser(name.into()))?;
        Ok(user.cached.take())
    }

    pub fn push(&mut self, name: &str, identity: RealizedIdentity) -> Result<(), DynamicUserError> {
        let user = self
            .users
            .get_mut(name)
            .ok_or_else(|| DynamicUserError::UnknownUser(name.into()))?;
        self.used_ids.insert(identity.uid);
        user.cached = Some(identity);
        Ok(())
    }

    pub fn lookup_uid(&self, uid: u32) -> Option<String> {
        self.users
            .values()
            .find(|user| {
                user.cached
                    .as_ref()
                    .is_some_and(|identity| identity.uid == uid)
            })
            .map(|user| user.name.clone())
    }

    pub fn lookup_name(&self, name: &str) -> Option<u32> {
        self.users
            .get(name)
            .and_then(|user| user.cached.as_ref().map(|identity| identity.uid))
    }

    pub fn vacuum(&mut self, close_user: bool) {
        if close_user {
            self.users.clear();
            self.used_ids.clear();
            return;
        }

        self.users
            .retain(|_, user| user.reference_count > 0 || user.cached.is_some());
    }

    pub fn make_creds(&self, user: &str, group: &str) -> Result<DynamicCreds, DynamicUserError> {
        validate_name(user)?;
        validate_name(group)?;
        Ok(DynamicCreds {
            user: user.into(),
            group: group.into(),
        })
    }

    pub fn realize_creds(
        &mut self,
        creds: &DynamicCreds,
        suggested_paths: &[String],
    ) -> Result<RealizedCreds, DynamicUserError> {
        self.acquire(&creds.user)?;
        let user_identity = self.realize(&creds.user, suggested_paths)?;
        let gid = self
            .static_groups
            .get(&creds.group)
            .copied()
            .unwrap_or_else(|| clamp_uid(hash_name(&creds.group)));

        Ok(RealizedCreds {
            uid: user_identity.uid,
            gid,
        })
    }
}

fn validate_name(name: &str) -> Result<(), DynamicUserError> {
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        Err(DynamicUserError::InvalidName(name.into()))
    } else {
        Ok(())
    }
}

fn uid_is_dynamic(uid: u32) -> bool {
    (DYNAMIC_UID_MIN..=DYNAMIC_UID_MAX).contains(&uid)
}

fn clamp_uid(value: u64) -> u32 {
    let span = u64::from(DYNAMIC_UID_MAX - DYNAMIC_UID_MIN + 1);
    ((value % span) as u32) + DYNAMIC_UID_MIN
}

fn hash_name(name: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_reuses_existing_structure() {
        let mut manager = DynamicUserManager::default();
        assert!(manager.acquire("demo").unwrap());
        assert!(!manager.acquire("demo").unwrap());
        assert_eq!(manager.users["demo"].reference_count, 2);
    }

    #[test]
    fn pick_uid_prefers_suggested_path_owner() {
        let manager = DynamicUserManager::default().with_path_owner("/var/lib/demo", 62000);
        let uid = manager.pick_uid(&["/var/lib/demo".into()], "demo").unwrap();
        assert_eq!(uid, 62000);
    }

    #[test]
    fn realize_uses_static_user_without_lock_path() {
        let mut manager = DynamicUserManager::default().with_static_user("demo", 4242);
        manager.acquire("demo").unwrap();
        let identity = manager.realize("demo", &[]).unwrap();
        assert!(identity.from_static_user);
        assert_eq!(identity.lock_path, None);
    }

    #[test]
    fn pop_and_push_round_trip_cached_identity() {
        let mut manager = DynamicUserManager::default();
        manager.acquire("demo").unwrap();
        let identity = manager.realize("demo", &[]).unwrap();
        let popped = manager.pop("demo").unwrap().unwrap();
        assert_eq!(popped.uid, identity.uid);
        manager.push("demo", popped.clone()).unwrap();
        assert_eq!(manager.lookup_name("demo"), Some(popped.uid));
    }

    #[test]
    fn realize_creds_combines_dynamic_user_and_group() {
        let mut manager = DynamicUserManager::default().with_static_group("demo", 7777);
        let creds = manager.make_creds("demo", "demo").unwrap();
        let realized = manager.realize_creds(&creds, &[]).unwrap();
        assert_eq!(realized.gid, 7777);
        assert!(uid_is_dynamic(realized.uid));
    }
}
