// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-genl.c
//

use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, GenlError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenlError {
    FamilyNameMismatch,
    UnsupportedFamily,
    DuplicateFamilyId(u16),
    DuplicateFamilyName(String),
    InvalidMulticastGroup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericNetlinkFamily {
    pub id: u16,
    pub name: String,
    pub version: u32,
    pub additional_header_size: u32,
    pub policy_set_name: String,
    pub multicast_groups: BTreeMap<String, u32>,
    pub supported: bool,
}

impl GenericNetlinkFamily {
    pub fn unsupported(name: &str, policy_set_name: &str) -> Self {
        Self {
            id: 0,
            name: name.to_string(),
            version: 0,
            additional_header_size: 0,
            policy_set_name: policy_set_name.to_string(),
            multicast_groups: BTreeMap::new(),
            supported: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerFamilyMessage {
    pub family_name: String,
    pub id: u16,
    pub version: u32,
    pub additional_header_size: u32,
    pub multicast_groups: Vec<(String, u32)>,
}

#[derive(Debug, Default)]
pub struct GenericNetlinkRegistry {
    by_id: BTreeMap<u16, GenericNetlinkFamily>,
    by_name: BTreeMap<String, GenericNetlinkFamily>,
}

impl GenericNetlinkRegistry {
    pub fn clear_family(&mut self) {
        self.by_id.clear();
        self.by_name.clear();
    }

    pub fn register_unsupported(&mut self, family_name: &str, policy_set_name: &str) -> Result<()> {
        let family = GenericNetlinkFamily::unsupported(family_name, policy_set_name);
        self.insert(family)
    }

    pub fn register_from_ctrl(
        &mut self,
        expected_family_name: &str,
        policy_set_name: &str,
        message: ControllerFamilyMessage,
    ) -> Result<&GenericNetlinkFamily> {
        if message.family_name != expected_family_name {
            return Err(GenlError::FamilyNameMismatch);
        }

        let mut multicast_groups = BTreeMap::new();
        for (name, id) in message.multicast_groups {
            if id == 0 {
                continue;
            }
            if multicast_groups.insert(name, id).is_some() {
                return Err(GenlError::InvalidMulticastGroup);
            }
        }

        let family = GenericNetlinkFamily {
            id: message.id,
            name: message.family_name,
            version: message.version,
            additional_header_size: message.additional_header_size,
            policy_set_name: policy_set_name.to_string(),
            multicast_groups,
            supported: true,
        };
        self.insert(family)?;
        self.by_name
            .get(expected_family_name)
            .ok_or(GenlError::UnsupportedFamily)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&GenericNetlinkFamily> {
        self.by_name.get(name)
    }

    pub fn get_by_id(&self, id: u16) -> Option<&GenericNetlinkFamily> {
        self.by_id.get(&id)
    }

    fn insert(&mut self, family: GenericNetlinkFamily) -> Result<()> {
        if family.id != 0 && self.by_id.contains_key(&family.id) {
            return Err(GenlError::DuplicateFamilyId(family.id));
        }
        if self.by_name.contains_key(&family.name) {
            return Err(GenlError::DuplicateFamilyName(family.name));
        }

        if family.id != 0 {
            self.by_id.insert(family.id, family.clone());
        }
        self.by_name.insert(family.name.clone(), family);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenlMessageSpec {
    pub family_id: u16,
    pub command: u8,
    pub version: u32,
    pub payload_size: usize,
}

pub fn message_new(family: &GenericNetlinkFamily, command: u8) -> Result<GenlMessageSpec> {
    if !family.supported {
        return Err(GenlError::UnsupportedFamily);
    }
    Ok(GenlMessageSpec {
        family_id: family.id,
        command,
        version: family.version,
        payload_size: std::mem::size_of::<u8>() + family.additional_header_size as usize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_family_is_cached_by_name_only() {
        let mut registry = GenericNetlinkRegistry::default();
        registry
            .register_unsupported("nl80211", "genl_nl80211")
            .unwrap();
        assert!(registry.get_by_name("nl80211").is_some());
        assert!(registry.get_by_id(0).is_none());
    }

    #[test]
    fn controller_message_registers_supported_family() {
        let mut registry = GenericNetlinkRegistry::default();
        let family = registry
            .register_from_ctrl(
                "nlctrl",
                "genl_ctrl",
                ControllerFamilyMessage {
                    family_name: "nlctrl".into(),
                    id: 16,
                    version: 1,
                    additional_header_size: 4,
                    multicast_groups: vec![("notify".into(), 3), ("ignored".into(), 0)],
                },
            )
            .unwrap();
        assert_eq!(family.multicast_groups.get("notify"), Some(&3));
    }

    #[test]
    fn mismatched_family_name_is_rejected() {
        let mut registry = GenericNetlinkRegistry::default();
        let err = registry
            .register_from_ctrl(
                "expected",
                "policy",
                ControllerFamilyMessage {
                    family_name: "actual".into(),
                    id: 1,
                    version: 1,
                    additional_header_size: 0,
                    multicast_groups: vec![],
                },
            )
            .unwrap_err();
        assert_eq!(err, GenlError::FamilyNameMismatch);
    }

    #[test]
    fn message_spec_uses_family_metadata() {
        let spec = message_new(
            &GenericNetlinkFamily {
                id: 31,
                name: "wireguard".into(),
                version: 2,
                additional_header_size: 8,
                policy_set_name: "genl_wireguard".into(),
                multicast_groups: BTreeMap::new(),
                supported: true,
            },
            5,
        )
        .unwrap();
        assert_eq!(spec.payload_size, 9);
    }
}
