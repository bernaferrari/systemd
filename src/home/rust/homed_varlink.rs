// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homed-varlink.c, src/home/homed-varlink.h

use crate::homed_home_bus::Home;
use crate::homed_manager_bus::ManagerBus;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LookupParameters {
    pub user_name: Option<String>,
    pub group_name: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub service: Option<String>,
}

pub fn client_is_trusted(peer_uid: u32, home: &Home) -> bool {
    peer_uid == 0 || peer_uid == home.uid
}

pub fn home_user_match_lookup_parameters(parameters: &LookupParameters, home: &Home) -> bool {
    if let Some(ref user_name) = parameters.user_name {
        if &home.user_name != user_name {
            return false;
        }
    }
    if let Some(uid) = parameters.uid {
        if home.uid != uid {
            return false;
        }
    }
    true
}

pub fn home_group_match_lookup_parameters(parameters: &LookupParameters, home: &Home) -> bool {
    if let Some(ref group_name) = parameters.group_name {
        if &home.user_name != group_name {
            return false;
        }
    }
    if let Some(gid) = parameters.gid {
        if home.uid != gid {
            return false;
        }
    }
    true
}

pub fn build_user_json(home: &Home, trusted: bool) -> String {
    format!(
        "{{\"record\":{{\"userName\":\"{}\",\"uid\":{}}},\"incomplete\":{}}}",
        home.user_name,
        home.uid,
        (!trusted)
    )
}

pub fn build_group_json(home: &Home) -> String {
    format!(
        "{{\"record\":{{\"groupName\":\"{}\",\"gid\":{}}}}}",
        home.user_name, home.uid
    )
}

pub fn vl_method_get_user_record(
    manager: &ManagerBus,
    parameters: &LookupParameters,
) -> Vec<String> {
    manager
        .homes_by_uid
        .values()
        .filter(|home| home_user_match_lookup_parameters(parameters, home))
        .map(|home| build_user_json(home, true))
        .collect()
}

pub fn vl_method_get_group_record(
    manager: &ManagerBus,
    parameters: &LookupParameters,
) -> Vec<String> {
    manager
        .homes_by_uid
        .values()
        .filter(|home| home_group_match_lookup_parameters(parameters, home))
        .map(build_group_json)
        .collect()
}

pub fn vl_method_get_memberships(
    manager: &ManagerBus,
    parameters: &LookupParameters,
) -> Vec<(String, String)> {
    manager
        .homes_by_uid
        .values()
        .filter(|home| {
            parameters
                .user_name
                .as_ref()
                .is_none_or(|name| &home.user_name == name)
                && parameters
                    .group_name
                    .as_ref()
                    .is_none_or(|name| &home.user_name == name)
        })
        .map(|home| (home.user_name.clone(), home.user_name.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> ManagerBus {
        let mut manager = ManagerBus::new();
        manager.register_home(Home::new("alice".into(), 1000));
        manager.register_home(Home::new("bob".into(), 1001));
        manager
    }

    #[test]
    fn trusted_accepts_root() {
        let home = Home::new("alice".into(), 1000);
        assert!(client_is_trusted(0, &home));
    }

    #[test]
    fn trusted_accepts_matching_uid() {
        let home = Home::new("alice".into(), 1000);
        assert!(client_is_trusted(1000, &home));
    }

    #[test]
    fn trusted_rejects_other_uid() {
        let home = Home::new("alice".into(), 1000);
        assert!(!client_is_trusted(1001, &home));
    }

    #[test]
    fn user_lookup_filters_by_name() {
        let records = vl_method_get_user_record(
            &manager(),
            &LookupParameters {
                user_name: Some("alice".into()),
                ..Default::default()
            },
        );
        assert_eq!(records.len(), 1);
        assert!(records[0].contains("alice"));
    }

    #[test]
    fn group_lookup_filters_by_gid() {
        let records = vl_method_get_group_record(
            &manager(),
            &LookupParameters {
                gid: Some(1001),
                ..Default::default()
            },
        );
        assert_eq!(records.len(), 1);
        assert!(records[0].contains("bob"));
    }

    #[test]
    fn build_user_json_marks_untrusted_as_incomplete() {
        let home = Home::new("alice".into(), 1000);
        assert!(build_user_json(&home, false).contains("\"incomplete\":true"));
    }

    #[test]
    fn memberships_default_to_primary_group() {
        let memberships = vl_method_get_memberships(&manager(), &LookupParameters::default());
        assert!(memberships.contains(&("alice".into(), "alice".into())));
        assert!(memberships.contains(&("bob".into(), "bob".into())));
    }

    #[test]
    fn user_match_checks_uid() {
        let home = Home::new("alice".into(), 1000);
        assert!(!home_user_match_lookup_parameters(
            &LookupParameters {
                uid: Some(1001),
                ..Default::default()
            },
            &home
        ));
    }

    #[test]
    fn group_match_checks_group_name() {
        let home = Home::new("alice".into(), 1000);
        assert!(!home_group_match_lookup_parameters(
            &LookupParameters {
                group_name: Some("bob".into()),
                ..Default::default()
            },
            &home
        ));
    }
}
