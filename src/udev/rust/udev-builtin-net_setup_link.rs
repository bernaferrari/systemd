// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-net_setup_link.c
//
// Link configuration selection.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkPolicy {
    pub mac_policy: String,
    pub name_policy: Vec<String>,
    pub alternative_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSetupResult {
    pub chosen_name: Option<String>,
    pub applied_policies: Vec<String>,
}

pub fn choose_link_setup(policy: &LinkPolicy, stable_name: Option<&str>) -> LinkSetupResult {
    LinkSetupResult {
        chosen_name: stable_name.map(str::to_string).or_else(|| policy.alternative_names.first().cloned()),
        applied_policies: std::iter::once(policy.mac_policy.clone()).chain(policy.name_policy.iter().cloned()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn prefers_stable_name() { let result = choose_link_setup(&LinkPolicy { mac_policy: "persistent".into(), name_policy: vec!["kernel".into()], alternative_names: vec!["enp0s1".into()] }, Some("eno1")); assert_eq!(result.chosen_name.as_deref(), Some("eno1")); }
    #[test] fn falls_back_to_alternative_name() { let result = choose_link_setup(&LinkPolicy { mac_policy: "none".into(), name_policy: vec![], alternative_names: vec!["enp0s1".into()] }, None); assert_eq!(result.chosen_name.as_deref(), Some("enp0s1")); }
}
