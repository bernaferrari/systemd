// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-objects.c

use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
pub const NEG_EEXIST: i32 = -(libc::EEXIST as i32);
pub const NEG_ENOENT: i32 = -(libc::ENOENT as i32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VTableMember {
    pub name: String,
    pub offset: usize,
    pub absolute_offset: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VTableRegistration {
    pub interface: String,
    pub members: Vec<VTableMember>,
    pub userdata_base: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub path: String,
    pub objects: Vec<String>,
    pub fallbacks: Vec<String>,
    pub object_manager: bool,
    pub enumerated_children: BTreeSet<String>,
    pub vtables: Vec<VTableRegistration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchResult {
    Exact { path: String, callback: String },
    Fallback { anchor: String, callback: String },
    ObjectManager { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    PropertiesChanged {
        path: String,
        interface: String,
        properties: Vec<String>,
    },
    InterfacesAdded {
        path: String,
        interfaces: Vec<String>,
    },
    InterfacesRemoved {
        path: String,
        interfaces: Vec<String>,
    },
}

#[derive(Debug, Default, Clone)]
pub struct BusObjectRegistry {
    nodes: BTreeMap<String, Node>,
    pub signals: Vec<Signal>,
}

impl BusObjectRegistry {
    pub fn add_object(&mut self, path: &str, callback_name: &str) -> Result<()> {
        validate_object_path(path)?;
        validate_non_empty(callback_name)?;

        let node = self.ensure_node(path);
        if node.objects.iter().any(|n| n == callback_name) {
            return Err(NEG_EEXIST);
        }
        node.objects.push(callback_name.to_string());
        Ok(())
    }

    pub fn add_fallback(&mut self, path: &str, callback_name: &str) -> Result<()> {
        validate_object_path(path)?;
        validate_non_empty(callback_name)?;

        let node = self.ensure_node(path);
        if node.fallbacks.iter().any(|n| n == callback_name) {
            return Err(NEG_EEXIST);
        }
        node.fallbacks.push(callback_name.to_string());
        Ok(())
    }

    pub fn add_object_vtable(
        &mut self,
        path: &str,
        interface: &str,
        userdata_base: usize,
        members: Vec<VTableMember>,
    ) -> Result<()> {
        validate_object_path(path)?;
        validate_interface_name(interface)?;
        if members.is_empty() {
            return Err(NEG_EINVAL);
        }

        let node = self.ensure_node(path);
        node.vtables.push(VTableRegistration {
            interface: interface.to_string(),
            members,
            userdata_base,
        });
        Ok(())
    }

    pub fn add_object_manager(&mut self, path: &str) -> Result<()> {
        validate_object_path(path)?;
        self.ensure_node(path).object_manager = true;
        Ok(())
    }

    pub fn add_node_enumerator<I, S>(&mut self, path: &str, children: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        validate_object_path(path)?;

        let node = self.ensure_node(path);
        for child in children {
            let child = child.as_ref();
            validate_object_path(child)?;
            if object_path_startswith(child, path) {
                node.enumerated_children.insert(child.to_string());
            }
        }

        Ok(())
    }

    pub fn emit_properties_changed<I, S>(
        &mut self,
        path: &str,
        interface: &str,
        properties: I,
    ) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        validate_object_path(path)?;
        validate_interface_name(interface)?;
        let properties = properties
            .into_iter()
            .map(|p| p.as_ref().to_string())
            .collect::<Vec<_>>();
        self.signals.push(Signal::PropertiesChanged {
            path: path.to_string(),
            interface: interface.to_string(),
            properties,
        });
        Ok(())
    }

    pub fn emit_interfaces_added<I, S>(&mut self, path: &str, interfaces: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        validate_object_path(path)?;
        let interfaces = interfaces
            .into_iter()
            .map(|i| i.as_ref().to_string())
            .collect::<Vec<_>>();
        self.signals.push(Signal::InterfacesAdded {
            path: path.to_string(),
            interfaces,
        });
        Ok(())
    }

    pub fn emit_interfaces_removed<I, S>(&mut self, path: &str, interfaces: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        validate_object_path(path)?;
        let interfaces = interfaces
            .into_iter()
            .map(|i| i.as_ref().to_string())
            .collect::<Vec<_>>();
        self.signals.push(Signal::InterfacesRemoved {
            path: path.to_string(),
            interfaces,
        });
        Ok(())
    }

    pub fn process_object(&self, path: &str) -> Result<DispatchResult> {
        validate_object_path(path)?;

        if let Some(node) = self.nodes.get(path) {
            if let Some(callback) = node.objects.first() {
                return Ok(DispatchResult::Exact {
                    path: path.to_string(),
                    callback: callback.clone(),
                });
            }
            if node.object_manager {
                return Ok(DispatchResult::ObjectManager {
                    path: path.to_string(),
                });
            }
        }

        for ancestor in ancestors(path).iter().rev() {
            if let Some(node) = self.nodes.get(ancestor) {
                if let Some(callback) = node.fallbacks.first() {
                    return Ok(DispatchResult::Fallback {
                        anchor: ancestor.clone(),
                        callback: callback.clone(),
                    });
                }
            }
        }

        Err(NEG_ENOENT)
    }

    pub fn child_nodes(
        &self,
        prefix: &str,
        recursive: bool,
        include_subhierarchies: bool,
    ) -> Result<Vec<String>> {
        validate_object_path(prefix)?;
        let mut set = BTreeSet::new();

        for (path, node) in &self.nodes {
            if path == prefix {
                for child in &node.enumerated_children {
                    set.insert(child.clone());
                }
                continue;
            }

            if !object_path_startswith(path, prefix) {
                continue;
            }

            if !recursive && !is_direct_child(prefix, path) {
                continue;
            }

            if !include_subhierarchies {
                let intermediate_manager = ancestors(path)
                    .into_iter()
                    .filter(|a| a != prefix && a != path)
                    .any(|a| self.nodes.get(&a).is_some_and(|n| n.object_manager));
                if intermediate_manager {
                    continue;
                }
            }

            set.insert(path.clone());
            for child in &node.enumerated_children {
                if object_path_startswith(child, prefix) {
                    set.insert(child.clone());
                }
            }
        }

        Ok(set.into_iter().collect())
    }

    pub fn property_userdata(
        &self,
        path: &str,
        interface: &str,
        member_name: &str,
    ) -> Result<usize> {
        validate_object_path(path)?;
        validate_interface_name(interface)?;
        validate_non_empty(member_name)?;

        let node = self.nodes.get(path).ok_or(NEG_ENOENT)?;
        let registration = node
            .vtables
            .iter()
            .find(|v| v.interface == interface)
            .ok_or(NEG_ENOENT)?;
        let member = registration
            .members
            .iter()
            .find(|m| m.name == member_name)
            .ok_or(NEG_ENOENT)?;

        Ok(if member.absolute_offset {
            member.offset
        } else {
            registration.userdata_base.saturating_add(member.offset)
        })
    }

    fn ensure_node(&mut self, path: &str) -> &mut Node {
        self.nodes.entry(path.to_string()).or_insert_with(|| Node {
            path: path.to_string(),
            objects: Vec::new(),
            fallbacks: Vec::new(),
            object_manager: false,
            enumerated_children: BTreeSet::new(),
            vtables: Vec::new(),
        })
    }
}

fn validate_non_empty(s: &str) -> Result<()> {
    if s.is_empty() {
        Err(NEG_EINVAL)
    } else {
        Ok(())
    }
}

fn validate_interface_name(interface: &str) -> Result<()> {
    if interface.is_empty()
        || !interface.contains('.')
        || interface.starts_with('.')
        || interface.ends_with('.')
    {
        Err(NEG_EINVAL)
    } else {
        Ok(())
    }
}

fn validate_object_path(path: &str) -> Result<()> {
    if !path.starts_with('/') {
        return Err(NEG_EINVAL);
    }
    if path.len() > 1 && path.ends_with('/') {
        return Err(NEG_EINVAL);
    }
    if path.split('/').skip(1).any(|segment| segment.is_empty()) {
        return Err(NEG_EINVAL);
    }
    Ok(())
}

fn object_path_startswith(path: &str, prefix: &str) -> bool {
    path == prefix
        || prefix == "/"
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn is_direct_child(prefix: &str, path: &str) -> bool {
    let rest = if prefix == "/" {
        path.strip_prefix('/').unwrap_or(path)
    } else if let Some(rest) = path.strip_prefix(prefix) {
        rest.strip_prefix('/').unwrap_or(rest)
    } else {
        return false;
    };

    !rest.is_empty() && !rest.contains('/')
}

fn ancestors(path: &str) -> Vec<String> {
    if path == "/" {
        return vec!["/".into()];
    }

    let mut out = vec!["/".to_string()];
    let mut current = String::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        current.push('/');
        current.push_str(part);
        out.push(current.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_paths() {
        assert_eq!(validate_object_path("a/b"), Err(NEG_EINVAL));
        assert_eq!(validate_object_path("/a//b"), Err(NEG_EINVAL));
        assert_eq!(validate_object_path("/a/"), Err(NEG_EINVAL));
    }

    #[test]
    fn adds_exact_object() {
        let mut registry = BusObjectRegistry::default();
        registry.add_object("/a/b", "handler").unwrap();
        assert_eq!(
            registry.process_object("/a/b").unwrap(),
            DispatchResult::Exact {
                path: "/a/b".into(),
                callback: "handler".into()
            }
        );
    }

    #[test]
    fn resolves_fallback_from_ancestor() {
        let mut registry = BusObjectRegistry::default();
        registry.add_fallback("/a", "fallback").unwrap();
        assert_eq!(
            registry.process_object("/a/b/c").unwrap(),
            DispatchResult::Fallback {
                anchor: "/a".into(),
                callback: "fallback".into()
            }
        );
    }

    #[test]
    fn object_manager_dispatches_when_no_handler_exists() {
        let mut registry = BusObjectRegistry::default();
        registry.add_object_manager("/svc").unwrap();
        assert_eq!(
            registry.process_object("/svc").unwrap(),
            DispatchResult::ObjectManager {
                path: "/svc".into()
            }
        );
    }

    #[test]
    fn enumerators_are_sorted_and_deduplicated() {
        let mut registry = BusObjectRegistry::default();
        registry
            .add_node_enumerator("/svc", ["/svc/b", "/svc/a", "/svc/b"])
            .unwrap();
        assert_eq!(
            registry.child_nodes("/svc", false, true).unwrap(),
            vec!["/svc/a", "/svc/b"]
        );
    }

    #[test]
    fn non_recursive_child_lookup_filters_nested_paths() {
        let mut registry = BusObjectRegistry::default();
        registry.add_object("/svc/a", "a").unwrap();
        registry.add_object("/svc/a/b", "b").unwrap();
        assert_eq!(
            registry.child_nodes("/svc", false, true).unwrap(),
            vec!["/svc/a"]
        );
    }

    #[test]
    fn subhierarchy_managers_can_be_skipped() {
        let mut registry = BusObjectRegistry::default();
        registry.add_object("/svc/a", "a").unwrap();
        registry.add_object_manager("/svc/a").unwrap();
        registry.add_object("/svc/a/deeper", "deep").unwrap();
        assert_eq!(
            registry.child_nodes("/svc", true, false).unwrap(),
            vec!["/svc/a"]
        );
    }

    #[test]
    fn property_userdata_applies_relative_offsets() {
        let mut registry = BusObjectRegistry::default();
        registry
            .add_object_vtable(
                "/svc",
                "org.example.Service",
                100,
                vec![VTableMember {
                    name: "Answer".into(),
                    offset: 8,
                    absolute_offset: false,
                }],
            )
            .unwrap();
        assert_eq!(
            registry
                .property_userdata("/svc", "org.example.Service", "Answer")
                .unwrap(),
            108
        );
    }

    #[test]
    fn property_userdata_supports_absolute_offsets() {
        let mut registry = BusObjectRegistry::default();
        registry
            .add_object_vtable(
                "/svc",
                "org.example.Service",
                100,
                vec![VTableMember {
                    name: "Absolute".into(),
                    offset: 7,
                    absolute_offset: true,
                }],
            )
            .unwrap();
        assert_eq!(
            registry
                .property_userdata("/svc", "org.example.Service", "Absolute")
                .unwrap(),
            7
        );
    }

    #[test]
    fn signal_emission_is_recorded() {
        let mut registry = BusObjectRegistry::default();
        registry
            .emit_properties_changed("/svc", "org.example.Service", ["A", "B"])
            .unwrap();
        assert_eq!(registry.signals.len(), 1);
    }
}
