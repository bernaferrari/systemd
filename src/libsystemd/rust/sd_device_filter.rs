// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-device/device-filter.c
//

use std::collections::{BTreeSet, HashMap, HashSet};

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_ENOMEM: i32 = -libc::ENOMEM;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Device {
    pub syspath: String,
    pub sysname: String,
    pub sysattrs: HashMap<String, String>,
    pub properties: HashMap<String, String>,
    pub tags: HashSet<String>,
}

pub type MatchMap = HashMap<String, Vec<String>>;
pub type MatchSet = BTreeSet<String>;

pub fn update_match_strv(
    match_strv: &mut MatchMap,
    key: &str,
    value: Option<&str>,
    clear_on_null: bool,
) -> Result<bool> {
    let entry = match_strv.entry(key.to_string()).or_default();

    match value {
        Some(value) => {
            if entry.iter().any(|existing| existing == value) {
                return Ok(false);
            }
            entry.push(value.to_string());
            Ok(true)
        }
        None => {
            if entry.is_empty() || !clear_on_null {
                return Ok(false);
            }
            entry.clear();
            Ok(true)
        }
    }
}

fn matches_patterns(patterns: &[String], value: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|pattern| glob_match(pattern, value))
}

fn glob_match(pattern: &str, value: &str) -> bool {
    fn inner(pattern: &[u8], value: &[u8]) -> bool {
        match pattern.split_first() {
            None => value.is_empty(),
            Some((&b'*', rest)) => {
                inner(rest, value) || (!value.is_empty() && inner(pattern, &value[1..]))
            }
            Some((&b'?', rest)) => !value.is_empty() && inner(rest, &value[1..]),
            Some((&ch, rest)) => value.first().copied() == Some(ch) && inner(rest, &value[1..]),
        }
    }

    inner(pattern.as_bytes(), value.as_bytes())
}

fn device_match_value(
    lookup: impl Fn(&str) -> Option<String>,
    matches: &MatchMap,
    nomatches: &MatchMap,
) -> bool {
    for (key, patterns) in matches {
        let Some(value) = lookup(key) else {
            return false;
        };
        if !matches_patterns(patterns, &value) {
            return false;
        }
    }

    for (key, patterns) in nomatches {
        if let Some(value) = lookup(key)
            && matches_patterns(patterns, &value)
        {
            return false;
        }
    }

    true
}

pub fn device_match_sysattr(
    device: &Device,
    match_sysattr: &MatchMap,
    nomatch_sysattr: &MatchMap,
) -> bool {
    device_match_value(
        |key| device.sysattrs.get(key).cloned(),
        match_sysattr,
        nomatch_sysattr,
    )
}

pub fn device_match_property(
    device: &Device,
    match_property: &MatchMap,
    nomatch_property: &MatchMap,
) -> bool {
    device_match_value(
        |key| device.properties.get(key).cloned(),
        match_property,
        nomatch_property,
    )
}

pub fn device_match_parent(
    device: &Device,
    match_parent: &MatchSet,
    nomatch_parent: &MatchSet,
) -> bool {
    if nomatch_parent.iter().any(|prefix| {
        device.syspath == *prefix || device.syspath.starts_with(&format!("{prefix}/"))
    }) {
        return false;
    }

    match_parent.is_empty()
        || match_parent.iter().any(|prefix| {
            device.syspath == *prefix || device.syspath.starts_with(&format!("{prefix}/"))
        })
}

pub fn device_match_tag(device: &Device, match_tag: &MatchSet, nomatch_tag: &MatchSet) -> bool {
    if nomatch_tag.iter().any(|tag| device.tags.contains(tag)) {
        return false;
    }

    match_tag.is_empty() || match_tag.iter().any(|tag| device.tags.contains(tag))
}

pub fn device_match_sysname(
    device: &Device,
    match_sysname: &[String],
    nomatch_sysname: &[String],
) -> bool {
    if nomatch_sysname
        .iter()
        .any(|pattern| glob_match(pattern, &device.sysname))
    {
        return false;
    }

    match_sysname.is_empty()
        || match_sysname
            .iter()
            .any(|pattern| glob_match(pattern, &device.sysname))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_device() -> Device {
        Device {
            syspath: "/sys/devices/pci0000:00/0000:00:1f.2/block/sda".into(),
            sysname: "sda".into(),
            sysattrs: HashMap::from([
                ("size".into(), "1024".into()),
                ("queue".into(), "mq".into()),
            ]),
            properties: HashMap::from([("ID_MODEL".into(), "FastDisk".into())]),
            tags: HashSet::from(["systemd".into(), "seat".into()]),
        }
    }

    #[test]
    fn update_match_strv_adds_new_value() {
        let mut map = MatchMap::new();
        assert_eq!(
            update_match_strv(&mut map, "ID_MODEL", Some("FastDisk"), true),
            Ok(true)
        );
        assert_eq!(map["ID_MODEL"], vec!["FastDisk"]);
    }

    #[test]
    fn update_match_strv_ignores_duplicates() {
        let mut map = MatchMap::from([("ID_MODEL".into(), vec!["FastDisk".into()])]);
        assert_eq!(
            update_match_strv(&mut map, "ID_MODEL", Some("FastDisk"), true),
            Ok(false)
        );
    }

    #[test]
    fn update_match_strv_clears_on_null() {
        let mut map = MatchMap::from([("ID_MODEL".into(), vec!["FastDisk".into()])]);
        assert_eq!(
            update_match_strv(&mut map, "ID_MODEL", None, true),
            Ok(true)
        );
        assert!(map["ID_MODEL"].is_empty());
    }

    #[test]
    fn matches_sysattrs() {
        let device = sample_device();
        let matches = MatchMap::from([("size".into(), vec!["10*".into()])]);
        assert!(device_match_sysattr(&device, &matches, &MatchMap::new()));
    }

    #[test]
    fn rejects_nomatched_sysattrs() {
        let device = sample_device();
        let nomatches = MatchMap::from([("size".into(), vec!["10*".into()])]);
        assert!(!device_match_sysattr(&device, &MatchMap::new(), &nomatches));
    }

    #[test]
    fn matches_parent_prefixes() {
        let device = sample_device();
        let parents = MatchSet::from(["/sys/devices/pci0000:00".into()]);
        assert!(device_match_parent(&device, &parents, &MatchSet::new()));
    }

    #[test]
    fn rejects_nomatched_tags() {
        let device = sample_device();
        let nomatches = MatchSet::from(["systemd".into()]);
        assert!(!device_match_tag(&device, &MatchSet::new(), &nomatches));
    }

    #[test]
    fn matches_sysname_patterns() {
        let device = sample_device();
        assert!(device_match_sysname(&device, &["sd?".into()], &[]));
    }

    #[test]
    fn matches_properties() {
        let device = sample_device();
        let matches = MatchMap::from([("ID_MODEL".into(), vec!["Fast*".into()])]);
        assert!(device_match_property(&device, &matches, &MatchMap::new()));
    }
}
