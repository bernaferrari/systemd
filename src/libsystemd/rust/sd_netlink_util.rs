// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-util.c

use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolveInterfaceNameFlag(u8);

impl ResolveInterfaceNameFlag {
    pub const MAIN: Self = Self(1 << 0);
    pub const ALTERNATIVE: Self = Self(1 << 1);
    pub const NUMERIC: Self = Self(1 << 2);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for ResolveInterfaceNameFlag {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInfo {
    pub ifindex: i32,
    pub name: String,
    pub alternative_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetlinkUtilError {
    InvalidName,
    NameNotFound,
    InvalidMessage,
}

pub trait LinkRepository {
    fn by_name(&self, name: &str) -> Option<LinkInfo>;
    fn by_alternative_name(&self, name: &str) -> Option<LinkInfo>;
    fn by_ifindex(&self, ifindex: i32) -> Option<LinkInfo>;
    fn rename(&mut self, ifindex: i32, new_name: &str) -> Result<(), NetlinkUtilError>;
    fn replace_alternative_names(
        &mut self,
        ifindex: i32,
        alternative_names: Vec<String>,
    ) -> Result<(), NetlinkUtilError>;
}

#[derive(Debug, Clone, Default)]
pub struct MemoryLinkRepository {
    links: HashMap<i32, LinkInfo>,
}

impl MemoryLinkRepository {
    pub fn insert(&mut self, info: LinkInfo) {
        self.links.insert(info.ifindex, info);
    }
}

impl LinkRepository for MemoryLinkRepository {
    fn by_name(&self, name: &str) -> Option<LinkInfo> {
        self.links.values().find(|info| info.name == name).cloned()
    }

    fn by_alternative_name(&self, name: &str) -> Option<LinkInfo> {
        self.links
            .values()
            .find(|info| info.alternative_names.iter().any(|alt| alt == name))
            .cloned()
    }

    fn by_ifindex(&self, ifindex: i32) -> Option<LinkInfo> {
        self.links.get(&ifindex).cloned()
    }

    fn rename(&mut self, ifindex: i32, new_name: &str) -> Result<(), NetlinkUtilError> {
        let info = self
            .links
            .get_mut(&ifindex)
            .ok_or(NetlinkUtilError::NameNotFound)?;
        info.name = new_name.to_string();
        Ok(())
    }

    fn replace_alternative_names(
        &mut self,
        ifindex: i32,
        alternative_names: Vec<String>,
    ) -> Result<(), NetlinkUtilError> {
        let info = self
            .links
            .get_mut(&ifindex)
            .ok_or(NetlinkUtilError::NameNotFound)?;
        info.alternative_names = alternative_names;
        Ok(())
    }
}

pub fn parse_newlink_message(
    message: &LinkInfo,
) -> Result<(i32, String, Vec<String>), NetlinkUtilError> {
    if message.ifindex <= 0 || message.name.is_empty() {
        return Err(NetlinkUtilError::InvalidMessage);
    }

    Ok((
        message.ifindex,
        message.name.clone(),
        message.alternative_names.clone(),
    ))
}

pub fn parse_ifindex(text: &str) -> Option<i32> {
    text.parse::<i32>().ok().filter(|value| *value > 0)
}

pub fn ifname_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && !name.contains('/')
        && !name.chars().any(char::is_whitespace)
}

pub fn rtnl_resolve_ifname_full<R: LinkRepository>(
    repo: &R,
    flags: ResolveInterfaceNameFlag,
    name: &str,
) -> Result<LinkInfo, NetlinkUtilError> {
    if flags.contains(ResolveInterfaceNameFlag::MAIN)
        && ifname_valid(name)
        && let Some(info) = repo.by_name(name)
    {
        return Ok(info);
    }

    if flags.contains(ResolveInterfaceNameFlag::ALTERNATIVE)
        && ifname_valid(name)
        && let Some(info) = repo.by_alternative_name(name)
    {
        return Ok(info);
    }

    if flags.contains(ResolveInterfaceNameFlag::NUMERIC)
        && let Some(ifindex) = parse_ifindex(name)
    {
        return repo
            .by_ifindex(ifindex)
            .ok_or(NetlinkUtilError::NameNotFound);
    }

    Err(NetlinkUtilError::NameNotFound)
}

pub fn rtnl_rename_link<R: LinkRepository>(
    repo: &mut R,
    original_name: &str,
    new_name: &str,
) -> Result<(), NetlinkUtilError> {
    if original_name == new_name {
        return Ok(());
    }
    if !ifname_valid(new_name) {
        return Err(NetlinkUtilError::InvalidName);
    }

    let info = rtnl_resolve_ifname_full(
        repo,
        ResolveInterfaceNameFlag::MAIN | ResolveInterfaceNameFlag::NUMERIC,
        original_name,
    )?;
    repo.rename(info.ifindex, new_name)
}

pub fn dedup_alternative_names(
    name: Option<&str>,
    requested: &[String],
    original: &[String],
) -> Vec<String> {
    let original: BTreeSet<&str> = original.iter().map(String::as_str).collect();
    let mut new = BTreeSet::new();

    for candidate in requested {
        let candidate = candidate.as_str();
        if Some(candidate) == name || original.contains(candidate) || !ifname_valid(candidate) {
            continue;
        }
        new.insert(candidate.to_string());
    }

    new.into_iter().collect()
}

pub fn rtnl_set_link_name<R: LinkRepository>(
    repo: &mut R,
    ifindex: i32,
    name: Option<&str>,
    alternative_names: &[String],
) -> Result<(), NetlinkUtilError> {
    let original = repo
        .by_ifindex(ifindex)
        .ok_or(NetlinkUtilError::NameNotFound)?;
    if let Some(name) = name {
        if !ifname_valid(name) {
            return Err(NetlinkUtilError::InvalidName);
        }
        repo.rename(ifindex, name)?;
    }

    let new_altnames = dedup_alternative_names(
        name.or(Some(original.name.as_str())),
        alternative_names,
        &original.alternative_names,
    );
    repo.replace_alternative_names(ifindex, new_altnames)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> MemoryLinkRepository {
        let mut repo = MemoryLinkRepository::default();
        repo.insert(LinkInfo {
            ifindex: 5,
            name: "eth0".into(),
            alternative_names: vec!["wan0".into()],
        });
        repo.insert(LinkInfo {
            ifindex: 7,
            name: "veth0".into(),
            alternative_names: vec!["peer0".into(), "uplink0".into()],
        });
        repo
    }

    #[test]
    fn parses_valid_message() {
        let info = LinkInfo {
            ifindex: 1,
            name: "lo".into(),
            alternative_names: vec![],
        };
        assert_eq!(parse_newlink_message(&info).unwrap().0, 1);
    }

    #[test]
    fn rejects_invalid_message() {
        let info = LinkInfo {
            ifindex: 0,
            name: String::new(),
            alternative_names: vec![],
        };
        assert!(parse_newlink_message(&info).is_err());
    }

    #[test]
    fn resolves_main_name() {
        assert_eq!(
            rtnl_resolve_ifname_full(&repo(), ResolveInterfaceNameFlag::MAIN, "eth0")
                .unwrap()
                .ifindex,
            5
        );
    }

    #[test]
    fn resolves_alternative_name() {
        assert_eq!(
            rtnl_resolve_ifname_full(&repo(), ResolveInterfaceNameFlag::ALTERNATIVE, "peer0")
                .unwrap()
                .ifindex,
            7
        );
    }

    #[test]
    fn resolves_numeric_ifindex() {
        assert_eq!(
            rtnl_resolve_ifname_full(&repo(), ResolveInterfaceNameFlag::NUMERIC, "7")
                .unwrap()
                .name,
            "veth0"
        );
    }

    #[test]
    fn rename_updates_name() {
        let mut repo = repo();
        rtnl_rename_link(&mut repo, "eth0", "lan0").unwrap();
        assert_eq!(repo.by_ifindex(5).unwrap().name, "lan0");
    }

    #[test]
    fn dedup_filters_invalid_values() {
        let request = vec![
            "uplink0".to_string(),
            "bad name".to_string(),
            "alt1".to_string(),
            "alt1".to_string(),
        ];
        assert_eq!(
            dedup_alternative_names(Some("veth0"), &request, &["peer0".to_string()]),
            vec!["alt1".to_string(), "uplink0".to_string()]
        );
    }

    #[test]
    fn set_link_name_replaces_altnames() {
        let mut repo = repo();
        rtnl_set_link_name(
            &mut repo,
            7,
            Some("uplink1"),
            &["new0".to_string(), "uplink1".to_string()],
        )
        .unwrap();
        let info = repo.by_ifindex(7).unwrap();
        assert_eq!(info.name, "uplink1");
        assert_eq!(info.alternative_names, vec!["new0".to_string()]);
    }
}
