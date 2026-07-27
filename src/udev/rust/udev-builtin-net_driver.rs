// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-net_driver.c
//
// Network driver property extraction.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetDriverError { EmptyDriver }
pub type Result<T> = std::result::Result<T, NetDriverError>;

pub fn build_net_driver_properties(driver: &str, ifname: &str) -> Result<BTreeMap<String, String>> {
    if driver.trim().is_empty() { return Err(NetDriverError::EmptyDriver); }
    Ok(BTreeMap::from([("ID_NET_DRIVER".into(), driver.trim().into()), ("INTERFACE".into(), ifname.trim().into())]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn exports_driver_property() { let props = build_net_driver_properties("e1000e", "eth0").unwrap(); assert_eq!(props["ID_NET_DRIVER"], "e1000e"); }
    #[test] fn rejects_empty_driver() { assert_eq!(build_net_driver_properties(" ", "eth0"), Err(NetDriverError::EmptyDriver)); }
}
