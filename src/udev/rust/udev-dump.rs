// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-dump.c
//
// Text dump helpers for udev state.

use std::collections::BTreeMap;

pub fn dump_properties(properties: &BTreeMap<String, String>) -> String {
    properties
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn dump_section(name: &str, body: &str) -> String {
    format!("[{name}]\n{body}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dumps_sorted_properties() {
        let map = BTreeMap::from([("A".into(), "1".into()), ("B".into(), "2".into())]);
        assert_eq!(dump_properties(&map), "A=1\nB=2");
    }
    #[test]
    fn wraps_section() {
        assert_eq!(dump_section("device", "A=1"), "[device]\nA=1");
    }
}
