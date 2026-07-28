// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-hwdb.c
//
// Hardware database lookup helpers.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hwdb {
    entries: BTreeMap<String, BTreeMap<String, String>>,
}

impl Hwdb {
    pub fn new(entries: BTreeMap<String, BTreeMap<String, String>>) -> Self {
        Self { entries }
    }
    pub fn query(&self, modalias: &str) -> BTreeMap<String, String> {
        self.entries
            .iter()
            .filter(|(pattern, _)| modalias.starts_with(pattern.as_str()))
            .flat_map(|(_, values)| values.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn returns_matching_properties() {
        let hwdb = Hwdb::new(BTreeMap::from([(
            "usb:v1".into(),
            BTreeMap::from([("ID_MODEL".into(), "Keyboard".into())]),
        )]));
        let props = hwdb.query("usb:v1p2");
        assert_eq!(props["ID_MODEL"], "Keyboard");
    }
    #[test]
    fn returns_empty_map_for_miss() {
        let hwdb = Hwdb::new(BTreeMap::new());
        assert!(hwdb.query("pci:1").is_empty());
    }
}
