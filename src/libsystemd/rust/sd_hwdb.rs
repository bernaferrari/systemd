// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-hwdb/sd-hwdb.c

use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, HwdbError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwdbError {
    InvalidInput,
    NotFound,
    NeedSeek,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwdbEntry {
    pub pattern: String,
    pub key: String,
    pub value: String,
    pub file_priority: u32,
    pub line_number: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hwdb {
    entries: Vec<HwdbEntry>,
    properties: BTreeMap<String, HwdbEntry>,
    iter_keys: Vec<String>,
    iter_index: usize,
    properties_modified: bool,
}

impl Hwdb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_entry(
        &mut self,
        pattern: &str,
        key: &str,
        value: &str,
        file_priority: u32,
        line_number: u32,
    ) {
        self.entries.push(HwdbEntry {
            pattern: pattern.into(),
            key: key.into(),
            value: value.into(),
            file_priority,
            line_number,
        });
    }

    pub fn get(&mut self, modalias: &str, key: &str) -> Result<&str> {
        self.seek(modalias)?;
        self.properties
            .get(key)
            .map(|entry| entry.value.as_str())
            .ok_or(HwdbError::NotFound)
    }

    pub fn seek(&mut self, modalias: &str) -> Result<()> {
        if modalias.is_empty() {
            return Err(HwdbError::InvalidInput);
        }

        self.properties.clear();
        for entry in self
            .entries
            .iter()
            .filter(|entry| glob_match(&entry.pattern, modalias))
        {
            match self.properties.get(&entry.key) {
                Some(previous) if !is_higher_priority(entry, previous) => {}
                _ => {
                    self.properties.insert(entry.key.clone(), entry.clone());
                }
            }
        }

        self.iter_keys = self.properties.keys().cloned().collect();
        self.iter_index = 0;
        self.properties_modified = false;
        Ok(())
    }

    pub fn enumerate(&mut self) -> Result<Option<(&str, &str)>> {
        if self.properties_modified {
            return Err(HwdbError::NeedSeek);
        }
        let Some(key) = self.iter_keys.get(self.iter_index) else {
            return Ok(None);
        };
        self.iter_index += 1;
        let entry = self.properties.get(key).expect("iter key must exist");
        Ok(Some((entry.key.as_str(), entry.value.as_str())))
    }

    pub fn get_properties(&mut self, modalias: &str) -> Result<Vec<(String, String)>> {
        self.seek(modalias)?;
        Ok(self
            .properties
            .values()
            .map(|entry| (entry.key.clone(), entry.value.clone()))
            .collect())
    }

    pub fn get_properties_strv(&mut self, modalias: &str) -> Result<Vec<String>> {
        Ok(self
            .get_properties(modalias)?
            .into_iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect())
    }

    pub fn apply(
        &mut self,
        modalias: &str,
        device: &mut BTreeMap<String, String>,
    ) -> Result<usize> {
        self.seek(modalias)?;
        for entry in self.properties.values() {
            device.insert(entry.key.clone(), entry.value.clone());
        }
        Ok(self.properties.len())
    }

    pub fn set_property(
        &mut self,
        device: &mut BTreeMap<String, String>,
        key: &str,
        value: &str,
    ) -> Result<()> {
        if key.is_empty() {
            return Err(HwdbError::InvalidInput);
        }
        device.insert(key.into(), value.into());
        Ok(())
    }
}

fn is_higher_priority(candidate: &HwdbEntry, current: &HwdbEntry) -> bool {
    candidate.file_priority > current.file_priority
        || (candidate.file_priority == current.file_priority
            && candidate.line_number >= current.line_number)
}

fn glob_match(pattern: &str, value: &str) -> bool {
    glob_match_bytes(pattern.as_bytes(), value.as_bytes())
}

fn glob_match_bytes(pattern: &[u8], value: &[u8]) -> bool {
    let (mut p, mut v, mut star_p, mut star_v) = (0usize, 0usize, None, 0usize);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
            continue;
        }
        if p < pattern.len() && pattern[p] == b'*' {
            star_p = Some(p);
            p += 1;
            star_v = v;
            continue;
        }
        if let Some(star) = star_p {
            p = star + 1;
            star_v += 1;
            v = star_v;
            continue;
        }
        return false;
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hwdb() -> Hwdb {
        let mut hwdb = Hwdb::new();
        hwdb.add_entry("usb:*", "ID_VENDOR", "generic", 10, 1);
        hwdb.add_entry("usb:v1D6B*", "ID_VENDOR", "linux-foundation", 20, 2);
        hwdb.add_entry("usb:v1D6B*", "ID_MODEL", "root-hub", 20, 3);
        hwdb
    }

    #[test]
    fn get_returns_best_priority_match() {
        let mut hwdb = sample_hwdb();
        assert_eq!(
            hwdb.get("usb:v1D6Bp0002", "ID_VENDOR").unwrap(),
            "linux-foundation"
        );
    }

    #[test]
    fn get_reports_missing_key() {
        let mut hwdb = sample_hwdb();
        assert_eq!(
            hwdb.get("usb:v1D6Bp0002", "ID_SERIAL"),
            Err(HwdbError::NotFound)
        );
    }

    #[test]
    fn seek_prepares_enumeration() {
        let mut hwdb = sample_hwdb();
        hwdb.seek("usb:v1D6Bp0002").unwrap();
        assert_eq!(hwdb.enumerate().unwrap(), Some(("ID_MODEL", "root-hub")));
    }

    #[test]
    fn get_properties_returns_pairs() {
        let mut hwdb = sample_hwdb();
        assert_eq!(hwdb.get_properties("usb:v1D6Bp0002").unwrap().len(), 2);
    }

    #[test]
    fn get_properties_strv_formats_assignments() {
        let mut hwdb = sample_hwdb();
        let props = hwdb.get_properties_strv("usb:v1D6Bp0002").unwrap();
        assert!(props.contains(&"ID_MODEL=root-hub".into()));
    }

    #[test]
    fn apply_updates_device_map() {
        let mut hwdb = sample_hwdb();
        let mut device = BTreeMap::new();
        assert_eq!(hwdb.apply("usb:v1D6Bp0002", &mut device).unwrap(), 2);
        assert_eq!(device.get("ID_VENDOR").unwrap(), "linux-foundation");
    }

    #[test]
    fn set_property_rejects_empty_keys() {
        let mut hwdb = sample_hwdb();
        let mut device = BTreeMap::new();
        assert_eq!(
            hwdb.set_property(&mut device, "", "x"),
            Err(HwdbError::InvalidInput)
        );
    }

    #[test]
    fn simple_glob_supports_star_and_question_mark() {
        assert!(glob_match("usb:v1D6B*", "usb:v1D6Bp0002"));
        assert!(glob_match("pci:?000", "pci:1000"));
    }
}
