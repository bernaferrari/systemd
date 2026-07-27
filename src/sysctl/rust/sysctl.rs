// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/sysctl/sysctl.c
//
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionEntry {
    pub key: String,
    pub value: Option<String>,
    pub ignore_failure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysctlError {
    InvalidLine(String),
}

impl std::fmt::Display for SysctlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SysctlError {}

pub fn sysctl_normalize(key: &str) -> String {
    key.trim()
        .trim_start_matches("/proc/sys/")
        .replace('/', ".")
        .trim_start_matches('.')
        .to_string()
}

pub fn test_prefix(key: &str, prefixes: &[String]) -> bool {
    prefixes.is_empty() || prefixes.iter().any(|p| key.starts_with(p))
}

pub fn string_is_glob(value: &str) -> bool {
    value.contains('*') || value.contains('?') || value.contains('[')
}

pub fn parse_line(line: &str) -> Result<OptionEntry, SysctlError> {
    let raw = line.trim();
    if let Some((k, v)) = raw.split_once('=') {
        let mut key = k.trim();
        let ignore_failure = key.starts_with('-');
        if ignore_failure {
            key = &key[1..];
        }
        Ok(OptionEntry {
            key: sysctl_normalize(key),
            value: Some(v.trim().to_string()),
            ignore_failure,
        })
    } else {
        let key = raw
            .strip_prefix('-')
            .ok_or_else(|| SysctlError::InvalidLine(raw.into()))?;
        Ok(OptionEntry {
            key: sysctl_normalize(key),
            value: None,
            ignore_failure: false,
        })
    }
}

pub fn merge_options(lines: &[OptionEntry]) -> BTreeMap<String, OptionEntry> {
    let mut map = BTreeMap::new();
    for entry in lines {
        map.insert(entry.key.clone(), entry.clone());
    }
    map
}

pub fn wildcard_matches(pattern: &str, text: &str) -> bool {
    fn inner(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => inner(&p[1..], t) || (!t.is_empty() && inner(p, &t[1..])),
            (Some(b'?'), Some(_)) => inner(&p[1..], &t[1..]),
            (Some(a), Some(b)) if a == b => inner(&p[1..], &t[1..]),
            _ => false,
        }
    }
    inner(pattern.as_bytes(), text.as_bytes())
}

pub fn explicit_keys(entries: &BTreeMap<String, OptionEntry>) -> Vec<String> {
    entries
        .values()
        .filter(|e| !string_is_glob(&e.key))
        .map(|e| e.key.clone())
        .collect()
}

pub fn applyable_entries(entries: &BTreeMap<String, OptionEntry>) -> Vec<&OptionEntry> {
    entries.values().filter(|e| e.value.is_some()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_proc_prefix() {
        assert_eq!(
            sysctl_normalize("/proc/sys/net/ipv4/ip_forward"),
            "net.ipv4.ip_forward"
        );
    }

    #[test]
    fn parses_assignment() {
        let e = parse_line("a.b = 1").unwrap();
        assert_eq!(e.key, "a.b");
        assert_eq!(e.value.as_deref(), Some("1"));
    }

    #[test]
    fn parses_ignore_failure_assignment() {
        assert!(parse_line("-a.b=1").unwrap().ignore_failure);
    }

    #[test]
    fn parses_negative_match() {
        assert_eq!(parse_line("-kernel.*").unwrap().value, None);
    }

    #[test]
    fn rejects_invalid_line() {
        assert!(matches!(
            parse_line("kernel.pid_max"),
            Err(SysctlError::InvalidLine(_))
        ));
    }

    #[test]
    fn prefix_filter_matches() {
        assert!(test_prefix("net.ipv4", &["net".into()]));
    }

    #[test]
    fn wildcard_supports_star() {
        assert!(wildcard_matches("net.*", "net.ipv4"));
    }

    #[test]
    fn merge_overwrites_earlier_assignment() {
        let merged = merge_options(&[parse_line("a=1").unwrap(), parse_line("a=2").unwrap()]);
        assert_eq!(merged["a"].value.as_deref(), Some("2"));
    }
}
