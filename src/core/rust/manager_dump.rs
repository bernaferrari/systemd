// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/manager-dump.c
//

//! Compiled-but-disconnected manager-dump rendering model.
//!
//! Its `Manager`, `Unit`, and `Job` values are dump inputs rather than a
//! replacement for [`crate::runtime_manager::RuntimeManager`] ownership.

use crate::ffi::Errno;
use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    pub id: String,
    pub body: Vec<String>,
}

impl Unit {
    pub fn dump(&self, prefix: &str) -> String {
        let mut out = format!("{prefix}Unit: {}\n", self.id);
        for line in &self.body {
            out.push_str(prefix);
            out.push_str(line);
            out.push('\n');
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub id: u32,
    pub unit_id: String,
    pub kind: String,
}

impl Job {
    pub fn dump(&self, prefix: &str) -> String {
        format!("{prefix}Job {}: {} {}\n", self.id, self.unit_id, self.kind)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampValue {
    Realtime(String),
    Monotonic(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manager {
    pub project_version_full: String,
    pub git_version: String,
    pub systemd_features: String,
    pub timestamps: Vec<(String, TimestampValue)>,
    pub subscribed: Vec<String>,
    pub units: BTreeMap<String, Unit>,
    pub jobs: BTreeMap<u32, Job>,
}

impl Default for Manager {
    fn default() -> Self {
        Self {
            project_version_full: "test-version".into(),
            git_version: "test-git".into(),
            systemd_features: "feature-a feature-b".into(),
            timestamps: Vec::new(),
            subscribed: Vec::new(),
            units: BTreeMap::new(),
            jobs: BTreeMap::new(),
        }
    }
}

fn strempty(prefix: Option<&str>) -> &str {
    prefix.unwrap_or("")
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    fn inner(pattern: &[u8], value: &[u8]) -> bool {
        if pattern.is_empty() {
            return value.is_empty();
        }
        match pattern[0] {
            b'*' => (0..=value.len()).any(|i| inner(&pattern[1..], &value[i..])),
            b'?' => !value.is_empty() && inner(&pattern[1..], &value[1..]),
            c => !value.is_empty() && c == value[0] && inner(&pattern[1..], &value[1..]),
        }
    }
    inner(pattern.as_bytes(), value.as_bytes())
}

fn strv_fnmatch_or_empty(patterns: Option<&[String]>, value: &str) -> bool {
    match patterns {
        None => true,
        Some([]) => true,
        Some(patterns) => patterns.iter().any(|pattern| glob_matches(pattern, value)),
    }
}

pub fn manager_dump_jobs(
    m: &Manager,
    patterns: Option<&[String]>,
    prefix: Option<&str>,
) -> Result<String> {
    let prefix = strempty(prefix);
    let mut out = String::new();
    for job in m.jobs.values() {
        if strv_fnmatch_or_empty(patterns, &job.unit_id) {
            out.push_str(&job.dump(prefix));
        }
    }
    Ok(out)
}

pub fn manager_get_dump_jobs_string(
    m: &Manager,
    patterns: Option<&[String]>,
    prefix: Option<&str>,
) -> Result<String> {
    manager_dump_jobs(m, patterns, prefix)
}

pub fn manager_dump_units(
    m: &Manager,
    patterns: Option<&[String]>,
    prefix: Option<&str>,
) -> Result<String> {
    let prefix = strempty(prefix);
    let mut out = String::new();
    for (key, unit) in &m.units {
        if key != &unit.id {
            continue;
        }
        if strv_fnmatch_or_empty(patterns, &unit.id) {
            out.push_str(&unit.dump(prefix));
        }
    }
    Ok(out)
}

pub fn manager_dump_header(m: &Manager, prefix: Option<&str>) -> Result<String> {
    let prefix = strempty(prefix);
    let mut out = format!(
        "{prefix}Manager: systemd {} ({})\n{prefix}Features: {}\n",
        m.project_version_full, m.git_version, m.systemd_features
    );

    for (name, value) in &m.timestamps {
        let rendered = match value {
            TimestampValue::Realtime(v) | TimestampValue::Monotonic(v) => v,
        };
        out.push_str(&format!("{prefix}Timestamp {name}: {rendered}\n"));
    }

    for name in &m.subscribed {
        out.push_str(&format!("{prefix}Subscribed: {name}\n"));
    }

    Ok(out)
}

pub fn manager_dump(
    m: &Manager,
    patterns: Option<&[String]>,
    prefix: Option<&str>,
) -> Result<String> {
    let mut out = String::new();
    if patterns.is_none() {
        out.push_str(&manager_dump_header(m, prefix)?);
    }
    out.push_str(&manager_dump_units(m, patterns, prefix)?);
    out.push_str(&manager_dump_jobs(m, patterns, prefix)?);
    Ok(out)
}

pub fn manager_get_dump_string(m: &Manager, patterns: Option<&[String]>) -> Result<String> {
    manager_dump(m, patterns, None)
}

pub fn manager_test_summary(m: &Manager) -> Result<String> {
    Ok(format!(
        "-> By units:\n{}-> By jobs:\n{}",
        manager_dump_units(m, None, Some("\t"))?,
        manager_dump_jobs(m, None, Some("\t"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manager() -> Manager {
        let mut manager = Manager::default();
        manager.units.insert(
            "a.service".into(),
            Unit {
                id: "a.service".into(),
                body: vec!["State=active".into()],
            },
        );
        manager.units.insert(
            "b.timer".into(),
            Unit {
                id: "b.timer".into(),
                body: vec!["State=waiting".into()],
            },
        );
        manager.jobs.insert(
            1,
            Job {
                id: 1,
                unit_id: "a.service".into(),
                kind: "start".into(),
            },
        );
        manager.subscribed.push("org.freedesktop.systemd1".into());
        manager
            .timestamps
            .push(("userspace".into(), TimestampValue::Realtime("now".into())));
        manager
    }

    #[test]
    fn dumps_jobs() {
        let text = manager_dump_jobs(&sample_manager(), None, None).unwrap();
        assert!(text.contains("Job 1"));
    }

    #[test]
    fn filters_jobs_by_pattern() {
        let patterns = vec!["a.*".to_string()];
        let text = manager_dump_jobs(&sample_manager(), Some(&patterns), None).unwrap();
        assert!(text.contains("a.service"));
    }

    #[test]
    fn dumps_units_only_for_canonical_key() {
        let mut manager = sample_manager();
        manager.units.insert(
            "alias.service".into(),
            Unit {
                id: "real.service".into(),
                body: vec!["ignored".into()],
            },
        );
        let text = manager_dump_units(&manager, None, None).unwrap();
        assert!(!text.contains("real.service\nignored"));
    }

    #[test]
    fn header_contains_versions_and_subscriptions() {
        let text = manager_dump_header(&sample_manager(), Some("# ")).unwrap();
        assert!(text.contains("# Manager: systemd"));
        assert!(text.contains("# Subscribed: org.freedesktop.systemd1"));
    }

    #[test]
    fn full_dump_includes_header_without_patterns() {
        let text = manager_dump(&sample_manager(), None, None).unwrap();
        assert!(text.contains("Manager: systemd"));
    }

    #[test]
    fn filtered_dump_skips_header() {
        let patterns = vec!["*.timer".to_string()];
        let text = manager_dump(&sample_manager(), Some(&patterns), None).unwrap();
        assert!(!text.contains("Manager: systemd"));
        assert!(text.contains("b.timer"));
    }

    #[test]
    fn get_dump_string_forwards_to_dump() {
        let text = manager_get_dump_string(&sample_manager(), None).unwrap();
        assert!(text.contains("a.service"));
    }

    #[test]
    fn test_summary_has_both_sections() {
        let text = manager_test_summary(&sample_manager()).unwrap();
        assert!(text.contains("-> By units:"));
        assert!(text.contains("-> By jobs:"));
    }

    #[test]
    fn glob_matching_supports_star() {
        assert!(glob_matches("a*", "alpha"));
        assert!(!glob_matches("b*", "alpha"));
    }
}
