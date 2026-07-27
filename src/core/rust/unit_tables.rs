// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit.c, src/core/unit.h
//
// Unit enum string table conversions for collect mode, mount dependency
// type, and OOM policy.
//
// Provides safe Rust equivalents for the DEFINE_STRING_TABLE_LOOKUP
// string tables in unit.c (collect_mode_table,
// unit_mount_dependency_type_table, oom_policy_table).

// ── Enums ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectMode {
    Inactive,
    InactiveOrFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitMountDependencyType {
    Wants,
    Requires,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OomPolicy {
    Continue,
    Stop,
    Kill,
}

// ── Error ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableError;

// ── CollectMode table ─────────────────────────────────────────────────────

static COLLECT_MODE_TABLE: &[(CollectMode, &str)] = &[
    (CollectMode::Inactive, "inactive"),
    (CollectMode::InactiveOrFailed, "inactive-or-failed"),
];

pub fn collect_mode_to_string(mode: CollectMode) -> Option<&'static str> {
    COLLECT_MODE_TABLE
        .iter()
        .find(|(m, _)| *m == mode)
        .map(|(_, name)| *name)
}

pub fn collect_mode_from_string(name: &str) -> Result<CollectMode, TableError> {
    COLLECT_MODE_TABLE
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(mode, _)| *mode)
        .ok_or(TableError)
}

// ── UnitMountDependencyType table ─────────────────────────────────────────

static UNIT_MOUNT_DEPENDENCY_TYPE_TABLE: &[(UnitMountDependencyType, &str)] = &[
    (UnitMountDependencyType::Wants, "WantsMountsFor"),
    (UnitMountDependencyType::Requires, "RequiresMountsFor"),
];

pub fn unit_mount_dependency_type_to_string(dep: UnitMountDependencyType) -> Option<&'static str> {
    UNIT_MOUNT_DEPENDENCY_TYPE_TABLE
        .iter()
        .find(|(d, _)| *d == dep)
        .map(|(_, name)| *name)
}

pub fn unit_mount_dependency_type_from_string(
    name: &str,
) -> Result<UnitMountDependencyType, TableError> {
    UNIT_MOUNT_DEPENDENCY_TYPE_TABLE
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(dep, _)| *dep)
        .ok_or(TableError)
}

/// Map a mount dependency type to the corresponding unit dependency type.
///
/// Equivalent to `unit_mount_dependency_type_to_dependency_type()` in unit.c.
pub fn mount_dependency_to_unit_dependency(dep: UnitMountDependencyType) -> &'static str {
    match dep {
        UnitMountDependencyType::Wants => "Wants",
        UnitMountDependencyType::Requires => "Requires",
    }
}

// ── OomPolicy table ───────────────────────────────────────────────────────

static OOM_POLICY_TABLE: &[(OomPolicy, &str)] = &[
    (OomPolicy::Continue, "continue"),
    (OomPolicy::Stop, "stop"),
    (OomPolicy::Kill, "kill"),
];

pub fn oom_policy_to_string(policy: OomPolicy) -> Option<&'static str> {
    OOM_POLICY_TABLE
        .iter()
        .find(|(p, _)| *p == policy)
        .map(|(_, name)| *name)
}

pub fn oom_policy_from_string(name: &str) -> Result<OomPolicy, TableError> {
    OOM_POLICY_TABLE
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(policy, _)| *policy)
        .ok_or(TableError)
}

// ── Generic helpers ───────────────────────────────────────────────────────

pub fn table_to_string_raw<'a>(table: &'a [&'a str], v: i32) -> Option<&'a str> {
    if v < 0 {
        return None;
    }
    let idx = v as usize;
    if idx >= table.len() {
        return None;
    }
    Some(table[idx])
}

pub fn table_from_string_raw(table: &[&str], s: &str) -> Result<i32, TableError> {
    table
        .iter()
        .position(|item| *item == s)
        .map(|idx| idx as i32)
        .ok_or(TableError)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_mode_roundtrip() {
        for mode in [CollectMode::Inactive, CollectMode::InactiveOrFailed] {
            let name = collect_mode_to_string(mode).unwrap();
            let back = collect_mode_from_string(name).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn test_collect_mode_known_values() {
        assert_eq!(
            collect_mode_to_string(CollectMode::Inactive),
            Some("inactive")
        );
        assert_eq!(
            collect_mode_to_string(CollectMode::InactiveOrFailed),
            Some("inactive-or-failed")
        );
    }

    #[test]
    fn test_collect_mode_from_string_invalid() {
        assert!(collect_mode_from_string("active").is_err());
    }

    #[test]
    fn test_unit_mount_dependency_type_roundtrip() {
        for dep in [
            UnitMountDependencyType::Wants,
            UnitMountDependencyType::Requires,
        ] {
            let name = unit_mount_dependency_type_to_string(dep).unwrap();
            let back = unit_mount_dependency_type_from_string(name).unwrap();
            assert_eq!(back, dep);
        }
    }

    #[test]
    fn test_unit_mount_dependency_type_known_values() {
        assert_eq!(
            unit_mount_dependency_type_to_string(UnitMountDependencyType::Wants),
            Some("WantsMountsFor")
        );
        assert_eq!(
            unit_mount_dependency_type_to_string(UnitMountDependencyType::Requires),
            Some("RequiresMountsFor")
        );
    }

    #[test]
    fn test_mount_dependency_to_unit_dependency() {
        assert_eq!(
            mount_dependency_to_unit_dependency(UnitMountDependencyType::Wants),
            "Wants"
        );
        assert_eq!(
            mount_dependency_to_unit_dependency(UnitMountDependencyType::Requires),
            "Requires"
        );
    }

    #[test]
    fn test_unit_mount_dependency_from_string_invalid() {
        assert!(unit_mount_dependency_type_from_string("foo").is_err());
    }

    #[test]
    fn test_oom_policy_roundtrip() {
        for policy in [OomPolicy::Continue, OomPolicy::Stop, OomPolicy::Kill] {
            let name = oom_policy_to_string(policy).unwrap();
            let back = oom_policy_from_string(name).unwrap();
            assert_eq!(back, policy);
        }
    }

    #[test]
    fn test_oom_policy_known_values() {
        assert_eq!(oom_policy_to_string(OomPolicy::Continue), Some("continue"));
        assert_eq!(oom_policy_to_string(OomPolicy::Stop), Some("stop"));
        assert_eq!(oom_policy_to_string(OomPolicy::Kill), Some("kill"));
    }

    #[test]
    fn test_oom_policy_from_string_invalid() {
        assert!(oom_policy_from_string("wait").is_err());
    }

    #[test]
    fn test_table_to_string_raw_valid() {
        let table: &[&str] = &["a", "b", "c"];
        assert_eq!(table_to_string_raw(table, 0), Some("a"));
        assert_eq!(table_to_string_raw(table, 2), Some("c"));
    }

    #[test]
    fn test_table_to_string_raw_out_of_range() {
        let table: &[&str] = &["a", "b"];
        assert_eq!(table_to_string_raw(table, -1), None);
        assert_eq!(table_to_string_raw(table, 5), None);
    }

    #[test]
    fn test_table_from_string_roundtrip() {
        let table: &[&str] = &["inactive", "inactive-or-failed"];
        assert_eq!(table_from_string_raw(table, "inactive"), Ok(0));
        assert_eq!(table_from_string_raw(table, "inactive-or-failed"), Ok(1));
        assert!(table_from_string_raw(table, "nonexistent").is_err());
    }
}
