// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/varlink-common.c, src/core/varlink-common.h
//

use std::collections::BTreeMap;

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/core/varlink-common.c";

pub const BUS_ERROR_NO_SUCH_UNIT: &str = "org.freedesktop.systemd1.NoSuchUnit";
pub const BUS_ERROR_ONLY_BY_DEPENDENCY: &str = "org.freedesktop.systemd1.OnlyByDependency";
pub const BUS_ERROR_SHUTTING_DOWN: &str = "org.freedesktop.systemd1.ShuttingDown";

pub const VARLINK_ERROR_UNIT_NO_SUCH_UNIT: &str = "io.systemd.Unit.NoSuchUnit";
pub const VARLINK_ERROR_UNIT_ONLY_BY_DEPENDENCY: &str = "io.systemd.Unit.OnlyByDependency";
pub const VARLINK_ERROR_UNIT_DBUS_SHUTTING_DOWN: &str = "io.systemd.Unit.DBusShuttingDown";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLimit {
    pub soft: Option<u64>,
    pub hard: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuSet {
    pub bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Object(BTreeMap<String, JsonValue>),
    ArrayBytes(Vec<u8>),
    Unsigned(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarlinkCommonError {
    UnknownRLimitName,
    ResolverFailed(i32),
}

impl VarlinkCommonError {
    pub const fn errno(self) -> i32 {
        match self {
            Self::UnknownRLimitName => Errno::EINVAL.to_neg_errno(),
            Self::ResolverFailed(code) => code,
        }
    }
}

pub fn varlink_error_id_from_bus_error(bus_error_name: Option<&str>) -> Option<&'static str> {
    match bus_error_name {
        Some(BUS_ERROR_NO_SUCH_UNIT) => Some(VARLINK_ERROR_UNIT_NO_SUCH_UNIT),
        Some(BUS_ERROR_ONLY_BY_DEPENDENCY) => Some(VARLINK_ERROR_UNIT_ONLY_BY_DEPENDENCY),
        Some(BUS_ERROR_SHUTTING_DOWN) => Some(VARLINK_ERROR_UNIT_DBUS_SHUTTING_DOWN),
        _ => None,
    }
}

pub fn rlimit_build_json<F>(
    name: &str,
    rlimit: Option<&RLimit>,
    resolver: F,
) -> Result<Option<JsonValue>, VarlinkCommonError>
where
    F: FnOnce(&str) -> Result<Option<RLimit>, VarlinkCommonError>,
{
    let effective = match rlimit {
        Some(value) => value.clone(),
        None => match resolver(name)? {
            Some(value) => value,
            None => return Ok(None),
        },
    };

    if effective.soft.is_none() && effective.hard.is_none() {
        return Ok(None);
    }

    let mut object = BTreeMap::new();
    if let Some(soft) = effective.soft {
        object.insert("soft".to_string(), JsonValue::Unsigned(soft));
    }
    if let Some(hard) = effective.hard {
        object.insert("hard".to_string(), JsonValue::Unsigned(hard));
    }

    Ok(Some(JsonValue::Object(object)))
}

pub fn rlimit_table_build_json<'a, F>(
    names: impl IntoIterator<Item = &'a str>,
    table: &BTreeMap<&'a str, RLimit>,
    mut resolver: F,
) -> Result<JsonValue, VarlinkCommonError>
where
    F: FnMut(&str) -> Result<Option<RLimit>, VarlinkCommonError>,
{
    let mut object = BTreeMap::new();

    for name in names {
        if let Some(value) = rlimit_build_json(name, table.get(name), |current| resolver(current))?
        {
            object.insert(name.to_string(), value);
        }
    }

    Ok(JsonValue::Object(object))
}

pub fn cpuset_build_json(cpuset: &CpuSet) -> Result<Option<JsonValue>, VarlinkCommonError> {
    match &cpuset.bytes {
        None => Ok(None),
        Some(bytes) if bytes.is_empty() => Ok(None),
        Some(bytes) => Ok(Some(JsonValue::ArrayBytes(bytes.clone()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_error_mapping_handles_known_values() {
        assert_eq!(
            varlink_error_id_from_bus_error(Some(BUS_ERROR_NO_SUCH_UNIT)),
            Some(VARLINK_ERROR_UNIT_NO_SUCH_UNIT)
        );
        assert_eq!(
            varlink_error_id_from_bus_error(Some(BUS_ERROR_ONLY_BY_DEPENDENCY)),
            Some(VARLINK_ERROR_UNIT_ONLY_BY_DEPENDENCY)
        );
        assert_eq!(
            varlink_error_id_from_bus_error(Some(BUS_ERROR_SHUTTING_DOWN)),
            Some(VARLINK_ERROR_UNIT_DBUS_SHUTTING_DOWN)
        );
    }

    #[test]
    fn bus_error_mapping_ignores_unknown_values() {
        assert_eq!(varlink_error_id_from_bus_error(None), None);
        assert_eq!(
            varlink_error_id_from_bus_error(Some("org.example.Other")),
            None
        );
    }

    #[test]
    fn explicit_rlimit_uses_provided_value() {
        let value = RLimit {
            soft: Some(10),
            hard: Some(20),
        };

        let json = rlimit_build_json("LimitNOFILE", Some(&value), |_| unreachable!()).unwrap();
        assert_eq!(
            json,
            Some(JsonValue::Object(BTreeMap::from([
                ("hard".to_string(), JsonValue::Unsigned(20)),
                ("soft".to_string(), JsonValue::Unsigned(10)),
            ])))
        );
    }

    #[test]
    fn implicit_rlimit_uses_resolver() {
        let json = rlimit_build_json("LimitCPU", None, |name| {
            assert_eq!(name, "LimitCPU");
            Ok(Some(RLimit {
                soft: Some(5),
                hard: None,
            }))
        })
        .unwrap();

        assert_eq!(
            json,
            Some(JsonValue::Object(BTreeMap::from([(
                "soft".to_string(),
                JsonValue::Unsigned(5),
            )])))
        );
    }

    #[test]
    fn infinite_rlimit_returns_none() {
        let json = rlimit_build_json(
            "LimitAS",
            Some(&RLimit {
                soft: None,
                hard: None,
            }),
            |_| unreachable!(),
        )
        .unwrap();

        assert_eq!(json, None);
    }

    #[test]
    fn resolver_can_return_none_for_missing_rlimit() {
        let json = rlimit_build_json("LimitFSIZE", None, |_| Ok(None)).unwrap();
        assert_eq!(json, None);
    }

    #[test]
    fn rlimit_table_merges_non_empty_entries() {
        let table = BTreeMap::from([(
            "LimitNOFILE",
            RLimit {
                soft: Some(1),
                hard: Some(2),
            },
        )]);

        let json = rlimit_table_build_json(["LimitNOFILE", "LimitCPU"], &table, |_| {
            Ok(Some(RLimit {
                soft: Some(3),
                hard: None,
            }))
        })
        .unwrap();

        let JsonValue::Object(object) = json else {
            panic!("expected object");
        };

        assert_eq!(object.len(), 2);
        assert!(object.contains_key("LimitNOFILE"));
        assert!(object.contains_key("LimitCPU"));
    }

    #[test]
    fn cpuset_none_returns_none() {
        assert_eq!(cpuset_build_json(&CpuSet { bytes: None }).unwrap(), None);
    }

    #[test]
    fn cpuset_empty_returns_none() {
        assert_eq!(
            cpuset_build_json(&CpuSet {
                bytes: Some(vec![])
            })
            .unwrap(),
            None
        );
    }

    #[test]
    fn cpuset_bytes_become_array_json() {
        assert_eq!(
            cpuset_build_json(&CpuSet {
                bytes: Some(vec![1, 2, 3]),
            })
            .unwrap(),
            Some(JsonValue::ArrayBytes(vec![1, 2, 3]))
        );
    }

    #[test]
    fn error_errno_mapping_is_preserved() {
        assert_eq!(
            VarlinkCommonError::UnknownRLimitName.errno(),
            Errno::EINVAL.to_neg_errno()
        );
        assert_eq!(
            VarlinkCommonError::ResolverFailed(Errno::EIO.to_neg_errno()).errno(),
            Errno::EIO.to_neg_errno()
        );
    }
}
