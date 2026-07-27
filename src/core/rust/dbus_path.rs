// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-path.c
//
use crate::ffi::Errno;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathType {
    Exists,
    ExistsGlob,
    DirectoryNotEmpty,
    Changed,
    Modified,
}

impl PathType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exists => "PathExists",
            Self::ExistsGlob => "PathExistsGlob",
            Self::DirectoryNotEmpty => "DirectoryNotEmpty",
            Self::Changed => "PathChanged",
            Self::Modified => "PathModified",
        }
    }

    pub fn from_str(value: &str) -> Result<Self, Errno> {
        match value {
            "PathExists" => Ok(Self::Exists),
            "PathExistsGlob" => Ok(Self::ExistsGlob),
            "DirectoryNotEmpty" => Ok(Self::DirectoryNotEmpty),
            "PathChanged" => Ok(Self::Changed),
            "PathModified" => Ok(Self::Modified),
            _ => Err(Errno::EINVAL),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSpec {
    pub path: String,
    pub path_type: PathType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadState {
    Stub,
    Loaded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerLimit {
    pub interval_usec: u64,
    pub burst: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathUnit {
    pub transient: bool,
    pub load_state: LoadState,
    pub specs: Vec<PathSpec>,
    pub make_directory: bool,
    pub directory_mode: u32,
    pub trigger_limit: TriggerLimit,
    pub written_settings: Vec<String>,
}

impl Default for PathUnit {
    fn default() -> Self {
        Self {
            transient: false,
            load_state: LoadState::Loaded,
            specs: Vec::new(),
            make_directory: false,
            directory_mode: 0o755,
            trigger_limit: TriggerLimit {
                interval_usec: 0,
                burst: 0,
            },
            written_settings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyValue {
    Bool(bool),
    Mode(u32),
    Unsigned(u32),
    Usec(u64),
    Paths(Vec<(String, String)>),
}

pub fn property_get_paths(unit: &PathUnit) -> Result<Vec<(String, String)>, Errno> {
    if unit.specs.iter().any(|spec| spec.path.is_empty()) {
        return Err(Errno::EINVAL);
    }

    Ok(unit
        .specs
        .iter()
        .map(|spec| (spec.path_type.as_str().to_owned(), spec.path.clone()))
        .collect())
}

fn simplify_path(path: &str) -> String {
    let mut simplified = String::new();
    let mut previous_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if !previous_slash {
                simplified.push(ch);
            }
            previous_slash = true;
        } else {
            simplified.push(ch);
            previous_slash = false;
        }
    }
    if simplified.len() > 1 && simplified.ends_with('/') {
        simplified.pop();
    }
    simplified
}

pub fn bus_path_set_transient_property(
    unit: &mut PathUnit,
    name: &str,
    value: PropertyValue,
) -> Result<bool, Errno> {
    match (name, value) {
        ("MakeDirectory", PropertyValue::Bool(v)) => {
            unit.make_directory = v;
            unit.written_settings.push(format!("MakeDirectory={v}"));
            Ok(true)
        }
        ("DirectoryMode", PropertyValue::Mode(v)) => {
            unit.directory_mode = v;
            unit.written_settings.push(format!("DirectoryMode={v:o}"));
            Ok(true)
        }
        ("TriggerLimitBurst", PropertyValue::Unsigned(v)) => {
            unit.trigger_limit.burst = v;
            unit.written_settings.push(format!("TriggerLimitBurst={v}"));
            Ok(true)
        }
        ("TriggerLimitIntervalUSec", PropertyValue::Usec(v)) => {
            unit.trigger_limit.interval_usec = v;
            unit.written_settings
                .push(format!("TriggerLimitIntervalUSec={v}"));
            Ok(true)
        }
        ("Paths", PropertyValue::Paths(entries)) => {
            if entries.is_empty() {
                unit.specs.clear();
                unit.written_settings.push("PathExists=".to_string());
                return Ok(true);
            }

            for (type_name, path) in entries {
                if path.is_empty() || !path.starts_with('/') {
                    return Err(Errno::EINVAL);
                }
                let path_type = PathType::from_str(&type_name)?;
                let simplified = simplify_path(&path);
                unit.specs.push(PathSpec {
                    path: simplified.clone(),
                    path_type,
                });
                unit.written_settings
                    .push(format!("{type_name}={simplified}"));
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub fn bus_path_set_property(
    unit: &mut PathUnit,
    name: &str,
    value: PropertyValue,
) -> Result<bool, Errno> {
    if unit.transient && unit.load_state == LoadState::Stub {
        return bus_path_set_transient_property(unit, name, value);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transient_stub_unit() -> PathUnit {
        PathUnit {
            transient: true,
            load_state: LoadState::Stub,
            ..PathUnit::default()
        }
    }

    #[test]
    fn property_get_paths_returns_serialized_pairs() {
        let unit = PathUnit {
            specs: vec![PathSpec {
                path: "/tmp/demo".into(),
                path_type: PathType::Exists,
            }],
            ..PathUnit::default()
        };
        assert_eq!(
            property_get_paths(&unit).unwrap(),
            vec![("PathExists".into(), "/tmp/demo".into())]
        );
    }

    #[test]
    fn property_get_paths_rejects_empty_path() {
        let unit = PathUnit {
            specs: vec![PathSpec {
                path: String::new(),
                path_type: PathType::Exists,
            }],
            ..PathUnit::default()
        };
        assert_eq!(property_get_paths(&unit).unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn transient_boolean_property_is_applied() {
        let mut unit = transient_stub_unit();
        assert!(
            bus_path_set_property(&mut unit, "MakeDirectory", PropertyValue::Bool(true)).unwrap()
        );
        assert!(unit.make_directory);
    }

    #[test]
    fn transient_mode_property_is_applied() {
        let mut unit = transient_stub_unit();
        bus_path_set_property(&mut unit, "DirectoryMode", PropertyValue::Mode(0o700)).unwrap();
        assert_eq!(unit.directory_mode, 0o700);
    }

    #[test]
    fn path_entries_are_simplified_and_stored() {
        let mut unit = transient_stub_unit();
        bus_path_set_property(
            &mut unit,
            "Paths",
            PropertyValue::Paths(vec![("PathChanged".into(), "/tmp//demo/".into())]),
        )
        .unwrap();
        assert_eq!(unit.specs[0].path, "/tmp/demo");
        assert_eq!(unit.specs[0].path_type, PathType::Changed);
    }

    #[test]
    fn empty_paths_reset_configuration() {
        let mut unit = transient_stub_unit();
        unit.specs.push(PathSpec {
            path: "/tmp/demo".into(),
            path_type: PathType::Exists,
        });
        bus_path_set_property(&mut unit, "Paths", PropertyValue::Paths(vec![])).unwrap();
        assert!(unit.specs.is_empty());
    }

    #[test]
    fn relative_paths_are_rejected() {
        let mut unit = transient_stub_unit();
        assert_eq!(
            bus_path_set_property(
                &mut unit,
                "Paths",
                PropertyValue::Paths(vec![("PathExists".into(), "tmp/demo".into())]),
            )
            .unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn unknown_path_type_is_rejected() {
        let mut unit = transient_stub_unit();
        assert_eq!(
            bus_path_set_property(
                &mut unit,
                "Paths",
                PropertyValue::Paths(vec![("NoSuchType".into(), "/tmp/demo".into())]),
            )
            .unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn non_transient_units_ignore_mutations() {
        let mut unit = PathUnit::default();
        let handled =
            bus_path_set_property(&mut unit, "MakeDirectory", PropertyValue::Bool(true)).unwrap();
        assert!(!handled);
        assert!(!unit.make_directory);
    }

    #[test]
    fn trigger_limit_properties_are_applied() {
        let mut unit = transient_stub_unit();
        bus_path_set_property(&mut unit, "TriggerLimitBurst", PropertyValue::Unsigned(7)).unwrap();
        bus_path_set_property(
            &mut unit,
            "TriggerLimitIntervalUSec",
            PropertyValue::Usec(5_000),
        )
        .unwrap();
        assert_eq!(unit.trigger_limit.burst, 7);
        assert_eq!(unit.trigger_limit.interval_usec, 5_000);
    }
}
