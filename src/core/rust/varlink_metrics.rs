// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/varlink-metrics.c
//
// Manager metric-family generation ported into safe Rust data transforms.

use std::collections::BTreeMap;

use crate::ffi::Errno;

pub const METRIC_PREFIX: &str = "io.systemd.Manager.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MetricFamilyType {
    Counter,
    Gauge,
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnitType {
    Service,
    Socket,
    Target,
    Timer,
}

impl UnitType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Socket => "socket",
            Self::Target => "target",
            Self::Timer => "timer",
        }
    }

    pub const fn all() -> [Self; 4] {
        [Self::Service, Self::Socket, Self::Target, Self::Timer]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnitActiveState {
    Active,
    Inactive,
    Failed,
    Reloading,
}

impl UnitActiveState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Failed => "failed",
            Self::Reloading => "reloading",
        }
    }

    pub const fn all() -> [Self; 4] {
        [Self::Active, Self::Inactive, Self::Failed, Self::Reloading]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitLoadState {
    Loaded,
    NotFound,
    Error,
}

impl UnitLoadState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::NotFound => "not-found",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitMetricsEntry {
    pub id: String,
    pub unit_type: UnitType,
    pub active_state: UnitActiveState,
    pub load_state: UnitLoadState,
    pub n_restarts: u64,
    pub is_alias: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricsManager {
    pub units: Vec<UnitMetricsEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricFamily {
    pub name: &'static str,
    pub description: &'static str,
    pub family_type: MetricFamilyType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricValue {
    Text(String),
    Unsigned(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricSample {
    pub family_name: &'static str,
    pub object: Option<String>,
    pub value: MetricValue,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricsError {
    DuplicatePrimaryUnit(String),
}

impl MetricsError {
    pub const fn errno(&self) -> i32 {
        match self {
            Self::DuplicatePrimaryUnit(_) => Errno::EEXIST.to_neg_errno(),
        }
    }
}

pub const METRIC_FAMILIES: [MetricFamily; 5] = [
    MetricFamily {
        name: "io.systemd.Manager.NRestarts",
        description: "Per unit metric: number of restarts",
        family_type: MetricFamilyType::Counter,
    },
    MetricFamily {
        name: "io.systemd.Manager.UnitActiveState",
        description: "Per unit metric: active state",
        family_type: MetricFamilyType::String,
    },
    MetricFamily {
        name: "io.systemd.Manager.UnitLoadState",
        description: "Per unit metric: load state",
        family_type: MetricFamilyType::String,
    },
    MetricFamily {
        name: "io.systemd.Manager.UnitsByStateTotal",
        description: "Total number of units of different state",
        family_type: MetricFamilyType::Gauge,
    },
    MetricFamily {
        name: "io.systemd.Manager.UnitsByTypeTotal",
        description: "Total number of units of different types",
        family_type: MetricFamilyType::Gauge,
    },
];

fn primary_units(manager: &MetricsManager) -> Result<Vec<&UnitMetricsEntry>, MetricsError> {
    let mut seen = BTreeMap::<&str, ()>::new();
    let mut units = Vec::new();

    for unit in &manager.units {
        if unit.is_alias {
            continue;
        }
        if seen.insert(unit.id.as_str(), ()).is_some() {
            return Err(MetricsError::DuplicatePrimaryUnit(unit.id.clone()));
        }
        units.push(unit);
    }

    Ok(units)
}

pub fn unit_active_state_metrics(
    manager: &MetricsManager,
) -> Result<Vec<MetricSample>, MetricsError> {
    primary_units(manager).map(|units| {
        units
            .into_iter()
            .map(|unit| MetricSample {
                family_name: METRIC_FAMILIES[1].name,
                object: Some(unit.id.clone()),
                value: MetricValue::Text(unit.active_state.as_str().into()),
                fields: BTreeMap::new(),
            })
            .collect()
    })
}

pub fn unit_load_state_metrics(
    manager: &MetricsManager,
) -> Result<Vec<MetricSample>, MetricsError> {
    primary_units(manager).map(|units| {
        units
            .into_iter()
            .map(|unit| MetricSample {
                family_name: METRIC_FAMILIES[2].name,
                object: Some(unit.id.clone()),
                value: MetricValue::Text(unit.load_state.as_str().into()),
                fields: BTreeMap::new(),
            })
            .collect()
    })
}

pub fn nrestarts_metrics(manager: &MetricsManager) -> Result<Vec<MetricSample>, MetricsError> {
    primary_units(manager).map(|units| {
        units
            .into_iter()
            .filter(|unit| unit.unit_type == UnitType::Service)
            .map(|unit| MetricSample {
                family_name: METRIC_FAMILIES[0].name,
                object: Some(unit.id.clone()),
                value: MetricValue::Unsigned(unit.n_restarts),
                fields: BTreeMap::new(),
            })
            .collect()
    })
}

pub fn units_by_type_total_metrics(
    manager: &MetricsManager,
) -> Result<Vec<MetricSample>, MetricsError> {
    let units = primary_units(manager)?;
    Ok(UnitType::all()
        .into_iter()
        .map(|unit_type| {
            let mut fields = BTreeMap::new();
            fields.insert("type".into(), unit_type.as_str().into());
            MetricSample {
                family_name: METRIC_FAMILIES[4].name,
                object: None,
                value: MetricValue::Unsigned(
                    units
                        .iter()
                        .filter(|unit| unit.unit_type == unit_type)
                        .count() as u64,
                ),
                fields,
            }
        })
        .collect())
}

pub fn units_by_state_total_metrics(
    manager: &MetricsManager,
) -> Result<Vec<MetricSample>, MetricsError> {
    let units = primary_units(manager)?;
    Ok(UnitActiveState::all()
        .into_iter()
        .map(|state| {
            let mut fields = BTreeMap::new();
            fields.insert("state".into(), state.as_str().into());
            MetricSample {
                family_name: METRIC_FAMILIES[3].name,
                object: None,
                value: MetricValue::Unsigned(
                    units
                        .iter()
                        .filter(|unit| unit.active_state == state)
                        .count() as u64,
                ),
                fields,
            }
        })
        .collect())
}

pub fn describe_metrics() -> Vec<MetricFamily> {
    METRIC_FAMILIES.to_vec()
}

pub fn list_metrics(manager: &MetricsManager) -> Result<Vec<MetricSample>, MetricsError> {
    let mut samples = Vec::new();
    samples.extend(nrestarts_metrics(manager)?);
    samples.extend(unit_active_state_metrics(manager)?);
    samples.extend(unit_load_state_metrics(manager)?);
    samples.extend(units_by_state_total_metrics(manager)?);
    samples.extend(units_by_type_total_metrics(manager)?);
    Ok(samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> MetricsManager {
        MetricsManager {
            units: vec![
                UnitMetricsEntry {
                    id: "a.service".into(),
                    unit_type: UnitType::Service,
                    active_state: UnitActiveState::Active,
                    load_state: UnitLoadState::Loaded,
                    n_restarts: 3,
                    is_alias: false,
                },
                UnitMetricsEntry {
                    id: "b.socket".into(),
                    unit_type: UnitType::Socket,
                    active_state: UnitActiveState::Inactive,
                    load_state: UnitLoadState::Loaded,
                    n_restarts: 0,
                    is_alias: false,
                },
                UnitMetricsEntry {
                    id: "alias.service".into(),
                    unit_type: UnitType::Service,
                    active_state: UnitActiveState::Failed,
                    load_state: UnitLoadState::Error,
                    n_restarts: 9,
                    is_alias: true,
                },
            ],
        }
    }

    #[test]
    fn describe_metrics_keeps_alphabetical_order() {
        let described = describe_metrics();
        assert_eq!(described[0].name, "io.systemd.Manager.NRestarts");
        assert_eq!(described[4].name, "io.systemd.Manager.UnitsByTypeTotal");
    }

    #[test]
    fn active_state_metrics_ignore_aliases() {
        let samples = unit_active_state_metrics(&manager()).unwrap();
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].object.as_deref(), Some("a.service"));
    }

    #[test]
    fn load_state_metrics_emit_strings() {
        let samples = unit_load_state_metrics(&manager()).unwrap();
        assert_eq!(samples[0].value, MetricValue::Text("loaded".into()));
    }

    #[test]
    fn nrestarts_only_counts_services() {
        let samples = nrestarts_metrics(&manager()).unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].value, MetricValue::Unsigned(3));
    }

    #[test]
    fn units_by_type_total_emits_all_known_types() {
        let samples = units_by_type_total_metrics(&manager()).unwrap();
        assert_eq!(samples.len(), 4);
        assert_eq!(
            samples[0].fields.get("type").map(String::as_str),
            Some("service")
        );
    }

    #[test]
    fn units_by_state_total_counts_primary_units() {
        let samples = units_by_state_total_metrics(&manager()).unwrap();
        let active = samples
            .iter()
            .find(|sample| sample.fields.get("state") == Some(&"active".into()))
            .unwrap();
        assert_eq!(active.value, MetricValue::Unsigned(1));
    }

    #[test]
    fn list_metrics_concatenates_all_families() {
        let samples = list_metrics(&manager()).unwrap();
        assert!(
            samples
                .iter()
                .any(|sample| sample.family_name == "io.systemd.Manager.UnitLoadState")
        );
        assert!(
            samples
                .iter()
                .any(|sample| sample.family_name == "io.systemd.Manager.UnitsByTypeTotal")
        );
    }

    #[test]
    fn duplicate_primary_unit_is_rejected() {
        let err = list_metrics(&MetricsManager {
            units: vec![
                UnitMetricsEntry {
                    id: "dup.service".into(),
                    unit_type: UnitType::Service,
                    active_state: UnitActiveState::Active,
                    load_state: UnitLoadState::Loaded,
                    n_restarts: 0,
                    is_alias: false,
                },
                UnitMetricsEntry {
                    id: "dup.service".into(),
                    unit_type: UnitType::Socket,
                    active_state: UnitActiveState::Inactive,
                    load_state: UnitLoadState::Loaded,
                    n_restarts: 0,
                    is_alias: false,
                },
            ],
        })
        .unwrap_err();
        assert_eq!(
            err,
            MetricsError::DuplicatePrimaryUnit("dup.service".into())
        );
        assert_eq!(err.errno(), Errno::EEXIST.to_neg_errno());
    }
}
