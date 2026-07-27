// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/varlink-cgroup.c
//
use std::collections::{BTreeMap, BTreeSet};

pub const SOURCE_PATH: &str = "src/core/varlink-cgroup.c";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(u64),
    Signed(i64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    fn number(value: u64) -> Self {
        Self::Number(value)
    }

    fn signed(value: i64) -> Self {
        Self::Signed(value)
    }

    fn array(values: Vec<JsonValue>) -> Self {
        Self::Array(values)
    }

    fn object(entries: impl IntoIterator<Item = (impl Into<String>, JsonValue)>) -> Self {
        let mut map = BTreeMap::new();
        for (key, value) in entries {
            map.insert(key.into(), value);
        }
        Self::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarlinkCgroupError {
    UnknownIoLimitName(String),
    EmptyPath,
    InvalidPrefixLength(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CGroupTasksMax {
    pub value: u64,
    pub scale: u64,
    pub is_set: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoDeviceWeight {
    pub path: String,
    pub weight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoDeviceLimit {
    pub path: String,
    pub read_bandwidth_max: Option<u64>,
    pub write_bandwidth_max: Option<u64>,
    pub read_iops_max: Option<u64>,
    pub write_iops_max: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoDeviceLatency {
    pub path: String,
    pub target_usec: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddressAccess {
    pub family: i32,
    pub address: String,
    pub prefix_length: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketBind {
    pub family: i32,
    pub protocol: String,
    pub number_of_ports: u16,
    pub minimum_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftSet {
    pub source: String,
    pub protocol: String,
    pub table: String,
    pub set: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfProgram {
    pub attach_type: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAllow {
    pub path: String,
    pub permissions: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ControllerSet {
    pub enabled: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnitCgroupContext {
    pub slice: Option<String>,
    pub cpu_weight: Option<u64>,
    pub startup_cpu_weight: Option<u64>,
    pub cpu_quota_per_sec_usec: Option<u64>,
    pub cpu_quota_period_usec: Option<u64>,
    pub allowed_cpus: Vec<u32>,
    pub startup_allowed_cpus: Vec<u32>,
    pub memory_accounting: bool,
    pub tasks_accounting: bool,
    pub io_accounting: bool,
    pub tasks_max: Option<CGroupTasksMax>,
    pub device_allow: Vec<DeviceAllow>,
    pub controllers: ControllerSet,
}

fn ensure_non_empty_path(path: &str) -> Result<(), VarlinkCgroupError> {
    if path.is_empty() {
        Err(VarlinkCgroupError::EmptyPath)
    } else {
        Ok(())
    }
}

pub fn tasks_max_build_json(
    tasks_max: &CGroupTasksMax,
) -> Result<Option<JsonValue>, VarlinkCgroupError> {
    if !tasks_max.is_set {
        return Ok(None);
    }

    Ok(Some(JsonValue::object([
        ("value", JsonValue::number(tasks_max.value)),
        ("scale", JsonValue::number(tasks_max.scale)),
    ])))
}

pub fn io_device_weights_build_json(
    weights: &[IoDeviceWeight],
) -> Result<Option<JsonValue>, VarlinkCgroupError> {
    let mut values = Vec::with_capacity(weights.len());
    for weight in weights {
        ensure_non_empty_path(&weight.path)?;
        values.push(JsonValue::object([
            ("path", JsonValue::string(&weight.path)),
            ("weight", JsonValue::number(weight.weight)),
        ]));
    }

    Ok((!values.is_empty()).then(|| JsonValue::array(values)))
}

pub fn io_device_limits_build_json(
    name: &str,
    limits: &[IoDeviceLimit],
) -> Result<Option<JsonValue>, VarlinkCgroupError> {
    let selector: fn(&IoDeviceLimit) -> Option<u64> = match name {
        "IOReadBandwidthMax" => |l| l.read_bandwidth_max,
        "IOWriteBandwidthMax" => |l| l.write_bandwidth_max,
        "IOReadIOPSMax" => |l| l.read_iops_max,
        "IOWriteIOPSMax" => |l| l.write_iops_max,
        other => return Err(VarlinkCgroupError::UnknownIoLimitName(other.to_string())),
    };

    let mut values = Vec::new();
    for limit in limits {
        ensure_non_empty_path(&limit.path)?;
        if let Some(value) = selector(limit) {
            values.push(JsonValue::object([
                ("path", JsonValue::string(&limit.path)),
                ("limit", JsonValue::number(value)),
            ]));
        }
    }

    Ok((!values.is_empty()).then(|| JsonValue::array(values)))
}

pub fn io_device_latencies_build_json(
    latencies: &[IoDeviceLatency],
) -> Result<Option<JsonValue>, VarlinkCgroupError> {
    let mut values = Vec::with_capacity(latencies.len());
    for latency in latencies {
        ensure_non_empty_path(&latency.path)?;
        values.push(JsonValue::object([
            ("path", JsonValue::string(&latency.path)),
            ("targetUSec", JsonValue::number(latency.target_usec)),
        ]));
    }

    Ok((!values.is_empty()).then(|| JsonValue::array(values)))
}

pub fn ip_address_access_build_json(
    prefixes: &[IpAddressAccess],
) -> Result<Option<JsonValue>, VarlinkCgroupError> {
    let mut values = Vec::with_capacity(prefixes.len());
    for prefix in prefixes {
        if prefix.prefix_length > 128 {
            return Err(VarlinkCgroupError::InvalidPrefixLength(
                prefix.prefix_length,
            ));
        }
        values.push(JsonValue::object([
            ("family", JsonValue::signed(i64::from(prefix.family))),
            ("address", JsonValue::string(&prefix.address)),
            (
                "prefixLength",
                JsonValue::number(u64::from(prefix.prefix_length)),
            ),
        ]));
    }

    Ok((!values.is_empty()).then(|| JsonValue::array(values)))
}

pub fn socket_bind_build_json(
    items: &[SocketBind],
) -> Result<Option<JsonValue>, VarlinkCgroupError> {
    let mut values = Vec::with_capacity(items.len());
    for item in items {
        values.push(JsonValue::object([
            ("family", JsonValue::signed(i64::from(item.family))),
            ("protocol", JsonValue::string(&item.protocol)),
            (
                "numberOfPorts",
                JsonValue::number(u64::from(item.number_of_ports)),
            ),
            (
                "minimumPort",
                JsonValue::number(u64::from(item.minimum_port)),
            ),
        ]));
    }

    Ok((!values.is_empty()).then(|| JsonValue::array(values)))
}

pub fn nft_set_build_json(sets: &[NftSet]) -> Result<Option<JsonValue>, VarlinkCgroupError> {
    let values = sets
        .iter()
        .map(|item| {
            JsonValue::object([
                ("source", JsonValue::string(&item.source)),
                ("protocol", JsonValue::string(&item.protocol)),
                ("table", JsonValue::string(&item.table)),
                ("set", JsonValue::string(&item.set)),
            ])
        })
        .collect::<Vec<_>>();

    Ok((!values.is_empty()).then(|| JsonValue::array(values)))
}

pub fn bpf_program_build_json(
    programs: &[BpfProgram],
) -> Result<Option<JsonValue>, VarlinkCgroupError> {
    let values = programs
        .iter()
        .map(|program| {
            JsonValue::object([
                ("attachType", JsonValue::string(&program.attach_type)),
                ("path", JsonValue::string(&program.path)),
            ])
        })
        .collect::<Vec<_>>();

    Ok((!values.is_empty()).then(|| JsonValue::array(values)))
}

pub fn device_allow_build_json(
    entries: &[DeviceAllow],
) -> Result<Option<JsonValue>, VarlinkCgroupError> {
    let mut values = Vec::with_capacity(entries.len());
    for entry in entries {
        ensure_non_empty_path(&entry.path)?;
        values.push(JsonValue::object([
            ("path", JsonValue::string(&entry.path)),
            ("permissions", JsonValue::string(&entry.permissions)),
        ]));
    }

    Ok((!values.is_empty()).then(|| JsonValue::array(values)))
}

pub fn controllers_build_json(
    controllers: &ControllerSet,
) -> Result<Option<JsonValue>, VarlinkCgroupError> {
    let values = controllers
        .enabled
        .iter()
        .cloned()
        .map(JsonValue::string)
        .collect::<Vec<_>>();

    Ok((!values.is_empty()).then(|| JsonValue::array(values)))
}

pub fn unit_cgroup_context_build_json(
    context: &UnitCgroupContext,
) -> Result<Option<JsonValue>, VarlinkCgroupError> {
    let mut object = BTreeMap::new();

    if let Some(slice) = &context.slice {
        if !slice.is_empty() {
            object.insert("Slice".into(), JsonValue::string(slice));
        }
    }
    if let Some(value) = context.cpu_weight {
        object.insert("CPUWeight".into(), JsonValue::number(value));
    }
    if let Some(value) = context.startup_cpu_weight {
        object.insert("StartupCPUWeight".into(), JsonValue::number(value));
    }
    if let Some(value) = context.cpu_quota_per_sec_usec {
        object.insert("CPUQuotaPerSecUSec".into(), JsonValue::number(value));
    }
    if let Some(value) = context.cpu_quota_period_usec {
        object.insert("CPUQuotaPeriodUSec".into(), JsonValue::number(value));
    }
    if !context.allowed_cpus.is_empty() {
        object.insert(
            "AllowedCPUs".into(),
            JsonValue::array(
                context
                    .allowed_cpus
                    .iter()
                    .copied()
                    .map(u64::from)
                    .map(JsonValue::number)
                    .collect(),
            ),
        );
    }
    if !context.startup_allowed_cpus.is_empty() {
        object.insert(
            "StartupAllowedCPUs".into(),
            JsonValue::array(
                context
                    .startup_allowed_cpus
                    .iter()
                    .copied()
                    .map(u64::from)
                    .map(JsonValue::number)
                    .collect(),
            ),
        );
    }
    if context.memory_accounting {
        object.insert("MemoryAccounting".into(), JsonValue::Bool(true));
    }
    if context.tasks_accounting {
        object.insert("TasksAccounting".into(), JsonValue::Bool(true));
    }
    if context.io_accounting {
        object.insert("IOAccounting".into(), JsonValue::Bool(true));
    }
    if let Some(tasks_max) = &context.tasks_max {
        if let Some(value) = tasks_max_build_json(tasks_max)? {
            object.insert("TasksMax".into(), value);
        }
    }
    if let Some(value) = device_allow_build_json(&context.device_allow)? {
        object.insert("DeviceAllow".into(), value);
    }
    if let Some(value) = controllers_build_json(&context.controllers)? {
        object.insert("Controllers".into(), value);
    }

    Ok((!object.is_empty()).then_some(JsonValue::Object(object)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tasks_max_omits_unset_values() {
        let result = tasks_max_build_json(&CGroupTasksMax {
            value: 10,
            scale: 1,
            is_set: false,
        })
        .unwrap();

        assert_eq!(result, None);
    }

    #[test]
    fn io_limit_builder_filters_missing_limit_values() {
        let result = io_device_limits_build_json(
            "IOReadBandwidthMax",
            &[
                IoDeviceLimit {
                    path: "/dev/vda".into(),
                    read_bandwidth_max: Some(1024),
                    write_bandwidth_max: None,
                    read_iops_max: None,
                    write_iops_max: None,
                },
                IoDeviceLimit {
                    path: "/dev/vdb".into(),
                    read_bandwidth_max: None,
                    write_bandwidth_max: Some(2048),
                    read_iops_max: None,
                    write_iops_max: None,
                },
            ],
        )
        .unwrap()
        .unwrap();

        match result {
            JsonValue::Array(values) => assert_eq!(values.len(), 1),
            other => panic!("unexpected json: {other:?}"),
        }
    }

    #[test]
    fn ip_access_rejects_invalid_prefix_lengths() {
        let error = ip_address_access_build_json(&[IpAddressAccess {
            family: 2,
            address: "192.0.2.0".into(),
            prefix_length: 255,
        }])
        .unwrap_err();

        assert_eq!(error, VarlinkCgroupError::InvalidPrefixLength(255));
    }

    #[test]
    fn unit_context_collects_only_present_properties() {
        let mut controllers = ControllerSet::default();
        controllers.enabled.insert("cpu".into());
        controllers.enabled.insert("memory".into());

        let json = unit_cgroup_context_build_json(&UnitCgroupContext {
            slice: Some("system.slice".into()),
            cpu_weight: Some(100),
            memory_accounting: true,
            tasks_max: Some(CGroupTasksMax {
                value: 512,
                scale: 1,
                is_set: true,
            }),
            controllers,
            ..UnitCgroupContext::default()
        })
        .unwrap()
        .unwrap();

        match json {
            JsonValue::Object(map) => {
                assert_eq!(map.get("Slice"), Some(&JsonValue::string("system.slice")));
                assert!(map.contains_key("TasksMax"));
                assert!(map.contains_key("Controllers"));
                assert!(!map.contains_key("DeviceAllow"));
            }
            other => panic!("unexpected json: {other:?}"),
        }
    }
}
