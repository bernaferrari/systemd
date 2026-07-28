// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-cgroup.c

use crate::ffi::Errno;
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, CGroupError>;
pub type CGroupMask = u64;

pub const CGROUP_MASK_CPU: CGroupMask = 1 << 0;
pub const CGROUP_MASK_IO: CGroupMask = 1 << 1;
pub const CGROUP_MASK_MEMORY: CGroupMask = 1 << 2;
pub const CGROUP_MASK_PIDS: CGroupMask = 1 << 3;
pub const CGROUP_MASK_CPUSET: CGroupMask = 1 << 4;
pub const CGROUP_MASK_BPF_DEVICES: CGroupMask = 1 << 5;
pub const CGROUP_MASK_DELEGATE: CGroupMask =
    CGROUP_MASK_CPU | CGROUP_MASK_IO | CGROUP_MASK_MEMORY | CGROUP_MASK_PIDS | CGROUP_MASK_CPUSET;
pub const CGROUP_LIMIT_MAX: u64 = u64::MAX;
pub const CGROUP_WEIGHT_INVALID: u64 = 0;
pub const CGROUP_WEIGHT_IDLE: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupError {
    pub errno: Errno,
    pub message: String,
}

impl CGroupError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            errno: Errno::EINVAL,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CGroupController {
    Cpu,
    Io,
    Memory,
    Pids,
    Cpuset,
}

impl CGroupController {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Io => "io",
            Self::Memory => "memory",
            Self::Pids => "pids",
            Self::Cpuset => "cpuset",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "cpu" => Ok(Self::Cpu),
            "io" => Ok(Self::Io),
            "memory" => Ok(Self::Memory),
            "pids" => Ok(Self::Pids),
            "cpuset" => Ok(Self::Cpuset),
            other => Err(CGroupError::invalid(format!(
                "Unknown cgroup controller '{other}'"
            ))),
        }
    }

    pub fn mask(self) -> CGroupMask {
        match self {
            Self::Cpu => CGROUP_MASK_CPU,
            Self::Io => CGROUP_MASK_IO,
            Self::Memory => CGROUP_MASK_MEMORY,
            Self::Pids => CGROUP_MASK_PIDS,
            Self::Cpuset => CGROUP_MASK_CPUSET,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CGroupPressureWatch {
    Off,
    No,
    Yes,
    Auto,
    Skip,
}

impl CGroupPressureWatch {
    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "" => Ok(Self::Off),
            "0" | "n" | "no" | "f" | "false" | "off" => Ok(Self::No),
            "1" | "y" | "yes" | "t" | "true" | "on" => Ok(Self::Yes),
            "auto" => Ok(Self::Auto),
            "skip" => Ok(Self::Skip),
            other => Err(CGroupError::invalid(format!(
                "Unknown pressure watch mode '{other}'"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "",
            Self::No => "no",
            Self::Yes => "yes",
            Self::Auto => "auto",
            Self::Skip => "skip",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuSetPartition {
    Member,
    Root,
    Isolated,
}

impl CpuSetPartition {
    fn parse(value: &str) -> Result<Option<Self>> {
        match value {
            "" => Ok(None),
            "member" => Ok(Some(Self::Member)),
            "root" => Ok(Some(Self::Root)),
            "isolated" => Ok(Some(Self::Isolated)),
            other => Err(CGroupError::invalid(format!(
                "Invalid CPUSetPartition value: {other}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Root => "root",
            Self::Isolated => "isolated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CGroupDevicePolicy {
    Auto,
    Closed,
    Strict,
}

impl CGroupDevicePolicy {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "auto" => Ok(Self::Auto),
            "closed" => Ok(Self::Closed),
            "strict" => Ok(Self::Strict),
            other => Err(CGroupError::invalid(format!(
                "Unknown device policy '{other}'"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CpuSet(pub BTreeSet<u16>);

impl CpuSet {
    pub fn from_ids(ids: impl IntoIterator<Item = u16>) -> Self {
        Self(ids.into_iter().collect())
    }

    pub fn to_dbus_bytes(&self) -> Vec<u8> {
        let max_bit = self.0.iter().copied().max().unwrap_or(0) as usize;
        let mut bytes = vec![0_u8; max_bit / 8 + 1];
        for cpu in &self.0 {
            let idx = *cpu as usize / 8;
            let bit = *cpu as usize % 8;
            bytes[idx] |= 1 << bit;
        }
        if self.0.is_empty() { Vec::new() } else { bytes }
    }

    pub fn from_dbus_bytes(bytes: &[u8]) -> Self {
        let mut set = BTreeSet::new();
        for (byte_index, byte) in bytes.iter().copied().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) != 0 {
                    set.insert((byte_index * 8 + bit) as u16);
                }
            }
        }
        Self(set)
    }

    pub fn to_range_string(&self) -> String {
        self.0
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupTasksMax {
    pub value: u64,
    pub scale: u64,
}

impl Default for CGroupTasksMax {
    fn default() -> Self {
        Self {
            value: CGROUP_LIMIT_MAX,
            scale: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceWeight {
    pub path: String,
    pub weight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceLimits {
    pub path: String,
    pub read_bandwidth_max: u64,
    pub write_bandwidth_max: u64,
    pub read_iops_max: u64,
    pub write_iops_max: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLatency {
    pub path: String,
    pub target_usec: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAllow {
    pub path: String,
    pub permissions: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfForeignProgram {
    pub attach_type: String,
    pub bpffs_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketBindItem {
    pub address_family: i32,
    pub ip_protocol: i32,
    pub nr_ports: u16,
    pub port_min: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftSet {
    pub source: i32,
    pub nfproto: i32,
    pub table: String,
    pub set: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CGroupMessage {
    Bool(bool),
    U64(u64),
    U32(u32),
    String(String),
    StringArray(Vec<String>),
    Bytes(Vec<u8>),
    DeviceWeights(Vec<(String, u64)>),
    DeviceLimits(Vec<(String, u64)>),
    DeviceLatencies(Vec<(String, u64)>),
    DeviceAllows(Vec<(String, String)>),
    BpfPrograms(Vec<(String, String)>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnitWriteFlags {
    pub noop: bool,
    pub private: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnitState {
    pub can_delegate: bool,
    pub transient: bool,
    pub load_stub: bool,
    pub invalidated_masks: Vec<CGroupMask>,
    pub write_log: Vec<String>,
}

impl UnitState {
    fn invalidate(&mut self, mask: CGroupMask) {
        self.invalidated_masks.push(mask);
    }

    fn write(&mut self, line: impl Into<String>) {
        self.write_log.push(line.into());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupContext {
    pub delegate: bool,
    pub delegate_controllers: CGroupMask,
    pub disable_controllers: CGroupMask,
    pub delegate_subgroup: Option<String>,
    pub io_accounting: bool,
    pub io_weight: u64,
    pub startup_io_weight: u64,
    pub memory_accounting: bool,
    pub memory_min: u64,
    pub memory_low: u64,
    pub startup_memory_low: u64,
    pub memory_high: u64,
    pub memory_max: u64,
    pub memory_swap_max: u64,
    pub memory_zswap_max: u64,
    pub memory_zswap_writeback: bool,
    pub tasks_accounting: bool,
    pub tasks_max: CGroupTasksMax,
    pub cpu_weight: u64,
    pub startup_cpu_weight: u64,
    pub cpu_quota_per_sec_usec: u64,
    pub cpu_quota_period_usec: u64,
    pub cpuset_cpus: CpuSet,
    pub startup_cpuset_cpus: CpuSet,
    pub cpuset_mems: CpuSet,
    pub startup_cpuset_mems: CpuSet,
    pub cpuset_partition: Option<CpuSetPartition>,
    pub io_device_weights: Vec<DeviceWeight>,
    pub io_device_limits: Vec<DeviceLimits>,
    pub io_device_latencies: Vec<DeviceLatency>,
    pub device_policy: CGroupDevicePolicy,
    pub device_allow: Vec<DeviceAllow>,
    pub bpf_foreign_programs: Vec<BpfForeignProgram>,
    pub socket_bind_items: Vec<SocketBindItem>,
    pub restrict_network_interfaces_is_allow_list: bool,
    pub restrict_network_interfaces: BTreeSet<String>,
    pub nft_sets: Vec<NftSet>,
    pub memory_pressure_watch: CGroupPressureWatch,
    pub memory_pressure_threshold_usec: u64,
    pub cpu_pressure_watch: CGroupPressureWatch,
    pub cpu_pressure_threshold_usec: u64,
    pub io_pressure_watch: CGroupPressureWatch,
    pub io_pressure_threshold_usec: u64,
    pub coredump_receive: bool,
}

impl Default for CGroupContext {
    fn default() -> Self {
        Self {
            delegate: false,
            delegate_controllers: 0,
            disable_controllers: 0,
            delegate_subgroup: None,
            io_accounting: false,
            io_weight: CGROUP_WEIGHT_INVALID,
            startup_io_weight: CGROUP_WEIGHT_INVALID,
            memory_accounting: false,
            memory_min: CGROUP_LIMIT_MAX,
            memory_low: CGROUP_LIMIT_MAX,
            startup_memory_low: CGROUP_LIMIT_MAX,
            memory_high: CGROUP_LIMIT_MAX,
            memory_max: CGROUP_LIMIT_MAX,
            memory_swap_max: CGROUP_LIMIT_MAX,
            memory_zswap_max: CGROUP_LIMIT_MAX,
            memory_zswap_writeback: false,
            tasks_accounting: false,
            tasks_max: CGroupTasksMax::default(),
            cpu_weight: CGROUP_WEIGHT_INVALID,
            startup_cpu_weight: CGROUP_WEIGHT_INVALID,
            cpu_quota_per_sec_usec: CGROUP_LIMIT_MAX,
            cpu_quota_period_usec: CGROUP_LIMIT_MAX,
            cpuset_cpus: CpuSet::default(),
            startup_cpuset_cpus: CpuSet::default(),
            cpuset_mems: CpuSet::default(),
            startup_cpuset_mems: CpuSet::default(),
            cpuset_partition: None,
            io_device_weights: Vec::new(),
            io_device_limits: Vec::new(),
            io_device_latencies: Vec::new(),
            device_policy: CGroupDevicePolicy::Auto,
            device_allow: Vec::new(),
            bpf_foreign_programs: Vec::new(),
            socket_bind_items: Vec::new(),
            restrict_network_interfaces_is_allow_list: false,
            restrict_network_interfaces: BTreeSet::new(),
            nft_sets: Vec::new(),
            memory_pressure_watch: CGroupPressureWatch::Off,
            memory_pressure_threshold_usec: CGROUP_LIMIT_MAX,
            cpu_pressure_watch: CGroupPressureWatch::Off,
            cpu_pressure_threshold_usec: CGROUP_LIMIT_MAX,
            io_pressure_watch: CGroupPressureWatch::Off,
            io_pressure_threshold_usec: CGROUP_LIMIT_MAX,
            coredump_receive: false,
        }
    }
}

impl CGroupContext {
    pub fn property_get_cgroup_mask(mask: CGroupMask) -> Vec<String> {
        [
            CGroupController::Cpu,
            CGroupController::Io,
            CGroupController::Memory,
            CGroupController::Pids,
            CGroupController::Cpuset,
        ]
        .into_iter()
        .filter(|controller| mask & controller.mask() != 0)
        .map(|controller| controller.as_str().to_string())
        .collect()
    }

    pub fn property_get_delegate_controllers(&self) -> Vec<String> {
        if !self.delegate {
            Vec::new()
        } else {
            Self::property_get_cgroup_mask(self.delegate_controllers)
        }
    }

    pub fn property_get_cpuset(set: &CpuSet) -> Vec<u8> {
        set.to_dbus_bytes()
    }

    pub fn property_get_io_device_weight(&self) -> Vec<(String, u64)> {
        self.io_device_weights
            .iter()
            .map(|item| (item.path.clone(), item.weight))
            .collect()
    }

    pub fn property_get_io_device_limits(&self, property: &str) -> Result<Vec<(String, u64)>> {
        Ok(self
            .io_device_limits
            .iter()
            .filter_map(|limit| {
                let value = match property {
                    "IOReadBandwidthMax" => limit.read_bandwidth_max,
                    "IOWriteBandwidthMax" => limit.write_bandwidth_max,
                    "IOReadIOPSMax" => limit.read_iops_max,
                    "IOWriteIOPSMax" => limit.write_iops_max,
                    _ => return None,
                };
                (value != 0).then(|| (limit.path.clone(), value))
            })
            .collect())
    }

    pub fn property_get_io_device_latency(&self) -> Vec<(String, u64)> {
        self.io_device_latencies
            .iter()
            .map(|item| (item.path.clone(), item.target_usec))
            .collect()
    }

    pub fn property_get_device_allow(&self) -> Vec<(String, String)> {
        self.device_allow
            .iter()
            .map(|item| (item.path.clone(), item.permissions.clone()))
            .collect()
    }

    pub fn property_get_bpf_foreign_program(&self) -> Vec<(String, String)> {
        self.bpf_foreign_programs
            .iter()
            .map(|item| (item.attach_type.clone(), item.bpffs_path.clone()))
            .collect()
    }

    pub fn property_get_socket_bind(&self) -> Vec<(i32, i32, u16, u16)> {
        self.socket_bind_items
            .iter()
            .map(|item| {
                (
                    item.address_family,
                    item.ip_protocol,
                    item.nr_ports,
                    item.port_min,
                )
            })
            .collect()
    }

    pub fn property_get_restrict_network_interfaces(&self) -> (bool, Vec<String>) {
        (
            self.restrict_network_interfaces_is_allow_list,
            self.restrict_network_interfaces.iter().cloned().collect(),
        )
    }

    pub fn property_get_cgroup_nft_set(&self) -> Vec<(i32, i32, String, String)> {
        self.nft_sets
            .iter()
            .map(|item| {
                (
                    item.source,
                    item.nfproto,
                    item.table.clone(),
                    item.set.clone(),
                )
            })
            .collect()
    }

    pub fn bus_cgroup_set_transient_property(
        &mut self,
        unit: &mut UnitState,
        name: &str,
        message: &CGroupMessage,
        mut flags: UnitWriteFlags,
    ) -> Result<bool> {
        flags.private = true;

        match (name, message) {
            ("Delegate", CGroupMessage::Bool(value)) => {
                if !unit.can_delegate {
                    return Err(CGroupError::invalid(
                        "Delegation not available for unit type",
                    ));
                }
                if !flags.noop {
                    self.delegate = *value;
                    self.delegate_controllers = if *value { CGROUP_MASK_DELEGATE } else { 0 };
                    unit.write(format!("Delegate={}", if *value { "yes" } else { "no" }));
                }
                Ok(true)
            }
            ("DelegateSubgroup", CGroupMessage::String(value)) => {
                if !unit.can_delegate {
                    return Err(CGroupError::invalid(
                        "Delegation not available for unit type",
                    ));
                }
                if !value.is_empty() && value.contains('/') {
                    return Err(CGroupError::invalid(format!(
                        "Invalid control group name: {value}"
                    )));
                }
                if !flags.noop {
                    self.delegate_subgroup = (!value.is_empty()).then(|| value.clone());
                    unit.write(format!("DelegateSubgroup={value}"));
                }
                Ok(true)
            }
            ("DelegateControllers", CGroupMessage::StringArray(values))
            | ("DisableControllers", CGroupMessage::StringArray(values)) => {
                if name == "DelegateControllers" && !unit.can_delegate {
                    return Err(CGroupError::invalid(
                        "Delegation not available for unit type",
                    ));
                }
                let mask = values.iter().try_fold(0_u64, |mask, value| {
                    Ok(mask | CGroupController::parse(value)?.mask())
                })?;
                if !flags.noop {
                    let rendered = Self::property_get_cgroup_mask(mask).join(" ");
                    if name == "DelegateControllers" {
                        self.delegate = true;
                        self.delegate_controllers = if mask == 0 {
                            0
                        } else {
                            self.delegate_controllers | mask
                        };
                        unit.write(format!("Delegate={rendered}"));
                    } else {
                        self.disable_controllers = if mask == 0 {
                            0
                        } else {
                            self.disable_controllers | mask
                        };
                        unit.write(format!("DisableControllers={rendered}"));
                    }
                }
                Ok(true)
            }
            ("BPFProgram", CGroupMessage::BpfPrograms(programs)) => {
                if !flags.noop {
                    self.bpf_foreign_programs = programs
                        .iter()
                        .map(|(attach_type, bpffs_path)| BpfForeignProgram {
                            attach_type: attach_type.clone(),
                            bpffs_path: bpffs_path.clone(),
                        })
                        .collect();
                    unit.write(format!("BPFProgram={}", self.bpf_foreign_programs.len()));
                }
                Ok(true)
            }
            (
                "MemoryPressureWatch" | "CPUPressureWatch" | "IOPressureWatch",
                CGroupMessage::String(value),
            ) => {
                if !flags.noop {
                    let watch = CGroupPressureWatch::parse(value)?;
                    match name {
                        "MemoryPressureWatch" => self.memory_pressure_watch = watch,
                        "CPUPressureWatch" => self.cpu_pressure_watch = watch,
                        "IOPressureWatch" => self.io_pressure_watch = watch,
                        _ => unreachable!(),
                    }
                    unit.write(format!("{name}={}", watch.as_str()));
                }
                Ok(true)
            }
            (
                "MemoryPressureThresholdUSec"
                | "CPUPressureThresholdUSec"
                | "IOPressureThresholdUSec",
                CGroupMessage::U64(value),
            ) => {
                if !flags.noop {
                    match name {
                        "MemoryPressureThresholdUSec" => {
                            self.memory_pressure_threshold_usec = *value
                        }
                        "CPUPressureThresholdUSec" => self.cpu_pressure_threshold_usec = *value,
                        "IOPressureThresholdUSec" => self.io_pressure_threshold_usec = *value,
                        _ => unreachable!(),
                    }
                    unit.write(if *value == CGROUP_LIMIT_MAX {
                        format!("{name}=")
                    } else {
                        format!("{name}={value}")
                    });
                }
                Ok(true)
            }
            ("CoredumpReceive", CGroupMessage::Bool(value)) => {
                if !unit.can_delegate {
                    return Err(CGroupError::invalid(
                        "Delegation not available for unit type",
                    ));
                }
                if !flags.noop {
                    self.coredump_receive = *value;
                    unit.write(format!(
                        "CoredumpReceive={}",
                        if *value { "yes" } else { "no" }
                    ));
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn set_bool(
        unit: &mut UnitState,
        name: &str,
        slot: &mut bool,
        mask: CGroupMask,
        value: bool,
        flags: UnitWriteFlags,
    ) -> Result<bool> {
        if !flags.noop {
            *slot = value;
            unit.invalidate(mask);
            unit.write(format!("{name}={}", if value { "yes" } else { "no" }));
        }
        Ok(true)
    }

    fn set_weight(
        unit: &mut UnitState,
        name: &str,
        slot: &mut u64,
        mask: CGroupMask,
        value: u64,
        allow_idle: bool,
        flags: UnitWriteFlags,
    ) -> Result<bool> {
        let weight_ok = (1..=10_000).contains(&value)
            || value == CGROUP_WEIGHT_INVALID
            || (allow_idle && value == CGROUP_WEIGHT_IDLE);
        if !weight_ok {
            return Err(CGroupError::invalid(format!(
                "Value specified in {name} is out of range"
            )));
        }
        if !flags.noop {
            *slot = value;
            unit.invalidate(mask);
            unit.write(if value == CGROUP_WEIGHT_INVALID {
                format!("{name}=")
            } else if allow_idle && value == CGROUP_WEIGHT_IDLE {
                format!("{name}=idle")
            } else {
                format!("{name}={value}")
            });
        }
        Ok(true)
    }

    fn set_limit(
        unit: &mut UnitState,
        name: &str,
        slot: &mut u64,
        mask: CGroupMask,
        value: u64,
        minimum: u64,
        flags: UnitWriteFlags,
    ) -> Result<bool> {
        if value < minimum {
            return Err(CGroupError::invalid(format!(
                "Value specified in {name} is out of range"
            )));
        }
        if !flags.noop {
            *slot = value;
            unit.invalidate(mask);
            unit.write(if value == CGROUP_LIMIT_MAX {
                format!("{name}=infinity")
            } else {
                format!("{name}={value}")
            });
        }
        Ok(true)
    }

    fn set_tasks_max(
        &mut self,
        unit: &mut UnitState,
        name: &str,
        value: u64,
        flags: UnitWriteFlags,
    ) -> Result<bool> {
        if value < 1 {
            return Err(CGroupError::invalid(format!(
                "Value specified in {name} is out of range"
            )));
        }
        if !flags.noop {
            self.tasks_max = CGroupTasksMax { value, scale: 0 };
            unit.invalidate(CGROUP_MASK_PIDS);
            unit.write(if value == CGROUP_LIMIT_MAX {
                format!("{name}=infinity")
            } else {
                format!("{name}={value}")
            });
        }
        Ok(true)
    }

    fn set_tasks_max_scale(
        &mut self,
        unit: &mut UnitState,
        name: &str,
        value: u32,
        flags: UnitWriteFlags,
    ) -> Result<bool> {
        if value == 0 || value == u32::MAX {
            return Err(CGroupError::invalid(format!(
                "Value specified in {name} is out of range"
            )));
        }
        if !flags.noop {
            self.tasks_max = CGroupTasksMax {
                value: value as u64,
                scale: u32::MAX as u64,
            };
            unit.invalidate(CGROUP_MASK_PIDS);
            unit.write(format!(
                "TasksMax={:.2}%",
                (value as f64 * 100.0) / u32::MAX as f64
            ));
        }
        Ok(true)
    }

    fn path_is_normalized(path: &str) -> bool {
        path.starts_with('/')
            && !path.contains("//")
            && !path.contains("/./")
            && !path.ends_with("/.")
    }

    pub fn bus_cgroup_set_property(
        &mut self,
        unit: &mut UnitState,
        name: &str,
        message: &CGroupMessage,
        mut flags: UnitWriteFlags,
    ) -> Result<bool> {
        flags.private = true;

        if unit.transient && unit.load_stub {
            let transient = self.bus_cgroup_set_transient_property(unit, name, message, flags)?;
            if transient {
                return Ok(true);
            }
        }

        match (name, message) {
            ("CPUWeight", CGroupMessage::U64(value)) => Self::set_weight(
                unit,
                name,
                &mut self.cpu_weight,
                CGROUP_MASK_CPU,
                *value,
                true,
                flags,
            ),
            ("StartupCPUWeight", CGroupMessage::U64(value)) => Self::set_weight(
                unit,
                name,
                &mut self.startup_cpu_weight,
                CGROUP_MASK_CPU,
                *value,
                true,
                flags,
            ),
            ("IOAccounting", CGroupMessage::Bool(value)) => Self::set_bool(
                unit,
                name,
                &mut self.io_accounting,
                CGROUP_MASK_IO,
                *value,
                flags,
            ),
            ("IOWeight", CGroupMessage::U64(value)) => Self::set_weight(
                unit,
                name,
                &mut self.io_weight,
                CGROUP_MASK_IO,
                *value,
                false,
                flags,
            ),
            ("StartupIOWeight", CGroupMessage::U64(value)) => Self::set_weight(
                unit,
                name,
                &mut self.startup_io_weight,
                CGROUP_MASK_IO,
                *value,
                false,
                flags,
            ),
            ("MemoryAccounting", CGroupMessage::Bool(value)) => Self::set_bool(
                unit,
                name,
                &mut self.memory_accounting,
                CGROUP_MASK_MEMORY,
                *value,
                flags,
            ),
            ("MemoryMin", CGroupMessage::U64(value)) => Self::set_limit(
                unit,
                name,
                &mut self.memory_min,
                CGROUP_MASK_MEMORY,
                *value,
                0,
                flags,
            ),
            ("MemoryLow", CGroupMessage::U64(value)) => Self::set_limit(
                unit,
                name,
                &mut self.memory_low,
                CGROUP_MASK_MEMORY,
                *value,
                0,
                flags,
            ),
            ("StartupMemoryLow", CGroupMessage::U64(value)) => Self::set_limit(
                unit,
                name,
                &mut self.startup_memory_low,
                CGROUP_MASK_MEMORY,
                *value,
                0,
                flags,
            ),
            ("MemoryHigh", CGroupMessage::U64(value)) => Self::set_limit(
                unit,
                name,
                &mut self.memory_high,
                CGROUP_MASK_MEMORY,
                *value,
                1,
                flags,
            ),
            ("MemoryMax", CGroupMessage::U64(value)) => Self::set_limit(
                unit,
                name,
                &mut self.memory_max,
                CGROUP_MASK_MEMORY,
                *value,
                1,
                flags,
            ),
            ("MemorySwapMax", CGroupMessage::U64(value)) => Self::set_limit(
                unit,
                name,
                &mut self.memory_swap_max,
                CGROUP_MASK_MEMORY,
                *value,
                0,
                flags,
            ),
            ("MemoryZSwapMax", CGroupMessage::U64(value)) => Self::set_limit(
                unit,
                name,
                &mut self.memory_zswap_max,
                CGROUP_MASK_MEMORY,
                *value,
                0,
                flags,
            ),
            ("MemoryZSwapWriteback", CGroupMessage::Bool(value)) => Self::set_bool(
                unit,
                name,
                &mut self.memory_zswap_writeback,
                CGROUP_MASK_MEMORY,
                *value,
                flags,
            ),
            ("TasksAccounting", CGroupMessage::Bool(value)) => Self::set_bool(
                unit,
                name,
                &mut self.tasks_accounting,
                CGROUP_MASK_PIDS,
                *value,
                flags,
            ),
            ("TasksMax", CGroupMessage::U64(value)) => {
                self.set_tasks_max(unit, name, *value, flags)
            }
            ("TasksMaxScale", CGroupMessage::U32(value)) => {
                self.set_tasks_max_scale(unit, name, *value, flags)
            }
            ("CPUQuotaPerSecUSec", CGroupMessage::U64(value)) => {
                if *value == 0 {
                    return Err(CGroupError::invalid(
                        "CPUQuotaPerSecUSec= value out of range",
                    ));
                }
                if !flags.noop {
                    self.cpu_quota_per_sec_usec = *value;
                    unit.invalidate(CGROUP_MASK_CPU);
                    unit.write(format!("CPUQuota={:.2}%", *value as f64 / 10_000.0));
                }
                Ok(true)
            }
            ("CPUQuotaPeriodUSec", CGroupMessage::U64(value)) => {
                if !flags.noop {
                    self.cpu_quota_period_usec = *value;
                    unit.invalidate(CGROUP_MASK_CPU);
                    unit.write(if *value == CGROUP_LIMIT_MAX {
                        "CPUQuotaPeriodSec=".into()
                    } else {
                        format!("CPUQuotaPeriodSec={value}")
                    });
                }
                Ok(true)
            }
            ("AllowedCPUs", CGroupMessage::Bytes(bytes)) => {
                self.set_cpuset(unit, name, bytes, flags, |ctx, set| ctx.cpuset_cpus = set)
            }
            ("StartupAllowedCPUs", CGroupMessage::Bytes(bytes)) => {
                self.set_cpuset(unit, name, bytes, flags, |ctx, set| {
                    ctx.startup_cpuset_cpus = set
                })
            }
            ("AllowedMemoryNodes", CGroupMessage::Bytes(bytes)) => {
                self.set_cpuset(unit, name, bytes, flags, |ctx, set| ctx.cpuset_mems = set)
            }
            ("StartupAllowedMemoryNodes", CGroupMessage::Bytes(bytes)) => {
                self.set_cpuset(unit, name, bytes, flags, |ctx, set| {
                    ctx.startup_cpuset_mems = set
                })
            }
            ("CPUSetPartition", CGroupMessage::String(value)) => {
                let partition = CpuSetPartition::parse(value)?;
                if !flags.noop {
                    self.cpuset_partition = partition;
                    unit.invalidate(CGROUP_MASK_CPUSET);
                    unit.write(format!(
                        "{name}={}",
                        partition.map(CpuSetPartition::as_str).unwrap_or("")
                    ));
                }
                Ok(true)
            }
            ("IODeviceWeight", CGroupMessage::DeviceWeights(values)) => {
                for (path, weight) in values {
                    if !Self::path_is_normalized(path) || *weight == 0 || *weight > 10_000 {
                        return Err(CGroupError::invalid("IODeviceWeight= value out of range"));
                    }
                }
                if !flags.noop {
                    self.io_device_weights = values
                        .iter()
                        .map(|(path, weight)| DeviceWeight {
                            path: path.clone(),
                            weight: *weight,
                        })
                        .collect();
                    unit.invalidate(CGROUP_MASK_IO);
                    unit.write(format!("IODeviceWeight={}", self.io_device_weights.len()));
                }
                Ok(true)
            }
            ("IODeviceLatencyTargetUSec", CGroupMessage::DeviceLatencies(values)) => {
                for (path, _) in values {
                    if !Self::path_is_normalized(path) {
                        return Err(CGroupError::invalid(format!(
                            "Path '{path}' specified in {name}= is not normalized."
                        )));
                    }
                }
                if !flags.noop {
                    self.io_device_latencies = values
                        .iter()
                        .map(|(path, target_usec)| DeviceLatency {
                            path: path.clone(),
                            target_usec: *target_usec,
                        })
                        .collect();
                    unit.invalidate(CGROUP_MASK_IO);
                    unit.write(format!(
                        "IODeviceLatencyTargetSec={}",
                        self.io_device_latencies.len()
                    ));
                }
                Ok(true)
            }
            ("DevicePolicy", CGroupMessage::String(value)) => {
                if !flags.noop {
                    self.device_policy = CGroupDevicePolicy::parse(value)?;
                    unit.invalidate(CGROUP_MASK_BPF_DEVICES);
                    unit.write(format!("DevicePolicy={value}"));
                }
                Ok(true)
            }
            ("DeviceAllow", CGroupMessage::DeviceAllows(values)) => {
                for (path, _) in values {
                    if path.trim().is_empty() || path.contains(char::is_whitespace) {
                        return Err(CGroupError::invalid(
                            "DeviceAllow= requires device node or pattern",
                        ));
                    }
                }
                if !flags.noop {
                    self.device_allow = values
                        .iter()
                        .map(|(path, permissions)| DeviceAllow {
                            path: path.clone(),
                            permissions: if permissions.is_empty() {
                                "rwm".into()
                            } else {
                                permissions.clone()
                            },
                        })
                        .collect();
                    unit.invalidate(CGROUP_MASK_BPF_DEVICES);
                    unit.write(format!("DeviceAllow={}", self.device_allow.len()));
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn set_cpuset<F>(
        &mut self,
        unit: &mut UnitState,
        name: &str,
        bytes: &[u8],
        flags: UnitWriteFlags,
        mut store: F,
    ) -> Result<bool>
    where
        F: FnMut(&mut Self, CpuSet),
    {
        let set = CpuSet::from_dbus_bytes(bytes);
        if !flags.noop {
            let setstr = set.to_range_string();
            store(self, set);
            unit.invalidate(CGROUP_MASK_CPUSET);
            unit.write(format!("{name}=\n{name}={setstr}"));
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_mask_to_strings() {
        let names = CGroupContext::property_get_cgroup_mask(CGROUP_MASK_CPU | CGROUP_MASK_IO);
        assert_eq!(names, vec!["cpu", "io"]);
    }

    #[test]
    fn delegate_controllers_empty_without_delegate() {
        let ctx = CGroupContext::default();
        assert!(ctx.property_get_delegate_controllers().is_empty());
    }

    #[test]
    fn cpuset_round_trip() {
        let set = CpuSet::from_ids([0, 2, 9]);
        let bytes = set.to_dbus_bytes();
        assert_eq!(CpuSet::from_dbus_bytes(&bytes), set);
    }

    #[test]
    fn transient_delegate_requires_capability() {
        let mut ctx = CGroupContext::default();
        let mut unit = UnitState::default();
        assert!(
            ctx.bus_cgroup_set_transient_property(
                &mut unit,
                "Delegate",
                &CGroupMessage::Bool(true),
                UnitWriteFlags::default()
            )
            .is_err()
        );
    }

    #[test]
    fn transient_delegate_updates_mask() {
        let mut ctx = CGroupContext::default();
        let mut unit = UnitState {
            can_delegate: true,
            ..Default::default()
        };
        ctx.bus_cgroup_set_transient_property(
            &mut unit,
            "Delegate",
            &CGroupMessage::Bool(true),
            UnitWriteFlags::default(),
        )
        .unwrap();
        assert!(ctx.delegate);
        assert_eq!(ctx.delegate_controllers, CGROUP_MASK_DELEGATE);
    }

    #[test]
    fn cpu_weight_accepts_idle() {
        let mut ctx = CGroupContext::default();
        let mut unit = UnitState::default();
        ctx.bus_cgroup_set_property(
            &mut unit,
            "CPUWeight",
            &CGroupMessage::U64(CGROUP_WEIGHT_IDLE),
            UnitWriteFlags::default(),
        )
        .unwrap();
        assert_eq!(ctx.cpu_weight, CGROUP_WEIGHT_IDLE);
        assert!(unit.write_log.last().unwrap().contains("idle"));
    }

    #[test]
    fn tasks_max_scale_rejects_full_scale() {
        let mut ctx = CGroupContext::default();
        let mut unit = UnitState::default();
        assert!(
            ctx.bus_cgroup_set_property(
                &mut unit,
                "TasksMaxScale",
                &CGroupMessage::U32(u32::MAX),
                UnitWriteFlags::default()
            )
            .is_err()
        );
    }

    #[test]
    fn allowed_cpus_invalidates_cpuset() {
        let mut ctx = CGroupContext::default();
        let mut unit = UnitState::default();
        ctx.bus_cgroup_set_property(
            &mut unit,
            "AllowedCPUs",
            &CGroupMessage::Bytes(vec![0b0000_0101]),
            UnitWriteFlags::default(),
        )
        .unwrap();
        assert!(ctx.cpuset_cpus.0.contains(&0));
        assert!(ctx.cpuset_cpus.0.contains(&2));
        assert_eq!(unit.invalidated_masks, vec![CGROUP_MASK_CPUSET]);
    }

    #[test]
    fn cpuset_partition_round_trips_through_property_setter() {
        let mut ctx = CGroupContext::default();
        let mut unit = UnitState::default();
        ctx.bus_cgroup_set_property(
            &mut unit,
            "CPUSetPartition",
            &CGroupMessage::String("isolated".into()),
            UnitWriteFlags::default(),
        )
        .unwrap();
        assert_eq!(ctx.cpuset_partition, Some(CpuSetPartition::Isolated));
        assert_eq!(unit.invalidated_masks, vec![CGROUP_MASK_CPUSET]);
    }

    #[test]
    fn transient_pressure_properties_cover_all_resources() {
        let mut ctx = CGroupContext::default();
        let mut unit = UnitState::default();
        ctx.bus_cgroup_set_transient_property(
            &mut unit,
            "CPUPressureWatch",
            &CGroupMessage::String("yes".into()),
            UnitWriteFlags::default(),
        )
        .unwrap();
        ctx.bus_cgroup_set_transient_property(
            &mut unit,
            "IOPressureThresholdUSec",
            &CGroupMessage::U64(42),
            UnitWriteFlags::default(),
        )
        .unwrap();
        assert_eq!(ctx.cpu_pressure_watch, CGroupPressureWatch::Yes);
        assert_eq!(ctx.io_pressure_threshold_usec, 42);
    }

    #[test]
    fn device_allow_rejects_whitespace_path() {
        let mut ctx = CGroupContext::default();
        let mut unit = UnitState::default();
        assert!(
            ctx.bus_cgroup_set_property(
                &mut unit,
                "DeviceAllow",
                &CGroupMessage::DeviceAllows(vec![("bad path".into(), "r".into())]),
                UnitWriteFlags::default()
            )
            .is_err()
        );
    }
}
