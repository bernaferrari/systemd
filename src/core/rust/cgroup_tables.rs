// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/cgroup.c, src/core/cgroup.h
//
// CGroup enum/string tables mirroring the C string-table helpers.

use crate::ffi::Errno;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CGroupDevicePolicy {
    Auto,
    Closed,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CGroupPressureWatch {
    No,
    Yes,
    Auto,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuSetPartition {
    Member,
    Root,
    Isolated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CGroupIpAccountingMetric {
    IngressBytes,
    IngressPackets,
    EgressBytes,
    EgressPackets,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CGroupIoAccountingMetric {
    ReadBytes,
    WriteBytes,
    ReadOperations,
    WriteOperations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CGroupMemoryAccountingMetric {
    Peak,
    SwapPeak,
    Current,
    SwapCurrent,
    ZSwapCurrent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CGroupEffectiveLimitType {
    MemoryMax,
    MemoryHigh,
    TasksMax,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CGroupTablesError {
    InvalidValue,
}

impl CGroupTablesError {
    pub const fn errno(&self) -> i32 {
        match self {
            Self::InvalidValue => Errno::EINVAL.to_neg_errno(),
        }
    }
}

pub fn cgroup_device_policy_to_string(value: CGroupDevicePolicy) -> &'static str {
    match value {
        CGroupDevicePolicy::Auto => "auto",
        CGroupDevicePolicy::Closed => "closed",
        CGroupDevicePolicy::Strict => "strict",
    }
}

pub fn cgroup_device_policy_from_string(
    value: &str,
) -> Result<CGroupDevicePolicy, CGroupTablesError> {
    match value {
        "auto" => Ok(CGroupDevicePolicy::Auto),
        "closed" => Ok(CGroupDevicePolicy::Closed),
        "strict" => Ok(CGroupDevicePolicy::Strict),
        _ => Err(CGroupTablesError::InvalidValue),
    }
}

pub fn cgroup_pressure_watch_to_string(value: CGroupPressureWatch) -> &'static str {
    match value {
        CGroupPressureWatch::No => "no",
        CGroupPressureWatch::Yes => "yes",
        CGroupPressureWatch::Auto => "auto",
        CGroupPressureWatch::Skip => "skip",
    }
}

pub fn cgroup_pressure_watch_from_string(
    value: &str,
) -> Result<CGroupPressureWatch, CGroupTablesError> {
    match value {
        "1" | "y" | "Y" | "yes" | "YES" | "t" | "true" | "on" => Ok(CGroupPressureWatch::Yes),
        "0" | "n" | "N" | "no" | "NO" | "f" | "false" | "off" => Ok(CGroupPressureWatch::No),
        "auto" => Ok(CGroupPressureWatch::Auto),
        "skip" => Ok(CGroupPressureWatch::Skip),
        _ => Err(CGroupTablesError::InvalidValue),
    }
}

pub fn cpuset_partition_to_string(value: CpuSetPartition) -> &'static str {
    match value {
        CpuSetPartition::Member => "member",
        CpuSetPartition::Root => "root",
        CpuSetPartition::Isolated => "isolated",
    }
}

pub fn cpuset_partition_from_string(value: &str) -> Result<CpuSetPartition, CGroupTablesError> {
    match value {
        "member" => Ok(CpuSetPartition::Member),
        "root" => Ok(CpuSetPartition::Root),
        "isolated" => Ok(CpuSetPartition::Isolated),
        _ => Err(CGroupTablesError::InvalidValue),
    }
}

pub fn cgroup_ip_accounting_metric_to_string(value: CGroupIpAccountingMetric) -> &'static str {
    match value {
        CGroupIpAccountingMetric::IngressBytes => "IPIngressBytes",
        CGroupIpAccountingMetric::IngressPackets => "IPIngressPackets",
        CGroupIpAccountingMetric::EgressBytes => "IPEgressBytes",
        CGroupIpAccountingMetric::EgressPackets => "IPEgressPackets",
    }
}

pub fn cgroup_ip_accounting_metric_from_string(
    value: &str,
) -> Result<CGroupIpAccountingMetric, CGroupTablesError> {
    match value {
        "IPIngressBytes" => Ok(CGroupIpAccountingMetric::IngressBytes),
        "IPIngressPackets" => Ok(CGroupIpAccountingMetric::IngressPackets),
        "IPEgressBytes" => Ok(CGroupIpAccountingMetric::EgressBytes),
        "IPEgressPackets" => Ok(CGroupIpAccountingMetric::EgressPackets),
        _ => Err(CGroupTablesError::InvalidValue),
    }
}

pub fn cgroup_io_accounting_metric_to_string(value: CGroupIoAccountingMetric) -> &'static str {
    match value {
        CGroupIoAccountingMetric::ReadBytes => "IOReadBytes",
        CGroupIoAccountingMetric::WriteBytes => "IOWriteBytes",
        CGroupIoAccountingMetric::ReadOperations => "IOReadOperations",
        CGroupIoAccountingMetric::WriteOperations => "IOWriteOperations",
    }
}

pub fn cgroup_io_accounting_metric_from_string(
    value: &str,
) -> Result<CGroupIoAccountingMetric, CGroupTablesError> {
    match value {
        "IOReadBytes" => Ok(CGroupIoAccountingMetric::ReadBytes),
        "IOWriteBytes" => Ok(CGroupIoAccountingMetric::WriteBytes),
        "IOReadOperations" => Ok(CGroupIoAccountingMetric::ReadOperations),
        "IOWriteOperations" => Ok(CGroupIoAccountingMetric::WriteOperations),
        _ => Err(CGroupTablesError::InvalidValue),
    }
}

pub fn cgroup_memory_accounting_metric_to_string(
    value: CGroupMemoryAccountingMetric,
) -> &'static str {
    match value {
        CGroupMemoryAccountingMetric::Peak => "MemoryPeak",
        CGroupMemoryAccountingMetric::SwapPeak => "MemorySwapPeak",
        CGroupMemoryAccountingMetric::Current => "MemoryCurrent",
        CGroupMemoryAccountingMetric::SwapCurrent => "MemorySwapCurrent",
        CGroupMemoryAccountingMetric::ZSwapCurrent => "MemoryZSwapCurrent",
    }
}

pub fn cgroup_memory_accounting_metric_from_string(
    value: &str,
) -> Result<CGroupMemoryAccountingMetric, CGroupTablesError> {
    match value {
        "MemoryPeak" => Ok(CGroupMemoryAccountingMetric::Peak),
        "MemorySwapPeak" => Ok(CGroupMemoryAccountingMetric::SwapPeak),
        "MemoryCurrent" => Ok(CGroupMemoryAccountingMetric::Current),
        "MemorySwapCurrent" => Ok(CGroupMemoryAccountingMetric::SwapCurrent),
        "MemoryZSwapCurrent" => Ok(CGroupMemoryAccountingMetric::ZSwapCurrent),
        _ => Err(CGroupTablesError::InvalidValue),
    }
}

pub fn cgroup_effective_limit_type_to_string(value: CGroupEffectiveLimitType) -> &'static str {
    match value {
        CGroupEffectiveLimitType::MemoryMax => "EffectiveMemoryMax",
        CGroupEffectiveLimitType::MemoryHigh => "EffectiveMemoryHigh",
        CGroupEffectiveLimitType::TasksMax => "EffectiveTasksMax",
    }
}

pub fn cgroup_effective_limit_type_from_string(
    value: &str,
) -> Result<CGroupEffectiveLimitType, CGroupTablesError> {
    match value {
        "EffectiveMemoryMax" => Ok(CGroupEffectiveLimitType::MemoryMax),
        "EffectiveMemoryHigh" => Ok(CGroupEffectiveLimitType::MemoryHigh),
        "EffectiveTasksMax" => Ok(CGroupEffectiveLimitType::TasksMax),
        _ => Err(CGroupTablesError::InvalidValue),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_policy_round_trips() {
        let parsed = cgroup_device_policy_from_string("closed").unwrap();
        assert_eq!(parsed, CGroupDevicePolicy::Closed);
        assert_eq!(cgroup_device_policy_to_string(parsed), "closed");
    }

    #[test]
    fn pressure_watch_accepts_boolean_yes_forms() {
        assert_eq!(
            cgroup_pressure_watch_from_string("1").unwrap(),
            CGroupPressureWatch::Yes
        );
        assert_eq!(
            cgroup_pressure_watch_from_string("on").unwrap(),
            CGroupPressureWatch::Yes
        );
    }

    #[test]
    fn pressure_watch_accepts_boolean_no_forms() {
        assert_eq!(
            cgroup_pressure_watch_from_string("0").unwrap(),
            CGroupPressureWatch::No
        );
        assert_eq!(
            cgroup_pressure_watch_from_string("off").unwrap(),
            CGroupPressureWatch::No
        );
    }

    #[test]
    fn pressure_watch_accepts_named_modes() {
        assert_eq!(
            cgroup_pressure_watch_from_string("auto").unwrap(),
            CGroupPressureWatch::Auto
        );
        assert_eq!(
            cgroup_pressure_watch_from_string("skip").unwrap(),
            CGroupPressureWatch::Skip
        );
    }

    #[test]
    fn cpuset_partition_round_trips() {
        for partition in [
            CpuSetPartition::Member,
            CpuSetPartition::Root,
            CpuSetPartition::Isolated,
        ] {
            assert_eq!(
                cpuset_partition_from_string(cpuset_partition_to_string(partition)),
                Ok(partition)
            );
        }
    }

    #[test]
    fn ip_metric_round_trips() {
        let value = cgroup_ip_accounting_metric_from_string("IPEgressPackets").unwrap();
        assert_eq!(value, CGroupIpAccountingMetric::EgressPackets);
        assert_eq!(
            cgroup_ip_accounting_metric_to_string(value),
            "IPEgressPackets"
        );
    }

    #[test]
    fn io_metric_round_trips() {
        let value = cgroup_io_accounting_metric_from_string("IOReadOperations").unwrap();
        assert_eq!(value, CGroupIoAccountingMetric::ReadOperations);
        assert_eq!(
            cgroup_io_accounting_metric_to_string(value),
            "IOReadOperations"
        );
    }

    #[test]
    fn memory_metric_round_trips() {
        let value = cgroup_memory_accounting_metric_from_string("MemoryZSwapCurrent").unwrap();
        assert_eq!(value, CGroupMemoryAccountingMetric::ZSwapCurrent);
        assert_eq!(
            cgroup_memory_accounting_metric_to_string(value),
            "MemoryZSwapCurrent"
        );
    }

    #[test]
    fn effective_limit_round_trips() {
        let value = cgroup_effective_limit_type_from_string("EffectiveTasksMax").unwrap();
        assert_eq!(value, CGroupEffectiveLimitType::TasksMax);
        assert_eq!(
            cgroup_effective_limit_type_to_string(value),
            "EffectiveTasksMax"
        );
    }

    #[test]
    fn invalid_values_report_errno() {
        let err = cgroup_device_policy_from_string("bogus").unwrap_err();
        assert_eq!(err, CGroupTablesError::InvalidValue);
        assert_eq!(err.errno(), Errno::EINVAL.to_neg_errno());
    }
}
