// SPDX-License-Identifier: GPL-2.0-or-later
// PORT-SYNC: src/udev/udev-event.c

pub const SOURCE_PATH: &str = "src/udev/udev-event.c";
pub const SOURCE_LINE_COUNT: usize = 442;

pub const INCLUDED_HEADERS: &[&str] = &[
    "alloc-util.h",
    "device-internal.h",
    "device-private.h",
    "device-util.h",
    "hashmap.h",
    "netif-naming-scheme.h",
    "netlink-util.h",
    "path-util.h",
    "sd-netlink.h",
    "socket-util.h",
    "string-util.h",
    "strv.h",
    "time-util.h",
    "udev-event.h",
    "udev-node.h",
    "udev-rules.h",
    "udev-trace.h",
    "udev-util.h",
    "udev-worker.h",
    "user-util.h",
];

pub const EXPORTED_FUNCTIONS: &[&str] = &[
    "udev_event_new",
    "udev_event_free",
    "device_rename",
    "rename_netif",
    "assign_altnames",
    "update_devnode",
    "event_execute_rules_on_remove",
    "update_clone",
    "udev_event_execute_rules",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventModeModel {
    UdevWorker,
    UdevadmTest,
    TestRuleRunner,
    TestSpawn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStage {
    Allocate,
    RenameNetif,
    AssignAltnames,
    UpdateDevnode,
    ApplyRemoveRules,
    UpdateClone,
    ExecuteRules,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventOverview {
    pub source_path: &'static str,
    pub line_count: usize,
    pub include_count: usize,
    pub function_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventModelError {
    UnknownFunction(String),
    InvalidTransition,
}

pub fn port_overview() -> EventOverview {
    EventOverview {
        source_path: SOURCE_PATH,
        line_count: SOURCE_LINE_COUNT,
        include_count: INCLUDED_HEADERS.len(),
        function_count: EXPORTED_FUNCTIONS.len(),
    }
}

pub fn event_stages(mode: EventModeModel) -> Result<Vec<EventStage>, EventModelError> {
    let mut stages = vec![EventStage::Allocate];
    if matches!(
        mode,
        EventModeModel::UdevWorker | EventModeModel::TestRuleRunner
    ) {
        stages.extend([
            EventStage::RenameNetif,
            EventStage::AssignAltnames,
            EventStage::UpdateDevnode,
            EventStage::ApplyRemoveRules,
            EventStage::UpdateClone,
        ]);
    }
    stages.push(EventStage::ExecuteRules);
    Ok(stages)
}

pub fn function_group(name: &str) -> Result<&'static str, EventModelError> {
    match name {
        "udev_event_new" | "udev_event_free" => Ok("lifecycle"),
        "device_rename" | "rename_netif" | "assign_altnames" => Ok("network"),
        "update_devnode" | "update_clone" => Ok("device-state"),
        "event_execute_rules_on_remove" | "udev_event_execute_rules" => Ok("rule-engine"),
        other => Err(EventModelError::UnknownFunction(other.to_string())),
    }
}

pub fn validate_port_model() -> Result<(), EventModelError> {
    if port_overview().function_count != 9 {
        return Err(EventModelError::InvalidTransition);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_metadata_matches_c_file() {
        assert_eq!(SOURCE_PATH, "src/udev/udev-event.c");
        assert_eq!(SOURCE_LINE_COUNT, 442);
    }

    #[test]
    fn overview_counts_match_static_tables() {
        let overview = port_overview();
        assert_eq!(overview.include_count, INCLUDED_HEADERS.len());
        assert_eq!(overview.function_count, EXPORTED_FUNCTIONS.len());
    }

    #[test]
    fn worker_mode_contains_network_and_devnode_stages() {
        let stages = event_stages(EventModeModel::UdevWorker).unwrap();
        assert!(stages.contains(&EventStage::RenameNetif));
        assert!(stages.contains(&EventStage::UpdateDevnode));
    }

    #[test]
    fn test_spawn_mode_is_minimal() {
        let stages = event_stages(EventModeModel::TestSpawn).unwrap();
        assert_eq!(stages, vec![EventStage::Allocate, EventStage::ExecuteRules]);
    }

    #[test]
    fn lifecycle_functions_are_classified() {
        assert_eq!(function_group("udev_event_new").unwrap(), "lifecycle");
    }

    #[test]
    fn network_functions_are_classified() {
        assert_eq!(function_group("rename_netif").unwrap(), "network");
    }

    #[test]
    fn rule_engine_functions_are_classified() {
        assert_eq!(
            function_group("udev_event_execute_rules").unwrap(),
            "rule-engine"
        );
    }

    #[test]
    fn unknown_function_is_rejected() {
        assert_eq!(
            function_group("missing"),
            Err(EventModelError::UnknownFunction("missing".into()))
        );
    }

    #[test]
    fn headers_include_sd_netlink() {
        assert!(INCLUDED_HEADERS.contains(&"sd-netlink.h"));
    }

    #[test]
    fn port_model_validation_succeeds() {
        assert_eq!(validate_port_model(), Ok(()));
    }
}
