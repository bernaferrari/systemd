// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/varlink-unit.c
//
use std::collections::{BTreeMap, BTreeSet};

pub const SOURCE_PATH: &str = "src/core/varlink-unit.c";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
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
pub enum VarlinkUnitError {
    UnknownProperty(String),
    InvalidMarker(String),
    MissingIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    pub kind: String,
    pub trigger: bool,
    pub negate: bool,
    pub parameter: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationDetail {
    pub detail_type: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnitContext {
    pub unit_type: String,
    pub id: String,
    pub names: BTreeSet<String>,
    pub description: Option<String>,
    pub documentation: Vec<String>,
    pub dependencies: BTreeMap<String, BTreeSet<String>>,
    pub mounts_for: BTreeMap<String, BTreeSet<String>>,
    pub on_success_job_mode: Option<String>,
    pub on_failure_job_mode: Option<String>,
    pub ignore_on_isolate: bool,
    pub stop_when_unneeded: bool,
    pub refuse_manual_start: bool,
    pub refuse_manual_stop: bool,
    pub allow_isolate: bool,
    pub default_dependencies: bool,
    pub conditions: Vec<Condition>,
    pub asserts: Vec<Condition>,
    pub access_selinux_context: Option<String>,
    pub fragment_path: Option<String>,
    pub source_path: Option<String>,
    pub drop_in_paths: Vec<String>,
    pub transient: bool,
    pub perpetual: bool,
    pub debug_invocation: bool,
    pub cgroup: Option<JsonValue>,
    pub exec: Option<JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnitRuntime {
    pub following: Option<String>,
    pub load_state: String,
    pub active_state: String,
    pub freezer_state: String,
    pub sub_state: String,
    pub unit_file_state: Option<String>,
    pub can_start: bool,
    pub can_stop: bool,
    pub can_reload: bool,
    pub can_isolate: bool,
    pub can_clean: BTreeSet<String>,
    pub can_freeze: bool,
    pub can_live_mount: bool,
    pub job_id: Option<u64>,
    pub need_daemon_reload: bool,
    pub condition_result: bool,
    pub assert_result: bool,
    pub markers: BTreeSet<String>,
    pub activation_details: Vec<ActivationDetail>,
    pub cgroup: Option<JsonValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitMarker {
    NeedsReload,
    Maintenance,
    Generated,
    Transient,
}

pub fn unit_dependencies_build_json(
    name: &str,
    dependencies: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Option<JsonValue>, VarlinkUnitError> {
    let Some(entries) = dependencies.get(name) else {
        return Ok(None);
    };

    Ok(Some(JsonValue::Array(
        entries.iter().cloned().map(JsonValue::string).collect(),
    )))
}

pub fn unit_mounts_for_build_json(
    name: &str,
    mounts_for: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Option<JsonValue>, VarlinkUnitError> {
    let Some(entries) = mounts_for.get(name) else {
        return Ok(None);
    };

    Ok(Some(JsonValue::Array(
        entries.iter().cloned().map(JsonValue::string).collect(),
    )))
}

pub fn unit_conditions_build_json(
    name: &str,
    items: &[Condition],
) -> Result<Option<JsonValue>, VarlinkUnitError> {
    let _assert_mode = name == "Asserts";
    let values = items
        .iter()
        .map(|condition| {
            let mut map = BTreeMap::new();
            map.insert("type".into(), JsonValue::string(&condition.kind));
            map.insert("trigger".into(), JsonValue::Bool(condition.trigger));
            map.insert("negate".into(), JsonValue::Bool(condition.negate));
            if let Some(parameter) = &condition.parameter {
                if !parameter.is_empty() {
                    map.insert("parameter".into(), JsonValue::string(parameter));
                }
            }
            JsonValue::Object(map)
        })
        .collect::<Vec<_>>();

    Ok((!values.is_empty()).then(|| JsonValue::Array(values)))
}

pub fn can_clean_build_json(
    entries: &BTreeSet<String>,
) -> Result<Option<JsonValue>, VarlinkUnitError> {
    Ok((!entries.is_empty())
        .then(|| JsonValue::Array(entries.iter().cloned().map(JsonValue::string).collect())))
}

pub fn markers_build_json(
    entries: &BTreeSet<String>,
) -> Result<Option<JsonValue>, VarlinkUnitError> {
    Ok((!entries.is_empty())
        .then(|| JsonValue::Array(entries.iter().cloned().map(JsonValue::string).collect())))
}

pub fn activation_details_build_json(
    items: &[ActivationDetail],
) -> Result<Option<JsonValue>, VarlinkUnitError> {
    let values = items
        .iter()
        .map(|item| {
            JsonValue::object([
                ("type", JsonValue::string(&item.detail_type)),
                ("name", JsonValue::string(&item.name)),
            ])
        })
        .collect::<Vec<_>>();

    Ok((!values.is_empty()).then(|| JsonValue::Array(values)))
}

pub fn unit_context_build_json(context: &UnitContext) -> Result<JsonValue, VarlinkUnitError> {
    if context.id.is_empty() || context.unit_type.is_empty() {
        return Err(VarlinkUnitError::MissingIdentity);
    }

    let mut object = BTreeMap::new();
    object.insert("Type".into(), JsonValue::string(&context.unit_type));
    object.insert("ID".into(), JsonValue::string(&context.id));

    if !context.names.is_empty() {
        object.insert(
            "Names".into(),
            JsonValue::Array(
                context
                    .names
                    .iter()
                    .cloned()
                    .map(JsonValue::string)
                    .collect(),
            ),
        );
    }
    if let Some(description) = &context.description {
        if !description.is_empty() {
            object.insert("Description".into(), JsonValue::string(description));
        }
    }
    if !context.documentation.is_empty() {
        object.insert(
            "Documentation".into(),
            JsonValue::Array(
                context
                    .documentation
                    .iter()
                    .cloned()
                    .map(JsonValue::string)
                    .collect(),
            ),
        );
    }

    for key in [
        "Wants",
        "WantedBy",
        "Requires",
        "RequiredBy",
        "Conflicts",
        "Before",
        "After",
        "Triggers",
        "TriggeredBy",
    ] {
        if let Some(value) = unit_dependencies_build_json(key, &context.dependencies)? {
            object.insert(key.into(), value);
        }
    }

    for key in ["RequiresMountsFor", "WantsMountsFor"] {
        if let Some(value) = unit_mounts_for_build_json(key, &context.mounts_for)? {
            object.insert(key.into(), value);
        }
    }

    for (name, value) in [
        ("IgnoreOnIsolate", context.ignore_on_isolate),
        ("StopWhenUnneeded", context.stop_when_unneeded),
        ("RefuseManualStart", context.refuse_manual_start),
        ("RefuseManualStop", context.refuse_manual_stop),
        ("AllowIsolate", context.allow_isolate),
        ("DefaultDependencies", context.default_dependencies),
        ("Transient", context.transient),
        ("Perpetual", context.perpetual),
        ("DebugInvocation", context.debug_invocation),
    ] {
        object.insert(name.into(), JsonValue::Bool(value));
    }

    if let Some(value) = unit_conditions_build_json("Conditions", &context.conditions)? {
        object.insert("Conditions".into(), value);
    }
    if let Some(value) = unit_conditions_build_json("Asserts", &context.asserts)? {
        object.insert("Asserts".into(), value);
    }
    if let Some(value) = &context.on_success_job_mode {
        object.insert("OnSuccessJobMode".into(), JsonValue::string(value));
    }
    if let Some(value) = &context.on_failure_job_mode {
        object.insert("OnFailureJobMode".into(), JsonValue::string(value));
    }
    if let Some(value) = &context.access_selinux_context {
        object.insert("AccessSELinuxContext".into(), JsonValue::string(value));
    }
    if let Some(value) = &context.fragment_path {
        object.insert("FragmentPath".into(), JsonValue::string(value));
    }
    if let Some(value) = &context.source_path {
        object.insert("SourcePath".into(), JsonValue::string(value));
    }
    if !context.drop_in_paths.is_empty() {
        object.insert(
            "DropInPaths".into(),
            JsonValue::Array(
                context
                    .drop_in_paths
                    .iter()
                    .cloned()
                    .map(JsonValue::string)
                    .collect(),
            ),
        );
    }
    if let Some(value) = &context.cgroup {
        object.insert("CGroup".into(), value.clone());
    }
    if let Some(value) = &context.exec {
        object.insert("Exec".into(), value.clone());
    }

    Ok(JsonValue::Object(object))
}

pub fn unit_runtime_build_json(runtime: &UnitRuntime) -> Result<JsonValue, VarlinkUnitError> {
    let mut object = BTreeMap::new();
    if let Some(value) = &runtime.following {
        object.insert("Following".into(), JsonValue::string(value));
    }
    object.insert("LoadState".into(), JsonValue::string(&runtime.load_state));
    object.insert(
        "ActiveState".into(),
        JsonValue::string(&runtime.active_state),
    );
    object.insert(
        "FreezerState".into(),
        JsonValue::string(&runtime.freezer_state),
    );
    object.insert("SubState".into(), JsonValue::string(&runtime.sub_state));
    if let Some(value) = &runtime.unit_file_state {
        object.insert("UnitFileState".into(), JsonValue::string(value));
    }
    for (name, value) in [
        ("CanStart", runtime.can_start),
        ("CanStop", runtime.can_stop),
        ("CanReload", runtime.can_reload),
        ("CanIsolate", runtime.can_isolate),
        ("CanFreeze", runtime.can_freeze),
        ("CanLiveMount", runtime.can_live_mount),
        ("NeedDaemonReload", runtime.need_daemon_reload),
        ("ConditionResult", runtime.condition_result),
        ("AssertResult", runtime.assert_result),
    ] {
        object.insert(name.into(), JsonValue::Bool(value));
    }
    if let Some(value) = can_clean_build_json(&runtime.can_clean)? {
        object.insert("CanClean".into(), value);
    }
    if let Some(job_id) = runtime.job_id {
        object.insert("JobId".into(), JsonValue::Number(job_id));
    }
    if let Some(value) = markers_build_json(&runtime.markers)? {
        object.insert("Markers".into(), value);
    }
    if let Some(value) = activation_details_build_json(&runtime.activation_details)? {
        object.insert("ActivationDetails".into(), value);
    }
    if let Some(value) = &runtime.cgroup {
        object.insert("CGroup".into(), value.clone());
    }

    Ok(JsonValue::Object(object))
}

pub fn parse_unit_marker(name: &str) -> Result<UnitMarker, VarlinkUnitError> {
    match name {
        "needs-reload" => Ok(UnitMarker::NeedsReload),
        "maintenance" => Ok(UnitMarker::Maintenance),
        "generated" => Ok(UnitMarker::Generated),
        "transient" => Ok(UnitMarker::Transient),
        other => Err(VarlinkUnitError::InvalidMarker(other.to_string())),
    }
}

pub fn unit_dispatch_properties(
    property: &str,
    context: &UnitContext,
    runtime: &UnitRuntime,
) -> Result<JsonValue, VarlinkUnitError> {
    match property {
        "context" => unit_context_build_json(context),
        "runtime" => unit_runtime_build_json(runtime),
        other => Err(VarlinkUnitError::UnknownProperty(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_builder_returns_named_dependency_set() {
        let mut dependencies = BTreeMap::new();
        dependencies.insert(
            "Wants".into(),
            BTreeSet::from(["a.service".into(), "b.service".into()]),
        );

        let json = unit_dependencies_build_json("Wants", &dependencies)
            .unwrap()
            .unwrap();
        match json {
            JsonValue::Array(values) => assert_eq!(values.len(), 2),
            other => panic!("unexpected json: {other:?}"),
        }
    }

    #[test]
    fn context_builder_keeps_identity_and_conditions() {
        let json = unit_context_build_json(&UnitContext {
            unit_type: "service".into(),
            id: "demo.service".into(),
            conditions: vec![Condition {
                kind: "PathExists".into(),
                trigger: false,
                negate: false,
                parameter: Some("/tmp/demo".into()),
            }],
            ..UnitContext::default()
        })
        .unwrap();

        match json {
            JsonValue::Object(map) => {
                assert_eq!(map.get("ID"), Some(&JsonValue::string("demo.service")));
                assert!(map.contains_key("Conditions"));
            }
            other => panic!("unexpected json: {other:?}"),
        }
    }

    #[test]
    fn runtime_builder_collects_runtime_only_fields() {
        let json = unit_runtime_build_json(&UnitRuntime {
            load_state: "loaded".into(),
            active_state: "active".into(),
            freezer_state: "running".into(),
            sub_state: "running".into(),
            can_start: true,
            markers: BTreeSet::from(["needs-reload".into()]),
            ..UnitRuntime::default()
        })
        .unwrap();

        match json {
            JsonValue::Object(map) => assert!(map.contains_key("Markers")),
            other => panic!("unexpected json: {other:?}"),
        }
    }

    #[test]
    fn marker_parser_rejects_unknown_markers() {
        let error = parse_unit_marker("mystery").unwrap_err();
        assert_eq!(error, VarlinkUnitError::InvalidMarker("mystery".into()));
    }
}
