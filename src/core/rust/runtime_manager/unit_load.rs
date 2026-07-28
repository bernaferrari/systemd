// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Own fragment and drop-in lookup plus condition evaluation. This module consumes decoded
 * UnitFileInfo values and never mutates RuntimeManager.
 */
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

use super::unit_file::{
    UnitConditionConfig, UnitConditionExpression, UnitFileInfo, parse_unit_content_into,
};
use super::unit_specifier::template_unit_name;
use systemd_shared_rs::condition::{
    Condition as SharedCondition, ConditionType as SharedConditionType,
    condition_test_list as shared_condition_test_list,
};
use systemd_shared_rs::unit_file::UnitFileParseError;

pub(super) fn collect_dropin_directories(name: &str, search_paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let unit_dropin = format!("{name}.d");
    for search_path in search_paths {
        dirs.push(search_path.join(&unit_dropin));
    }

    if let Some(template) = template_unit_name(name) {
        let template_dropin = format!("{template}.d");
        for search_path in search_paths {
            dirs.push(search_path.join(&template_dropin));
        }
    }

    dirs
}

pub(super) fn collect_dropin_files(name: &str, search_paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut selected: BTreeMap<String, PathBuf> = BTreeMap::new();
    let dirs = collect_dropin_directories(name, search_paths);

    for dir in dirs {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if !file_name.ends_with(".conf") || file_name.starts_with('.') {
                continue;
            }

            selected
                .entry(file_name.to_string())
                .or_insert_with(|| path.clone());
        }
    }

    selected.into_values().collect()
}

#[derive(Debug, Clone)]
pub(super) struct UnitFragmentResolution {
    source_path: PathBuf,
    pub(super) fragment_path: PathBuf,
    logical_name: String,
    aliases: Vec<String>,
}

pub(super) fn resolve_unit_fragment(
    name: &str,
    search_paths: &[PathBuf],
) -> Option<UnitFragmentResolution> {
    let mut candidates = vec![(name.to_string(), false)];
    if let Some(template) = template_unit_name(name) {
        candidates.push((template, true));
    }

    for (candidate, from_template) in candidates {
        for search_path in search_paths {
            let source_path = search_path.join(&candidate);
            if !source_path.exists() {
                continue;
            }

            let fragment_path = source_path
                .canonicalize()
                .unwrap_or_else(|_| source_path.clone());
            let canonical_name = fragment_path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.to_string())?;
            let logical_name = if from_template {
                name.to_string()
            } else {
                canonical_name
            };
            let aliases = if logical_name != name {
                vec![name.to_string()]
            } else {
                Vec::new()
            };

            return Some(UnitFragmentResolution {
                source_path,
                fragment_path,
                logical_name,
                aliases,
            });
        }
    }

    None
}

#[derive(Debug, Clone)]
pub(super) struct LoadedUnitFile {
    pub(super) info: UnitFileInfo,
    pub(super) aliases: Vec<String>,
}

pub(super) fn load_unit_file_with_dropins(
    name: &str,
    search_paths: &[PathBuf],
) -> Result<Option<LoadedUnitFile>, UnitFileParseError> {
    let Some(resolved) = resolve_unit_fragment(name, search_paths) else {
        return Ok(None);
    };
    let content = match fs::read_to_string(&resolved.fragment_path) {
        Ok(content) => content,
        Err(_) => return Ok(None),
    };
    let mut info = UnitFileInfo::new(&resolved.logical_name, resolved.fragment_path.clone());
    parse_unit_content_into(&mut info, &content)?;
    if info.source_path.is_none() && resolved.source_path != resolved.fragment_path {
        info.source_path = Some(resolved.source_path.display().to_string());
    }

    for dropin in collect_dropin_files(name, search_paths) {
        let Ok(content) = fs::read_to_string(&dropin) else {
            continue;
        };
        parse_unit_content_into(&mut info, &content)?;
    }

    Ok(Some(LoadedUnitFile {
        info,
        aliases: resolved.aliases,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnitConditionEvaluation {
    Passed,
    ConditionFailed,
    AssertFailed,
}

pub(super) fn collect_effective_environment() -> Vec<String> {
    env::vars_os()
        .map(|(key, value)| format!("{}={}", key.to_string_lossy(), value.to_string_lossy()))
        .collect()
}

pub(super) fn evaluate_shared_condition_list(
    conditions: &[UnitConditionExpression],
    condition_type: SharedConditionType,
    environment: &[String],
) -> bool {
    if conditions.is_empty() {
        return true;
    }

    let mut list: Vec<SharedCondition> = conditions
        .iter()
        .map(|condition| {
            SharedCondition::new(
                condition_type,
                condition.value.clone(),
                condition.trigger,
                condition.invert,
            )
        })
        .collect();

    shared_condition_test_list(&mut list, environment).unwrap_or(false)
}

#[cfg(target_os = "linux")]
pub(super) fn network_namespace_matches(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }

    let target = if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        Path::new("/run/netns").join(value)
    };

    let current = match fs::metadata("/proc/self/ns/net") {
        Ok(meta) => meta,
        Err(_) => return false,
    };
    let candidate = match fs::metadata(target) {
        Ok(meta) => meta,
        Err(_) => return false,
    };

    current.dev() == candidate.dev() && current.ino() == candidate.ino()
}

#[cfg(not(target_os = "linux"))]
pub(super) fn network_namespace_matches(_value: &str) -> bool {
    false
}

pub(super) fn evaluate_network_namespace_list(conditions: &[UnitConditionExpression]) -> bool {
    let mut triggered: Option<bool> = None;

    for condition in conditions {
        let mut result = network_namespace_matches(&condition.value);
        if condition.invert {
            result = !result;
        }

        if condition.trigger {
            if !triggered.unwrap_or(false) {
                triggered = Some(result);
            }
        } else if !result {
            return false;
        }
    }

    triggered.unwrap_or(true)
}

pub(super) fn condition_config_satisfied(
    config: &UnitConditionConfig,
    environment: &[String],
) -> bool {
    evaluate_shared_condition_list(
        &config.path_exists,
        SharedConditionType::PathExists,
        environment,
    ) && evaluate_shared_condition_list(
        &config.path_exists_glob,
        SharedConditionType::PathExistsGlob,
        environment,
    ) && evaluate_shared_condition_list(
        &config.path_is_directory,
        SharedConditionType::PathIsDirectory,
        environment,
    ) && evaluate_shared_condition_list(
        &config.path_is_symbolic_link,
        SharedConditionType::PathIsSymbolicLink,
        environment,
    ) && evaluate_shared_condition_list(
        &config.path_is_mount_point,
        SharedConditionType::PathIsMountPoint,
        environment,
    ) && evaluate_shared_condition_list(
        &config.path_is_read_write,
        SharedConditionType::PathIsReadWrite,
        environment,
    ) && evaluate_shared_condition_list(
        &config.path_is_encrypted,
        SharedConditionType::PathIsEncrypted,
        environment,
    ) && evaluate_shared_condition_list(
        &config.path_is_socket,
        SharedConditionType::PathIsSocket,
        environment,
    ) && evaluate_shared_condition_list(
        &config.directory_not_empty,
        SharedConditionType::DirectoryNotEmpty,
        environment,
    ) && evaluate_shared_condition_list(
        &config.file_not_empty,
        SharedConditionType::FileNotEmpty,
        environment,
    ) && evaluate_shared_condition_list(
        &config.file_is_executable,
        SharedConditionType::FileIsExecutable,
        environment,
    ) && evaluate_shared_condition_list(
        &config.needs_update,
        SharedConditionType::NeedsUpdate,
        environment,
    ) && evaluate_shared_condition_list(
        &config.first_boot,
        SharedConditionType::FirstBoot,
        environment,
    ) && evaluate_shared_condition_list(
        &config.architecture,
        SharedConditionType::Architecture,
        environment,
    ) && evaluate_shared_condition_list(
        &config.firmware,
        SharedConditionType::Firmware,
        environment,
    ) && evaluate_shared_condition_list(
        &config.virtualization,
        SharedConditionType::Virtualization,
        environment,
    ) && evaluate_shared_condition_list(&config.host, SharedConditionType::Host, environment)
        && evaluate_shared_condition_list(
            &config.kernel_command_line,
            SharedConditionType::KernelCommandLine,
            environment,
        )
        && evaluate_shared_condition_list(
            &config.kernel_version,
            SharedConditionType::Version,
            environment,
        )
        && evaluate_shared_condition_list(
            &config.version,
            SharedConditionType::Version,
            environment,
        )
        && evaluate_shared_condition_list(
            &config.credential,
            SharedConditionType::Credential,
            environment,
        )
        && evaluate_shared_condition_list(
            &config.security,
            SharedConditionType::Security,
            environment,
        )
        && evaluate_shared_condition_list(
            &config.capability,
            SharedConditionType::Capability,
            environment,
        )
        && evaluate_shared_condition_list(
            &config.ac_power,
            SharedConditionType::AcPower,
            environment,
        )
        && evaluate_shared_condition_list(&config.memory, SharedConditionType::Memory, environment)
        && evaluate_shared_condition_list(
            &config.cpu_feature,
            SharedConditionType::CpuFeature,
            environment,
        )
        && evaluate_shared_condition_list(&config.cpus, SharedConditionType::Cpus, environment)
        && evaluate_shared_condition_list(
            &config.environment,
            SharedConditionType::Environment,
            environment,
        )
        && evaluate_shared_condition_list(&config.user, SharedConditionType::User, environment)
        && evaluate_shared_condition_list(&config.group, SharedConditionType::Group, environment)
        && evaluate_shared_condition_list(
            &config.control_group_controller,
            SharedConditionType::ControlGroupController,
            environment,
        )
        && evaluate_shared_condition_list(
            &config.os_release,
            SharedConditionType::OsRelease,
            environment,
        )
        && evaluate_shared_condition_list(
            &config.memory_pressure,
            SharedConditionType::MemoryPressure,
            environment,
        )
        && evaluate_shared_condition_list(
            &config.cpu_pressure,
            SharedConditionType::CpuPressure,
            environment,
        )
        && evaluate_shared_condition_list(
            &config.io_pressure,
            SharedConditionType::IoPressure,
            environment,
        )
        && evaluate_shared_condition_list(
            &config.kernel_module_loaded,
            SharedConditionType::KernelModuleLoaded,
            environment,
        )
        && evaluate_network_namespace_list(&config.network_namespace)
}

pub(super) fn unit_condition_evaluation(info: &UnitFileInfo) -> UnitConditionEvaluation {
    let environment = collect_effective_environment();

    if !condition_config_satisfied(&info.conditions, &environment) {
        return UnitConditionEvaluation::ConditionFailed;
    }
    if !condition_config_satisfied(&info.asserts, &environment) {
        return UnitConditionEvaluation::AssertFailed;
    }

    UnitConditionEvaluation::Passed
}

pub(super) fn unit_conditions_satisfied(info: &UnitFileInfo) -> bool {
    matches!(
        unit_condition_evaluation(info),
        UnitConditionEvaluation::Passed
    )
}
