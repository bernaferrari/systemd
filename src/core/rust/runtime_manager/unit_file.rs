// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Own the parsed unit-file data model and its in-memory decoding/application. This module may
 * update a Unit from decoded configuration, but must not spawn processes or mutate cgroupfs.
 */
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use super::unit_specifier::{
    default_instance_is_valid, expand_instance_specifiers, expand_instance_specifiers_token_wise,
    is_instance_unit_name, is_template_unit_name,
};
use crate::service::{NotifyAccess, ServiceType};
use crate::unit::{KillContext, OomPolicy, Unit, UnitType, oom_policy_from_string};
use systemd_shared_rs::unit_file::{UnitFile, UnitFileParseError};

const VALID_SUFFIXES: &[&str] = &[
    ".service",
    ".target",
    ".mount",
    ".socket",
    ".timer",
    ".path",
    ".swap",
    ".automount",
    ".slice",
    ".scope",
];

/// The parser-side classification of an assignment that was not applied as a
/// normal typed unit setting. This is intentionally informational: loading
/// keeps C's forward-compatible warn-and-continue policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitFileDiagnosticClass {
    UnknownSection,
    UnknownLvalue,
    InvalidValue,
    InvalidSpecifier,
}

/// Whether parsing changed the decoded value for one assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitFileAssignmentDisposition {
    Applied,
    IgnoredPreservingPriorValue,
    Fatal,
}

/// A retained counterpart to the syntax diagnostics emitted by C's parser.
///
/// These records do not decide whether a unit may later be activated. That is
/// a manager admission policy, not a parser compatibility decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitFileDiagnostic {
    pub class: UnitFileDiagnosticClass,
    pub disposition: UnitFileAssignmentDisposition,
    pub section: String,
    pub key: Option<String>,
    pub line: usize,
    pub unit_type: UnitType,
    pub warning: bool,
}

#[cfg(target_os = "linux")]
pub(super) const UNIT_SEARCH_PATHS: &[&str] = &[
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/generator.late",
];

#[cfg(not(target_os = "linux"))]
pub(super) const UNIT_SEARCH_PATHS: &[&str] = &["/tmp/test-systemd-units"];

#[derive(Debug, Clone)]
pub struct UnitFileInfo {
    pub name: String,
    pub path: PathBuf,
    pub unit_type: UnitType,
    pub description: Option<String>,
    pub documentation: Vec<String>,
    pub source_path: Option<String>,
    pub wants: Vec<String>,
    pub requires: Vec<String>,
    pub requisite: Vec<String>,
    pub binds_to: Vec<String>,
    pub upholds: Vec<String>,
    pub part_of: Vec<String>,
    pub after: Vec<String>,
    pub before: Vec<String>,
    pub conflicts: Vec<String>,
    pub on_success: Vec<String>,
    pub on_failure: Vec<String>,
    pub propagates_reload_to: Vec<String>,
    pub reload_propagated_from: Vec<String>,
    pub ignore_on_isolate: bool,
    pub stop_when_unneeded: bool,
    pub refuse_manual_start: bool,
    pub refuse_manual_stop: bool,
    pub allow_isolate: bool,
    pub conditions: UnitConditionConfig,
    pub asserts: UnitConditionConfig,
    pub exec_start: Option<String>,
    pub exec_stop: Option<String>,
    pub exec_reload: Option<String>,
    pub service: ServiceConfig,
    pub service_override: Option<String>,
    pub service_type: Option<ServiceType>,
    pub default_dependencies: bool,
    pub listen_stream: Vec<String>,
    pub listen_datagram: Vec<String>,
    pub socket: SocketConfig,
    pub timer: TimerConfig,
    pub path_config: PathConfig,
    pub mount: MountConfig,
    pub swap: SwapConfig,
    pub automount: AutomountConfig,
    pub exec_context: ExecContextConfig,
    pub kill: KillConfig,
    pub cgroup: CgroupConfig,
    pub slice: SliceConfig,
    pub scope: ScopeConfig,
    pub install: InstallConfig,
    pub diagnostics: Vec<UnitFileDiagnostic>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitConditionExpression {
    pub trigger: bool,
    pub invert: bool,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitConditionConfig {
    pub path_exists: Vec<UnitConditionExpression>,
    pub path_exists_glob: Vec<UnitConditionExpression>,
    pub path_is_directory: Vec<UnitConditionExpression>,
    pub path_is_symbolic_link: Vec<UnitConditionExpression>,
    pub path_is_mount_point: Vec<UnitConditionExpression>,
    pub path_is_read_write: Vec<UnitConditionExpression>,
    pub path_is_encrypted: Vec<UnitConditionExpression>,
    pub path_is_socket: Vec<UnitConditionExpression>,
    pub directory_not_empty: Vec<UnitConditionExpression>,
    pub file_not_empty: Vec<UnitConditionExpression>,
    pub file_is_executable: Vec<UnitConditionExpression>,
    pub needs_update: Vec<UnitConditionExpression>,
    pub first_boot: Vec<UnitConditionExpression>,
    pub architecture: Vec<UnitConditionExpression>,
    pub firmware: Vec<UnitConditionExpression>,
    pub virtualization: Vec<UnitConditionExpression>,
    pub host: Vec<UnitConditionExpression>,
    pub kernel_command_line: Vec<UnitConditionExpression>,
    pub kernel_version: Vec<UnitConditionExpression>,
    pub version: Vec<UnitConditionExpression>,
    pub credential: Vec<UnitConditionExpression>,
    pub security: Vec<UnitConditionExpression>,
    pub capability: Vec<UnitConditionExpression>,
    pub ac_power: Vec<UnitConditionExpression>,
    pub memory: Vec<UnitConditionExpression>,
    pub cpu_feature: Vec<UnitConditionExpression>,
    pub cpus: Vec<UnitConditionExpression>,
    pub environment: Vec<UnitConditionExpression>,
    pub user: Vec<UnitConditionExpression>,
    pub group: Vec<UnitConditionExpression>,
    pub control_group_controller: Vec<UnitConditionExpression>,
    pub os_release: Vec<UnitConditionExpression>,
    pub memory_pressure: Vec<UnitConditionExpression>,
    pub cpu_pressure: Vec<UnitConditionExpression>,
    pub io_pressure: Vec<UnitConditionExpression>,
    pub kernel_module_loaded: Vec<UnitConditionExpression>,
    pub network_namespace: Vec<UnitConditionExpression>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstallConfig {
    pub wanted_by: Vec<String>,
    pub required_by: Vec<String>,
    pub also: Vec<String>,
    pub aliases: Vec<String>,
    pub default_instance: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgroupConfig {
    pub slice: Option<String>,
    pub delegate: Option<bool>,
    pub delegate_controllers: Vec<String>,
    pub delegate_subgroup: Option<String>,
    pub cpu_accounting: Option<bool>,
    pub cpu_weight: Option<u64>,
    pub cpu_quota: Option<String>,
    /// `CPUQuotaPeriodSec=` normalized to microseconds with the same duration
    /// grammar as the C parser.
    pub cpu_quota_period_usec: Option<u64>,
    pub allowed_cpus: Option<String>,
    pub io_accounting: Option<bool>,
    pub io_weight: Option<u64>,
    pub io_device_weight: Vec<String>,
    pub io_limits: Vec<CgroupIoLimitConfig>,
    pub memory_accounting: Option<bool>,
    pub memory_min: Option<String>,
    pub memory_low: Option<String>,
    pub memory_high: Option<String>,
    pub memory_max: Option<String>,
    pub memory_swap_max: Option<String>,
    pub memory_zswap_max: Option<String>,
    pub tasks_accounting: Option<bool>,
    pub ip_accounting: Option<bool>,
    pub tasks_max: Option<u64>,
    pub ip_address_allow: Vec<String>,
    pub ip_address_deny: Vec<String>,
    pub bpf_program: Vec<String>,
    pub socket_bind_allow: Vec<String>,
    pub socket_bind_deny: Vec<String>,
    pub restrict_network_interfaces: Vec<String>,
    pub nft_set: Vec<String>,
    pub coredump_filter: Option<String>,
    pub managed_oom_memory_pressure: Option<String>,
    pub managed_oom_memory_pressure_limit: Option<String>,
    pub managed_oom_preference: Option<String>,
    pub managed_oom_swap: Option<String>,
    pub memory_pressure_watch: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupIoLimitKind {
    ReadBandwidth,
    WriteBandwidth,
    ReadIops,
    WriteIops,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupIoLimitConfig {
    pub kind: CgroupIoLimitKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillMode {
    ControlGroup,
    Process,
    Mixed,
    None,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KillConfig {
    pub kill_mode: Option<KillMode>,
    pub kill_signal: Option<i32>,
    pub restart_kill_signal: Option<i32>,
    pub final_kill_signal: Option<i32>,
    pub send_sighup: Option<bool>,
    pub send_sigkill: Option<bool>,
    pub watchdog_signal: Option<i32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SliceConfig {
    pub cgroup: CgroupConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeConfig {
    pub runtime_max_sec: Option<u64>,
    pub runtime_randomized_extra_sec: Option<u64>,
    pub timeout_stop_sec: Option<u64>,
    pub oom_policy: Option<OomPolicy>,
    pub kill_signal: Option<i32>,
    pub final_kill_signal: Option<i32>,
    pub cgroup: CgroupConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceRestartPolicy {
    No,
    OnSuccess,
    OnFailure,
    OnAbnormal,
    OnWatchdog,
    OnAbort,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceTimeoutFailureMode {
    Terminate,
    Abort,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileDescriptorStorePreserve {
    No,
    Yes,
    Restart,
    OnSuccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecCommandSpec {
    pub prefixes: String,
    pub command: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceConfig {
    pub exec_start: Vec<ExecCommandSpec>,
    pub exec_start_pre: Vec<ExecCommandSpec>,
    pub exec_start_post: Vec<ExecCommandSpec>,
    pub exec_stop: Vec<ExecCommandSpec>,
    pub exec_stop_post: Vec<ExecCommandSpec>,
    pub exec_reload: Vec<ExecCommandSpec>,
    pub exec_reload_post: Vec<ExecCommandSpec>,
    pub exec_condition: Vec<ExecCommandSpec>,
    pub restart: Option<ServiceRestartPolicy>,
    pub restart_sec: Option<u64>,
    pub restart_steps: Option<u32>,
    pub restart_max_delay_sec: Option<u64>,
    pub timeout_start_sec: Option<u64>,
    pub timeout_stop_sec: Option<u64>,
    pub timeout_abort_sec: Option<u64>,
    pub timeout_start_failure_mode: Option<ServiceTimeoutFailureMode>,
    pub timeout_stop_failure_mode: Option<ServiceTimeoutFailureMode>,
    pub runtime_max_sec: Option<u64>,
    pub watchdog_sec: Option<u64>,
    pub success_exit_status: Vec<String>,
    pub restart_prevent_exit_status: Vec<String>,
    pub restart_force_exit_status: Vec<String>,
    pub remain_after_exit: Option<bool>,
    pub guess_main_pid: Option<bool>,
    pub pid_file: Option<String>,
    pub bus_name: Option<String>,
    pub notify_access: Option<NotifyAccess>,
    pub sockets: Vec<String>,
    pub file_descriptor_store_max: Option<u64>,
    pub file_descriptor_store_preserve: Option<FileDescriptorStorePreserve>,
    pub oom_policy: Option<OomPolicy>,
    pub open_file: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketConfig {
    pub listen_stream: Vec<String>,
    pub listen_datagram: Vec<String>,
    pub listen_sequential_packet: Vec<String>,
    pub listen_fifo: Vec<String>,
    pub listen_special: Vec<String>,
    pub listen_netlink: Vec<String>,
    pub listen_message_queue: Vec<String>,
    pub listen_usb_function: Vec<String>,
    pub socket_mode: Option<u32>,
    pub directory_mode: Option<u32>,
    pub accept: Option<bool>,
    pub writable: Option<bool>,
    pub max_connections: Option<u64>,
    pub max_connections_per_source: Option<u64>,
    pub keep_alive: Option<bool>,
    pub keep_alive_time_sec: Option<u64>,
    pub keep_alive_interval_sec: Option<u64>,
    pub keep_alive_probes: Option<u32>,
    pub no_delay: Option<bool>,
    pub priority: Option<i32>,
    pub receive_buffer: Option<u64>,
    pub send_buffer: Option<u64>,
    pub ip_tos: Option<u32>,
    pub ip_ttl: Option<u32>,
    pub mark: Option<u32>,
    pub reuse_port: Option<bool>,
    pub smack_label: Option<String>,
    pub smack_label_ip_in: Option<String>,
    pub smack_label_ip_out: Option<String>,
    pub selinux_context_from_net: Option<bool>,
    pub pipe_size: Option<u64>,
    pub message_queue_max_messages: Option<u64>,
    pub message_queue_message_size: Option<u64>,
    pub free_bind: Option<bool>,
    pub transparent: Option<bool>,
    pub broadcast: Option<bool>,
    pub pass_credentials: Option<bool>,
    pub pass_security: Option<bool>,
    pub pass_packet_info: Option<bool>,
    pub socket_protocol: Option<String>,
    pub bind_to_device: Option<String>,
    pub service: Option<String>,
    pub remove_on_stop: Option<bool>,
    pub symlinks: Vec<String>,
    pub file_descriptor_name: Option<String>,
    pub trigger_limit_interval_sec: Option<u64>,
    pub trigger_limit_burst: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimerConfig {
    pub on_active_sec: Vec<u64>,
    pub on_boot_sec: Vec<u64>,
    pub on_startup_sec: Vec<u64>,
    pub on_unit_active_sec: Vec<u64>,
    pub on_unit_inactive_sec: Vec<u64>,
    pub on_calendar: Vec<String>,
    pub accuracy_sec: Option<u64>,
    pub randomized_delay_sec: Option<u64>,
    pub fixed_random_delay: Option<bool>,
    pub on_clock_change: Option<bool>,
    pub on_timezone_change: Option<bool>,
    pub unit: Option<String>,
    pub persistent: Option<bool>,
    pub wake_system: Option<bool>,
    pub remain_after_elapse: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathConfig {
    pub path_exists: Vec<String>,
    pub path_exists_glob: Vec<String>,
    pub path_changed: Vec<String>,
    pub path_modified: Vec<String>,
    pub directory_not_empty: Vec<String>,
    pub unit: Option<String>,
    pub make_directory: Option<bool>,
    pub directory_mode: Option<u32>,
    pub trigger_limit_interval_sec: Option<u64>,
    pub trigger_limit_burst: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountConfig {
    pub what: Option<String>,
    pub where_path: Option<String>,
    pub fstype: Option<String>,
    pub options: Option<String>,
    pub sloppy_options: Option<bool>,
    pub lazy_unmount: Option<bool>,
    pub force_unmount: Option<bool>,
    pub readwrite_only: Option<bool>,
    pub directory_mode: Option<u32>,
    pub timeout_sec: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SwapConfig {
    pub what: Option<String>,
    pub priority: Option<i32>,
    pub options: Option<String>,
    pub timeout_sec: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AutomountConfig {
    pub where_path: Option<String>,
    pub extra_options: Option<String>,
    pub directory_mode: Option<u32>,
    pub timeout_idle_sec: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecContextConfig {
    pub user: Option<String>,
    pub group: Option<String>,
    pub dynamic_user: Option<bool>,
    pub supplementary_groups: Vec<String>,
    pub pam_name: Option<String>,
    pub capability_bounding_set: Vec<String>,
    pub ambient_capabilities: Vec<String>,
    pub no_new_privileges: Option<bool>,
    pub secure_bits: Vec<String>,
    pub working_directory: Option<String>,
    pub root_directory: Option<String>,
    pub root_image: Option<String>,
    pub private_tmp: Option<bool>,
    pub private_devices: Option<bool>,
    pub private_network: Option<bool>,
    pub private_ipc: Option<bool>,
    pub private_users: Option<bool>,
    pub private_mounts: Option<bool>,
    pub protect_system: Option<String>,
    pub protect_home: Option<String>,
    pub protect_hostname: Option<bool>,
    pub protect_clock: Option<bool>,
    pub protect_kernel_tunables: Option<bool>,
    pub protect_kernel_modules: Option<bool>,
    pub protect_kernel_logs: Option<bool>,
    pub protect_control_groups: Option<bool>,
    pub restrict_address_families: Vec<String>,
    pub restrict_file_systems: Vec<String>,
    pub restrict_namespaces: Option<String>,
    pub lock_personality: Option<bool>,
    pub memory_deny_write_execute: Option<bool>,
    pub restrict_realtime: Option<bool>,
    pub restrict_suid_sgid: Option<bool>,
    pub system_call_filter: Vec<String>,
    pub system_call_error_number: Option<String>,
    pub system_call_architectures: Vec<String>,
    pub environment: Vec<String>,
    pub environment_file: Vec<String>,
    pub pass_environment: Vec<String>,
    pub unset_environment: Vec<String>,
    pub standard_input: Option<String>,
    pub standard_output: Option<String>,
    pub standard_error: Option<String>,
    pub tty_path: Option<String>,
    pub tty_reset: Option<bool>,
    pub tty_vhangup: Option<bool>,
    pub tty_vt_disallocate: Option<bool>,
    pub syslog_identifier: Option<String>,
    pub syslog_facility: Option<String>,
    pub syslog_level: Option<String>,
    pub nice: Option<i32>,
    pub cpu_scheduling_policy: Option<String>,
    pub cpu_affinity: Vec<String>,
    pub limits: BTreeMap<String, String>,
    pub umask: Option<String>,
    pub oom_score_adjust: Option<i32>,
    pub runtime_directory: Vec<String>,
    pub state_directory: Vec<String>,
    pub cache_directory: Vec<String>,
    pub logs_directory: Vec<String>,
    pub configuration_directory: Vec<String>,
    pub directory_mode: Option<u32>,
    pub runtime_directory_mode: Option<u32>,
    pub state_directory_mode: Option<u32>,
    pub cache_directory_mode: Option<u32>,
    pub logs_directory_mode: Option<u32>,
    pub configuration_directory_mode: Option<u32>,
    pub runtime_directory_preserve: Option<String>,
    pub read_write_paths: Vec<String>,
    pub read_only_paths: Vec<String>,
    pub inaccessible_paths: Vec<String>,
    pub selinux_context: Option<String>,
    pub app_armor_profile: Option<String>,
    pub seccomp_filter: Vec<String>,
    pub load_credential: Vec<String>,
    pub load_credential_encrypted: Vec<String>,
    pub set_credential: Vec<String>,
    pub set_credential_encrypted: Vec<String>,
    pub import_credential: Vec<String>,
}

impl UnitFileInfo {
    pub fn new(name: &str, path: PathBuf) -> Self {
        let unit_type = suffix_to_unit_type(name);
        Self {
            name: name.to_string(),
            path,
            unit_type,
            description: None,
            documentation: Vec::new(),
            source_path: None,
            wants: Vec::new(),
            requires: Vec::new(),
            requisite: Vec::new(),
            binds_to: Vec::new(),
            upholds: Vec::new(),
            part_of: Vec::new(),
            after: Vec::new(),
            before: Vec::new(),
            conflicts: Vec::new(),
            on_success: Vec::new(),
            on_failure: Vec::new(),
            propagates_reload_to: Vec::new(),
            reload_propagated_from: Vec::new(),
            ignore_on_isolate: false,
            stop_when_unneeded: false,
            refuse_manual_start: false,
            refuse_manual_stop: false,
            allow_isolate: false,
            conditions: UnitConditionConfig::default(),
            asserts: UnitConditionConfig::default(),
            exec_start: None,
            exec_stop: None,
            exec_reload: None,
            service: ServiceConfig::default(),
            service_override: None,
            service_type: None,
            default_dependencies: true,
            listen_stream: Vec::new(),
            listen_datagram: Vec::new(),
            socket: SocketConfig::default(),
            timer: TimerConfig::default(),
            path_config: PathConfig::default(),
            mount: MountConfig::default(),
            swap: SwapConfig::default(),
            automount: AutomountConfig::default(),
            exec_context: ExecContextConfig::default(),
            kill: KillConfig::default(),
            cgroup: CgroupConfig::default(),
            slice: SliceConfig::default(),
            scope: ScopeConfig::default(),
            install: InstallConfig::default(),
            diagnostics: Vec::new(),
        }
    }

    fn record_diagnostic(
        &mut self,
        class: UnitFileDiagnosticClass,
        disposition: UnitFileAssignmentDisposition,
        section: &str,
        key: Option<&str>,
        line: usize,
        warning: bool,
    ) {
        self.diagnostics.push(UnitFileDiagnostic {
            class,
            disposition,
            section: section.to_string(),
            key: key.map(str::to_string),
            line,
            unit_type: self.unit_type,
            warning,
        });
    }

    fn record_invalid_value(&mut self, section: &str, key: &str, line: usize) {
        self.record_diagnostic(
            UnitFileDiagnosticClass::InvalidValue,
            UnitFileAssignmentDisposition::IgnoredPreservingPriorValue,
            section,
            Some(key),
            line,
            true,
        );
    }
}

pub(super) fn suffix_to_unit_type(name: &str) -> UnitType {
    if name.ends_with(".service") {
        UnitType::Service
    } else if name.ends_with(".target") {
        UnitType::Target
    } else if name.ends_with(".mount") {
        UnitType::Mount
    } else if name.ends_with(".socket") {
        UnitType::Socket
    } else if name.ends_with(".timer") {
        UnitType::Timer
    } else if name.ends_with(".path") {
        UnitType::Path
    } else if name.ends_with(".swap") {
        UnitType::Swap
    } else if name.ends_with(".automount") {
        UnitType::Automount
    } else if name.ends_with(".slice") {
        UnitType::Slice
    } else if name.ends_with(".scope") {
        UnitType::Scope
    } else {
        UnitType::Service
    }
}

pub(super) fn parse_unit_file(path: &Path) -> Result<Option<UnitFileInfo>, UnitFileParseError> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(None);
    };
    let name = name.to_string();
    let valid = VALID_SUFFIXES.iter().any(|s| name.ends_with(s));
    if !valid {
        return Ok(None);
    }
    if name.starts_with('.') {
        return Ok(None);
    }

    let mut info = UnitFileInfo::new(&name, path.to_path_buf());
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => return Ok(None),
    };
    parse_unit_content_into(&mut info, &content)?;
    Ok(Some(info))
}

pub(super) fn parse_unit_content_into(
    info: &mut UnitFileInfo,
    content: &str,
) -> Result<(), UnitFileParseError> {
    /*
     * config_parse() treats unknown sections and lvalues as warnings and continues. Only the
     * syntax errors from the reader itself make a fragment unusable, so schema validation must
     * not turn a forward-compatible unit file into a load failure.
     */
    let parsed = UnitFile::parse_str(content)?;

    for section in &parsed.sections {
        let current_section = section.name.to_ascii_lowercase();
        if !known_section(current_section.as_str()) {
            let warning = !current_section.starts_with("x-");
            info.record_diagnostic(
                UnitFileDiagnosticClass::UnknownSection,
                UnitFileAssignmentDisposition::IgnoredPreservingPriorValue,
                current_section.as_str(),
                None,
                section.line_number,
                warning,
            );
            continue;
        }
        for directive in &section.directives {
            let key = directive.key.as_str();
            let value_expanded = match expand_instance_specifiers(
                &directive.value,
                &info.name,
                Some(info.path.as_path()),
            ) {
                Some(value) => value,
                None if directive_allows_tokenwise_specifier_fallback(
                    current_section.as_str(),
                    key,
                ) =>
                {
                    match expand_instance_specifiers_token_wise(
                        &directive.value,
                        &info.name,
                        Some(info.path.as_path()),
                    ) {
                        Some(value) => value,
                        None => {
                            info.record_diagnostic(
                                UnitFileDiagnosticClass::InvalidSpecifier,
                                UnitFileAssignmentDisposition::IgnoredPreservingPriorValue,
                                current_section.as_str(),
                                Some(key),
                                directive.line_number,
                                true,
                            );
                            continue;
                        }
                    }
                }
                None => {
                    info.record_diagnostic(
                        UnitFileDiagnosticClass::InvalidSpecifier,
                        UnitFileAssignmentDisposition::IgnoredPreservingPriorValue,
                        current_section.as_str(),
                        Some(key),
                        directive.line_number,
                        true,
                    );
                    continue;
                }
            };
            let value = value_expanded.as_str();

            if unit_boolean_directive(current_section.as_str(), key)
                && !value.is_empty()
                && parse_boolean(value).is_none()
            {
                info.record_diagnostic(
                    UnitFileDiagnosticClass::InvalidValue,
                    UnitFileAssignmentDisposition::IgnoredPreservingPriorValue,
                    current_section.as_str(),
                    Some(key),
                    directive.line_number,
                    true,
                );
                continue;
            }

            match (current_section.as_str(), key) {
                ("unit", "Description") => info.description = parse_optional_string(value),
                ("unit", "Documentation") => {
                    append_or_clear_list(&mut info.documentation, value);
                }
                ("unit", "SourcePath") => {
                    info.source_path = parse_optional_string(value);
                }
                ("unit", "Wants") => {
                    append_or_clear_list(&mut info.wants, value);
                }
                ("unit", "Requires") => {
                    append_or_clear_list(&mut info.requires, value);
                }
                ("unit", "Requisite") => {
                    append_or_clear_list(&mut info.requisite, value);
                }
                ("unit", "BindsTo" | "BindTo") => {
                    append_or_clear_list(&mut info.binds_to, value);
                }
                ("unit", "Upholds") => {
                    append_or_clear_list(&mut info.upholds, value);
                }
                ("unit", "PartOf") => {
                    append_or_clear_list(&mut info.part_of, value);
                }
                ("unit", "After") => {
                    append_or_clear_list(&mut info.after, value);
                }
                ("unit", "Before") => {
                    append_or_clear_list(&mut info.before, value);
                }
                ("unit", "Conflicts") => {
                    append_or_clear_list(&mut info.conflicts, value);
                }
                ("unit", "OnSuccess") => {
                    append_or_clear_list(&mut info.on_success, value);
                }
                ("unit", "OnFailure") => {
                    append_or_clear_list(&mut info.on_failure, value);
                }
                ("unit", "PropagatesReloadTo" | "PropagateReloadTo") => {
                    append_or_clear_list(&mut info.propagates_reload_to, value);
                }
                ("unit", "ReloadPropagatedFrom" | "PropagateReloadFrom") => {
                    append_or_clear_list(&mut info.reload_propagated_from, value);
                }
                ("unit", "DefaultDependencies") => info.default_dependencies = parse_bool(value),
                ("unit", "IgnoreOnIsolate") => info.ignore_on_isolate = parse_bool(value),
                ("unit", "StopWhenUnneeded") => info.stop_when_unneeded = parse_bool(value),
                ("unit", "RefuseManualStart") => info.refuse_manual_start = parse_bool(value),
                ("unit", "RefuseManualStop") => info.refuse_manual_stop = parse_bool(value),
                ("unit", "AllowIsolate") => info.allow_isolate = parse_bool(value),
                ("unit", key)
                    if parse_unit_condition_directive(&mut info.conditions, key, value) => {}
                ("unit", key) if parse_unit_assert_directive(&mut info.asserts, key, value) => {}
                ("service", "Type") => {
                    // config_parse_service_type() leaves its destination
                    // untouched when C rejects an empty or invalid enum.
                    if let Some(service_type) = parse_service_type(value) {
                        info.service_type = Some(service_type);
                    } else {
                        info.record_invalid_value(
                            current_section.as_str(),
                            key,
                            directive.line_number,
                        );
                    }
                }
                ("service", "ExecStart") => {
                    append_or_clear_exec_list(&mut info.service.exec_start, value);
                    info.exec_start = info.service.exec_start.last().map(|s| s.command.clone());
                }
                ("service", "ExecStartPre") => {
                    append_or_clear_exec_list(&mut info.service.exec_start_pre, value);
                }
                ("service", "ExecStartPost") => {
                    append_or_clear_exec_list(&mut info.service.exec_start_post, value);
                }
                ("service", "ExecStop") => {
                    append_or_clear_exec_list(&mut info.service.exec_stop, value);
                    info.exec_stop = info.service.exec_stop.last().map(|s| s.command.clone());
                }
                ("service", "ExecStopPost") => {
                    append_or_clear_exec_list(&mut info.service.exec_stop_post, value);
                }
                ("service", "ExecReload") => {
                    append_or_clear_exec_list(&mut info.service.exec_reload, value);
                    info.exec_reload = info.service.exec_reload.last().map(|s| s.command.clone());
                }
                ("service", "ExecReloadPost") => {
                    append_or_clear_exec_list(&mut info.service.exec_reload_post, value);
                }
                ("service", "ExecCondition") => {
                    append_or_clear_exec_list(&mut info.service.exec_condition, value);
                }
                ("service", "Restart") => {
                    // C's config_parse_service_restart() leaves the previous
                    // setting intact when the enum input is empty or invalid.
                    if let Some(restart) = parse_restart_policy(value) {
                        info.service.restart = Some(restart);
                    } else {
                        info.record_invalid_value(
                            current_section.as_str(),
                            key,
                            directive.line_number,
                        );
                    }
                }
                ("service", "RestartSec") => {
                    // C's config_parse_sec() retains the previous value when
                    // an assignment is empty or otherwise invalid.
                    if let Some(restart_sec) = parse_duration_seconds(value) {
                        info.service.restart_sec = Some(restart_sec);
                    }
                }
                ("service", "RestartSteps") => {
                    // config_parse_unsigned() has the same retain-on-failure
                    // semantics as config_parse_sec().
                    if let Some(restart_steps) = parse_optional_u32(value) {
                        info.service.restart_steps = Some(restart_steps);
                    }
                }
                ("service", "RestartMaxDelaySec") => {
                    if let Some(restart_max_delay_sec) = parse_duration_seconds(value) {
                        info.service.restart_max_delay_sec = Some(restart_max_delay_sec);
                    }
                }
                ("service", "TimeoutStartSec") => {
                    // C's config_parse_service_timeout() ignores invalid values
                    // and uses parse_sec_fix_0(), where zero disables the timeout.
                    if let Some(timeout) = parse_duration_seconds(value) {
                        info.service.timeout_start_sec = Some(timeout);
                    }
                }
                ("service", "TimeoutStopSec") => {
                    // C's config_parse_sec_fix_0() likewise leaves the prior
                    // setting alone on a parse failure.
                    if let Some(timeout) = parse_duration_seconds(value) {
                        info.service.timeout_stop_sec = Some(timeout);
                    }
                }
                ("service", "TimeoutAbortSec") => {
                    // config_parse_service_timeout_abort() clears the
                    // optional setting for an empty assignment, but retains
                    // the prior value when parse_sec() rejects a non-empty
                    // value. Keep the warning visible in the parser
                    // diagnostics just as C's log_syntax() does.
                    if value.is_empty() {
                        info.service.timeout_abort_sec = None;
                    } else if let Some(timeout) = parse_duration_seconds(value) {
                        info.service.timeout_abort_sec = Some(timeout);
                    } else {
                        info.record_invalid_value(
                            current_section.as_str(),
                            key,
                            directive.line_number,
                        );
                    }
                }
                ("service", "TimeoutStartFailureMode") => {
                    // C's config_parse_service_timeout_failure_mode() retains
                    // the preceding mode for empty or invalid input.
                    if let Some(mode) = parse_timeout_failure_mode(value) {
                        info.service.timeout_start_failure_mode = Some(mode);
                    } else {
                        info.record_invalid_value(
                            current_section.as_str(),
                            key,
                            directive.line_number,
                        );
                    }
                }
                ("service", "TimeoutStopFailureMode") => {
                    if let Some(mode) = parse_timeout_failure_mode(value) {
                        info.service.timeout_stop_failure_mode = Some(mode);
                    } else {
                        info.record_invalid_value(
                            current_section.as_str(),
                            key,
                            directive.line_number,
                        );
                    }
                }
                ("service", "TimeoutSec") => {
                    // config_parse_service_timeout() updates both values only
                    // after parse_sec_fix_0() has accepted the setting.
                    if let Some(timeout) = parse_duration_seconds(value) {
                        info.service.timeout_start_sec = Some(timeout);
                        info.service.timeout_stop_sec = Some(timeout);
                    }
                }
                ("service", "RuntimeMaxSec") => {
                    if let Some(runtime_max_sec) = parse_duration_seconds(value) {
                        info.service.runtime_max_sec = Some(runtime_max_sec);
                    }
                }
                ("service", "WatchdogSec") => {
                    if let Some(watchdog_sec) = parse_duration_seconds(value) {
                        info.service.watchdog_sec = Some(watchdog_sec);
                    }
                }
                ("service", "SuccessExitStatus") => {
                    append_or_clear_list(&mut info.service.success_exit_status, value);
                }
                ("service", "RestartPreventExitStatus") => {
                    append_or_clear_list(&mut info.service.restart_prevent_exit_status, value);
                }
                ("service", "RestartForceExitStatus") => {
                    append_or_clear_list(&mut info.service.restart_force_exit_status, value);
                }
                ("service", "RemainAfterExit") => {
                    info.service.remain_after_exit = parse_optional_bool(value);
                }
                ("service", "GuessMainPID") => {
                    info.service.guess_main_pid = parse_optional_bool(value);
                }
                ("service", "PIDFile") => {
                    info.service.pid_file = parse_optional_string(value);
                }
                ("service", "BusName") => {
                    info.service.bus_name = parse_optional_string(value);
                }
                ("service", "NotifyAccess") => {
                    if let Some(notify_access) = parse_notify_access(value) {
                        info.service.notify_access = Some(notify_access);
                    } else {
                        info.record_invalid_value(
                            current_section.as_str(),
                            key,
                            directive.line_number,
                        );
                    }
                }
                ("service", "Sockets") => {
                    append_or_clear_list(&mut info.service.sockets, value);
                }
                ("service", "FileDescriptorStoreMax") => {
                    info.service.file_descriptor_store_max = parse_optional_u64(value);
                }
                ("service", "FileDescriptorStorePreserve") => {
                    if let Some(preserve) = parse_fd_store_preserve(value) {
                        info.service.file_descriptor_store_preserve = Some(preserve);
                    } else {
                        info.record_invalid_value(
                            current_section.as_str(),
                            key,
                            directive.line_number,
                        );
                    }
                }
                ("service", "OOMPolicy") => {
                    // config_parse_oom_policy() is a C enum parser: empty
                    // and invalid assignments warn without clearing the prior
                    // configured policy.
                    if let Ok(oom_policy) = oom_policy_from_string(value) {
                        info.service.oom_policy = Some(oom_policy);
                    } else {
                        info.record_invalid_value(
                            current_section.as_str(),
                            key,
                            directive.line_number,
                        );
                    }
                }
                ("service", "OpenFile") => {
                    append_or_clear_list(&mut info.service.open_file, value);
                }
                ("socket", "ListenStream") => {
                    append_or_clear_list(&mut info.listen_stream, value);
                    append_or_clear_list(&mut info.socket.listen_stream, value);
                }
                ("socket", "ListenDatagram") => {
                    append_or_clear_list(&mut info.listen_datagram, value);
                    append_or_clear_list(&mut info.socket.listen_datagram, value);
                }
                ("socket", "ListenSequentialPacket") => {
                    append_or_clear_list(&mut info.socket.listen_sequential_packet, value);
                }
                ("socket", "ListenFIFO") => {
                    append_or_clear_list(&mut info.socket.listen_fifo, value);
                }
                ("socket", "ListenSpecial") => {
                    append_or_clear_list(&mut info.socket.listen_special, value);
                }
                ("socket", "ListenNetlink") => {
                    append_or_clear_list(&mut info.socket.listen_netlink, value);
                }
                ("socket", "ListenMessageQueue") => {
                    append_or_clear_list(&mut info.socket.listen_message_queue, value);
                }
                ("socket", "ListenUSBFunction") => {
                    append_or_clear_list(&mut info.socket.listen_usb_function, value);
                }
                ("socket", "SocketMode") => {
                    info.socket.socket_mode = parse_optional_mode(value);
                }
                ("socket", "DirectoryMode") => {
                    info.socket.directory_mode = parse_optional_mode(value);
                }
                ("socket", "Accept") => {
                    info.socket.accept = parse_optional_bool(value);
                }
                ("socket", "Writable") => {
                    info.socket.writable = parse_optional_bool(value);
                }
                ("socket", "MaxConnections") => {
                    info.socket.max_connections = parse_optional_u64(value);
                }
                ("socket", "MaxConnectionsPerSource") => {
                    info.socket.max_connections_per_source = parse_optional_u64(value);
                }
                ("socket", "KeepAlive") => {
                    info.socket.keep_alive = parse_optional_bool(value);
                }
                ("socket", "KeepAliveTimeSec") => {
                    info.socket.keep_alive_time_sec = parse_duration_seconds(value);
                }
                ("socket", "KeepAliveIntervalSec") => {
                    info.socket.keep_alive_interval_sec = parse_duration_seconds(value);
                }
                ("socket", "KeepAliveProbes") => {
                    info.socket.keep_alive_probes = parse_optional_u32(value);
                }
                ("socket", "NoDelay") => {
                    info.socket.no_delay = parse_optional_bool(value);
                }
                ("socket", "Priority") => {
                    info.socket.priority = parse_optional_i32(value);
                }
                ("socket", "ReceiveBuffer") => {
                    info.socket.receive_buffer = parse_optional_u64(value);
                }
                ("socket", "SendBuffer") => {
                    info.socket.send_buffer = parse_optional_u64(value);
                }
                ("socket", "IPTOS") => {
                    info.socket.ip_tos = parse_optional_u32(value);
                }
                ("socket", "IPTTL") => {
                    info.socket.ip_ttl = parse_optional_u32(value);
                }
                ("socket", "Mark") => {
                    info.socket.mark = parse_optional_u32(value);
                }
                ("socket", "ReusePort") => {
                    info.socket.reuse_port = parse_optional_bool(value);
                }
                ("socket", "SmackLabel") => {
                    info.socket.smack_label = parse_optional_string(value);
                }
                ("socket", "SmackLabelIPIn") => {
                    info.socket.smack_label_ip_in = parse_optional_string(value);
                }
                ("socket", "SmackLabelIPOut") => {
                    info.socket.smack_label_ip_out = parse_optional_string(value);
                }
                ("socket", "SELinuxContextFromNet") => {
                    info.socket.selinux_context_from_net = parse_optional_bool(value);
                }
                ("socket", "PipeSize") => {
                    info.socket.pipe_size = parse_optional_u64(value);
                }
                ("socket", "MessageQueueMaxMessages") => {
                    info.socket.message_queue_max_messages = parse_optional_u64(value);
                }
                ("socket", "MessageQueueMessageSize") => {
                    info.socket.message_queue_message_size = parse_optional_u64(value);
                }
                ("socket", "FreeBind") => {
                    info.socket.free_bind = parse_optional_bool(value);
                }
                ("socket", "Transparent") => {
                    info.socket.transparent = parse_optional_bool(value);
                }
                ("socket", "Broadcast") => {
                    info.socket.broadcast = parse_optional_bool(value);
                }
                ("socket", "PassCredentials") => {
                    info.socket.pass_credentials = parse_optional_bool(value);
                }
                ("socket", "PassSecurity") => {
                    info.socket.pass_security = parse_optional_bool(value);
                }
                ("socket", "PassPacketInfo") => {
                    info.socket.pass_packet_info = parse_optional_bool(value);
                }
                ("socket", "SocketProtocol") => {
                    info.socket.socket_protocol = parse_optional_string(value);
                }
                ("socket", "BindToDevice") => {
                    info.socket.bind_to_device = parse_optional_string(value);
                }
                ("socket", "Service") => {
                    // C's config_parse_socket_service() accepts only service units.  Keeping an
                    // arbitrary unit name here used to let the bounded activation layer bind a
                    // listener and later attempt to start, for example, a target. Treat an
                    // invalid value exactly like C's ignored directive: crucially, leave an
                    // earlier valid Service= directive intact rather than resetting it.
                    if let Some(service) =
                        parse_optional_string(value).filter(|service| service.ends_with(".service"))
                    {
                        info.service_override = Some(service.clone());
                        info.socket.service = Some(service);
                    }
                }
                ("socket", "RemoveOnStop") => {
                    info.socket.remove_on_stop = parse_optional_bool(value);
                }
                ("socket", "Symlinks") => {
                    append_or_clear_list(&mut info.socket.symlinks, value);
                }
                ("socket", "FileDescriptorName") => {
                    info.socket.file_descriptor_name = parse_optional_string(value);
                }
                ("socket", "TriggerLimitIntervalSec") => {
                    info.socket.trigger_limit_interval_sec = parse_duration_seconds(value);
                }
                ("socket", "TriggerLimitBurst") => {
                    info.socket.trigger_limit_burst = parse_optional_u32(value);
                }
                ("timer", "OnActiveSec") => {
                    append_or_clear_duration_list(&mut info.timer.on_active_sec, value);
                }
                ("timer", "OnBootSec") => {
                    append_or_clear_duration_list(&mut info.timer.on_boot_sec, value);
                }
                ("timer", "OnStartupSec") => {
                    append_or_clear_duration_list(&mut info.timer.on_startup_sec, value);
                }
                ("timer", "OnUnitActiveSec") => {
                    append_or_clear_duration_list(&mut info.timer.on_unit_active_sec, value);
                }
                ("timer", "OnUnitInactiveSec") => {
                    append_or_clear_duration_list(&mut info.timer.on_unit_inactive_sec, value);
                }
                ("timer", "OnCalendar") => {
                    append_or_clear_value_list(&mut info.timer.on_calendar, value);
                }
                ("timer", "AccuracySec") => {
                    info.timer.accuracy_sec = parse_duration_seconds(value);
                }
                ("timer", "RandomizedDelaySec") => {
                    info.timer.randomized_delay_sec = parse_duration_seconds(value);
                }
                ("timer", "FixedRandomDelay") => {
                    info.timer.fixed_random_delay = parse_optional_bool(value);
                }
                ("timer", "OnClockChange") => {
                    info.timer.on_clock_change = parse_optional_bool(value);
                }
                ("timer", "OnTimezoneChange") => {
                    info.timer.on_timezone_change = parse_optional_bool(value);
                }
                ("timer", "Unit") => {
                    info.timer.unit = parse_optional_string(value);
                }
                ("timer", "Persistent") => {
                    info.timer.persistent = parse_optional_bool(value);
                }
                ("timer", "WakeSystem") => {
                    info.timer.wake_system = parse_optional_bool(value);
                }
                ("timer", "RemainAfterElapse") => {
                    info.timer.remain_after_elapse = parse_optional_bool(value);
                }
                ("path", "PathExists") => {
                    append_or_clear_value_list(&mut info.path_config.path_exists, value);
                }
                ("path", "PathExistsGlob") => {
                    append_or_clear_value_list(&mut info.path_config.path_exists_glob, value);
                }
                ("path", "PathChanged") => {
                    append_or_clear_value_list(&mut info.path_config.path_changed, value);
                }
                ("path", "PathModified") => {
                    append_or_clear_value_list(&mut info.path_config.path_modified, value);
                }
                ("path", "DirectoryNotEmpty") => {
                    append_or_clear_value_list(&mut info.path_config.directory_not_empty, value);
                }
                ("path", "Unit") => {
                    info.path_config.unit = parse_optional_string(value);
                }
                ("path", "MakeDirectory") => {
                    info.path_config.make_directory = parse_optional_bool(value);
                }
                ("path", "DirectoryMode") => {
                    info.path_config.directory_mode = parse_optional_mode(value);
                }
                ("path", "TriggerLimitIntervalSec") => {
                    info.path_config.trigger_limit_interval_sec = parse_duration_seconds(value);
                }
                ("path", "TriggerLimitBurst") => {
                    info.path_config.trigger_limit_burst = parse_optional_u32(value);
                }
                ("mount", "What") => {
                    info.mount.what = parse_optional_string(value);
                }
                ("mount", "Where") => {
                    info.mount.where_path = parse_optional_string(value);
                }
                ("mount", "Type") => {
                    info.mount.fstype = parse_optional_string(value);
                }
                ("mount", "Options") => {
                    info.mount.options = parse_optional_string(value);
                }
                ("mount", "SloppyOptions") => {
                    info.mount.sloppy_options = parse_optional_bool(value);
                }
                ("mount", "LazyUnmount") => {
                    info.mount.lazy_unmount = parse_optional_bool(value);
                }
                ("mount", "ForceUnmount") => {
                    info.mount.force_unmount = parse_optional_bool(value);
                }
                ("mount", "ReadwriteOnly") => {
                    info.mount.readwrite_only = parse_optional_bool(value);
                }
                ("mount", "DirectoryMode") => {
                    info.mount.directory_mode = parse_optional_mode(value);
                }
                ("mount", "TimeoutSec") => {
                    info.mount.timeout_sec = parse_duration_seconds(value);
                }
                ("swap", "What") => {
                    info.swap.what = parse_optional_string(value);
                }
                ("swap", "Priority") => {
                    info.swap.priority = parse_optional_i32(value);
                }
                ("swap", "Options") => {
                    info.swap.options = parse_optional_string(value);
                }
                ("swap", "TimeoutSec") => {
                    info.swap.timeout_sec = parse_duration_seconds(value);
                }
                ("automount", "Where") => {
                    info.automount.where_path = parse_optional_string(value);
                }
                ("automount", "ExtraOptions") => {
                    info.automount.extra_options = parse_optional_string(value);
                }
                ("automount", "DirectoryMode") => {
                    info.automount.directory_mode = parse_optional_mode(value);
                }
                ("automount", "TimeoutIdleSec") => {
                    info.automount.timeout_idle_sec = parse_duration_seconds(value);
                }
                (section, "KillMode")
                    if matches!(section, "service" | "socket" | "mount" | "swap" | "scope") =>
                {
                    // config_parse_kill_mode() resets an empty assignment to
                    // control-group, but warns and preserves the prior value
                    // for a nonempty invalid enum spelling.
                    if let Some(kill_mode) = parse_kill_mode(value) {
                        info.kill.kill_mode = Some(kill_mode);
                    } else {
                        info.record_invalid_value(
                            current_section.as_str(),
                            key,
                            directive.line_number,
                        );
                    }
                }
                (section, key)
                    if matches!(section, "service" | "socket" | "mount" | "swap" | "scope")
                        && !(section == "scope"
                            && matches!(key, "KillSignal" | "FinalKillSignal"))
                        && parse_kill_context_directive(&mut info.kill, key, value) => {}
                (section, key)
                    if matches!(section, "service" | "socket" | "mount" | "swap")
                        && parse_cgroup_context_directive(&mut info.cgroup, key, value) => {}
                (section, key)
                    if matches!(section, "service" | "socket" | "mount" | "swap")
                        && parse_exec_context_directive(&mut info.exec_context, key, value) => {}
                ("slice", key) => {
                    parse_cgroup_key(&mut info.slice.cgroup, key, value);
                }
                ("scope", "RuntimeMaxSec") => {
                    info.scope.runtime_max_sec = parse_duration_seconds(value);
                }
                ("scope", "RuntimeRandomizedExtraSec") => {
                    info.scope.runtime_randomized_extra_sec = parse_duration_seconds(value);
                }
                ("scope", "TimeoutStopSec") => {
                    info.scope.timeout_stop_sec = parse_duration_seconds(value);
                }
                ("scope", "OOMPolicy") => {
                    // config_parse_oom_policy() retains the prior value on
                    // empty or invalid assignments while recording a warning.
                    if let Ok(oom_policy) = oom_policy_from_string(value) {
                        info.scope.oom_policy = Some(oom_policy);
                    } else {
                        info.record_invalid_value(
                            current_section.as_str(),
                            key,
                            directive.line_number,
                        );
                    }
                }
                ("scope", "KillSignal") => {
                    info.scope.kill_signal = parse_optional_i32(value);
                }
                ("scope", "FinalKillSignal") => {
                    info.scope.final_kill_signal = parse_optional_i32(value);
                }
                ("scope", key) => {
                    parse_cgroup_key(&mut info.scope.cgroup, key, value);
                }
                ("install", "WantedBy") => {
                    append_or_clear_list(&mut info.install.wanted_by, value);
                }
                ("install", "RequiredBy") => {
                    append_or_clear_list(&mut info.install.required_by, value);
                }
                ("install", "Also") => {
                    append_or_clear_list(&mut info.install.also, value);
                }
                ("install", "Alias") => {
                    append_or_clear_list(&mut info.install.aliases, value);
                }
                ("install", "DefaultInstance") => {
                    if value.is_empty() {
                        info.install.default_instance = None;
                    } else if is_template_unit_name(&info.name)
                        && !is_instance_unit_name(&info.name)
                        && default_instance_is_valid(value)
                    {
                        info.install.default_instance = Some(value.to_string());
                    }
                }
                _ => {
                    info.record_diagnostic(
                        UnitFileDiagnosticClass::UnknownLvalue,
                        UnitFileAssignmentDisposition::IgnoredPreservingPriorValue,
                        current_section.as_str(),
                        Some(key),
                        directive.line_number,
                        !key.starts_with("X-"),
                    );
                }
            }
        }
    }

    Ok(())
}

fn known_section(section: &str) -> bool {
    matches!(
        section,
        "unit"
            | "service"
            | "socket"
            | "timer"
            | "path"
            | "mount"
            | "swap"
            | "automount"
            | "slice"
            | "scope"
            | "install"
    )
}

fn unit_boolean_directive(section: &str, key: &str) -> bool {
    matches!(
        (section, key),
        ("unit", "DefaultDependencies")
            | ("unit", "IgnoreOnIsolate")
            | ("unit", "StopWhenUnneeded")
            | ("unit", "RefuseManualStart")
            | ("unit", "RefuseManualStop")
            | ("unit", "AllowIsolate")
    )
}

pub(super) fn directive_allows_tokenwise_specifier_fallback(section: &str, key: &str) -> bool {
    matches!(
        (section, key),
        ("unit", "Wants")
            | ("unit", "Requires")
            | ("unit", "Requisite")
            | ("unit", "BindsTo")
            | ("unit", "BindTo")
            | ("unit", "Upholds")
            | ("unit", "PartOf")
            | ("unit", "After")
            | ("unit", "Before")
            | ("unit", "Conflicts")
            | ("unit", "OnSuccess")
            | ("unit", "OnFailure")
            | ("unit", "PropagatesReloadTo")
            | ("unit", "PropagateReloadTo")
            | ("unit", "ReloadPropagatedFrom")
            | ("unit", "PropagateReloadFrom")
    )
}

pub(crate) fn default_unit_search_paths() -> Vec<PathBuf> {
    UNIT_SEARCH_PATHS.iter().map(PathBuf::from).collect()
}

/// Parse `SYSTEMD_UNIT_PATH` using the same empty-component and trailing-colon
/// rules as systemd's `get_paths_from_environ()`. Keeping this pure makes the
/// contract testable without mutating the process environment.
pub(super) fn parse_unit_search_path(path: &str) -> Option<Vec<PathBuf>> {
    let append_default_paths = path.ends_with(':');
    let parsed: Vec<PathBuf> = path
        .split(':')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    if parsed.is_empty() {
        return None;
    }
    Some(if append_default_paths {
        parsed
            .into_iter()
            .chain(default_unit_search_paths())
            .collect()
    } else {
        parsed
    })
}

pub(super) fn unit_search_paths() -> Vec<PathBuf> {
    if let Ok(path) = env::var("SYSTEMD_UNIT_PATH") {
        // PORT-SYNC: src/libsystemd/sd-path/path-lookup.c
        // `get_paths_from_environ()` in C treats a trailing colon as an
        // explicit request to append the built-in system search path.  This
        // matters during early boot: an initrd or a test harness can inject
        // one high-priority unit directory without accidentally hiding the
        // vendor units that supply the selected boot target.
        if let Some(parsed) = parse_unit_search_path(&path) {
            return parsed;
        }
    }
    default_unit_search_paths()
}

pub(super) fn append_or_clear_list(target: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        target.clear();
    } else {
        target.extend(value.split_whitespace().map(String::from));
    }
}

pub(super) fn append_or_clear_syscall_filter_list(target: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        target.clear();
        return;
    }

    let trimmed = value.trim_start();
    let invert_line = trimmed.starts_with('~');
    let payload = if invert_line {
        trimmed.trim_start_matches('~').trim_start()
    } else {
        value
    };

    for token in payload.split_whitespace() {
        if invert_line {
            target.push(format!("~{}", token.trim_start_matches('~')));
        } else {
            target.push(token.to_string());
        }
    }
}

pub(super) fn append_or_clear_value_list(target: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        target.clear();
    } else {
        target.push(value.to_string());
    }
}

pub(super) fn append_or_clear_duration_list(target: &mut Vec<u64>, value: &str) {
    if value.is_empty() {
        target.clear();
    } else if let Some(parsed) = parse_duration_seconds(value) {
        target.push(parsed);
    }
}

pub(super) fn parse_unit_condition_expression(value: &str) -> Option<UnitConditionExpression> {
    let mut raw = value.trim();
    if raw.is_empty() {
        return None;
    }

    let trigger = if let Some(rest) = raw.strip_prefix('|') {
        raw = rest.trim_start();
        true
    } else {
        false
    };

    let invert = if let Some(rest) = raw.strip_prefix('!') {
        raw = rest.trim_start();
        true
    } else {
        false
    };

    if raw.is_empty() {
        return None;
    }

    Some(UnitConditionExpression {
        trigger,
        invert,
        value: raw.to_string(),
    })
}

pub(super) fn append_or_clear_condition_list(
    target: &mut Vec<UnitConditionExpression>,
    value: &str,
) {
    if value.is_empty() {
        target.clear();
    } else if let Some(parsed) = parse_unit_condition_expression(value) {
        target.push(parsed);
    }
}

pub(super) fn parse_unit_condition_suffix(
    target: &mut UnitConditionConfig,
    suffix: &str,
    value: &str,
) -> bool {
    match suffix {
        "PathExists" => append_or_clear_condition_list(&mut target.path_exists, value),
        "PathExistsGlob" => append_or_clear_condition_list(&mut target.path_exists_glob, value),
        "PathIsDirectory" => append_or_clear_condition_list(&mut target.path_is_directory, value),
        "PathIsSymbolicLink" => {
            append_or_clear_condition_list(&mut target.path_is_symbolic_link, value)
        }
        "PathIsMountPoint" => {
            append_or_clear_condition_list(&mut target.path_is_mount_point, value)
        }
        "PathIsReadWrite" => append_or_clear_condition_list(&mut target.path_is_read_write, value),
        "PathIsEncrypted" => append_or_clear_condition_list(&mut target.path_is_encrypted, value),
        "PathIsSocket" => append_or_clear_condition_list(&mut target.path_is_socket, value),
        "DirectoryNotEmpty" => {
            append_or_clear_condition_list(&mut target.directory_not_empty, value)
        }
        "FileNotEmpty" => append_or_clear_condition_list(&mut target.file_not_empty, value),
        "FileIsExecutable" => append_or_clear_condition_list(&mut target.file_is_executable, value),
        "NeedsUpdate" => append_or_clear_condition_list(&mut target.needs_update, value),
        "FirstBoot" => append_or_clear_condition_list(&mut target.first_boot, value),
        "Architecture" => append_or_clear_condition_list(&mut target.architecture, value),
        "Firmware" => append_or_clear_condition_list(&mut target.firmware, value),
        "Virtualization" => append_or_clear_condition_list(&mut target.virtualization, value),
        "Host" => append_or_clear_condition_list(&mut target.host, value),
        "KernelCommandLine" => {
            append_or_clear_condition_list(&mut target.kernel_command_line, value)
        }
        "KernelVersion" => append_or_clear_condition_list(&mut target.kernel_version, value),
        "Version" => append_or_clear_condition_list(&mut target.version, value),
        "Credential" => append_or_clear_condition_list(&mut target.credential, value),
        "Security" => append_or_clear_condition_list(&mut target.security, value),
        "Capability" => append_or_clear_condition_list(&mut target.capability, value),
        "ACPower" => append_or_clear_condition_list(&mut target.ac_power, value),
        "Memory" => append_or_clear_condition_list(&mut target.memory, value),
        "CPUFeature" => append_or_clear_condition_list(&mut target.cpu_feature, value),
        "CPUs" => append_or_clear_condition_list(&mut target.cpus, value),
        "Environment" => append_or_clear_condition_list(&mut target.environment, value),
        "User" => append_or_clear_condition_list(&mut target.user, value),
        "Group" => append_or_clear_condition_list(&mut target.group, value),
        "ControlGroupController" => {
            append_or_clear_condition_list(&mut target.control_group_controller, value)
        }
        "OSRelease" => append_or_clear_condition_list(&mut target.os_release, value),
        "MemoryPressure" => append_or_clear_condition_list(&mut target.memory_pressure, value),
        "CPUPressure" => append_or_clear_condition_list(&mut target.cpu_pressure, value),
        "IOPressure" => append_or_clear_condition_list(&mut target.io_pressure, value),
        "KernelModuleLoaded" => {
            append_or_clear_condition_list(&mut target.kernel_module_loaded, value)
        }
        "NetworkNamespace" => append_or_clear_condition_list(&mut target.network_namespace, value),
        _ => return false,
    }
    true
}

pub(super) fn parse_unit_condition_directive(
    target: &mut UnitConditionConfig,
    key: &str,
    value: &str,
) -> bool {
    let Some(suffix) = key.strip_prefix("Condition") else {
        return false;
    };
    parse_unit_condition_suffix(target, suffix, value)
}

pub(super) fn parse_unit_assert_directive(
    target: &mut UnitConditionConfig,
    key: &str,
    value: &str,
) -> bool {
    let Some(suffix) = key.strip_prefix("Assert") else {
        return false;
    };
    parse_unit_condition_suffix(target, suffix, value)
}

pub(super) fn parse_exec_command_spec(value: &str) -> Option<ExecCommandSpec> {
    let mut rest = value.trim();
    if rest.is_empty() {
        return None;
    }

    let mut prefixes = String::new();
    loop {
        let next = rest.chars().next()?;
        if matches!(next, '-' | '+' | '!') {
            prefixes.push(next);
            rest = &rest[next.len_utf8()..];
            rest = rest.trim_start();
            continue;
        }
        break;
    }

    let command = rest.trim();
    if command.is_empty() {
        return None;
    }

    Some(ExecCommandSpec {
        prefixes,
        command: command.to_string(),
    })
}

pub(super) fn append_or_clear_exec_list(target: &mut Vec<ExecCommandSpec>, value: &str) {
    if value.is_empty() {
        target.clear();
    } else if let Some(spec) = parse_exec_command_spec(value) {
        target.push(spec);
    }
}

pub(super) fn parse_service_type(value: &str) -> Option<ServiceType> {
    match value {
        "simple" => Some(ServiceType::Simple),
        "forking" => Some(ServiceType::Forking),
        "oneshot" => Some(ServiceType::Oneshot),
        "dbus" => Some(ServiceType::Dbus),
        "notify" => Some(ServiceType::Notify),
        "notify-reload" => Some(ServiceType::NotifyReload),
        "idle" => Some(ServiceType::Idle),
        "exec" => Some(ServiceType::Exec),
        _ => None,
    }
}

pub(super) fn parse_restart_policy(value: &str) -> Option<ServiceRestartPolicy> {
    match value {
        "no" => Some(ServiceRestartPolicy::No),
        "on-success" => Some(ServiceRestartPolicy::OnSuccess),
        "on-failure" => Some(ServiceRestartPolicy::OnFailure),
        "on-abnormal" => Some(ServiceRestartPolicy::OnAbnormal),
        "on-watchdog" => Some(ServiceRestartPolicy::OnWatchdog),
        "on-abort" => Some(ServiceRestartPolicy::OnAbort),
        "always" => Some(ServiceRestartPolicy::Always),
        _ => None,
    }
}

pub(super) fn parse_timeout_failure_mode(value: &str) -> Option<ServiceTimeoutFailureMode> {
    match value {
        "terminate" => Some(ServiceTimeoutFailureMode::Terminate),
        "abort" => Some(ServiceTimeoutFailureMode::Abort),
        "kill" => Some(ServiceTimeoutFailureMode::Kill),
        _ => None,
    }
}

pub(super) fn parse_notify_access(value: &str) -> Option<NotifyAccess> {
    match value {
        "none" => Some(NotifyAccess::None),
        "main" => Some(NotifyAccess::Main),
        "exec" => Some(NotifyAccess::Exec),
        "all" => Some(NotifyAccess::All),
        _ => None,
    }
}

pub(super) fn parse_fd_store_preserve(value: &str) -> Option<FileDescriptorStorePreserve> {
    // C's DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN() accepts its exact enum
    // values and case-insensitive parse_boolean() aliases first.
    match value.to_ascii_lowercase().as_str() {
        "0" | "n" | "no" | "false" | "f" | "off" => Some(FileDescriptorStorePreserve::No),
        "1" | "y" | "yes" | "true" | "t" | "on" => Some(FileDescriptorStorePreserve::Yes),
        "restart" => Some(FileDescriptorStorePreserve::Restart),
        "on-success" => Some(FileDescriptorStorePreserve::OnSuccess),
        _ => None,
    }
}

pub(super) fn parse_bool(value: &str) -> bool {
    parse_boolean(value).unwrap_or(false)
}

fn parse_boolean(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "y" | "yes" | "true" | "t" | "on" => Some(true),
        "0" | "n" | "no" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

pub(super) fn parse_optional_bool(value: &str) -> Option<bool> {
    if value.is_empty() {
        None
    } else {
        Some(parse_bool(value))
    }
}

pub(super) fn parse_optional_i32(value: &str) -> Option<i32> {
    if value.is_empty() {
        None
    } else {
        value.parse::<i32>().ok()
    }
}

pub(super) fn parse_duration_seconds(value: &str) -> Option<u64> {
    if value.is_empty() {
        return None;
    }

    let normalized = value.trim().to_ascii_lowercase();
    if let Some(raw) = normalized.strip_suffix("ms") {
        return raw
            .trim()
            .parse::<u64>()
            .ok()
            .map(|millis| millis.saturating_add(999) / 1000);
    }
    if let Some(raw) = normalized.strip_suffix("min") {
        return raw
            .trim()
            .parse::<u64>()
            .ok()
            .map(|minutes| minutes.saturating_mul(60));
    }
    if let Some(raw) = normalized.strip_suffix("h") {
        return raw
            .trim()
            .parse::<u64>()
            .ok()
            .map(|hours| hours.saturating_mul(3600));
    }
    if let Some(raw) = normalized.strip_suffix("sec") {
        return raw.trim().parse::<u64>().ok();
    }
    if let Some(raw) = normalized.strip_suffix('s') {
        return raw.trim().parse::<u64>().ok();
    }
    normalized.parse::<u64>().ok()
}

pub(super) fn parse_optional_u64(value: &str) -> Option<u64> {
    if value.is_empty() {
        None
    } else {
        value.parse::<u64>().ok()
    }
}

pub(super) fn parse_optional_u32(value: &str) -> Option<u32> {
    if value.is_empty() {
        None
    } else {
        value.parse::<u32>().ok()
    }
}

pub(super) fn parse_optional_string(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

pub(super) fn parse_optional_mode(value: &str) -> Option<u32> {
    if value.is_empty() {
        return None;
    }

    let trimmed = value.trim();
    if let Some(rest) = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
    {
        return u32::from_str_radix(rest, 8).ok();
    }

    if trimmed.starts_with('0') && trimmed.len() > 1 {
        return u32::from_str_radix(trimmed, 8).ok();
    }

    trimmed.parse::<u32>().ok()
}

pub(super) fn parse_exec_context_directive(
    ctx: &mut ExecContextConfig,
    key: &str,
    value: &str,
) -> bool {
    match key {
        "User" => ctx.user = parse_optional_string(value),
        "Group" => ctx.group = parse_optional_string(value),
        "DynamicUser" => ctx.dynamic_user = parse_optional_bool(value),
        "SupplementaryGroups" => append_or_clear_list(&mut ctx.supplementary_groups, value),
        "PAMName" => ctx.pam_name = parse_optional_string(value),
        "CapabilityBoundingSet" => append_or_clear_list(&mut ctx.capability_bounding_set, value),
        "AmbientCapabilities" => append_or_clear_list(&mut ctx.ambient_capabilities, value),
        "NoNewPrivileges" => ctx.no_new_privileges = parse_optional_bool(value),
        "SecureBits" => append_or_clear_list(&mut ctx.secure_bits, value),
        "WorkingDirectory" => ctx.working_directory = parse_optional_string(value),
        "RootDirectory" => ctx.root_directory = parse_optional_string(value),
        "RootImage" => ctx.root_image = parse_optional_string(value),
        "PrivateTmp" => ctx.private_tmp = parse_optional_bool(value),
        "PrivateDevices" => ctx.private_devices = parse_optional_bool(value),
        "PrivateNetwork" => ctx.private_network = parse_optional_bool(value),
        "PrivateIPC" => ctx.private_ipc = parse_optional_bool(value),
        "PrivateUsers" => ctx.private_users = parse_optional_bool(value),
        "PrivateMounts" => ctx.private_mounts = parse_optional_bool(value),
        "ProtectSystem" => ctx.protect_system = parse_optional_string(value),
        "ProtectHome" => ctx.protect_home = parse_optional_string(value),
        "ProtectHostname" => ctx.protect_hostname = parse_optional_bool(value),
        "ProtectClock" => ctx.protect_clock = parse_optional_bool(value),
        "ProtectKernelTunables" => ctx.protect_kernel_tunables = parse_optional_bool(value),
        "ProtectKernelModules" => ctx.protect_kernel_modules = parse_optional_bool(value),
        "ProtectKernelLogs" => ctx.protect_kernel_logs = parse_optional_bool(value),
        "ProtectControlGroups" => ctx.protect_control_groups = parse_optional_bool(value),
        "RestrictAddressFamilies" => {
            append_or_clear_list(&mut ctx.restrict_address_families, value)
        }
        "RestrictFileSystems" => append_or_clear_list(&mut ctx.restrict_file_systems, value),
        "RestrictNamespaces" => ctx.restrict_namespaces = parse_optional_string(value),
        "LockPersonality" => ctx.lock_personality = parse_optional_bool(value),
        "MemoryDenyWriteExecute" => ctx.memory_deny_write_execute = parse_optional_bool(value),
        "RestrictRealtime" => ctx.restrict_realtime = parse_optional_bool(value),
        "RestrictSUIDSGID" => ctx.restrict_suid_sgid = parse_optional_bool(value),
        "SystemCallFilter" => {
            append_or_clear_syscall_filter_list(&mut ctx.system_call_filter, value)
        }
        "SystemCallErrorNumber" => ctx.system_call_error_number = parse_optional_string(value),
        "SystemCallArchitectures" => {
            append_or_clear_list(&mut ctx.system_call_architectures, value)
        }
        "Environment" => append_or_clear_value_list(&mut ctx.environment, value),
        "EnvironmentFile" => append_or_clear_value_list(&mut ctx.environment_file, value),
        "PassEnvironment" => append_or_clear_list(&mut ctx.pass_environment, value),
        "UnsetEnvironment" => append_or_clear_value_list(&mut ctx.unset_environment, value),
        "StandardInput" => ctx.standard_input = parse_optional_string(value),
        "StandardOutput" => ctx.standard_output = parse_optional_string(value),
        "StandardError" => ctx.standard_error = parse_optional_string(value),
        "TTYPath" => ctx.tty_path = parse_optional_string(value),
        "TTYReset" => ctx.tty_reset = parse_optional_bool(value),
        "TTYVHangup" => ctx.tty_vhangup = parse_optional_bool(value),
        "TTYVTDisallocate" => ctx.tty_vt_disallocate = parse_optional_bool(value),
        "SyslogIdentifier" => ctx.syslog_identifier = parse_optional_string(value),
        "SyslogFacility" => ctx.syslog_facility = parse_optional_string(value),
        "SyslogLevel" => ctx.syslog_level = parse_optional_string(value),
        "Nice" => ctx.nice = parse_optional_i32(value),
        "CPUSchedulingPolicy" => ctx.cpu_scheduling_policy = parse_optional_string(value),
        "CPUAffinity" => append_or_clear_list(&mut ctx.cpu_affinity, value),
        "UMask" => ctx.umask = parse_optional_string(value),
        "OOMScoreAdjust" => ctx.oom_score_adjust = parse_optional_i32(value),
        "RuntimeDirectory" => append_or_clear_list(&mut ctx.runtime_directory, value),
        "StateDirectory" => append_or_clear_list(&mut ctx.state_directory, value),
        "CacheDirectory" => append_or_clear_list(&mut ctx.cache_directory, value),
        "LogsDirectory" => append_or_clear_list(&mut ctx.logs_directory, value),
        "ConfigurationDirectory" => append_or_clear_list(&mut ctx.configuration_directory, value),
        "DirectoryMode" => ctx.directory_mode = parse_optional_mode(value),
        "RuntimeDirectoryMode" => ctx.runtime_directory_mode = parse_optional_mode(value),
        "StateDirectoryMode" => ctx.state_directory_mode = parse_optional_mode(value),
        "CacheDirectoryMode" => ctx.cache_directory_mode = parse_optional_mode(value),
        "LogsDirectoryMode" => ctx.logs_directory_mode = parse_optional_mode(value),
        "ConfigurationDirectoryMode" => {
            ctx.configuration_directory_mode = parse_optional_mode(value)
        }
        "RuntimeDirectoryPreserve" => ctx.runtime_directory_preserve = parse_optional_string(value),
        "ReadWritePaths" => append_or_clear_list(&mut ctx.read_write_paths, value),
        "ReadOnlyPaths" => append_or_clear_list(&mut ctx.read_only_paths, value),
        "InaccessiblePaths" => append_or_clear_list(&mut ctx.inaccessible_paths, value),
        "SELinuxContext" => ctx.selinux_context = parse_optional_string(value),
        "AppArmorProfile" => ctx.app_armor_profile = parse_optional_string(value),
        "SeccompFilter" => append_or_clear_syscall_filter_list(&mut ctx.seccomp_filter, value),
        "LoadCredential" => append_or_clear_value_list(&mut ctx.load_credential, value),
        "LoadCredentialEncrypted" => {
            append_or_clear_value_list(&mut ctx.load_credential_encrypted, value)
        }
        "SetCredential" => append_or_clear_value_list(&mut ctx.set_credential, value),
        "SetCredentialEncrypted" => {
            append_or_clear_value_list(&mut ctx.set_credential_encrypted, value)
        }
        "ImportCredential" => append_or_clear_value_list(&mut ctx.import_credential, value),
        _ if key.starts_with("Limit") => {
            if value.is_empty() {
                ctx.limits.remove(key);
            } else {
                ctx.limits.insert(key.to_string(), value.to_string());
            }
        }
        _ => return false,
    }
    true
}

pub(super) fn parse_kill_mode(value: &str) -> Option<KillMode> {
    if value.is_empty() {
        return Some(KillMode::ControlGroup);
    }

    match value {
        "control-group" => Some(KillMode::ControlGroup),
        "process" => Some(KillMode::Process),
        "mixed" => Some(KillMode::Mixed),
        "none" => Some(KillMode::None),
        _ => None,
    }
}

pub(super) fn parse_kill_context_directive(kill: &mut KillConfig, key: &str, value: &str) -> bool {
    match key {
        "KillMode" => {
            if let Some(kill_mode) = parse_kill_mode(value) {
                kill.kill_mode = Some(kill_mode);
            }
        }
        "KillSignal" => kill.kill_signal = parse_optional_i32(value),
        "RestartKillSignal" => kill.restart_kill_signal = parse_optional_i32(value),
        "FinalKillSignal" => kill.final_kill_signal = parse_optional_i32(value),
        "SendSIGHUP" => kill.send_sighup = parse_optional_bool(value),
        "SendSIGKILL" => kill.send_sigkill = parse_optional_bool(value),
        "WatchdogSignal" => kill.watchdog_signal = parse_optional_i32(value),
        _ => return false,
    }
    true
}

pub(super) fn parse_cgroup_context_directive(
    cgroup: &mut CgroupConfig,
    key: &str,
    value: &str,
) -> bool {
    match key {
        "Slice" => cgroup.slice = parse_optional_string(value),
        "Delegate" => parse_delegate(cgroup, value),
        "DelegateSubgroup" => cgroup.delegate_subgroup = parse_optional_string(value),
        _ => return parse_cgroup_key(cgroup, key, value),
    }
    true
}

fn parse_delegate(cgroup: &mut CgroupConfig, value: &str) {
    const CONTROLLERS: &[&str] = &["cpu", "cpuset", "io", "memory", "pids"];
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        cgroup.delegate = Some(true);
        cgroup.delegate_controllers.clear();
    } else if matches!(normalized.as_str(), "1" | "yes" | "y" | "true" | "t" | "on") {
        cgroup.delegate = Some(true);
        cgroup.delegate_controllers = CONTROLLERS
            .iter()
            .map(|controller| (*controller).to_string())
            .collect();
    } else if matches!(
        normalized.as_str(),
        "0" | "no" | "n" | "false" | "f" | "off"
    ) {
        cgroup.delegate = Some(false);
        cgroup.delegate_controllers.clear();
    } else {
        let Some(words) = parse_unquoted_words(&normalized) else {
            // Match extract_first_word(): malformed quoting leaves the prior
            // merged setting untouched.
            return;
        };
        cgroup.delegate = Some(true);
        for controller in words {
            if CONTROLLERS.contains(&controller.as_str())
                && !cgroup
                    .delegate_controllers
                    .iter()
                    .any(|existing| existing == &controller)
            {
                cgroup.delegate_controllers.push(controller);
            }
        }
    }
}

fn parse_unquoted_words(value: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            word.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            } else {
                word.push(character);
            }
        } else if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(character);
        }
    }
    if escaped || quote.is_some() {
        return None;
    }
    if !word.is_empty() {
        words.push(word);
    }
    Some(words)
}

pub(super) fn parse_cgroup_key(cgroup: &mut CgroupConfig, key: &str, value: &str) -> bool {
    match key {
        "CPUAccounting" => cgroup.cpu_accounting = parse_optional_bool(value),
        "CPUWeight" => cgroup.cpu_weight = parse_optional_u64(value),
        "CPUQuota" => cgroup.cpu_quota = parse_optional_string(value),
        "CPUQuotaPeriodSec" => {
            if value.is_empty() {
                cgroup.cpu_quota_period_usec = None;
            } else if let Ok(period) = systemd_basic_rs::time_util::parse_sec(value) {
                // Like config_parse_sec_def_infinity(), malformed
                // assignments are ignored instead of erasing an earlier
                // valid value from the merged unit configuration.
                cgroup.cpu_quota_period_usec = Some(period);
            }
        }
        "AllowedCPUs" => {
            if value.is_empty() {
                cgroup.allowed_cpus = None;
            } else if let Some(existing) = &mut cgroup.allowed_cpus {
                existing.push(' ');
                existing.push_str(value);
            } else {
                cgroup.allowed_cpus = Some(value.to_string());
            }
        }
        "IOAccounting" => cgroup.io_accounting = parse_optional_bool(value),
        "IOWeight" => cgroup.io_weight = parse_optional_u64(value),
        "IODeviceWeight" => append_or_clear_value_list(&mut cgroup.io_device_weight, value),
        "MemoryMin" => cgroup.memory_min = parse_optional_string(value),
        "MemoryLow" => cgroup.memory_low = parse_optional_string(value),
        "MemoryHigh" => cgroup.memory_high = parse_optional_string(value),
        "MemoryMax" => cgroup.memory_max = parse_optional_string(value),
        "MemorySwapMax" => cgroup.memory_swap_max = parse_optional_string(value),
        "MemoryZSwapMax" => cgroup.memory_zswap_max = parse_optional_string(value),
        "MemoryAccounting" => cgroup.memory_accounting = parse_optional_bool(value),
        "TasksAccounting" => cgroup.tasks_accounting = parse_optional_bool(value),
        "IPAccounting" => cgroup.ip_accounting = parse_optional_bool(value),
        "TasksMax" => cgroup.tasks_max = parse_optional_u64(value),
        "IPAddressAllow" => append_or_clear_value_list(&mut cgroup.ip_address_allow, value),
        "IPAddressDeny" => append_or_clear_value_list(&mut cgroup.ip_address_deny, value),
        "BPFProgram" => append_or_clear_value_list(&mut cgroup.bpf_program, value),
        "SocketBindAllow" => append_or_clear_value_list(&mut cgroup.socket_bind_allow, value),
        "SocketBindDeny" => append_or_clear_value_list(&mut cgroup.socket_bind_deny, value),
        "RestrictNetworkInterfaces" => {
            append_or_clear_list(&mut cgroup.restrict_network_interfaces, value)
        }
        "NFTSet" => append_or_clear_value_list(&mut cgroup.nft_set, value),
        "CoredumpFilter" => cgroup.coredump_filter = parse_optional_string(value),
        "ManagedOOMMemoryPressure" => {
            cgroup.managed_oom_memory_pressure = parse_optional_string(value)
        }
        "ManagedOOMMemoryPressureLimit" => {
            cgroup.managed_oom_memory_pressure_limit = parse_optional_string(value)
        }
        "ManagedOOMPreference" => cgroup.managed_oom_preference = parse_optional_string(value),
        "ManagedOOMSwap" => cgroup.managed_oom_swap = parse_optional_string(value),
        "MemoryPressureWatch" => cgroup.memory_pressure_watch = parse_optional_string(value),
        "IOReadBandwidthMax" => {
            append_or_clear_io_limit(cgroup, CgroupIoLimitKind::ReadBandwidth, value)
        }
        "IOWriteBandwidthMax" => {
            append_or_clear_io_limit(cgroup, CgroupIoLimitKind::WriteBandwidth, value)
        }
        "IOReadIOPSMax" => append_or_clear_io_limit(cgroup, CgroupIoLimitKind::ReadIops, value),
        "IOWriteIOPSMax" => append_or_clear_io_limit(cgroup, CgroupIoLimitKind::WriteIops, value),
        _ => return false,
    }
    true
}

fn append_or_clear_io_limit(cgroup: &mut CgroupConfig, kind: CgroupIoLimitKind, value: &str) {
    if value.is_empty() {
        cgroup.io_limits.retain(|entry| entry.kind != kind);
    } else {
        cgroup.io_limits.push(CgroupIoLimitConfig {
            kind,
            value: value.to_string(),
        });
    }
}

pub(super) fn apply_cgroup_config(unit: &mut Unit, config: &CgroupConfig) {
    let mut ctx = unit.cgroup_context.clone().unwrap_or_default();

    if let Some(v) = config.io_accounting {
        ctx.io_accounting = v;
    }
    if let Some(v) = config.memory_accounting {
        ctx.memory_accounting = v;
    }
    if let Some(v) = config.tasks_accounting {
        ctx.tasks_accounting = v;
    }
    if let Some(v) = config.ip_accounting {
        ctx.ip_accounting = v;
    }
    if let Some(v) = config.tasks_max {
        ctx.tasks_max = v;
    }

    unit.cgroup_context = Some(ctx);
}

pub(super) fn apply_exec_context_config(unit: &mut Unit, config: &ExecContextConfig) {
    let ctx = unit
        .exec_context
        .get_or_insert_with(crate::unit::ExecContext::default);

    if let Some(nice) = config.nice {
        ctx.nice = nice;
    }

    // These are the console-touching parts of C's ExecContext.  They are
    // applied to the shared unit model so `unit_needs_console()` can make the
    // same conservative ownership decision even before a live manager-side
    // console counter is wired up.
    if let Some(tty_path) = &config.tty_path {
        ctx.tty_path = Some(tty_path.clone());
    }
    if let Some(tty_reset) = config.tty_reset {
        ctx.tty_reset = tty_reset;
    }
    if let Some(tty_vhangup) = config.tty_vhangup {
        ctx.tty_vhangup = tty_vhangup;
    }
    if let Some(tty_vt_disallocate) = config.tty_vt_disallocate {
        ctx.tty_vt_disallocate = tty_vt_disallocate;
    }

    for item in &config.environment {
        if let Some((k, v)) = item.split_once('=') {
            ctx.environment.insert(k.to_string(), v.to_string());
        }
    }
}

pub(super) fn apply_kill_config(unit: &mut Unit, config: &KillConfig) {
    let ctx = unit.kill_context.get_or_insert_with(KillContext::default);

    if let Some(signal) = config.kill_signal {
        ctx.kill_signal = signal;
    }
    if let Some(signal) = config.final_kill_signal {
        ctx.final_kill_signal = signal;
    }
}
