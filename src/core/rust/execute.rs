// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/execute.c
//
use std::fmt;

pub const SOURCE_PATH: &str = "src/core/execute.c";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecuteError {
    InvalidArgument(&'static str),
    MissingData(&'static str),
}

impl fmt::Display for ExecuteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::MissingData(msg) => write!(f, "missing data: {msg}"),
        }
    }
}

impl std::error::Error for ExecuteError {}

pub type Result<T> = std::result::Result<T, ExecuteError>;

pub const EXEC_IS_CONTROL: u64 = 1 << 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtectControlGroups {
    #[default]
    No,
    Yes,
    Private,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrivatePids {
    #[default]
    No,
    Yes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecDirectoryType {
    #[default]
    Runtime,
    State,
    Cache,
    Logs,
    Configuration,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecParameters {
    pub stdout_fd: Option<i32>,
    pub flags: u64,
    pub cgroup_path: Option<String>,
    pub log_level_max: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecCommand {
    pub path: String,
    pub argv: Vec<String>,
    pub status: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecStatus {
    pub code: Option<i32>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecRuntime {
    pub runtime_directory: Option<String>,
    pub mount_ns_dir: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecSharedRuntime {
    pub id: String,
    pub acquired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecDirectory {
    pub path: String,
    pub kind: ExecDirectoryType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtyResetPlan {
    pub tty_path: Option<String>,
    pub applied_size: Option<(u32, u32)>,
    pub invocation_id: Option<String>,
    pub vhangup: bool,
    pub vt_disallocate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecSpawnResult {
    pub command_path: String,
    pub cgroup_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecContext {
    pub stdio_as_fds: bool,
    pub tty_path: Option<String>,
    pub tty_rows: Option<u32>,
    pub tty_cols: Option<u32>,
    pub tty_reset: bool,
    pub tty_vhangup: bool,
    pub tty_vt_disallocate: bool,
    pub private_network: bool,
    pub network_namespace_path: Option<String>,
    pub private_ipc: bool,
    pub ipc_namespace_path: Option<String>,
    pub protect_control_groups: ProtectControlGroups,
    pub cgroup_namespace_supported: bool,
    pub private_pids: PrivatePids,
    pub private_tmp: bool,
    pub private_devices: bool,
    pub private_users: bool,
    pub private_mounts: bool,
    pub root_directory: Option<String>,
    pub root_image: Option<String>,
    pub root_ephemeral: bool,
    pub mount_apivfs: bool,
    pub bind_log_sockets: bool,
    pub cpu_affinity_from_numa: bool,
    pub log_level_max: i32,
    pub oom_score_adjust: i32,
    pub nice: i32,
    pub cpu_sched_policy: i32,
    pub cpu_sched_priority: i32,
    pub set_login_environment: bool,
    pub syscall_filter: Vec<String>,
    pub syscall_archs: Vec<String>,
    pub syscall_log: bool,
    pub address_families: Vec<String>,
    pub restrict_filesystems: Vec<String>,
    pub restrict_namespaces: bool,
    pub rootfs_strict: bool,
    pub vpicked_extensions: bool,
    pub clean_directories: Vec<ExecDirectory>,
    pub clean_mask: i32,
    pub maintains_privileges: bool,
    pub effective_ioprio: i32,
    pub log_extra_fields: Vec<String>,
}

impl ExecContext {
    fn touch_rootfs(&self) -> bool {
        self.root_directory.is_some() || self.root_image.is_some()
    }
}

pub fn exec_context_tty_path(context: &ExecContext) -> Option<&str> {
    if context.stdio_as_fds {
        None
    } else {
        Some(context.tty_path.as_deref().unwrap_or("/dev/console"))
    }
}

pub fn exec_context_apply_tty_size(
    context: &ExecContext,
    input_is_tty: bool,
    output_is_tty: bool,
    tty_path: Option<&str>,
) -> Result<Option<(u32, u32)>> {
    if !output_is_tty {
        return Ok(None);
    }

    let _tty_path = tty_path.or_else(|| exec_context_tty_path(context));
    let rows = context.tty_rows.unwrap_or(u32::MAX);
    let cols = context.tty_cols.unwrap_or(u32::MAX);

    if rows == u32::MAX && cols == u32::MAX && !input_is_tty {
        return Ok(None);
    }

    Ok(Some((rows.min(65_535), cols.min(65_535))))
}

pub fn exec_context_tty_reset(
    context: &ExecContext,
    parameters: Option<&ExecParameters>,
    invocation_id: Option<&str>,
) -> Result<TtyResetPlan> {
    let tty_path = exec_context_tty_path(context).map(ToOwned::to_owned);
    let output_is_tty = parameters.and_then(|p| p.stdout_fd).is_some() || tty_path.is_some();
    let applied_size =
        exec_context_apply_tty_size(context, true, output_is_tty, tty_path.as_deref())?;

    Ok(TtyResetPlan {
        tty_path,
        applied_size,
        invocation_id: invocation_id.map(ToOwned::to_owned),
        vhangup: context.tty_vhangup,
        vt_disallocate: context.tty_vt_disallocate,
    })
}

pub fn exec_needs_network_namespace(context: &ExecContext) -> bool {
    context.private_network || context.network_namespace_path.is_some()
}

pub fn exec_needs_ephemeral(context: &ExecContext) -> bool {
    context.touch_rootfs() && context.root_ephemeral
}

pub fn exec_needs_ipc_namespace(context: &ExecContext) -> bool {
    context.private_ipc || context.ipc_namespace_path.is_some()
}

pub fn needs_cgroup_namespace(i: ProtectControlGroups) -> bool {
    matches!(
        i,
        ProtectControlGroups::Private | ProtectControlGroups::Strict
    )
}

pub fn exec_get_protect_control_groups(context: &ExecContext) -> ProtectControlGroups {
    if needs_cgroup_namespace(context.protect_control_groups) && !context.cgroup_namespace_supported
    {
        return match context.protect_control_groups {
            ProtectControlGroups::Private => ProtectControlGroups::No,
            ProtectControlGroups::Strict => ProtectControlGroups::Yes,
            other => other,
        };
    }
    context.protect_control_groups
}

pub fn exec_needs_cgroup_namespace(context: &ExecContext) -> bool {
    needs_cgroup_namespace(exec_get_protect_control_groups(context))
}

pub fn exec_needs_cgroup_mount(context: &ExecContext) -> bool {
    exec_get_protect_control_groups(context) != ProtectControlGroups::No
}

pub fn exec_is_cgroup_mount_read_only(context: &ExecContext) -> bool {
    matches!(
        exec_get_protect_control_groups(context),
        ProtectControlGroups::Yes | ProtectControlGroups::Strict
    )
}

pub fn exec_needs_pid_namespace(context: &ExecContext, params: Option<&ExecParameters>) -> bool {
    if params.is_some_and(|p| p.flags & EXEC_IS_CONTROL != 0) {
        return false;
    }
    context.private_pids != PrivatePids::No
}

pub fn exec_needs_mount_namespace(context: &ExecContext, params: Option<&ExecParameters>) -> bool {
    context.touch_rootfs()
        || context.private_tmp
        || context.private_devices
        || context.private_mounts
        || exec_needs_ephemeral(context)
        || exec_needs_cgroup_mount(context)
        || params.is_some_and(|p| p.cgroup_path.is_some())
}

pub fn exec_log_level_max_with_exec_params(
    context: &ExecContext,
    params: Option<&ExecParameters>,
) -> i32 {
    params
        .and_then(|p| p.log_level_max)
        .unwrap_or(context.log_level_max)
}

pub fn exec_log_level_max(context: &ExecContext) -> i32 {
    context.log_level_max
}

pub fn exec_directory_is_private(context: &ExecContext, type_: ExecDirectoryType) -> bool {
    context.clean_directories.iter().any(|d| d.kind == type_)
}

pub fn exec_params_needs_control_subcgroup(params: &ExecParameters) -> Result<bool> {
    Ok(params.flags & EXEC_IS_CONTROL != 0)
}

pub fn exec_params_get_cgroup_path(
    params: &ExecParameters,
    base: &str,
    suffix: Option<&str>,
) -> Result<String> {
    if base.is_empty() {
        return Err(ExecuteError::MissingData("base"));
    }
    let raw = params.cgroup_path.as_deref().unwrap_or(base);
    Ok(match suffix {
        Some(sfx) if !sfx.is_empty() => format!("{raw}/{sfx}"),
        _ => raw.to_string(),
    })
}

pub fn exec_context_get_cpu_affinity_from_numa(c: &ExecContext) -> bool {
    c.cpu_affinity_from_numa
}

pub fn exec_spawn(
    command: &ExecCommand,
    _context: &ExecContext,
    params: &ExecParameters,
    _runtime: &ExecRuntime,
) -> Result<ExecSpawnResult> {
    if command.path.is_empty() {
        return Err(ExecuteError::MissingData("command.path"));
    }
    Ok(ExecSpawnResult {
        command_path: command.path.clone(),
        cgroup_path: params.cgroup_path.clone(),
    })
}

pub fn exec_context_init(c: &mut ExecContext) {
    *c = ExecContext::default();
}

pub fn exec_context_done(c: &mut ExecContext) {
    c.log_extra_fields.clear();
}

pub fn exec_context_destroy_runtime_directory(
    c: &ExecContext,
    runtime_prefix: &str,
) -> Result<String> {
    if runtime_prefix.is_empty() {
        return Err(ExecuteError::MissingData("runtime_prefix"));
    }
    Ok(format!("{runtime_prefix}/runtime-{}", c.clean_mask))
}

pub fn exec_context_destroy_mount_ns_dir(runtime: &mut ExecRuntime) -> Result<()> {
    runtime.mount_ns_dir = None;
    Ok(())
}

pub fn exec_command_done(c: &mut ExecCommand) {
    c.status = None;
}

pub fn exec_command_done_array(c: &mut [ExecCommand]) {
    c.iter_mut().for_each(exec_command_done);
}

pub fn exec_command_free(c: ExecCommand) -> Option<ExecCommand> {
    if c.path.is_empty() && c.argv.is_empty() {
        None
    } else {
        Some(ExecCommand::default())
    }
}

pub fn exec_command_free_list(c: &mut Vec<ExecCommand>) {
    c.clear();
}

pub fn exec_command_free_array(c: &mut [ExecCommand]) {
    c.iter_mut().for_each(exec_command_done);
}

pub fn exec_command_reset_status_array(c: &mut [ExecCommand]) {
    c.iter_mut().for_each(|cmd| cmd.status = None);
}

pub fn exec_command_reset_status_list_array(c: &mut [Vec<ExecCommand>]) {
    c.iter_mut()
        .for_each(|list| exec_command_reset_status_array(list));
}

pub fn exec_params_dump(p: &ExecParameters, prefix: &str) -> String {
    format!("{prefix}flags={} cgroup={:?}", p.flags, p.cgroup_path)
}

pub fn exec_context_dump(c: &ExecContext, prefix: &str) -> String {
    format!("{prefix}tty={:?} rootfs={}", c.tty_path, c.touch_rootfs())
}

pub fn exec_context_maintains_privileges(c: &ExecContext) -> bool {
    c.maintains_privileges
}

pub fn exec_context_get_effective_ioprio(c: &ExecContext) -> i32 {
    c.effective_ioprio
}

pub fn exec_context_get_effective_mount_apivfs(c: &ExecContext) -> bool {
    c.mount_apivfs
}

pub fn exec_context_get_effective_bind_log_sockets(c: &ExecContext) -> bool {
    c.bind_log_sockets
}

pub fn exec_context_free_log_extra_fields(c: &mut ExecContext) {
    c.log_extra_fields.clear();
}

pub fn exec_context_revert_tty(c: &mut ExecContext, _invocation_id: Option<&str>) {
    c.tty_reset = false;
}

pub fn exec_context_get_clean_directories(
    c: &ExecContext,
    type_: ExecDirectoryType,
) -> Result<Vec<String>> {
    Ok(c.clean_directories
        .iter()
        .filter(|d| d.kind == type_)
        .map(|d| d.path.clone())
        .collect())
}

pub fn exec_context_get_clean_mask(c: &ExecContext) -> Result<i32> {
    Ok(c.clean_mask)
}

pub fn exec_context_get_oom_score_adjust(c: &ExecContext) -> i32 {
    c.oom_score_adjust
}
pub fn exec_context_get_nice(c: &ExecContext) -> i32 {
    c.nice
}
pub fn exec_context_get_cpu_sched_policy(c: &ExecContext) -> i32 {
    c.cpu_sched_policy
}
pub fn exec_context_get_cpu_sched_priority(c: &ExecContext) -> i32 {
    c.cpu_sched_priority
}
pub fn exec_context_get_set_login_environment(c: &ExecContext) -> bool {
    c.set_login_environment
}
pub fn exec_context_get_syscall_filter(c: &ExecContext) -> &[String] {
    &c.syscall_filter
}
pub fn exec_context_get_syscall_archs(c: &ExecContext) -> &[String] {
    &c.syscall_archs
}
pub fn exec_context_get_syscall_log(c: &ExecContext) -> bool {
    c.syscall_log
}
pub fn exec_context_get_address_families(c: &ExecContext) -> &[String] {
    &c.address_families
}
pub fn exec_context_get_restrict_filesystems(c: &ExecContext) -> &[String] {
    &c.restrict_filesystems
}
pub fn exec_context_restrict_namespaces_set(c: &ExecContext) -> bool {
    c.restrict_namespaces
}
pub fn exec_context_restrict_filesystems_set(c: &ExecContext) -> bool {
    !c.restrict_filesystems.is_empty()
}
pub fn exec_context_with_rootfs(c: &ExecContext) -> bool {
    c.touch_rootfs()
}
pub fn exec_context_with_rootfs_strict(c: &ExecContext) -> bool {
    c.touch_rootfs() && c.rootfs_strict
}
pub fn exec_context_has_vpicked_extensions(c: &ExecContext) -> bool {
    c.vpicked_extensions
}

pub fn exec_status_start(s: &mut ExecStatus, message: &str) {
    s.message = Some(message.into());
}
pub fn exec_status_exit(s: &mut ExecStatus, code: i32, message: &str) {
    s.code = Some(code);
    s.message = Some(message.into());
}
pub fn exec_status_handoff(from: &ExecStatus, to: &mut ExecStatus) {
    *to = from.clone();
}
pub fn exec_status_reset(s: &mut ExecStatus) {
    *s = ExecStatus::default();
}
pub fn exec_status_dump(s: &ExecStatus, prefix: &str) -> String {
    format!("{prefix}code={:?} msg={:?}", s.code, s.message)
}
pub fn exec_command_dump(c: &ExecCommand, prefix: &str) -> String {
    format!("{prefix}{} {:?}", c.path, c.argv)
}
pub fn exec_command_dump_list(c: &[ExecCommand], prefix: &str) -> Vec<String> {
    c.iter().map(|cmd| exec_command_dump(cmd, prefix)).collect()
}
pub fn exec_command_append_list(list: &mut Vec<ExecCommand>, cmd: ExecCommand) -> Result<()> {
    list.push(cmd);
    Ok(())
}
pub fn exec_command_set(slot: &mut Option<ExecCommand>, cmd: ExecCommand) -> Result<()> {
    *slot = Some(cmd);
    Ok(())
}
pub fn exec_command_append(list: &mut Vec<ExecCommand>, cmd: ExecCommand) -> Result<()> {
    list.push(cmd);
    Ok(())
}
pub fn exec_shared_runtime_done(rt: &mut ExecSharedRuntime) {
    rt.acquired = false;
}
pub fn exec_shared_runtime_destroy(rt: &mut ExecSharedRuntime) -> Result<()> {
    rt.acquired = false;
    rt.id.clear();
    Ok(())
}
pub fn exec_shared_runtime_acquire(rt: &mut ExecSharedRuntime, id: &str) -> Result<()> {
    rt.id = id.into();
    rt.acquired = true;
    Ok(())
}
pub fn exec_shared_runtime_serialize(rt: &ExecSharedRuntime) -> Result<String> {
    Ok(format!("{}:{}", rt.id, rt.acquired))
}
pub fn exec_shared_runtime_deserialize_compat(raw: &str) -> Result<ExecSharedRuntime> {
    Ok(ExecSharedRuntime {
        id: raw.into(),
        acquired: true,
    })
}
pub fn exec_shared_runtime_deserialize_one(raw: &str) -> Result<ExecSharedRuntime> {
    exec_shared_runtime_deserialize_compat(raw)
}
pub fn exec_shared_runtime_vacuum(rt: &mut Vec<ExecSharedRuntime>) {
    rt.retain(|item| item.acquired);
}
pub fn exec_runtime_make(path: &str) -> Result<ExecRuntime> {
    Ok(ExecRuntime {
        runtime_directory: Some(path.into()),
        mount_ns_dir: None,
    })
}
pub fn exec_runtime_free(rt: &mut ExecRuntime) {
    *rt = ExecRuntime::default();
}
pub fn exec_runtime_destroy(rt: &mut ExecRuntime) {
    exec_runtime_free(rt);
}
pub fn exec_runtime_clear(rt: &mut ExecRuntime) {
    exec_runtime_free(rt);
}
pub fn exec_params_shallow_clear(p: &mut ExecParameters) {
    p.stdout_fd = None;
    p.flags = 0;
}
pub fn exec_params_deep_clear(p: &mut ExecParameters) {
    *p = ExecParameters::default();
}
pub fn exec_directory_done(d: &mut ExecDirectory) {
    d.path.clear();
}
pub fn exec_directory_add(list: &mut Vec<ExecDirectory>, d: ExecDirectory) -> Result<()> {
    list.push(d);
    Ok(())
}
pub fn exec_directory_sort(d: &mut [ExecDirectory]) {
    d.sort_by(|a, b| a.path.cmp(&b.path));
}
pub fn exec_clean_mask_from_string(s: &str) -> Result<i32> {
    s.parse()
        .map_err(|_| ExecuteError::InvalidArgument("clean mask"))
}
pub fn log_command_line(command: &ExecCommand) -> Result<String> {
    Ok(command.argv.join(" "))
}
pub fn exec_context_load_environment(context: &ExecContext) -> Result<Vec<String>> {
    Ok(context.log_extra_fields.clone())
}
pub fn tty_may_match_dev_console(tty: Option<&str>) -> bool {
    tty.is_none() || tty == Some("/dev/console")
}
pub fn exec_context_may_touch_tty(context: &ExecContext) -> bool {
    exec_context_tty_path(context).is_some()
}
pub fn exec_context_may_touch_console(context: &ExecContext) -> bool {
    tty_may_match_dev_console(exec_context_tty_path(context))
}
pub fn exec_context_shall_ansi_seq_reset(context: &ExecContext) -> bool {
    context.tty_reset
}
pub fn strv_fprintf(list: &[String]) -> String {
    list.join("\n")
}
pub fn strv_dump(prefix: &str, list: &[String]) -> Vec<String> {
    list.iter().map(|v| format!("{prefix}{v}")).collect()
}
pub fn invalid_env(p: &str) -> bool {
    p.is_empty() || !p.contains('=')
}
pub fn destroy_tree(path: &str) -> Option<String> {
    if path.is_empty() {
        None
    } else {
        Some(path.into())
    }
}
pub fn exec_shared_runtime_free(rt: &mut ExecSharedRuntime) {
    *rt = ExecSharedRuntime::default();
}
pub fn exec_shared_runtime_allocate(id: &str) -> Result<ExecSharedRuntime> {
    Ok(ExecSharedRuntime {
        id: id.into(),
        acquired: false,
    })
}
pub fn exec_shared_runtime_add(
    list: &mut Vec<ExecSharedRuntime>,
    rt: ExecSharedRuntime,
) -> Result<()> {
    list.push(rt);
    Ok(())
}
pub fn exec_shared_runtime_make(id: &str) -> Result<ExecSharedRuntime> {
    Ok(ExecSharedRuntime {
        id: id.into(),
        acquired: true,
    })
}
pub fn exec_directory_find<'a>(list: &'a [ExecDirectory], path: &str) -> Option<&'a ExecDirectory> {
    list.iter().find(|d| d.path == path)
}
pub fn exec_directory_item_compare_func(
    a: &ExecDirectory,
    b: &ExecDirectory,
) -> std::cmp::Ordering {
    a.path.cmp(&b.path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_needs_network_namespace() {
        let context = ExecContext {
            private_network: true,
            ..ExecContext::default()
        };
        assert!(exec_needs_network_namespace(&context));
    }

    #[test]
    fn test_exec_get_protect_control_groups_downgrade() {
        let context = ExecContext {
            protect_control_groups: ProtectControlGroups::Strict,
            cgroup_namespace_supported: false,
            ..ExecContext::default()
        };
        assert_eq!(
            exec_get_protect_control_groups(&context),
            ProtectControlGroups::Yes
        );
    }

    #[test]
    fn test_exec_needs_pid_namespace_skips_control() {
        let context = ExecContext {
            private_pids: PrivatePids::Yes,
            ..ExecContext::default()
        };
        let params = ExecParameters {
            flags: EXEC_IS_CONTROL,
            ..ExecParameters::default()
        };
        assert!(!exec_needs_pid_namespace(&context, Some(&params)));
    }

    #[test]
    fn test_exec_context_apply_tty_size_requires_output_tty() {
        let context = ExecContext {
            tty_rows: Some(24),
            tty_cols: Some(80),
            ..ExecContext::default()
        };
        assert_eq!(
            exec_context_apply_tty_size(&context, true, false, None).unwrap(),
            None
        );
        assert_eq!(
            exec_context_apply_tty_size(&context, true, true, None).unwrap(),
            Some((24, 80))
        );
    }

    #[test]
    fn test_exec_command_append_and_find_directory() {
        let mut list = Vec::new();
        exec_directory_add(
            &mut list,
            ExecDirectory {
                path: "/run/x".into(),
                kind: ExecDirectoryType::Runtime,
            },
        )
        .unwrap();
        assert!(exec_directory_find(&list, "/run/x").is_some());
    }

    #[test]
    fn test_invalid_env_detection() {
        assert!(invalid_env(""));
        assert!(invalid_env("PATH"));
        assert!(!invalid_env("PATH=/usr/bin"));
    }
}
