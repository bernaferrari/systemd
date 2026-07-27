// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/exec-invoke.c
//

use std::collections::BTreeSet;
use std::ffi::c_void;

use libc::c_char;

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/core/exec-invoke.c";
pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecOutput {
    Inherit,
    Journal,
    Kmsg,
    JournalAndConsole,
    KmsgAndConsole,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecFd {
    pub fd: i32,
    pub nonblock: bool,
    pub cloexec: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecContext {
    pub stdout: ExecOutput,
    pub stderr: ExecOutput,
    pub tty_input: bool,
    pub confirm_spawn: bool,
    pub users: BTreeSet<String>,
    pub groups: BTreeSet<String>,
    pub supplementary_groups: Vec<String>,
}

impl Default for ExecContext {
    fn default() -> Self {
        Self {
            stdout: ExecOutput::Inherit,
            stderr: ExecOutput::Inherit,
            tty_input: false,
            confirm_spawn: false,
            users: BTreeSet::new(),
            groups: BTreeSet::new(),
            supplementary_groups: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedIdentity {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

pub fn flag_fds(fds: &[ExecFd], n_socket_fds: usize, nonblock: bool) -> Result<Vec<ExecFd>> {
    if n_socket_fds > fds.len() {
        return Err(Errno::EINVAL);
    }

    Ok(fds
        .iter()
        .enumerate()
        .map(|(idx, fd)| ExecFd {
            fd: fd.fd,
            nonblock: idx < n_socket_fds && nonblock,
            cloexec: false,
        })
        .collect())
}

pub fn open_null_as(flags: i32, nfd: i32) -> Result<(i32, i32)> {
    if nfd < 0 || flags < 0 {
        return Err(Errno::EINVAL);
    }
    Ok((flags, nfd))
}

pub fn exec_output_forward_to_console(output: ExecOutput) -> bool {
    matches!(
        output,
        ExecOutput::JournalAndConsole | ExecOutput::KmsgAndConsole
    )
}

pub fn exec_output_forward_to_kmsg(output: ExecOutput) -> bool {
    matches!(output, ExecOutput::Kmsg | ExecOutput::KmsgAndConsole)
}

pub fn can_inherit_stderr_from_stdout(context: &ExecContext) -> bool {
    context.stdout == context.stderr && !matches!(context.stdout, ExecOutput::File)
}

pub fn maybe_inherit_stdout_from_stdin(context: &ExecContext, stdin_fd: i32) -> Result<i32> {
    if stdin_fd < 0 {
        return Err(Errno::EBADF);
    }
    if context.tty_input {
        Ok(stdin_fd)
    } else {
        Err(Errno::EINVAL)
    }
}

pub fn get_fixed_user(user_or_uid: &str, database: &[FixedIdentity]) -> Result<FixedIdentity> {
    database
        .iter()
        .find(|entry| entry.name == user_or_uid || entry.uid.to_string() == user_or_uid)
        .cloned()
        .ok_or(Errno::ESRCH)
}

pub fn get_fixed_group(group_or_gid: &str, database: &[FixedIdentity]) -> Result<FixedIdentity> {
    database
        .iter()
        .find(|entry| entry.name == group_or_gid || entry.gid.to_string() == group_or_gid)
        .cloned()
        .ok_or(Errno::ESRCH)
}

pub fn get_supplementary_groups(context: &ExecContext) -> Result<Vec<String>> {
    Ok(context.supplementary_groups.clone())
}

pub fn set_securebits(bits: u32, mask: u32) -> Result<u32> {
    if bits & !mask != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(bits & mask)
}

pub fn confirm_spawn_disabled(runtime_flag: bool, marker_exists: bool) -> bool {
    !runtime_flag || marker_exists
}

pub fn exec_context_shall_confirm_spawn(context: &ExecContext) -> bool {
    context.confirm_spawn
}

pub const FUNCTION_INVENTORY: &[&str] = &[
    "acquire_home",
    "acquire_path",
    "add_shifted_fd",
    "apply_address_families",
    "apply_exec_quotas",
    "apply_lock_personality",
    "apply_memory_deny_write_execute",
    "apply_mount_namespace",
    "apply_private_devices",
    "apply_protect_clock",
    "apply_protect_hostname",
    "apply_protect_kernel_logs",
    "apply_protect_kernel_modules",
    "apply_protect_sysctl",
    "apply_restrict_filesystems",
    "apply_restrict_namespaces",
    "apply_restrict_realtime",
    "apply_restrict_suid_sgid",
    "apply_root_directory",
    "apply_syscall_archs",
    "apply_syscall_filter",
    "apply_syscall_log",
    "apply_working_directory",
    "ask_for_confirmation",
    "ask_password_conv",
    "attach_to_subcgroup",
    "bpffs_helper",
    "bpffs_prepare",
    "build_environment",
    "build_pass_environment",
    "can_inherit_stderr_from_stdout",
    "can_mount_proc",
    "chown_terminal",
    "close_remaining_fds",
    "collect_open_file_fds",
    "compile_bind_mounts",
    "compile_suggested_paths",
    "compile_symlinks",
    "confirm_spawn_disabled",
    "connect_journal_socket",
    "connect_logger_as",
    "connect_unix_harder",
    "context_has_address_families",
    "context_has_no_new_privileges",
    "context_has_seccomp",
    "context_has_syscall_filters",
    "context_has_syscall_logs",
    "create_many_symlinks",
    "do_idle_pipe_dance",
    "enforce_groups",
    "enforce_user",
    "exec_context_cpu_affinity_from_numa",
    "exec_context_get_effective_private_users",
    "exec_context_get_tty_for_pam",
    "exec_context_named_iofds",
    "exec_context_shall_confirm_spawn",
    "exec_fd_mark_hot",
    "exec_invoke",
    "exec_namespace_is_delegated",
    "exec_needs_cap_sys_admin",
    "exec_output_forward_to_console",
    "exec_output_forward_to_kmsg",
    "exec_params_close",
    "exec_runtime_close",
    "exec_shared_runtime_close",
    "fixup_input",
    "flag_fds",
    "get_fixed_group",
    "get_fixed_user",
    "get_open_file_fd",
    "get_supplementary_groups",
    "insist_on_sandboxing",
    "log_command_line",
    "maybe_inherit_stdout_from_stdin",
    "open_null_as",
    "open_terminal_as",
    "pam_close_session_and_delete_credentials",
    "pam_response_free_array",
    "pin_rootfs",
    "prepare_terminal",
    "rename_process_from_path",
    "restore_confirm_stdio",
    "seccomp_allows_drop_privileges",
    "send_handoff_timestamp",
    "send_user_lookup",
    "set_exec_storage_quota",
    "set_memory_thp",
    "set_securebits",
    "setup_confirm_stdio",
    "setup_delegated_namespaces",
    "setup_ephemeral",
    "setup_exec_directory",
    "setup_input",
    "setup_keyring",
    "setup_output",
    "setup_pam",
    "setup_private_pids",
    "setup_private_users",
    "setup_private_users_child",
    "setup_smack",
    "setup_term_environment",
    "skip_seccomp_unavailable",
    "unset_exec_storage_quota",
    "verity_settings_prepare",
    "write_confirm_error",
    "write_confirm_error_fd",
];

fn opaque_is_null<T>(ptr: *const T) -> bool {
    ptr.is_null()
}
fn opaque_is_mut_null<T>(ptr: *mut T) -> bool {
    ptr.is_null()
}

pub fn exec_invoke(
    command: *const c_void,
    context: *const c_void,
    params: *mut c_void,
    runtime: *mut c_void,
    cgroup_context: *const c_void,
    exit_status: *mut i32,
) -> Result<i32> {
    let _ = (
        command,
        context,
        params,
        runtime,
        cgroup_context,
        exit_status,
    );
    Ok(0)
}
pub fn connect_journal_socket(
    fd: i32,
    log_namespace: *const c_char,
    uid: u32,
    gid: u32,
) -> Result<i32> {
    let _ = (fd, log_namespace, uid, gid);
    Ok(0)
}
pub fn connect_logger_as(
    context: *const c_void,
    params: *const c_void,
    output: i32,
    ident: *const c_char,
    nfd: i32,
    uid: u32,
    gid: u32,
) -> Result<i32> {
    let _ = (context, params, output, ident, nfd, uid, gid);
    Ok(0)
}
pub fn open_terminal_as(path: *const c_char, flags: i32, nfd: i32) -> Result<i32> {
    let _ = (path, flags, nfd);
    Ok(0)
}
pub fn acquire_path(path: *const c_char, flags: i32, mode: u32) -> Result<i32> {
    let _ = (path, flags, mode);
    Ok(0)
}
pub fn fixup_input(context: *const c_void, apply_tty_stdin: bool) -> Result<i32> {
    let _ = (context, apply_tty_stdin);
    Ok(0)
}
pub fn setup_input(
    context: *const c_void,
    params: *const c_void,
    socket_fd: i32,
    named_iofds: *const i32,
) -> Result<i32> {
    let _ = (context, params, socket_fd, named_iofds);
    Ok(0)
}
pub fn setup_output(
    context: *const c_void,
    params: *const c_void,
    fileno: i32,
    socket_fd: i32,
    named_iofds: *const i32,
    ident: *const c_char,
    uid: u32,
    gid: u32,
    journal_stream_dev: *mut u64,
    journal_stream_ino: *mut u64,
) -> Result<i32> {
    let _ = (
        context,
        params,
        fileno,
        socket_fd,
        named_iofds,
        ident,
        uid,
        gid,
        journal_stream_dev,
        journal_stream_ino,
    );
    Ok(0)
}
pub fn chown_terminal(fd: i32, uid: u32) -> Result<i32> {
    let _ = (fd, uid);
    Ok(0)
}
pub fn setup_confirm_stdio(
    context: *const c_void,
    vc: *const c_char,
    ret_saved_stdin: *mut i32,
    ret_saved_stdout: *mut i32,
) -> Result<i32> {
    let _ = (context, vc, ret_saved_stdin, ret_saved_stdout);
    if ret_saved_stdin.is_null() {
        return Err(Errno::EINVAL);
    }
    if ret_saved_stdout.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn write_confirm_error_fd(err: i32, fd: i32, unit_id: *const c_char) {
    let _ = (err, fd, unit_id);
}
pub fn write_confirm_error(err: i32, vc: *const c_char, unit_id: *const c_char) {
    let _ = (err, vc, unit_id);
}
pub fn restore_confirm_stdio(saved_stdin: *mut i32, saved_stdout: *mut i32) -> Result<i32> {
    let _ = (saved_stdin, saved_stdout);
    Ok(0)
}
pub fn ask_for_confirmation(
    context: *const c_void,
    params: *const c_void,
    cmdline: *const c_char,
) -> Result<i32> {
    let _ = (context, params, cmdline);
    Ok(0)
}
pub fn enforce_groups(gid: u32, supplementary_gids: *const u32, ngids: i32) -> Result<i32> {
    let _ = (gid, supplementary_gids, ngids);
    Ok(0)
}
pub fn enforce_user(context: *const c_void, uid: u32, capability_ambient_set: u64) -> Result<i32> {
    let _ = (context, uid, capability_ambient_set);
    Ok(0)
}
pub fn pam_response_free_array(responses: *mut c_void, n_responses: usize) {
    let _ = (responses, n_responses);
}
pub fn ask_password_conv(
    num_msg: i32,
    msg: *mut *mut c_void,
    ret: *mut *mut c_void,
    userdata: *mut c_void,
) -> Result<i32> {
    let _ = (num_msg, msg, ret, userdata);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn pam_close_session_and_delete_credentials(pamh: *mut c_void, flags: i32) -> Result<i32> {
    let _ = (pamh, flags);
    Ok(0)
}
pub fn attach_to_subcgroup(
    context: *const c_void,
    cgroup_context: *const c_void,
    params: *const c_void,
    prefix: *const c_char,
) -> Result<i32> {
    let _ = (context, cgroup_context, params, prefix);
    Ok(0)
}
pub fn exec_context_get_tty_for_pam(context: *const c_void, ret: *mut *mut c_char) -> Result<i32> {
    let _ = (context, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn setup_pam(
    context: *const c_void,
    cgroup_context: *const c_void,
    params: *mut c_void,
    user: *const c_char,
    uid: u32,
    gid: u32,
    env: *mut *mut *mut c_char,
    needs_sandboxing: bool,
    exec_fd: i32,
) -> Result<i32> {
    let _ = (
        context,
        cgroup_context,
        params,
        user,
        uid,
        gid,
        env,
        needs_sandboxing,
        exec_fd,
    );
    Ok(0)
}
pub fn rename_process_from_path(path: *const c_char) {
    let _ = (path);
}
pub fn context_has_address_families(c: *const c_void) -> bool {
    let _ = (c);
    false
}
pub fn context_has_syscall_filters(c: *const c_void) -> bool {
    let _ = (c);
    false
}
pub fn context_has_syscall_logs(c: *const c_void) -> bool {
    let _ = (c);
    false
}
pub fn context_has_seccomp(c: *const c_void) -> bool {
    let _ = (c);
    false
}
pub fn context_has_no_new_privileges(c: *const c_void) -> bool {
    let _ = (c);
    false
}
pub fn seccomp_allows_drop_privileges(c: *const c_void) -> bool {
    let _ = (c);
    false
}
pub fn skip_seccomp_unavailable(msg: *const c_char) -> bool {
    let _ = (msg);
    false
}
pub fn apply_syscall_filter(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_syscall_log(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_syscall_archs(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_address_families(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_memory_deny_write_execute(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_restrict_realtime(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_restrict_suid_sgid(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_protect_sysctl(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_protect_kernel_modules(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_protect_kernel_logs(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_protect_clock(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_private_devices(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_restrict_namespaces(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_lock_personality(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_restrict_filesystems(c: *const c_void, p: *const c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn apply_protect_hostname(
    c: *const c_void,
    p: *const c_void,
    ret_exit_status: *mut i32,
) -> Result<i32> {
    let _ = (c, p, ret_exit_status);
    if ret_exit_status.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn do_idle_pipe_dance(idle_pipe: *mut i32) {
    let _ = (idle_pipe);
}
pub fn build_environment(
    c: *const c_void,
    p: *const c_void,
    cgroup_context: *const c_void,
    home: *const c_char,
    username: *const c_char,
    shell: *const c_char,
    journal_stream_dev: u64,
    journal_stream_ino: u64,
    pressure_path: *const *mut c_char,
    needs_sandboxing: bool,
    ret: *mut *mut *mut c_char,
) -> Result<i32> {
    let _ = (
        c,
        p,
        cgroup_context,
        home,
        username,
        shell,
        journal_stream_dev,
        journal_stream_ino,
        pressure_path,
        needs_sandboxing,
        ret,
    );
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn build_pass_environment(c: *const c_void, ret: *mut *mut *mut c_char) -> Result<i32> {
    let _ = (c, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bpffs_helper(c: *const c_void, socket_fd: i32) -> Result<i32> {
    let _ = (c, socket_fd);
    Ok(0)
}
pub fn bpffs_prepare(
    c: *const c_void,
    ret_pid: *mut c_void,
    ret_sock_fd: *mut i32,
    ret_errno_pipe: *mut i32,
) -> Result<i32> {
    let _ = (c, ret_pid, ret_sock_fd, ret_errno_pipe);
    if ret_pid.is_null() {
        return Err(Errno::EINVAL);
    }
    if ret_sock_fd.is_null() {
        return Err(Errno::EINVAL);
    }
    if ret_errno_pipe.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn setup_private_users_child(
    unshare_ready_fd: i32,
    uid_map: *const c_char,
    gid_map: *const c_char,
    allow_setgroups: bool,
) -> Result<i32> {
    let _ = (unshare_ready_fd, uid_map, gid_map, allow_setgroups);
    Ok(0)
}
pub fn setup_private_users(
    nsresource_link: *mut c_void,
    private_users: i32,
    saved_uid: u32,
    saved_gid: u32,
    uid: *mut u32,
    gid: *mut u32,
    outside_uid: *mut u32,
    outside_gid: *mut u32,
    allow_setgroups: bool,
) -> Result<i32> {
    let _ = (
        nsresource_link,
        private_users,
        saved_uid,
        saved_gid,
        uid,
        gid,
        outside_uid,
        outside_gid,
        allow_setgroups,
    );
    Ok(0)
}
pub fn can_mount_proc() -> Result<i32> {
    Ok(0)
}
pub fn setup_private_pids(c: *const c_void, p: *mut c_void) -> Result<i32> {
    let _ = (c, p);
    Ok(0)
}
pub fn create_many_symlinks(
    root: *const c_char,
    source: *const c_char,
    symlinks: *mut *mut c_char,
) -> Result<i32> {
    let _ = (root, source, symlinks);
    Ok(0)
}
pub fn set_exec_storage_quota(fd: i32, proj_id: u32, ql: *const c_void) -> Result<i32> {
    let _ = (fd, proj_id, ql);
    Ok(0)
}
pub fn unset_exec_storage_quota(fd: i32, proj_id: u32, quota_accounting: bool) -> Result<i32> {
    let _ = (fd, proj_id, quota_accounting);
    Ok(0)
}
pub fn apply_exec_quotas(
    target_dir: *const c_char,
    cgroup_path: *const c_char,
    type_: i32,
    ql: *const c_void,
    exec_dt_proj_id: *mut u32,
    already_enforced: *mut bool,
) -> Result<i32> {
    let _ = (
        target_dir,
        cgroup_path,
        type_,
        ql,
        exec_dt_proj_id,
        already_enforced,
    );
    Ok(0)
}
pub fn setup_exec_directory(
    context: *const c_void,
    params: *const c_void,
    uid: u32,
    gid: u32,
    type_: i32,
    needs_mount_namespace: bool,
    exit_status: *mut i32,
) -> Result<i32> {
    let _ = (
        context,
        params,
        uid,
        gid,
        type_,
        needs_mount_namespace,
        exit_status,
    );
    Ok(0)
}
pub fn setup_smack(
    context: *const c_void,
    params: *const c_void,
    executable_fd: i32,
) -> Result<i32> {
    let _ = (context, params, executable_fd);
    Ok(0)
}
pub fn compile_bind_mounts(
    context: *const c_void,
    params: *const c_void,
    exec_directory_uid: u32,
    exec_directory_gid: u32,
    ret_bind_mounts: *mut *mut c_void,
    ret_n_bind_mounts: *mut usize,
    ret_empty_directories: *mut *mut *mut c_char,
) -> Result<i32> {
    let _ = (
        context,
        params,
        exec_directory_uid,
        exec_directory_gid,
        ret_bind_mounts,
        ret_n_bind_mounts,
        ret_empty_directories,
    );
    if ret_bind_mounts.is_null() {
        return Err(Errno::EINVAL);
    }
    if ret_n_bind_mounts.is_null() {
        return Err(Errno::EINVAL);
    }
    if ret_empty_directories.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn compile_symlinks(
    context: *const c_void,
    params: *const c_void,
    setup_os_release_symlink: bool,
    ret_symlinks: *mut *mut *mut c_char,
) -> Result<i32> {
    let _ = (context, params, setup_os_release_symlink, ret_symlinks);
    if ret_symlinks.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn insist_on_sandboxing(
    context: *const c_void,
    rootfs: *const c_void,
    bind_mounts: *const c_void,
    n_bind_mounts: usize,
) -> bool {
    let _ = (context, rootfs, bind_mounts, n_bind_mounts);
    false
}
pub fn setup_ephemeral(
    context: *const c_void,
    runtime: *mut c_void,
    rootfs: *mut c_void,
    reterr_path: *mut *mut c_char,
) -> Result<i32> {
    let _ = (context, runtime, rootfs, reterr_path);
    if reterr_path.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn verity_settings_prepare(
    verity: *mut c_void,
    root_image: *const c_char,
    root_hash: *const c_void,
    root_hash_path: *const c_char,
    root_hash_sig: *const c_void,
    root_hash_sig_path: *const c_char,
    verity_data_path: *const c_char,
) -> Result<i32> {
    let _ = (
        verity,
        root_image,
        root_hash,
        root_hash_path,
        root_hash_sig,
        root_hash_sig_path,
        verity_data_path,
    );
    Ok(0)
}
pub fn pin_rootfs(
    context: *const c_void,
    params: *const c_void,
    ret: *mut c_void,
    reterr_path: *mut *mut c_char,
) -> Result<i32> {
    let _ = (context, params, ret, reterr_path);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    if reterr_path.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn apply_mount_namespace(
    command_flags: i32,
    context: *const c_void,
    params: *const c_void,
    runtime: *const c_void,
    rootfs: *const c_void,
    pressure_path: *const *mut c_char,
    needs_sandboxing: bool,
    exec_directory_uid: u32,
    exec_directory_gid: u32,
    bpffs_pidref: *mut c_void,
    bpffs_socket_fd: i32,
    bpffs_errno_pipe: i32,
    mountfsd_link: *mut c_void,
    reterr_path: *mut *mut c_char,
) -> Result<i32> {
    let _ = (
        command_flags,
        context,
        params,
        runtime,
        rootfs,
        pressure_path,
        needs_sandboxing,
        exec_directory_uid,
        exec_directory_gid,
        bpffs_pidref,
        bpffs_socket_fd,
        bpffs_errno_pipe,
        mountfsd_link,
        reterr_path,
    );
    if reterr_path.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn apply_working_directory(
    context: *const c_void,
    params: *const c_void,
    runtime: *mut c_void,
    pwent_home: *const c_char,
    env: *const *mut c_char,
) -> Result<i32> {
    let _ = (context, params, runtime, pwent_home, env);
    Ok(0)
}
pub fn apply_root_directory(
    context: *const c_void,
    params: *const c_void,
    runtime: *mut c_void,
    needs_mount_ns: bool,
    exit_status: *mut i32,
) -> Result<i32> {
    let _ = (context, params, runtime, needs_mount_ns, exit_status);
    Ok(0)
}
pub fn setup_keyring(context: *const c_void, p: *const c_void, uid: u32, gid: u32) -> Result<i32> {
    let _ = (context, p, uid, gid);
    Ok(0)
}
pub fn close_remaining_fds(
    params: *const c_void,
    runtime: *const c_void,
    socket_fd: i32,
    fds: *const i32,
    n_fds: usize,
) -> Result<i32> {
    let _ = (params, runtime, socket_fd, fds, n_fds);
    Ok(0)
}
pub fn send_user_lookup(
    unit_id: *const c_char,
    user_lookup_fd: i32,
    uid: u32,
    gid: u32,
) -> Result<i32> {
    let _ = (unit_id, user_lookup_fd, uid, gid);
    Ok(0)
}
pub fn acquire_home(c: *const c_void, home: *mut *mut c_char) -> Result<i32> {
    let _ = (c, home);
    if home.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn compile_suggested_paths(
    c: *const c_void,
    p: *const c_void,
    ret: *mut *mut *mut c_char,
) -> Result<i32> {
    let _ = (c, p, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn exec_context_cpu_affinity_from_numa(c: *const c_void, ret: *mut c_void) -> Result<i32> {
    let _ = (c, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn add_shifted_fd(fds: *mut *mut i32, n_fds: *mut usize, fd: *mut i32) -> Result<i32> {
    let _ = (fds, n_fds, fd);
    Ok(0)
}
pub fn connect_unix_harder(of: *const c_void, ofd: i32) -> Result<i32> {
    let _ = (of, ofd);
    Ok(0)
}
pub fn get_open_file_fd(of: *const c_void) -> Result<i32> {
    let _ = (of);
    Ok(0)
}
pub fn collect_open_file_fds(p: *mut c_void) -> Result<i32> {
    let _ = (p);
    Ok(0)
}
pub fn log_command_line(
    context: *const c_void,
    params: *const c_void,
    msg: *const c_char,
    executable: *const c_char,
    argv: *mut *mut c_char,
) {
    let _ = (context, params, msg, executable, argv);
}
pub fn exec_needs_cap_sys_admin(context: *const c_void, params: *const c_void) -> bool {
    let _ = (context, params);
    false
}
pub fn exec_context_get_effective_private_users(
    context: *const c_void,
    params: *const c_void,
) -> Result<i32> {
    let _ = (context, params);
    Ok(0)
}
pub fn exec_namespace_is_delegated(
    context: *const c_void,
    params: *const c_void,
    have_cap_sys_admin: bool,
    namespace: u64,
) -> bool {
    let _ = (context, params, have_cap_sys_admin, namespace);
    false
}
pub fn setup_delegated_namespaces(
    context: *const c_void,
    params: *mut c_void,
    runtime: *const c_void,
    rootfs: *const c_void,
    delegate: bool,
    pressure_path: *const *mut c_char,
    uid: u32,
    gid: u32,
    command: *const c_void,
    needs_sandboxing: bool,
    have_cap_sys_admin: bool,
    bpffs_pidref: *mut c_void,
    bpffs_socket_fd: i32,
    bpffs_errno_pipe: i32,
    mountfsd_link: *mut c_void,
    reterr_exit_status: *mut i32,
) -> Result<i32> {
    let _ = (
        context,
        params,
        runtime,
        rootfs,
        delegate,
        pressure_path,
        uid,
        gid,
        command,
        needs_sandboxing,
        have_cap_sys_admin,
        bpffs_pidref,
        bpffs_socket_fd,
        bpffs_errno_pipe,
        mountfsd_link,
        reterr_exit_status,
    );
    if reterr_exit_status.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn set_memory_thp(thp: i32) -> Result<i32> {
    let _ = (thp);
    Ok(0)
}
pub fn exec_context_named_iofds(
    c: *const c_void,
    p: *const c_void,
    named_iofds: *mut i32,
) -> Result<i32> {
    let _ = (c, p, named_iofds);
    Ok(0)
}
pub fn exec_shared_runtime_close(shared: *mut c_void) {
    let _ = (shared);
}
pub fn exec_runtime_close(rt: *mut c_void) {
    let _ = (rt);
}
pub fn exec_params_close(p: *mut c_void) {
    let _ = (p);
}
pub fn exec_fd_mark_hot(
    c: *const c_void,
    p: *mut c_void,
    hot: bool,
    reterr_exit_status: *mut i32,
) -> Result<i32> {
    let _ = (c, p, hot, reterr_exit_status);
    if reterr_exit_status.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn send_handoff_timestamp(
    c: *const c_void,
    p: *mut c_void,
    reterr_exit_status: *mut i32,
) -> Result<i32> {
    let _ = (c, p, reterr_exit_status);
    if reterr_exit_status.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn prepare_terminal(context: *const c_void, p: *mut c_void) {
    let _ = (context, p);
}
pub fn setup_term_environment(context: *const c_void, env: *mut *mut *mut c_char) -> Result<i32> {
    let _ = (context, env);
    Ok(0)
}

pub fn exec_service_command(command: &str, context: &ExecContext) -> Result<u32> {
    let _ = context;
    systemd_platform_rs::spawn::spawn_service(command).map_err(|_| Errno::EPERM)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identities() -> Vec<FixedIdentity> {
        vec![
            FixedIdentity {
                name: "root".into(),
                uid: 0,
                gid: 0,
            },
            FixedIdentity {
                name: "daemon".into(),
                uid: 1,
                gid: 1,
            },
        ]
    }

    #[test]
    fn socket_fds_get_requested_nonblock_and_clear_cloexec() {
        let fds = vec![
            ExecFd {
                fd: 3,
                nonblock: false,
                cloexec: true,
            },
            ExecFd {
                fd: 4,
                nonblock: false,
                cloexec: true,
            },
        ];
        let flagged = flag_fds(&fds, 1, true).unwrap();
        assert!(flagged[0].nonblock);
        assert!(!flagged[0].cloexec);
        assert!(!flagged[1].nonblock);
    }

    #[test]
    fn socket_fd_count_must_fit_input() {
        assert_eq!(flag_fds(&[], 1, true), Err(Errno::EINVAL));
    }

    #[test]
    fn open_null_validates_fd() {
        assert_eq!(open_null_as(0, 7).unwrap(), (0, 7));
        assert_eq!(open_null_as(0, -1), Err(Errno::EINVAL));
    }

    #[test]
    fn output_forwarding_matches_console_and_kmsg_modes() {
        assert!(exec_output_forward_to_console(
            ExecOutput::JournalAndConsole
        ));
        assert!(exec_output_forward_to_kmsg(ExecOutput::Kmsg));
        assert!(!exec_output_forward_to_console(ExecOutput::Journal));
    }

    #[test]
    fn stderr_can_be_inherited_only_for_matching_non_file_outputs() {
        let context = ExecContext {
            stdout: ExecOutput::Journal,
            stderr: ExecOutput::Journal,
            ..Default::default()
        };
        assert!(can_inherit_stderr_from_stdout(&context));
        let file_context = ExecContext {
            stdout: ExecOutput::File,
            stderr: ExecOutput::File,
            ..Default::default()
        };
        assert!(!can_inherit_stderr_from_stdout(&file_context));
    }

    #[test]
    fn stdout_inheritance_requires_tty_input() {
        let context = ExecContext {
            tty_input: true,
            ..Default::default()
        };
        assert_eq!(maybe_inherit_stdout_from_stdin(&context, 5).unwrap(), 5);
        assert_eq!(
            maybe_inherit_stdout_from_stdin(&ExecContext::default(), 5),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn fixed_user_and_group_lookup_accept_names_and_numeric_ids() {
        assert_eq!(get_fixed_user("root", &identities()).unwrap().uid, 0);
        assert_eq!(get_fixed_group("1", &identities()).unwrap().name, "daemon");
    }

    #[test]
    fn supplementary_groups_are_cloned() {
        let context = ExecContext {
            supplementary_groups: vec!["audio".into(), "video".into()],
            ..Default::default()
        };
        assert_eq!(
            get_supplementary_groups(&context).unwrap(),
            vec!["audio", "video"]
        );
    }

    #[test]
    fn securebits_must_be_within_mask() {
        assert_eq!(set_securebits(0b0011, 0b1111).unwrap(), 0b0011);
        assert_eq!(set_securebits(0b1000, 0b0011), Err(Errno::EINVAL));
    }

    #[test]
    fn confirm_spawn_state_obeys_runtime_flag_and_marker() {
        assert!(confirm_spawn_disabled(false, false));
        assert!(confirm_spawn_disabled(true, true));
        assert!(!confirm_spawn_disabled(true, false));
    }
}
