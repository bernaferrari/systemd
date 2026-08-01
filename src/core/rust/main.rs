// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::Write;
use std::num::NonZeroUsize;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;
use systemd_basic_rs::extract_word::{
    EXTRACT_RELAX, EXTRACT_RETAIN_ESCAPE, EXTRACT_UNQUOTE, extract_first_word,
};
use systemd_core_rs::generator_setup::{GeneratorEnvironmentFacts, GeneratorRuntimeScope};
use systemd_core_rs::pid1_bus_source::{
    Pid1BusCommandInbox, Pid1BusCommandSender, pid1_bus_command_channel,
};
#[cfg(target_os = "linux")]
use systemd_core_rs::pid1_cgroup_source::CgroupSourceOwner;
#[cfg(target_os = "linux")]
use systemd_core_rs::pid1_dbus_server::PrivateBusServerTurnBudget;
#[cfg(target_os = "linux")]
use systemd_core_rs::pid1_dbus_transport::PrivateBusWireSlotConfig;
use systemd_core_rs::pid1_exec_sources::ExecStatusSourceOwner;
use systemd_core_rs::pid1_generator_lifecycle::{
    Pid1GeneratorStartupPlan, startup_path_environment, system_manager_initial_environment,
};
#[cfg(target_os = "linux")]
use systemd_core_rs::pid1_idle_pipe_source::IdlePipeSourceOwner;
use systemd_core_rs::pid1_lifecycle::{
    OuterLoopExit, SignalAction, SignalRecord, SpecialTargetMode, decode_system_signal,
    outer_loop_exit,
};
use systemd_core_rs::pid1_manager_commands::{
    DenyAllPid1CommandAuthorizer, Pid1CommandAuthorizer, Pid1CommandError,
    PrivateBusPid1CommandAuthorizer,
};
use systemd_core_rs::pid1_manager_runtime::{
    ManagerLoopExit, OuterLifecycleDisposition, ReloadPreparationResult, prepare_outer_lifecycle,
};
#[cfg(target_os = "linux")]
use systemd_core_rs::pid1_notify_source::NotifySourceOwner;
#[cfg(target_os = "linux")]
use systemd_core_rs::pid1_private_bus_runtime::{Pid1PrivateBusRuntime, Pid1PrivateBusTurnBudget};
use systemd_core_rs::pid1_socket_sources::SocketSourceOwner;
use systemd_core_rs::runtime_manager::RuntimeManager;
use systemd_core_rs::transaction::JobMode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const DATA_SIGNAL: u64 = 1;
const DATA_TIMER: u64 = 2;
const DATA_BOUND_STOP_RETRY_TIMER: u64 = 3;
const CLI_ERROR_EXIT_STATUS: i32 = 1;
const FALLBACK_DEFAULT_TARGET: &str = match option_env!("SYSTEMD_FALLBACK_DEFAULT_TARGET") {
    Some(target) => target,
    None => "graphical.target",
};

/// Test-only private-bus opt-in used by the Linux namespace harness. It is
/// deliberately path based and refused for PID 1 or the production socket,
/// so enabling this environment variable cannot silently advertise the
/// incomplete Rust API from a booted system.
const PRIVATE_BUS_TEST_SOCKET_ENV: &str = "SYSTEMD_RUST_PRIVATE_BUS_TEST_SOCKET";
const SYSTEM_PRIVATE_BUS_PATH: &str = "/run/systemd/private";
#[cfg(target_os = "linux")]
const SYSTEM_NOTIFY_SOCKET_PATH: &str = "/run/systemd/notify";

#[cfg(target_os = "linux")]
type Pid1NotifySource = NotifySourceOwner;
#[cfg(not(target_os = "linux"))]
struct Pid1NotifySource;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum CliAction {
    #[default]
    Run,
    Help,
    Version,
    Test,
}

impl CliAction {
    fn option_name(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Help => "--help",
            Self::Version => "--version",
            Self::Test => "--test",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CliOptions {
    action: CliAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliParseError<'a> {
    UnsupportedOption(&'a str),
    PositionalArgument(&'a str),
    ConflictingActions {
        previous: CliAction,
        requested: CliAction,
    },
}

impl std::fmt::Display for CliParseError<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedOption(option) => write!(
                formatter,
                "option {option:?} is not implemented by this Rust PID 1"
            ),
            Self::PositionalArgument(argument) => {
                write!(
                    formatter,
                    "positional argument {argument:?} is not supported"
                )
            }
            Self::ConflictingActions {
                previous,
                requested,
            } => write!(
                formatter,
                "cannot combine {} and {}",
                previous.option_name(),
                requested.option_name(),
            ),
        }
    }
}

fn select_cli_action(current: CliAction, requested: CliAction) -> Option<CliAction> {
    if current == CliAction::Run || current == requested {
        Some(requested)
    } else {
        None
    }
}

fn parse_cli_options(args: &[String]) -> Result<CliOptions, CliParseError<'_>> {
    let mut options = CliOptions::default();

    for arg in args {
        let requested = match arg.as_str() {
            "-h" | "--help" => CliAction::Help,
            "--version" => CliAction::Version,
            "--test" => CliAction::Test,
            _ if arg.starts_with('-') => return Err(CliParseError::UnsupportedOption(arg)),
            _ => return Err(CliParseError::PositionalArgument(arg)),
        };

        options.action = select_cli_action(options.action, requested).ok_or(
            CliParseError::ConflictingActions {
                previous: options.action,
                requested,
            },
        )?;
    }

    Ok(options)
}

fn print_help() {
    println!("systemd [OPTIONS...]");
    println!();
    println!("  -h --help            Show this help");
    println!("     --version         Show package version");
    println!("     --test            Run the experimental PID 1 signal-startup smoke");
    println!();
    println!("This Rust implementation takes no positional arguments.");
    println!("The experimental --test smoke is supported only when this binary is PID 1.");
}

/// The C implementation's `--test` mode builds and reports a complete
/// initial transaction. The developer-only Rust PID 1 has not ported that
/// contract. Its similarly named mode exists solely for the tightly scoped
/// PID-namespace signal-startup smoke in `test-rust-pid1-syscall-smoke.sh`.
///
/// Keep this decision separate from `main()` so a future implementation of
/// the actual C test contract has one explicit place to replace. In
/// particular, never let `--test` outside a PID namespace silently become a
/// normal, long-running manager invocation.
fn test_smoke_is_supported(action: CliAction, is_pid1: bool) -> bool {
    action != CliAction::Test || is_pid1
}

fn print_version() {
    println!("systemd {}", VERSION);
}

fn fail_closed(stage: &str, error: impl std::fmt::Debug) -> ! {
    boot_log(&format!("{stage} failed: {error:?}"));
    if std::process::id() == 1 {
        boot_log("fatal PID 1 failure; freezing instead of exiting and panicking the kernel");
        loop {
            std::thread::park();
        }
    }
    std::process::exit(1);
}

fn boot_log(message: &str) {
    if let Ok(mut kmsg) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
        let _ = writeln!(kmsg, "<6>systemd-rust: {message}");
    }
    eprintln!("systemd: {message}");
}

#[cfg(target_os = "linux")]
fn private_bus_test_socket_for_pid(pid: u32, path: Option<PathBuf>) -> Option<PathBuf> {
    if pid == 1 {
        return None;
    }
    let path = path?;
    if path == Path::new(SYSTEM_PRIVATE_BUS_PATH) {
        return None;
    }
    Some(path)
}

#[cfg(target_os = "linux")]
fn private_bus_test_socket() -> Option<PathBuf> {
    private_bus_test_socket_for_pid(
        std::process::id(),
        std::env::var_os(PRIVATE_BUS_TEST_SOCKET_ENV).map(PathBuf::from),
    )
}

#[cfg(not(target_os = "linux"))]
fn private_bus_test_socket() -> Option<PathBuf> {
    None
}

fn command_authorizer_for_runtime() -> Box<dyn Pid1CommandAuthorizer> {
    #[cfg(target_os = "linux")]
    if private_bus_test_socket().is_some() {
        return Box::new(PrivateBusPid1CommandAuthorizer::new(
            nix::unistd::geteuid().as_raw(),
        ));
    }
    Box::new(DenyAllPid1CommandAuthorizer)
}

fn in_initrd() -> bool {
    if let Some(value) = std::env::var_os("SYSTEMD_IN_INITRD")
        && let Some(value) = value.to_str()
        && let Some(value) = systemd_basic_rs::string_table::parse_boolean(value)
    {
        return value;
    }

    std::path::Path::new("/etc/initrd-release").exists()
}

/// Match `log_execution_mode()`'s first-boot decision before generator
/// execution. This intentionally uses the captured initrd state: publishing
/// PID 1's clean transient environment removes an inherited
/// `SYSTEMD_IN_INITRD` override before the manager is constructed.
fn detect_first_boot(in_initrd: bool) -> bool {
    if in_initrd {
        return false;
    }

    if let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") {
        for word in cmdline.split_ascii_whitespace() {
            if let Some(value) = word.strip_prefix("systemd.condition_first_boot=")
                && let Some(value) = systemd_basic_rs::string_table::parse_boolean(value)
            {
                return value;
            }
        }
    }

    match std::fs::read_to_string("/etc/machine-id") {
        Ok(machine_id) => machine_id.trim() == "uninitialized",
        // C treats a missing or unreadable machine ID as first boot.
        Err(_) => true,
    }
}

/// Translate Rust target architecture spelling to the public spelling used by
/// `architecture_to_string(uname_architecture())`. A future full PID 1 port
/// should replace this target-based subset with the shared uname/personality
/// detector; unknown targets retain their compiler spelling rather than
/// inventing an incorrect architecture name.
fn generator_architecture() -> String {
    match std::env::consts::ARCH {
        "x86_64" => "x86-64",
        "x86" | "i686" => "x86",
        "aarch64" => "arm64",
        "arm" => "arm",
        "powerpc64" => "ppc64",
        "powerpc64le" => "ppc64-le",
        architecture => architecture,
    }
    .to_string()
}

fn pid1_generator_facts(in_initrd: bool, first_boot: bool) -> GeneratorEnvironmentFacts {
    GeneratorEnvironmentFacts {
        scope: GeneratorRuntimeScope::System,
        in_initrd,
        soft_reboots_count: 0,
        first_boot: Some(first_boot),
        // C's virtualization probes are advisory: failures omit these
        // variables. Do the same until their complete safe Rust detector is
        // shared with PID 1; never substitute a partial heuristic here.
        virtualization: None,
        confidential_virtualization: None,
        architecture: generator_architecture(),
    }
}

/// Run both generator classes at the exact point before Rust creates its
/// manager. The lifecycle owner publishes the clean system-manager
/// environment before executing environment generators, then the accumulated
/// map before unit generators and unit loading.
fn run_pid1_generators(in_initrd: bool, first_boot: bool) {
    let path_environment = startup_path_environment();
    let plan = Pid1GeneratorStartupPlan::new_with_path_environment(
        Path::new("/"),
        system_manager_initial_environment(),
        &path_environment,
        pid1_generator_facts(in_initrd, first_boot),
    )
    .unwrap_or_else(|error| fail_closed("PID 1 generator startup plan", error));

    // SAFETY: main invokes this before RuntimeManager, the event loop, or
    // service children exist. The executor joins its temporary stdout reader
    // before publication, so no concurrent process-environment access exists.
    let report = unsafe_ffi!(plan.execute_and_publish())
        .unwrap_or_else(|error| fail_closed("PID 1 generator startup", error));
    if report.environment.children.iter().any(|child| {
        !matches!(
            child.status,
            systemd_core_rs::generator_runtime::GeneratorChildStatus::Exited(0)
        )
    }) {
        boot_log(
            "one or more environment generators failed; continuing as C's IGNORE_ERRORS policy requires",
        );
    }
    if !report.environment.diagnostics.is_empty() {
        boot_log(&format!(
            "ignored {} malformed environment-generator records",
            report.environment.diagnostics.len()
        ));
    }
}

fn kernel_cmdline_override_target_from(cmdline: &str, in_initrd: bool) -> Option<String> {
    let mut remaining = cmdline;
    let mut selected = None;
    let flags = EXTRACT_UNQUOTE | EXTRACT_RELAX | EXTRACT_RETAIN_ESCAPE;

    while let Ok(Some((word, rest))) = extract_first_word(remaining, None, flags) {
        remaining = rest;
        let key = if in_initrd {
            "rd.systemd.unit="
        } else {
            "systemd.unit="
        };
        if let Some(value) = word.strip_prefix(key)
            && !value.is_empty()
            && systemd_basic_rs::unit_name::unit_name_is_valid_plain_or_instance(value)
        {
            // Like parse_proc_cmdline_item(), later occurrences override
            // earlier valid ones. Invalid assignments are ignored and do not
            // erase an earlier valid selection.
            selected = Some(value.to_string());
        }
    }

    selected
}

fn kernel_cmdline_override_target(in_initrd: bool) -> Option<String> {
    let cmdline = std::fs::read_to_string("/proc/cmdline").ok()?;
    kernel_cmdline_override_target_from(&cmdline, in_initrd)
}

fn configure_unit_search_paths_from_startup_environment(startup_value: Option<OsString>) {
    let value = startup_value.unwrap_or_else(|| {
        OsString::from(
            "/etc/systemd/system.control:/run/systemd/system.control:/run/systemd/transient:/run/systemd/generator.early:/etc/systemd/system:/etc/systemd/system.attached:/run/systemd/system:/run/systemd/system.attached:/run/systemd/generator:/usr/local/lib/systemd/system:/usr/lib/systemd/system:/run/systemd/generator.late",
        )
    });
    // `lookup_paths_init()` consumes its override before C runs environment
    // generators. Preserve that ordering: a generator assignment to
    // SYSTEMD_UNIT_PATH changes the manager environment but cannot rewrite
    // the already selected lookup paths.
    // SAFETY: main invokes this during single-threaded PID 1 startup, before
    // RuntimeManager or the event loop can create concurrent work.
    unsafe_ffi!(std::env::set_var("SYSTEMD_UNIT_PATH", value));
}

#[cfg(target_os = "linux")]
fn apply_hostname_from_etc() -> std::io::Result<Option<String>> {
    let content = match std::fs::read_to_string("/etc/hostname") {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    let hostname = content.lines().next().unwrap_or("").trim();
    if hostname.is_empty() {
        return Ok(None);
    }

    let bytes = hostname.as_bytes();
    // SAFETY: `bytes` points to valid UTF-8 storage owned by this function and remains
    // alive for the duration of the call; length is passed explicitly to libc.
    let rc = unsafe_ffi!(libc::sethostname(
        bytes.as_ptr() as *const libc::c_char,
        bytes.len()
    ));
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(Some(hostname.to_string()))
}

#[cfg(not(target_os = "linux"))]
fn apply_hostname_from_etc() -> std::io::Result<Option<String>> {
    Ok(None)
}

#[cfg(target_os = "linux")]
fn mount_setup() -> std::io::Result<()> {
    // Keep PID 1 on the shared mount-setup table rather than a hand-written
    // subset. The table owns C's fatal/best-effort policy, container skips,
    // mount options, writability checks, and runtime-directory preparation;
    // duplicating only proc/sysfs/devtmpfs here silently omits devpts,
    // securityfs, pstore, efivarfs, bpf, and the shared-root contract.
    systemd_shared_rs::mount_setup::mount_setup(false, false).map_err(std::io::Error::other)
}

#[cfg(not(target_os = "linux"))]
fn mount_setup() -> std::io::Result<()> {
    Ok(())
}

/// Establish the process-wide invariants C sets before any PID 1 setup.
///
/// Neither the caller's working directory nor its file-creation mask is a
/// safe input to an init process. In particular, retaining a directory on a
/// mount that will later be unmounted prevents orderly shutdown, and a
/// restrictive inherited umask can make manager-owned runtime state
/// inaccessible to the units that need it. Do this before the test-mode
/// shortcut too: C applies these invariants before deciding whether to build
/// a normal boot transaction.
#[cfg(target_os = "linux")]
fn prepare_pid1_process_environment() -> std::io::Result<()> {
    use nix::sys::stat::{Mode, umask};

    std::env::set_current_dir("/")?;
    umask(Mode::empty());
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn prepare_pid1_process_environment() -> std::io::Result<()> {
    Ok(())
}

/// Return the cgroup root that C's `manager_setup_cgroup()` derives for PID1.
///
/// `cg_pid_get_path()` has already validated the unified cgroup path before
/// this helper sees it. C removes a trailing `init.scope` when PID1 was
/// inherited inside one, and strips trailing slashes so the hierarchy root is
/// represented by the empty path rather than `/`.
fn manager_cgroup_root_from_pid_path(pid_path: &str) -> String {
    let root = pid_path.strip_suffix("/init.scope").unwrap_or(pid_path);
    root.trim_end_matches('/').to_owned()
}

/// Turn the kernel's hierarchy-relative cgroup path into the physical
/// cgroupfs directory retained by [`RuntimeManager`].  Keep this conversion
/// separate from the cgroup operations above: the platform cgroup helpers
/// deliberately take hierarchy-relative paths, whereas the manager's
/// descriptor-confined cgroup implementation starts from an already-open
/// filesystem directory.
#[cfg(target_os = "linux")]
fn manager_cgroup_root_directory(cgroup_root: &str) -> PathBuf {
    Path::new("/sys/fs/cgroup").join(cgroup_root.trim_start_matches('/'))
}

/// Join C's manager cgroup root with its special init scope name.
fn init_scope_path(cgroup_root: &str) -> String {
    if cgroup_root.is_empty() {
        "init.scope".to_owned()
    } else {
        format!("{cgroup_root}/init.scope")
    }
}

/// C-compatible subset of `manager_setup_cgroup()` that is safe to exercise
/// against a synthetic cgroup filesystem.
///
/// In particular, manager setup does *not* enable controllers and does not
/// create `systemd.slice`: controller enablement belongs to later unit
/// realization, while the init scope is created directly below the manager's
/// inherited cgroup root.
fn bootstrap_cgroup_v2_at_root_for_pid(cgroup_root: &str, pid: i32) -> std::io::Result<()> {
    use systemd_platform_rs::cgroup;

    let scope_path = init_scope_path(cgroup_root);
    let _ = cgroup::cg_create(&scope_path)?;

    // Synthetic cgroupfs fixtures are ordinary directories, while the kernel
    // creates cgroup.procs automatically. Keep the production operation
    // faithful but let tests provide the kernel-owned file explicitly.
    cgroup::cg_attach(&scope_path, pid)?;

    // Match C's best-effort migration of userspace processes left in the
    // manager root. The move is intentionally non-fatal: PID reuse and
    // concurrent exits are normal while PID 1 takes over the hierarchy.
    if let Err(error) = cgroup::cg_migrate(cgroup_root, &scope_path, cgroup::CGroupFlags::empty()) {
        boot_log(&format!(
            "could not move remaining processes into {scope_path}, ignoring: {error}"
        ));
    }

    // Preserve C's startup validation/order: this is capability discovery,
    // not controller delegation. Unit realization later selects controllers
    // for the cgroups that need them.
    let _ = cgroup::cg_mask_supported_subtree(cgroup_root)?;
    Ok(())
}

fn bootstrap_cgroup_v2_for_pid(pid: i32) -> std::io::Result<String> {
    use systemd_platform_rs::cgroup;

    let pid_path = cgroup::cg_pid_get_path(pid)?;
    let cgroup_root = manager_cgroup_root_from_pid_path(&pid_path);
    bootstrap_cgroup_v2_at_root_for_pid(&cgroup_root, pid)?;
    Ok(cgroup_root)
}

#[cfg(target_os = "linux")]
fn cgroup_setup() -> std::io::Result<PathBuf> {
    let pid = std::process::id() as i32;
    let cgroup_root = bootstrap_cgroup_v2_for_pid(pid)?;
    Ok(manager_cgroup_root_directory(&cgroup_root))
}

#[cfg(not(target_os = "linux"))]
fn cgroup_setup() -> std::io::Result<PathBuf> {
    Ok(PathBuf::from("/sys/fs/cgroup"))
}

#[cfg(target_os = "linux")]
fn signal_setup() -> Result<(), nix::errno::Errno> {
    use systemd_platform_rs::signal;

    signal::reset_sigchld()?;
    signal::manager_signal_mask()?.thread_set_mask()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_signal_action(
    runtime: &mut RuntimeManager,
    action: SignalAction,
) -> Option<OuterLoopExit> {
    match action {
        SignalAction::ReapChildren => {
            for unit in runtime.reap_children() {
                eprintln!("systemd: unit {unit} state changed after SIGCHLD");
            }
        }
        SignalAction::StartSpecial { target, mode } => {
            let job_mode = match mode {
                SpecialTargetMode::Replace => JobMode::Replace,
                SpecialTargetMode::ReplaceIrreversibly => JobMode::ReplaceIrreversibly,
                SpecialTargetMode::Isolate => JobMode::Isolate,
            };
            if let Err(error) = runtime.start_unit_with_mode(target.unit_name(), job_mode) {
                eprintln!(
                    "systemd: signal request for {} failed: {:?}",
                    target.unit_name(),
                    error
                );
            }
        }
        SignalAction::DumpManager => {
            eprintln!(
                "systemd: manager dump: units={} active={} failed={}",
                runtime.unit_count(),
                runtime.active_count(),
                runtime.failed_count()
            );
        }
        SignalAction::RequestObjective(objective) => return outer_loop_exit(objective),
        SignalAction::ReconnectBus => {
            eprintln!(
                "systemd: D-Bus reconnect requested but authenticated manager transport is unavailable"
            );
        }
        SignalAction::CommonControl(record) => {
            eprintln!(
                "systemd: SIGRTMIN+18 command {} from pid {} is not implemented",
                record.value, record.sender_pid
            );
        }
        SignalAction::ManagerControl(control) => {
            eprintln!(
                "systemd: signal manager-control request {:?} is not implemented",
                control
            );
        }
        SignalAction::Ignore => {}
        SignalAction::Unsupported(record) => {
            eprintln!(
                "systemd: unsupported manager signal {} from pid {}",
                record.signal, record.sender_pid
            );
        }
    }

    None
}

/// `invoke_main_loop()` in C leaves `manager_loop()` before it begins any
/// objective-specific lifecycle work. Preserve that ordering here, while
/// refusing to claim a state-transferring or shutdown objective succeeded
/// until Rust can transfer every manager-owned resource safely. Unsupported
/// reload preparation is classified separately and resumes before mutation.
fn complete_outer_lifecycle(exit: ManagerLoopExit) -> ! {
    // Retain the exact manager through the fail-closed boundary. This is not
    // yet a substitute for manager serialization, but it prevents an outer
    // lifecycle implementation from accidentally starting with a dropped
    // runtime or an independently reconstructed manager.
    let (objective, runtime, pending_reply) = exit.into_parts();
    if let Some(reply) = pending_reply {
        reply.reply(Err(Pid1CommandError::Runtime(
            systemd_core_rs::ffi::Errno::EOPNOTSUPP,
        )));
    }
    let _runtime = runtime;
    fail_closed(
        "manager outer lifecycle",
        format!(
            "{} requested, but {} is not implemented; refusing to continue with stale manager state",
            objective.operation_name(),
            objective.missing_runtime_contract()
        ),
    )
}

fn drive_manager_lifecycle(
    mut runtime: RuntimeManager,
    mut notify_source: Option<Pid1NotifySource>,
) -> ! {
    // The channel owner outlives each event-loop invocation. A recoverable
    // reload must preserve commands queued behind the lifecycle request.
    let (command_sender, mut command_inbox) = pid1_bus_command_channel(
        NonZeroUsize::new(64).expect("constant command inbox capacity is nonzero"),
    )
    .unwrap_or_else(|error| fail_closed("manager bus command wake setup", error));
    let mut command_authorizer = command_authorizer_for_runtime();

    loop {
        #[cfg(target_os = "linux")]
        let loop_exit = run_event_loop(
            runtime,
            &mut command_inbox,
            command_sender.clone(),
            command_authorizer.as_mut(),
            notify_source.as_mut(),
        );
        #[cfg(not(target_os = "linux"))]
        let loop_exit = run_event_loop(
            runtime,
            &mut command_inbox,
            command_sender.clone(),
            command_authorizer.as_mut(),
        );

        match prepare_outer_lifecycle(loop_exit) {
            OuterLifecycleDisposition::ReloadPreparation(
                ReloadPreparationResult::FailedBeforePointOfNoReturn {
                    runtime: preserved_runtime,
                    error,
                    pending_reply,
                },
            ) => {
                if let Some(reply) = pending_reply {
                    reply.reply(Err(Pid1CommandError::Runtime(
                        systemd_core_rs::ffi::Errno::EOPNOTSUPP,
                    )));
                }
                boot_log(&format!(
                    "manager reload preparation failed before the point of no return: {}; continuing with unchanged runtime",
                    error
                ));
                runtime = preserved_runtime;
            }
            OuterLifecycleDisposition::TerminalUnsupported(exit) => complete_outer_lifecycle(exit),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn signal_setup() -> Result<(), nix::errno::Errno> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn reclaim_event_loop_runtime(runtime: Rc<RefCell<RuntimeManager>>) -> RuntimeManager {
    Rc::try_unwrap(runtime)
        .unwrap_or_else(|_| {
            fail_closed(
                "manager event-loop ownership",
                "event-loop callback retained a second RuntimeManager owner",
            )
        })
        .into_inner()
}

#[cfg(target_os = "linux")]
fn drain_exec_status_inbox(
    runtime: &Rc<RefCell<RuntimeManager>>,
    sources: &ExecStatusSourceOwner,
) -> bool {
    for _ in 0..32 {
        let status = match sources.pop_ready() {
            Ok(status) => status,
            Err(error) => fail_closed("exec-status readiness inbox", error),
        };
        let Some(status) = status else {
            break;
        };
        for unit in runtime.borrow_mut().observe_exec_status_ready(status) {
            eprintln!("systemd: unit {unit} exec-status changed");
        }
    }

    match sources.has_ready() {
        Ok(has_ready) => has_ready,
        Err(error) => fail_closed("exec-status readiness inbox", error),
    }
}

#[cfg(target_os = "linux")]
fn epoll_timeout_ms(timeout: Duration) -> isize {
    if timeout.is_zero() {
        return 0;
    }

    // epoll accepts integral milliseconds. Round a positive sub-millisecond
    // remainder up so an early wake cannot spin PID 1 until the deadline.
    timeout
        .as_millis()
        .max(1)
        .min(i32::MAX as u128)
        .try_into()
        .expect("timeout was clamped to i32::MAX")
}

#[cfg(target_os = "linux")]
fn random_private_bus_server_id() -> Result<[u8; 16], nix::errno::Errno> {
    systemd_libsystemd_rs::sd_id128_api::sd_id128_randomize()
        .map(|id| id.0)
        .map_err(|error| nix::errno::Errno::from_raw(error.checked_neg().unwrap_or(libc::EIO)))
}

#[cfg(test)]
mod lifecycle_ownership_tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn loop_exit_recovers_the_exact_single_manager_owner() {
        let runtime = Rc::new(RefCell::new(RuntimeManager::new()));
        assert_eq!(Rc::strong_count(&runtime), 1);

        let recovered = reclaim_event_loop_runtime(runtime);
        assert_eq!(recovered.unit_count(), 0);
        assert_eq!(recovered.active_count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_bus_test_socket_guard_never_selects_production_pid1_path() {
        assert_eq!(
            private_bus_test_socket_for_pid(1, Some(PathBuf::from("/tmp/test.sock"))),
            None
        );
        assert_eq!(
            private_bus_test_socket_for_pid(42, Some(PathBuf::from(SYSTEM_PRIVATE_BUS_PATH)),),
            None
        );
        assert_eq!(
            private_bus_test_socket_for_pid(42, Some(PathBuf::from("/tmp/test.sock"))),
            Some(PathBuf::from("/tmp/test.sock"))
        );
    }
}

#[cfg(target_os = "linux")]
fn run_event_loop(
    runtime: RuntimeManager,
    command_inbox: &mut Pid1BusCommandInbox,
    command_sender: Pid1BusCommandSender,
    command_authorizer: &mut dyn Pid1CommandAuthorizer,
    mut notify_source: Option<&mut NotifySourceOwner>,
) -> ManagerLoopExit {
    use nix::sys::epoll::EpollFlags;
    use std::os::fd::AsFd;
    use systemd_event_loop_rs::loop_::EventLoop;
    use systemd_platform_rs::signal::SignalFd;

    // sd-event-style dispatch is single-threaded. Keep one manager owner on
    // this thread instead of introducing poisonable cross-thread locking.
    let runtime = Rc::new(RefCell::new(runtime));

    let mut event_loop = match EventLoop::new() {
        Ok(el) => el,
        Err(error) => fail_closed("event-loop setup", error),
    };
    if let Err(error) = command_inbox.register(&mut event_loop) {
        fail_closed("manager bus command wake registration", error);
    }
    if let Some(source) = notify_source.as_deref_mut()
        && let Err(error) = source.register(&mut event_loop)
    {
        fail_closed("notify socket event-source registration", error);
    }

    let signal_mask = match systemd_platform_rs::signal::manager_signal_mask() {
        Ok(mask) => mask,
        Err(error) => fail_closed("manager signal-mask setup", error),
    };
    let realtime_min = match systemd_platform_rs::signal::realtime_signal_range() {
        Ok((minimum, _)) => minimum,
        Err(error) => fail_closed("manager realtime-signal setup", error),
    };
    let signal_inbox = Rc::new(RefCell::new(VecDeque::<SignalRecord>::new()));
    // Keep the sole owning descriptor alive for the whole event loop. The callback only borrows
    // it through this shared owner; it must never recreate an owner from the raw descriptor.
    let signalfd = Rc::new(match SignalFd::from_mask(&signal_mask) {
        Ok(fd) => fd,
        Err(error) => fail_closed("manager signal-fd setup", error),
    });

    let signalfd_callback = Rc::clone(&signalfd);
    let signal_inbox_callback = Rc::clone(&signal_inbox);

    if let Err(error) = event_loop.add_source(
        signalfd.as_fd(),
        EpollFlags::EPOLLIN,
        DATA_SIGNAL,
        Box::new(move |events, _data| {
            if events & (EpollFlags::EPOLLIN.bits() as u32) != 0
                && let Some(info) = signalfd_callback.read_signal()?
            {
                signal_inbox_callback.borrow_mut().push_back(SignalRecord {
                    signal: info.ssi_signo as i32,
                    sender_pid: info.ssi_pid,
                    sender_uid: info.ssi_uid,
                    code: info.ssi_code,
                    value: info.ssi_int,
                });
            }
            Ok(())
        }),
    ) {
        fail_closed("manager signal-fd registration", error);
    }

    if let Some(timer) = runtime
        .borrow()
        .clone_bound_stop_retry_timer_for_registration()
    {
        let callback_timer = Rc::clone(&timer);
        if let Err(error) = event_loop.add_source(
            timer.as_fd(),
            EpollFlags::EPOLLIN,
            DATA_BOUND_STOP_RETRY_TIMER,
            Box::new(move |events, _data| {
                if events & (EpollFlags::EPOLLIN.bits() as u32) != 0 {
                    callback_timer.consume().map_err(|error| {
                        nix::errno::Errno::from_raw(error.raw_os_error().unwrap_or(libc::EIO))
                    })?;
                }
                Ok(())
            }),
        ) {
            eprintln!("systemd: failed to register BindsTo= retry timerfd with epoll: {error}");
        }
    }

    if let Ok(timerfd) = systemd_event_loop_rs::timerfd::timerfd_create() {
        let timerfd = Rc::new(timerfd);
        if let Err(error) = systemd_event_loop_rs::timerfd::timerfd_settime(&timerfd, 5_000_000) {
            eprintln!("systemd: failed to arm timerfd: {error}");
        } else {
            let callback_timerfd = Rc::clone(&timerfd);
            if let Err(error) = event_loop.add_source(
                timerfd.as_fd(),
                EpollFlags::EPOLLIN,
                DATA_TIMER,
                Box::new(move |events, _data| {
                    if events & (EpollFlags::EPOLLIN.bits() as u32) != 0 {
                        systemd_event_loop_rs::timerfd::timerfd_read(&callback_timerfd)?;
                        systemd_event_loop_rs::timerfd::timerfd_settime(
                            &callback_timerfd,
                            5_000_000,
                        )?;
                    }
                    Ok(())
                }),
            ) {
                eprintln!("systemd: failed to register timerfd with epoll: {error}");
            }
        }
    }

    // The installed PID 1 deliberately does not bind its production private
    // socket yet: the checked Rust API is still smaller than C's complete
    // vtable/policy surface. An explicit non-PID1 test pathname nevertheless
    // exercises this exact event-loop ownership path without changing boot
    // behavior or replacing `/run/systemd/private`.
    let mut private_bus = private_bus_test_socket().map(|path| {
        let config = PrivateBusWireSlotConfig::new(
            64 * 1024,
            NonZeroUsize::new(64).expect("private-bus pending limit is nonzero"),
            16 * 1024,
            64 * 1024,
        );
        let connection_limit = NonZeroUsize::new(4096).expect("private-bus limit is nonzero");
        let server = Pid1PrivateBusRuntime::bind_path(
            &mut event_loop,
            &path,
            nix::unistd::geteuid().as_raw(),
            command_sender.clone(),
            connection_limit,
            config,
        )
        .unwrap_or_else(|error| fail_closed("experimental private-bus test setup", error));
        eprintln!(
            "systemd: experimental Rust private-bus event-loop integration enabled at {}",
            path.display()
        );
        server
    });

    if private_bus.is_none() {
        // Do not open an outbound bus client and drain messages. PID 1 needs
        // an authenticated server transport, org.freedesktop.systemd1
        // ownership, and a dispatcher mutating this exact RuntimeManager.
        // Those pieces are not complete enough for the installed path.
        eprintln!("systemd: manager D-Bus API unavailable (server transport not enabled)");
    }

    eprintln!("systemd: entering event loop");
    let mut socket_sources = SocketSourceOwner::new();
    let mut exec_status_sources = ExecStatusSourceOwner::new();
    #[cfg(target_os = "linux")]
    let mut idle_pipe_source = IdlePipeSourceOwner::new();
    let mut cgroup_source = CgroupSourceOwner::new();

    loop {
        // This is the Rust manager-loop equivalent of the idle-pipe close in
        // C's manager_check_finished(): it runs only from the outer manager
        // turn, after job dispatch/reaping, never from an arbitrary nested
        // transaction submission.
        #[cfg(target_os = "linux")]
        runtime.borrow_mut().close_idle_pipe_when_manager_idle();
        let listeners = runtime.borrow().get_socket_listeners();
        if let Err(error) = socket_sources.reconcile(&mut event_loop, listeners) {
            fail_closed("socket event-source reconciliation", error);
        }
        let exec_statuses = runtime.borrow().pending_exec_statuses();
        if let Err(error) = exec_status_sources.reconcile(&mut event_loop, exec_statuses) {
            fail_closed("exec-status event-source reconciliation", error);
        }
        let cgroup_descriptor = runtime
            .borrow()
            .cgroup_event_descriptor()
            .unwrap_or_else(|error| fail_closed("cgroup event descriptor snapshot", error));
        if let Err(error) = cgroup_source.reconcile(&mut event_loop, cgroup_descriptor) {
            fail_closed("cgroup event-source reconciliation", error);
        }
        #[cfg(target_os = "linux")]
        {
            let idle_pipe = runtime
                .borrow()
                .idle_pipe_alert_descriptor()
                .unwrap_or_else(|error| fail_closed("idle-pipe descriptor snapshot", error));
            if let Err(error) = idle_pipe_source.reconcile(&mut event_loop, idle_pipe) {
                fail_closed("idle-pipe event-source reconciliation", error);
            }
        }

        // Reap children and update service states on SIGCHLD events as well as periodically
        let changed = {
            let mut guard = runtime.borrow_mut();
            guard.reap_children()
        };
        for unit in &changed {
            eprintln!("systemd: unit {} state changed", unit);
        }

        // If a prior epoll batch hit the bounded exec-status dispatch budget,
        // finish those already-delivered notifications before another blocking
        // wait. This is the part that removes the former five-second polling
        // latency for all but the first ready Type=exec service.
        if drain_exec_status_inbox(&runtime, &exec_status_sources) {
            continue;
        }

        let service_timeout = runtime
            .borrow()
            .service_event_timeout(Duration::from_secs(5));
        match event_loop.run_once(epoll_timeout_ms(service_timeout)) {
            Ok(_) => {
                let notify_batch = if let Some(source) = notify_source.as_deref_mut() {
                    runtime
                        .borrow_mut()
                        .dispatch_authenticated_notify_source(
                            source,
                            NonZeroUsize::new(32)
                                .expect("constant notify dispatch budget is nonzero"),
                        )
                        .unwrap_or_else(|error| fail_closed("authenticated notify dispatch", error))
                } else {
                    systemd_core_rs::runtime_manager::NotifyDispatchBatch::default()
                };
                // C processes notifications before SIGCHLD so a direct child
                // can publish READY= before reaping observes its exit. A
                // full bounded batch stays nonblocking on the next turn.
                if notify_batch.budget_exhausted {
                    continue;
                }
                #[cfg(target_os = "linux")]
                {
                    let idle_alert = idle_pipe_source
                        .take_alert()
                        .unwrap_or_else(|error| fail_closed("idle-pipe alert inbox", error));
                    if idle_alert {
                        // `manager_dispatch_idle_pipe_fd()` acknowledges the
                        // child's bounded wait by closing both pipe pairs. The
                        // following reconciliation removes the stale epoll clone.
                        // C additionally suppresses manager status output while
                        // an on-console unit owns the TTY. Rust PID 1 has not yet
                        // implemented C's n_on_console/status-printing ownership,
                        // so there is no live status route to suppress here; this
                        // keeps the descriptor/startup ordering faithful without
                        // pretending that console-arbitration parity exists.
                        runtime.borrow_mut().close_idle_pipe();
                        continue;
                    }
                }
                let record = signal_inbox.borrow_mut().pop_front();
                if let Some(record) = record {
                    let action = decode_system_signal(record, realtime_min);
                    let exit = {
                        let mut guard = runtime.borrow_mut();
                        apply_signal_action(&mut guard, action)
                    };
                    if let Some(exit) = exit {
                        if let Some(source) = notify_source.as_deref_mut() {
                            source.unregister(&mut event_loop).unwrap_or_else(|error| {
                                fail_closed("notify socket teardown", error)
                            });
                        }
                        exec_status_sources
                            .unregister(&mut event_loop)
                            .unwrap_or_else(|error| {
                                fail_closed("exec-status event-source teardown", error)
                            });
                        socket_sources
                            .unregister(&mut event_loop)
                            .unwrap_or_else(|error| {
                                fail_closed("socket event-source teardown", error)
                            });
                        idle_pipe_source
                            .unregister(&mut event_loop)
                            .unwrap_or_else(|error| {
                                fail_closed("idle-pipe event-source teardown", error)
                            });
                        cgroup_source
                            .unregister(&mut event_loop)
                            .unwrap_or_else(|error| {
                                fail_closed("cgroup event-source teardown", error)
                            });
                        if let Some(private_bus) = private_bus.as_mut() {
                            private_bus
                                .unregister(&mut event_loop)
                                .unwrap_or_else(|error| fail_closed("private-bus teardown", error));
                        }
                        command_inbox
                            .unregister(&mut event_loop)
                            .unwrap_or_else(|error| {
                                fail_closed("manager bus command-source teardown", error)
                            });
                        return ManagerLoopExit::from_signal(
                            exit,
                            reclaim_event_loop_runtime(runtime),
                        );
                    }
                }
                // One epoll wait may queue several short-lived child status
                // pipes. Drain a bounded batch before sleeping again so a
                // ready Type=exec acknowledgement is never delayed by the
                // normal five-second timeout; keep the batch finite so other
                // PID 1 sources still make progress under a fork storm.
                if drain_exec_status_inbox(&runtime, &exec_status_sources) {
                    continue;
                }
                let cgroup_ready = cgroup_source
                    .take_ready()
                    .unwrap_or_else(|error| fail_closed("cgroup event inbox", error));
                if cgroup_ready {
                    // This runs after signal dispatch/reaping in the manager
                    // turn. The callback itself never borrows RuntimeManager,
                    // preserving C's deferred cgroup-empty ordering.
                    runtime.borrow_mut().dispatch_cgroup_events();
                }
                let socket_unit = match socket_sources.pop_activation() {
                    Ok(socket_unit) => socket_unit,
                    Err(error) => fail_closed("socket activation inbox", error),
                };
                if let Some(socket_unit) = socket_unit {
                    let activation = runtime.borrow_mut().spawn_service_for_socket(&socket_unit);
                    if let Err(error) = activation {
                        eprintln!(
                            "systemd: socket activation for {socket_unit} failed: {error:?}; disabling the listener"
                        );
                        runtime.borrow_mut().fail_socket_activation(&socket_unit);
                    }
                }
                let command_outcome = if let Some(private_bus) = private_bus.as_mut() {
                    private_bus
                        .dispatch_turn(
                            &mut event_loop,
                            command_inbox,
                            &mut runtime.borrow_mut(),
                            command_authorizer,
                            Pid1PrivateBusTurnBudget {
                                server: PrivateBusServerTurnBudget {
                                    accepts: NonZeroUsize::new(32)
                                        .expect("private-bus accept budget is nonzero"),
                                    authentication_steps: NonZeroUsize::new(64)
                                        .expect("private-bus authentication budget is nonzero"),
                                    promotions: NonZeroUsize::new(64)
                                        .expect("private-bus promotion budget is nonzero"),
                                    wire_events: NonZeroUsize::new(64)
                                        .expect("private-bus wire budget is nonzero"),
                                    reply_polls_per_event: NonZeroUsize::new(8)
                                        .expect("private-bus reply budget is nonzero"),
                                },
                                manager_commands: NonZeroUsize::new(32)
                                    .expect("manager command budget is nonzero"),
                                reply_slots: NonZeroUsize::new(64)
                                    .expect("private-bus reply slot budget is nonzero"),
                                reply_polls_per_slot: NonZeroUsize::new(8)
                                    .expect("private-bus reply poll budget is nonzero"),
                            },
                            random_private_bus_server_id,
                        )
                        .unwrap_or_else(|error| fail_closed("private-bus manager turn", error))
                        .manager
                } else {
                    command_inbox
                        .dispatch_pending(
                            &mut runtime.borrow_mut(),
                            command_authorizer,
                            NonZeroUsize::new(32)
                                .expect("constant command dispatch budget is nonzero"),
                        )
                        .unwrap_or_else(|error| {
                            fail_closed("manager bus command wake accounting", error)
                        })
                };
                if let Some(request) = command_outcome.objective {
                    if let Some(source) = notify_source.as_deref_mut() {
                        source
                            .unregister(&mut event_loop)
                            .unwrap_or_else(|error| fail_closed("notify socket teardown", error));
                    }
                    exec_status_sources
                        .unregister(&mut event_loop)
                        .unwrap_or_else(|error| {
                            fail_closed("exec-status event-source teardown", error)
                        });
                    socket_sources
                        .unregister(&mut event_loop)
                        .unwrap_or_else(|error| fail_closed("socket event-source teardown", error));
                    idle_pipe_source
                        .unregister(&mut event_loop)
                        .unwrap_or_else(|error| {
                            fail_closed("idle-pipe event-source teardown", error)
                        });
                    cgroup_source
                        .unregister(&mut event_loop)
                        .unwrap_or_else(|error| fail_closed("cgroup event-source teardown", error));
                    if let Some(private_bus) = private_bus.as_mut() {
                        private_bus
                            .unregister(&mut event_loop)
                            .unwrap_or_else(|error| fail_closed("private-bus teardown", error));
                    }
                    command_inbox
                        .unregister(&mut event_loop)
                        .unwrap_or_else(|error| {
                            fail_closed("manager bus command-source teardown", error)
                        });
                    return ManagerLoopExit::from_command(
                        reclaim_event_loop_runtime(runtime),
                        request,
                    )
                    .expect("command dispatch rejects the non-request Ok objective");
                }
            }
            Err(e) => {
                fail_closed("event-loop dispatch", e);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_event_loop(
    mut runtime: RuntimeManager,
    _command_inbox: &mut Pid1BusCommandInbox,
    _command_sender: Pid1BusCommandSender,
    _command_authorizer: &mut dyn Pid1CommandAuthorizer,
) -> ManagerLoopExit {
    eprintln!("systemd: running in non-Linux test mode, polling loop");

    loop {
        let changed = runtime.reap_children();
        for unit in &changed {
            eprintln!("systemd: unit {} state changed", unit);
        }

        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let options = match parse_cli_options(&args[1..]) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("systemd: {error}");
            eprintln!("Try 'systemd --help' for more information.");
            std::process::exit(CLI_ERROR_EXIT_STATUS);
        }
    };

    match options.action {
        CliAction::Help => {
            print_help();
            return;
        }
        CliAction::Version => {
            print_version();
            return;
        }
        CliAction::Run | CliAction::Test => {}
    }

    let is_pid1 = std::process::id() == 1;
    if !test_smoke_is_supported(options.action, is_pid1) {
        eprintln!(
            "systemd: --test is currently only the experimental Rust PID 1 signal-startup smoke; run it as PID 1 in an isolated PID namespace"
        );
        std::process::exit(CLI_ERROR_EXIT_STATUS);
    }

    let mut pid1_boot_facts = None;
    // C freezes lookup paths before environment generators can mutate the
    // manager environment. Capture this once while the original startup
    // environment is still available.
    let startup_unit_path = std::env::var_os("SYSTEMD_UNIT_PATH");
    let manager_cgroup_root = if is_pid1 {
        boot_log("running as PID 1, starting early boot sequence");

        if let Err(error) = prepare_pid1_process_environment() {
            fail_closed("PID 1 process environment setup", error);
        }

        if options.action == CliAction::Test {
            boot_log("PID 1 test mode enabled; skipping mount/cgroup/hostname setup");
            boot_log("step 4/9: signal setup");
            if let Err(e) = signal_setup() {
                fail_closed("signal setup", e);
            }
            boot_log("PID 1 test mode complete; skipping manager startup and event loop");
            return;
        }

        boot_log("step 1/9: mount setup");
        if let Err(e) = mount_setup() {
            fail_closed("mount setup", e);
        }

        boot_log("step 2/9: cgroup setup");
        let cgroup_root = cgroup_setup().unwrap_or_else(|error| fail_closed("cgroup setup", error));

        boot_log("step 3/9: apply hostname");
        match apply_hostname_from_etc() {
            Ok(Some(hostname)) => boot_log(&format!("hostname set from /etc/hostname: {hostname}")),
            Ok(None) => boot_log("hostname unchanged (no /etc/hostname entry)"),
            Err(e) => boot_log(&format!("hostname setup skipped due to error: {e}")),
        }

        boot_log("step 4/9: signal setup");
        if let Err(e) = signal_setup() {
            fail_closed("signal setup", e);
        }
        let in_initrd = in_initrd();
        let first_boot = detect_first_boot(in_initrd);
        pid1_boot_facts = Some((in_initrd, first_boot));
        Some(cgroup_root)
    } else {
        None
    };

    if let Some((in_initrd, first_boot)) = pid1_boot_facts {
        boot_log("step 5/9: run environment and unit generators");
        run_pid1_generators(in_initrd, first_boot);
    }

    boot_log("step 6/9: configure unit search paths and initialize manager");
    configure_unit_search_paths_from_startup_environment(startup_unit_path);
    let mut runtime = manager_cgroup_root
        .map(RuntimeManager::new_at_cgroup_root)
        .unwrap_or_else(RuntimeManager::new);

    // Match C's manager_new(): a system manager without an opened cgroup
    // authority cannot safely account, contain, or reap its units.  The
    // constructor remains infallible for synthetic unit tests, so enforce the
    // production failure boundary here before any boot transaction is queued.
    if is_pid1 && let Err(error) = runtime.validate_cgroup_root() {
        fail_closed("manager cgroup capability", error);
    }

    // Bind the receiver before the boot transaction can spawn a service. The
    // pathname is never inherited from the caller: it becomes a capability
    // held by this exact manager and is injected only into eligible direct
    // children. Refusing an existing entry is intentional; PID 1 must never
    // unlink a pathname it cannot prove it owns.
    #[cfg(target_os = "linux")]
    let notify_source = if is_pid1 {
        let source = NotifySourceOwner::bind(Path::new(SYSTEM_NOTIFY_SOCKET_PATH))
            .unwrap_or_else(|error| fail_closed("authenticated notify socket bind", error));
        runtime
            .configure_authenticated_notify_socket(source.path())
            .unwrap_or_else(|error| {
                fail_closed("authenticated notify socket configuration", error)
            });
        Some(source)
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let notify_source: Option<Pid1NotifySource> = None;

    if is_pid1 {
        boot_log("step 7/9: select boot target");
        let (in_initrd, _) =
            pid1_boot_facts.expect("PID 1 boot facts were captured before generators");
        let cmdline_target = kernel_cmdline_override_target(in_initrd);
        if cmdline_target.is_some() {
            boot_log(&format!(
                "using kernel override target: {}",
                cmdline_target.as_deref().expect("checked above")
            ));
        }

        boot_log("step 8/9: start selected target");
        let start_result = if let Some(selected) = cmdline_target {
            runtime
                .start_boot_target(&selected)
                .map(|()| selected.to_string())
        } else {
            runtime.start_default_target(in_initrd, FALLBACK_DEFAULT_TARGET)
        };

        match start_result {
            Ok(selected) => {
                boot_log(&format!("selected boot target: {selected}"));
            }
            Err(e) => {
                // do_queue_default_job() tries rescue.target when the selected
                // or implicit default target cannot be loaded or queued.
                boot_log(&format!(
                    "target startup failed: {e:?}; falling back to rescue.target"
                ));
                if let Err(rescue_error) = runtime.start_boot_target("rescue.target") {
                    fail_closed("rescue target startup", rescue_error);
                }
            }
        };
        // The C manager queues the selected target and immediately enters its
        // event loop. Unit activation is asynchronous; failures are reported
        // by the normal job transaction and do not cause PID 1 to invent an
        // emergency.target fallback after a wall-clock timeout.
    } else if let Err(e) = runtime.start_default_target(false, FALLBACK_DEFAULT_TARGET) {
        eprintln!("systemd: target startup failed: {:?}", e);
    }

    boot_log("step 9/9: enter event loop");
    boot_log(&format!(
        "{} units loaded, {} active",
        runtime.unit_count(),
        runtime.active_count()
    ));

    drive_manager_lifecycle(runtime, notify_source);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use systemd_shared_rs::tests::TestEnvironment;

    #[test]
    fn parse_cli_options_defaults_to_run() {
        let options = parse_cli_options(&[]).unwrap();
        assert_eq!(options.action, CliAction::Run);
    }

    #[test]
    fn parse_cli_options_supports_test_mode_flag() {
        let args = vec!["--test".to_string()];
        let options = parse_cli_options(&args).unwrap();
        assert_eq!(options.action, CliAction::Test);
    }

    #[test]
    fn test_smoke_never_turns_into_a_non_pid1_manager_loop() {
        assert!(test_smoke_is_supported(CliAction::Test, true));
        assert!(!test_smoke_is_supported(CliAction::Test, false));
        assert!(test_smoke_is_supported(CliAction::Run, false));
        assert!(test_smoke_is_supported(CliAction::Help, false));
    }

    #[test]
    fn parse_cli_options_accepts_repeated_action() {
        let args = vec!["--help".to_string(), "-h".to_string()];
        let options = parse_cli_options(&args).unwrap();
        assert_eq!(options.action, CliAction::Help);
    }

    #[test]
    fn parse_cli_options_rejects_conflicting_actions() {
        let args = vec!["--help".to_string(), "--version".to_string()];
        assert_eq!(
            parse_cli_options(&args),
            Err(CliParseError::ConflictingActions {
                previous: CliAction::Help,
                requested: CliAction::Version,
            })
        );
    }

    #[test]
    fn parse_cli_options_rejects_unimplemented_and_malformed_options() {
        for argument in ["--dump-core", "--test=true"] {
            let args = vec![argument.to_string()];
            assert_eq!(
                parse_cli_options(&args),
                Err(CliParseError::UnsupportedOption(argument))
            );
        }
    }

    #[test]
    fn parse_cli_options_rejects_positional_arguments() {
        let args = vec!["default.target".to_string()];
        assert_eq!(
            parse_cli_options(&args),
            Err(CliParseError::PositionalArgument("default.target"))
        );
    }

    #[test]
    fn pid1_default_target_prefers_default_target() {
        assert_eq!(
            systemd_core_rs::runtime_manager::default_target_name(
                false,
                false,
                true,
                FALLBACK_DEFAULT_TARGET,
            ),
            "default.target"
        );
    }

    #[test]
    fn pid1_default_target_uses_the_configured_host_fallback() {
        assert_eq!(
            systemd_core_rs::runtime_manager::default_target_name(
                false,
                false,
                false,
                FALLBACK_DEFAULT_TARGET,
            ),
            FALLBACK_DEFAULT_TARGET
        );
    }

    #[test]
    fn initrd_prefers_initrd_target_and_only_falls_back_to_default_target() {
        assert_eq!(
            systemd_core_rs::runtime_manager::default_target_name(
                true,
                true,
                true,
                FALLBACK_DEFAULT_TARGET,
            ),
            "initrd.target"
        );
        assert_eq!(
            systemd_core_rs::runtime_manager::default_target_name(
                true,
                false,
                true,
                FALLBACK_DEFAULT_TARGET,
            ),
            "default.target"
        );
        assert_eq!(
            systemd_core_rs::runtime_manager::default_target_name(
                true,
                false,
                false,
                FALLBACK_DEFAULT_TARGET,
            ),
            "default.target"
        );
    }

    #[test]
    fn kernel_target_override_respects_initrd_prefix_and_last_assignment() {
        let cmdline = "systemd.unit=host-a.target rd.systemd.unit=initrd-a.target \
                       systemd.unit='host-final.target' rd.systemd.unit=initrd-final.target";
        assert_eq!(
            kernel_cmdline_override_target_from(cmdline, false).as_deref(),
            Some("host-final.target")
        );
        assert_eq!(
            kernel_cmdline_override_target_from(cmdline, true).as_deref(),
            Some("initrd-final.target")
        );
    }

    #[test]
    fn invalid_kernel_target_does_not_erase_an_earlier_valid_assignment() {
        assert_eq!(
            kernel_cmdline_override_target_from(
                "systemd.unit=rescue.target systemd.unit=not-a-unit",
                false,
            )
            .as_deref(),
            Some("rescue.target")
        );
        assert_eq!(
            kernel_cmdline_override_target_from("rd.systemd.unit=@bad.target", true),
            None
        );
    }

    #[test]
    fn cgroup_root_matches_manager_setup_cgroup_scope_handling() {
        assert_eq!(manager_cgroup_root_from_pid_path("/"), "");
        assert_eq!(manager_cgroup_root_from_pid_path("/init.scope"), "");
        assert_eq!(
            manager_cgroup_root_from_pid_path("/tenant.slice/init.scope"),
            "/tenant.slice"
        );
        assert_eq!(
            manager_cgroup_root_from_pid_path("/tenant.slice/"),
            "/tenant.slice"
        );
        assert_eq!(init_scope_path(""), "init.scope");
        assert_eq!(init_scope_path("/tenant.slice"), "/tenant.slice/init.scope");
    }

    #[test]
    fn cgroup_bootstrap_attaches_init_scope_below_inherited_root_without_delegation() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe_ffi!(TestEnvironment::lock());
        let dir = std::env::temp_dir().join("test-systemd-main-cgroup-bootstrap");
        fs::create_dir_all(&dir).unwrap();
        let inherited = dir.join("tenant.slice");
        let scope = inherited.join("init.scope");
        fs::create_dir_all(&scope).unwrap();
        fs::write(inherited.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        fs::write(inherited.join("cgroup.subtree_control"), "pre-existing\n").unwrap();
        fs::write(inherited.join("cgroup.procs"), "888\n").unwrap();
        // cgroupfs creates this file with a new cgroup. The ordinary-directory
        // fixture supplies it so the safe attach operation is testable.
        fs::write(scope.join("cgroup.procs"), "").unwrap();

        environment.set("SYSTEMD_CGROUP_ROOT", dir.display().to_string());

        bootstrap_cgroup_v2_at_root_for_pid("/tenant.slice", 777).unwrap();

        assert!(scope.exists());
        assert!(!dir.join("systemd.slice").exists());
        assert!(!dir.join("init.scope").exists());

        // C manager setup only discovers support; it does not enable or
        // disable controllers at this stage.
        assert_eq!(
            fs::read_to_string(inherited.join("cgroup.subtree_control")).unwrap(),
            "pre-existing\n"
        );

        let init_procs = fs::read_to_string(scope.join("cgroup.procs")).unwrap();
        assert!(init_procs.contains("777"));
        assert!(init_procs.contains("888"));

        let _ = fs::remove_dir_all(&dir);
    }
}
