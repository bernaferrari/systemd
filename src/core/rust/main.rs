// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Write;
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::time::Duration;
use systemd_basic_rs::extract_word::{
    EXTRACT_RELAX, EXTRACT_RETAIN_ESCAPE, EXTRACT_UNQUOTE, extract_first_word,
};
use systemd_core_rs::pid1_bus_source::{Pid1BusCommandInbox, pid1_bus_command_channel};
use systemd_core_rs::pid1_exec_sources::ExecStatusSourceOwner;
#[cfg(target_os = "linux")]
use systemd_core_rs::pid1_idle_pipe_source::IdlePipeSourceOwner;
use systemd_core_rs::pid1_lifecycle::{
    OuterLoopExit, SignalAction, SignalRecord, SpecialTargetMode, decode_system_signal,
    outer_loop_exit,
};
use systemd_core_rs::pid1_manager_commands::{DenyAllPid1CommandAuthorizer, Pid1CommandError};
use systemd_core_rs::pid1_manager_runtime::{
    ManagerLoopExit, OuterLifecycleDisposition, ReloadPreparationResult, prepare_outer_lifecycle,
};
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

fn in_initrd() -> bool {
    if let Some(value) = std::env::var_os("SYSTEMD_IN_INITRD")
        && let Some(value) = value.to_str()
        && let Some(value) = systemd_basic_rs::string_table::parse_boolean(value)
    {
        return value;
    }

    std::path::Path::new("/etc/initrd-release").exists()
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

fn configure_unit_search_paths() {
    if std::env::var_os("SYSTEMD_UNIT_PATH").is_none() {
        // SAFETY: main() invokes this during single-threaded PID 1 startup,
        // before RuntimeManager or the event loop can create concurrent work.
        unsafe {
            std::env::set_var(
                "SYSTEMD_UNIT_PATH",
                "/etc/systemd/system:/run/systemd/system:/usr/lib/systemd/system:/lib/systemd/system",
            );
        }
    }
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
    let rc = unsafe { libc::sethostname(bytes.as_ptr() as *const libc::c_char, bytes.len()) };
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
    use systemd_platform_rs::mount::{self, MountFlags};

    let mounts: &[(&str, &str, &str, MountFlags, &str)] = &[
        (
            "proc",
            "/proc",
            "proc",
            MountFlags::MS_NOSUID | MountFlags::MS_NOEXEC | MountFlags::MS_NODEV,
            "",
        ),
        (
            "sysfs",
            "/sys",
            "sysfs",
            MountFlags::MS_NOSUID | MountFlags::MS_NOEXEC | MountFlags::MS_NODEV,
            "",
        ),
        (
            "devtmpfs",
            "/dev",
            "devtmpfs",
            MountFlags::MS_NOSUID,
            "mode=0755",
        ),
        (
            "tmpfs",
            "/dev/shm",
            "tmpfs",
            MountFlags::MS_NOSUID | MountFlags::MS_NODEV,
            "mode=1777",
        ),
        (
            "tmpfs",
            "/run",
            "tmpfs",
            MountFlags::MS_NOSUID | MountFlags::MS_NODEV,
            "mode=0755",
        ),
        ("tmpfs", "/tmp", "tmpfs", MountFlags::empty(), ""),
        (
            "cgroup2",
            "/sys/fs/cgroup",
            "cgroup2",
            MountFlags::MS_NOSUID | MountFlags::MS_NODEV | MountFlags::MS_NOEXEC,
            "",
        ),
    ];

    for &(src, tgt, fstype, flags, data) in mounts {
        if let Err(e) = mount::mount(src, tgt, fstype, flags, data) {
            let already_mounted = matches!(e.raw_os_error(), Some(code) if code == libc::EBUSY);
            if e.kind() != std::io::ErrorKind::AlreadyExists && !already_mounted {
                eprintln!("systemd: mount {} → {}: {}", src, tgt, e);
                return Err(e);
            }
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn mount_setup() -> std::io::Result<()> {
    Ok(())
}

fn bootstrap_cgroup_v2_for_pid(pid: i32) -> std::io::Result<()> {
    use systemd_platform_rs::cgroup::{self, CgroupController};

    let requested = CgroupController::Cpu.mask()
        | CgroupController::Cpuset.mask()
        | CgroupController::Io.mask()
        | CgroupController::Memory.mask()
        | CgroupController::Pids.mask();

    let supported = cgroup::cg_mask_supported()?;
    let _ = cgroup::cg_enable(supported, requested, "/")?;

    let _ = cgroup::cg_create("systemd.slice")?;
    let _ = cgroup::cg_create("init.scope")?;

    let init_procs = cgroup::cg_get_path("init.scope", Some("cgroup.procs"))?;
    if !init_procs.exists() {
        let _ = std::fs::write(&init_procs, "");
    }

    cgroup::cg_attach("init.scope", pid)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn cgroup_setup() -> std::io::Result<()> {
    let pid = std::process::id() as i32;
    bootstrap_cgroup_v2_for_pid(pid)?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn cgroup_setup() -> std::io::Result<()> {
    Ok(())
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

fn drive_manager_lifecycle(mut runtime: RuntimeManager) -> ! {
    // The channel owner outlives each event-loop invocation. A recoverable
    // reload must preserve commands queued behind the lifecycle request.
    let (_command_sender, mut command_inbox) = pid1_bus_command_channel(
        NonZeroUsize::new(64).expect("constant command inbox capacity is nonzero"),
    )
    .unwrap_or_else(|error| fail_closed("manager bus command wake setup", error));
    let mut command_authorizer = DenyAllPid1CommandAuthorizer;

    loop {
        match prepare_outer_lifecycle(run_event_loop(
            runtime,
            &mut command_inbox,
            &mut command_authorizer,
        )) {
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
}

#[cfg(target_os = "linux")]
fn run_event_loop(
    runtime: RuntimeManager,
    command_inbox: &mut Pid1BusCommandInbox,
    command_authorizer: &mut DenyAllPid1CommandAuthorizer,
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

    // Do not open an outbound bus client and drain messages. PID 1 needs an
    // authenticated server transport, org.freedesktop.systemd1 ownership, and
    // a dispatcher mutating this exact RuntimeManager. Those pieces are not
    // implemented yet, so the manager API remains explicitly unavailable.
    eprintln!("systemd: manager D-Bus API unavailable (server transport not implemented)");

    eprintln!("systemd: entering event loop");
    let mut socket_sources = SocketSourceOwner::new();
    let mut exec_status_sources = ExecStatusSourceOwner::new();
    #[cfg(target_os = "linux")]
    let mut idle_pipe_source = IdlePipeSourceOwner::new();

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
                let command_outcome = command_inbox
                    .dispatch_pending(
                        &mut runtime.borrow_mut(),
                        command_authorizer,
                        NonZeroUsize::new(32).expect("constant command dispatch budget is nonzero"),
                    )
                    .unwrap_or_else(|error| {
                        fail_closed("manager bus command wake accounting", error)
                    });
                if let Some(request) = command_outcome.objective {
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
    _command_authorizer: &mut DenyAllPid1CommandAuthorizer,
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

    if is_pid1 {
        boot_log("running as PID 1, starting early boot sequence");

        if options.action == CliAction::Test {
            boot_log("PID 1 test mode enabled; skipping mount/cgroup/hostname setup");
            boot_log("step 4/8: signal setup");
            if let Err(e) = signal_setup() {
                fail_closed("signal setup", e);
            }
            boot_log("PID 1 test mode complete; skipping manager startup and event loop");
            return;
        }

        boot_log("step 1/8: mount setup");
        if let Err(e) = mount_setup() {
            fail_closed("mount setup", e);
        }

        boot_log("step 2/8: cgroup setup");
        if let Err(e) = cgroup_setup() {
            fail_closed("cgroup setup", e);
        }

        boot_log("step 3/8: apply hostname");
        match apply_hostname_from_etc() {
            Ok(Some(hostname)) => boot_log(&format!("hostname set from /etc/hostname: {hostname}")),
            Ok(None) => boot_log("hostname unchanged (no /etc/hostname entry)"),
            Err(e) => boot_log(&format!("hostname setup skipped due to error: {e}")),
        }

        boot_log("step 4/8: signal setup");
        if let Err(e) = signal_setup() {
            fail_closed("signal setup", e);
        }
    }

    boot_log("step 5/8: configure unit search paths and initialize manager");
    configure_unit_search_paths();
    let mut runtime = RuntimeManager::new();

    if is_pid1 {
        boot_log("step 6/8: select boot target");
        let in_initrd = in_initrd();
        let cmdline_target = kernel_cmdline_override_target(in_initrd);
        if cmdline_target.is_some() {
            boot_log(&format!(
                "using kernel override target: {}",
                cmdline_target.as_deref().expect("checked above")
            ));
        }

        boot_log("step 7/8: start selected target");
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

    boot_log("step 8/8: enter event loop");
    boot_log(&format!(
        "{} units loaded, {} active",
        runtime.unit_count(),
        runtime.active_count()
    ));

    drive_manager_lifecycle(runtime);
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
    fn cgroup_bootstrap_creates_init_scope_and_enables_controllers() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        let dir = std::env::temp_dir().join("test-systemd-main-cgroup-bootstrap");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("cgroup.controllers"),
            "cpu cpuset io memory pids\n",
        )
        .unwrap();
        fs::write(dir.join("cgroup.subtree_control"), "").unwrap();

        environment.set("SYSTEMD_CGROUP_ROOT", dir.display().to_string());

        bootstrap_cgroup_v2_for_pid(777).unwrap();

        assert!(dir.join("systemd.slice").exists());
        assert!(dir.join("init.scope").exists());

        let subtree = fs::read_to_string(dir.join("cgroup.subtree_control")).unwrap();
        assert!(subtree.contains("+cpu"));
        assert!(subtree.contains("+cpuset"));
        assert!(subtree.contains("+io"));
        assert!(subtree.contains("+memory"));
        assert!(subtree.contains("+pids"));

        let init_procs = fs::read_to_string(dir.join("init.scope").join("cgroup.procs")).unwrap();
        assert!(init_procs.contains("777"));

        let _ = fs::remove_dir_all(&dir);
    }
}
