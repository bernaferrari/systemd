// SPDX-License-Identifier: LGPL-2.1-or-later

#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use systemd_libsystemd_rs::sd_daemon_checks::sd_listen_fds_with_names;
use systemd_shared_rs::unsafe_ffi;
use systemd_udev_rs::udev_db_monitor::{
    ControlCommand, UDEV_RUN_DIR, UdevRuntimeResources, default_rules_dirs,
    encode_uevent_properties, initialize_udev_runtime_with_fds,
};
use systemd_udev_rs::udev_rule_engine::{
    AssignToken, DeviceEvent, DeviceNodeKind, DeviceNodeSpec, EngineError, MatchToken,
    NodeApplyError, Rule, is_safe_device_relative_path, process_device_event,
};
use systemd_udev_rs::udev_rules::{
    RuleKey, RuleToken, UdevRuleOperatorType, parse_rules_from_dirs,
};
use systemd_udev_rs::udev_worker::{parse_worker_notify_payload, try_again_message};
use systemd_udev_rs::uevent_netlink::{KobjectUeventReceiver, UeventAction, UeventMessage};
use tokio::runtime::Builder;
use tokio::sync::mpsc;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const KERNEL_UEVENT_MULTICAST_GROUP: u32 = 1;
const ACTIVATION_CTRL_SOCKET_NAME: &str = "systemd-udevd-control.socket";
const ACTIVATION_KERNEL_SOCKET_NAME: &str = "systemd-udevd-kernel.socket";
const ACTIVATION_MONITOR_SOCKET_NAME: &str = "systemd-udevd-monitor.socket";
const LOCKED_EVENT_REQUEUE_DELAY: Duration = Duration::from_millis(200);
const LOCKED_EVENT_REQUEUE_MAX_RETRIES: u16 = 900;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationFdKind {
    Control,
    Kernel,
    Monitor,
}

#[derive(Default)]
struct ActivationSockets {
    control_fd: Option<OwnedFd>,
    kernel_fd: Option<OwnedFd>,
    monitor_fd: Option<OwnedFd>,
}

#[derive(Clone, Default)]
struct RulesProcessingQueue {
    queue: Arc<Mutex<VecDeque<QueuedEvent>>>,
}

impl RulesProcessingQueue {
    fn enqueue(&self, event: UeventMessage) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.push_back(QueuedEvent::new(event));
        }
    }

    fn enqueue_retry(&self, event: UeventMessage, retries: u16) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.push_back(QueuedEvent::retry(event, retries));
        }
    }

    fn dequeue_ready(&self) -> Option<QueuedEvent> {
        let mut queue = self.queue.lock().ok()?;
        match queue.front() {
            Some(front) if front.ready_at <= Instant::now() => queue.pop_front(),
            _ => None,
        }
    }

    fn has_pending(&self) -> bool {
        self.queue
            .lock()
            .map(|queue| !queue.is_empty())
            .unwrap_or(false)
    }
}

#[derive(Clone)]
struct QueuedEvent {
    event: UeventMessage,
    retry_count: u16,
    ready_at: Instant,
}

impl QueuedEvent {
    fn new(event: UeventMessage) -> Self {
        Self {
            event,
            retry_count: 0,
            ready_at: Instant::now(),
        }
    }

    fn retry(event: UeventMessage, retry_count: u16) -> Self {
        Self {
            event,
            retry_count,
            ready_at: Instant::now() + LOCKED_EVENT_REQUEUE_DELAY,
        }
    }
}

struct QueueFileLifecycle {
    queue_path: PathBuf,
    present: bool,
}

impl QueueFileLifecycle {
    fn new(run_dir: &Path) -> Self {
        Self {
            queue_path: run_dir.join("queue"),
            present: false,
        }
    }

    fn sync(&mut self, has_pending: bool) {
        if has_pending && !self.present {
            if let Err(err) = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.queue_path)
            {
                eprintln!(
                    "systemd-udevd: failed to create queue file {}: {}",
                    self.queue_path.display(),
                    err
                );
            } else {
                self.present = true;
            }
            return;
        }

        if !has_pending && self.present {
            match std::fs::remove_file(&self.queue_path) {
                Ok(_) => self.present = false,
                Err(err) if err.kind() == io::ErrorKind::NotFound => self.present = false,
                Err(err) => {
                    eprintln!(
                        "systemd-udevd: failed to remove queue file {}: {}",
                        self.queue_path.display(),
                        err
                    )
                }
            }
        }
    }
}

fn map_activation_name(name: &str) -> Option<ActivationFdKind> {
    match name {
        ACTIVATION_CTRL_SOCKET_NAME => Some(ActivationFdKind::Control),
        ACTIVATION_KERNEL_SOCKET_NAME => Some(ActivationFdKind::Kernel),
        ACTIVATION_MONITOR_SOCKET_NAME => Some(ActivationFdKind::Monitor),
        _ => None,
    }
}

fn close_activation_fd(fd: i32) {
    // SAFETY: fd comes from LISTEN_FDS and is owned by this process.
    let _ = unsafe_ffi!(libc::close(fd));
}

fn collect_activation_sockets() -> ActivationSockets {
    let mut sockets = ActivationSockets::default();
    // SAFETY: main() collects and consumes activation descriptors before
    // constructing UdevRuntime or starting any worker threads.
    let passed = match unsafe_ffi!(sd_listen_fds_with_names(true)) {
        Ok(passed) => passed,
        Err(err) => {
            eprintln!("systemd-udevd: failed to parse socket activation fds: {err:?}");
            return sockets;
        }
    };

    for passed_fd in passed {
        let slot = match map_activation_name(&passed_fd.name) {
            Some(ActivationFdKind::Control) => &mut sockets.control_fd,
            Some(ActivationFdKind::Kernel) => &mut sockets.kernel_fd,
            Some(ActivationFdKind::Monitor) => &mut sockets.monitor_fd,
            None => {
                close_activation_fd(passed_fd.fd);
                continue;
            }
        };

        if slot.is_some() {
            close_activation_fd(passed_fd.fd);
            continue;
        }

        // SAFETY: fd originates from systemd socket activation and ownership is transferred here.
        *slot = Some(unsafe_ffi!(OwnedFd::from_raw_fd(passed_fd.fd)));
    }

    sockets
}

fn spawn_kernel_uevent_receiver(
    queue: RulesProcessingQueue,
    inherited_kernel_socket: Option<OwnedFd>,
) -> io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("rust-uevent-netlink".to_string())
        .spawn(move || {
            let runtime = match Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    eprintln!("systemd-udevd: failed to build tokio runtime for uevents: {err}");
                    return;
                }
            };

            runtime.block_on(async move {
                let receiver = match inherited_kernel_socket {
                    Some(fd) => KobjectUeventReceiver::from_fd(fd),
                    None => KobjectUeventReceiver::new(KERNEL_UEVENT_MULTICAST_GROUP),
                };
                let receiver = match receiver {
                    Ok(receiver) => receiver,
                    Err(err) => {
                        eprintln!(
                            "systemd-udevd: failed to bind kernel uevent netlink socket: {err}"
                        );
                        return;
                    }
                };

                let (tx, mut rx) = mpsc::channel::<UeventMessage>(1024);
                tokio::spawn(async move {
                    if let Err(err) = receiver.run(tx).await {
                        eprintln!("systemd-udevd: kernel uevent receiver stopped: {err}");
                    }
                });

                while let Some(event) = rx.recv().await {
                    queue.enqueue(event);
                }
            });
        })
        .map_err(|_| io::Error::from_raw_os_error(libc::EIO))
}

fn print_help() {
    println!("systemd-udevd [OPTIONS...]");
    println!();
    println!("  -h --help             Show this help");
    println!("     --version          Show package version");
    println!("  -d --daemon           Detach and run as daemon");
    println!("  -D --debug            Enable debug output");
    println!("     --children-max=N   Set maximum number of workers");
    println!("     --resolve-names=early|late|never  When to resolve names");
}

fn print_version() {
    println!("systemd-udevd {}", VERSION);
}

fn parse_mode(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_prefix = trimmed.strip_prefix("0o").unwrap_or(trimmed);
    u32::from_str_radix(without_prefix, 8)
        .ok()
        .or_else(|| trimmed.parse::<u32>().ok())
}

fn compile_match_token(token: &RuleToken) -> Option<MatchToken> {
    if token.operator != UdevRuleOperatorType::Match {
        return None;
    }

    match &token.key {
        RuleKey::Action => Some(MatchToken::Action(token.value.clone())),
        RuleKey::Devpath => Some(MatchToken::Devpath(token.value.clone())),
        RuleKey::Kernel => Some(MatchToken::Kernel(token.value.clone())),
        RuleKey::Subsystem => Some(MatchToken::Subsystem(token.value.clone())),
        RuleKey::Env(key) => Some(MatchToken::Env {
            key: key.clone(),
            value: token.value.clone(),
        }),
        RuleKey::Tag => Some(MatchToken::Tag(token.value.clone())),
        _ => None,
    }
}

fn compile_assign_token(token: &RuleToken) -> Option<AssignToken> {
    if !matches!(
        token.operator,
        UdevRuleOperatorType::Add
            | UdevRuleOperatorType::Assign
            | UdevRuleOperatorType::AssignFinal
    ) {
        return None;
    }

    match &token.key {
        RuleKey::Name => Some(AssignToken::Name(token.value.clone())),
        RuleKey::Symlink => Some(AssignToken::Symlink(token.value.clone())),
        RuleKey::Owner => Some(AssignToken::Owner(token.value.clone())),
        RuleKey::Group => Some(AssignToken::Group(token.value.clone())),
        RuleKey::Mode => parse_mode(&token.value).map(AssignToken::Mode),
        RuleKey::Env(key) => Some(AssignToken::Env {
            key: key.clone(),
            value: token.value.clone(),
        }),
        RuleKey::Tag => Some(AssignToken::Tag(token.value.clone())),
        RuleKey::Run(_) => Some(AssignToken::Run(token.value.clone())),
        _ => None,
    }
}

fn compile_rule(tokens: &[RuleToken]) -> Option<Rule> {
    let mut matches = Vec::new();
    let mut assigns = Vec::new();

    for token in tokens {
        if let Some(mt) = compile_match_token(token) {
            matches.push(mt);
            continue;
        }
        if let Some(at) = compile_assign_token(token) {
            assigns.push(at);
            continue;
        }
        // Skip rule lines we cannot map safely in this first vertical slice.
        return None;
    }

    Some(Rule { matches, assigns })
}

fn load_supported_rules(rule_dirs: &[PathBuf]) -> Vec<Rule> {
    let dir_refs: Vec<&Path> = rule_dirs.iter().map(PathBuf::as_path).collect();
    let parsed = match parse_rules_from_dirs(&dir_refs) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!(
                "systemd-udevd: failed to parse rules files, continuing with empty set: {err:?}"
            );
            return Vec::new();
        }
    };

    let mut compiled = Vec::new();
    for line in parsed {
        if let Some(rule) = compile_rule(&line) {
            compiled.push(rule);
        }
    }
    compiled
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticDevPerm {
    path: PathBuf,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}

fn is_static_name_candidate(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.contains('%') && !name.contains('$')
}

fn parse_numeric_id(value: &str) -> Option<u32> {
    value.parse::<u32>().ok()
}

fn derive_static_dev_perms(rules: &[Rule]) -> Vec<StaticDevPerm> {
    let mut by_path: BTreeMap<PathBuf, StaticDevPerm> = BTreeMap::new();

    for rule in rules {
        let mut name: Option<String> = None;
        let mut mode: Option<u32> = None;
        let mut uid: Option<u32> = None;
        let mut gid: Option<u32> = None;

        for assign in &rule.assigns {
            match assign {
                AssignToken::Name(value) if is_static_name_candidate(value) => {
                    name = Some(value.clone());
                }
                AssignToken::Mode(value) => mode = Some(*value),
                AssignToken::Owner(value) => uid = parse_numeric_id(value),
                AssignToken::Group(value) => gid = parse_numeric_id(value),
                _ => {}
            }
        }

        let Some(name) = name else {
            continue;
        };
        if mode.is_none() && uid.is_none() && gid.is_none() {
            continue;
        }

        let path = Path::new("/dev").join(name);
        by_path.insert(
            path.clone(),
            StaticDevPerm {
                path,
                mode,
                uid,
                gid,
            },
        );
    }

    by_path.into_values().collect()
}

fn apply_static_dev_perms(rules: &[Rule]) {
    let specs = derive_static_dev_perms(rules);
    if specs.is_empty() {
        return;
    }

    let mut applied = 0usize;
    for spec in specs {
        if !spec.path.exists() {
            continue;
        }

        if let Some(mode) = spec.mode
            && let Err(err) =
                std::fs::set_permissions(&spec.path, std::fs::Permissions::from_mode(mode))
        {
            eprintln!(
                "systemd-udevd: failed applying static mode on {}: {}",
                spec.path.display(),
                err
            );
            continue;
        }

        if spec.uid.is_some() || spec.gid.is_some() {
            let uid = spec.uid.unwrap_or(u32::MAX);
            let gid = spec.gid.unwrap_or(u32::MAX);
            let Ok(c_path) = std::ffi::CString::new(spec.path.as_os_str().as_bytes()) else {
                continue;
            };
            // SAFETY: c_path is NUL-terminated and points to a valid filesystem path bytestring.
            if unsafe_ffi!(libc::chown(c_path.as_ptr(), uid, gid)) < 0 {
                eprintln!(
                    "systemd-udevd: failed applying static owner/group on {}: {}",
                    spec.path.display(),
                    io::Error::last_os_error()
                );
                continue;
            }
        }

        applied += 1;
    }

    if applied > 0 {
        eprintln!(
            "systemd-udevd: applied static permissions to {} existing devnodes",
            applied
        );
    }
}

fn action_to_str(action: &UeventAction) -> Option<&'static str> {
    match action {
        UeventAction::Add => Some("add"),
        UeventAction::Remove => Some("remove"),
        UeventAction::Change => Some("change"),
        _ => None,
    }
}

fn kernel_from_uevent(event: &UeventMessage) -> String {
    if let Some(devname) = event.devname.as_ref() {
        let trimmed = devname.trim_start_matches('/');
        if let Some(name) = trimmed.rsplit('/').next()
            && !name.is_empty()
        {
            return name.to_string();
        }
    }
    event
        .devpath
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn tags_from_uevent(event: &UeventMessage) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    for key in ["TAGS", "TAG"] {
        if let Some(value) = event.properties.get(key) {
            for tag in value
                .split(':')
                .map(str::trim)
                .filter(|tag| !tag.is_empty())
            {
                tags.insert(tag.to_string());
            }
        }
    }
    tags
}

fn to_device_event(event: &UeventMessage) -> Option<DeviceEvent> {
    let action = action_to_str(&event.action)?;
    Some(DeviceEvent {
        action: action.to_string(),
        devpath: event.devpath.clone(),
        kernel: kernel_from_uevent(event),
        subsystem: event.subsystem.clone().unwrap_or_default(),
        env: event.properties.clone(),
        tags: tags_from_uevent(event),
    })
}

fn device_path_from_devname(devname: &str) -> Result<PathBuf, NodeApplyError> {
    if !is_safe_device_relative_path(devname) {
        return Err(NodeApplyError::InvalidPath);
    }

    Ok(Path::new("/dev").join(devname))
}

fn node_spec_for_uevent(event: &UeventMessage) -> Result<Option<DeviceNodeSpec>, NodeApplyError> {
    let Some(devname) = event.devname.as_ref() else {
        return Ok(None);
    };
    let path = device_path_from_devname(devname)?;
    let (Some(major), Some(minor)) = (event.major, event.minor) else {
        return Ok(None);
    };

    let mode = event
        .properties
        .get("DEVMODE")
        .and_then(|value| parse_mode(value))
        .unwrap_or(0o660);
    let uid = event
        .properties
        .get("DEVUID")
        .and_then(|value| value.parse::<u32>().ok());
    let gid = event
        .properties
        .get("DEVGID")
        .and_then(|value| value.parse::<u32>().ok());

    let kind = if event.subsystem.as_deref() == Some("block") {
        DeviceNodeKind::Block
    } else {
        DeviceNodeKind::Char
    };

    Ok(Some(DeviceNodeSpec {
        dev_root: PathBuf::from("/dev"),
        path,
        kind,
        major,
        minor,
        mode,
        uid,
        gid,
    }))
}

enum EventProcessingResult {
    Processed,
    RetryLocked,
}

fn should_retry_locked_error(err: &EngineError) -> bool {
    matches!(
        err,
        EngineError::Node(NodeApplyError::Io(code))
            if *code == -libc::EBUSY || *code == -libc::EAGAIN || *code == -libc::EWOULDBLOCK
    )
}

fn process_queued_event(event: &UeventMessage, rules: &[Rule]) -> EventProcessingResult {
    let Some(device_event) = to_device_event(event) else {
        return EventProcessingResult::Processed;
    };

    // Validate DEVNAME for all actions. Removal must not silently accept an
    // event that would select a path outside /dev if removal gains filesystem
    // handling later.
    let node_spec = match node_spec_for_uevent(event) {
        Ok(spec) if device_event.action != "remove" => spec,
        Ok(_) => None,
        Err(err) => {
            eprintln!(
                "systemd-udevd: rejecting uevent action={} devpath={}: {:?}",
                device_event.action, device_event.devpath, err
            );
            return EventProcessingResult::Processed;
        }
    };

    match process_device_event(&device_event, rules, node_spec.as_ref(), false) {
        Ok(_) => EventProcessingResult::Processed,
        Err(err) if should_retry_locked_error(&err) => EventProcessingResult::RetryLocked,
        Err(err) => {
            eprintln!(
                "systemd-udevd: failed to process uevent action={} devpath={}: {:?}",
                device_event.action, device_event.devpath, err
            );
            EventProcessingResult::Processed
        }
    }
}

fn reload_compiled_rules(rules: &mut Vec<Rule>, rules_dirs: &[PathBuf], reason: &str) {
    *rules = load_supported_rules(rules_dirs);
    eprintln!(
        "systemd-udevd: reloaded {} supported rule lines ({reason})",
        rules.len()
    );
}

fn maybe_broadcast_event(event: &UeventMessage, runtime: &mut UdevRuntimeResources) {
    if runtime.monitor.subscriber_count() == 0 {
        return;
    }

    let payload_fields: Vec<(String, String)> = event
        .properties
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if payload_fields.is_empty() {
        return;
    }

    let payload = match encode_uevent_properties(&payload_fields) {
        Ok(payload) => payload,
        Err(err) => {
            eprintln!("systemd-udevd: failed to encode monitor event payload: {err:?}");
            return;
        }
    };

    if let Err(err) = runtime.monitor.broadcast(&payload) {
        eprintln!("systemd-udevd: failed to broadcast monitor event: {err}");
    }
}

fn drain_control_commands(
    runtime: &mut UdevRuntimeResources,
    rules: &mut Vec<Rule>,
    rules_dirs: &[PathBuf],
) {
    loop {
        let command = match runtime.control.try_receive_command() {
            Ok(command) => command,
            Err(err) => {
                eprintln!("systemd-udevd: failed reading control command: {err}");
                return;
            }
        };

        let Some(command) = command else {
            return;
        };

        match command {
            ControlCommand::Subscribe(path) => {
                runtime.monitor.register_subscriber(path);
            }
            ControlCommand::Unsubscribe(path) => {
                runtime.monitor.unregister_subscriber(&path);
            }
            ControlCommand::ReloadRules => {
                reload_compiled_rules(rules, rules_dirs, "control command");
            }
        }
    }
}

fn poll_rules_reload_watcher(
    runtime: &mut UdevRuntimeResources,
    rules: &mut Vec<Rule>,
    rules_dirs: &[PathBuf],
) {
    let Some(watcher) = runtime.rules_watcher.as_ref() else {
        return;
    };

    let events = match watcher.read_events() {
        Ok(events) => events,
        Err(err) => {
            eprintln!("systemd-udevd: failed reading rules inotify events: {err}");
            return;
        }
    };

    if events.iter().any(|event| event.should_reload_rules()) {
        reload_compiled_rules(rules, rules_dirs, "rules directory update");
    }
}

fn handle_worker_notify_retry(queue: &RulesProcessingQueue, queued: QueuedEvent) {
    let payload = try_again_message(&queued.event.devpath);
    let parsed = parse_worker_notify_payload(&payload);
    if !parsed.try_again {
        return;
    }

    if queued.retry_count >= LOCKED_EVENT_REQUEUE_MAX_RETRIES {
        eprintln!(
            "systemd-udevd: giving up locked event retry for devpath={} after {} retries",
            queued.event.devpath, queued.retry_count
        );
        return;
    }

    queue.enqueue_retry(queued.event, queued.retry_count + 1);
}

fn run_processing_loop(
    queue: RulesProcessingQueue,
    mut rules: Vec<Rule>,
    rules_dirs: Vec<PathBuf>,
    mut runtime: Option<UdevRuntimeResources>,
    run_dir: PathBuf,
) -> ! {
    let mut queue_file = QueueFileLifecycle::new(&run_dir);

    if let Some(resources) = runtime.as_mut()
        && let Err(err) = resources.control.set_nonblocking(true)
    {
        eprintln!("systemd-udevd: failed to make control socket non-blocking: {err}");
    }

    loop {
        if let Some(resources) = runtime.as_mut() {
            drain_control_commands(resources, &mut rules, &rules_dirs);
            poll_rules_reload_watcher(resources, &mut rules, &rules_dirs);
        }

        if let Some(queued) = queue.dequeue_ready() {
            match process_queued_event(&queued.event, &rules) {
                EventProcessingResult::Processed => {
                    if let Some(resources) = runtime.as_mut() {
                        maybe_broadcast_event(&queued.event, resources);
                    }
                }
                EventProcessingResult::RetryLocked => {
                    handle_worker_notify_retry(&queue, queued);
                }
            }
            queue_file.sync(queue.has_pending());
            continue;
        }

        queue_file.sync(queue.has_pending());
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    for arg in &args[1..] {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "--version" => {
                print_version();
                return;
            }
            _ => {}
        }
    }

    let rules_dirs = default_rules_dirs();
    let mut activation_sockets = collect_activation_sockets();
    let run_dir = std::env::var("SYSTEMD_UDEVD_RUN_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(UDEV_RUN_DIR));
    let runtime = match initialize_udev_runtime_with_fds(
        &run_dir,
        &rules_dirs,
        activation_sockets.control_fd.take(),
        activation_sockets.monitor_fd.take(),
    ) {
        Ok(runtime) => Some(runtime),
        Err(err) => {
            eprintln!(
                "systemd-udevd: failed to initialize udev runtime paths/sockets (continuing): {}",
                err
            );
            None
        }
    };
    let compiled_rules = load_supported_rules(&rules_dirs);
    apply_static_dev_perms(&compiled_rules);
    let rules_queue = RulesProcessingQueue::default();
    let _uevent_receiver = match spawn_kernel_uevent_receiver(
        rules_queue.clone(),
        activation_sockets.kernel_fd.take(),
    ) {
        Ok(handle) => Some(handle),
        Err(err) => {
            eprintln!(
                "systemd-udevd: failed to start kernel uevent receiver thread (continuing): {}",
                err
            );
            None
        }
    };
    run_processing_loop(rules_queue, compiled_rules, rules_dirs, runtime, run_dir);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;

    #[test]
    fn compile_rule_supports_basic_action_subsystem_match_and_assignments() {
        let tokens = vec![
            RuleToken {
                key: RuleKey::Action,
                operator: UdevRuleOperatorType::Match,
                value: "add".to_string(),
            },
            RuleToken {
                key: RuleKey::Subsystem,
                operator: UdevRuleOperatorType::Match,
                value: "block".to_string(),
            },
            RuleToken {
                key: RuleKey::Symlink,
                operator: UdevRuleOperatorType::Add,
                value: "disk/by-id/mock".to_string(),
            },
            RuleToken {
                key: RuleKey::Mode,
                operator: UdevRuleOperatorType::Assign,
                value: "0660".to_string(),
            },
        ];

        let rule = compile_rule(&tokens).expect("supported tokens should compile");
        assert_eq!(rule.matches.len(), 2);
        assert_eq!(rule.assigns.len(), 2);
    }

    #[test]
    fn to_device_event_maps_basic_uevent_fields() {
        let mut properties = BTreeMap::new();
        properties.insert("ACTION".to_string(), "add".to_string());
        properties.insert("DEVPATH".to_string(), "/devices/mock0".to_string());
        properties.insert("TAGS".to_string(), "seat:systemd".to_string());

        let event = UeventMessage {
            action: UeventAction::Add,
            devpath: "/devices/mock0".to_string(),
            subsystem: Some("block".to_string()),
            devname: Some("sda".to_string()),
            devtype: Some("disk".to_string()),
            major: Some(8),
            minor: Some(0),
            seqnum: Some(42),
            properties,
        };

        let mapped = to_device_event(&event).expect("add action should be mapped");
        assert_eq!(mapped.action, "add");
        assert_eq!(mapped.kernel, "sda");
        assert!(mapped.tags.contains("seat"));
        assert!(mapped.tags.contains("systemd"));
    }

    #[test]
    fn devname_paths_stay_beneath_dev() {
        assert_eq!(
            device_path_from_devname("input/event0").unwrap(),
            PathBuf::from("/dev/input/event0")
        );

        for invalid in [
            "",
            "/etc/passwd",
            "../etc/passwd",
            "input/../event0",
            "./event0",
        ] {
            assert_eq!(
                device_path_from_devname(invalid),
                Err(NodeApplyError::InvalidPath),
                "{invalid} must be rejected"
            );
        }
    }

    #[test]
    fn activation_socket_name_mapping_matches_c_service_names() {
        assert_eq!(
            map_activation_name(ACTIVATION_CTRL_SOCKET_NAME),
            Some(ActivationFdKind::Control)
        );
        assert_eq!(
            map_activation_name(ACTIVATION_KERNEL_SOCKET_NAME),
            Some(ActivationFdKind::Kernel)
        );
        assert_eq!(map_activation_name("unexpected"), None);
    }

    #[test]
    fn locked_retry_classifier_catches_transient_node_errors() {
        assert!(should_retry_locked_error(&EngineError::Node(
            NodeApplyError::Io(-libc::EBUSY)
        )));
        assert!(should_retry_locked_error(&EngineError::Node(
            NodeApplyError::Io(-libc::EAGAIN)
        )));
        assert!(!should_retry_locked_error(&EngineError::Node(
            NodeApplyError::Io(-libc::ENOENT)
        )));
    }

    #[test]
    fn queue_file_lifecycle_creates_and_removes_marker() {
        let run_dir = std::env::temp_dir().join(format!("udev-queue-{}", std::process::id()));
        let _ = fs::remove_dir_all(&run_dir);
        fs::create_dir_all(&run_dir).unwrap();

        let queue_path = run_dir.join("queue");
        let mut lifecycle = QueueFileLifecycle::new(&run_dir);
        lifecycle.sync(true);
        assert!(queue_path.is_file());

        lifecycle.sync(false);
        assert!(!queue_path.exists());

        let _ = fs::remove_dir_all(&run_dir);
    }

    #[test]
    fn worker_notify_retry_hook_requeues_locked_event() {
        let queue = RulesProcessingQueue::default();
        let queued = QueuedEvent::new(UeventMessage {
            action: UeventAction::Add,
            devpath: "/devices/mock0".to_string(),
            subsystem: Some("block".to_string()),
            devname: Some("sda".to_string()),
            devtype: None,
            major: Some(8),
            minor: Some(0),
            seqnum: Some(1),
            properties: BTreeMap::new(),
        });

        handle_worker_notify_retry(&queue, queued);
        let pending = queue.queue.lock().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.front().unwrap().retry_count, 1);
    }

    #[test]
    fn worker_notify_retry_hook_respects_retry_budget() {
        let queue = RulesProcessingQueue::default();
        let queued = QueuedEvent {
            event: UeventMessage {
                action: UeventAction::Add,
                devpath: "/devices/mock1".to_string(),
                subsystem: Some("block".to_string()),
                devname: Some("sdb".to_string()),
                devtype: None,
                major: Some(8),
                minor: Some(1),
                seqnum: Some(2),
                properties: BTreeMap::new(),
            },
            retry_count: LOCKED_EVENT_REQUEUE_MAX_RETRIES,
            ready_at: Instant::now(),
        };

        handle_worker_notify_retry(&queue, queued);
        assert!(!queue.has_pending());
    }

    #[test]
    fn derive_static_dev_perms_filters_unsafe_names_and_non_numeric_ids() {
        let rules = vec![
            Rule {
                matches: Vec::new(),
                assigns: vec![
                    AssignToken::Name("sda".to_string()),
                    AssignToken::Mode(0o660),
                    AssignToken::Owner("1000".to_string()),
                    AssignToken::Group("disk".to_string()),
                ],
            },
            Rule {
                matches: Vec::new(),
                assigns: vec![
                    AssignToken::Name("%k".to_string()),
                    AssignToken::Mode(0o600),
                    AssignToken::Owner("0".to_string()),
                    AssignToken::Group("0".to_string()),
                ],
            },
        ];

        let specs = derive_static_dev_perms(&rules);
        assert_eq!(specs.len(), 1);
        let spec = &specs[0];
        assert_eq!(spec.path, Path::new("/dev").join("sda"));
        assert_eq!(spec.mode, Some(0o660));
        assert_eq!(spec.uid, Some(1000));
        assert_eq!(spec.gid, None);
    }
}
