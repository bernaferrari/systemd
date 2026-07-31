// SPDX-License-Identifier: LGPL-2.1-or-later

/* Cross-domain regression coverage for the runtime manager remains test-only. */
#[cfg(target_os = "linux")]
use super::notify_runtime::AuthenticatedNotifyDispatch;
use super::service_shutdown::{ServiceTimeoutAction, service_timeout_action};
use super::service_test_events::ServiceTestEvent;
use super::unit_file::*;
use super::unit_load::*;
use super::unit_specifier::*;
use super::*;
use crate::job_tables::{JobResult as CanonicalJobResult, JobState as CanonicalJobState};
#[cfg(target_os = "linux")]
use crate::pid1_notify_source::{AuthenticatedNotifyDatagram, NotifyPeerCredentials};
use crate::service::{NotifyAccess, PidRef};
use crate::service_tables::{ServiceExecCommand, ServiceResult};
use crate::unit::OomPolicy;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use systemd_shared_rs::tests::TestEnvironment;

fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

fn test_temp_dir(name: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = std::process::id();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("systemd-rust-{id}-{count}-{name}"))
}

fn new_test_runtime_manager() -> RuntimeManager {
    RuntimeManager::new_with_test_cgroup_root(test_temp_dir("cgroup-root"))
}

fn insert_test_service(mgr: &mut RuntimeManager, name: &str, state: ServiceState) {
    let mut unit = Unit::new(mgr.manager_record.clone(), UnitType::Service);
    unit.id = Some(name.to_string());
    unit.load_state = LoadState::Loaded;
    unit.active_state =
        crate::service::service_state_translation(state, ServiceType::Simple).into();
    mgr.units.insert(name.to_string(), unit);

    let service = Service {
        service_type: ServiceType::Simple,
        state,
        ..Default::default()
    };
    mgr.services.insert(name.to_string(), service);
}

fn insert_fsm_service(
    mgr: &mut RuntimeManager,
    name: &str,
    state: ServiceState,
    service_type: ServiceType,
    configure: impl FnOnce(&mut UnitFileInfo),
) {
    insert_test_service(mgr, name, state);
    let mut info = UnitFileInfo::new(name, PathBuf::from(name));
    info.service_type = Some(service_type);
    configure(&mut info);
    mgr.unit_files.insert(name.to_string(), info);
    mgr.services.get_mut(name).unwrap().service_type = service_type;
}

#[cfg(target_os = "linux")]
fn authenticated_notify(pid: u32, text: &str) -> crate::pid1_notify_source::ParsedNotifyDatagram {
    AuthenticatedNotifyDatagram {
        peer: NotifyPeerCredentials {
            pid,
            uid: 1000,
            gid: 1000,
        },
        text: text.to_owned(),
    }
    .parse()
}

#[cfg(target_os = "linux")]
fn authorize_notify_main_pid(mgr: &mut RuntimeManager, name: &str, pid: u32) {
    mgr.inject_test_main_pid(name, pid);
    let service = mgr.services.get_mut(name).unwrap();
    service.notify_access = NotifyAccess::Main;
    service.main_pid = Some(PidRef {
        pid: pid as i32,
        start_time: None,
        is_self: false,
        is_child: Some(true),
    });
    service.main_pid_known = true;
}

#[cfg(target_os = "linux")]
#[test]
fn authenticated_notify_ready_advances_only_an_authorized_notify_service() {
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "ready.service",
        ServiceState::Start,
        ServiceType::Notify,
        |_| {},
    );
    authorize_notify_main_pid(&mut mgr, "ready.service", 41_101);

    let outcome = mgr.dispatch_authenticated_notify(authenticated_notify(
        41_101,
        "READY=1\nSTATUS=ready\nMAINPID=999\nFDSTORE=1\nFDNAME=kept",
    ));
    assert!(matches!(
        outcome,
        AuthenticatedNotifyDispatch::Applied {
            entered_start_post: true,
            main_pid_ignored: true,
            fd_store_ignored: true,
            status_observed: true,
            ..
        }
    ));
    assert_eq!(
        mgr.services
            .get("ready.service")
            .map(|service| service.state),
        Some(ServiceState::Running)
    );

    let outcome = mgr.dispatch_authenticated_notify(authenticated_notify(41_102, "READY=1"));
    assert_eq!(
        outcome,
        AuthenticatedNotifyDispatch::IgnoredUnknownSender { pid: 41_102 }
    );
}

#[cfg(target_os = "linux")]
#[test]
fn authenticated_notify_honors_reload_freshness_and_watchdog_ownership() {
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "reload.service",
        ServiceState::ReloadSignal,
        ServiceType::NotifyReload,
        |_| {},
    );
    authorize_notify_main_pid(&mut mgr, "reload.service", 41_102);
    mgr.services
        .get_mut("reload.service")
        .unwrap()
        .reload_begin_usec = 77;

    let stale = mgr.dispatch_authenticated_notify(authenticated_notify(
        41_102,
        "RELOADING=1\nMONOTONIC_USEC=76",
    ));
    assert!(matches!(stale, AuthenticatedNotifyDispatch::Applied { .. }));
    assert_eq!(
        mgr.services
            .get("reload.service")
            .map(|service| service.state),
        Some(ServiceState::ReloadSignal)
    );

    let fresh = mgr.dispatch_authenticated_notify(authenticated_notify(
        41_102,
        "RELOADING=1\nMONOTONIC_USEC=77",
    ));
    assert!(matches!(fresh, AuthenticatedNotifyDispatch::Applied { .. }));
    assert_eq!(
        mgr.services
            .get("reload.service")
            .map(|service| service.state),
        Some(ServiceState::ReloadNotify)
    );

    mgr.set_service_state("reload.service", ServiceState::Running);
    mgr.services
        .get_mut("reload.service")
        .unwrap()
        .watchdog_usec = 1_000_000;
    let ping = mgr.dispatch_authenticated_notify(authenticated_notify(41_102, "WATCHDOG=1"));
    assert!(matches!(
        ping,
        AuthenticatedNotifyDispatch::Applied {
            watchdog_reset: true,
            ..
        }
    ));
    assert!(
        mgr.service_watchdog_deadlines
            .contains_key("reload.service")
    );

    let stopping = mgr.dispatch_authenticated_notify(authenticated_notify(41_102, "STOPPING=1"));
    assert!(matches!(
        stopping,
        AuthenticatedNotifyDispatch::Applied {
            entered_stop_by_notify: true,
            ..
        }
    ));
    assert_eq!(
        mgr.services
            .get("reload.service")
            .map(|service| service.state),
        Some(ServiceState::StopSigterm)
    );
    assert!(
        !mgr.service_watchdog_deadlines
            .contains_key("reload.service")
    );
}

#[test]
fn test_suffix_to_unit_type() {
    let _test_lock = test_env_lock();
    assert_eq!(suffix_to_unit_type("foo.service"), UnitType::Service);
    assert_eq!(suffix_to_unit_type("bar.target"), UnitType::Target);
    assert_eq!(suffix_to_unit_type("sys.mount"), UnitType::Mount);
}

#[test]
fn test_parse_bool() {
    let _test_lock = test_env_lock();
    assert!(parse_bool("yes"));
    assert!(parse_bool("true"));
    assert!(parse_bool("1"));
    assert!(!parse_bool("no"));
    assert!(!parse_bool("0"));
}

#[test]
fn test_runtime_manager_new() {
    let _test_lock = test_env_lock();
    let mgr = RuntimeManager::new();
    assert_eq!(mgr.unit_count(), 0);
    assert_eq!(mgr.active_count(), 0);
    assert_eq!(mgr.cgroup_root, PathBuf::from(CGROUP_V2_ROOT));
}

#[test]
fn test_runtime_manager_production_root_ignores_cgroup_environment_override() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let previous = std::env::var_os("SYSTEMD_CGROUP_ROOT");
    environment.set("SYSTEMD_CGROUP_ROOT", test_temp_dir("ignored-cgroup-root"));

    let mgr = RuntimeManager::new();
    assert_eq!(mgr.cgroup_root, PathBuf::from(CGROUP_V2_ROOT));

    if let Some(value) = previous {
        environment.set("SYSTEMD_CGROUP_ROOT", value);
    } else {
        environment.remove("SYSTEMD_CGROUP_ROOT");
    }
}

#[test]
fn test_runtime_manager_test_root_requires_explicit_constructor() {
    let _test_lock = test_env_lock();
    let cgroup_root = test_temp_dir("explicit-cgroup-root");

    let mgr = RuntimeManager::new_with_test_cgroup_root(cgroup_root.clone());
    assert_eq!(mgr.cgroup_root, cgroup_root);
}

#[test]
fn test_parse_unit_file() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-units");
    fs::create_dir_all(&dir).unwrap();
    let service_path = dir.join("test.service");
    fs::write(
            &service_path,
            "[Unit]\nDescription=Test Service\nAfter=network.target\nWants=network.target\n\n[Service]\nExecStart=/usr/bin/test\n",
        )
        .unwrap();

    let info = parse_unit_file(&service_path).unwrap().unwrap();
    assert_eq!(info.name, "test.service");
    assert_eq!(info.description.as_deref(), Some("Test Service"));
    assert_eq!(info.wants, vec!["network.target"]);
    assert_eq!(info.after, vec!["network.target"]);
    assert_eq!(info.exec_start.as_deref(), Some("/usr/bin/test"));
    assert_eq!(info.unit_type, UnitType::Service);
}

#[test]
fn test_unit_parser_ignores_unknown_lvalues_but_rejects_syntax_errors() {
    let _test_lock = test_env_lock();
    let mut info = UnitFileInfo::new("compat.service", PathBuf::from("compat.service"));

    parse_unit_content_into(
        &mut info,
        "[Unit]\nDescription=Compatible\nUnknownFutureDirective=yes\n\n[Service]\nExecStart=/usr/bin/true\n",
    )
    .unwrap();

    assert_eq!(info.description.as_deref(), Some("Compatible"));
    assert_eq!(info.exec_start.as_deref(), Some("/usr/bin/true"));

    let mut invalid = UnitFileInfo::new("broken.service", PathBuf::from("broken.service"));
    assert!(parse_unit_content_into(&mut invalid, "[Unit\nDescription=Broken\n").is_err());
}

#[test]
fn test_load_unit_rejects_syntax_errors_in_fragments_and_dropins() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let root = test_temp_dir("unit-load-syntax-errors");
    fs::create_dir_all(&root).unwrap();
    let unit = root.join("broken.service");
    fs::write(&unit, "[Unit\nDescription=Broken\n").unwrap();

    let previous = std::env::var_os("SYSTEMD_UNIT_PATH");
    environment.set("SYSTEMD_UNIT_PATH", root.display().to_string());

    let mut mgr = new_test_runtime_manager();
    assert_eq!(mgr.load_unit("broken.service"), Err(Errno::ENOEXEC));

    fs::write(&unit, "[Service]\nExecStart=/usr/bin/true\n").unwrap();
    let dropin_dir = root.join("broken.service.d");
    fs::create_dir_all(&dropin_dir).unwrap();
    fs::write(
        dropin_dir.join("10-broken.conf"),
        "[Service\nType=oneshot\n",
    )
    .unwrap();
    assert_eq!(mgr.load_unit("broken.service"), Err(Errno::ENOEXEC));

    if let Some(value) = previous {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_parse_repeated_unit_lists_and_reset() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-unit-lists");
    fs::create_dir_all(&dir).unwrap();
    let service_path = dir.join("repeat.service");
    fs::write(
            &service_path,
            "[Unit]\nWants=a.service b.service\nWants=c.service\nWants=\nWants=d.service\n\n[Socket]\nListenStream=127.0.0.1:1111\nListenStream=127.0.0.1:2222\nListenStream=\nListenStream=127.0.0.1:3333\nListenDatagram=/run/test.sock\nListenDatagram=/run/test2.sock\n",
        )
        .unwrap();

    let info = parse_unit_file(&service_path).unwrap().unwrap();
    assert_eq!(info.wants, vec!["d.service"]);
    assert_eq!(info.listen_stream, vec!["127.0.0.1:3333"]);
    assert_eq!(
        info.listen_datagram,
        vec!["/run/test.sock", "/run/test2.sock"]
    );
}

#[test]
fn test_parse_service_type_directives() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-service-types");
    fs::create_dir_all(&dir).unwrap();
    let idle_path = dir.join("idle.service");
    let notify_path = dir.join("notify.service");
    let notify_reload_path = dir.join("notify-reload.service");
    let exec_path = dir.join("exec.service");
    fs::write(&idle_path, "[Service]\nType=idle\n").unwrap();
    fs::write(&notify_path, "[Service]\nType=notify\n").unwrap();
    fs::write(&notify_reload_path, "[Service]\nType=notify-reload\n").unwrap();
    fs::write(&exec_path, "[Service]\nType=exec\n").unwrap();

    let idle_info = parse_unit_file(&idle_path).unwrap().unwrap();
    let notify_info = parse_unit_file(&notify_path).unwrap().unwrap();
    let notify_reload_info = parse_unit_file(&notify_reload_path).unwrap().unwrap();
    let exec_info = parse_unit_file(&exec_path).unwrap().unwrap();
    assert_eq!(idle_info.service_type, Some(ServiceType::Idle));
    assert_eq!(notify_info.service_type, Some(ServiceType::Notify));
    assert_eq!(
        notify_reload_info.service_type,
        Some(ServiceType::NotifyReload)
    );
    assert_eq!(exec_info.service_type, Some(ServiceType::Exec));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_parse_service_directives_comprehensive() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-service-directives-comprehensive");
    fs::create_dir_all(&dir).unwrap();
    let service_path = dir.join("demo.service");
    fs::write(
            &service_path,
            "[Service]\nType=notify-reload\nExecStartPre=-/usr/bin/pre\nExecStartPre=+/usr/bin/pre2\nExecStart=\nExecStart=/usr/bin/main --flag\nExecStartPost=!/usr/bin/post\nExecStop=/usr/bin/stop\nExecStopPost=-!/usr/bin/stop-post\nExecReload=+/usr/bin/reload\nExecReloadPost=-/usr/bin/reload-post\nExecCondition=-!/usr/bin/cond\nRestart=on-failure\nRestartSec=2min\nRestartSteps=7\nRestartMaxDelaySec=1h\nTimeoutStartSec=30s\nTimeoutStopSec=40\nTimeoutAbortSec=50\nTimeoutStartFailureMode=abort\nTimeoutStopFailureMode=kill\nTimeoutSec=60\nRuntimeMaxSec=90\nWatchdogSec=1500ms\nSuccessExitStatus=0 1 SIGTERM\nRestartPreventExitStatus=2\nRestartForceExitStatus=3 4\nRemainAfterExit=yes\nGuessMainPID=no\nPIDFile=/run/demo.pid\nBusName=org.demo.Service\nNotifyAccess=all\nSockets=alpha.socket beta.socket\nFileDescriptorStoreMax=32\nFileDescriptorStorePreserve=restart\nOOMPolicy=stop\nOpenFile=/etc/demo\nOpenFile=\nOpenFile=/var/lib/demo\n",
        )
        .unwrap();

    let info = parse_unit_file(&service_path).unwrap().unwrap();

    assert_eq!(info.service_type, Some(ServiceType::NotifyReload));
    assert_eq!(info.exec_start.as_deref(), Some("/usr/bin/main --flag"));
    assert_eq!(info.exec_stop.as_deref(), Some("/usr/bin/stop"));
    assert_eq!(info.exec_reload.as_deref(), Some("/usr/bin/reload"));

    assert_eq!(info.service.exec_start_pre.len(), 2);
    assert_eq!(info.service.exec_start_pre[0].prefixes, "-");
    assert_eq!(info.service.exec_start_pre[0].command, "/usr/bin/pre");
    assert_eq!(info.service.exec_start_pre[1].prefixes, "+");
    assert_eq!(info.service.exec_start_pre[1].command, "/usr/bin/pre2");

    assert_eq!(info.service.exec_start.len(), 1);
    assert_eq!(info.service.exec_start[0].command, "/usr/bin/main --flag");
    assert_eq!(info.service.exec_start_post[0].prefixes, "!");
    assert_eq!(info.service.exec_stop_post[0].prefixes, "-!");
    assert_eq!(info.service.exec_reload_post[0].prefixes, "-");
    assert_eq!(
        info.service.exec_reload_post[0].command,
        "/usr/bin/reload-post"
    );
    assert_eq!(info.service.exec_condition[0].prefixes, "-!");

    assert_eq!(info.service.restart, Some(ServiceRestartPolicy::OnFailure));
    assert_eq!(info.service.restart_sec, Some(120));
    assert_eq!(info.service.restart_steps, Some(7));
    assert_eq!(info.service.restart_max_delay_sec, Some(3600));
    assert_eq!(info.service.timeout_start_sec, Some(60));
    assert_eq!(info.service.timeout_stop_sec, Some(60));
    assert_eq!(info.service.timeout_abort_sec, Some(50));
    assert_eq!(
        info.service.timeout_start_failure_mode,
        Some(ServiceTimeoutFailureMode::Abort)
    );
    assert_eq!(
        info.service.timeout_stop_failure_mode,
        Some(ServiceTimeoutFailureMode::Kill)
    );
    assert_eq!(info.service.runtime_max_sec, Some(90));
    assert_eq!(info.service.watchdog_sec, Some(2));

    assert_eq!(info.service.success_exit_status, vec!["0", "1", "SIGTERM"]);
    assert_eq!(info.service.restart_prevent_exit_status, vec!["2"]);
    assert_eq!(info.service.restart_force_exit_status, vec!["3", "4"]);
    assert_eq!(info.service.remain_after_exit, Some(true));
    assert_eq!(info.service.guess_main_pid, Some(false));
    assert_eq!(info.service.pid_file.as_deref(), Some("/run/demo.pid"));
    assert_eq!(info.service.bus_name.as_deref(), Some("org.demo.Service"));
    assert_eq!(info.service.notify_access, Some(NotifyAccess::All));
    assert_eq!(info.service.sockets, vec!["alpha.socket", "beta.socket"]);
    assert_eq!(info.service.file_descriptor_store_max, Some(32));
    assert_eq!(
        info.service.file_descriptor_store_preserve,
        Some(FileDescriptorStorePreserve::Restart)
    );
    assert_eq!(info.service.oom_policy, Some(OomPolicy::Stop));
    assert_eq!(info.service.open_file, vec!["/var/lib/demo"]);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_timeout_failure_modes_reject_unknown_values_and_allow_reset() {
    let _test_lock = test_env_lock();
    for key in ["TimeoutStartFailureMode", "TimeoutStopFailureMode"] {
        let mut invalid = UnitFileInfo::new("invalid.service", PathBuf::from("invalid.service"));
        assert!(
            parse_unit_content_into(&mut invalid, &format!("[Service]\n{key}=later\n")).is_err()
        );

        let mut reset = UnitFileInfo::new("reset.service", PathBuf::from("reset.service"));
        parse_unit_content_into(&mut reset, &format!("[Service]\n{key}=kill\n{key}=\n")).unwrap();
        let value = match key {
            "TimeoutStartFailureMode" => reset.service.timeout_start_failure_mode,
            "TimeoutStopFailureMode" => reset.service.timeout_stop_failure_mode,
            _ => unreachable!(),
        };
        assert_eq!(value, None);
    }
}

#[test]
fn test_service_timeout_action_matches_all_c_timer_phase_and_policy_cases() {
    use ServiceTimeoutAction::{Dead, Mount, Reload, Signal, Stop, StopPost};
    use ServiceTimeoutFailureMode::{Abort, Kill, Terminate};

    for state in [
        ServiceState::Condition,
        ServiceState::StartPre,
        ServiceState::Start,
        ServiceState::StartPost,
    ] {
        assert_eq!(
            service_timeout_action(state, Terminate, Terminate, true),
            Some(Signal(ServiceState::StopSigterm))
        );
        assert_eq!(
            service_timeout_action(state, Abort, Terminate, true),
            Some(Signal(ServiceState::StopWatchdog))
        );
        assert_eq!(
            service_timeout_action(state, Kill, Terminate, true),
            Some(Signal(ServiceState::StopSigkill))
        );
        assert_eq!(
            service_timeout_action(state, Kill, Terminate, false),
            Some(StopPost)
        );
    }

    for state in [ServiceState::Stop, ServiceState::StopPost] {
        let (terminate, abort, kill) = if state == ServiceState::Stop {
            (
                Signal(ServiceState::StopSigterm),
                Signal(ServiceState::StopWatchdog),
                Signal(ServiceState::StopSigkill),
            )
        } else {
            (
                Signal(ServiceState::FinalSigterm),
                Signal(ServiceState::FinalWatchdog),
                Signal(ServiceState::FinalSigkill),
            )
        };
        let no_kill = if state == ServiceState::Stop {
            StopPost
        } else {
            Dead {
                allow_restart: false,
            }
        };
        assert_eq!(
            service_timeout_action(state, Terminate, Terminate, true),
            Some(terminate)
        );
        assert_eq!(
            service_timeout_action(state, Terminate, Abort, true),
            Some(abort)
        );
        assert_eq!(
            service_timeout_action(state, Terminate, Kill, true),
            Some(kill)
        );
        assert_eq!(
            service_timeout_action(state, Terminate, Kill, false),
            Some(no_kill)
        );
    }

    assert_eq!(
        service_timeout_action(ServiceState::StopWatchdog, Terminate, Terminate, true),
        Some(Signal(ServiceState::StopSigkill))
    );
    assert_eq!(
        service_timeout_action(ServiceState::StopWatchdog, Terminate, Terminate, false),
        Some(StopPost)
    );
    assert_eq!(
        service_timeout_action(ServiceState::StopSigterm, Terminate, Abort, true),
        Some(Signal(ServiceState::StopWatchdog))
    );
    assert_eq!(
        service_timeout_action(ServiceState::StopSigterm, Terminate, Kill, true),
        Some(Signal(ServiceState::StopSigkill))
    );
    assert_eq!(
        service_timeout_action(ServiceState::StopSigterm, Terminate, Kill, false),
        Some(StopPost)
    );
    assert_eq!(
        service_timeout_action(ServiceState::StopSigkill, Terminate, Terminate, true),
        Some(StopPost)
    );
    assert_eq!(
        service_timeout_action(ServiceState::FinalWatchdog, Terminate, Terminate, true),
        Some(Signal(ServiceState::FinalSigkill))
    );
    assert_eq!(
        service_timeout_action(ServiceState::FinalWatchdog, Terminate, Terminate, false),
        Some(Dead {
            allow_restart: false,
        })
    );
    assert_eq!(
        service_timeout_action(ServiceState::FinalSigterm, Terminate, Abort, true),
        Some(Signal(ServiceState::FinalWatchdog))
    );
    assert_eq!(
        service_timeout_action(ServiceState::FinalSigterm, Terminate, Kill, true),
        Some(Signal(ServiceState::FinalSigkill))
    );
    assert_eq!(
        service_timeout_action(ServiceState::FinalSigterm, Terminate, Kill, false),
        Some(Dead {
            allow_restart: false,
        })
    );
    assert_eq!(
        service_timeout_action(ServiceState::FinalSigkill, Terminate, Terminate, true),
        Some(Dead {
            allow_restart: true,
        })
    );
    for state in [
        ServiceState::Reload,
        ServiceState::ReloadSignal,
        ServiceState::ReloadNotify,
        ServiceState::ReloadPost,
        ServiceState::RefreshExtensions,
        ServiceState::RefreshCredentials,
    ] {
        assert_eq!(
            service_timeout_action(state, Terminate, Terminate, true),
            Some(Reload)
        );
    }
    assert_eq!(
        service_timeout_action(ServiceState::Running, Terminate, Terminate, true),
        Some(Stop)
    );
    assert_eq!(
        service_timeout_action(ServiceState::Mounting, Terminate, Terminate, true),
        Some(Mount)
    );
}

#[test]
fn test_parse_exec_context_directives_shared_and_apply_to_unit() {
    let _test_lock = test_env_lock();

    let ctx = ExecContextConfig {
        user: Some("alice".to_string()),
        group: Some("staff".to_string()),
        dynamic_user: Some(true),
        supplementary_groups: vec!["wheel".to_string(), "docker".to_string()],
        pam_name: Some("login".to_string()),
        working_directory: Some("/srv".to_string()),
        private_tmp: Some(true),
        private_devices: Some(false),
        private_network: Some(true),
        private_ipc: Some(true),
        private_users: Some(true),
        private_mounts: Some(false),
        protect_system: Some("strict".to_string()),
        protect_home: Some("read-only".to_string()),
        protect_hostname: Some(true),
        protect_clock: Some(true),
        protect_kernel_tunables: Some(true),
        protect_kernel_modules: Some(false),
        protect_kernel_logs: Some(true),
        protect_control_groups: Some(true),
        environment: vec!["FOO=bar".to_string(), "BAR=baz".to_string()],
        pass_environment: vec!["FOO".to_string(), "BAR".to_string()],
        unset_environment: vec!["BAZ=1".to_string()],
        standard_input: Some("null".to_string()),
        standard_output: Some("journal".to_string()),
        standard_error: Some("inherit".to_string()),
        tty_path: Some("/dev/console".to_string()),
        tty_reset: Some(true),
        tty_vhangup: Some(false),
        tty_vt_disallocate: Some(true),
        syslog_identifier: Some("demo".to_string()),
        syslog_facility: Some("daemon".to_string()),
        syslog_level: Some("info".to_string()),
        nice: Some(7),
        cpu_scheduling_policy: Some("rr".to_string()),
        cpu_affinity: vec!["0-3".to_string()],
        umask: Some("0022".to_string()),
        oom_score_adjust: Some(-100),
        runtime_directory: vec!["demo".to_string(), "run".to_string()],
        state_directory: vec!["state".to_string()],
        cache_directory: vec!["cache".to_string()],
        logs_directory: vec!["logs".to_string()],
        configuration_directory: vec!["config".to_string()],
        directory_mode: Some(0o750),
        runtime_directory_mode: Some(0o700),
        state_directory_mode: Some(0o710),
        cache_directory_mode: Some(0o720),
        logs_directory_mode: Some(0o730),
        configuration_directory_mode: Some(0o740),
        runtime_directory_preserve: Some("restart".to_string()),
        read_write_paths: vec!["/var/lib/demo".to_string()],
        read_only_paths: vec!["/usr".to_string()],
        inaccessible_paths: vec!["/secret".to_string()],
        ..Default::default()
    };

    let mut unit = Unit::new(
        new_test_runtime_manager().manager_record.clone(),
        UnitType::Service,
    );
    unit.id = Some("execctx.service".to_string());
    apply_exec_context_config(&mut unit, &ctx);
    let unit_exec = unit.exec_context.as_ref().unwrap();
    assert_eq!(unit_exec.nice, 7);
    assert_eq!(unit_exec.tty_path.as_deref(), Some("/dev/console"));
    assert!(unit_exec.tty_reset);
    assert!(!unit_exec.tty_vhangup);
    assert!(unit_exec.tty_vt_disallocate);
    assert_eq!(
        unit_exec.environment.get("FOO").map(String::as_str),
        Some("bar")
    );
    assert_eq!(
        unit_exec.environment.get("BAR").map(String::as_str),
        Some("baz")
    );
}

#[test]
fn test_parse_system_call_filter_line_inversion_applies_to_all_tokens() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-syscall-filter-inversion");
    fs::create_dir_all(&dir).unwrap();
    let service_path = dir.join("syscall-filter.service");
    fs::write(
            &service_path,
            "[Service]\nSystemCallFilter=~mount umount2\nSystemCallFilter=read write\nExecStart=/usr/bin/true\n",
        )
        .unwrap();

    let info = parse_unit_file(&service_path).unwrap().unwrap();
    assert_eq!(
        info.exec_context.system_call_filter,
        vec!["~mount", "~umount2", "read", "write"]
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_parse_kill_and_cgroup_context_directives_shared_and_apply_to_unit() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-kill-cgroup-shared");
    fs::create_dir_all(&dir).unwrap();
    let service_path = dir.join("cg.service");
    fs::write(
            &service_path,
            "[Service]\nKillMode=mixed\nKillSignal=15\nRestartKillSignal=1\nFinalKillSignal=9\nSendSIGHUP=yes\nSendSIGKILL=no\nWatchdogSignal=6\nSlice=custom.slice\nDelegate=yes\nDelegateSubgroup=my-subgroup\nCPUAccounting=yes\nCPUWeight=200\nCPUQuota=50%\nCPUQuotaPeriodSec=200ms\nAllowedCPUs=0-1\nMemoryAccounting=yes\nMemoryMin=128M\nMemoryLow=256M\nMemoryHigh=512M\nMemoryMax=1G\nMemorySwapMax=2G\nMemoryZSwapMax=3G\nTasksAccounting=yes\nTasksMax=4096\nIOAccounting=yes\nIOWeight=300\nIODeviceWeight=/dev/sda 100\nIOReadBandwidthMax=/dev/sda 10M\nIOWriteIOPSMax=/dev/sda 200\nIPAccounting=yes\nIPAddressAllow=10.0.0.0/8\nIPAddressDeny=0.0.0.0/0\nBPFProgram=foo:bpf\nSocketBindAllow=tcp:80\nSocketBindDeny=udp:53\nRestrictNetworkInterfaces=eth0 wlan0\nNFTSet=setname\nCoredumpFilter=0x33\nManagedOOMMemoryPressure=kill\nManagedOOMMemoryPressureLimit=60%\nManagedOOMPreference=avoid\nManagedOOMSwap=kill\nMemoryPressureWatch=auto\nExecStart=/usr/bin/true\n",
        )
        .unwrap();

    let info = parse_unit_file(&service_path).unwrap().unwrap();
    assert_eq!(info.kill.kill_mode, Some(KillMode::Mixed));
    assert_eq!(info.kill.kill_signal, Some(15));
    assert_eq!(info.kill.restart_kill_signal, Some(1));
    assert_eq!(info.kill.final_kill_signal, Some(9));
    assert_eq!(info.kill.send_sighup, Some(true));
    assert_eq!(info.kill.send_sigkill, Some(false));
    assert_eq!(info.kill.watchdog_signal, Some(6));

    assert_eq!(info.cgroup.slice.as_deref(), Some("custom.slice"));
    assert_eq!(info.cgroup.delegate, Some(true));
    assert_eq!(
        info.cgroup
            .delegate_controllers
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["cpu", "cpuset", "io", "memory", "pids"]
    );
    assert_eq!(
        info.cgroup.delegate_subgroup.as_deref(),
        Some("my-subgroup")
    );
    assert_eq!(info.cgroup.cpu_accounting, Some(true));
    assert_eq!(info.cgroup.cpu_weight, Some(200));
    assert_eq!(info.cgroup.cpu_quota.as_deref(), Some("50%"));
    assert_eq!(info.cgroup.cpu_quota_period_usec, Some(200_000));
    assert_eq!(info.cgroup.allowed_cpus.as_deref(), Some("0-1"));
    assert_eq!(info.cgroup.memory_accounting, Some(true));
    assert_eq!(info.cgroup.memory_min.as_deref(), Some("128M"));
    assert_eq!(info.cgroup.memory_low.as_deref(), Some("256M"));
    assert_eq!(info.cgroup.memory_high.as_deref(), Some("512M"));
    assert_eq!(info.cgroup.memory_max.as_deref(), Some("1G"));
    assert_eq!(info.cgroup.memory_swap_max.as_deref(), Some("2G"));
    assert_eq!(info.cgroup.memory_zswap_max.as_deref(), Some("3G"));
    assert_eq!(info.cgroup.tasks_accounting, Some(true));
    assert_eq!(info.cgroup.tasks_max, Some(4096));
    assert_eq!(info.cgroup.io_accounting, Some(true));
    assert_eq!(info.cgroup.io_weight, Some(300));
    assert_eq!(info.cgroup.io_device_weight, vec!["/dev/sda 100"]);
    assert_eq!(
        info.cgroup.io_limits,
        vec![
            CgroupIoLimitConfig {
                kind: CgroupIoLimitKind::ReadBandwidth,
                value: "/dev/sda 10M".to_string(),
            },
            CgroupIoLimitConfig {
                kind: CgroupIoLimitKind::WriteIops,
                value: "/dev/sda 200".to_string(),
            },
        ]
    );
    assert_eq!(info.cgroup.ip_accounting, Some(true));
    assert_eq!(info.cgroup.ip_address_allow, vec!["10.0.0.0/8"]);
    assert_eq!(info.cgroup.ip_address_deny, vec!["0.0.0.0/0"]);
    assert_eq!(info.cgroup.bpf_program, vec!["foo:bpf"]);
    assert_eq!(info.cgroup.socket_bind_allow, vec!["tcp:80"]);
    assert_eq!(info.cgroup.socket_bind_deny, vec!["udp:53"]);
    assert_eq!(
        info.cgroup.restrict_network_interfaces,
        vec!["eth0", "wlan0"]
    );
    assert_eq!(info.cgroup.nft_set, vec!["setname"]);
    assert_eq!(info.cgroup.coredump_filter.as_deref(), Some("0x33"));
    assert_eq!(
        info.cgroup.managed_oom_memory_pressure.as_deref(),
        Some("kill")
    );
    assert_eq!(
        info.cgroup.managed_oom_memory_pressure_limit.as_deref(),
        Some("60%")
    );
    assert_eq!(info.cgroup.managed_oom_preference.as_deref(), Some("avoid"));
    assert_eq!(info.cgroup.managed_oom_swap.as_deref(), Some("kill"));
    assert_eq!(info.cgroup.memory_pressure_watch.as_deref(), Some("auto"));

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());
    let mut mgr = new_test_runtime_manager();
    mgr.load_unit("cg.service").unwrap();
    let unit = mgr.units.get("cg.service").unwrap();
    assert_eq!(unit.slice.as_deref(), Some("custom.slice"));
    let kill_ctx = unit.kill_context.as_ref().unwrap();
    assert_eq!(kill_ctx.kill_signal, 15);
    assert_eq!(kill_ctx.final_kill_signal, 9);
    let cg_ctx = unit.cgroup_context.as_ref().unwrap();
    assert!(cg_ctx.io_accounting);
    assert!(cg_ctx.memory_accounting);
    assert!(cg_ctx.tasks_accounting);
    assert!(cg_ctx.ip_accounting);
    assert_eq!(cg_ctx.tasks_max, 4096);
    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_parse_socket_service_override() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-socket-service");
    fs::create_dir_all(&dir).unwrap();
    let socket_path = dir.join("override.socket");
    fs::write(&socket_path, "[Socket]\nService=bar.service\n").unwrap();

    let info = parse_unit_file(&socket_path).unwrap().unwrap();
    assert_eq!(info.service_override.as_deref(), Some("bar.service"));
    assert_eq!(info.socket.service.as_deref(), Some("bar.service"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_parse_socket_service_override_ignores_non_service_unit_like_c() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-socket-invalid-service");
    fs::create_dir_all(&dir).unwrap();
    let socket_path = dir.join("override.socket");
    fs::write(
        &socket_path,
        "[Socket]\nService=first.service\nService=bar.target\n",
    )
    .unwrap();

    let info = parse_unit_file(&socket_path).unwrap().unwrap();
    assert_eq!(info.service_override.as_deref(), Some("first.service"));
    assert_eq!(info.socket.service.as_deref(), Some("first.service"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_socket_runtime_rejects_programmatic_non_service_association_before_listening() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    let socket_name = "guarded.socket";

    let mut unit = Unit::new(mgr.manager_record.clone(), UnitType::Socket);
    unit.id = Some(socket_name.to_string());
    unit.load_state = LoadState::Loaded;
    mgr.units.insert(socket_name.to_string(), unit);

    let mut info = UnitFileInfo::new(socket_name, PathBuf::from(socket_name));
    info.socket.listen_stream.push("127.0.0.1:0".to_string());
    // UnitFileInfo is public, so the runtime must not rely only on parser validation.
    info.socket.service = Some("wrong.target".to_string());
    mgr.unit_files.insert(socket_name.to_string(), info);

    assert!(mgr.execute_socket_job(socket_name, TxJobType::Start));
    assert_eq!(
        mgr.units.get(socket_name).map(|unit| unit.active_state),
        Some(ActiveState::Failed)
    );
    assert!(mgr.socket_mgr.get(socket_name).is_none());
    assert!(mgr.service_activation_sockets.is_empty());
}

#[test]
fn test_socket_activation_rejects_programmatic_non_service_association() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    let socket_name = "activation-guard.socket";
    mgr.socket_mgr
        .register_socket(socket_name, "127.0.0.1:0")
        .unwrap();

    let mut info = UnitFileInfo::new(socket_name, PathBuf::from(socket_name));
    info.socket.service = Some("wrong.target".to_string());
    mgr.unit_files.insert(socket_name.to_string(), info);

    assert_eq!(
        mgr.spawn_service_for_socket(socket_name),
        Err(Errno::EINVAL)
    );
    assert!(mgr.service_activation_sockets.is_empty());
}

#[test]
fn test_parse_socket_directives_comprehensive() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-socket-directives-comprehensive");
    fs::create_dir_all(&dir).unwrap();
    let socket_path = dir.join("comprehensive.socket");
    fs::write(
            &socket_path,
            "[Socket]\nListenStream=127.0.0.1:80\nListenStream=\nListenStream=127.0.0.1:8080\nListenDatagram=/run/demo.sock\nListenSequentialPacket=/run/demo.seq\nListenFIFO=/run/demo.fifo\nListenSpecial=/dev/null\nListenNetlink=route 0\nListenMessageQueue=/demo.mq\nListenUSBFunction=acm.usb0\nSocketMode=0660\nDirectoryMode=0750\nAccept=yes\nWritable=no\nMaxConnections=128\nMaxConnectionsPerSource=16\nKeepAlive=yes\nKeepAliveTimeSec=30\nKeepAliveIntervalSec=5\nKeepAliveProbes=4\nNoDelay=1\nPriority=6\nReceiveBuffer=2048\nSendBuffer=4096\nIPTOS=16\nIPTTL=64\nMark=123\nReusePort=true\nSmackLabel=socket-label\nSmackLabelIPIn=inbound\nSmackLabelIPOut=outbound\nSELinuxContextFromNet=yes\nPipeSize=8192\nMessageQueueMaxMessages=64\nMessageQueueMessageSize=512\nFreeBind=yes\nTransparent=true\nBroadcast=no\nPassCredentials=yes\nPassSecurity=no\nPassPacketInfo=true\nSocketProtocol=tcp\nBindToDevice=eth0\nService=demo.service\nRemoveOnStop=yes\nSymlinks=alpha beta\nSymlinks=\nSymlinks=final-link\nFileDescriptorName=demo-fd\nTriggerLimitIntervalSec=2min\nTriggerLimitBurst=20\n",
        )
        .unwrap();

    let info = parse_unit_file(&socket_path).unwrap().unwrap();

    assert_eq!(info.listen_stream, vec!["127.0.0.1:8080"]);
    assert_eq!(info.listen_datagram, vec!["/run/demo.sock"]);
    assert_eq!(info.socket.listen_sequential_packet, vec!["/run/demo.seq"]);
    assert_eq!(info.socket.listen_fifo, vec!["/run/demo.fifo"]);
    assert_eq!(info.socket.listen_special, vec!["/dev/null"]);
    assert_eq!(info.socket.listen_netlink, vec!["route", "0"]);
    assert_eq!(info.socket.listen_message_queue, vec!["/demo.mq"]);
    assert_eq!(info.socket.listen_usb_function, vec!["acm.usb0"]);
    assert_eq!(info.socket.socket_mode, Some(0o660));
    assert_eq!(info.socket.directory_mode, Some(0o750));
    assert_eq!(info.socket.accept, Some(true));
    assert_eq!(info.socket.writable, Some(false));
    assert_eq!(info.socket.max_connections, Some(128));
    assert_eq!(info.socket.max_connections_per_source, Some(16));
    assert_eq!(info.socket.keep_alive, Some(true));
    assert_eq!(info.socket.keep_alive_time_sec, Some(30));
    assert_eq!(info.socket.keep_alive_interval_sec, Some(5));
    assert_eq!(info.socket.keep_alive_probes, Some(4));
    assert_eq!(info.socket.no_delay, Some(true));
    assert_eq!(info.socket.priority, Some(6));
    assert_eq!(info.socket.receive_buffer, Some(2048));
    assert_eq!(info.socket.send_buffer, Some(4096));
    assert_eq!(info.socket.ip_tos, Some(16));
    assert_eq!(info.socket.ip_ttl, Some(64));
    assert_eq!(info.socket.mark, Some(123));
    assert_eq!(info.socket.reuse_port, Some(true));
    assert_eq!(info.socket.smack_label.as_deref(), Some("socket-label"));
    assert_eq!(info.socket.smack_label_ip_in.as_deref(), Some("inbound"));
    assert_eq!(info.socket.smack_label_ip_out.as_deref(), Some("outbound"));
    assert_eq!(info.socket.selinux_context_from_net, Some(true));
    assert_eq!(info.socket.pipe_size, Some(8192));
    assert_eq!(info.socket.message_queue_max_messages, Some(64));
    assert_eq!(info.socket.message_queue_message_size, Some(512));
    assert_eq!(info.socket.free_bind, Some(true));
    assert_eq!(info.socket.transparent, Some(true));
    assert_eq!(info.socket.broadcast, Some(false));
    assert_eq!(info.socket.pass_credentials, Some(true));
    assert_eq!(info.socket.pass_security, Some(false));
    assert_eq!(info.socket.pass_packet_info, Some(true));
    assert_eq!(info.socket.socket_protocol.as_deref(), Some("tcp"));
    assert_eq!(info.socket.bind_to_device.as_deref(), Some("eth0"));
    assert_eq!(info.socket.service.as_deref(), Some("demo.service"));
    assert_eq!(info.socket.remove_on_stop, Some(true));
    assert_eq!(info.socket.symlinks, vec!["final-link"]);
    assert_eq!(info.socket.file_descriptor_name.as_deref(), Some("demo-fd"));
    assert_eq!(info.socket.trigger_limit_interval_sec, Some(120));
    assert_eq!(info.socket.trigger_limit_burst, Some(20));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_parse_timer_path_mount_swap_automount_sections() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-other-sections");
    fs::create_dir_all(&dir).unwrap();

    let timer_path = dir.join("demo.timer");
    fs::write(
            &timer_path,
            "[Timer]\nOnActiveSec=5\nOnActiveSec=10\nOnBootSec=3min\nOnStartupSec=2\nOnUnitActiveSec=8\nOnUnitInactiveSec=9\nOnCalendar=Mon *-*-* 00:00:00\nOnCalendar=\nOnCalendar=Tue *-*-* 01:00:00\nAccuracySec=1min\nRandomizedDelaySec=30s\nFixedRandomDelay=yes\nOnClockChange=true\nOnTimezoneChange=false\nUnit=demo.service\nPersistent=yes\nWakeSystem=no\nRemainAfterElapse=yes\n",
        )
        .unwrap();

    let path_path = dir.join("demo.path");
    fs::write(
            &path_path,
            "[Path]\nPathExists=/tmp/a\nPathExists=/tmp/b\nPathExists=\nPathExists=/tmp/c\nPathExistsGlob=/var/log/*.log\nPathChanged=/tmp/changed\nPathModified=/tmp/modified\nDirectoryNotEmpty=/tmp/dir\nUnit=demo.service\nMakeDirectory=yes\nDirectoryMode=0755\nTriggerLimitIntervalSec=45\nTriggerLimitBurst=12\n",
        )
        .unwrap();

    let mount_path = dir.join("demo.mount");
    fs::write(
            &mount_path,
            "[Mount]\nWhat=/dev/vda1\nWhere=/mnt/demo\nType=ext4\nOptions=rw,noatime\nSloppyOptions=yes\nLazyUnmount=no\nForceUnmount=yes\nReadwriteOnly=true\nDirectoryMode=0750\nTimeoutSec=2min\n",
        )
        .unwrap();

    let swap_path = dir.join("demo.swap");
    fs::write(
        &swap_path,
        "[Swap]\nWhat=/dev/zram0\nPriority=100\nOptions=discard\nTimeoutSec=15\n",
    )
    .unwrap();

    let automount_path = dir.join("demo.automount");
    fs::write(
            &automount_path,
            "[Automount]\nWhere=/mnt/auto\nExtraOptions=rw,nodev\nDirectoryMode=0700\nTimeoutIdleSec=5min\n",
        )
        .unwrap();

    let timer_info = parse_unit_file(&timer_path).unwrap().unwrap();
    assert_eq!(timer_info.timer.on_active_sec, vec![5, 10]);
    assert_eq!(timer_info.timer.on_boot_sec, vec![180]);
    assert_eq!(timer_info.timer.on_startup_sec, vec![2]);
    assert_eq!(timer_info.timer.on_unit_active_sec, vec![8]);
    assert_eq!(timer_info.timer.on_unit_inactive_sec, vec![9]);
    assert_eq!(
        timer_info.timer.on_calendar,
        vec!["Tue *-*-* 01:00:00".to_string()]
    );
    assert_eq!(timer_info.timer.accuracy_sec, Some(60));
    assert_eq!(timer_info.timer.randomized_delay_sec, Some(30));
    assert_eq!(timer_info.timer.fixed_random_delay, Some(true));
    assert_eq!(timer_info.timer.on_clock_change, Some(true));
    assert_eq!(timer_info.timer.on_timezone_change, Some(false));
    assert_eq!(timer_info.timer.unit.as_deref(), Some("demo.service"));
    assert_eq!(timer_info.timer.persistent, Some(true));
    assert_eq!(timer_info.timer.wake_system, Some(false));
    assert_eq!(timer_info.timer.remain_after_elapse, Some(true));

    let path_info = parse_unit_file(&path_path).unwrap().unwrap();
    assert_eq!(
        path_info.path_config.path_exists,
        vec!["/tmp/c".to_string()]
    );
    assert_eq!(
        path_info.path_config.path_exists_glob,
        vec!["/var/log/*.log"]
    );
    assert_eq!(path_info.path_config.path_changed, vec!["/tmp/changed"]);
    assert_eq!(path_info.path_config.path_modified, vec!["/tmp/modified"]);
    assert_eq!(path_info.path_config.directory_not_empty, vec!["/tmp/dir"]);
    assert_eq!(path_info.path_config.unit.as_deref(), Some("demo.service"));
    assert_eq!(path_info.path_config.make_directory, Some(true));
    assert_eq!(path_info.path_config.directory_mode, Some(0o755));
    assert_eq!(path_info.path_config.trigger_limit_interval_sec, Some(45));
    assert_eq!(path_info.path_config.trigger_limit_burst, Some(12));

    let mut mount_info = UnitFileInfo::new("demo.mount", mount_path.clone());
    mount_info.mount.what = Some("/dev/vda1".to_string());
    mount_info.mount.where_path = Some("/mnt/demo".to_string());
    mount_info.mount.fstype = Some("ext4".to_string());
    mount_info.mount.options = Some("rw,noatime".to_string());
    mount_info.mount.sloppy_options = Some(true);
    mount_info.mount.lazy_unmount = Some(false);
    mount_info.mount.force_unmount = Some(true);
    mount_info.mount.readwrite_only = Some(true);
    mount_info.mount.directory_mode = Some(0o750);
    mount_info.mount.timeout_sec = Some(120);
    assert_eq!(mount_info.mount.what.as_deref(), Some("/dev/vda1"));
    assert_eq!(mount_info.mount.where_path.as_deref(), Some("/mnt/demo"));
    assert_eq!(mount_info.mount.fstype.as_deref(), Some("ext4"));
    assert_eq!(mount_info.mount.options.as_deref(), Some("rw,noatime"));
    assert_eq!(mount_info.mount.sloppy_options, Some(true));
    assert_eq!(mount_info.mount.lazy_unmount, Some(false));
    assert_eq!(mount_info.mount.force_unmount, Some(true));
    assert_eq!(mount_info.mount.readwrite_only, Some(true));
    assert_eq!(mount_info.mount.directory_mode, Some(0o750));
    assert_eq!(mount_info.mount.timeout_sec, Some(120));

    let swap_info = parse_unit_file(&swap_path).unwrap().unwrap();
    assert_eq!(swap_info.swap.what.as_deref(), Some("/dev/zram0"));
    assert_eq!(swap_info.swap.priority, Some(100));
    assert_eq!(swap_info.swap.options.as_deref(), Some("discard"));
    assert_eq!(swap_info.swap.timeout_sec, Some(15));

    let automount_info = parse_unit_file(&automount_path).unwrap().unwrap();
    assert_eq!(
        automount_info.automount.where_path.as_deref(),
        Some("/mnt/auto")
    );
    assert_eq!(
        automount_info.automount.extra_options.as_deref(),
        Some("rw,nodev")
    );
    assert_eq!(automount_info.automount.directory_mode, Some(0o700));
    assert_eq!(automount_info.automount.timeout_idle_sec, Some(300));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_parse_condition_and_on_failure() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-condition-and-failure");
    fs::create_dir_all(&dir).unwrap();
    let service_path = dir.join("cond.service");
    fs::write(
            &service_path,
            "[Unit]\nConditionPathExists=/etc\nConditionPathExists=!/definitely-missing-path\nAssertPathExists=!/definitely-missing-path\nOnFailure=failure-handler.service\n",
        )
        .unwrap();

    let info = parse_unit_file(&service_path).unwrap().unwrap();
    assert_eq!(info.conditions.path_exists.len(), 2);
    assert_eq!(info.conditions.path_exists[0].value, "/etc");
    assert!(!info.conditions.path_exists[0].invert);
    assert!(!info.conditions.path_exists[0].trigger);
    assert_eq!(
        info.conditions.path_exists[1].value,
        "/definitely-missing-path"
    );
    assert!(info.conditions.path_exists[1].invert);
    assert!(!info.conditions.path_exists[1].trigger);
    assert_eq!(info.asserts.path_exists.len(), 1);
    assert!(info.asserts.path_exists[0].invert);
    assert_eq!(info.on_failure, vec!["failure-handler.service"]);
    assert!(unit_conditions_satisfied(&info));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_parse_unit_section_directives_comprehensive() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-unit-section-comprehensive");
    fs::create_dir_all(&dir).unwrap();
    let service_path = dir.join("unitfull.service");
    fs::write(
            &service_path,
            "[Unit]\nDescription=Comprehensive Unit\nDocumentation=man:first(8) https://example.invalid/doc\nDocumentation=\nDocumentation=man:final(8)\nSourcePath=/usr/lib/systemd/system/unitfull.service\nWants=want-a.target want-b.target\nRequires=require-a.service\nRequisite=requisite-a.service\nBindsTo=bind-a.service\nUpholds=uphold-a.service\nPartOf=parent.target\nConflicts=conflict-a.service\nBefore=before.target\nAfter=after.target\nOnSuccess=success-handler.service\nOnFailure=failure-handler.service\nPropagatesReloadTo=reload-a.service reload-b.service\nReloadPropagatedFrom=reload-source.service\nDefaultDependencies=no\nIgnoreOnIsolate=yes\nStopWhenUnneeded=yes\nRefuseManualStart=yes\nRefuseManualStop=yes\nAllowIsolate=yes\n\n[Service]\nExecStart=/usr/bin/true\n",
        )
        .unwrap();

    let info = parse_unit_file(&service_path).unwrap().unwrap();
    assert_eq!(info.description.as_deref(), Some("Comprehensive Unit"));
    assert_eq!(info.documentation, vec!["man:final(8)"]);
    assert_eq!(
        info.source_path.as_deref(),
        Some("/usr/lib/systemd/system/unitfull.service")
    );
    assert_eq!(info.wants, vec!["want-a.target", "want-b.target"]);
    assert_eq!(info.requires, vec!["require-a.service"]);
    assert_eq!(info.requisite, vec!["requisite-a.service"]);
    assert_eq!(info.binds_to, vec!["bind-a.service"]);
    assert_eq!(info.upholds, vec!["uphold-a.service"]);
    assert_eq!(info.part_of, vec!["parent.target"]);
    assert_eq!(info.conflicts, vec!["conflict-a.service"]);
    assert_eq!(info.before, vec!["before.target"]);
    assert_eq!(info.after, vec!["after.target"]);
    assert_eq!(info.on_success, vec!["success-handler.service"]);
    assert_eq!(info.on_failure, vec!["failure-handler.service"]);
    assert_eq!(
        info.propagates_reload_to,
        vec!["reload-a.service", "reload-b.service"]
    );
    assert_eq!(info.reload_propagated_from, vec!["reload-source.service"]);
    assert!(!info.default_dependencies);
    assert!(info.ignore_on_isolate);
    assert!(info.stop_when_unneeded);
    assert!(info.refuse_manual_start);
    assert!(info.refuse_manual_stop);
    assert!(info.allow_isolate);
    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());
    let mut mgr = new_test_runtime_manager();
    mgr.load_unit("unitfull.service").unwrap();
    let unit = mgr.units.get("unitfull.service").unwrap();
    assert!(
        unit.dependencies
            .get(&DependencyKind::Requisite)
            .is_some_and(|deps| deps.contains("requisite-a.service"))
    );
    assert!(
        unit.dependencies
            .get(&DependencyKind::BindsTo)
            .is_some_and(|deps| deps.contains("bind-a.service"))
    );
    assert!(
        unit.dependencies
            .get(&DependencyKind::Upholds)
            .is_some_and(|deps| deps.contains("uphold-a.service"))
    );
    assert!(
        unit.dependencies
            .get(&DependencyKind::PartOf)
            .is_some_and(|deps| deps.contains("parent.target"))
    );
    assert!(
        unit.dependencies
            .get(&DependencyKind::OnSuccess)
            .is_some_and(|deps| deps.contains("success-handler.service"))
    );
    assert!(unit.markers.contains(&UnitMarker::RefuseManualStart));
    assert!(unit.markers.contains(&UnitMarker::RefuseManualStop));
    assert!(unit.markers.contains(&UnitMarker::AllowIsolate));
    let spec = mgr.unit_to_spec(unit).unwrap();
    assert!(spec.ignore_on_isolate);
    assert_eq!(
        spec.deps_reload,
        vec!["reload-a.service", "reload-b.service"]
    );
    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_parse_install_section_directives() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-install-directives");
    fs::create_dir_all(&dir).unwrap();
    let service_path = dir.join("demo@.service");
    fs::write(
            &service_path,
            "[Install]\nWantedBy=multi-user.target rescue.target\nRequiredBy=basic.target\nAlso=helper.service helper.path\nAlias=demo.service demo-alt.service\nDefaultInstance=blue\nWantedBy=\nWantedBy=graphical.target\n",
        )
        .unwrap();

    let info = parse_unit_file(&service_path).unwrap().unwrap();
    assert_eq!(info.install.wanted_by, vec!["graphical.target"]);
    assert_eq!(info.install.required_by, vec!["basic.target"]);
    assert_eq!(info.install.also, vec!["helper.service", "helper.path"]);
    assert_eq!(
        info.install.aliases,
        vec!["demo.service", "demo-alt.service"]
    );
    assert_eq!(info.install.default_instance.as_deref(), Some("blue"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_default_instance_only_for_template_units() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-default-instance");
    fs::create_dir_all(&dir).unwrap();

    let template = dir.join("foo@.service");
    let instance = dir.join("foo@bar.service");
    let plain = dir.join("foo.service");
    fs::write(&template, "[Install]\nDefaultInstance=prod\n").unwrap();
    fs::write(&instance, "[Install]\nDefaultInstance=prod\n").unwrap();
    fs::write(&plain, "[Install]\nDefaultInstance=prod\n").unwrap();

    let template_info = parse_unit_file(&template).unwrap().unwrap();
    let instance_info = parse_unit_file(&instance).unwrap().unwrap();
    let plain_info = parse_unit_file(&plain).unwrap().unwrap();

    assert_eq!(
        template_info.install.default_instance.as_deref(),
        Some("prod")
    );
    assert_eq!(instance_info.install.default_instance, None);
    assert_eq!(plain_info.install.default_instance, None);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_parse_scope_section_directives() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-scope-directives");
    fs::create_dir_all(&dir).unwrap();
    let scope_path = dir.join("demo.scope");
    fs::write(
            &scope_path,
            "[Scope]\nRuntimeMaxSec=15min\nRuntimeRandomizedExtraSec=500ms\nTimeoutStopSec=90\nOOMPolicy=kill\nKillSignal=15\nFinalKillSignal=9\nIOAccounting=yes\nMemoryAccounting=no\nTasksAccounting=true\nIPAccounting=1\nTasksMax=2048\n",
        )
        .unwrap();

    let info = parse_unit_file(&scope_path).unwrap().unwrap();
    assert_eq!(info.unit_type, UnitType::Scope);
    assert_eq!(info.scope.runtime_max_sec, Some(900));
    assert_eq!(info.scope.runtime_randomized_extra_sec, Some(1));
    assert_eq!(info.scope.timeout_stop_sec, Some(90));
    assert_eq!(info.scope.oom_policy, Some(OomPolicy::Kill));
    assert_eq!(info.scope.kill_signal, Some(15));
    assert_eq!(info.scope.final_kill_signal, Some(9));
    assert_eq!(info.scope.cgroup.io_accounting, Some(true));
    assert_eq!(info.scope.cgroup.memory_accounting, Some(false));
    assert_eq!(info.scope.cgroup.tasks_accounting, Some(true));
    assert_eq!(info.scope.cgroup.ip_accounting, Some(true));
    assert_eq!(info.scope.cgroup.tasks_max, Some(2048));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_parse_slice_section_cgroup_directives_and_reset() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-slice-directives");
    fs::create_dir_all(&dir).unwrap();
    let slice_path = dir.join("workload.slice");
    fs::write(
            &slice_path,
            "[Slice]\nIOAccounting=yes\nMemoryAccounting=true\nTasksAccounting=0\nIPAccounting=1\nTasksMax=4096\nTasksMax=\n",
        )
        .unwrap();

    let info = parse_unit_file(&slice_path).unwrap().unwrap();
    assert_eq!(info.unit_type, UnitType::Slice);
    assert_eq!(info.slice.cgroup.io_accounting, Some(true));
    assert_eq!(info.slice.cgroup.memory_accounting, Some(true));
    assert_eq!(info.slice.cgroup.tasks_accounting, Some(false));
    assert_eq!(info.slice.cgroup.ip_accounting, Some(true));
    assert_eq!(info.slice.cgroup.tasks_max, None);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_apply_cgroup_config_overrides_unit_context() {
    let _test_lock = test_env_lock();
    let mut unit = Unit::new(UnitManagerRecord::default(), UnitType::Scope);
    let cfg = CgroupConfig {
        io_accounting: Some(false),
        memory_accounting: Some(true),
        tasks_accounting: Some(true),
        ip_accounting: Some(false),
        tasks_max: Some(1234),
        ..Default::default()
    };

    apply_cgroup_config(&mut unit, &cfg);

    let applied = unit.cgroup_context.as_ref().unwrap();
    assert!(!applied.io_accounting);
    assert!(applied.memory_accounting);
    assert!(applied.tasks_accounting);
    assert!(!applied.ip_accounting);
    assert_eq!(applied.tasks_max, 1234);
}

#[test]
fn test_collect_dropin_files_precedence_and_sorting() {
    let _test_lock = test_env_lock();
    let root = test_temp_dir("test-systemd-dropin-precedence");
    let etc = root.join("etc");
    let usr = root.join("usr");
    fs::create_dir_all(etc.join("demo.service.d")).unwrap();
    fs::create_dir_all(usr.join("demo.service.d")).unwrap();

    let etc_10 = etc.join("demo.service.d/10-shared.conf");
    let usr_10 = usr.join("demo.service.d/10-shared.conf");
    let usr_20 = usr.join("demo.service.d/20-low.conf");
    fs::write(&etc_10, "[Unit]\nDescription=etc\n").unwrap();
    fs::write(&usr_10, "[Unit]\nDescription=usr\n").unwrap();
    fs::write(&usr_20, "[Unit]\nAfter=network.target\n").unwrap();

    let files = collect_dropin_files("demo.service", &[etc.clone(), usr.clone()]);
    let names: Vec<&str> = files
        .iter()
        .map(|p| p.file_name().unwrap().to_str().unwrap())
        .collect();

    assert_eq!(names, vec!["10-shared.conf", "20-low.conf"]);
    assert_eq!(files[0], etc_10);
    assert_eq!(files[1], usr_20);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_load_unit_merges_dropins_and_caches_merged_result() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let root = test_temp_dir("test-systemd-dropin-merge-load");
    let etc = root.join("etc");
    let usr = root.join("usr");
    fs::create_dir_all(&etc).unwrap();
    fs::create_dir_all(&usr).unwrap();
    fs::create_dir_all(etc.join("demo.service.d")).unwrap();
    fs::create_dir_all(usr.join("demo.service.d")).unwrap();

    fs::write(
            usr.join("demo.service"),
            "[Unit]\nDescription=Base Service\nWants=base.target\n\n[Service]\nExecStart=/usr/bin/base\n",
        )
        .unwrap();
    fs::write(
        usr.join("demo.service.d/10-wants.conf"),
        "[Unit]\nWants=low.target\n",
    )
    .unwrap();
    fs::write(
        etc.join("demo.service.d/10-wants.conf"),
        "[Unit]\nWants=high.target\n",
    )
    .unwrap();
    fs::write(etc.join("demo.service.d/20-reset.conf"), "[Unit]\nWants=\n").unwrap();
    fs::write(
        etc.join("demo.service.d/30-add.conf"),
        "[Unit]\nWants=final.target\n",
    )
    .unwrap();
    fs::write(
        etc.join("demo.service.d/40-service.conf"),
        "[Service]\nExecStart=/usr/bin/override\n",
    )
    .unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set(
        "SYSTEMD_UNIT_PATH",
        format!("{}:{}", etc.display(), usr.display()),
    );

    let mut mgr = new_test_runtime_manager();
    mgr.load_unit("demo.service").unwrap();
    let info = mgr.unit_files.get("demo.service").unwrap();

    assert_eq!(info.description.as_deref(), Some("Base Service"));
    assert_eq!(info.wants, vec!["final.target"]);
    assert_eq!(info.exec_start.as_deref(), Some("/usr/bin/override"));

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_load_instance_unit_uses_template_and_instance_dropins() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let root = test_temp_dir("test-systemd-template-dropins");
    let etc = root.join("etc");
    let usr = root.join("usr");
    fs::create_dir_all(&etc).unwrap();
    fs::create_dir_all(&usr).unwrap();
    fs::create_dir_all(etc.join("demo@blue.service.d")).unwrap();
    fs::create_dir_all(etc.join("demo@.service.d")).unwrap();

    fs::write(
            usr.join("demo@.service"),
            "[Unit]\nDescription=Template Base\nWants=templ-%i.target\n\n[Service]\nExecStart=/usr/bin/template %i\nEnvironment=ROLE=%i\n",
        )
        .unwrap();
    fs::write(
        etc.join("demo@blue.service.d/10-shared.conf"),
        "[Unit]\nDescription=Instance Override\n",
    )
    .unwrap();
    fs::write(
        etc.join("demo@blue.service.d/20-instance.conf"),
        "[Unit]\nWants=instance.target\n",
    )
    .unwrap();
    fs::write(
        etc.join("demo@.service.d/10-shared.conf"),
        "[Unit]\nDescription=Template Shared\nWants=template-shadowed.target\n",
    )
    .unwrap();
    fs::write(
        etc.join("demo@.service.d/30-template-only.conf"),
        "[Unit]\nAfter=template-only-%i.target\n",
    )
    .unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set(
        "SYSTEMD_UNIT_PATH",
        format!("{}:{}", etc.display(), usr.display()),
    );

    let mut mgr = new_test_runtime_manager();
    mgr.load_unit("demo@blue.service").unwrap();
    let info = mgr.unit_files.get("demo@blue.service").unwrap();

    assert_eq!(info.name, "demo@blue.service");
    assert_eq!(info.description.as_deref(), Some("Instance Override"));
    assert_eq!(info.exec_start.as_deref(), Some("/usr/bin/template blue"));
    assert_eq!(info.wants, vec!["templ-blue.target", "instance.target"]);
    assert_eq!(info.after, vec!["template-only-blue.target"]);
    assert_eq!(info.exec_context.environment, vec!["ROLE=blue".to_string()]);

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn test_expand_unit_specifiers_for_instance_units() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-specifiers-instance");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("foo-bar@baz-qux.service");
    fs::write(
        &path,
        "[Unit]\nDescription=%%|%i|%I|%n|%N|%p|%P|%j|%J|%f|%/|%\n",
    )
    .unwrap();

    let info = parse_unit_file(&path).unwrap().unwrap();
    assert_eq!(
        info.description.as_deref(),
        Some(
            "%|baz-qux|baz/qux|foo-bar@baz-qux.service|foo-bar@baz-qux|foo-bar|foo/bar|bar|bar|/baz/qux|%/|%"
        )
    );

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn test_expand_unit_specifiers_for_non_instance_units() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-specifiers-non-instance");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("foo-bar.service");
    fs::write(
        &path,
        "[Unit]\nDescription=%%|%i|%I|%n|%N|%p|%P|%j|%J|%f|%/|%\n",
    )
    .unwrap();

    let info = parse_unit_file(&path).unwrap().unwrap();
    assert_eq!(
        info.description.as_deref(),
        Some("%|||foo-bar.service|foo-bar|foo-bar|foo/bar|bar|bar|/foo/bar|%/|%")
    );

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn test_expand_unit_specifiers_rejects_unknown_alnum_specifiers() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-specifiers-unknown-alnum");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("foo.service");
    fs::write(
            &path,
            "[Unit]\nDescription=good\nDescription=bad-%x\n\n[Service]\nExecStart=/usr/bin/echo ok\nExecStart=/usr/bin/echo %x\n",
        )
        .unwrap();

    let info = parse_unit_file(&path).unwrap().unwrap();
    assert_eq!(info.description.as_deref(), Some("good"));
    assert_eq!(info.exec_start.as_deref(), Some("/usr/bin/echo ok"));
    assert_eq!(info.service.exec_start.len(), 1);

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn test_expand_unit_specifiers_list_directives_drop_only_invalid_tokens() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-specifiers-tokenwise-list-fallback");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("demo@blue.service");
    fs::write(
            &path,
            "[Unit]\nWants=first.target\nWants=templ-%x.target second.target templ-%i.target\n\n[Service]\nExecStart=/usr/bin/true\n",
        )
        .unwrap();

    let info = parse_unit_file(&path).unwrap().unwrap();
    assert_eq!(
        info.wants,
        vec!["first.target", "second.target", "templ-blue.target"]
    );

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn test_expand_unit_specifiers_for_common_system_specifiers() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-specifiers-common");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("foo-bar@baz-qux.service");
    fs::write(
        &path,
        "[Unit]\nDescription=%a|%A|%b|%B|%H|%l|%m|%M|%o|%q|%v|%w|%W|%t|%T|%V\n",
    )
    .unwrap();

    let info = parse_unit_file(&path).unwrap().unwrap();
    let expected = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        std::env::consts::ARCH,
        resolve_os_release_field("IMAGE_VERSION"),
        resolve_boot_id(),
        resolve_os_release_field("BUILD_ID"),
        resolve_hostname(),
        resolve_short_hostname(),
        resolve_machine_id(),
        resolve_os_release_field("IMAGE_ID"),
        resolve_os_release_field("ID"),
        resolve_pretty_hostname(),
        resolve_kernel_release(),
        resolve_os_release_field("VERSION_ID"),
        resolve_os_release_field("VARIANT_ID"),
        resolve_runtime_dir_root(),
        resolve_tmp_dir(),
        resolve_var_tmp_dir()
    );
    assert_eq!(info.description.as_deref(), Some(expected.as_str()));

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn test_expand_unit_specifiers_for_common_credential_specifiers() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-specifiers-credentials");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("foo.service");
    fs::write(&path, "[Unit]\nDescription=%u|%U|%g|%G|%h|%s\n").unwrap();

    let info = parse_unit_file(&path).unwrap().unwrap();
    let expected = format!(
        "{}|{}|{}|{}|{}|{}",
        resolve_user_name(),
        resolve_user_id(),
        resolve_group_name(),
        resolve_group_id(),
        resolve_user_home(),
        resolve_user_shell()
    );
    assert_eq!(info.description.as_deref(), Some(expected.as_str()));

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn test_expand_unit_specifiers_for_fragment_path_specifiers() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-specifiers-fragment-path");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("foo.service");
    fs::write(&path, "[Unit]\nDescription=%y|%Y\n").unwrap();

    let info = parse_unit_file(&path).unwrap().unwrap();
    let real_path = fs::canonicalize(&path).unwrap_or(path.clone());
    let real_dir = real_path
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let expected = format!("{}|{}", real_path.to_string_lossy(), real_dir);
    assert_eq!(info.description.as_deref(), Some(expected.as_str()));

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn test_expand_unit_specifiers_for_tmp_and_runtime_env_overrides() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-specifiers-env-overrides");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("foo.service");
    fs::write(&path, "[Unit]\nDescription=%t|%T|%V\n").unwrap();

    let prev_xdg = std::env::var("XDG_RUNTIME_DIR").ok();
    let prev_tmpdir = std::env::var("TMPDIR").ok();
    let prev_temp = std::env::var("TEMP").ok();
    let prev_tmp = std::env::var("TMP").ok();

    environment.set("XDG_RUNTIME_DIR", "/tmp/runtime-override");
    environment.set("TMPDIR", "/tmp/tmp-override");
    environment.remove("TEMP");
    environment.remove("TMP");

    let info = parse_unit_file(&path).unwrap().unwrap();
    assert_eq!(
        info.description.as_deref(),
        Some("/tmp/runtime-override|/tmp/tmp-override|/tmp/tmp-override")
    );

    if let Some(value) = prev_xdg {
        environment.set("XDG_RUNTIME_DIR", value);
    } else {
        environment.remove("XDG_RUNTIME_DIR");
    }
    if let Some(value) = prev_tmpdir {
        environment.set("TMPDIR", value);
    } else {
        environment.remove("TMPDIR");
    }
    if let Some(value) = prev_temp {
        environment.set("TEMP", value);
    } else {
        environment.remove("TEMP");
    }
    if let Some(value) = prev_tmp {
        environment.set("TMP", value);
    } else {
        environment.remove("TMP");
    }

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn test_expand_unit_specifiers_missing_system_values_do_not_panic() {
    let _test_lock = test_env_lock();
    assert_eq!(read_trimmed_file("/definitely/not/a/system/file"), None);
    assert_eq!(
        resolve_machine_id_from_paths(&["/definitely/not/a/system/file", "/also/missing"]),
        ""
    );
    assert_eq!(
        resolve_boot_id_from_path("/definitely/not/a/system/file"),
        ""
    );
    assert_eq!(
        resolve_hostname_from_path("/definitely/not/a/system/file"),
        ""
    );
    assert_eq!(
        resolve_os_release_field_from_paths(&["/definitely/not/a/system/file"], "ID"),
        ""
    );
    assert_eq!(
        resolve_pretty_hostname_from_path("/definitely/not/a/system/file"),
        ""
    );
}

#[test]
fn test_resolve_os_release_field_from_paths_parses_quotes_and_escapes() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-os-release-parse");
    fs::create_dir_all(&dir).unwrap();
    let os_release = dir.join("os-release");
    fs::write(
            &os_release,
            "ID=\"demo-os\"\nVERSION_ID='24.04'\nBUILD_ID=2026\nVARIANT_ID=cloud\nIMAGE_ID=\"demo\\\\ image\"\nIMAGE_VERSION=\"v1\\\"2\"\n",
        )
        .unwrap();

    let path = os_release.to_str().unwrap();
    assert_eq!(
        resolve_os_release_field_from_paths(&["/definitely/missing", path], "ID"),
        "demo-os"
    );
    assert_eq!(
        resolve_os_release_field_from_paths(&[path], "VERSION_ID"),
        "24.04"
    );
    assert_eq!(
        resolve_os_release_field_from_paths(&[path], "BUILD_ID"),
        "2026"
    );
    assert_eq!(
        resolve_os_release_field_from_paths(&[path], "VARIANT_ID"),
        "cloud"
    );
    assert_eq!(
        resolve_os_release_field_from_paths(&[path], "IMAGE_ID"),
        "demo\\ image"
    );
    assert_eq!(
        resolve_os_release_field_from_paths(&[path], "IMAGE_VERSION"),
        "v1\"2"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_resolve_pretty_hostname_from_path_reads_machine_info() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-machine-info-parse");
    fs::create_dir_all(&dir).unwrap();
    let machine_info = dir.join("machine-info");
    fs::write(
        &machine_info,
        "PRETTY_HOSTNAME=\"Rust Unit Test Host\"\nOTHER=value\n",
    )
    .unwrap();

    assert_eq!(
        resolve_pretty_hostname_from_path(machine_info.to_str().unwrap()),
        "Rust Unit Test Host"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn test_load_unit_symlink_registers_alias_to_canonical_name() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    use std::os::unix::fs::symlink;

    let root = test_temp_dir("test-systemd-load-unit-symlink-alias");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("real.service"),
        "[Unit]\nDescription=Real\n\n[Service]\nExecStart=/bin/true\n",
    )
    .unwrap();
    symlink(root.join("real.service"), root.join("alias.service")).unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", root.display().to_string());

    let mut mgr = new_test_runtime_manager();
    mgr.load_unit("alias.service").unwrap();

    let unit_from_alias = mgr.get_unit("alias.service").unwrap();
    let unit_from_canonical = mgr.get_unit("real.service").unwrap();

    assert_eq!(unit_from_alias.id.as_deref(), Some("real.service"));
    assert_eq!(unit_from_canonical.id.as_deref(), Some("real.service"));
    assert!(unit_from_alias.aliases.contains("alias.service"));
    assert!(mgr.unit_files.contains_key("real.service"));
    assert!(!mgr.unit_files.contains_key("alias.service"));

    let loaded_units = mgr.unit_count();
    mgr.load_unit("real.service").unwrap();
    assert_eq!(mgr.unit_count(), loaded_units);

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_default_systemd_unit_path_matches_c_search_order() {
    let expected = [
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
    assert_eq!(
        UNIT_SEARCH_PATHS
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>(),
        expected.into_iter().map(PathBuf::from).collect::<Vec<_>>()
    );
}

#[test]
fn test_systemd_unit_path_override() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", "/tmp/a:/tmp/b");
    let paths = unit_search_paths();
    assert_eq!(
        paths,
        vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")]
    );
    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
}

#[test]
fn test_systemd_unit_path_trailing_colon_appends_c_default_search_paths() {
    let paths = parse_unit_search_path("/tmp/early-units:").expect("non-empty path");
    let mut expected = vec![PathBuf::from("/tmp/early-units")];
    expected.extend(default_unit_search_paths());
    assert_eq!(paths, expected);
}

#[test]
fn test_start_unit_async_finishes_without_live_job() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-async-start");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("foo.target"),
        "[Unit]\nDescription=Foo\nAllowIsolate=yes\n",
    )
    .unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());

    let mut mgr = new_test_runtime_manager();
    let job_id = mgr
        .start_unit_async("foo.target", JobMode::Replace)
        .unwrap();
    assert!(job_id > 0);
    assert!(mgr.installed_job(job_id).is_none());
    assert_eq!(
        mgr.get_unit("foo.target")
            .and_then(|unit| unit.current_job_id),
        None
    );
    assert_eq!(
        mgr.get_unit("foo.target").map(|u| u.active_state),
        Some(ActiveState::Active)
    );

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_installed_start_job_waits_for_translated_active_state() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "start.service", ServiceState::Dead);

    let (job_id, installed) = mgr
        .install_target_job("start.service", CanonicalJobType::Start)
        .unwrap();
    assert!(installed);
    assert_eq!(
        mgr.units
            .get("start.service")
            .and_then(|unit| unit.current_job_id),
        Some(job_id)
    );
    assert_eq!(
        mgr.installed_jobs.get(&job_id).map(|job| job.state),
        Some(CanonicalJobState::Waiting)
    );
    assert!(mgr.mark_installed_job_running(job_id));

    mgr.set_service_state("start.service", ServiceState::Condition);
    assert_eq!(
        mgr.installed_job(job_id).map(|job| job.state),
        Some(CanonicalJobState::Running)
    );

    mgr.set_service_state("start.service", ServiceState::Running);
    assert!(mgr.installed_job(job_id).is_none());
    assert_eq!(
        mgr.units
            .get("start.service")
            .and_then(|unit| unit.current_job_id),
        None
    );
    assert_eq!(
        mgr.get_unit("start.service").map(|unit| unit.active_state),
        Some(ActiveState::Active)
    );
}

#[test]
fn test_live_before_barrier_waits_for_async_predecessor_completion() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "predecessor.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "target.service", ServiceState::Dead);
    mgr.units
        .get_mut("predecessor.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::Before)
        .or_default()
        .insert("target.service".into());

    let applied = AppliedTransaction {
        jobs: vec![
            crate::transaction::Job {
                id: 1,
                unit: "target.service".into(),
                job_type: TxJobType::Start,
                matters_to_anchor: true,
                irreversible: false,
                ignore_order: false,
            },
            crate::transaction::Job {
                id: 2,
                unit: "predecessor.service".into(),
                job_type: TxJobType::Start,
                matters_to_anchor: true,
                irreversible: false,
                ignore_order: false,
            },
        ],
        anchor_job: 1,
    };

    let installed = mgr.execute_transaction(&applied).unwrap();
    let target_id = installed[&1];
    let predecessor_id = installed[&2];
    assert_eq!(
        mgr.installed_jobs.get(&predecessor_id).map(|job| job.state),
        Some(CanonicalJobState::Running)
    );
    assert_eq!(
        mgr.installed_jobs.get(&target_id).map(|job| job.state),
        Some(CanonicalJobState::Waiting)
    );

    mgr.set_service_state("predecessor.service", ServiceState::Running);
    assert!(!mgr.installed_jobs.contains_key(&predecessor_id));
    assert_eq!(
        mgr.installed_jobs.get(&target_id).map(|job| job.state),
        Some(CanonicalJobState::Running)
    );
}

#[test]
fn test_requires_failure_propagates_without_becoming_a_dispatch_barrier() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "main.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "required.service", ServiceState::Dead);
    mgr.units
        .get_mut("main.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::Requires)
        .or_default()
        .insert("required.service".into());

    let applied = AppliedTransaction {
        jobs: vec![
            crate::transaction::Job {
                id: 1,
                unit: "main.service".into(),
                job_type: TxJobType::Start,
                matters_to_anchor: true,
                irreversible: false,
                ignore_order: false,
            },
            crate::transaction::Job {
                id: 2,
                unit: "required.service".into(),
                job_type: TxJobType::Start,
                matters_to_anchor: true,
                irreversible: false,
                ignore_order: false,
            },
        ],
        anchor_job: 1,
    };

    let installed = mgr.execute_transaction(&applied).unwrap();
    assert!(installed.values().all(|id| {
        mgr.installed_jobs
            .get(id)
            .is_some_and(|job| job.state == CanonicalJobState::Running)
    }));

    let main_id = installed[&1];
    let required_id = installed[&2];
    mgr.finish_installed_job(required_id, CanonicalJobResult::Failed);
    assert!(mgr.installed_job(required_id).is_none());
    assert!(mgr.installed_job(main_id).is_none());
    assert_eq!(
        mgr.units
            .get("main.service")
            .and_then(|unit| unit.current_job_id),
        None
    );
}

#[test]
fn test_wants_failure_does_not_fail_the_requester() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "main.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "wanted.service", ServiceState::Dead);
    mgr.units
        .get_mut("main.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::Wants)
        .or_default()
        .insert("wanted.service".into());

    let (main_id, _) = mgr
        .install_target_job("main.service", CanonicalJobType::Start)
        .unwrap();
    let (wanted_id, _) = mgr
        .install_target_job("wanted.service", CanonicalJobType::Start)
        .unwrap();
    assert!(mgr.mark_installed_job_running(main_id));
    assert!(mgr.mark_installed_job_running(wanted_id));

    mgr.finish_installed_job(wanted_id, CanonicalJobResult::Failed);
    assert!(mgr.installed_jobs.contains_key(&main_id));
}

#[test]
fn test_requisite_done_but_inactive_fails_only_requisite_requesters() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "prerequisite.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "requisite-main.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "requires-main.service", ServiceState::Dead);
    mgr.units
        .get_mut("requisite-main.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::Requisite)
        .or_default()
        .insert("prerequisite.service".into());
    mgr.units
        .get_mut("requires-main.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::Requires)
        .or_default()
        .insert("prerequisite.service".into());

    let (requisite_id, _) = mgr
        .install_target_job("requisite-main.service", CanonicalJobType::Start)
        .unwrap();
    let (requires_id, _) = mgr
        .install_target_job("requires-main.service", CanonicalJobType::Start)
        .unwrap();
    let (prerequisite_id, _) = mgr
        .install_target_job("prerequisite.service", CanonicalJobType::Start)
        .unwrap();

    mgr.finish_installed_job(prerequisite_id, CanonicalJobResult::Done);
    assert!(!mgr.installed_jobs.contains_key(&requisite_id));
    assert!(mgr.installed_jobs.contains_key(&requires_id));
}

#[test]
fn test_start_failure_propagates_iteratively_through_requires_and_binds_to() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "top.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "middle.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "bottom.service", ServiceState::Dead);
    mgr.units
        .get_mut("top.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::Requires)
        .or_default()
        .insert("middle.service".into());
    mgr.units
        .get_mut("middle.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::BindsTo)
        .or_default()
        .insert("bottom.service".into());

    let (top_id, _) = mgr
        .install_target_job("top.service", CanonicalJobType::Start)
        .unwrap();
    let (middle_id, _) = mgr
        .install_target_job("middle.service", CanonicalJobType::Start)
        .unwrap();
    let (bottom_id, _) = mgr
        .install_target_job("bottom.service", CanonicalJobType::Start)
        .unwrap();

    mgr.finish_installed_job(bottom_id, CanonicalJobResult::Failed);
    assert!(!mgr.installed_jobs.contains_key(&bottom_id));
    assert!(!mgr.installed_jobs.contains_key(&middle_id));
    assert!(!mgr.installed_jobs.contains_key(&top_id));
}

#[test]
fn test_failed_conflict_stop_fails_the_declaring_start_job() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "starter.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "conflict.service", ServiceState::Running);
    mgr.units
        .get_mut("starter.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::Conflicts)
        .or_default()
        .insert("conflict.service".into());

    let (starter_id, _) = mgr
        .install_target_job("starter.service", CanonicalJobType::Start)
        .unwrap();
    let (conflict_id, _) = mgr
        .install_target_job("conflict.service", CanonicalJobType::Stop)
        .unwrap();

    mgr.finish_installed_job(conflict_id, CanonicalJobResult::Failed);
    assert!(!mgr.installed_jobs.contains_key(&conflict_id));
    assert!(!mgr.installed_jobs.contains_key(&starter_id));
}

#[test]
fn test_verify_active_inactive_finishes_skipped_and_propagates_failure() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "main.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "requisite.service", ServiceState::Dead);
    mgr.units
        .get_mut("main.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::Requisite)
        .or_default()
        .insert("requisite.service".into());

    let (main_id, _) = mgr
        .install_target_job("main.service", CanonicalJobType::Start)
        .unwrap();
    let (verify_id, _) = mgr
        .install_target_job("requisite.service", CanonicalJobType::VerifyActive)
        .unwrap();
    mgr.enqueue_installed_job(verify_id);
    mgr.dispatch_job_run_queue();

    assert!(!mgr.installed_jobs.contains_key(&verify_id));
    assert!(!mgr.installed_jobs.contains_key(&main_id));
}

#[test]
fn test_binds_to_stops_active_dependent_when_provider_becomes_inactive() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "provider.service", ServiceState::Running);
    insert_test_service(&mut mgr, "bound.service", ServiceState::Running);
    mgr.units
        .get_mut("bound.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::BindsTo)
        .or_default()
        .insert("provider.service".into());

    mgr.set_service_state("provider.service", ServiceState::Dead);

    assert!(mgr.installed_job_for_unit("bound.service").is_none());
    assert_eq!(
        mgr.units.get("bound.service").map(|unit| unit.active_state),
        Some(ActiveState::Failed)
    );
}

#[test]
fn test_requires_does_not_create_post_transaction_state_coupling() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "provider.service", ServiceState::Running);
    insert_test_service(&mut mgr, "required.service", ServiceState::Running);
    mgr.units
        .get_mut("required.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::Requires)
        .or_default()
        .insert("provider.service".into());

    mgr.set_service_state("provider.service", ServiceState::Dead);

    assert!(mgr.installed_job_for_unit("required.service").is_none());
    assert_eq!(
        mgr.units
            .get("required.service")
            .map(|unit| unit.active_state),
        Some(ActiveState::Active)
    );
}

#[test]
fn test_binds_to_race_repair_stops_unit_activated_after_provider_is_gone() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "oneshot.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "bound.service", ServiceState::Dead);
    mgr.units
        .get_mut("bound.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::BindsTo)
        .or_default()
        .insert("oneshot.service".into());

    mgr.set_service_state("bound.service", ServiceState::Running);

    assert!(mgr.installed_job_for_unit("bound.service").is_none());
    assert_eq!(
        mgr.units.get("bound.service").map(|unit| unit.active_state),
        Some(ActiveState::Failed)
    );
}

#[test]
fn test_unexpected_provider_deactivation_retroactively_replaces_bound_work() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "provider.service", ServiceState::Running);
    insert_test_service(&mut mgr, "bound.service", ServiceState::Running);
    mgr.units
        .get_mut("bound.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::BindsTo)
        .or_default()
        .insert("provider.service".into());

    mgr.set_service_state("provider.service", ServiceState::StopSigterm);

    assert!(mgr.installed_job_for_unit("bound.service").is_none());
    assert_eq!(
        mgr.units.get("bound.service").map(|unit| unit.active_state),
        Some(ActiveState::Failed)
    );
}

#[test]
fn test_retroactive_binds_to_stop_replaces_queued_start_before_dispatch() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "provider.service", ServiceState::Running);
    insert_test_service(&mut mgr, "bound.service", ServiceState::Running);
    mgr.units
        .get_mut("bound.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::BindsTo)
        .or_default()
        .insert("provider.service".into());
    let (start_id, _) = mgr
        .install_target_job("bound.service", CanonicalJobType::Start)
        .unwrap();
    mgr.enqueue_installed_job(start_id);

    mgr.set_service_state("provider.service", ServiceState::StopSigterm);

    assert!(mgr.installed_job(start_id).is_none());
    assert_eq!(
        mgr.units
            .get("bound.service")
            .and_then(|unit| unit.current_job_id),
        None
    );
    assert_eq!(
        mgr.units.get("bound.service").map(|unit| unit.active_state),
        Some(ActiveState::Failed)
    );
}

#[test]
fn test_retroactive_binds_to_stop_preserves_irreversible_queued_start() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "provider.service", ServiceState::Running);
    insert_test_service(&mut mgr, "bound.service", ServiceState::Running);
    mgr.units
        .get_mut("bound.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::BindsTo)
        .or_default()
        .insert("provider.service".into());
    let (start_id, _) = mgr
        .install_canonical_job("bound.service", CanonicalJobType::Start, true, false)
        .unwrap();

    mgr.set_service_state("provider.service", ServiceState::StopSigterm);

    let queued_start = mgr
        .installed_jobs
        .get(&start_id)
        .expect("irreversible start job must remain installed");
    assert_eq!(queued_start.kind, CanonicalJobType::Start);
    assert_eq!(queued_start.state, CanonicalJobState::Waiting);
    assert!(queued_start.irreversible);
    assert_eq!(
        mgr.units
            .get("bound.service")
            .and_then(|unit| unit.current_job_id),
        Some(start_id)
    );
}

#[test]
fn test_binds_to_ignores_maintenance_until_provider_becomes_inactive() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "provider.service", ServiceState::Running);
    insert_test_service(&mut mgr, "bound.service", ServiceState::Running);
    mgr.units
        .get_mut("bound.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::BindsTo)
        .or_default()
        .insert("provider.service".into());

    mgr.set_service_state("provider.service", ServiceState::Cleaning);
    mgr.submit_bound_unit_for_recheck("bound.service");
    mgr.dispatch_bound_stop_queue();
    assert_eq!(
        mgr.installed_job_for_unit("bound.service")
            .map(|job| job.id),
        None
    );
    assert_eq!(
        mgr.units.get("bound.service").map(|unit| unit.active_state),
        Some(ActiveState::Active)
    );

    mgr.set_service_state("provider.service", ServiceState::Dead);
    assert!(mgr.installed_job_for_unit("bound.service").is_none());
    assert_eq!(
        mgr.units.get("bound.service").map(|unit| unit.active_state),
        Some(ActiveState::Failed)
    );
}

#[test]
fn test_nonservice_state_publication_drives_binds_to_liveness() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    mgr.inject_test_unit("provider.target", "provider", ActiveState::Active, "active");
    insert_test_service(&mut mgr, "bound.service", ServiceState::Running);
    mgr.units
        .get_mut("bound.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::BindsTo)
        .or_default()
        .insert("provider.target".into());

    mgr.publish_nonservice_state("provider.target", ActiveState::Inactive);

    assert!(mgr.installed_job_for_unit("bound.service").is_none());
    assert_eq!(
        mgr.units.get("bound.service").map(|unit| unit.active_state),
        Some(ActiveState::Failed)
    );
}

#[test]
fn test_binds_to_cycle_is_deduplicated_by_normal_stop_transactions() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "a.service", ServiceState::Running);
    insert_test_service(&mut mgr, "b.service", ServiceState::Running);
    mgr.units
        .get_mut("a.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::BindsTo)
        .or_default()
        .insert("b.service".into());
    mgr.units
        .get_mut("b.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::BindsTo)
        .or_default()
        .insert("a.service".into());

    mgr.set_service_state("a.service", ServiceState::Dead);

    assert!(mgr.installed_job_for_unit("b.service").is_none());
    assert_eq!(
        mgr.units.get("b.service").map(|unit| unit.active_state),
        Some(ActiveState::Failed)
    );
    assert!(mgr.bound_stop_queue.is_empty());
}

#[test]
fn test_binds_to_continuous_stop_rate_limit_arms_retry_deadline() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "provider.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "bound.service", ServiceState::Dead);
    let bound = mgr.units.get_mut("bound.service").unwrap();
    bound
        .dependencies
        .entry(DependencyKind::BindsTo)
        .or_default()
        .insert("provider.service".into());
    bound.auto_start_stop_ratelimit = crate::unit::RateLimit::new(10_000_000, 1);
    let now_usec = systemd_platform_rs::time::boottime_usec().unwrap();
    bound.auto_start_stop_ratelimit.check(now_usec).unwrap();

    mgr.set_service_state("bound.service", ServiceState::Running);

    assert!(mgr.bound_stop_retry_deadlines.contains_key("bound.service"));
    let first_deadline = mgr.bound_stop_retry_deadlines["bound.service"];
    mgr.set_service_state("bound.service", ServiceState::Running);
    assert_eq!(
        mgr.bound_stop_retry_deadlines["bound.service"],
        first_deadline
    );
    assert!(mgr.installed_job_for_unit("bound.service").is_none());
}

#[test]
fn test_binds_to_with_after_fails_start_if_provider_is_not_active() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "provider.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "bound.service", ServiceState::Dead);
    let bound = mgr.units.get_mut("bound.service").unwrap();
    bound
        .dependencies
        .entry(DependencyKind::BindsTo)
        .or_default()
        .insert("provider.service".into());
    bound
        .dependencies
        .entry(DependencyKind::After)
        .or_default()
        .insert("provider.service".into());

    let (id, _) = mgr
        .install_target_job("bound.service", CanonicalJobType::Start)
        .unwrap();
    mgr.enqueue_installed_job(id);
    mgr.dispatch_job_run_queue();

    assert!(mgr.installed_job(id).is_none());
    assert_eq!(
        mgr.units
            .get("bound.service")
            .and_then(|unit| unit.current_job_id),
        None
    );
    assert_eq!(
        mgr.units.get("bound.service").map(|unit| unit.active_state),
        Some(ActiveState::Inactive)
    );
}

#[test]
fn test_binds_to_without_after_keeps_the_deliberately_racy_start_contract() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "provider.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "bound.service", ServiceState::Dead);
    mgr.units
        .get_mut("bound.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::BindsTo)
        .or_default()
        .insert("provider.service".into());

    assert!(mgr.bound_start_dependencies_satisfied("bound.service"));
}

#[test]
fn test_transaction_preflight_rejects_irreversible_conflict_without_partial_install() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "first.service", ServiceState::Running);
    insert_test_service(&mut mgr, "protected.service", ServiceState::Running);
    let (protected_id, _) = mgr
        .install_canonical_job("protected.service", CanonicalJobType::Start, true, false)
        .unwrap();
    let applied = AppliedTransaction {
        jobs: vec![
            crate::transaction::Job {
                id: 1,
                unit: "first.service".into(),
                job_type: TxJobType::Stop,
                matters_to_anchor: true,
                irreversible: false,
                ignore_order: false,
            },
            crate::transaction::Job {
                id: 2,
                unit: "protected.service".into(),
                job_type: TxJobType::Stop,
                matters_to_anchor: true,
                irreversible: false,
                ignore_order: false,
            },
        ],
        anchor_job: 1,
    };

    assert_eq!(mgr.execute_transaction(&applied), Err(Errno::EEXIST));
    assert_eq!(
        mgr.units
            .get("first.service")
            .and_then(|unit| unit.current_job_id),
        None
    );
    assert_eq!(
        mgr.units
            .get("protected.service")
            .and_then(|unit| unit.current_job_id),
        Some(protected_id)
    );
    assert!(
        mgr.installed_jobs
            .get(&protected_id)
            .is_some_and(|job| job.irreversible && job.kind == CanonicalJobType::Start)
    );
}

#[test]
fn test_transaction_install_preflight_prevents_partial_live_jobs() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "present.service", ServiceState::Dead);

    let applied = AppliedTransaction {
        jobs: vec![
            crate::transaction::Job {
                id: 1,
                unit: "present.service".into(),
                job_type: TxJobType::Start,
                matters_to_anchor: true,
                irreversible: false,
                ignore_order: false,
            },
            crate::transaction::Job {
                id: 2,
                unit: "missing.service".into(),
                job_type: TxJobType::Start,
                matters_to_anchor: true,
                irreversible: false,
                ignore_order: false,
            },
        ],
        anchor_job: 1,
    };

    assert_eq!(mgr.execute_transaction(&applied), Err(Errno::ENOENT));
    assert!(mgr.installed_jobs.is_empty());
    assert_eq!(
        mgr.units
            .get("present.service")
            .and_then(|unit| unit.current_job_id),
        None
    );
}

#[test]
fn test_ignore_order_bypasses_before_barrier_but_keeps_both_jobs_live() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "predecessor.service", ServiceState::Dead);
    insert_test_service(&mut mgr, "target.service", ServiceState::Dead);
    mgr.units
        .get_mut("target.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::After)
        .or_default()
        .insert("predecessor.service".into());

    let applied = AppliedTransaction {
        jobs: vec![
            crate::transaction::Job {
                id: 1,
                unit: "target.service".into(),
                job_type: TxJobType::Start,
                matters_to_anchor: true,
                irreversible: false,
                ignore_order: true,
            },
            crate::transaction::Job {
                id: 2,
                unit: "predecessor.service".into(),
                job_type: TxJobType::Start,
                matters_to_anchor: true,
                irreversible: false,
                ignore_order: false,
            },
        ],
        anchor_job: 1,
    };

    let installed = mgr.execute_transaction(&applied).unwrap();
    assert!(installed.values().all(|id| {
        mgr.installed_jobs
            .get(id)
            .is_some_and(|job| job.state == CanonicalJobState::Running)
    }));
}

#[test]
fn test_stop_jobs_reverse_before_order_at_live_runnable_check() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "a.service", ServiceState::Running);
    insert_test_service(&mut mgr, "b.service", ServiceState::Running);
    mgr.units
        .get_mut("a.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::Before)
        .or_default()
        .insert("b.service".into());

    let (a_id, _) = mgr
        .install_canonical_job("a.service", CanonicalJobType::Stop, false, false)
        .unwrap();
    let (b_id, _) = mgr
        .install_canonical_job("b.service", CanonicalJobType::Stop, false, false)
        .unwrap();

    assert!(!mgr.job_is_runnable(a_id));
    assert!(mgr.job_is_runnable(b_id));
}

#[test]
fn test_restart_start_phase_keeps_id_and_rechecks_live_ordering() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "restart.service", ServiceState::Running);
    insert_test_service(&mut mgr, "after.service", ServiceState::Dead);
    mgr.units
        .get_mut("restart.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::Before)
        .or_default()
        .insert("after.service".into());

    let (restart_id, _) = mgr
        .install_canonical_job("restart.service", CanonicalJobType::Restart, false, false)
        .unwrap();
    let (after_id, _) = mgr
        .install_canonical_job("after.service", CanonicalJobType::Start, false, false)
        .unwrap();
    assert!(mgr.job_is_runnable(restart_id));
    assert!(!mgr.job_is_runnable(after_id));

    assert!(mgr.mark_installed_job_running(restart_id));
    assert!(mgr.change_restart_job_to_start(restart_id));
    assert_eq!(
        mgr.installed_jobs
            .get(&restart_id)
            .map(|job| (job.kind, job.state)),
        Some((CanonicalJobType::Start, CanonicalJobState::Waiting))
    );
    assert!(mgr.job_is_runnable(restart_id));
    assert!(!mgr.job_is_runnable(after_id));
}

#[test]
fn test_installed_reload_job_remains_running_while_refreshing() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "reload.service", ServiceState::Running);

    let (job_id, installed) = mgr
        .install_target_job("reload.service", CanonicalJobType::Reload)
        .unwrap();
    assert!(installed);
    assert!(mgr.mark_installed_job_running(job_id));

    mgr.set_service_state("reload.service", ServiceState::RefreshCredentials);
    assert_eq!(
        mgr.installed_jobs.get(&job_id).map(|job| job.state),
        Some(CanonicalJobState::Running)
    );

    mgr.set_service_state("reload.service", ServiceState::Running);
    assert!(mgr.installed_job(job_id).is_none());
    assert_eq!(
        mgr.units
            .get("reload.service")
            .map(|unit| unit.active_state),
        Some(ActiveState::Active)
    );
}

#[test]
fn test_installed_stop_job_finishes_at_failed_terminal_state() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "stop.service", ServiceState::Running);

    let (job_id, installed) = mgr
        .install_target_job("stop.service", CanonicalJobType::Stop)
        .unwrap();
    assert!(installed);
    assert!(mgr.mark_installed_job_running(job_id));

    mgr.set_service_state("stop.service", ServiceState::StopSigterm);
    assert_eq!(
        mgr.installed_jobs.get(&job_id).map(|job| job.state),
        Some(CanonicalJobState::Running)
    );

    // A stop operation succeeded once the unit is terminal, even when the
    // unit's terminal active state is Failed.
    mgr.set_service_state("stop.service", ServiceState::Failed);
    assert!(mgr.installed_job(job_id).is_none());
    assert_eq!(
        mgr.units.get("stop.service").map(|unit| unit.active_state),
        Some(ActiveState::Failed)
    );
    assert!(mgr.job_registry.reserve_existing_id(job_id).is_ok());
}

#[test]
fn test_installed_restart_job_keeps_id_across_stop_and_start() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "restart.service", ServiceState::Running);

    let (job_id, installed) = mgr
        .install_target_job("restart.service", CanonicalJobType::Restart)
        .unwrap();
    assert!(installed);
    assert!(mgr.mark_installed_job_running(job_id));

    mgr.set_service_state("restart.service", ServiceState::StopSigterm);
    assert_eq!(
        mgr.installed_jobs.get(&job_id).map(|job| job.kind),
        Some(CanonicalJobType::Restart)
    );

    mgr.set_service_state("restart.service", ServiceState::Dead);
    assert_eq!(
        mgr.units
            .get("restart.service")
            .and_then(|unit| unit.current_job_id),
        Some(job_id)
    );
    assert_eq!(
        mgr.installed_jobs
            .get(&job_id)
            .map(|job| (job.kind, job.state)),
        Some((CanonicalJobType::Start, CanonicalJobState::Waiting))
    );
    mgr.dispatch_pending_explicit_restart("restart.service");
    assert_eq!(
        mgr.installed_jobs.get(&job_id).map(|job| job.state),
        Some(CanonicalJobState::Running)
    );
    mgr.set_service_state("restart.service", ServiceState::Condition);
    assert!(mgr.installed_jobs.contains_key(&job_id));
    mgr.set_service_state("restart.service", ServiceState::Running);
    assert!(mgr.installed_job(job_id).is_none());
    assert_eq!(
        mgr.units
            .get("restart.service")
            .map(|unit| unit.active_state),
        Some(ActiveState::Active)
    );
}

#[test]
fn test_replacing_installed_job_cancels_old_not_incoming() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "replace.service", ServiceState::Condition);

    let (old_id, _) = mgr
        .install_target_job("replace.service", CanonicalJobType::Start)
        .unwrap();
    let (new_id, installed) = mgr
        .install_target_job("replace.service", CanonicalJobType::Stop)
        .unwrap();

    assert!(installed);
    assert_ne!(old_id, new_id);
    assert!(mgr.installed_job(old_id).is_none());
    assert_eq!(
        mgr.installed_jobs
            .get(&new_id)
            .map(|job| (job.kind, job.state, job.result)),
        Some((CanonicalJobType::Stop, CanonicalJobState::Waiting, None))
    );
    assert_eq!(
        mgr.units
            .get("replace.service")
            .and_then(|unit| unit.current_job_id),
        Some(new_id)
    );
    assert!(mgr.job_registry.reserve_existing_id(old_id).is_ok());
}

#[test]
fn test_mergeable_installed_job_preserves_identity() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "merge.service", ServiceState::Running);

    let (restart_id, installed) = mgr
        .install_target_job("merge.service", CanonicalJobType::Restart)
        .unwrap();
    assert!(installed);
    assert!(mgr.mark_installed_job_running(restart_id));

    let (merged_id, should_dispatch) = mgr
        .install_target_job("merge.service", CanonicalJobType::Start)
        .unwrap();
    assert_eq!(merged_id, restart_id);
    assert!(!should_dispatch);
    assert_eq!(
        mgr.installed_jobs
            .get(&merged_id)
            .map(|job| (job.kind, job.state, job.result)),
        Some((CanonicalJobType::Restart, CanonicalJobState::Running, None))
    );
}

#[test]
fn test_repeated_running_reload_is_coalesced_for_redispatch() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "reload-again.service", ServiceState::Reload);

    let (first_id, installed) = mgr
        .install_target_job("reload-again.service", CanonicalJobType::Reload)
        .unwrap();
    assert!(installed);
    assert!(mgr.mark_installed_job_running(first_id));

    let (second_id, should_dispatch_now) = mgr
        .install_target_job("reload-again.service", CanonicalJobType::Reload)
        .unwrap();
    assert_eq!(second_id, first_id);
    assert!(!should_dispatch_now);
    assert!(mgr.job_redispatch_queue.contains(&first_id));
    assert_eq!(
        mgr.installed_jobs.get(&first_id).map(|job| job.state),
        Some(CanonicalJobState::Running)
    );
}

#[test]
fn test_running_reload_merged_with_restart_is_queued_for_redispatch() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_test_service(&mut mgr, "reload-restart.service", ServiceState::Reload);
    insert_test_service(&mut mgr, "ordering-peer.service", ServiceState::Dead);
    mgr.units
        .get_mut("reload-restart.service")
        .unwrap()
        .dependencies
        .entry(DependencyKind::After)
        .or_default()
        .insert("ordering-peer.service".into());

    let (reload_id, installed) = mgr
        .install_target_job("reload-restart.service", CanonicalJobType::Reload)
        .unwrap();
    assert!(installed);
    assert!(mgr.mark_installed_job_running(reload_id));
    let (peer_id, _) = mgr
        .install_target_job("ordering-peer.service", CanonicalJobType::Start)
        .unwrap();
    assert!(mgr.mark_installed_job_running(peer_id));

    let applied = AppliedTransaction {
        jobs: vec![crate::transaction::Job {
            id: 1,
            unit: "reload-restart.service".into(),
            job_type: TxJobType::Restart,
            matters_to_anchor: true,
            irreversible: false,
            ignore_order: false,
        }],
        anchor_job: 1,
    };
    let installed = mgr.execute_transaction(&applied).unwrap();
    let restart_id = installed[&1];
    assert_eq!(restart_id, reload_id);
    assert!(mgr.job_redispatch_queue.contains(&restart_id));
    assert!(!mgr.job_run_queue.contains(&restart_id));
    assert_eq!(
        mgr.services
            .get("reload-restart.service")
            .map(|service| service.state),
        Some(ServiceState::Reload)
    );
    mgr.set_service_state("ordering-peer.service", ServiceState::Running);
    assert!(!mgr.installed_jobs.contains_key(&peer_id));
    assert!(!mgr.job_run_queue.contains(&restart_id));
    assert_eq!(
        mgr.installed_jobs
            .get(&restart_id)
            .map(|job| (job.kind, job.state)),
        Some((CanonicalJobType::Restart, CanonicalJobState::Waiting))
    );
    assert_eq!(
        mgr.services
            .get("reload-restart.service")
            .map(|service| service.state),
        Some(ServiceState::Reload)
    );
    assert_eq!(
        mgr.installed_jobs
            .get(&restart_id)
            .map(|job| (job.kind, job.state)),
        Some((CanonicalJobType::Restart, CanonicalJobState::Waiting))
    );
}

#[test]
fn test_isolate_stops_other_active_units() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-isolate-async");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("primary.target"),
        "[Unit]\nDescription=Primary\nAllowIsolate=yes\n",
    )
    .unwrap();
    fs::write(dir.join("other.target"), "[Unit]\nDescription=Other\n").unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());

    let mut mgr = new_test_runtime_manager();
    mgr.start_unit("primary.target").unwrap();
    mgr.start_unit("other.target").unwrap();
    assert_eq!(
        mgr.get_unit("other.target").map(|u| u.active_state),
        Some(ActiveState::Active)
    );

    mgr.isolate("primary.target").unwrap();
    assert_eq!(
        mgr.get_unit("primary.target").map(|u| u.active_state),
        Some(ActiveState::Active)
    );
    assert_eq!(
        mgr.get_unit("other.target").map(|u| u.active_state),
        Some(ActiveState::Inactive)
    );

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_boot_target_isolates_when_allowed() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    mgr.inject_test_unit("boot.target", "Boot", ActiveState::Inactive, "dead");
    mgr.units
        .get_mut("boot.target")
        .unwrap()
        .markers
        .insert(UnitMarker::AllowIsolate);
    mgr.inject_test_unit("other.target", "Other", ActiveState::Active, "active");
    mgr.start_boot_target("boot.target").unwrap();

    assert_eq!(
        mgr.get_unit("boot.target").map(|unit| unit.active_state),
        Some(ActiveState::Active)
    );
    assert_eq!(
        mgr.get_unit("other.target").map(|unit| unit.active_state),
        Some(ActiveState::Inactive)
    );
}

#[test]
fn test_boot_target_retries_replace_when_isolation_is_refused() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    mgr.inject_test_unit("boot.target", "Boot", ActiveState::Inactive, "dead");
    mgr.inject_test_unit("other.target", "Other", ActiveState::Active, "active");
    mgr.start_boot_target("boot.target").unwrap();

    assert_eq!(
        mgr.get_unit("boot.target").map(|unit| unit.active_state),
        Some(ActiveState::Active)
    );
    // The retry is JOB_REPLACE, not a partial or failed isolate; existing
    // unrelated jobs/units therefore remain active.
    assert_eq!(
        mgr.get_unit("other.target").map(|unit| unit.active_state),
        Some(ActiveState::Active)
    );
}

#[test]
fn test_default_target_loading_is_lazy_and_uses_only_the_enoent_fallback() {
    let _test_lock = test_env_lock();
    let mut calls = Vec::new();
    let selected = load_default_target_candidate(false, "graphical.target", |name| {
        calls.push(name.to_string());
        match name {
            "default.target" => Err(Errno::ENOENT),
            "graphical.target" => Ok(()),
            _ => panic!("default-target selection loaded unrelated unit {name}"),
        }
    })
    .unwrap();

    assert_eq!(selected, "graphical.target");
    assert_eq!(calls, ["default.target", "graphical.target"]);

    calls.clear();
    let error = load_default_target_candidate(false, "graphical.target", |name| {
        calls.push(name.to_string());
        Err(Errno::ENOEXEC)
    })
    .unwrap_err();
    assert_eq!(error, Errno::ENOEXEC);
    assert_eq!(calls, ["default.target"]);
}

#[test]
fn test_initrd_default_target_fallback_never_uses_the_host_build_default() {
    let _test_lock = test_env_lock();
    let mut calls = Vec::new();
    let selected = load_default_target_candidate(true, "graphical.target", |name| {
        calls.push(name.to_string());
        if name == "initrd.target" {
            Err(Errno::ENOENT)
        } else {
            Ok(())
        }
    })
    .unwrap();

    assert_eq!(selected, "default.target");
    assert_eq!(calls, ["initrd.target", "default.target"]);
}

#[cfg(target_os = "linux")]
#[test]
fn test_idle_pipe_gate_keeps_all_endpoints_until_manager_acknowledges() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    let pipe = mgr.idle_pipe_for_spawn().unwrap();
    assert!(pipe.child_wait_fd >= 0);
    assert!(pipe.manager_release_fd >= 0);
    assert!(pipe.manager_alert_fd >= 0);
    assert!(pipe.child_alert_fd >= 0);
    assert_ne!(pipe.child_wait_fd, pipe.manager_release_fd);
    assert_ne!(pipe.manager_alert_fd, pipe.child_alert_fd);

    let descriptor = mgr.idle_pipe_alert_descriptor().unwrap().unwrap();
    assert!(descriptor.generation() > 0);
    mgr.close_idle_pipe();
    assert!(mgr.idle_pipe_alert_descriptor().unwrap().is_none());
}

#[test]
fn test_reset_failed_clears_failed_state() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    let mut unit = Unit::new(UnitManagerRecord::default(), UnitType::Service);
    unit.id = Some("failed.service".to_string());
    unit.active_state = ActiveState::Failed;
    mgr.units.insert("failed.service".to_string(), unit);

    mgr.reset_failed("failed.service").unwrap();
    assert_eq!(
        mgr.units.get("failed.service").map(|u| u.active_state),
        Some(ActiveState::Inactive)
    );
}

#[test]
fn test_kill_unit_rejects_missing_pid() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    let mut unit = Unit::new(UnitManagerRecord::default(), UnitType::Service);
    unit.id = Some("nopid.service".to_string());
    mgr.units.insert("nopid.service".to_string(), unit);

    let result = mgr.kill_unit("nopid.service", UnitKillWho::All, 15);
    assert_eq!(result, Err(Errno::ENOENT));
}

#[test]
fn test_start_post_reaches_running_only_after_its_exact_exit_event() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "pipeline.service",
        ServiceState::StartPost,
        ServiceType::Simple,
        |_| {},
    );
    mgr.inject_test_main_pid("pipeline.service", 41_015);
    mgr.inject_test_service_command(
        "pipeline.service",
        ServiceExecCommand::StartPost,
        41_013,
        "",
    )
    .unwrap();
    assert_eq!(
        mgr.get_unit("pipeline.service").map(|u| u.active_state),
        Some(ActiveState::Activating)
    );
    assert!(mgr.inject_test_service_event(
        "pipeline.service",
        ServiceTestEvent::ChildExited {
            pid: 41_013,
            state: ChildState::ExitedCleanly,
        },
    ));
    assert_eq!(
        mgr.get_unit("pipeline.service").map(|u| u.active_state),
        Some(ActiveState::Active)
    );
}

#[test]
fn test_service_condition_failure_skips_start() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-service-condition-fail");
    fs::create_dir_all(&dir).unwrap();
    let marker = dir.join("condition.log");
    let unit = "[Unit]\nConditionPathExists=/definitely/missing/path\n[Service]\nType=simple\nExecStartPre=/not-run\nExecStart=/not-run\n";
    fs::write(dir.join("cond.service"), unit).unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());

    let mut mgr = new_test_runtime_manager();
    mgr.start_unit("cond.service").unwrap();
    assert_eq!(
        mgr.get_unit("cond.service").map(|u| u.active_state),
        Some(ActiveState::Inactive)
    );
    assert!(!marker.exists());

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_parse_condition_trigger_prefix() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-condition-trigger");
    fs::create_dir_all(&dir).unwrap();
    let service_path = dir.join("trigger.service");
    fs::write(
        &service_path,
        "[Unit]\nConditionPathExists=|!/definitely-missing-path\n",
    )
    .unwrap();

    let info = parse_unit_file(&service_path).unwrap().unwrap();
    assert_eq!(info.conditions.path_exists.len(), 1);
    assert!(info.conditions.path_exists[0].trigger);
    assert!(info.conditions.path_exists[0].invert);
    assert_eq!(
        info.conditions.path_exists[0].value,
        "/definitely-missing-path"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_service_assert_failure_marks_unit_failed() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-service-assert-fail");
    fs::create_dir_all(&dir).unwrap();
    let marker = dir.join("assert.log");
    let unit = "[Unit]\nAssertPathExists=/definitely/missing/path\n[Service]\nType=simple\nExecStart=/not-run\n";
    fs::write(dir.join("assert.service"), unit).unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());

    let mut mgr = new_test_runtime_manager();
    mgr.start_unit("assert.service").unwrap();
    assert_eq!(
        mgr.get_unit("assert.service").map(|u| u.active_state),
        Some(ActiveState::Failed)
    );
    assert!(!marker.exists());

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_stop_command_advances_only_after_its_exact_exit_event() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "stop.service",
        ServiceState::Running,
        ServiceType::Simple,
        |_| {},
    );
    mgr.inject_test_service_command("stop.service", ServiceExecCommand::Stop, 41_014, "")
        .unwrap();
    assert_eq!(
        mgr.get_unit("stop.service").map(|u| u.active_state),
        Some(ActiveState::Deactivating)
    );
    assert!(mgr.inject_test_service_event(
        "stop.service",
        ServiceTestEvent::ChildExited {
            pid: 41_014,
            state: ChildState::ExitedCleanly,
        },
    ));
    assert_ne!(
        mgr.services
            .get("stop.service")
            .map(|service| service.state),
        Some(ServiceState::Stop)
    );
    assert!(!mgr.pid_to_unit_map.contains_key(&41_014));
}

#[test]
fn test_notify_service_fails_closed_without_authenticated_transport() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-notify-ready");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("notify.service"),
        "[Service]\nType=notify\nExecStart=/not-run\nExecStartPost=/not-run\n",
    )
    .unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());

    let mut mgr = new_test_runtime_manager();
    mgr.start_unit("notify.service").unwrap();
    assert_eq!(
        mgr.get_unit("notify.service").map(|u| u.active_state),
        Some(ActiveState::Failed)
    );

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_idle_service_launch_failure_remains_a_service_failure() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-idle-without-gate");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("idle.service"),
        "[Service]\nType=idle\nExecStart=/not-run\n",
    )
    .unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());

    let mut mgr = new_test_runtime_manager();
    mgr.start_unit("idle.service").unwrap();
    assert_eq!(
        mgr.get_unit("idle.service").map(|u| u.active_state),
        Some(ActiveState::Failed)
    );

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_dbus_service_without_bus_name_fails_closed() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-dbus-without-name");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("missing-name.service"),
        "[Service]\nType=dbus\nExecStart=/not-run\n",
    )
    .unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());

    let mut mgr = new_test_runtime_manager();
    mgr.start_unit("missing-name.service").unwrap();
    assert_eq!(
        mgr.get_unit("missing-name.service").map(|u| u.active_state),
        Some(ActiveState::Failed)
    );

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_service_restart_policy_queues_after_exact_main_exit_event() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "restart.service",
        ServiceState::Running,
        ServiceType::Simple,
        |info| {
            info.service.restart = Some(ServiceRestartPolicy::OnFailure);
            info.service.restart_sec = Some(60);
        },
    );
    mgr.inject_test_main_pid("restart.service", 41_001);

    assert!(mgr.inject_test_service_event(
        "restart.service",
        ServiceTestEvent::ChildExited {
            pid: 41_001,
            state: ChildState::ExitedWithCode(1),
        },
    ));
    assert_eq!(
        mgr.services
            .get("restart.service")
            .map(|service| service.state),
        Some(ServiceState::AutoRestartQueued)
    );
    assert_eq!(
        mgr.services
            .get("restart.service")
            .map(|service| service.n_restarts),
        Some(1)
    );
    assert!(
        mgr.service_restart_deadlines
            .contains_key("restart.service")
    );
}

#[test]
fn test_ignore_failure_condition_advances_only_after_its_exact_exit_event() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "condition.service",
        ServiceState::Dead,
        ServiceType::Oneshot,
        |info| info.service.remain_after_exit = Some(true),
    );
    mgr.inject_test_service_command(
        "condition.service",
        ServiceExecCommand::Condition,
        41_002,
        "-",
    )
    .unwrap();

    assert!(mgr.inject_test_service_event(
        "condition.service",
        ServiceTestEvent::ChildExited {
            pid: 41_002,
            state: ChildState::ExitedWithCode(1),
        },
    ));
    assert_eq!(
        mgr.services
            .get("condition.service")
            .map(|service| service.state),
        Some(ServiceState::Exited)
    );
    assert_eq!(
        mgr.services
            .get("condition.service")
            .map(|service| service.result),
        Some(ServiceResult::Success)
    );
}

#[test]
fn test_stale_control_exit_event_cannot_advance_the_current_command() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "stale-control.service",
        ServiceState::Dead,
        ServiceType::Oneshot,
        |info| info.service.remain_after_exit = Some(true),
    );
    mgr.inject_test_service_command(
        "stale-control.service",
        ServiceExecCommand::Condition,
        41_003,
        "",
    )
    .unwrap();

    assert!(!mgr.inject_test_service_event(
        "stale-control.service",
        ServiceTestEvent::ChildExited {
            pid: 41_004,
            state: ChildState::ExitedCleanly,
        },
    ));
    assert_eq!(
        mgr.services
            .get("stale-control.service")
            .map(|service| service.state),
        Some(ServiceState::Condition)
    );
    assert_eq!(
        mgr.units
            .get("stale-control.service")
            .and_then(|unit| unit.control_pid)
            .map(|pid| pid.0),
        Some(41_003)
    );

    assert!(mgr.inject_test_service_event(
        "stale-control.service",
        ServiceTestEvent::ChildExited {
            pid: 41_003,
            state: ChildState::ExitedCleanly,
        },
    ));
    assert_eq!(
        mgr.services
            .get("stale-control.service")
            .map(|service| service.state),
        Some(ServiceState::Exited)
    );
}

#[test]
fn test_exec_service_waits_for_the_exact_execed_event_before_running() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "execed.service",
        ServiceState::Dead,
        ServiceType::Exec,
        |_| {},
    );
    mgr.inject_test_service_command("execed.service", ServiceExecCommand::Start, 41_005, "")
        .unwrap();

    assert!(
        !mgr.inject_test_service_event("execed.service", ServiceTestEvent::Execed { pid: 41_006 },)
    );
    assert_eq!(
        mgr.services
            .get("execed.service")
            .map(|service| service.state),
        Some(ServiceState::Start)
    );
    assert!(
        mgr.inject_test_service_event("execed.service", ServiceTestEvent::Execed { pid: 41_005 },)
    );
    assert_eq!(
        mgr.services
            .get("execed.service")
            .map(|service| service.state),
        Some(ServiceState::Running)
    );
}

#[test]
fn test_reload_waits_for_control_exit_after_main_death() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "reload.service",
        ServiceState::Running,
        ServiceType::Simple,
        |_| {},
    );
    mgr.inject_test_main_pid("reload.service", 41_007);
    mgr.inject_test_service_command("reload.service", ServiceExecCommand::Reload, 41_008, "")
        .unwrap();

    assert!(mgr.inject_test_service_event(
        "reload.service",
        ServiceTestEvent::ChildExited {
            pid: 41_007,
            state: ChildState::ExitedWithCode(1),
        },
    ));
    assert_eq!(
        mgr.services
            .get("reload.service")
            .map(|service| service.state),
        Some(ServiceState::Reload)
    );
    assert!(mgr.inject_test_service_event(
        "reload.service",
        ServiceTestEvent::ChildExited {
            pid: 41_008,
            state: ChildState::ExitedCleanly,
        },
    ));
    assert_ne!(
        mgr.services
            .get("reload.service")
            .map(|service| service.state),
        Some(ServiceState::Running)
    );
}

#[test]
fn test_alien_cgroup_empty_event_clears_the_untracked_main_pid() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "alien.service",
        ServiceState::Running,
        ServiceType::Simple,
        |_| {},
    );
    // No ProcessTracker child is inserted: this models a cgroup-reported PID
    // that the manager no longer owns as a direct child.
    mgr.inject_test_main_pid("alien.service", 41_009);

    assert!(mgr.inject_test_service_event("alien.service", ServiceTestEvent::CgroupEmpty));
    assert_eq!(
        mgr.units
            .get("alien.service")
            .and_then(|unit| unit.main_pid),
        None
    );
    assert_eq!(
        mgr.services
            .get("alien.service")
            .map(|service| service.state),
        Some(ServiceState::Dead)
    );
}

#[test]
fn test_final_kill_escalation_uses_the_canonical_signal_transition() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "final-kill.service",
        ServiceState::FinalSigterm,
        ServiceType::Simple,
        |_| {},
    );

    mgr.inject_test_service_signal_deadline("final-kill.service", ServiceState::FinalSigterm)
        .unwrap();
    assert!(mgr.inject_test_service_event("final-kill.service", ServiceTestEvent::Timeout));
    assert_eq!(
        mgr.services
            .get("final-kill.service")
            .map(|service| service.state),
        Some(ServiceState::Failed)
    );
}

#[test]
fn test_service_stdio_file_append_and_truncate_open_modes_without_a_child() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-stdio-file-modes");
    fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("stdio.log");
    let mgr = new_test_runtime_manager();

    // The semantics under test are the flags used while preparing the
    // descriptor, not scheduling an external shell and hoping it has run.
    // Keep ownership in PreparedStdio until each assertion completes.
    for target in ["file", "append"] {
        fs::write(&log_path, "preserved").unwrap();
        let mut info = UnitFileInfo::new("stdio.service", PathBuf::from("stdio.service"));
        info.exec_context.standard_output = Some(format!("{target}:{}", log_path.display()));
        let prepared = mgr.prepare_service_stdio("stdio.service", &info);
        assert!(prepared.stdio.stdout_fd.is_some());
        assert_eq!(fs::read_to_string(&log_path).unwrap(), "preserved");
    }

    fs::write(&log_path, "must be truncated").unwrap();
    let mut info = UnitFileInfo::new("stdio.service", PathBuf::from("stdio.service"));
    info.exec_context.standard_output = Some(format!("truncate:{}", log_path.display()));
    let prepared = mgr.prepare_service_stdio("stdio.service", &info);
    assert!(prepared.stdio.stdout_fd.is_some());
    assert!(prepared.owned_fds.len() == 1);
    assert_eq!(fs::read_to_string(&log_path).unwrap(), "");
    drop(prepared);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_service_stdio_socket_uses_activation_fd_without_a_child() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    mgr.socket_mgr
        .register_socket("socket-stdio.socket", "127.0.0.1:0")
        .unwrap();
    let expected_fd = mgr
        .socket_mgr
        .get("socket-stdio.socket")
        .and_then(|s| s.raw_fd())
        .unwrap();

    let mut info = UnitFileInfo::new(
        "socket-stdio.service",
        PathBuf::from("socket-stdio.service"),
    );
    info.service.sockets.push("socket-stdio.socket".to_string());
    info.exec_context.standard_output = Some("socket".to_string());
    let prepared = mgr.prepare_service_stdio("socket-stdio.service", &info);
    assert_eq!(prepared.stdio.stdout_fd, Some(expected_fd));
    assert!(prepared.owned_fds.is_empty());
}

#[test]
fn test_service_stdio_journal_console_selects_the_console_mirror_mode() {
    let _test_lock = test_env_lock();
    let spec = RuntimeManager::parse_stdio_spec(Some("journal+console"));
    assert_eq!(spec.mode, StdioTargetMode::JournalAndConsole);
    assert_eq!(spec.payload, None);
}

#[test]
fn test_forking_service_tracks_control_pid_separately_through_the_typed_fsm() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "forking.service",
        ServiceState::Dead,
        ServiceType::Forking,
        |_| {},
    );
    mgr.inject_test_service_command("forking.service", ServiceExecCommand::Start, 41_010, "")
        .unwrap();

    let unit = mgr.units.get("forking.service").unwrap();
    let control_pid = unit.control_pid.expect("control pid missing").0;
    assert!(unit.main_pid.is_none());
    assert_eq!(
        mgr.pid_role_map.get(&control_pid).copied(),
        Some(TrackedPidRole::Control)
    );
    assert_eq!(
        mgr.pid_to_unit_map.get(&control_pid).map(String::as_str),
        Some("forking.service")
    );
    assert!(mgr.inject_test_service_event(
        "forking.service",
        ServiceTestEvent::ChildExited {
            pid: control_pid,
            state: ChildState::ExitedCleanly,
        },
    ));
    assert!(
        mgr.units
            .get("forking.service")
            .and_then(|unit| unit.control_pid)
            .is_none()
    );
}

#[test]
fn test_pid_reverse_map_cleared_on_exact_main_exit_event() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "tracked.service",
        ServiceState::Running,
        ServiceType::Simple,
        |_| {},
    );
    let pid = 41_011;
    mgr.inject_test_main_pid("tracked.service", pid);
    assert_eq!(
        mgr.pid_to_unit_map.get(&pid).map(String::as_str),
        Some("tracked.service")
    );

    assert!(mgr.inject_test_service_event(
        "tracked.service",
        ServiceTestEvent::ChildExited {
            pid,
            state: ChildState::ExitedCleanly,
        },
    ));
    assert!(!mgr.unit_pid_map.contains_key("tracked.service"));
    assert!(!mgr.pid_to_unit_map.contains_key(&pid));
    assert!(!mgr.pid_role_map.contains_key(&pid));
}

#[test]
fn test_untracked_child_exit_event_is_rejected_without_service_mutation() {
    let _test_lock = test_env_lock();
    let mut mgr = new_test_runtime_manager();
    insert_fsm_service(
        &mut mgr,
        "untracked.service",
        ServiceState::Running,
        ServiceType::Simple,
        |_| {},
    );
    assert!(!mgr.inject_test_service_event(
        "untracked.service",
        ServiceTestEvent::ChildExited {
            pid: 41_012,
            state: ChildState::ExitedCleanly,
        },
    ));
    assert_eq!(
        mgr.services
            .get("untracked.service")
            .map(|service| service.state),
        Some(ServiceState::Running)
    );
    assert!(mgr.pid_to_unit_map.is_empty());
}

#[test]
fn test_cgroup_path_uses_slice_hierarchy() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-cgroup-slice-hierarchy");
    let cgroup_root = dir.join("cgroup-root");
    let mut mgr = RuntimeManager::new_with_test_cgroup_root(cgroup_root.clone());
    let mut info = UnitFileInfo::new("hier.service", dir.join("hier.service"));
    info.cgroup.slice = Some("tenant-prod.slice".to_string());
    info.cgroup.cpu_weight = Some(200);
    mgr.ensure_unit_cgroup("hier.service", &info).unwrap();

    let cgroup_path = mgr
        .unit_cgroup_paths
        .get("hier.service")
        .cloned()
        .expect("missing cgroup path");
    assert_eq!(
        cgroup_path,
        cgroup_root
            .join("tenant.slice")
            .join("tenant-prod.slice")
            .join("hier.service")
    );

    let subtree =
        fs::read_to_string(cgroup_path.parent().unwrap().join("cgroup.subtree_control")).unwrap();
    assert!(subtree.contains("+cpu"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_cgroup_realization_writes_controller_and_limit_files() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-cgroup-realize-files");
    let cgroup_root = dir.join("cgroup-root");
    let mut mgr = RuntimeManager::new_with_test_cgroup_root(cgroup_root.clone());
    let mut info = UnitFileInfo::new("limits.service", dir.join("limits.service"));
    info.cgroup.cpu_weight = Some(111);
    info.cgroup.io_weight = Some(222);
    info.cgroup.memory_min = Some("67108864".to_string());
    info.cgroup.memory_max = Some("1073741824".to_string());
    info.cgroup.memory_swap_max = Some("2147483648".to_string());
    info.cgroup.tasks_max = Some(1234);
    mgr.ensure_unit_cgroup("limits.service", &info).unwrap();

    let cgroup_path = mgr
        .unit_cgroup_paths
        .get("limits.service")
        .cloned()
        .expect("missing cgroup path");
    assert_eq!(
        cgroup_path,
        cgroup_root.join("system.slice").join("limits.service")
    );

    assert_eq!(
        fs::read_to_string(cgroup_path.join("cpu.weight")).unwrap(),
        "111\n"
    );
    assert_eq!(
        fs::read_to_string(cgroup_path.join("memory.max")).unwrap(),
        "1073741824\n"
    );
    assert_eq!(
        fs::read_to_string(cgroup_path.join("memory.swap.max")).unwrap(),
        "2147483648\n"
    );
    assert_eq!(
        fs::read_to_string(cgroup_path.join("pids.max")).unwrap(),
        "1234\n"
    );
    let io_weight = fs::read_to_string(cgroup_path.join("io.weight")).unwrap();
    assert!(io_weight.contains("default 222"));
    let subtree =
        fs::read_to_string(cgroup_path.parent().unwrap().join("cgroup.subtree_control")).unwrap();
    assert!(subtree.contains("+cpu"));
    assert!(subtree.contains("+io"));
    assert!(subtree.contains("+memory"));
    assert!(subtree.contains("+pids"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_cgroup_realization_rejects_unimplemented_non_cgroupfs_settings() {
    let dir = test_temp_dir("test-systemd-cgroup-reject-fake-controls");
    let mut info = UnitFileInfo::new("unsupported.service", dir.join("unsupported.service"));
    info.cgroup.ip_address_allow.push("10.0.0.0/8".to_string());

    let mut mgr = RuntimeManager::new_with_test_cgroup_root(dir.join("cgroup-root"));
    let error = mgr
        .ensure_unit_cgroup("unsupported.service", &info)
        .unwrap_err();
    assert_eq!(
        error.operation(),
        super::cgroup_runtime::CgroupRealizationOperation::UnsupportedSetting
    );
    assert_eq!(error.path(), std::path::Path::new("IPAddressAllow"));
    assert!(!mgr.unit_cgroups.contains_key("unsupported.service"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_stop_prunes_unit_cgroup_when_empty() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-cgroup-prune-empty");
    let cgroup_root = dir.join("cgroup-root");
    let mut mgr = RuntimeManager::new_with_test_cgroup_root(cgroup_root.clone());
    let info = UnitFileInfo::new("tracked.service", dir.join("tracked.service"));
    mgr.unit_files.insert(info.name.clone(), info.clone());
    mgr.ensure_unit_cgroup("tracked.service", &info).unwrap();
    let cgroup_path = mgr
        .unit_cgroup_paths
        .get("tracked.service")
        .cloned()
        .expect("missing cgroup path");
    assert!(cgroup_path.exists());

    mgr.prune_unit_cgroup("tracked.service");
    assert!(!cgroup_path.exists());
    assert!(!mgr.unit_cgroup_paths.contains_key("tracked.service"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_delegate_owns_distinct_payload_and_control_capabilities() {
    let dir = test_temp_dir("test-systemd-cgroup-delegate-targets");
    let mut info = UnitFileInfo::new("delegate.service", dir.join("delegate.service"));
    info.cgroup.delegate = Some(true);
    info.cgroup.delegate_subgroup = Some("payload".to_string());

    let mut mgr = RuntimeManager::new_with_test_cgroup_root(dir.join("cgroup-root"));
    mgr.unit_files
        .insert("delegate.service".to_string(), info.clone());
    mgr.ensure_unit_cgroup("delegate.service", &info).unwrap();
    let unit_path = mgr
        .unit_cgroup_paths
        .get("delegate.service")
        .cloned()
        .unwrap();
    assert!(unit_path.join("payload").is_dir());
    assert!(unit_path.join(".control").is_dir());

    {
        let start = mgr
            .unit_cgroup_spawn_fds("delegate.service", ServiceExecCommand::Start)
            .unwrap();
        let start_target = fs::read_link(format!(
            "/proc/self/fd/{}",
            start.target_directory.as_raw_fd()
        ))
        .unwrap();
        assert_eq!(start_target, unit_path.join("payload"));
        assert!(start.recursive_target_access);
    }

    {
        let post = mgr
            .unit_cgroup_spawn_fds("delegate.service", ServiceExecCommand::StartPost)
            .unwrap();
        let post_target = fs::read_link(format!(
            "/proc/self/fd/{}",
            post.target_directory.as_raw_fd()
        ))
        .unwrap();
        assert_eq!(post_target, unit_path.join(".control"));
        assert!(post.delegated);
        assert!(post.recursive_target_access);
    }

    {
        let condition = mgr
            .unit_cgroup_spawn_fds("delegate.service", ServiceExecCommand::Condition)
            .unwrap();
        let condition_target = fs::read_link(format!(
            "/proc/self/fd/{}",
            condition.target_directory.as_raw_fd()
        ))
        .unwrap();
        assert_eq!(condition_target, unit_path.join(".control"));
        assert!(condition.recursive_target_access);
    }

    let nested = unit_path.join("payload").join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("cgroup.procs"), b"4242\n").unwrap();
    assert_eq!(
        mgr.read_unit_cgroup_pids("delegate.service").unwrap(),
        vec![4242]
    );

    mgr.prune_unit_cgroup("delegate.service");
    assert!(!unit_path.exists());
    assert!(!mgr.unit_cgroups.contains_key("delegate.service"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_delegate_without_subgroup_keeps_initial_commands_in_unit_leaf() {
    let dir = test_temp_dir("test-systemd-cgroup-delegate-leaf");
    let mut info = UnitFileInfo::new("delegate-leaf.service", dir.join("delegate-leaf.service"));
    info.cgroup.delegate = Some(true);

    let mut mgr = RuntimeManager::new_with_test_cgroup_root(dir.join("cgroup-root"));
    mgr.unit_files
        .insert("delegate-leaf.service".to_string(), info.clone());
    mgr.ensure_unit_cgroup("delegate-leaf.service", &info)
        .unwrap();
    let unit_path = mgr
        .unit_cgroup_paths
        .get("delegate-leaf.service")
        .cloned()
        .unwrap();

    for command in [
        ServiceExecCommand::Condition,
        ServiceExecCommand::StartPre,
        ServiceExecCommand::Start,
    ] {
        let target = mgr
            .unit_cgroup_spawn_fds("delegate-leaf.service", command)
            .unwrap();
        assert_eq!(
            fs::read_link(format!(
                "/proc/self/fd/{}",
                target.target_directory.as_raw_fd()
            ))
            .unwrap(),
            unit_path
        );
        assert!(!target.recursive_target_access);
    }

    {
        let post = mgr
            .unit_cgroup_spawn_fds("delegate-leaf.service", ServiceExecCommand::StartPost)
            .unwrap();
        assert_eq!(
            fs::read_link(format!(
                "/proc/self/fd/{}",
                post.target_directory.as_raw_fd()
            ))
            .unwrap(),
            unit_path.join(".control")
        );
        assert!(post.recursive_target_access);
    }

    mgr.prepare_delegated_cgroup_start("delegate-leaf.service");
    assert_eq!(
        fs::read_to_string(unit_path.join("cgroup.subtree_control")).unwrap(),
        "-pids\n"
    );

    mgr.prune_unit_cgroup("delegate-leaf.service");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_cgroup_controls_are_normalized_before_kernel_writes() {
    let dir = test_temp_dir("test-systemd-cgroup-normalized-controls");
    fs::create_dir_all(&dir).unwrap();
    let backing = dir.join("backing-file");
    fs::write(&backing, b"device identity fixture").unwrap();

    let mut info = UnitFileInfo::new("normalize.service", dir.join("normalize.service"));
    info.cgroup.cpu_quota = Some("50%".to_string());
    info.cgroup.cpu_quota_period_usec = Some(200_000);
    info.cgroup.allowed_cpus = Some("3,1-2,2".to_string());
    info.cgroup.memory_min = Some("128M".to_string());
    info.cgroup.memory_max = Some("1G".to_string());
    info.cgroup.io_device_weight = vec![format!("{} 250", backing.display())];
    info.cgroup.io_limits = vec![
        CgroupIoLimitConfig {
            kind: CgroupIoLimitKind::ReadBandwidth,
            value: format!("{} 10M", backing.display()),
        },
        CgroupIoLimitConfig {
            kind: CgroupIoLimitKind::WriteIops,
            value: format!("{} 200", backing.display()),
        },
    ];

    let mut mgr = RuntimeManager::new_with_test_cgroup_root(dir.join("cgroup-root"));
    mgr.ensure_unit_cgroup("normalize.service", &info).unwrap();
    let cgroup = mgr.unit_cgroup_paths.get("normalize.service").unwrap();
    assert_eq!(
        fs::read_to_string(cgroup.join("cpu.max")).unwrap(),
        "100000 200000\n"
    );
    assert_eq!(
        fs::read_to_string(cgroup.join("cpuset.cpus")).unwrap(),
        "1-3\n"
    );
    assert_eq!(
        fs::read_to_string(cgroup.join("memory.min")).unwrap(),
        "134217728\n"
    );
    assert_eq!(
        fs::read_to_string(cgroup.join("memory.max")).unwrap(),
        "1073741824\n"
    );
    let io_weight = fs::read_to_string(cgroup.join("io.weight")).unwrap();
    assert!(io_weight.ends_with(" 250\n"));
    let io_max = fs::read_to_string(cgroup.join("io.max")).unwrap();
    assert!(io_max.contains("rbps=10000000"));
    assert!(io_max.contains("wbps=max"));
    assert!(io_max.contains("riops=max"));
    assert!(io_max.contains("wiops=200"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_cgroup_io_controls_reject_character_devices() {
    let dir = test_temp_dir("test-systemd-cgroup-reject-char-device");
    let mut info = UnitFileInfo::new("char-device.service", dir.join("char-device.service"));
    info.cgroup.io_limits.push(CgroupIoLimitConfig {
        kind: CgroupIoLimitKind::ReadIops,
        value: "/dev/null 100".to_string(),
    });

    let mut mgr = RuntimeManager::new_with_test_cgroup_root(dir.join("cgroup-root"));
    let error = mgr
        .ensure_unit_cgroup("char-device.service", &info)
        .unwrap_err();
    assert_eq!(
        error.operation(),
        super::cgroup_runtime::CgroupRealizationOperation::NormalizeControl
    );
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[test]
fn test_cgroup_events_watch_installed_for_direct_realization() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-cgroup-watch");
    let cgroup_root = dir.join("cgroup-root");
    let mut mgr = RuntimeManager::new_with_test_cgroup_root(cgroup_root.clone());
    let info = UnitFileInfo::new("watch.service", dir.join("watch.service"));
    mgr.unit_files.insert(info.name.clone(), info.clone());
    mgr.ensure_unit_cgroup("watch.service", &info).unwrap();
    assert!(mgr.cgroup_watch_by_unit.contains_key("watch.service"));
    let wd = *mgr.cgroup_watch_by_unit.get("watch.service").unwrap();
    assert!(mgr.cgroup_watch_by_wd.contains_key(&wd));

    mgr.prune_unit_cgroup("watch.service");
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[test]
fn test_cgroup_realization_rejects_shared_events_capability_atomically() {
    let _test_lock = test_env_lock();
    let dir = test_temp_dir("test-systemd-cgroup-shared-events");
    let cgroup_root = dir.join("cgroup-root");
    let mut mgr = RuntimeManager::new_with_test_cgroup_root(cgroup_root);
    let first = UnitFileInfo::new("first.service", dir.join("first.service"));
    let second = UnitFileInfo::new("second.service", dir.join("second.service"));
    mgr.unit_files.insert(first.name.clone(), first.clone());
    mgr.unit_files.insert(second.name.clone(), second.clone());
    mgr.ensure_unit_cgroup("first.service", &first).unwrap();

    let first_events = mgr
        .unit_cgroup_path_for("first.service", &first)
        .join("cgroup.events");
    let second_path = mgr.unit_cgroup_path_for("second.service", &second);
    fs::create_dir_all(&second_path).unwrap();
    fs::hard_link(&first_events, second_path.join("cgroup.events")).unwrap();

    let error = mgr
        .ensure_unit_cgroup("second.service", &second)
        .unwrap_err();
    assert_eq!(
        error.operation(),
        super::cgroup_runtime::CgroupRealizationOperation::WatchEvents
    );
    assert!(mgr.unit_cgroups.contains_key("first.service"));
    assert!(mgr.cgroup_watch_by_unit.contains_key("first.service"));
    assert!(!mgr.unit_cgroups.contains_key("second.service"));
    assert!(!mgr.unit_cgroup_paths.contains_key("second.service"));
    assert!(!mgr.unit_cgroup_populated.contains_key("second.service"));
    assert!(!mgr.cgroup_watch_by_unit.contains_key("second.service"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_service_directories_are_created_and_runtime_removed_on_stop() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-service-directories");
    fs::create_dir_all(&dir).unwrap();

    let runtime_root = dir.join("runtime");
    let state_root = dir.join("state");
    let cache_root = dir.join("cache");
    let logs_root = dir.join("logs");
    let config_root = dir.join("config");
    let dynamic_root = dir.join("dynamic-uid");

    let prev_runtime = std::env::var("SYSTEMD_RUNTIME_DIR_ROOT").ok();
    let prev_state = std::env::var("SYSTEMD_STATE_DIR_ROOT").ok();
    let prev_cache = std::env::var("SYSTEMD_CACHE_DIR_ROOT").ok();
    let prev_logs = std::env::var("SYSTEMD_LOGS_DIR_ROOT").ok();
    let prev_config = std::env::var("SYSTEMD_CONFIGURATION_DIR_ROOT").ok();
    let prev_dynamic = std::env::var("SYSTEMD_DYNAMIC_UID_ROOT").ok();

    environment.set(
        "SYSTEMD_RUNTIME_DIR_ROOT",
        runtime_root.display().to_string(),
    );
    environment.set("SYSTEMD_STATE_DIR_ROOT", state_root.display().to_string());
    environment.set("SYSTEMD_CACHE_DIR_ROOT", cache_root.display().to_string());
    environment.set("SYSTEMD_LOGS_DIR_ROOT", logs_root.display().to_string());
    environment.set(
        "SYSTEMD_CONFIGURATION_DIR_ROOT",
        config_root.display().to_string(),
    );
    environment.set(
        "SYSTEMD_DYNAMIC_UID_ROOT",
        dynamic_root.display().to_string(),
    );

    let mut info = UnitFileInfo::new("dirs.service", dir.join("dirs.service"));
    info.exec_context.runtime_directory = vec!["svc-runtime".to_string()];
    info.exec_context.state_directory = vec!["svc-state".to_string()];
    info.exec_context.cache_directory = vec!["svc-cache".to_string()];
    info.exec_context.logs_directory = vec!["svc-logs".to_string()];
    info.exec_context.configuration_directory = vec!["svc-config".to_string()];
    info.exec_context.directory_mode = Some(0o750);

    let mut mgr = new_test_runtime_manager();
    assert!(mgr.setup_service_directories("dirs.service", &info));

    let runtime_dir = runtime_root.join("svc-runtime");
    let state_dir = state_root.join("svc-state");
    let cache_dir = cache_root.join("svc-cache");
    let logs_dir = logs_root.join("svc-logs");
    let config_dir = config_root.join("svc-config");

    assert!(runtime_dir.exists());
    assert!(state_dir.exists());
    assert!(cache_dir.exists());
    assert!(logs_dir.exists());
    assert!(config_dir.exists());
    assert_eq!(
        fs::metadata(&runtime_dir).unwrap().permissions().mode() & 0o7777,
        0o750
    );

    mgr.cleanup_runtime_directories_for_unit("dirs.service", &info.exec_context);
    assert!(!runtime_dir.exists());
    assert!(state_dir.exists());
    assert!(cache_dir.exists());
    assert!(logs_dir.exists());
    assert!(config_dir.exists());

    if let Some(value) = prev_runtime {
        environment.set("SYSTEMD_RUNTIME_DIR_ROOT", value);
    } else {
        environment.remove("SYSTEMD_RUNTIME_DIR_ROOT");
    }
    if let Some(value) = prev_state {
        environment.set("SYSTEMD_STATE_DIR_ROOT", value);
    } else {
        environment.remove("SYSTEMD_STATE_DIR_ROOT");
    }
    if let Some(value) = prev_cache {
        environment.set("SYSTEMD_CACHE_DIR_ROOT", value);
    } else {
        environment.remove("SYSTEMD_CACHE_DIR_ROOT");
    }
    if let Some(value) = prev_logs {
        environment.set("SYSTEMD_LOGS_DIR_ROOT", value);
    } else {
        environment.remove("SYSTEMD_LOGS_DIR_ROOT");
    }
    if let Some(value) = prev_config {
        environment.set("SYSTEMD_CONFIGURATION_DIR_ROOT", value);
    } else {
        environment.remove("SYSTEMD_CONFIGURATION_DIR_ROOT");
    }
    if let Some(value) = prev_dynamic {
        environment.set("SYSTEMD_DYNAMIC_UID_ROOT", value);
    } else {
        environment.remove("SYSTEMD_DYNAMIC_UID_ROOT");
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_runtime_directory_preserve_keeps_runtime_path() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-runtime-directory-preserve");
    fs::create_dir_all(&dir).unwrap();

    let runtime_root = dir.join("runtime");
    let dynamic_root = dir.join("dynamic-uid");

    let prev_units = std::env::var("SYSTEMD_UNIT_PATH").ok();
    let prev_runtime = std::env::var("SYSTEMD_RUNTIME_DIR_ROOT").ok();
    let prev_dynamic = std::env::var("SYSTEMD_DYNAMIC_UID_ROOT").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());
    environment.set(
        "SYSTEMD_RUNTIME_DIR_ROOT",
        runtime_root.display().to_string(),
    );
    environment.set(
        "SYSTEMD_DYNAMIC_UID_ROOT",
        dynamic_root.display().to_string(),
    );

    let mut info = UnitFileInfo::new("preserve.service", dir.join("preserve.service"));
    info.exec_context.runtime_directory = vec!["svc-preserve".to_string()];
    info.exec_context.runtime_directory_preserve = Some("yes".to_string());
    info.exec_context.directory_mode = Some(0o700);

    let mut mgr = new_test_runtime_manager();
    assert!(mgr.setup_service_directories("preserve.service", &info));
    let runtime_dir = runtime_root.join("svc-preserve");
    assert!(runtime_dir.exists());

    mgr.cleanup_runtime_directories_for_unit("preserve.service", &info.exec_context);
    assert!(runtime_dir.exists());

    if let Some(value) = prev_units {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    if let Some(value) = prev_runtime {
        environment.set("SYSTEMD_RUNTIME_DIR_ROOT", value);
    } else {
        environment.remove("SYSTEMD_RUNTIME_DIR_ROOT");
    }
    if let Some(value) = prev_dynamic {
        environment.set("SYSTEMD_DYNAMIC_UID_ROOT", value);
    } else {
        environment.remove("SYSTEMD_DYNAMIC_UID_ROOT");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_dynamic_user_uid_assignment_is_stable_across_manager_restart() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-dynamic-user-stable");
    fs::create_dir_all(&dir).unwrap();

    let runtime_root = dir.join("runtime");
    let dynamic_root = dir.join("dynamic-uid");

    let prev_units = std::env::var("SYSTEMD_UNIT_PATH").ok();
    let prev_runtime = std::env::var("SYSTEMD_RUNTIME_DIR_ROOT").ok();
    let prev_dynamic = std::env::var("SYSTEMD_DYNAMIC_UID_ROOT").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());
    environment.set(
        "SYSTEMD_RUNTIME_DIR_ROOT",
        runtime_root.display().to_string(),
    );
    environment.set(
        "SYSTEMD_DYNAMIC_UID_ROOT",
        dynamic_root.display().to_string(),
    );

    let mut info = UnitFileInfo::new("dyn.service", dir.join("dyn.service"));
    info.exec_context.dynamic_user = Some(true);
    info.exec_context.runtime_directory = vec!["svc-dynamic".to_string()];

    let mut mgr1 = new_test_runtime_manager();
    assert!(mgr1.setup_service_directories("dyn.service", &info));
    mgr1.cleanup_runtime_directories_for_unit("dyn.service", &info.exec_context);

    let record_path = dynamic_root.join("dyn.service.uid");
    let first = fs::read_to_string(&record_path).unwrap();

    let mut mgr2 = new_test_runtime_manager();
    assert!(mgr2.setup_service_directories("dyn.service", &info));
    mgr2.cleanup_runtime_directories_for_unit("dyn.service", &info.exec_context);
    let second = fs::read_to_string(&record_path).unwrap();
    assert_eq!(first, second);

    let mut parts = first.trim().split(':');
    let uid = parts.next().unwrap().parse::<u32>().unwrap();
    let gid = parts.next().unwrap().parse::<u32>().unwrap();
    assert_eq!(uid, gid);
    assert!((DYNAMIC_UID_MIN..=DYNAMIC_UID_MAX).contains(&uid));

    if let Some(value) = prev_units {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    if let Some(value) = prev_runtime {
        environment.set("SYSTEMD_RUNTIME_DIR_ROOT", value);
    } else {
        environment.remove("SYSTEMD_RUNTIME_DIR_ROOT");
    }
    if let Some(value) = prev_dynamic {
        environment.set("SYSTEMD_DYNAMIC_UID_ROOT", value);
    } else {
        environment.remove("SYSTEMD_DYNAMIC_UID_ROOT");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_build_transaction_ignore_requirements_allows_missing_required_deps() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-ignore-requirements-mode");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("main.service"),
        "[Unit]\nRequires=missing.service\n[Service]\nType=simple\nExecStart=/bin/true\n",
    )
    .unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());

    let mut mgr = new_test_runtime_manager();
    let strict = mgr.build_transaction("main.service", TxJobType::Start, JobMode::Replace);
    assert!(strict.is_err());

    let ignored = mgr
        .build_transaction(
            "main.service",
            TxJobType::Start,
            JobMode::IgnoreRequirements,
        )
        .unwrap();
    assert_eq!(ignored.jobs.len(), 1);
    assert_eq!(ignored.jobs[0].unit, "main.service");

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_build_transaction_ignore_dependencies_does_not_pull_in_requires() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-ignore-dependencies-mode");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
            dir.join("main.service"),
            "[Unit]\nRequires=dep.service\nAfter=dep.service\n[Service]\nType=simple\nExecStart=/bin/true\n",
        )
        .unwrap();
    fs::write(
        dir.join("dep.service"),
        "[Service]\nType=simple\nExecStart=/bin/true\n",
    )
    .unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());

    let mut mgr = new_test_runtime_manager();
    let strict = mgr
        .build_transaction("main.service", TxJobType::Start, JobMode::Replace)
        .unwrap();
    assert!(strict.jobs.iter().any(|job| job.unit == "dep.service"));

    let ignored = mgr
        .build_transaction(
            "main.service",
            TxJobType::Start,
            JobMode::IgnoreDependencies,
        )
        .unwrap();
    assert_eq!(ignored.jobs.len(), 1);
    assert_eq!(ignored.jobs[0].unit, "main.service");

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_build_transaction_restart_dependencies_starts_forward_requirements() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-restart-dependencies-mode");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
            dir.join("main.service"),
            "[Unit]\nRequires=dep.service\nAfter=dep.service\n[Service]\nType=simple\nExecStart=/bin/true\n",
        )
        .unwrap();
    fs::write(
        dir.join("dep.service"),
        "[Service]\nType=simple\nExecStart=/bin/true\n",
    )
    .unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());

    let mut mgr = new_test_runtime_manager();
    let applied = mgr
        .build_transaction(
            "main.service",
            TxJobType::Start,
            JobMode::RestartDependencies,
        )
        .unwrap();

    assert!(
        applied
            .jobs
            .iter()
            .any(|job| job.unit == "main.service" && job.job_type == TxJobType::Start)
    );
    assert!(
        applied
            .jobs
            .iter()
            .any(|job| job.unit == "dep.service" && job.job_type == TxJobType::Start)
    );

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_build_transaction_loads_direct_conflict_target() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-direct-conflict-loading");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("main.service"),
        "[Unit]\nConflicts=conflict.service missing.service\n[Service]\nType=simple\nExecStart=/bin/true\n",
    )
    .unwrap();
    fs::write(
        dir.join("conflict.service"),
        "[Service]\nType=simple\nExecStart=/bin/true\n",
    )
    .unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());

    let mut mgr = new_test_runtime_manager();
    mgr.build_transaction("main.service", TxJobType::Start, JobMode::Replace)
        .unwrap();
    assert!(mgr.units.contains_key("conflict.service"));

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_build_transaction_honors_inverse_conflict_from_loaded_unit() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-inverse-conflict");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("main.service"),
        "[Service]\nType=simple\nExecStart=/bin/true\n",
    )
    .unwrap();
    fs::write(
        dir.join("conflict.service"),
        "[Unit]\nConflicts=main.service\n[Service]\nType=simple\nExecStart=/bin/true\n",
    )
    .unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());

    let mut mgr = new_test_runtime_manager();
    mgr.load_unit_recursive("conflict.service", &mut BTreeSet::new())
        .unwrap();
    mgr.units.get_mut("conflict.service").unwrap().active_state = ActiveState::Active;
    let applied = mgr
        .build_transaction("main.service", TxJobType::Start, JobMode::Replace)
        .unwrap();
    assert!(
        applied
            .jobs
            .iter()
            .any(|job| job.unit == "conflict.service" && job.job_type == TxJobType::Stop)
    );

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_build_transaction_restart_dependencies_requires_start_job() {
    let _test_lock = test_env_lock();
    // SAFETY: this environment-dependent test target runs with --test-threads=1
    // and does not spawn threads that access the process environment.
    let environment = unsafe { TestEnvironment::lock() };
    let dir = test_temp_dir("test-systemd-restart-dependencies-invalid-mode");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("main.service"),
        "[Service]\nType=simple\nExecStart=/bin/true\n",
    )
    .unwrap();

    let prev = std::env::var("SYSTEMD_UNIT_PATH").ok();
    environment.set("SYSTEMD_UNIT_PATH", dir.display().to_string());

    let mut mgr = new_test_runtime_manager();
    let err = mgr
        .build_transaction(
            "main.service",
            TxJobType::Stop,
            JobMode::RestartDependencies,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        TransactionError::InvalidMode(message)
            if message == "restart-dependencies mode requires start job"
    ));

    if let Some(value) = prev {
        environment.set("SYSTEMD_UNIT_PATH", value);
    } else {
        environment.remove("SYSTEMD_UNIT_PATH");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_child_exit_clean_mode_keeps_commands_strict_and_daemons_compatible() {
    let info = UnitFileInfo::new("clean-mode.service", PathBuf::from("clean-mode.service"));

    for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM, libc::SIGPIPE] {
        let state = ChildState::KilledBySignal(signal);
        assert!(!child_state_considered_clean_with_mode(
            state,
            &info,
            ChildExitCleanMode::Command,
        ));
        assert!(child_state_considered_clean_with_mode(
            state,
            &info,
            ChildExitCleanMode::Daemon,
        ));
    }

    assert!(!child_state_considered_clean_with_mode(
        ChildState::KilledBySignal(libc::SIGKILL),
        &info,
        ChildExitCleanMode::Daemon,
    ));
}

#[test]
fn test_child_exit_clean_mode_preserves_success_exit_status_for_both_roles() {
    let mut info = UnitFileInfo::new(
        "success-status.service",
        PathBuf::from("success-status.service"),
    );
    info.service.success_exit_status = vec!["23".to_string(), "SIGKILL".to_string()];

    for mode in [ChildExitCleanMode::Command, ChildExitCleanMode::Daemon] {
        assert!(child_state_considered_clean_with_mode(
            ChildState::ExitedWithCode(23),
            &info,
            mode,
        ));
        assert!(child_state_considered_clean_with_mode(
            ChildState::KilledBySignal(libc::SIGKILL),
            &info,
            mode,
        ));
    }
}
