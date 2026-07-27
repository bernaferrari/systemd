// SPDX-License-Identifier: LGPL-2.1-or-later

use super::*;
use crate::dbus_util::{
    bus_verify_manage_units_async_impl, POLKIT_ACTION_MANAGE_UNITS, POLKIT_ACTION_RELOAD_DAEMON,
};
use crate::job_tables::{JobState, JobType};
use crate::runtime_manager::RuntimeManager;
use crate::unit::ActiveState;
use std::collections::BTreeSet;
use systemd_shared_rs::bus_polkit::{AsyncActionStatus, AsyncPolkitQueryAction};

#[test]
fn virtualization_none_maps_to_empty_api_value() {
    assert_eq!(property_get_virtualization(Virtualization::None), None);
}

#[test]
fn virtualization_name_is_forwarded() {
    assert_eq!(
        property_get_virtualization(Virtualization::Vm("kvm")),
        Some("kvm")
    );
}

#[test]
fn confidential_virtualization_name_is_optional() {
    assert_eq!(
        property_get_confidential_virtualization(ConfidentialVirtualization::None),
        None
    );
    assert_eq!(
        property_get_confidential_virtualization(ConfidentialVirtualization::Mode("sev")),
        Some("sev")
    );
}

#[test]
fn taint_flags_are_joined_in_sorted_order() {
    let flags = BTreeSet::from(["local-hwclock".into(), "split-usr".into()]);
    assert_eq!(
        property_get_tainted(&flags).unwrap(),
        "local-hwclock:split-usr"
    );
}

#[test]
fn empty_log_target_and_level_restore_defaults() {
    let mut manager = ManagerRecord::default();
    property_set_log_target(&mut manager, "console").unwrap();
    property_set_log_level(&mut manager, "debug").unwrap();
    property_set_log_target(&mut manager, "").unwrap();
    property_set_log_level(&mut manager, "").unwrap();
    assert_eq!(manager.log_target, None);
    assert_eq!(manager.log_level, None);
}

#[test]
fn environment_is_copied_out() {
    let manager = ManagerRecord {
        environment: vec!["A=1".into(), "B=2".into()],
        ..Default::default()
    };
    assert_eq!(
        property_get_environment(&manager).unwrap(),
        vec!["A=1", "B=2"]
    );
}

#[test]
fn show_status_is_forwarded() {
    let manager = ManagerRecord {
        show_status: true,
        ..Default::default()
    };
    assert!(property_get_show_status(&manager));
}

#[test]
fn watchdog_properties_roundtrip() {
    let mut manager = ManagerRecord::default();
    property_set_watchdog(&mut manager.runtime_watchdog_usec, 10).unwrap();
    property_set_watchdog(&mut manager.pretimeout_watchdog_usec, 20).unwrap();
    property_set_watchdog(&mut manager.reboot_watchdog_usec, 30).unwrap();
    property_set_watchdog(&mut manager.kexec_watchdog_usec, 40).unwrap();
    manager.pretimeout_watchdog_governor = Some("panic".into());
    assert_eq!(property_get_runtime_watchdog(&manager), 10);
    assert_eq!(property_get_pretimeout_watchdog(&manager), 20);
    assert_eq!(property_get_reboot_watchdog(&manager), 30);
    assert_eq!(property_get_kexec_watchdog(&manager), 40);
    assert_eq!(
        property_get_pretimeout_watchdog_governor(&manager).as_deref(),
        Some("panic")
    );
}

#[test]
fn manager_subscription_roundtrip() {
    let mut manager = ManagerRecord::default();
    assert!(!manager.subscribed);
    manager_subscribe(&mut manager);
    assert!(manager.subscribed);
    manager_unsubscribe(&mut manager);
    assert!(!manager.subscribed);
}

#[test]
fn manager_unit_helpers_use_runtime_state() {
    let mut runtime = RuntimeManager::new();
    runtime.inject_test_unit("beta.target", "Beta Target", ActiveState::Inactive, "dead");
    runtime.inject_test_unit(
        "alpha.target",
        "Alpha Target",
        ActiveState::Active,
        "active",
    );
    runtime.inject_test_installed_job(7, "alpha.target", JobType::Start, JobState::Waiting);

    assert_eq!(
        manager_get_unit_path(&runtime, "alpha.target").unwrap(),
        "/org/freedesktop/systemd1/unit/alpha_2etarget"
    );

    let units = manager_list_units(&runtime);
    assert_eq!(units.len(), 2);
    assert_eq!(units[0].0, "alpha.target");
    assert_eq!(units[1].0, "beta.target");
    assert_eq!(units[0].7, 7);
    assert_eq!(units[0].8, "start");
    assert_eq!(units[0].9, "/org/freedesktop/systemd1/job/7");
}

#[test]
fn manager_job_helpers_use_runtime_state() {
    let mut runtime = RuntimeManager::new();
    runtime.inject_test_unit(
        "alpha.target",
        "Alpha Target",
        ActiveState::Active,
        "active",
    );
    runtime.inject_test_installed_job(41, "alpha.target", JobType::Restart, JobState::Running);

    assert_eq!(
        manager_get_job_path(&runtime, 41).unwrap(),
        "/org/freedesktop/systemd1/job/41"
    );

    let jobs = manager_list_jobs(&runtime);
    assert_eq!(
        jobs,
        vec![(
            41,
            "alpha.target".to_string(),
            "restart".to_string(),
            "running".to_string(),
            "/org/freedesktop/systemd1/job/41".to_string(),
            "/org/freedesktop/systemd1/unit/alpha_2etarget".to_string(),
        )]
    );
}

#[test]
fn manager_job_helpers_only_expose_installed_jobs() {
    let mut runtime = RuntimeManager::new();
    runtime.inject_test_unit(
        "alpha.target",
        "Alpha Target",
        ActiveState::Active,
        "active",
    );
    assert_eq!(manager_get_job_path(&runtime, 42), Err(Errno::ENOENT));
    assert!(manager_list_jobs(&runtime).is_empty());
    let units = manager_list_units(&runtime);
    assert_eq!(
        (units[0].7, units[0].8.as_str(), units[0].9.as_str()),
        (0, "", "/")
    );
}

#[test]
fn manager_dispatch_routes_requests_to_runtime_helpers() {
    let mut runtime = RuntimeManager::new();
    runtime.inject_test_unit(
        "alpha.target",
        "Alpha Target",
        ActiveState::Active,
        "active",
    );
    runtime.inject_test_unit("beta.target", "Beta Target", ActiveState::Inactive, "dead");
    runtime.inject_test_main_pid("alpha.target", 4242);
    runtime.inject_test_invocation_id("alpha.target", [0x11; 16]);
    runtime.inject_test_installed_job(9, "alpha.target", JobType::Start, JobState::Running);
    let mut manager = ManagerRecord::default();

    let unit_reply = manager_dispatch(
        &mut runtime,
        &mut manager,
        ManagerRequest::GetUnit {
            name: "alpha.target".to_string(),
        },
    )
    .unwrap();
    assert_eq!(
        unit_reply,
        ManagerReply::UnitPath("/org/freedesktop/systemd1/unit/alpha_2etarget".to_string())
    );

    let by_pid = manager_dispatch(
        &mut runtime,
        &mut manager,
        ManagerRequest::GetUnitByPid { pid: 4242 },
    )
    .unwrap();
    assert_eq!(
        by_pid,
        ManagerReply::UnitPath("/org/freedesktop/systemd1/unit/alpha_2etarget".to_string())
    );

    let by_invocation = manager_dispatch(
        &mut runtime,
        &mut manager,
        ManagerRequest::GetUnitByInvocationId {
            invocation_id: "11111111111111111111111111111111".to_string(),
        },
    )
    .unwrap();
    assert_eq!(
        by_invocation,
        ManagerReply::UnitPath("/org/freedesktop/systemd1/unit/alpha_2etarget".to_string())
    );

    let by_cgroup = manager_dispatch(
        &mut runtime,
        &mut manager,
        ManagerRequest::GetUnitByControlGroup {
            cgroup: "/sys/fs/cgroup/system.slice/alpha.target".to_string(),
        },
    )
    .unwrap();
    assert_eq!(
        by_cgroup,
        ManagerReply::UnitPath("/org/freedesktop/systemd1/unit/alpha_2etarget".to_string())
    );

    let jobs_reply =
        manager_dispatch(&mut runtime, &mut manager, ManagerRequest::ListJobs).unwrap();
    match jobs_reply {
        ManagerReply::Jobs(rows) => {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].0, 9);
            assert_eq!(rows[0].2, "start");
        }
        other => panic!("unexpected manager reply: {other:?}"),
    }

    let filtered = manager_dispatch(
        &mut runtime,
        &mut manager,
        ManagerRequest::ListUnitsByNames {
            names: vec!["beta.target".to_string(), "missing.target".to_string()],
        },
    )
    .unwrap();
    match filtered {
        ManagerReply::Units(rows) => {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].0, "beta.target");
        }
        other => panic!("unexpected manager reply: {other:?}"),
    }

    let filtered_by_state_and_pattern = manager_dispatch(
        &mut runtime,
        &mut manager,
        ManagerRequest::ListUnitsFiltered {
            states: vec!["active".to_string()],
            patterns: vec!["alpha*".to_string()],
        },
    )
    .unwrap();
    match filtered_by_state_and_pattern {
        ManagerReply::Units(rows) => {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].0, "alpha.target");
        }
        other => panic!("unexpected manager reply: {other:?}"),
    }

    let by_patterns = manager_dispatch(
        &mut runtime,
        &mut manager,
        ManagerRequest::ListUnitsByPatterns {
            patterns: vec!["beta*".to_string()],
        },
    )
    .unwrap();
    match by_patterns {
        ManagerReply::Units(rows) => {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].0, "beta.target");
        }
        other => panic!("unexpected manager reply: {other:?}"),
    }

    manager_dispatch(&mut runtime, &mut manager, ManagerRequest::Subscribe).unwrap();
    assert!(manager.subscribed);
    manager_dispatch(&mut runtime, &mut manager, ManagerRequest::Unsubscribe).unwrap();
    assert!(!manager.subscribed);
}

#[test]
fn method_payload_mapping_accepts_expected_shapes() {
    let get_unit = ManagerMethodCall {
        member: "GetUnit".to_string(),
        payload: ManagerMethodPayload::UnitName("alpha.target".to_string()),
    };
    assert_eq!(
        map_method_call_to_request(&get_unit).unwrap(),
        ManagerRequest::GetUnit {
            name: "alpha.target".to_string()
        }
    );

    let get_unit_by_pid = ManagerMethodCall {
        member: "GetUnitByPID".to_string(),
        payload: ManagerMethodPayload::Pid(42),
    };
    assert_eq!(
        map_method_call_to_request(&get_unit_by_pid).unwrap(),
        ManagerRequest::GetUnitByPid { pid: 42 }
    );

    let get_unit_by_invocation = ManagerMethodCall {
        member: "GetUnitByInvocationID".to_string(),
        payload: ManagerMethodPayload::InvocationId("11111111111111111111111111111111".to_string()),
    };
    assert_eq!(
        map_method_call_to_request(&get_unit_by_invocation).unwrap(),
        ManagerRequest::GetUnitByInvocationId {
            invocation_id: "11111111111111111111111111111111".to_string()
        }
    );

    let get_unit_by_cgroup = ManagerMethodCall {
        member: "GetUnitByControlGroup".to_string(),
        payload: ManagerMethodPayload::ControlGroup(
            "/sys/fs/cgroup/system.slice/alpha.target".to_string(),
        ),
    };
    assert_eq!(
        map_method_call_to_request(&get_unit_by_cgroup).unwrap(),
        ManagerRequest::GetUnitByControlGroup {
            cgroup: "/sys/fs/cgroup/system.slice/alpha.target".to_string()
        }
    );

    let get_unit_by_pidfd = ManagerMethodCall {
        member: "GetUnitByPIDFD".to_string(),
        payload: ManagerMethodPayload::PidFd(99),
    };
    assert_eq!(
        map_method_call_to_request(&get_unit_by_pidfd).unwrap(),
        ManagerRequest::GetUnitByPidFd { pidfd: 99 }
    );

    let list_jobs = ManagerMethodCall {
        member: "ListJobs".to_string(),
        payload: ManagerMethodPayload::None,
    };
    assert_eq!(
        map_method_call_to_request(&list_jobs).unwrap(),
        ManagerRequest::ListJobs
    );

    let list_units_by_names = ManagerMethodCall {
        member: "ListUnitsByNames".to_string(),
        payload: ManagerMethodPayload::UnitNames(vec![
            "alpha.target".to_string(),
            "beta.target".to_string(),
        ]),
    };
    assert_eq!(
        map_method_call_to_request(&list_units_by_names).unwrap(),
        ManagerRequest::ListUnitsByNames {
            names: vec!["alpha.target".to_string(), "beta.target".to_string()]
        }
    );

    let list_units_filtered = ManagerMethodCall {
        member: "ListUnitsFiltered".to_string(),
        payload: ManagerMethodPayload::UnitFilters {
            states: vec!["active".to_string()],
            patterns: vec!["alpha*".to_string()],
        },
    };
    assert_eq!(
        map_method_call_to_request(&list_units_filtered).unwrap(),
        ManagerRequest::ListUnitsFiltered {
            states: vec!["active".to_string()],
            patterns: vec!["alpha*".to_string()],
        }
    );

    let list_units_by_patterns = ManagerMethodCall {
        member: "ListUnitsByPatterns".to_string(),
        payload: ManagerMethodPayload::Patterns(vec!["*.target".to_string()]),
    };
    assert_eq!(
        map_method_call_to_request(&list_units_by_patterns).unwrap(),
        ManagerRequest::ListUnitsByPatterns {
            patterns: vec!["*.target".to_string()]
        }
    );

    let reload = ManagerMethodCall {
        member: "Reload".to_string(),
        payload: ManagerMethodPayload::None,
    };
    assert_eq!(
        map_method_call_to_request(&reload).unwrap(),
        ManagerRequest::Reload
    );

    let soft_reboot = ManagerMethodCall {
        member: "SoftReboot".to_string(),
        payload: ManagerMethodPayload::StringValue("/newroot".to_string()),
    };
    assert_eq!(
        map_method_call_to_request(&soft_reboot).unwrap(),
        ManagerRequest::SoftReboot {
            root: Some("/newroot".to_string())
        }
    );

    let switch_root = ManagerMethodCall {
        member: "SwitchRoot".to_string(),
        payload: ManagerMethodPayload::StringPair {
            left: "/sysroot".to_string(),
            right: "/usr/lib/systemd/systemd".to_string(),
        },
    };
    assert_eq!(
        map_method_call_to_request(&switch_root).unwrap(),
        ManagerRequest::SwitchRoot {
            root: "/sysroot".to_string(),
            init: "/usr/lib/systemd/systemd".to_string(),
        }
    );

    let set_env = ManagerMethodCall {
        member: "SetEnvironment".to_string(),
        payload: ManagerMethodPayload::StringList(vec!["A=1".to_string()]),
    };
    assert_eq!(
        map_method_call_to_request(&set_env).unwrap(),
        ManagerRequest::SetEnvironment {
            plus: vec!["A=1".to_string()]
        }
    );

    let unset_and_set = ManagerMethodCall {
        member: "UnsetAndSetEnvironment".to_string(),
        payload: ManagerMethodPayload::StringLists {
            first: vec!["A".to_string()],
            second: vec!["B=2".to_string()],
        },
    };
    assert_eq!(
        map_method_call_to_request(&unset_and_set).unwrap(),
        ManagerRequest::UnsetAndSetEnvironment {
            minus: vec!["A".to_string()],
            plus: vec!["B=2".to_string()],
        }
    );

    let set_exit_code = ManagerMethodCall {
        member: "SetExitCode".to_string(),
        payload: ManagerMethodPayload::U8(7),
    };
    assert_eq!(
        map_method_call_to_request(&set_exit_code).unwrap(),
        ManagerRequest::SetExitCode { code: 7 }
    );
}

#[test]
fn method_payload_mapping_rejects_invalid_shapes() {
    let invalid_payload = ManagerMethodCall {
        member: "GetJob".to_string(),
        payload: ManagerMethodPayload::UnitName("alpha.target".to_string()),
    };
    assert_eq!(
        map_method_call_to_request(&invalid_payload).unwrap_err(),
        Errno::EINVAL
    );

    let unknown = ManagerMethodCall {
        member: "Nope".to_string(),
        payload: ManagerMethodPayload::None,
    };
    assert_eq!(
        map_method_call_to_request(&unknown).unwrap_err(),
        Errno::EOPNOTSUPP
    );
}

#[test]
fn pidfd_lookup_fails_closed_without_kernel_resolution() {
    let mut runtime = RuntimeManager::new();
    runtime.inject_test_unit(
        "alpha.target",
        "Alpha Target",
        ActiveState::Active,
        "active",
    );
    let mut manager = ManagerRecord::default();

    assert_eq!(
        manager_dispatch(
            &mut runtime,
            &mut manager,
            ManagerRequest::GetUnitByPidFd { pidfd: 1 },
        )
        .unwrap_err(),
        Errno::EOPNOTSUPP
    );
}

#[test]
fn handle_method_call_dispatches_and_encodes_result() {
    let mut runtime = RuntimeManager::new();
    runtime.inject_test_unit(
        "alpha.target",
        "Alpha Target",
        ActiveState::Active,
        "active",
    );
    let mut manager = ManagerRecord::default();

    let call = ManagerMethodCall {
        member: "GetUnit".to_string(),
        payload: ManagerMethodPayload::UnitName("alpha.target".to_string()),
    };
    let result = handle_manager_method_call(&mut runtime, &mut manager, &call).unwrap();
    assert_eq!(
        result,
        ManagerMethodResultPayload::UnitPath(
            "/org/freedesktop/systemd1/unit/alpha_2etarget".to_string()
        )
    );

    let subscribe = ManagerMethodCall {
        member: "Subscribe".to_string(),
        payload: ManagerMethodPayload::None,
    };
    let subscribe_result = handle_manager_method_call(&mut runtime, &mut manager, &subscribe)
        .expect("subscribe should succeed");
    assert_eq!(subscribe_result, ManagerMethodResultPayload::Empty);
    assert!(manager.subscribed);
}

#[test]
fn operation_method_calls_queue_jobs_and_return_job_paths() {
    let mut runtime = RuntimeManager::new();
    runtime.inject_test_unit(
        "alpha.target",
        "Alpha Target",
        ActiveState::Inactive,
        "dead",
    );
    let mut manager = ManagerRecord::default();

    let try_restart = ManagerMethodCall {
        member: "TryRestartUnit".to_string(),
        payload: ManagerMethodPayload::UnitAndMode {
            name: "alpha.target".to_string(),
            mode: "replace".to_string(),
        },
    };
    let try_restart_result =
        handle_manager_method_call(&mut runtime, &mut manager, &try_restart).unwrap();
    assert_eq!(
        try_restart_result,
        ManagerMethodResultPayload::JobPath("/".to_string())
    );

    let start = ManagerMethodCall {
        member: "StartUnit".to_string(),
        payload: ManagerMethodPayload::UnitAndMode {
            name: "alpha.target".to_string(),
            mode: "replace".to_string(),
        },
    };
    let start_result = handle_manager_method_call(&mut runtime, &mut manager, &start).unwrap();
    assert_eq!(
        start_result,
        ManagerMethodResultPayload::JobPath("/org/freedesktop/systemd1/job/1".to_string())
    );

    let reload_or_try_restart = ManagerMethodCall {
        member: "ReloadOrTryRestartUnit".to_string(),
        payload: ManagerMethodPayload::UnitAndMode {
            name: "alpha.target".to_string(),
            mode: "replace".to_string(),
        },
    };
    let reload_or_try_restart_result =
        handle_manager_method_call(&mut runtime, &mut manager, &reload_or_try_restart).unwrap();
    assert_eq!(
        reload_or_try_restart_result,
        ManagerMethodResultPayload::JobPath("/org/freedesktop/systemd1/job/2".to_string())
    );

    let bad_mode = ManagerMethodCall {
        member: "StartUnit".to_string(),
        payload: ManagerMethodPayload::UnitAndMode {
            name: "alpha.target".to_string(),
            mode: "bogus".to_string(),
        },
    };
    assert_eq!(
        handle_manager_method_call(&mut runtime, &mut manager, &bad_mode).unwrap_err(),
        Errno::EINVAL
    );

    let restart_dependencies = ManagerMethodCall {
        member: "StartUnit".to_string(),
        payload: ManagerMethodPayload::UnitAndMode {
            name: "alpha.target".to_string(),
            mode: "restart-dependencies".to_string(),
        },
    };
    let restart_dependencies_result =
        handle_manager_method_call(&mut runtime, &mut manager, &restart_dependencies).unwrap();
    assert_eq!(
        restart_dependencies_result,
        ManagerMethodResultPayload::JobPath("/org/freedesktop/systemd1/job/3".to_string())
    );
}

#[test]
fn manager_control_requests_update_environment() {
    let mut runtime = RuntimeManager::new();
    let mut manager = ManagerRecord::default();

    let set_environment = ManagerMethodCall {
        member: "SetEnvironment".to_string(),
        payload: ManagerMethodPayload::StringList(vec!["A=1".to_string(), "B=2".to_string()]),
    };
    assert_eq!(
        handle_manager_method_call(&mut runtime, &mut manager, &set_environment).unwrap(),
        ManagerMethodResultPayload::Empty
    );
    assert_eq!(
        manager.environment,
        vec!["A=1".to_string(), "B=2".to_string()]
    );

    let unset_and_set_environment = ManagerMethodCall {
        member: "UnsetAndSetEnvironment".to_string(),
        payload: ManagerMethodPayload::StringLists {
            first: vec!["A".to_string()],
            second: vec!["B=3".to_string()],
        },
    };
    assert_eq!(
        handle_manager_method_call(&mut runtime, &mut manager, &unset_and_set_environment).unwrap(),
        ManagerMethodResultPayload::Empty
    );
    assert_eq!(manager.environment, vec!["B=3".to_string()]);
}

#[test]
fn detached_manager_model_rejects_outer_lifecycle_requests() {
    let mut runtime = RuntimeManager::new();
    let mut manager = ManagerRecord::default();

    for call in [
        ManagerMethodCall {
            member: "Reload".to_string(),
            payload: ManagerMethodPayload::None,
        },
        ManagerMethodCall {
            member: "Reexecute".to_string(),
            payload: ManagerMethodPayload::None,
        },
        ManagerMethodCall {
            member: "Exit".to_string(),
            payload: ManagerMethodPayload::None,
        },
        ManagerMethodCall {
            member: "Reboot".to_string(),
            payload: ManagerMethodPayload::None,
        },
        ManagerMethodCall {
            member: "SoftReboot".to_string(),
            payload: ManagerMethodPayload::StringValue("/run/nextroot".to_string()),
        },
        ManagerMethodCall {
            member: "PowerOff".to_string(),
            payload: ManagerMethodPayload::None,
        },
        ManagerMethodCall {
            member: "Halt".to_string(),
            payload: ManagerMethodPayload::None,
        },
        ManagerMethodCall {
            member: "KExec".to_string(),
            payload: ManagerMethodPayload::None,
        },
        ManagerMethodCall {
            member: "SwitchRoot".to_string(),
            payload: ManagerMethodPayload::StringPair {
                left: "/newroot".to_string(),
                right: "/usr/lib/systemd/systemd".to_string(),
            },
        },
        ManagerMethodCall {
            member: "SetExitCode".to_string(),
            payload: ManagerMethodPayload::U8(42),
        },
    ] {
        assert_eq!(
            handle_manager_method_call(&mut runtime, &mut manager, &call),
            Err(Errno::EOPNOTSUPP)
        );
    }
}

#[test]
fn manager_control_requests_reject_invalid_payload_values() {
    let mut runtime = RuntimeManager::new();
    let mut manager = ManagerRecord::default();

    let invalid_set_environment = ManagerMethodCall {
        member: "SetEnvironment".to_string(),
        payload: ManagerMethodPayload::StringList(vec!["INVALID".to_string()]),
    };
    assert_eq!(
        handle_manager_method_call(&mut runtime, &mut manager, &invalid_set_environment)
            .unwrap_err(),
        Errno::EINVAL
    );

    let invalid_switch_root = ManagerMethodCall {
        member: "SwitchRoot".to_string(),
        payload: ManagerMethodPayload::StringPair {
            left: "relative".to_string(),
            right: "".to_string(),
        },
    };
    assert_eq!(
        handle_manager_method_call(&mut runtime, &mut manager, &invalid_switch_root).unwrap_err(),
        Errno::EINVAL
    );
}

#[test]
fn authorized_handler_denies_manage_units_without_grant() {
    let mut context = ManagerMethodContext {
        sender_uid: 1000,
        sender_privileged: false,
        ..ManagerMethodContext::default()
    };
    context.runtime.inject_test_unit(
        "alpha.target",
        "Alpha Target",
        ActiveState::Inactive,
        "dead",
    );
    let call = ManagerMethodCall {
        member: "StartUnit".to_string(),
        payload: ManagerMethodPayload::UnitAndMode {
            name: "alpha.target".to_string(),
            mode: "replace".to_string(),
        },
    };

    assert_eq!(
        handle_authorized_manager_method_call(&mut context, &call).unwrap_err(),
        Errno::EACCES
    );
}

#[test]
fn test_context_default_does_not_grant_sender_privilege() {
    let context = ManagerMethodContext::default();
    assert_eq!(context.sender_uid, u32::MAX);
    assert!(!context.sender_privileged);
}

#[test]
fn authorized_handler_uses_cached_manage_units_grant() {
    let details = bus_verify_manage_units_async_impl(
        Some("alpha.target"),
        Some("start"),
        Some("start alpha.target"),
    );
    let mut context = ManagerMethodContext {
        sender_uid: 1000,
        sender_privileged: false,
        polkit_actions: vec![AsyncPolkitQueryAction {
            action: POLKIT_ACTION_MANAGE_UNITS.to_string(),
            details,
            status: AsyncActionStatus::Authorized,
        }],
        ..ManagerMethodContext::default()
    };
    context.runtime.inject_test_unit(
        "alpha.target",
        "Alpha Target",
        ActiveState::Inactive,
        "dead",
    );
    let call = ManagerMethodCall {
        member: "StartUnit".to_string(),
        payload: ManagerMethodPayload::UnitAndMode {
            name: "alpha.target".to_string(),
            mode: "replace".to_string(),
        },
    };

    assert_eq!(
        handle_authorized_manager_method_call(&mut context, &call).unwrap(),
        ManagerMethodResultPayload::JobPath("/org/freedesktop/systemd1/job/1".to_string())
    );
}

#[test]
fn authorized_handler_enforces_daemon_and_privileged_actions() {
    let mut reload_context = ManagerMethodContext {
        sender_uid: 1000,
        sender_privileged: false,
        polkit_actions: vec![AsyncPolkitQueryAction {
            action: POLKIT_ACTION_RELOAD_DAEMON.to_string(),
            details: vec![],
            status: AsyncActionStatus::Authorized,
        }],
        ..ManagerMethodContext::default()
    };
    let reload = ManagerMethodCall {
        member: "Reload".to_string(),
        payload: ManagerMethodPayload::None,
    };
    assert_eq!(
        handle_authorized_manager_method_call(&mut reload_context, &reload),
        Err(Errno::EOPNOTSUPP)
    );

    let mut reboot_context = ManagerMethodContext {
        sender_uid: 1000,
        sender_privileged: false,
        ..ManagerMethodContext::default()
    };
    let reboot = ManagerMethodCall {
        member: "Reboot".to_string(),
        payload: ManagerMethodPayload::None,
    };
    assert_eq!(
        handle_authorized_manager_method_call(&mut reboot_context, &reboot).unwrap_err(),
        Errno::EACCES
    );
}
