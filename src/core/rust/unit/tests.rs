#![expect(
    clippy::module_inception,
    reason = "the C-aligned `unit` facade deliberately keeps its tests in unit/tests.rs"
)]

mod tests {
    use crate::unit::{
        ActiveState, CollectMode, DependencyKind, FUNCTION_INVENTORY, FreezerState, ManagerRecord,
        OomPolicy, QueueKind, RateLimit, SOURCE_PATH, Unit, UnitError, UnitMountDependencyType,
        UnitType, activation_details_append_env, activation_details_append_pair,
        activation_details_deserialize, activation_details_new, activation_details_serialize,
        collect_mode_from_string, collect_mode_to_string, oom_policy_from_string,
        oom_policy_to_string, port_status, setenv_unit_path, unit_acquire_invocation_id,
        unit_active_state, unit_add_alias, unit_add_mounts_for, unit_add_to_load_queue,
        unit_add_to_stop_notify_queue, unit_add_two_dependencies_by_name, unit_can_freeze,
        unit_compare_priority, unit_export_state_files, unit_freezer_action, unit_freezer_complete,
        unit_has_dependency, unit_has_name, unit_invocation_log_field, unit_log_field,
        unit_mount_dependency_type_from_string, unit_mount_dependency_type_to_string,
        unit_new_for_name, unit_remove_from_stop_notify_queue, unit_start, unit_stop,
        unit_test_start_limit, unit_unlink_state_files,
    };
    use systemd_shared_rs::tests::TestEnvironment;

    fn sample_manager() -> ManagerRecord {
        ManagerRecord::default()
    }

    fn sample_unit() -> Unit {
        unit_new_for_name(sample_manager(), UnitType::Service, "demo.service").unwrap()
    }

    #[test]
    fn creates_unit_with_primary_name() {
        let unit = sample_unit();
        assert_eq!(unit.id.as_deref(), Some("demo.service"));
    }

    #[test]
    fn aliases_are_tracked() {
        let mut unit = sample_unit();
        unit_add_alias(&mut unit, "alias.service").unwrap();
        assert!(unit_has_name(&unit, "alias.service"));
    }

    #[test]
    fn queue_membership_is_managed() {
        let mut unit = sample_unit();
        unit_add_to_load_queue(&mut unit);
        unit_add_to_stop_notify_queue(&mut unit);
        unit_remove_from_stop_notify_queue(&mut unit);
        assert!(unit.queues.contains(&QueueKind::Load));
        assert!(!unit.queues.contains(&QueueKind::StopNotify));
    }

    #[test]
    fn dependency_addition_is_queryable() {
        let mut unit = sample_unit();
        unit_add_two_dependencies_by_name(
            &mut unit,
            DependencyKind::Requires,
            DependencyKind::After,
            "network.target",
            true,
            0,
        )
        .unwrap();
        assert!(unit_has_dependency(
            &unit,
            DependencyKind::Requires,
            "network.target"
        ));
        assert!(unit_has_dependency(
            &unit,
            DependencyKind::After,
            "network.target"
        ));
    }

    #[test]
    fn start_limit_is_enforced() {
        let mut unit = sample_unit();
        unit.start_ratelimit = RateLimit::new(10, 1);
        assert!(unit_test_start_limit(&mut unit, 1).is_ok());
        assert_eq!(
            unit_test_start_limit(&mut unit, 2),
            Err(UnitError::StartLimitHit)
        );
        assert_eq!(unit.start_ratelimit.retry_at_usec(), Some(12));
    }

    #[test]
    fn rate_limit_resets_the_whole_fixed_window() {
        let mut limit = RateLimit::new(10, 2);
        assert!(limit.check(1).is_ok());
        assert!(limit.check(9).is_ok());
        assert_eq!(limit.check(10), Err(UnitError::StartLimitHit));
        assert!(limit.check(12).is_ok());
        assert!(limit.check(12).is_ok());
        assert_eq!(limit.check(12), Err(UnitError::StartLimitHit));
    }

    #[test]
    fn start_and_stop_change_state() {
        let mut unit = sample_unit();
        unit_start(&mut unit, 1).unwrap();
        assert_eq!(unit_active_state(&unit), ActiveState::Active);
        unit_stop(&mut unit).unwrap();
        assert_eq!(unit_active_state(&unit), ActiveState::Inactive);
    }

    #[test]
    fn invocation_id_is_deterministic_for_same_input() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let _environment = unsafe { TestEnvironment::lock() };
        let mut a = sample_unit();
        let mut b = sample_unit();
        // SAFETY: TestEnvironment serializes process-environment mutation for
        // the full duration of this test.
        unsafe { setenv_unit_path("/etc/systemd/system") }.unwrap();
        assert_eq!(
            unit_acquire_invocation_id(&mut a).unwrap(),
            unit_acquire_invocation_id(&mut b).unwrap()
        );
    }

    #[test]
    fn mount_paths_must_be_canonical() {
        let mut unit = sample_unit();
        assert!(
            unit_add_mounts_for(&mut unit, "/var/lib", 0, UnitMountDependencyType::Requires)
                .is_ok()
        );
        assert_eq!(
            unit_add_mounts_for(
                &mut unit,
                "var/../tmp",
                0,
                UnitMountDependencyType::Requires
            ),
            Err(UnitError::Invalid)
        );
    }

    #[test]
    fn freezer_transitions_are_modeled() {
        let mut unit = sample_unit();
        unit.active_state = ActiveState::Active;
        unit_freezer_action(&mut unit, true);
        assert_eq!(unit.freezer_state, FreezerState::Freezing);
        unit_freezer_complete(&mut unit, true);
        assert_eq!(unit.freezer_state, FreezerState::Frozen);
    }

    #[test]
    fn freezer_requires_exact_active_state() {
        let mut unit = sample_unit();
        unit.active_state = ActiveState::Refreshing;
        assert!(!unit_can_freeze(&unit));
        unit.active_state = ActiveState::Active;
        assert!(unit_can_freeze(&unit));
        unit.active_state = ActiveState::Frozen;
        assert!(unit_can_freeze(&unit));
    }

    #[test]
    fn activation_details_roundtrip() {
        let mut details = activation_details_new();
        activation_details_append_env(&mut details, "A", "1");
        activation_details_append_pair(&mut details, "B", "2");
        let text = activation_details_serialize(&details);
        let parsed = activation_details_deserialize(&text);
        assert_eq!(parsed, details);
    }

    #[test]
    fn string_tables_roundtrip() {
        assert_eq!(
            collect_mode_from_string(collect_mode_to_string(CollectMode::Inactive)).unwrap(),
            CollectMode::Inactive
        );
        assert_eq!(
            unit_mount_dependency_type_from_string(unit_mount_dependency_type_to_string(
                UnitMountDependencyType::Requires
            ))
            .unwrap(),
            UnitMountDependencyType::Requires
        );
        assert_eq!(
            oom_policy_from_string(oom_policy_to_string(OomPolicy::Kill)).unwrap(),
            OomPolicy::Kill
        );
    }

    #[test]
    fn log_fields_include_unit_identity() {
        let mut unit = sample_unit();
        unit_acquire_invocation_id(&mut unit).unwrap();
        assert!(unit_log_field(&unit).contains("demo.service"));
        assert!(
            unit_invocation_log_field(&unit)
                .unwrap()
                .contains("INVOCATION_ID")
        );
    }

    #[test]
    fn priority_orders_cpu_weight_before_nice_and_identity() {
        let mut a = sample_unit();
        let mut b =
            unit_new_for_name(sample_manager(), UnitType::Service, "other.service").unwrap();
        a.cpu_weight = 200;
        b.cpu_weight = 100;
        assert_eq!(unit_compare_priority(&a, &b), std::cmp::Ordering::Less);
        b.cpu_weight = a.cpu_weight;
        a.exec_context.as_mut().unwrap().nice = 5;
        b.exec_context.as_mut().unwrap().nice = 10;
        assert_eq!(unit_compare_priority(&a, &b), std::cmp::Ordering::Less);
    }

    #[test]
    fn exported_state_files_roundtrip() {
        let mut unit = sample_unit();
        unit_export_state_files(&mut unit);
        assert_eq!(unit.state_files.len(), 1);
        unit_unlink_state_files(&mut unit);
        assert!(unit.state_files.is_empty());
    }

    #[test]
    fn inventory_and_port_status_are_complete() {
        let status = port_status();
        assert_eq!(status.source_path, SOURCE_PATH);
        assert!(status.ported_functions >= 248);
        assert!(FUNCTION_INVENTORY.contains(&"unit_new"));
        assert!(FUNCTION_INVENTORY.contains(&"activation_details_free"));
    }
}
