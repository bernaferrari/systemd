// SPDX-License-Identifier: LGPL-2.1-or-later

use super::dispatch::{mount_id_from_mountinfo, should_relinquish_var_from_dev_ids};
use super::filter::{
    BOOT_ID_NULL_MATCH, TASK_COMM_LEN, current_boot_id_match_term, replay_filter_plan,
    truncate_task_comm,
};
use super::model::{
    ARG_LINES_ALL, SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE, SD_JSON_FORMAT_COLOR_AUTO,
    SD_JSON_FORMAT_OFF,
};
use super::{
    DispatchPlan, DispatchTarget, FilterApplyError, FilterBackendOp, FilterMatchTerm, FilterPlan,
    IdDescriptor, JournalctlAction, JournalctlArgs, ParseArgvError, ParseArgvResult,
    ParseIdDescriptorError, ParsedLines, PatternCase, RunOutcome, ScopePlan, SecretString,
    TransportFilter, UnitMatchPlan, build_filter_plan, parse_argv, parse_id_descriptor,
    parse_lines, plan_dispatch, run,
};
use std::collections::BTreeSet;
use std::path::Path;
use systemd_shared_rs::output_mode::{OutputMode, output_mode_to_json_format_flags};
use systemd_shared_rs::pcre2_util::{PatternCompileCase, Pcre2Error, pattern_compile};

fn expect_parsed(result: Result<ParseArgvResult, ParseArgvError>) -> JournalctlArgs {
    match result.unwrap() {
        ParseArgvResult::Parsed(v) => v,
        other => panic!("expected ParseArgvResult::Parsed, got {other:?}"),
    }
}

#[test]
fn parse_id_descriptor_all_keyword() {
    assert_eq!(
        parse_id_descriptor("all").unwrap(),
        IdDescriptor {
            id: None,
            offset: 0
        }
    );
}

#[test]
fn parse_id_descriptor_offset_only() {
    assert_eq!(
        parse_id_descriptor("-3").unwrap(),
        IdDescriptor {
            id: None,
            offset: -3
        }
    );
    assert_eq!(
        parse_id_descriptor("17").unwrap(),
        IdDescriptor {
            id: None,
            offset: 17
        }
    );
}

#[test]
fn parse_id_descriptor_id_with_optional_offset() {
    let base = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert_eq!(
        parse_id_descriptor(base).unwrap(),
        IdDescriptor {
            id: Some([0xaa; 16]),
            offset: 0
        }
    );
    assert_eq!(
        parse_id_descriptor("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+2").unwrap(),
        IdDescriptor {
            id: Some([0xaa; 16]),
            offset: 2
        }
    );
    assert_eq!(
        parse_id_descriptor("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-4").unwrap(),
        IdDescriptor {
            id: Some([0xaa; 16]),
            offset: -4
        }
    );
}

#[test]
fn parse_id_descriptor_rejects_invalid_suffix_and_bad_values() {
    assert_eq!(
        parse_id_descriptor("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax"),
        Err(ParseIdDescriptorError::Invalid)
    );
    assert_eq!(
        parse_id_descriptor("not-an-id-and-not-an-offset"),
        Err(ParseIdDescriptorError::Invalid)
    );
}

#[test]
fn parse_id_descriptor_rejects_non_ascii_without_panicking() {
    assert_eq!(
        parse_id_descriptor("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaá"),
        Err(ParseIdDescriptorError::Invalid)
    );
}

#[test]
fn parse_lines_matches_c_behavior() {
    assert_eq!(
        parse_lines(Some("all"), false).unwrap(),
        ParsedLines {
            value: ARG_LINES_ALL,
            oldest_first: false,
            explicit: true,
        }
    );
    assert_eq!(
        parse_lines(Some("+5"), false).unwrap(),
        ParsedLines {
            value: 5,
            oldest_first: true,
            explicit: true,
        }
    );
    assert_eq!(
        parse_lines(Some("7"), false).unwrap(),
        ParsedLines {
            value: 7,
            oldest_first: false,
            explicit: true,
        }
    );
}

#[test]
fn truncate_task_comm_enforces_byte_ceiling() {
    let truncated = truncate_task_comm("ééééééééé");
    assert!(truncated.len() < TASK_COMM_LEN);
}

#[test]
fn parse_lines_graceful_and_strict_errors() {
    assert_eq!(
        parse_lines(None, true).unwrap(),
        ParsedLines {
            value: 10,
            oldest_first: false,
            explicit: false,
        }
    );
    assert_eq!(
        parse_lines(Some("invalid"), true).unwrap(),
        ParsedLines {
            value: 10,
            oldest_first: false,
            explicit: false,
        }
    );
    assert_eq!(
        parse_lines(Some("invalid"), false),
        Err(ParseIdDescriptorError::Invalid)
    );
    assert_eq!(
        parse_lines(Some("-1"), false),
        Err(ParseIdDescriptorError::Invalid)
    );
}

#[test]
fn parse_argv_output_mode_semantics_match_c() {
    let parsed = expect_parsed(parse_argv(&["journalctl", "-o", "json"]));
    assert_eq!(parsed.output, OutputMode::Json);
    assert!(parsed.quiet);
    assert_eq!(
        parsed.json_format_flags,
        output_mode_to_json_format_flags(OutputMode::Json) | SD_JSON_FORMAT_COLOR_AUTO
    );

    let parsed = expect_parsed(parse_argv(&["journalctl", "--output=short"]));
    assert_eq!(parsed.output, OutputMode::Short);
    assert!(!parsed.quiet);
    assert_eq!(parsed.json_format_flags, SD_JSON_FORMAT_OFF);
}

#[test]
fn parse_argv_output_help_short_circuit() {
    assert_eq!(
        parse_argv(&["journalctl", "--output=help"]).unwrap(),
        ParseArgvResult::OutputModeHelpRequested
    );
}

#[test]
fn parse_argv_facility_help_short_circuit() {
    assert_eq!(
        parse_argv(&["journalctl", "--facility=help"]).unwrap(),
        ParseArgvResult::FacilitiesHelpRequested
    );
}

#[test]
fn parse_argv_lines_optional_argument_behavior() {
    let parsed = expect_parsed(parse_argv(&["journalctl", "-n"]));
    assert_eq!(parsed.lines, 10);
    assert!(!parsed.lines_oldest);

    let parsed = expect_parsed(parse_argv(&["journalctl", "-n", "+7"]));
    assert_eq!(parsed.lines, 7);
    assert!(parsed.lines_oldest);

    let parsed = expect_parsed(parse_argv(&["journalctl", "-n", "not-a-number", "x=y"]));
    assert_eq!(parsed.lines, 10);
    assert_eq!(
        parsed.positional_matches,
        vec!["not-a-number".to_string(), "x=y".to_string()]
    );
}

#[test]
fn parse_argv_boot_optional_argument_behavior() {
    let parsed = expect_parsed(parse_argv(&["journalctl", "-b", "all"]));
    assert_eq!(parsed.boot, 0);
    assert!(!parsed.boot_filter);

    let parsed = expect_parsed(parse_argv(&["journalctl", "-b", "not-an-id", "x=y"]));
    assert_eq!(parsed.boot, 1);
    assert!(parsed.boot_filter);
    assert_eq!(
        parsed.positional_matches,
        vec!["not-an-id".to_string(), "x=y".to_string()]
    );
}

#[test]
fn parse_argv_conflict_checks() {
    assert_eq!(
        parse_argv(&["journalctl", "--follow", "--reverse"]),
        Err(ParseArgvError::Invalid(
            "please specify either --reverse or --follow, not both"
        ))
    );
    assert_eq!(
        parse_argv(&["journalctl", "--since=today", "--cursor=abc"]),
        Err(ParseArgvError::Invalid(
            "please specify only one of --since=, --cursor=, --cursor-file=, and --after-cursor="
        ))
    );
    assert_eq!(
        parse_argv(&["journalctl", "-n", "+5", "--follow"]),
        Err(ParseArgvError::Invalid(
            "--lines=+N is unsupported when --reverse or --follow is specified"
        ))
    );
    assert_eq!(
        parse_argv(&["journalctl", "--boot", "--merge"]),
        Err(ParseArgvError::Invalid(
            "using --boot or --list-boots with --merge is not supported"
        ))
    );
}

#[test]
fn parse_argv_rejects_scoped_field_enumeration() {
    assert_eq!(
        parse_argv(&["journalctl", "--fields", "--boot"]),
        Err(ParseArgvError::Invalid(
            "-F/--field= and -N/--fields cannot be combined with options that limit the journal"
        ))
    );
    assert_eq!(
        parse_argv(&["journalctl", "--field=MESSAGE", "--identifier=sshd"]),
        Err(ParseArgvError::Invalid(
            "-F/--field= and -N/--fields cannot be combined with options that limit the journal"
        ))
    );

    let parsed = expect_parsed(parse_argv(&["journalctl", "--fields", "--boot=all"]));
    assert_eq!(parsed.action, JournalctlAction::ListFieldNames);
    assert!(!parsed.boot_filter);
}

#[test]
fn parse_argv_since_until_timestamp_validation_and_order() {
    let parsed = expect_parsed(parse_argv(&[
        "journalctl",
        "--since=2023-09-06T12:49:27Z",
        "--until=2023-09-06T14:49:27Z",
    ]));
    assert_eq!(parsed.since, Some("2023-09-06T12:49:27Z".to_string()));
    assert_eq!(parsed.until, Some("2023-09-06T14:49:27Z".to_string()));

    assert_eq!(
        parse_argv(&[
            "journalctl",
            "--since=2023-09-06T14:49:27Z",
            "--until=2023-09-06T12:49:27Z",
        ]),
        Err(ParseArgvError::Invalid("--since= must be before --until="))
    );

    assert_eq!(
        parse_argv(&["journalctl", "--since=show"]),
        Err(ParseArgvError::Invalid("failed to parse timestamp"))
    );
}

#[test]
fn parse_argv_timestamp_error_precedes_cursor_conflict() {
    assert_eq!(
        parse_argv(&["journalctl", "--since=cancel", "--cursor=abc"]),
        Err(ParseArgvError::Invalid("failed to parse timestamp"))
    );
}

#[test]
fn parse_argv_user_with_unit_rewrites_to_user_unit() {
    let parsed = expect_parsed(parse_argv(&["journalctl", "--user", "--unit=foo.service"]));
    assert!(parsed.system_units.is_empty());
    assert_eq!(parsed.user_units, vec!["foo.service".to_string()]);
}

#[test]
fn parse_argv_no_tail_and_default_lines_behavior() {
    let parsed = expect_parsed(parse_argv(&["journalctl", "--no-tail", "--follow"]));
    assert_eq!(parsed.lines, ARG_LINES_ALL);

    let parsed = expect_parsed(parse_argv(&["journalctl", "--follow"]));
    assert_eq!(parsed.lines, 10);

    let parsed = expect_parsed(parse_argv(&["journalctl", "--pager-end"]));
    assert_eq!(parsed.lines, 1000);
}

#[test]
fn parse_argv_grep_implies_reverse_when_needed() {
    let parsed = expect_parsed(parse_argv(&["journalctl", "-g", "err", "-n", "12"]));
    assert!(parsed.reverse);

    let parsed = expect_parsed(parse_argv(&[
        "journalctl",
        "-g",
        "err",
        "-n",
        "12",
        "--follow",
    ]));
    assert!(!parsed.reverse);
}

#[test]
fn parse_argv_grep_invalid_pattern_is_rejected_when_pcre2_is_available() {
    let probe = pattern_compile("ok", PatternCompileCase::Auto);
    if matches!(
        probe,
        Err(Pcre2Error::Unsupported | Pcre2Error::DlopenFailed(_) | Pcre2Error::SymbolNotFound(_))
    ) {
        return;
    }

    assert_eq!(
        parse_argv(&["journalctl", "--grep=("]),
        Err(ParseArgvError::Invalid("invalid --grep pattern"))
    );
}

#[test]
fn parse_argv_source_and_action_positional_conflicts() {
    assert_eq!(
        parse_argv(&["journalctl", "-D", "/a", "-M", "ctr"]),
        Err(ParseArgvError::Invalid("conflicting source options"))
    );

    assert_eq!(
        parse_argv(&["journalctl", "--disk-usage", "extra"]),
        Err(ParseArgvError::Invalid("extraneous arguments"))
    );

    let parsed = expect_parsed(parse_argv(&["journalctl", "--list-catalog", "extra"]));
    assert_eq!(parsed.action, JournalctlAction::ListCatalog);
    assert_eq!(parsed.positional_matches, vec!["extra".to_string()]);
}

#[test]
fn parse_argv_root_image_and_policy_path_parity_slice() {
    let parsed = expect_parsed(parse_argv(&[
        "journalctl",
        "--root=/",
        "--file=/tmp/a.journal",
    ]));
    assert!(parsed.root.is_none());
    assert_eq!(parsed.file, vec!["/tmp/a.journal".to_string()]);

    let parsed = expect_parsed(parse_argv(&["journalctl", "--image=relative/path"]));
    let image = parsed.image.expect("image should be set");
    assert!(image.starts_with('/'));
    assert!(image.ends_with("relative/path"));

    assert_eq!(
        parse_argv(&["journalctl", "--image-policy=definitely-not-valid"]),
        Err(ParseArgvError::Invalid("invalid --image-policy argument"))
    );
}

#[test]
fn parse_argv_file_glob_behaves_like_glob_nocheck() {
    let unique = format!(
        "journalctl-rs-glob-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&dir).unwrap();

    let file_a = dir.join("a.journal");
    let file_b = dir.join("b.journal");
    std::fs::write(&file_a, b"").unwrap();
    std::fs::write(&file_b, b"").unwrap();

    let pattern = format!("{}/{}.journal", dir.display(), "*");
    let parsed = expect_parsed(parse_argv(&["journalctl", "--file", &pattern]));
    assert_eq!(parsed.file.len(), 2);
    assert!(parsed.file.contains(&file_a.to_string_lossy().into_owned()));
    assert!(parsed.file.contains(&file_b.to_string_lossy().into_owned()));

    let no_match = format!("{}/nomatch*.journal", dir.display());
    let parsed = expect_parsed(parse_argv(&["journalctl", "--file", &no_match]));
    assert_eq!(parsed.file, vec![no_match]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parse_argv_priority_and_facility_parsing() {
    let parsed = expect_parsed(parse_argv(&[
        "journalctl",
        "--priority=3",
        "--facility=daemon,local7,5",
    ]));
    assert_eq!(
        parsed.priorities_mask,
        (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3)
    );
    assert_eq!(parsed.facilities, BTreeSet::from([3u8, 5u8, 23u8]));

    let parsed = expect_parsed(parse_argv(&["journalctl", "-p", "5..3"]));
    assert_eq!(parsed.priorities_mask, (1 << 3) | (1 << 4) | (1 << 5));
}

#[test]
fn parse_argv_facility_empty_segments_match_c_behavior() {
    let parsed = expect_parsed(parse_argv(&["journalctl", "--facility=daemon,,auth,"]));
    assert_eq!(parsed.facilities, BTreeSet::from([3u8, 4u8]));

    let parsed = expect_parsed(parse_argv(&["journalctl", "--facility="]));
    assert!(parsed.facilities.is_empty());
}

#[test]
fn parse_argv_identifier_filters() {
    let parsed = expect_parsed(parse_argv(&[
        "journalctl",
        "-t",
        "sshd",
        "--exclude-identifier=systemd",
    ]));
    assert_eq!(parsed.syslog_identifier, vec!["sshd".to_string()]);
    assert_eq!(parsed.exclude_identifier, vec!["systemd".to_string()]);
}

#[test]
fn parse_argv_short_option_utf8_arguments_are_safe() {
    let parsed = expect_parsed(parse_argv(&["journalctl", "-té"]));
    assert_eq!(parsed.syslog_identifier, vec!["é".to_string()]);

    assert_eq!(
        parse_argv(&["journalctl", "-é"]),
        Err(ParseArgvError::Invalid("unknown option"))
    );
}

#[test]
fn parse_argv_misc_flag_parity_slice() {
    let parsed = expect_parsed(parse_argv(&[
        "journalctl",
        "--namespace=+tenant",
        "--output-fields=MESSAGE,PRIORITY",
        "--case-sensitive=no",
        "--synchronize-on-exit=yes",
        "--show-cursor",
        "--truncate-newline",
        "--utc",
        "-x",
        "-W",
        "-I",
    ]));

    assert_eq!(parsed.namespace_flags, SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE);
    assert_eq!(parsed.namespace, Some("tenant".to_string()));
    assert_eq!(
        parsed.output_fields,
        BTreeSet::from(["MESSAGE".to_string(), "PRIORITY".to_string()])
    );
    assert_eq!(parsed.case, PatternCase::Insensitive);
    assert!(parsed.synchronize_on_exit);
    assert!(parsed.show_cursor);
    assert!(parsed.truncate_newline);
    assert!(parsed.utc);
    assert!(parsed.catalog);
    assert!(parsed.no_hostname);
    assert!(parsed.invocation);
    assert_eq!(parsed.invocation_id, None);
    assert_eq!(parsed.invocation_offset, 0);
}

#[test]
fn parse_argv_invocation_and_case_sensitivity_variants() {
    let parsed = expect_parsed(parse_argv(&["journalctl", "--invocation=all"]));
    assert!(!parsed.invocation);
    assert_eq!(parsed.invocation_id, None);
    assert_eq!(parsed.invocation_offset, 0);

    let parsed = expect_parsed(parse_argv(&[
        "journalctl",
        "--invocation=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+2",
        "--case-sensitive",
    ]));
    assert!(parsed.invocation);
    assert_eq!(parsed.invocation_id, Some([0xaa; 16]));
    assert_eq!(parsed.invocation_offset, 2);
    assert_eq!(parsed.case, PatternCase::Sensitive);
}

#[test]
fn parse_argv_action_switches_for_newid_setupkeys_verifykey() {
    let parsed = expect_parsed(parse_argv(&["journalctl", "--new-id128"]));
    assert_eq!(parsed.action, JournalctlAction::NewId128);

    let parsed = expect_parsed(parse_argv(&["journalctl", "--setup-keys"]));
    assert_eq!(parsed.action, JournalctlAction::SetupKeys);

    let parsed = expect_parsed(parse_argv(&[
        "journalctl",
        "--merge",
        "--verify-key=sekrit",
        "--smart-relinquish-var",
    ]));
    assert_eq!(parsed.action, JournalctlAction::RelinquishVar);
    assert!(parsed.smart_relinquish_var);
    assert_eq!(
        parsed.verify_key,
        Some(SecretString::new("sekrit".to_string()))
    );
    assert!(!parsed.merge);

    let debug = format!("{parsed:?}");
    assert!(!debug.contains("sekrit"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn run_short_circuit_results_match_parse_stage() {
    assert_eq!(
        run(&["journalctl", "--help"]).unwrap(),
        RunOutcome::HelpRequested
    );
    assert_eq!(
        run(&["journalctl", "--version"]).unwrap(),
        RunOutcome::VersionRequested
    );
    assert_eq!(
        run(&["journalctl", "--output=help"]).unwrap(),
        RunOutcome::OutputModeHelpRequested
    );
    assert_eq!(
        run(&["journalctl", "--facility=help"]).unwrap(),
        RunOutcome::FacilitiesHelpRequested
    );
}

#[test]
fn plan_dispatch_matches_c_action_switch() {
    let parsed = expect_parsed(parse_argv(&["journalctl", "--new-id128"]));
    assert_eq!(plan_dispatch(&parsed).target, DispatchTarget::Id128PrintNew);

    let parsed = expect_parsed(parse_argv(&["journalctl", "--setup-keys"]));
    assert_eq!(
        plan_dispatch(&parsed).target,
        DispatchTarget::ActionSetupKeys
    );

    let parsed = expect_parsed(parse_argv(&["journalctl", "--list-catalog"]));
    assert_eq!(
        plan_dispatch(&parsed).target,
        DispatchTarget::ActionListCatalog
    );

    let parsed = expect_parsed(parse_argv(&["journalctl", "--dump-catalog"]));
    assert_eq!(
        plan_dispatch(&parsed).target,
        DispatchTarget::ActionDumpCatalog
    );

    let parsed = expect_parsed(parse_argv(&["journalctl", "--update-catalog"]));
    assert_eq!(
        plan_dispatch(&parsed).target,
        DispatchTarget::ActionUpdateCatalog
    );

    let parsed = expect_parsed(parse_argv(&["journalctl", "--verify"]));
    assert_eq!(plan_dispatch(&parsed).target, DispatchTarget::ActionVerify);
}

#[test]
fn run_dispatch_preserves_matches_for_show_like_actions() {
    let outcome = run(&["journalctl", "_SYSTEMD_UNIT=sshd.service", "PRIORITY=3"]).unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Dispatch(DispatchPlan {
            target: DispatchTarget::ActionShow,
            matches: vec![
                "_SYSTEMD_UNIT=sshd.service".to_string(),
                "PRIORITY=3".to_string()
            ],
            filter_plan: Some(FilterPlan {
                scope: None,
                unit_matches: None,
                transport: None,
                priority_terms: Vec::new(),
                facility_terms: Vec::new(),
                identifier_terms: Vec::new(),
                exclude_identifiers: BTreeSet::new(),
                match_groups: vec![vec![
                    FilterMatchTerm::Field("_SYSTEMD_UNIT=sshd.service".to_string()),
                    FilterMatchTerm::Field("PRIORITY=3".to_string())
                ]],
            }),
            filter_backend_ops: Some(vec![
                FilterBackendOp::FlushMatches,
                FilterBackendOp::SetExcludeIdentifiers(BTreeSet::new()),
                FilterBackendOp::AddMatch("_SYSTEMD_UNIT=sshd.service".to_string()),
                FilterBackendOp::AddMatch("PRIORITY=3".to_string()),
            ]),
        })
    );

    let outcome = run(&["journalctl", "--list-catalog", "MESSAGE_ID=abcd"]).unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Dispatch(DispatchPlan {
            target: DispatchTarget::ActionListCatalog,
            matches: vec!["MESSAGE_ID=abcd".to_string()],
            filter_plan: None,
            filter_backend_ops: None,
        })
    );

    let outcome = run(&["journalctl", "--dump-catalog", "MESSAGE_ID=efgh"]).unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Dispatch(DispatchPlan {
            target: DispatchTarget::ActionDumpCatalog,
            matches: vec!["MESSAGE_ID=efgh".to_string()],
            filter_plan: None,
            filter_backend_ops: None,
        })
    );
}

#[test]
fn run_dispatch_rotate_vacuum_composition() {
    let outcome = run(&["journalctl", "--rotate", "--vacuum-time=123"]).unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Dispatch(DispatchPlan {
            target: DispatchTarget::ActionRotateAndVacuum,
            matches: Vec::new(),
            filter_plan: None,
            filter_backend_ops: None,
        })
    );
}

#[test]
fn run_show_rejects_misplaced_plus_separator() {
    assert_eq!(
        run(&["journalctl", "+"]),
        Err(ParseArgvError::Invalid(
            "\"+\" can only be used between terms"
        ))
    );
}

#[test]
fn replay_filter_plan_uses_invocation_precedence_and_c_order() {
    let parsed = expect_parsed(parse_argv(&[
        "journalctl",
        "--invocation=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+2",
        "--unit=foo.service",
        "--dmesg",
        "--identifier=sshd",
        "--exclude-identifier=cron",
        "--priority=2",
        "--facility=daemon",
        "MESSAGE=hello",
        "+",
        "_PID=42",
    ]));
    let plan = build_filter_plan(&parsed).unwrap();
    let ops = replay_filter_plan(&plan).unwrap();

    assert_eq!(
        ops,
        vec![
            FilterBackendOp::FlushMatches,
            FilterBackendOp::AddScopeInvocation {
                id: Some([0xaa; 16]),
                offset: 2,
            },
            FilterBackendOp::AddConjunction,
            FilterBackendOp::AddTransportKernel,
            FilterBackendOp::AddConjunction,
            FilterBackendOp::AddMatch("SYSLOG_IDENTIFIER=sshd".to_string()),
            FilterBackendOp::AddDisjunction,
            FilterBackendOp::AddConjunction,
            FilterBackendOp::SetExcludeIdentifiers(BTreeSet::from(["cron".to_string()])),
            FilterBackendOp::AddMatch("PRIORITY=0".to_string()),
            FilterBackendOp::AddMatch("PRIORITY=1".to_string()),
            FilterBackendOp::AddMatch("PRIORITY=2".to_string()),
            FilterBackendOp::AddConjunction,
            FilterBackendOp::AddMatch("SYSLOG_FACILITY=3".to_string()),
            FilterBackendOp::AddConjunction,
            FilterBackendOp::AddMatch("MESSAGE=hello".to_string()),
            FilterBackendOp::AddDisjunction,
            FilterBackendOp::AddMatch("_PID=42".to_string()),
        ]
    );
}

#[test]
fn replay_filter_plan_orders_boot_then_units_then_dmesg() {
    let parsed = expect_parsed(parse_argv(&[
        "journalctl",
        "--boot=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-1",
        "--unit=foo.service",
        "--user-unit=bar.service",
        "--dmesg",
    ]));
    let plan = build_filter_plan(&parsed).unwrap();
    let ops = replay_filter_plan(&plan).unwrap();

    assert_eq!(
        ops,
        vec![
            FilterBackendOp::FlushMatches,
            FilterBackendOp::AddScopeBoot {
                id: Some([0xbb; 16]),
                offset: -1,
            },
            FilterBackendOp::AddConjunction,
            FilterBackendOp::AddUnitMatches(UnitMatchPlan {
                system_units: vec!["foo.service".to_string()],
                user_units: vec!["bar.service".to_string()],
                coredump_uid_relaxed: false,
                mangle_warn: true,
            }),
            FilterBackendOp::AddConjunction,
            FilterBackendOp::AddTransportKernel,
            FilterBackendOp::AddConjunction,
            FilterBackendOp::SetExcludeIdentifiers(BTreeSet::new()),
        ]
    );
}

#[test]
fn replay_filter_plan_rejects_unresolved_absolute_path_term() {
    let plan = FilterPlan {
        scope: None,
        unit_matches: None,
        transport: None,
        priority_terms: Vec::new(),
        facility_terms: Vec::new(),
        identifier_terms: Vec::new(),
        exclude_identifiers: BTreeSet::new(),
        match_groups: vec![vec![FilterMatchTerm::AbsolutePath("/bin/sh".to_string())]],
    };

    assert_eq!(
        replay_filter_plan(&plan),
        Err(FilterApplyError::UnresolvedAbsolutePathTerm)
    );
}

#[test]
fn build_filter_plan_encodes_scope_units_and_transport() {
    let parsed = expect_parsed(parse_argv(&[
        "journalctl",
        "--invocation=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+1",
        "--boot",
        "--unit=foo.service",
        "--dmesg",
    ]));
    let plan = build_filter_plan(&parsed).unwrap();
    assert_eq!(
        plan.scope,
        Some(ScopePlan::Invocation {
            id: Some([0xaa; 16]),
            offset: 1,
        })
    );
    assert_eq!(plan.unit_matches, None);
    assert_eq!(plan.transport, Some(TransportFilter::Kernel));

    let parsed = expect_parsed(parse_argv(&[
        "journalctl",
        "--boot=all",
        "--unit=foo.service",
        "--user-unit=bar.service",
        "--directory=/tmp",
    ]));
    let plan = build_filter_plan(&parsed).unwrap();
    assert_eq!(plan.scope, None);
    assert_eq!(
        plan.unit_matches,
        Some(UnitMatchPlan {
            system_units: vec!["foo.service".to_string()],
            user_units: vec!["bar.service".to_string()],
            coredump_uid_relaxed: true,
            mangle_warn: true,
        })
    );
    assert_eq!(plan.transport, None);
}

#[test]
fn build_filter_plan_records_unit_mangle_warning_mode() {
    let parsed = expect_parsed(parse_argv(&["journalctl", "--unit=foo.service"]));
    let plan = build_filter_plan(&parsed).unwrap();
    assert_eq!(
        plan.unit_matches,
        Some(UnitMatchPlan {
            system_units: vec!["foo.service".to_string()],
            user_units: Vec::new(),
            coredump_uid_relaxed: false,
            mangle_warn: true,
        })
    );
}

#[test]
fn build_filter_plan_suppresses_unit_mangle_warning_when_quiet() {
    let parsed = expect_parsed(parse_argv(&["journalctl", "--quiet", "--unit=foo.service"]));
    let plan = build_filter_plan(&parsed).unwrap();
    assert_eq!(
        plan.unit_matches,
        Some(UnitMatchPlan {
            system_units: vec!["foo.service".to_string()],
            user_units: Vec::new(),
            coredump_uid_relaxed: false,
            mangle_warn: false,
        })
    );
}

#[test]
fn build_filter_plan_expands_executable_absolute_path() {
    use std::os::unix::fs::PermissionsExt;

    let unique = format!(
        "journalctl-rs-exe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join("tool.sh");
    std::fs::write(&exe, b"echo test\n").unwrap();
    let mut perm = std::fs::metadata(&exe).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&exe, perm).unwrap();

    let exe_str = exe.to_string_lossy().to_string();
    let parsed = expect_parsed(parse_argv(&["journalctl", &exe_str]));
    let plan = build_filter_plan(&parsed).unwrap();
    assert_eq!(plan.match_groups.len(), 1);
    assert_eq!(plan.match_groups[0].len(), 1);
    assert_eq!(
        plan.match_groups[0][0],
        FilterMatchTerm::Field(format!("_EXE={}", exe.canonicalize().unwrap().display()))
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn build_filter_plan_expands_device_absolute_path() {
    let devnull = Path::new("/dev/null");
    if !devnull.exists() {
        return;
    }

    let devnull_str = devnull.to_string_lossy().to_string();
    let parsed = expect_parsed(parse_argv(&["journalctl", &devnull_str]));
    let plan = build_filter_plan(&parsed).unwrap();
    assert_eq!(plan.match_groups.len(), 1);

    let terms = &plan.match_groups[0];
    let expected_boot_id =
        current_boot_id_match_term().unwrap_or_else(|| BOOT_ID_NULL_MATCH.to_string());
    assert!(terms.iter().any(|t| matches!(
            t,
            FilterMatchTerm::Field(v) if v.starts_with("_KERNEL_DEVICE=c") || v.starts_with("_KERNEL_DEVICE=b")
        )));
    assert!(
        terms
            .iter()
            .any(|t| *t == FilterMatchTerm::Field(expected_boot_id.clone()))
    );
}

#[test]
fn run_show_rejects_non_device_non_executable_absolute_path() {
    let unique = format!(
        "journalctl-rs-path-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("plain.txt");
    std::fs::write(&file, b"not executable").unwrap();

    let file_str = file.to_string_lossy().to_string();
    assert_eq!(
        run(&["journalctl", &file_str]),
        Err(ParseArgvError::Invalid(
            "file is neither a device node nor executable"
        ))
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn run_show_rejects_absolute_path_matches_with_external_sources() {
    assert_eq!(
        run(&["journalctl", "--machine=demo", "/bin/sh"]),
        Err(ParseArgvError::Invalid(
            "an extra path in match filter is currently not supported with --root, --image, or -M/--machine"
        ))
    );
}

#[test]
fn smart_relinquish_decision_matches_c_mount_logic_shape() {
    assert!(!should_relinquish_var_from_dev_ids(Some(1), Some(1)));
    assert!(should_relinquish_var_from_dev_ids(Some(1), Some(2)));
    assert!(should_relinquish_var_from_dev_ids(None, Some(2)));
    assert!(should_relinquish_var_from_dev_ids(Some(1), None));
}

#[test]
fn mount_id_parser_handles_root_and_trailing_slash() {
    let mountinfo = "\
36 30 0:31 / / rw,nosuid - ext4 /dev/root rw\n\
42 36 0:44 / /var/log/journal rw,nosuid - ext4 /dev/sda2 rw\n";

    assert_eq!(mount_id_from_mountinfo(mountinfo, "/"), Some(36));
    assert_eq!(
        mount_id_from_mountinfo(mountinfo, "/var/log/journal/"),
        Some(42)
    );
    assert_eq!(mount_id_from_mountinfo(mountinfo, "/does/not/exist"), None);
}
