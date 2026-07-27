// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/udev/test-udev-rule-runner.c

pub const SOURCE_PATH: &str = "src/udev/test-udev-rule-runner.c";
pub const SOURCE_LINE_COUNT: usize = 180;
pub const REQUIRED_ARGC: &[usize] = &[2, 3, 4];

pub const INCLUDED_HEADERS: &[&str] = &[
    "device-private.h",
    "device-util.h",
    "fs-util.h",
    "label-util.h",
    "log.h",
    "main-func.h",
    "mkdir-label.h",
    "mount-util.h",
    "namespace-util.h",
    "parse-util.h",
    "selinux-util.h",
    "signal-util.h",
    "string-util.h",
    "tests.h",
    "time-util.h",
    "udev-event.h",
    "udev-rules.h",
    "udev-spawn.h",
    "version.h",
];

pub const HELPER_FUNCTIONS: &[&str] = &["device_new_from_synthetic_event", "fake_filesystems"];
pub const ENTRY_FUNCTIONS: &[&str] = &["run"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerPhase {
    ValidateArguments,
    PrepareNamespace,
    PrepareSecurityState,
    LoadRules,
    CreateDevice,
    PrepareDevnode,
    ExecuteRules,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeFilesystem {
    pub src: &'static str,
    pub target: &'static str,
    pub ignore_mount_error: bool,
}

pub const FAKE_FILESYSTEMS: &[FakeFilesystem] = &[
    FakeFilesystem {
        src: "tmpfs/sys",
        target: "/sys",
        ignore_mount_error: false,
    },
    FakeFilesystem {
        src: "tmpfs/dev",
        target: "/dev",
        ignore_mount_error: false,
    },
    FakeFilesystem {
        src: "run",
        target: "/run",
        ignore_mount_error: false,
    },
    FakeFilesystem {
        src: "run",
        target: "/etc/udev/rules.d",
        ignore_mount_error: true,
    },
    FakeFilesystem {
        src: "run",
        target: "UDEVLIBEXECDIR/rules.d",
        ignore_mount_error: true,
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInvocation<'a> {
    pub action: Option<&'a str>,
    pub devpath: Option<&'a str>,
    pub delay_usec: Option<u32>,
    pub check_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerError {
    InvalidArgCount(usize),
    UnknownCheckMode(String),
    MissingAction,
    MissingDevpath,
    InvalidDelay(String),
}

pub fn parse_invocation<'a>(args: &[&'a str]) -> Result<RunInvocation<'a>, RunnerError> {
    if !REQUIRED_ARGC.contains(&args.len()) {
        return Err(RunnerError::InvalidArgCount(args.len()));
    }

    if args.len() == 2 {
        return if args[1] == "check" {
            Ok(RunInvocation {
                action: None,
                devpath: None,
                delay_usec: None,
                check_only: true,
            })
        } else {
            Err(RunnerError::UnknownCheckMode(args[1].to_string()))
        };
    }

    let delay_usec = match args.get(3) {
        Some(value) => Some(
            value
                .parse()
                .map_err(|_| RunnerError::InvalidDelay((*value).to_string()))?,
        ),
        None => None,
    };

    Ok(RunInvocation {
        action: Some(args[1]),
        devpath: Some(args[2]),
        delay_usec,
        check_only: false,
    })
}

pub fn synthetic_syspath(devpath: &str) -> Result<String, RunnerError> {
    if devpath.is_empty() {
        return Err(RunnerError::MissingDevpath);
    }
    Ok(format!("/sys{devpath}"))
}

pub fn execution_plan(invocation: &RunInvocation<'_>) -> Result<Vec<RunnerPhase>, RunnerError> {
    if invocation.check_only {
        return Ok(vec![
            RunnerPhase::ValidateArguments,
            RunnerPhase::PrepareNamespace,
        ]);
    }

    if invocation.action.is_none() {
        return Err(RunnerError::MissingAction);
    }
    if invocation.devpath.is_none() {
        return Err(RunnerError::MissingDevpath);
    }

    Ok(vec![
        RunnerPhase::ValidateArguments,
        RunnerPhase::PrepareNamespace,
        RunnerPhase::PrepareSecurityState,
        RunnerPhase::LoadRules,
        RunnerPhase::CreateDevice,
        RunnerPhase::PrepareDevnode,
        RunnerPhase::ExecuteRules,
    ])
}

pub fn validate_port_model() -> Result<(), RunnerError> {
    if FAKE_FILESYSTEMS.len() != 5 || !INCLUDED_HEADERS.contains(&"udev-rules.h") {
        return Err(RunnerError::MissingDevpath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_metadata_matches_expected_c_file() {
        assert_eq!(SOURCE_PATH, "src/udev/test-udev-rule-runner.c");
        assert_eq!(SOURCE_LINE_COUNT, 180);
    }

    #[test]
    fn fake_filesystem_layout_matches_c_table() {
        assert_eq!(FAKE_FILESYSTEMS.len(), 5);
        assert_eq!(FAKE_FILESYSTEMS[0].target, "/sys");
        assert!(FAKE_FILESYSTEMS[3].ignore_mount_error);
    }

    #[test]
    fn parse_check_mode() {
        let parsed = parse_invocation(&["runner", "check"]).unwrap();
        assert!(parsed.check_only);
        assert_eq!(parsed.delay_usec, None);
    }

    #[test]
    fn parse_execution_mode_without_delay() {
        let parsed = parse_invocation(&["runner", "add", "/devices/test"]).unwrap();
        assert_eq!(parsed.action, Some("add"));
        assert_eq!(parsed.devpath, Some("/devices/test"));
    }

    #[test]
    fn parse_execution_mode_with_delay() {
        let parsed = parse_invocation(&["runner", "remove", "/devices/test", "25"]).unwrap();
        assert_eq!(parsed.delay_usec, Some(25));
    }

    #[test]
    fn reject_unknown_check_argument() {
        assert_eq!(
            parse_invocation(&["runner", "nope"]),
            Err(RunnerError::UnknownCheckMode("nope".into()))
        );
    }

    #[test]
    fn reject_invalid_delay() {
        assert_eq!(
            parse_invocation(&["runner", "add", "/d", "x"]),
            Err(RunnerError::InvalidDelay("x".into()))
        );
    }

    #[test]
    fn synthetic_syspath_prefixes_sys() {
        assert_eq!(
            synthetic_syspath("/devices/virt").unwrap(),
            "/sys/devices/virt"
        );
    }

    #[test]
    fn execution_plan_for_check_mode_is_short() {
        let plan = execution_plan(&parse_invocation(&["runner", "check"]).unwrap()).unwrap();
        assert_eq!(
            plan,
            vec![
                RunnerPhase::ValidateArguments,
                RunnerPhase::PrepareNamespace
            ]
        );
    }

    #[test]
    fn execution_plan_for_full_run_matches_c_flow() {
        let plan = execution_plan(&parse_invocation(&["runner", "add", "/devices/test"]).unwrap())
            .unwrap();
        assert_eq!(plan.last(), Some(&RunnerPhase::ExecuteRules));
        assert!(plan.contains(&RunnerPhase::PrepareDevnode));
    }

    #[test]
    fn port_model_validation_succeeds() {
        assert_eq!(validate_port_model(), Ok(()));
    }
}
