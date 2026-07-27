// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/fuzz-unit-file.c

pub const MAX_FUZZ_INPUT_SIZE: usize = 65_536;
const UTF8_BOM: &str = "\u{feff}";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitType {
    Service,
    Socket,
    Target,
    Device,
    Mount,
    Automount,
    Swap,
    Timer,
    Path,
    Slice,
    Scope,
}

impl UnitType {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "service" => Some(Self::Service),
            "socket" => Some(Self::Socket),
            "target" => Some(Self::Target),
            "device" => Some(Self::Device),
            "mount" => Some(Self::Mount),
            "automount" => Some(Self::Automount),
            "swap" => Some(Self::Swap),
            "timer" => Some(Self::Timer),
            "path" => Some(Self::Path),
            "slice" => Some(Self::Slice),
            "scope" => Some(Self::Scope),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Socket => "socket",
            Self::Target => "target",
            Self::Device => "device",
            Self::Mount => "mount",
            Self::Automount => "automount",
            Self::Swap => "swap",
            Self::Timer => "timer",
            Self::Path => "path",
            Self::Slice => "slice",
            Self::Scope => "scope",
        }
    }

    pub const fn supports_load(self) -> bool {
        true
    }

    pub fn unit_name(self) -> String {
        format!("a.{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FuzzUnitFileOptions {
    pub memory_sanitizer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzUnitFileSkipReason {
    Oversize { size: usize },
    EmptyInput,
    UnknownUnitType(String),
    UnsupportedUnitType(UnitType),
    ListenNetlinkRejectedByMsan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzUnitFileRun {
    pub unit_type: UnitType,
    pub unit_name: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzUnitFileOutcome {
    Skipped(FuzzUnitFileSkipReason),
    Executed(FuzzUnitFileRun),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzUnitFileError {
    ManagerNew(String),
    UnitNew(String),
    ConfigParse(String),
    UnitDump(String),
    ManagerDump(String),
}

pub trait UnitFileHarness {
    fn fuzz_setup_logging(&mut self);
    fn manager_new(&mut self) -> Result<(), String>;
    fn unit_new_for_name(&mut self, unit_name: &str, unit_type: UnitType) -> Result<(), String>;
    fn config_parse(&mut self, unit_name: &str, body: &str) -> Result<(), String>;
    fn unit_dump(&mut self, unit_name: &str) -> Result<(), String>;
    fn manager_dump(&mut self, marker: &str) -> Result<(), String>;
}

pub fn llvm_fuzzer_test_one_input(
    data: &[u8],
    options: FuzzUnitFileOptions,
    harness: &mut impl UnitFileHarness,
) -> Result<FuzzUnitFileOutcome, FuzzUnitFileError> {
    if data.len() > MAX_FUZZ_INPUT_SIZE {
        return Ok(FuzzUnitFileOutcome::Skipped(
            FuzzUnitFileSkipReason::Oversize { size: data.len() },
        ));
    }

    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines();
    let Some(first_line) = lines.next() else {
        return Ok(FuzzUnitFileOutcome::Skipped(
            FuzzUnitFileSkipReason::EmptyInput,
        ));
    };

    let Some(unit_type) = UnitType::parse(first_line) else {
        return Ok(FuzzUnitFileOutcome::Skipped(
            FuzzUnitFileSkipReason::UnknownUnitType(first_line.trim().to_string()),
        ));
    };

    if !unit_type.supports_load() {
        return Ok(FuzzUnitFileOutcome::Skipped(
            FuzzUnitFileSkipReason::UnsupportedUnitType(unit_type),
        ));
    }

    let body = lines.collect::<Vec<_>>().join("\n");
    if options.memory_sanitizer
        && body
            .lines()
            .map(|line| line.strip_prefix(UTF8_BOM).unwrap_or(line))
            .map(str::trim_start)
            .any(|line| line.starts_with("ListenNetlink"))
    {
        return Ok(FuzzUnitFileOutcome::Skipped(
            FuzzUnitFileSkipReason::ListenNetlinkRejectedByMsan,
        ));
    }

    harness.fuzz_setup_logging();
    harness
        .manager_new()
        .map_err(FuzzUnitFileError::ManagerNew)?;

    let unit_name = unit_type.unit_name();
    harness
        .unit_new_for_name(&unit_name, unit_type)
        .map_err(FuzzUnitFileError::UnitNew)?;
    harness
        .config_parse(&unit_name, &body)
        .map_err(FuzzUnitFileError::ConfigParse)?;
    harness
        .unit_dump(&unit_name)
        .map_err(FuzzUnitFileError::UnitDump)?;
    harness
        .manager_dump(">>>")
        .map_err(FuzzUnitFileError::ManagerDump)?;

    Ok(FuzzUnitFileOutcome::Executed(FuzzUnitFileRun {
        unit_type,
        unit_name,
        body,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug, Default)]
    struct RecordingHarness {
        calls: Vec<String>,
        failures: VecDeque<(&'static str, &'static str)>,
    }

    impl RecordingHarness {
        fn fail(step: &'static str, detail: &'static str) -> Self {
            let mut harness = Self::default();
            harness.failures.push_back((step, detail));
            harness
        }

        fn maybe_fail(&mut self, step: &'static str) -> Result<(), String> {
            if self.failures.front().is_some_and(|(name, _)| *name == step) {
                let (_, detail) = self.failures.pop_front().expect("queued failure");
                return Err(detail.to_string());
            }

            Ok(())
        }
    }

    impl UnitFileHarness for RecordingHarness {
        fn fuzz_setup_logging(&mut self) {
            self.calls.push("fuzz_setup_logging".into());
        }

        fn manager_new(&mut self) -> Result<(), String> {
            self.calls.push("manager_new".into());
            self.maybe_fail("manager_new")
        }

        fn unit_new_for_name(
            &mut self,
            unit_name: &str,
            unit_type: UnitType,
        ) -> Result<(), String> {
            self.calls
                .push(format!("unit_new_for_name:{unit_name}:{:?}", unit_type));
            self.maybe_fail("unit_new")
        }

        fn config_parse(&mut self, unit_name: &str, body: &str) -> Result<(), String> {
            self.calls.push(format!("config_parse:{unit_name}:{body}"));
            self.maybe_fail("config_parse")
        }

        fn unit_dump(&mut self, unit_name: &str) -> Result<(), String> {
            self.calls.push(format!("unit_dump:{unit_name}"));
            self.maybe_fail("unit_dump")
        }

        fn manager_dump(&mut self, marker: &str) -> Result<(), String> {
            self.calls.push(format!("manager_dump:{marker}"));
            self.maybe_fail("manager_dump")
        }
    }

    #[test]
    fn skips_oversized_input() {
        let mut harness = RecordingHarness::default();
        let input = vec![0_u8; MAX_FUZZ_INPUT_SIZE + 1];

        let outcome =
            llvm_fuzzer_test_one_input(&input, FuzzUnitFileOptions::default(), &mut harness)
                .expect("should skip");

        assert_eq!(
            outcome,
            FuzzUnitFileOutcome::Skipped(FuzzUnitFileSkipReason::Oversize { size: input.len() })
        );
        assert!(harness.calls.is_empty());
    }

    #[test]
    fn rejects_empty_input() {
        let mut harness = RecordingHarness::default();

        let outcome = llvm_fuzzer_test_one_input(b"", FuzzUnitFileOptions::default(), &mut harness)
            .expect("should skip");

        assert_eq!(
            outcome,
            FuzzUnitFileOutcome::Skipped(FuzzUnitFileSkipReason::EmptyInput)
        );
    }

    #[test]
    fn rejects_unknown_unit_types() {
        let mut harness = RecordingHarness::default();

        let outcome = llvm_fuzzer_test_one_input(
            b"nonsense\n[Unit]",
            FuzzUnitFileOptions::default(),
            &mut harness,
        )
        .expect("should skip");

        assert_eq!(
            outcome,
            FuzzUnitFileOutcome::Skipped(FuzzUnitFileSkipReason::UnknownUnitType(
                "nonsense".into()
            ))
        );
    }

    #[test]
    fn builds_the_expected_unit_name() {
        let mut harness = RecordingHarness::default();

        let outcome = llvm_fuzzer_test_one_input(
            b"service\n[Unit]\nDescription=x",
            FuzzUnitFileOptions::default(),
            &mut harness,
        )
        .expect("should run");

        let FuzzUnitFileOutcome::Executed(run) = outcome else {
            panic!("expected an executed run");
        };

        assert_eq!(run.unit_type, UnitType::Service);
        assert_eq!(run.unit_name, "a.service");
    }

    #[test]
    fn rejects_listen_netlink_when_msan_is_enabled() {
        let mut harness = RecordingHarness::default();

        let outcome = llvm_fuzzer_test_one_input(
            format!("socket\n{UTF8_BOM}   ListenNetlink=route").as_bytes(),
            FuzzUnitFileOptions {
                memory_sanitizer: true,
            },
            &mut harness,
        )
        .expect("should skip");

        assert_eq!(
            outcome,
            FuzzUnitFileOutcome::Skipped(FuzzUnitFileSkipReason::ListenNetlinkRejectedByMsan)
        );
        assert!(harness.calls.is_empty());
    }

    #[test]
    fn keeps_listen_netlink_when_msan_is_disabled() {
        let mut harness = RecordingHarness::default();

        let outcome = llvm_fuzzer_test_one_input(
            b"socket\n ListenNetlink=route",
            FuzzUnitFileOptions::default(),
            &mut harness,
        )
        .expect("should run");

        assert!(matches!(outcome, FuzzUnitFileOutcome::Executed(_)));
    }

    #[test]
    fn preserves_the_c_execution_order() {
        let mut harness = RecordingHarness::default();

        let _ = llvm_fuzzer_test_one_input(
            b"mount\n[Mount]\nWhat=/dev/null",
            FuzzUnitFileOptions::default(),
            &mut harness,
        )
        .expect("should run");

        assert_eq!(harness.calls[0], "fuzz_setup_logging");
        assert_eq!(harness.calls[1], "manager_new");
        assert!(harness.calls[2].starts_with("unit_new_for_name:a.mount:Mount"));
        assert!(harness.calls[3].starts_with("config_parse:a.mount:[Mount]"));
        assert_eq!(harness.calls[4], "unit_dump:a.mount");
        assert_eq!(harness.calls[5], "manager_dump:>>>");
    }

    #[test]
    fn forwards_the_body_without_the_first_line() {
        let mut harness = RecordingHarness::default();

        let outcome = llvm_fuzzer_test_one_input(
            b"timer\n[Timer]\nOnBootSec=1s",
            FuzzUnitFileOptions::default(),
            &mut harness,
        )
        .expect("should run");

        let FuzzUnitFileOutcome::Executed(run) = outcome else {
            panic!("expected an executed run");
        };

        assert_eq!(run.body, "[Timer]\nOnBootSec=1s");
    }

    #[test]
    fn reports_config_parse_failures() {
        let mut harness = RecordingHarness::fail("config_parse", "bad config");

        let error = llvm_fuzzer_test_one_input(
            b"path\n[Path]\nPathExists=/tmp/x",
            FuzzUnitFileOptions::default(),
            &mut harness,
        )
        .expect_err("must fail");

        assert_eq!(error, FuzzUnitFileError::ConfigParse("bad config".into()));
    }
}
