// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/fuzz-manager-serialize.c

pub const MAX_FUZZ_INPUT_SIZE: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializePass {
    WithFds,
    WithoutFds,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzManagerSerializeRun {
    pub input_size: usize,
    pub serialize_passes: [SerializePass; 2],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzManagerSerializeOutcome {
    SkippedOversize { size: usize },
    Executed(FuzzManagerSerializeRun),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzManagerSerializeError {
    ManagerNew(String),
    OverrideLogLevel(String),
    OverrideLogTarget(String),
    OpenNull(String),
    CreateFdSet(String),
    DataToFile(String),
    Deserialize(String),
    Serialize { with_fds: bool, detail: String },
}

pub trait ManagerSerializeHarness {
    fn fuzz_setup_logging(&mut self);
    fn manager_new(&mut self) -> Result<(), String>;
    fn manager_override_log_level(&mut self) -> Result<(), String>;
    fn manager_override_log_target(&mut self) -> Result<(), String>;
    fn open_null_output(&mut self) -> Result<(), String>;
    fn fdset_new(&mut self) -> Result<(), String>;
    fn data_to_file(&mut self, data: &[u8]) -> Result<(), String>;
    fn manager_deserialize(&mut self) -> Result<(), String>;
    fn manager_serialize(&mut self, with_fds: bool) -> Result<(), String>;
}

pub fn llvm_fuzzer_test_one_input(
    data: &[u8],
    harness: &mut impl ManagerSerializeHarness,
) -> Result<FuzzManagerSerializeOutcome, FuzzManagerSerializeError> {
    if data.len() > MAX_FUZZ_INPUT_SIZE {
        return Ok(FuzzManagerSerializeOutcome::SkippedOversize { size: data.len() });
    }

    harness.fuzz_setup_logging();
    harness
        .manager_new()
        .map_err(FuzzManagerSerializeError::ManagerNew)?;
    harness
        .manager_override_log_level()
        .map_err(FuzzManagerSerializeError::OverrideLogLevel)?;
    harness
        .manager_override_log_target()
        .map_err(FuzzManagerSerializeError::OverrideLogTarget)?;
    harness
        .open_null_output()
        .map_err(FuzzManagerSerializeError::OpenNull)?;
    harness
        .fdset_new()
        .map_err(FuzzManagerSerializeError::CreateFdSet)?;
    harness
        .data_to_file(data)
        .map_err(FuzzManagerSerializeError::DataToFile)?;
    harness
        .manager_deserialize()
        .map_err(FuzzManagerSerializeError::Deserialize)?;
    harness
        .manager_serialize(true)
        .map_err(|detail| FuzzManagerSerializeError::Serialize {
            with_fds: true,
            detail,
        })?;
    harness
        .manager_serialize(false)
        .map_err(|detail| FuzzManagerSerializeError::Serialize {
            with_fds: false,
            detail,
        })?;

    Ok(FuzzManagerSerializeOutcome::Executed(
        FuzzManagerSerializeRun {
            input_size: data.len(),
            serialize_passes: [SerializePass::WithFds, SerializePass::WithoutFds],
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug, Default)]
    struct RecordingHarness {
        calls: Vec<&'static str>,
        seen_data: Vec<u8>,
        failures: VecDeque<Failure>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Failure {
        step: &'static str,
        detail: &'static str,
    }

    impl RecordingHarness {
        fn fail(step: &'static str, detail: &'static str) -> Self {
            let mut harness = Self::default();
            harness.failures.push_back(Failure { step, detail });
            harness
        }

        fn maybe_fail(&mut self, step: &'static str) -> Result<(), String> {
            if let Some(failure) = self.failures.pop_front_if(|failure| failure.step == step) {
                return Err(failure.detail.to_string());
            }

            self.calls.push(step);
            Ok(())
        }
    }

    impl ManagerSerializeHarness for RecordingHarness {
        fn fuzz_setup_logging(&mut self) {
            self.calls.push("fuzz_setup_logging");
        }

        fn manager_new(&mut self) -> Result<(), String> {
            self.maybe_fail("manager_new")
        }

        fn manager_override_log_level(&mut self) -> Result<(), String> {
            self.maybe_fail("manager_override_log_level")
        }

        fn manager_override_log_target(&mut self) -> Result<(), String> {
            self.maybe_fail("manager_override_log_target")
        }

        fn open_null_output(&mut self) -> Result<(), String> {
            self.maybe_fail("open_null_output")
        }

        fn fdset_new(&mut self) -> Result<(), String> {
            self.maybe_fail("fdset_new")
        }

        fn data_to_file(&mut self, data: &[u8]) -> Result<(), String> {
            self.seen_data = data.to_vec();
            self.maybe_fail("data_to_file")
        }

        fn manager_deserialize(&mut self) -> Result<(), String> {
            self.maybe_fail("manager_deserialize")
        }

        fn manager_serialize(&mut self, with_fds: bool) -> Result<(), String> {
            let step = if with_fds {
                "manager_serialize_true"
            } else {
                "manager_serialize_false"
            };
            self.calls.push(step);

            if let Some(failure) = self.failures.pop_front_if(|failure| failure.step == step) {
                return Err(failure.detail.to_string());
            }

            Ok(())
        }
    }

    #[test]
    fn accepts_empty_input() {
        let mut harness = RecordingHarness::default();
        let outcome = llvm_fuzzer_test_one_input(&[], &mut harness).expect("should run");

        assert_eq!(
            outcome,
            FuzzManagerSerializeOutcome::Executed(FuzzManagerSerializeRun {
                input_size: 0,
                serialize_passes: [SerializePass::WithFds, SerializePass::WithoutFds],
            })
        );
    }

    #[test]
    fn skips_inputs_larger_than_the_c_limit() {
        let mut harness = RecordingHarness::default();
        let input = vec![0_u8; MAX_FUZZ_INPUT_SIZE + 1];
        let outcome = llvm_fuzzer_test_one_input(&input, &mut harness).expect("should skip");

        assert_eq!(
            outcome,
            FuzzManagerSerializeOutcome::SkippedOversize { size: input.len() }
        );
        assert!(harness.calls.is_empty());
    }

    #[test]
    fn preserves_the_c_call_order() {
        let mut harness = RecordingHarness::default();

        let _ = llvm_fuzzer_test_one_input(b"abc", &mut harness).expect("should run");

        assert_eq!(
            harness.calls,
            vec![
                "fuzz_setup_logging",
                "manager_new",
                "manager_override_log_level",
                "manager_override_log_target",
                "open_null_output",
                "fdset_new",
                "data_to_file",
                "manager_deserialize",
                "manager_serialize_true",
                "manager_serialize_false",
            ]
        );
    }

    #[test]
    fn forwards_input_bytes_to_the_data_stage() {
        let mut harness = RecordingHarness::default();
        let input = b"serialized-manager-state";

        let _ = llvm_fuzzer_test_one_input(input, &mut harness).expect("should run");

        assert_eq!(harness.seen_data, input);
    }

    #[test]
    fn reports_manager_creation_failures() {
        let mut harness = RecordingHarness::fail("manager_new", "boom");

        let error = llvm_fuzzer_test_one_input(b"x", &mut harness).expect_err("must fail");

        assert_eq!(error, FuzzManagerSerializeError::ManagerNew("boom".into()));
    }

    #[test]
    fn reports_deserialize_failures() {
        let mut harness = RecordingHarness::fail("manager_deserialize", "bad-state");

        let error = llvm_fuzzer_test_one_input(b"x", &mut harness).expect_err("must fail");

        assert_eq!(
            error,
            FuzzManagerSerializeError::Deserialize("bad-state".into())
        );
    }

    #[test]
    fn reports_first_serialize_pass_failures_with_context() {
        let mut harness = RecordingHarness::fail("manager_serialize_true", "io");

        let error = llvm_fuzzer_test_one_input(b"x", &mut harness).expect_err("must fail");

        assert_eq!(
            error,
            FuzzManagerSerializeError::Serialize {
                with_fds: true,
                detail: "io".into(),
            }
        );
    }

    #[test]
    fn executes_both_serialize_passes_in_order() {
        let mut harness = RecordingHarness::default();

        let outcome = llvm_fuzzer_test_one_input(b"x", &mut harness).expect("should run");

        let FuzzManagerSerializeOutcome::Executed(run) = outcome else {
            panic!("expected an executed run");
        };

        assert_eq!(
            run.serialize_passes,
            [SerializePass::WithFds, SerializePass::WithoutFds]
        );
        assert!(
            harness
                .calls
                .ends_with(&["manager_serialize_true", "manager_serialize_false"])
        );
    }
}
