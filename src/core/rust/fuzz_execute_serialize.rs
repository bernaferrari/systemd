// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/fuzz-execute-serialize.c
//

pub const MAX_FUZZ_INPUT_SIZE: usize = 128 * 1024;
pub const INVALID_FD: i32 = -libc::EBADF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzError {
    InputTooLarge,
    DeserializeFailed,
    SerializeFailed,
}

pub type Result<T> = std::result::Result<T, FuzzError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrivateTmp {
    #[default]
    Connected,
    Disconnected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecParameters {
    pub stdin_fd: i32,
    pub stdout_fd: i32,
    pub stderr_fd: i32,
    pub root_directory_fd: i32,
    pub exec_fd: i32,
    pub user_lookup_fd: i32,
    pub bpf_restrict_fs_map_fd: i32,
    pub fds: Option<Vec<i32>>,
    pub n_socket_fds: usize,
    pub n_stashed_fds: usize,
}

impl Default for ExecParameters {
    fn default() -> Self {
        Self {
            stdin_fd: 0,
            stdout_fd: 1,
            stderr_fd: 2,
            root_directory_fd: 3,
            exec_fd: 4,
            user_lookup_fd: 5,
            bpf_restrict_fs_map_fd: 6,
            fds: None,
            n_socket_fds: 0,
            n_stashed_fds: 0,
        }
    }
}

impl ExecParameters {
    pub fn invalidate_deserialized_fds(&mut self) {
        self.stdin_fd = INVALID_FD;
        self.stdout_fd = INVALID_FD;
        self.stderr_fd = INVALID_FD;
        self.root_directory_fd = INVALID_FD;
        self.exec_fd = INVALID_FD;
        self.user_lookup_fd = INVALID_FD;
        self.bpf_restrict_fs_map_fd = INVALID_FD;

        match self.fds.as_mut() {
            Some(fds) => {
                for fd in fds.iter_mut().take(self.n_socket_fds + self.n_stashed_fds) {
                    *fd = INVALID_FD;
                }
            }
            None => {
                self.n_socket_fds = 0;
                self.n_stashed_fds = 0;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecContext {
    pub private_var_tmp: PrivateTmp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecCommand;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecRuntime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CGroupContext;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FdSet;

pub trait ExecuteCodec {
    #[expect(
        clippy::too_many_arguments,
        reason = "the C serialization boundary carries its fixed invocation state explicitly"
    )]
    fn deserialize_invocation(
        &mut self,
        input: &[u8],
        fdset: &mut FdSet,
        exec_context: &mut ExecContext,
        command: &mut ExecCommand,
        params: &mut ExecParameters,
        runtime: &mut ExecRuntime,
        cgroup_context: &mut CGroupContext,
    ) -> Result<()>;

    fn serialize_invocation(
        &mut self,
        fdset: &mut FdSet,
        exec_context: &ExecContext,
        command: &ExecCommand,
        params: &ExecParameters,
        runtime: &ExecRuntime,
        cgroup_context: &CGroupContext,
    ) -> Result<Vec<u8>>;
}

pub fn validate_input_size(size: usize) -> Result<()> {
    if size > MAX_FUZZ_INPUT_SIZE {
        Err(FuzzError::InputTooLarge)
    } else {
        Ok(())
    }
}

pub fn exec_fuzz_one(codec: &mut impl ExecuteCodec, input: &[u8], fdset: &mut FdSet) -> Result<()> {
    let mut params = ExecParameters::default();
    let mut exec_context = ExecContext::default();
    let mut cgroup_context = CGroupContext;
    let mut command = ExecCommand;
    let mut runtime = ExecRuntime;

    codec.deserialize_invocation(
        input,
        fdset,
        &mut exec_context,
        &mut command,
        &mut params,
        &mut runtime,
        &mut cgroup_context,
    )?;

    exec_context.private_var_tmp = PrivateTmp::Disconnected;

    let serialized = codec.serialize_invocation(
        fdset,
        &exec_context,
        &command,
        &params,
        &runtime,
        &cgroup_context,
    )?;

    codec.deserialize_invocation(
        &serialized,
        fdset,
        &mut exec_context,
        &mut command,
        &mut params,
        &mut runtime,
        &mut cgroup_context,
    )?;

    params.invalidate_deserialized_fds();
    Ok(())
}

pub fn llvm_fuzzer_test_one_input(codec: &mut impl ExecuteCodec, data: &[u8]) -> i32 {
    if validate_input_size(data.len()).is_err() {
        return 0;
    }

    let mut fdset = FdSet;
    let _ = exec_fuzz_one(codec, data, &mut fdset);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingCodec {
        calls: Vec<&'static str>,
        payload: Vec<u8>,
        fail_deserialize: bool,
        fail_serialize: bool,
    }

    impl ExecuteCodec for RecordingCodec {
        fn deserialize_invocation(
            &mut self,
            input: &[u8],
            _fdset: &mut FdSet,
            exec_context: &mut ExecContext,
            _command: &mut ExecCommand,
            params: &mut ExecParameters,
            _runtime: &mut ExecRuntime,
            _cgroup_context: &mut CGroupContext,
        ) -> Result<()> {
            if self.fail_deserialize {
                return Err(FuzzError::DeserializeFailed);
            }

            self.calls.push("deserialize");
            self.payload = input.to_vec();
            exec_context.private_var_tmp = PrivateTmp::Connected;
            params.fds = Some(vec![10, 11, 12]);
            params.n_socket_fds = 2;
            params.n_stashed_fds = 1;
            Ok(())
        }

        fn serialize_invocation(
            &mut self,
            _fdset: &mut FdSet,
            exec_context: &ExecContext,
            _command: &ExecCommand,
            _params: &ExecParameters,
            _runtime: &ExecRuntime,
            _cgroup_context: &CGroupContext,
        ) -> Result<Vec<u8>> {
            if self.fail_serialize {
                return Err(FuzzError::SerializeFailed);
            }

            self.calls.push("serialize");
            assert_eq!(exec_context.private_var_tmp, PrivateTmp::Disconnected);
            Ok(self.payload.clone())
        }
    }

    #[test]
    fn validate_input_size_accepts_boundary() {
        assert_eq!(validate_input_size(MAX_FUZZ_INPUT_SIZE), Ok(()));
    }

    #[test]
    fn validate_input_size_rejects_oversized_buffers() {
        assert_eq!(
            validate_input_size(MAX_FUZZ_INPUT_SIZE + 1),
            Err(FuzzError::InputTooLarge)
        );
    }

    #[test]
    fn invalidate_deserialized_fds_clears_primary_descriptors() {
        let mut params = ExecParameters::default();
        params.invalidate_deserialized_fds();

        assert_eq!(params.stdin_fd, INVALID_FD);
        assert_eq!(params.stderr_fd, INVALID_FD);
        assert_eq!(params.exec_fd, INVALID_FD);
    }

    #[test]
    fn invalidate_deserialized_fds_clears_optional_fd_array() {
        let mut params = ExecParameters {
            fds: Some(vec![3, 4, 5]),
            n_socket_fds: 2,
            n_stashed_fds: 1,
            ..ExecParameters::default()
        };

        params.invalidate_deserialized_fds();
        assert_eq!(params.fds, Some(vec![INVALID_FD, INVALID_FD, INVALID_FD]));
    }

    #[test]
    fn invalidate_deserialized_fds_resets_counts_without_fd_array() {
        let mut params = ExecParameters {
            fds: None,
            n_socket_fds: 2,
            n_stashed_fds: 3,
            ..ExecParameters::default()
        };

        params.invalidate_deserialized_fds();
        assert_eq!(params.n_socket_fds, 0);
        assert_eq!(params.n_stashed_fds, 0);
    }

    #[test]
    fn exec_fuzz_one_runs_deserialize_serialize_deserialize() {
        let mut codec = RecordingCodec::default();
        let mut fdset = FdSet;

        assert_eq!(exec_fuzz_one(&mut codec, b"abc", &mut fdset), Ok(()));
        assert_eq!(codec.calls, vec!["deserialize", "serialize", "deserialize"]);
    }

    #[test]
    fn exec_fuzz_one_propagates_deserialize_errors() {
        let mut codec = RecordingCodec {
            fail_deserialize: true,
            ..RecordingCodec::default()
        };

        assert_eq!(
            exec_fuzz_one(&mut codec, b"abc", &mut FdSet),
            Err(FuzzError::DeserializeFailed)
        );
    }

    #[test]
    fn exec_fuzz_one_propagates_serialize_errors() {
        let mut codec = RecordingCodec {
            fail_serialize: true,
            ..RecordingCodec::default()
        };

        assert_eq!(
            exec_fuzz_one(&mut codec, b"abc", &mut FdSet),
            Err(FuzzError::SerializeFailed)
        );
    }

    #[test]
    fn llvm_fuzzer_test_one_input_returns_zero_for_small_input() {
        let mut codec = RecordingCodec::default();
        assert_eq!(llvm_fuzzer_test_one_input(&mut codec, b"abc"), 0);
    }

    #[test]
    fn llvm_fuzzer_test_one_input_returns_zero_for_large_input_without_running_codec() {
        let mut codec = RecordingCodec::default();
        let oversized = vec![0_u8; MAX_FUZZ_INPUT_SIZE + 1];

        assert_eq!(llvm_fuzzer_test_one_input(&mut codec, &oversized), 0);
        assert!(codec.calls.is_empty());
    }
}
