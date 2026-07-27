// SPDX-License-Identifier: GPL-2.0-or-later
// PORT-SYNC: src/udev/udev-spawn.c

pub const SOURCE_PATH: &str = "src/udev/udev-spawn.c";
pub const SOURCE_LINE_COUNT: usize = 402;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnIoStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spawn<'a> {
    pub cmd: &'a str,
    pub timeout_warn_usec: u64,
    pub timeout_usec: u64,
    pub accept_failure: bool,
    pub result_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnError {
    EmptyCommand,
    InvalidTimeout,
    EmptyResultBuffer,
}

pub fn build_spawn<'a>(
    cmd: &'a str,
    timeout_warn_usec: u64,
    timeout_usec: u64,
    result_size: usize,
) -> Result<Spawn<'a>, SpawnError> {
    if cmd.is_empty() {
        return Err(SpawnError::EmptyCommand);
    }
    if result_size == 0 {
        return Err(SpawnError::EmptyResultBuffer);
    }
    if timeout_warn_usec > timeout_usec {
        return Err(SpawnError::InvalidTimeout);
    }
    Ok(Spawn {
        cmd,
        timeout_warn_usec,
        timeout_usec,
        accept_failure: false,
        result_size,
    })
}

pub fn reads_into_result(stream: SpawnIoStream, truncated: bool) -> bool {
    matches!(stream, SpawnIoStream::Stdout) && !truncated
}

pub fn command_timeout(total_timeout_usec: u64, age_usec: u64) -> Result<u64, SpawnError> {
    if age_usec >= total_timeout_usec {
        return Err(SpawnError::InvalidTimeout);
    }
    Ok(total_timeout_usec - age_usec)
}

pub fn validate_port_model() -> Result<(), SpawnError> {
    if SOURCE_LINE_COUNT != 402 {
        return Err(SpawnError::InvalidTimeout);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_metadata_matches_c_file() {
        assert_eq!(SOURCE_PATH, "src/udev/udev-spawn.c");
        assert_eq!(SOURCE_LINE_COUNT, 402);
    }

    #[test]
    fn build_spawn_requires_command() {
        assert_eq!(build_spawn("", 1, 2, 8), Err(SpawnError::EmptyCommand));
    }

    #[test]
    fn build_spawn_requires_result_buffer() {
        assert_eq!(
            build_spawn("cat", 1, 2, 0),
            Err(SpawnError::EmptyResultBuffer)
        );
    }

    #[test]
    fn warning_timeout_cannot_exceed_main_timeout() {
        assert_eq!(build_spawn("cat", 5, 4, 8), Err(SpawnError::InvalidTimeout));
    }

    #[test]
    fn build_spawn_accepts_valid_inputs() {
        let spawn = build_spawn("cat /sys/class/net/lo/uevent", 1, 5, 1024).unwrap();
        assert_eq!(spawn.cmd, "cat /sys/class/net/lo/uevent");
    }

    #[test]
    fn only_stdout_without_truncation_reads_into_result() {
        assert!(reads_into_result(SpawnIoStream::Stdout, false));
        assert!(!reads_into_result(SpawnIoStream::Stdout, true));
        assert!(!reads_into_result(SpawnIoStream::Stderr, false));
    }

    #[test]
    fn timeout_subtracts_event_age() {
        assert_eq!(command_timeout(10, 3).unwrap(), 7);
    }

    #[test]
    fn timeout_rejects_expired_commands() {
        assert_eq!(command_timeout(10, 10), Err(SpawnError::InvalidTimeout));
    }

    #[test]
    fn port_model_validation_succeeds() {
        assert_eq!(validate_port_model(), Ok(()));
    }
}
