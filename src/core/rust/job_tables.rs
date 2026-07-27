// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/job.c
//
// Job state, type, and result string tables with lookup functions
// and the job-type-to-access-method mapping.
//
// Port of the string table and access-method logic defined near the
// end of job.c, backed by the enum definitions in job.h.

// ── EINVAL sentinel ───────────────────────────────────────────────────────

const EINVAL: i32 = -22;

// ── JobState enum ─────────────────────────────────────────────────────────

/// Job execution state.
///
/// Corresponds to `JobState` in job.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Waiting,
    Running,
    Done,
    Failed,
}

static JOB_STATE_TABLE: &[&str] = &["waiting", "running", "done", "failed"];

impl JobState {
    /// Convert to the canonical string representation.
    pub fn to_string_val(self) -> Result<&'static str, i32> {
        JOB_STATE_TABLE.get(self as usize).copied().ok_or(EINVAL)
    }

    /// Parse from the canonical string representation.
    pub fn from_string(s: &str) -> Result<Self, i32> {
        match s {
            "waiting" => Ok(JobState::Waiting),
            "running" => Ok(JobState::Running),
            "done" => Ok(JobState::Done),
            "failed" => Ok(JobState::Failed),
            _ => Err(EINVAL),
        }
    }
}

// ── JobType enum ──────────────────────────────────────────────────────────

/// Job operation type.
///
/// Corresponds to `JobType` in job.h. The discriminant values
/// match the C enum layout: values 0..4 are the core merging types,
/// 5 is NOP, 6 is TRY_RESTART, 7 is TRY_RELOAD, 8 is RELOAD_OR_START.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobType {
    Start = 0,
    VerifyActive = 1,
    Stop = 2,
    Reload = 3,
    Restart = 4,
    Nop = 5,
    TryRestart = 6,
    TryReload = 7,
    ReloadOrStart = 8,
}

static JOB_TYPE_TABLE: &[&str] = &[
    "start",
    "verify-active",
    "stop",
    "reload",
    "restart",
    "nop",
    "try-restart",
    "try-reload",
    "reload-or-start",
];

impl JobType {
    /// Convert to the canonical string representation.
    pub fn to_string_val(self) -> Result<&'static str, i32> {
        JOB_TYPE_TABLE.get(self as usize).copied().ok_or(EINVAL)
    }

    /// Parse from the canonical string representation.
    pub fn from_string(s: &str) -> Result<Self, i32> {
        JOB_TYPE_TABLE
            .iter()
            .position(|entry| *entry == s)
            .map(|idx| match idx {
                0 => JobType::Start,
                1 => JobType::VerifyActive,
                2 => JobType::Stop,
                3 => JobType::Reload,
                4 => JobType::Restart,
                5 => JobType::Nop,
                6 => JobType::TryRestart,
                7 => JobType::TryReload,
                8 => JobType::ReloadOrStart,
                _ => unreachable!(),
            })
            .ok_or(EINVAL)
    }

    /// Convert from a raw integer value.
    pub fn from_i32(v: i32) -> Result<Self, i32> {
        match v {
            0 => Ok(JobType::Start),
            1 => Ok(JobType::VerifyActive),
            2 => Ok(JobType::Stop),
            3 => Ok(JobType::Reload),
            4 => Ok(JobType::Restart),
            5 => Ok(JobType::Nop),
            6 => Ok(JobType::TryRestart),
            7 => Ok(JobType::TryReload),
            8 => Ok(JobType::ReloadOrStart),
            _ => Err(EINVAL),
        }
    }

    /// Convert to a raw integer value.
    pub fn to_i32(self) -> i32 {
        self as i32
    }
}

// ── JobResult enum ────────────────────────────────────────────────────────

/// Job completion result.
///
/// Corresponds to `JobResult` in job.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobResult {
    Done = 0,
    Canceled = 1,
    Timeout = 2,
    Failed = 3,
    Dependency = 4,
    Skipped = 5,
    Invalid = 6,
    Assert = 7,
    Unsupported = 8,
    Collected = 9,
    Once = 10,
    Frozen = 11,
    Concurrency = 12,
}

static JOB_RESULT_TABLE: &[&str] = &[
    "done",
    "canceled",
    "timeout",
    "failed",
    "dependency",
    "skipped",
    "invalid",
    "assert",
    "unsupported",
    "collected",
    "once",
    "frozen",
    "concurrency",
];

impl JobResult {
    /// Convert to the canonical string representation.
    pub fn to_string_val(self) -> Result<&'static str, i32> {
        JOB_RESULT_TABLE.get(self as usize).copied().ok_or(EINVAL)
    }

    /// Parse from the canonical string representation.
    pub fn from_string(s: &str) -> Result<Self, i32> {
        JOB_RESULT_TABLE
            .iter()
            .position(|entry| *entry == s)
            .map(|idx| match idx {
                0 => JobResult::Done,
                1 => JobResult::Canceled,
                2 => JobResult::Timeout,
                3 => JobResult::Failed,
                4 => JobResult::Dependency,
                5 => JobResult::Skipped,
                6 => JobResult::Invalid,
                7 => JobResult::Assert,
                8 => JobResult::Unsupported,
                9 => JobResult::Collected,
                10 => JobResult::Once,
                11 => JobResult::Frozen,
                12 => JobResult::Concurrency,
                _ => unreachable!(),
            })
            .ok_or(EINVAL)
    }

    /// Convert from a raw integer value.
    pub fn from_i32(v: i32) -> Result<Self, i32> {
        match v {
            0 => Ok(JobResult::Done),
            1 => Ok(JobResult::Canceled),
            2 => Ok(JobResult::Timeout),
            3 => Ok(JobResult::Failed),
            4 => Ok(JobResult::Dependency),
            5 => Ok(JobResult::Skipped),
            6 => Ok(JobResult::Invalid),
            7 => Ok(JobResult::Assert),
            8 => Ok(JobResult::Unsupported),
            9 => Ok(JobResult::Collected),
            10 => Ok(JobResult::Once),
            11 => Ok(JobResult::Frozen),
            12 => Ok(JobResult::Concurrency),
            _ => Err(EINVAL),
        }
    }
}

// ── Job type → access method ──────────────────────────────────────────────

/// Access method that a job type maps to for permission checks.
///
/// Port of `job_type_to_access_method()` from job.c:
///   - Start, Restart, TryRestart → "start"
///   - Stop → "stop"
///   - Everything else → "reload"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMethod {
    Start,
    Stop,
    Reload,
}

static ACCESS_METHOD_TABLE: &[&str] = &["start", "stop", "reload"];

impl AccessMethod {
    /// Convert to string.
    pub fn to_string_val(self) -> &'static str {
        ACCESS_METHOD_TABLE[self as usize]
    }
}

/// Map a job type to its access method for permission checks.
///
/// Port of `job_type_to_access_method()` from job.c.
pub fn job_type_to_access_method(t: JobType) -> Result<AccessMethod, i32> {
    match t {
        JobType::Start | JobType::Restart | JobType::TryRestart => Ok(AccessMethod::Start),
        JobType::Stop => Ok(AccessMethod::Stop),
        JobType::VerifyActive
        | JobType::Reload
        | JobType::Nop
        | JobType::TryReload
        | JobType::ReloadOrStart => Ok(AccessMethod::Reload),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_state_roundtrip() {
        assert_eq!(JobState::Waiting.to_string_val().unwrap(), "waiting");
        assert_eq!(JobState::Running.to_string_val().unwrap(), "running");
        assert_eq!(JobState::Done.to_string_val().unwrap(), "done");
        assert_eq!(JobState::Failed.to_string_val().unwrap(), "failed");
        assert_eq!(JobState::from_string("waiting").unwrap(), JobState::Waiting);
        assert_eq!(JobState::from_string("running").unwrap(), JobState::Running);
        assert_eq!(JobState::from_string("done").unwrap(), JobState::Done);
        assert_eq!(JobState::from_string("failed").unwrap(), JobState::Failed);
    }

    #[test]
    fn test_job_state_from_string_invalid() {
        assert!(JobState::from_string("stopped").is_err());
        assert!(JobState::from_string("").is_err());
    }

    #[test]
    fn test_job_type_roundtrip() {
        for (idx, &name) in JOB_TYPE_TABLE.iter().enumerate() {
            let jt = JobType::from_string(name).unwrap();
            assert_eq!(jt as usize, idx);
            assert_eq!(jt.to_string_val().unwrap(), name);
        }
    }

    #[test]
    fn test_job_type_from_string_invalid() {
        assert!(JobType::from_string("nonexistent").is_err());
        assert!(JobType::from_string("").is_err());
    }

    #[test]
    fn test_job_type_from_i32() {
        assert_eq!(JobType::from_i32(0).unwrap(), JobType::Start);
        assert_eq!(JobType::from_i32(2).unwrap(), JobType::Stop);
        assert_eq!(JobType::from_i32(8).unwrap(), JobType::ReloadOrStart);
        assert!(JobType::from_i32(-1).is_err());
        assert!(JobType::from_i32(9).is_err());
    }

    #[test]
    fn test_job_type_to_i32() {
        assert_eq!(JobType::Start.to_i32(), 0);
        assert_eq!(JobType::Stop.to_i32(), 2);
        assert_eq!(JobType::ReloadOrStart.to_i32(), 8);
    }

    #[test]
    fn test_job_result_roundtrip() {
        for (idx, &name) in JOB_RESULT_TABLE.iter().enumerate() {
            let jr = JobResult::from_string(name).unwrap();
            assert_eq!(jr as usize, idx);
            assert_eq!(jr.to_string_val().unwrap(), name);
        }
    }

    #[test]
    fn test_job_result_from_string_invalid() {
        assert!(JobResult::from_string("nonexistent").is_err());
    }

    #[test]
    fn test_job_result_from_i32() {
        assert_eq!(JobResult::from_i32(0).unwrap(), JobResult::Done);
        assert_eq!(JobResult::from_i32(12).unwrap(), JobResult::Concurrency);
        assert!(JobResult::from_i32(-1).is_err());
        assert!(JobResult::from_i32(13).is_err());
    }

    #[test]
    fn test_job_type_to_access_method_start() {
        assert_eq!(
            job_type_to_access_method(JobType::Start).unwrap(),
            AccessMethod::Start
        );
        assert_eq!(
            job_type_to_access_method(JobType::Restart).unwrap(),
            AccessMethod::Start
        );
        assert_eq!(
            job_type_to_access_method(JobType::TryRestart).unwrap(),
            AccessMethod::Start
        );
    }

    #[test]
    fn test_job_type_to_access_method_stop() {
        assert_eq!(
            job_type_to_access_method(JobType::Stop).unwrap(),
            AccessMethod::Stop
        );
    }

    #[test]
    fn test_job_type_to_access_method_reload() {
        assert_eq!(
            job_type_to_access_method(JobType::VerifyActive).unwrap(),
            AccessMethod::Reload
        );
        assert_eq!(
            job_type_to_access_method(JobType::Reload).unwrap(),
            AccessMethod::Reload
        );
        assert_eq!(
            job_type_to_access_method(JobType::Nop).unwrap(),
            AccessMethod::Reload
        );
        assert_eq!(
            job_type_to_access_method(JobType::TryReload).unwrap(),
            AccessMethod::Reload
        );
        assert_eq!(
            job_type_to_access_method(JobType::ReloadOrStart).unwrap(),
            AccessMethod::Reload
        );
    }

    #[test]
    fn test_access_method_to_string() {
        assert_eq!(AccessMethod::Start.to_string_val(), "start");
        assert_eq!(AccessMethod::Stop.to_string_val(), "stop");
        assert_eq!(AccessMethod::Reload.to_string_val(), "reload");
    }
}
