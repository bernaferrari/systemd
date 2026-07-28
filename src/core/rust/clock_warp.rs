// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/clock-warp.c
//
pub const EPOCH_CLOCK_FILE: &str = "/usr/lib/clock-epoch";
pub const TIMESYNCD_CLOCK_FILE: &str = "/var/lib/systemd/timesync/clock";
pub const USEC_PER_SEC: u64 = 1_000_000;
pub const USEC_PER_DAY: u64 = 86_400 * USEC_PER_SEC;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockWarpConfig {
    pub time_epoch_usec: u64,
    pub clock_valid_range_usec_max: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockEpochSource {
    BuiltInEpoch,
    TimesyncdClockFile,
    EpochClockFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockApplyEpochOutcome {
    NoAdjustment,
    Advanced {
        epoch_usec: u64,
        source: ClockEpochSource,
    },
    Rewound {
        epoch_usec: u64,
        source: ClockEpochSource,
    },
    AdjustmentFailed {
        epoch_usec: u64,
        source: ClockEpochSource,
        attempted_forward: bool,
        errno: i32,
    },
}

pub trait ClockWarpEnvironment {
    fn set_timewarp_timezone(&mut self, tz_minuteswest: i32, tz_dsttime: i32) -> Result<(), i32>;
    fn stat_mtime_usec(&mut self, path: &str) -> Result<u64, i32>;
    fn now_realtime_usec(&mut self) -> u64;
    fn set_realtime_usec(&mut self, usec: u64) -> Result<(), i32>;
    fn log(&mut self, level: LogLevel, message: String);
}

pub fn clock_reset_timewarp(env: &mut impl ClockWarpEnvironment) -> Result<(), i32> {
    env.set_timewarp_timezone(0, 0)
}

pub fn clock_apply_epoch(
    env: &mut impl ClockWarpEnvironment,
    config: ClockWarpConfig,
    allow_backwards: bool,
) -> ClockApplyEpochOutcome {
    let timesyncd_usec = match env.stat_mtime_usec(TIMESYNCD_CLOCK_FILE) {
        Ok(usec) => usec,
        Err(errno) if errno == -libc::ENOENT => 0,
        Err(errno) => {
            env.log(
                LogLevel::Warning,
                format!(
                    "Could not stat {TIMESYNCD_CLOCK_FILE}, ignoring: errno {}",
                    -errno
                ),
            );
            0
        }
    };

    let epoch_file_usec = match env.stat_mtime_usec(EPOCH_CLOCK_FILE) {
        Ok(usec) => usec,
        Err(errno) if errno == -libc::ENOENT => 0,
        Err(errno) => {
            env.log(
                LogLevel::Warning,
                format!(
                    "Could not stat {EPOCH_CLOCK_FILE}, ignoring: errno {}",
                    -errno
                ),
            );
            0
        }
    };

    let (epoch_usec, source) =
        if config.time_epoch_usec >= timesyncd_usec && config.time_epoch_usec >= epoch_file_usec {
            (config.time_epoch_usec, ClockEpochSource::BuiltInEpoch)
        } else if timesyncd_usec >= epoch_file_usec {
            (timesyncd_usec, ClockEpochSource::TimesyncdClockFile)
        } else {
            (epoch_file_usec, ClockEpochSource::EpochClockFile)
        };

    if epoch_usec == 0 {
        env.log(
            LogLevel::Debug,
            "Clock epoch is 0, skipping clock adjustment.".into(),
        );
        return ClockApplyEpochOutcome::NoAdjustment;
    }

    let now_usec = env.now_realtime_usec();
    let advance = if now_usec < epoch_usec {
        true
    } else if config.clock_valid_range_usec_max > 0
        && now_usec > epoch_usec.saturating_add(config.clock_valid_range_usec_max)
        && allow_backwards
    {
        false
    } else {
        return ClockApplyEpochOutcome::NoAdjustment;
    };

    if let Err(errno) = env.set_realtime_usec(epoch_usec) {
        if advance {
            env.log(
                LogLevel::Error,
                format!(
                    "Current system time is before epoch, but cannot correct: errno {}",
                    -errno
                ),
            );
        } else {
            env.log(
                LogLevel::Error,
                format!(
                    "Current system time is further ahead than {} usec after epoch, but cannot correct: errno {}",
                    config.clock_valid_range_usec_max,
                    -errno
                ),
            );
        }

        return ClockApplyEpochOutcome::AdjustmentFailed {
            epoch_usec,
            source,
            attempted_forward: advance,
            errno,
        };
    }

    if advance {
        env.log(
            LogLevel::Info,
            format!("System time advanced to {:?}: {}", source, epoch_usec),
        );
        ClockApplyEpochOutcome::Advanced { epoch_usec, source }
    } else {
        env.log(
            LogLevel::Info,
            format!(
                "System time was further ahead than {:?} after {:?}, clock reset to {}",
                config.clock_valid_range_usec_max, source, epoch_usec
            ),
        );
        ClockApplyEpochOutcome::Rewound { epoch_usec, source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockClockEnv {
        stat_results: HashMap<String, Result<u64, i32>>,
        now_usec: u64,
        settimeofday_result: Result<(), i32>,
        settime_result: Result<(), i32>,
        set_values: Vec<u64>,
        logs: Vec<(LogLevel, String)>,
    }

    impl Default for MockClockEnv {
        fn default() -> Self {
            Self {
                stat_results: HashMap::new(),
                now_usec: 0,
                settimeofday_result: Ok(()),
                settime_result: Ok(()),
                set_values: Vec::new(),
                logs: Vec::new(),
            }
        }
    }

    impl ClockWarpEnvironment for MockClockEnv {
        fn set_timewarp_timezone(
            &mut self,
            _tz_minuteswest: i32,
            _tz_dsttime: i32,
        ) -> Result<(), i32> {
            self.settimeofday_result
        }

        fn stat_mtime_usec(&mut self, path: &str) -> Result<u64, i32> {
            self.stat_results
                .get(path)
                .copied()
                .unwrap_or(Err(-libc::ENOENT))
        }

        fn now_realtime_usec(&mut self) -> u64 {
            self.now_usec
        }

        fn set_realtime_usec(&mut self, usec: u64) -> Result<(), i32> {
            self.set_values.push(usec);
            self.settime_result
        }

        fn log(&mut self, level: LogLevel, message: String) {
            self.logs.push((level, message));
        }
    }

    fn config() -> ClockWarpConfig {
        ClockWarpConfig {
            time_epoch_usec: 10 * USEC_PER_SEC,
            clock_valid_range_usec_max: 2 * USEC_PER_SEC,
        }
    }

    #[test]
    fn reset_timewarp_succeeds() {
        let mut env = MockClockEnv::default();
        assert_eq!(clock_reset_timewarp(&mut env), Ok(()));
    }

    #[test]
    fn reset_timewarp_returns_errno() {
        let mut env = MockClockEnv {
            settimeofday_result: Err(-libc::EPERM),
            ..MockClockEnv::default()
        };
        assert_eq!(clock_reset_timewarp(&mut env), Err(-libc::EPERM));
    }

    #[test]
    fn zero_epoch_skips_adjustment() {
        let mut env = MockClockEnv::default();
        let outcome = clock_apply_epoch(
            &mut env,
            ClockWarpConfig {
                time_epoch_usec: 0,
                clock_valid_range_usec_max: 0,
            },
            false,
        );
        assert_eq!(outcome, ClockApplyEpochOutcome::NoAdjustment);
        assert!(
            env.logs
                .iter()
                .any(|(_, msg)| msg.contains("Clock epoch is 0"))
        );
    }

    #[test]
    fn later_timesyncd_timestamp_is_used() {
        let mut env = MockClockEnv {
            now_usec: 5 * USEC_PER_SEC,
            ..MockClockEnv::default()
        };
        env.stat_results
            .insert(TIMESYNCD_CLOCK_FILE.into(), Ok(20 * USEC_PER_SEC));
        let outcome = clock_apply_epoch(&mut env, config(), false);
        assert_eq!(
            outcome,
            ClockApplyEpochOutcome::Advanced {
                epoch_usec: 20 * USEC_PER_SEC,
                source: ClockEpochSource::TimesyncdClockFile,
            }
        );
    }

    #[test]
    fn later_epoch_file_timestamp_is_used() {
        let mut env = MockClockEnv {
            now_usec: 5 * USEC_PER_SEC,
            ..MockClockEnv::default()
        };
        env.stat_results
            .insert(EPOCH_CLOCK_FILE.into(), Ok(30 * USEC_PER_SEC));
        let outcome = clock_apply_epoch(&mut env, config(), false);
        assert_eq!(
            outcome,
            ClockApplyEpochOutcome::Advanced {
                epoch_usec: 30 * USEC_PER_SEC,
                source: ClockEpochSource::EpochClockFile,
            }
        );
    }

    #[test]
    fn built_in_epoch_is_used_when_largest() {
        let mut env = MockClockEnv {
            now_usec: 5 * USEC_PER_SEC,
            ..MockClockEnv::default()
        };
        let outcome = clock_apply_epoch(&mut env, config(), false);
        assert_eq!(
            outcome,
            ClockApplyEpochOutcome::Advanced {
                epoch_usec: 10 * USEC_PER_SEC,
                source: ClockEpochSource::BuiltInEpoch,
            }
        );
    }

    #[test]
    fn no_adjustment_when_current_time_is_in_range() {
        let mut env = MockClockEnv {
            now_usec: 11 * USEC_PER_SEC,
            ..MockClockEnv::default()
        };
        assert_eq!(
            clock_apply_epoch(&mut env, config(), true),
            ClockApplyEpochOutcome::NoAdjustment
        );
        assert!(env.set_values.is_empty());
    }

    #[test]
    fn rewinds_when_time_is_far_ahead_and_backwards_is_allowed() {
        let mut env = MockClockEnv {
            now_usec: 13 * USEC_PER_SEC + 1,
            ..MockClockEnv::default()
        };
        let outcome = clock_apply_epoch(&mut env, config(), true);
        assert_eq!(
            outcome,
            ClockApplyEpochOutcome::Rewound {
                epoch_usec: 10 * USEC_PER_SEC,
                source: ClockEpochSource::BuiltInEpoch,
            }
        );
        assert_eq!(env.set_values, vec![10 * USEC_PER_SEC]);
    }

    #[test]
    fn stat_failures_other_than_enoent_are_logged() {
        let mut env = MockClockEnv {
            now_usec: 5 * USEC_PER_SEC,
            ..MockClockEnv::default()
        };
        env.stat_results
            .insert(TIMESYNCD_CLOCK_FILE.into(), Err(-libc::EIO));
        let _ = clock_apply_epoch(&mut env, config(), false);
        assert!(
            env.logs
                .iter()
                .any(|(level, _)| *level == LogLevel::Warning)
        );
    }

    #[test]
    fn settime_failure_is_reported() {
        let mut env = MockClockEnv {
            now_usec: 5 * USEC_PER_SEC,
            settime_result: Err(-libc::EPERM),
            ..MockClockEnv::default()
        };
        let outcome = clock_apply_epoch(&mut env, config(), false);
        assert_eq!(
            outcome,
            ClockApplyEpochOutcome::AdjustmentFailed {
                epoch_usec: 10 * USEC_PER_SEC,
                source: ClockEpochSource::BuiltInEpoch,
                attempted_forward: true,
                errno: -libc::EPERM,
            }
        );
    }
}
