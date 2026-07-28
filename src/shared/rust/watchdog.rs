// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/watchdog.c

use std::error::Error;
use std::fmt;

pub const USEC_PER_SEC: u64 = 1_000_000;
pub const USEC_INFINITY: u64 = u64::MAX;
pub const WATCHDOG_TIMEOUT_MAX_SEC: u64 = {
    let a = u32::MAX as u64 / 1000;
    let b = i32::MAX as u64;
    if a < b { a } else { b }
};
pub const WATCHDOG_PING_BURST: u32 = 3;
pub const WATCHDOG_MAX_FAILED_PINGS: u32 = 15;
pub const WATCHDOG_GOV_NAME_MAXLEN: usize = 20;

pub type Result<T> = std::result::Result<T, WatchdogError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchdogError {
    BadFileDescriptor,
    InvalidArgument,
    WouldBlock,
    Overflow,
}

impl fmt::Display for WatchdogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFileDescriptor => f.write_str("bad file descriptor"),
            Self::InvalidArgument => f.write_str("invalid argument"),
            Self::WouldBlock => f.write_str("operation would block"),
            Self::Overflow => f.write_str("arithmetic overflow"),
        }
    }
}

impl Error for WatchdogError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockId {
    Boottime,
    Monotonic,
    Realtime,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DualTimestamp {
    pub monotonic: u64,
    pub realtime: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PingOutcome {
    Noop,
    Triggered,
    Failed { bad_pings: u32, closed: bool },
    Recovered { attempts: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    interval_usec: u64,
    begin_usec: Option<u64>,
}

impl RateLimit {
    pub const fn new(interval_usec: u64) -> Self {
        Self {
            interval_usec,
            begin_usec: None,
        }
    }

    pub fn below(&mut self, now_usec: u64) -> bool {
        match self.begin_usec {
            Some(begin) if now_usec.saturating_sub(begin) < self.interval_usec => false,
            _ => {
                self.begin_usec = Some(now_usec);
                true
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchdogState {
    device: Option<String>,
    timeout_usec: u64,
    pretimeout_usec: u64,
    last_good_ping_usec: u64,
    last_bad_ping_usec: u64,
    bad_pings: u32,
    supports_pretimeout: bool,
    pretimeout_governor: Option<String>,
    opened: bool,
    last_open_error_was_enoent: bool,
}

impl Default for WatchdogState {
    fn default() -> Self {
        Self {
            device: None,
            timeout_usec: 0,
            pretimeout_usec: 0,
            last_good_ping_usec: USEC_INFINITY,
            last_bad_ping_usec: USEC_INFINITY,
            bad_pings: 0,
            supports_pretimeout: false,
            pretimeout_governor: None,
            opened: false,
            last_open_error_was_enoent: false,
        }
    }
}

pub fn saturated_usec_to_sec(val: u64) -> i32 {
    val.div_ceil(USEC_PER_SEC).min(WATCHDOG_TIMEOUT_MAX_SEC) as i32
}

fn timestamp_is_set(v: u64) -> bool {
    v != USEC_INFINITY
}

fn usec_sub_unsigned(a: u64, b: u64) -> u64 {
    a.saturating_sub(b)
}

impl WatchdogState {
    pub fn device(&self) -> Option<&str> {
        self.device.as_deref()
    }

    pub fn timeout_usec(&self) -> u64 {
        self.timeout_usec
    }

    pub fn pretimeout_usec(&self) -> u64 {
        self.pretimeout_usec
    }

    pub fn bad_pings(&self) -> u32 {
        self.bad_pings
    }

    pub fn is_open(&self) -> bool {
        self.opened
    }

    pub fn supports_pretimeout(&self) -> bool {
        self.supports_pretimeout
    }

    pub fn pretimeout_governor(&self) -> Option<&str> {
        self.pretimeout_governor.as_deref()
    }

    pub fn get_last_ping(&self, _clock: ClockId) -> u64 {
        self.last_good_ping_usec
    }

    pub fn get_last_ping_as_dual_timestamp(&self, realtime_offset_usec: u64) -> DualTimestamp {
        let monotonic = self.get_last_ping(ClockId::Monotonic);
        let realtime = if timestamp_is_set(monotonic) {
            monotonic.saturating_add(realtime_offset_usec)
        } else {
            USEC_INFINITY
        };

        DualTimestamp {
            monotonic,
            realtime,
        }
    }

    pub fn mark_open(&mut self) {
        self.opened = true;
        self.last_open_error_was_enoent = false;
        self.last_good_ping_usec = USEC_INFINITY;
        self.last_bad_ping_usec = USEC_INFINITY;
        self.bad_pings = 0;
    }

    pub fn mark_open_failed_missing(&mut self) {
        self.opened = false;
        self.last_open_error_was_enoent = true;
    }

    pub fn report_if_missing(&self) -> bool {
        self.last_open_error_was_enoent && !self.opened
    }

    pub fn set_device(&mut self, path: Option<&str>) -> bool {
        let next = path.map(ToOwned::to_owned);
        if self.device == next {
            return false;
        }

        self.device = next;
        self.close();
        true
    }

    pub fn setup(&mut self, timeout_usec: u64) {
        if timeout_usec == 0 {
            self.close();
            return;
        }

        if self.opened && (timeout_usec == self.timeout_usec || timeout_usec == USEC_INFINITY) {
            return;
        }

        self.timeout_usec = timeout_usec;
    }

    pub fn setup_pretimeout(&mut self, timeout_usec: u64) {
        if (self.opened && timeout_usec == self.pretimeout_usec) || timeout_usec == USEC_INFINITY {
            return;
        }

        self.pretimeout_usec = timeout_usec;
    }

    pub fn setup_pretimeout_governor(&mut self, governor: Option<&str>) -> Result<()> {
        self.pretimeout_governor = governor
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        if let Some(governor) = &self.pretimeout_governor {
            if governor.len() >= WATCHDOG_GOV_NAME_MAXLEN {
                return Err(WatchdogError::InvalidArgument);
            }
        }

        Ok(())
    }

    pub fn update_pretimeout_support(&mut self, governor: Option<&str>) -> Result<()> {
        let governor = governor.map(str::trim).filter(|value| !value.is_empty());

        self.supports_pretimeout = governor.is_some();

        if self.timeout_usec == USEC_INFINITY || self.pretimeout_usec == USEC_INFINITY {
            return Ok(());
        }

        if !self.supports_pretimeout && self.pretimeout_usec == 0 {
            return Ok(());
        }

        let timeout_sec = saturated_usec_to_sec(self.timeout_usec) as u64;
        let pretimeout_sec = saturated_usec_to_sec(self.pretimeout_usec) as u64;

        if pretimeout_sec >= timeout_sec && self.pretimeout_usec != 0 {
            return Err(WatchdogError::InvalidArgument);
        }

        Ok(())
    }

    pub fn calc_timeout(&self) -> u64 {
        if self.bad_pings >= WATCHDOG_MAX_FAILED_PINGS {
            return 0;
        }

        if self.supports_pretimeout
            && timestamp_is_set(self.pretimeout_usec)
            && self.timeout_usec >= self.pretimeout_usec
        {
            self.timeout_usec - self.pretimeout_usec
        } else {
            self.timeout_usec
        }
    }

    pub fn runtime_wait(&self, divisor: u32, now_usec: u64) -> Result<u64> {
        if divisor == 0 {
            return Err(WatchdogError::InvalidArgument);
        }

        let timeout = self.calc_timeout();
        if !timestamp_is_set(timeout) {
            return Ok(USEC_INFINITY);
        }

        let ts = self.last_good_ping_usec.max(self.last_bad_ping_usec);
        if timestamp_is_set(ts) {
            let scaled_divisor = if ts == self.last_bad_ping_usec {
                divisor.checked_mul(5).ok_or(WatchdogError::Overflow)?
            } else {
                divisor
            };

            let deadline = ts
                .checked_add(timeout / scaled_divisor as u64)
                .ok_or(WatchdogError::Overflow)?;

            return Ok(usec_sub_unsigned(deadline, now_usec));
        }

        Ok(timeout / divisor as u64)
    }

    pub fn ping(&mut self, now_usec: u64) -> Result<PingOutcome> {
        if self.timeout_usec == 0 {
            return Ok(PingOutcome::Noop);
        }

        if !self.opened {
            self.mark_open();
            self.last_good_ping_usec = now_usec;
            return Ok(PingOutcome::Triggered);
        }

        if self.runtime_wait(4, now_usec)? > 0 {
            return Ok(PingOutcome::Noop);
        }

        self.record_ping_success(now_usec)
    }

    pub fn record_ping_success(&mut self, now_usec: u64) -> Result<PingOutcome> {
        self.last_good_ping_usec = now_usec;
        self.last_bad_ping_usec = 0;

        if self.bad_pings > 0 {
            let attempts = self.bad_pings + 1;
            self.bad_pings = 0;
            return Ok(PingOutcome::Recovered { attempts });
        }

        Ok(PingOutcome::Triggered)
    }

    pub fn record_ping_failure(&mut self, now_usec: u64) -> PingOutcome {
        self.last_bad_ping_usec = now_usec;
        self.last_good_ping_usec = 0;
        self.bad_pings = self.bad_pings.saturating_add(1);

        if self.bad_pings >= WATCHDOG_MAX_FAILED_PINGS {
            self.close();
            return PingOutcome::Failed {
                bad_pings: WATCHDOG_MAX_FAILED_PINGS,
                closed: true,
            };
        }

        PingOutcome::Failed {
            bad_pings: self.bad_pings,
            closed: false,
        }
    }

    pub fn close(&mut self) {
        self.timeout_usec = 0;
        self.opened = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturated_usec_to_sec_rounds_up() {
        assert_eq!(saturated_usec_to_sec(1), 1);
        assert_eq!(saturated_usec_to_sec(USEC_PER_SEC + 1), 2);
    }

    #[test]
    fn saturated_usec_to_sec_saturates() {
        assert_eq!(
            saturated_usec_to_sec(u64::MAX) as u64,
            WATCHDOG_TIMEOUT_MAX_SEC
        );
    }

    #[test]
    fn set_device_closes_open_watchdog() {
        let mut state = WatchdogState::default();
        state.mark_open();
        state.setup(10 * USEC_PER_SEC);

        assert!(state.set_device(Some("/dev/watchdog0")));
        assert!(!state.is_open());
        assert_eq!(state.timeout_usec(), 0);
        assert_eq!(state.device(), Some("/dev/watchdog0"));
    }

    #[test]
    fn setup_zero_closes_watchdog() {
        let mut state = WatchdogState::default();
        state.mark_open();
        state.setup(0);

        assert_eq!(state.timeout_usec(), 0);
        assert!(!state.is_open());
    }

    #[test]
    fn setup_infinity_keeps_existing_open_timeout() {
        let mut state = WatchdogState::default();
        state.mark_open();
        state.setup(5 * USEC_PER_SEC);
        state.mark_open();

        state.setup(USEC_INFINITY);

        assert_eq!(state.timeout_usec(), 5 * USEC_PER_SEC);
    }

    #[test]
    fn governor_must_fit_kernel_limit() {
        let mut state = WatchdogState::default();
        let err = state
            .setup_pretimeout_governor(Some("x".repeat(WATCHDOG_GOV_NAME_MAXLEN).as_str()))
            .unwrap_err();

        assert_eq!(err, WatchdogError::InvalidArgument);
    }

    #[test]
    fn pretimeout_requires_smaller_value_than_timeout() {
        let mut state = WatchdogState::default();
        state.setup(5 * USEC_PER_SEC);
        state.setup_pretimeout(5 * USEC_PER_SEC);

        let err = state.update_pretimeout_support(Some("panic")).unwrap_err();
        assert_eq!(err, WatchdogError::InvalidArgument);
    }

    #[test]
    fn pretimeout_is_subtracted_from_effective_timeout() {
        let mut state = WatchdogState::default();
        state.setup(10 * USEC_PER_SEC);
        state.setup_pretimeout(2 * USEC_PER_SEC);
        state.update_pretimeout_support(Some("panic")).unwrap();

        assert_eq!(state.calc_timeout(), 8 * USEC_PER_SEC);
    }

    #[test]
    fn runtime_wait_without_ping_uses_fraction_of_timeout() {
        let mut state = WatchdogState::default();
        state.setup(8 * USEC_PER_SEC);

        assert_eq!(state.runtime_wait(4, 0).unwrap(), 2 * USEC_PER_SEC);
    }

    #[test]
    fn runtime_wait_after_good_ping_counts_from_last_good_ping() {
        let mut state = WatchdogState::default();
        state.setup(8 * USEC_PER_SEC);
        state.mark_open();
        state.record_ping_success(10 * USEC_PER_SEC).unwrap();

        assert_eq!(
            state.runtime_wait(4, 11 * USEC_PER_SEC).unwrap(),
            USEC_PER_SEC
        );
    }

    #[test]
    fn runtime_wait_after_bad_ping_is_faster() {
        let mut state = WatchdogState::default();
        state.setup(20 * USEC_PER_SEC);
        state.mark_open();
        state.record_ping_failure(10 * USEC_PER_SEC);

        assert_eq!(
            state.runtime_wait(4, 10 * USEC_PER_SEC).unwrap(),
            USEC_PER_SEC
        );
    }

    #[test]
    fn ping_is_noop_when_timeout_is_disabled() {
        let mut state = WatchdogState::default();
        assert_eq!(state.ping(0).unwrap(), PingOutcome::Noop);
    }

    #[test]
    fn first_ping_opens_and_records_success() {
        let mut state = WatchdogState::default();
        state.setup(4 * USEC_PER_SEC);

        assert_eq!(state.ping(123).unwrap(), PingOutcome::Triggered);
        assert!(state.is_open());
        assert_eq!(state.get_last_ping(ClockId::Boottime), 123);
    }

    #[test]
    fn successful_ping_recovers_after_failures() {
        let mut state = WatchdogState::default();
        state.setup(8 * USEC_PER_SEC);
        state.mark_open();
        state.record_ping_failure(1);
        state.record_ping_failure(2);

        assert_eq!(
            state.record_ping_success(3).unwrap(),
            PingOutcome::Recovered { attempts: 3 }
        );
        assert_eq!(state.bad_pings(), 0);
    }

    #[test]
    fn repeated_failures_close_watchdog() {
        let mut state = WatchdogState::default();
        state.setup(8 * USEC_PER_SEC);
        state.mark_open();

        for i in 1..WATCHDOG_MAX_FAILED_PINGS {
            assert_eq!(
                state.record_ping_failure(i as u64),
                PingOutcome::Failed {
                    bad_pings: i,
                    closed: false,
                }
            );
        }

        assert_eq!(
            state.record_ping_failure(WATCHDOG_MAX_FAILED_PINGS as u64),
            PingOutcome::Failed {
                bad_pings: WATCHDOG_MAX_FAILED_PINGS,
                closed: true,
            }
        );
        assert_eq!(state.timeout_usec(), 0);
        assert!(!state.is_open());
    }

    #[test]
    fn dual_timestamp_preserves_infinity() {
        let state = WatchdogState::default();
        let ts = state.get_last_ping_as_dual_timestamp(55);

        assert_eq!(ts.monotonic, USEC_INFINITY);
        assert_eq!(ts.realtime, USEC_INFINITY);
    }

    #[test]
    fn report_missing_matches_enoent_state() {
        let mut state = WatchdogState::default();
        state.mark_open_failed_missing();
        assert!(state.report_if_missing());

        state.mark_open();
        assert!(!state.report_if_missing());
    }

    #[test]
    fn runtime_wait_rejects_zero_divisor() {
        let state = WatchdogState::default();
        assert_eq!(
            state.runtime_wait(0, 0),
            Err(WatchdogError::InvalidArgument)
        );
    }
}
