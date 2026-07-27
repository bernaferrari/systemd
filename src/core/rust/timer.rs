// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/timer.c
//

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::ffi::Errno;
use crate::timer_tables::TimerBase;

pub type Result<T> = std::result::Result<T, TimerError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerError {
    NoValueConfiguration,
    StartLimitHit,
    Busy,
    UnsupportedCleanMask,
    MissingHomeDirectory,
}

impl TimerError {
    pub const fn errno(self) -> i32 {
        match self {
            Self::NoValueConfiguration => Errno::ENOEXEC.to_neg_errno(),
            Self::StartLimitHit => Errno::ECANCELED.to_neg_errno(),
            Self::Busy => Errno::EBUSY.to_neg_errno(),
            Self::UnsupportedCleanMask => Errno::EUNATCH.to_neg_errno(),
            Self::MissingHomeDirectory => Errno::ENXIO.to_neg_errno(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerState {
    Dead,
    Waiting,
    Running,
    Elapsed,
    Failed,
}

impl TimerState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dead => "dead",
            Self::Waiting => "waiting",
            Self::Running => "running",
            Self::Elapsed => "elapsed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerResult {
    Success,
    Resources,
    StartLimitHit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitActiveState {
    Inactive,
    Active,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanMask {
    State,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerValue {
    pub base: TimerBase,
    pub value_usec: u64,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timer {
    pub unit_id: String,
    pub state: TimerState,
    pub result: TimerResult,
    pub values: Vec<TimerValue>,
    pub on_clock_change: bool,
    pub on_timezone_change: bool,
    pub persistent: bool,
    pub remain_after_elapse: bool,
    pub accuracy_usec: u64,
    pub stamp_path: Option<String>,
    pub next_elapse_monotonic_or_boottime: Option<u64>,
    pub next_elapse_realtime: Option<u64>,
    pub deserialized_state: TimerState,
    pub last_trigger_realtime: Option<u64>,
    pub event_sources_enabled: bool,
}

impl Timer {
    pub fn new(unit_id: impl Into<String>, accuracy_usec: u64) -> Self {
        Self {
            unit_id: unit_id.into(),
            state: TimerState::Dead,
            result: TimerResult::Success,
            values: Vec::new(),
            on_clock_change: false,
            on_timezone_change: false,
            persistent: false,
            remain_after_elapse: true,
            accuracy_usec,
            stamp_path: None,
            next_elapse_monotonic_or_boottime: None,
            next_elapse_realtime: None,
            deserialized_state: TimerState::Dead,
            last_trigger_realtime: None,
            event_sources_enabled: false,
        }
    }
}

pub fn timer_verify(timer: &Timer) -> Result<()> {
    if timer.values.is_empty() && !timer.on_clock_change && !timer.on_timezone_change {
        return Err(TimerError::NoValueConfiguration);
    }

    Ok(())
}

pub fn timer_add_default_dependencies(
    default_dependencies: bool,
    system_manager: bool,
    has_calendar: bool,
) -> Vec<&'static str> {
    if !default_dependencies {
        return Vec::new();
    }

    let mut deps = vec!["timers.target", "shutdown.target(conflicts)"];

    if system_manager {
        deps.push("sysinit.target");
        if has_calendar {
            deps.push("time-sync.target");
            deps.push("time-set.target");
        }
    }

    deps
}

pub fn timer_add_trigger_dependencies(has_trigger: bool) -> Vec<&'static str> {
    if has_trigger {
        Vec::new()
    } else {
        vec!["trigger.service(before)", "trigger.service(triggers)"]
    }
}

pub fn timer_setup_persistent(
    timer: &mut Timer,
    system_manager: bool,
    xdg_data_home: Option<&str>,
    home_dir: Option<&str>,
) -> Result<Option<String>> {
    if !timer.persistent {
        timer.stamp_path = None;
        return Ok(None);
    }

    let path = if system_manager {
        format!("/var/lib/systemd/timers/stamp-{}", timer.unit_id)
    } else if let Some(xdg) = xdg_data_home {
        format!("{xdg}/systemd/timers/stamp-{}", timer.unit_id)
    } else if let Some(home) = home_dir {
        format!("{home}/.local/share/systemd/timers/stamp-{}", timer.unit_id)
    } else {
        return Err(TimerError::MissingHomeDirectory);
    };

    timer.stamp_path = Some(path.clone());
    Ok(Some(path))
}

pub fn timer_get_fixed_delay_hash(unit_id: &str, system_manager: bool, uid: u32) -> u64 {
    let mut hasher = DefaultHasher::new();
    unit_id.hash(&mut hasher);
    system_manager.hash(&mut hasher);
    uid.hash(&mut hasher);
    hasher.finish()
}

pub fn timer_set_state(timer: &mut Timer, state: TimerState) {
    timer.state = state;

    if state != TimerState::Waiting {
        timer.event_sources_enabled = false;
        timer.next_elapse_monotonic_or_boottime = None;
        timer.next_elapse_realtime = None;
    }
}

pub fn timer_coldplug(timer: &mut Timer) {
    if timer.deserialized_state == timer.state {
        return;
    }

    match timer.deserialized_state {
        TimerState::Waiting => timer_enter_waiting(timer, Some(0), Some(0)),
        other => timer_set_state(timer, other),
    }
}

pub fn timer_enter_dead(timer: &mut Timer, result: TimerResult) {
    if timer.result == TimerResult::Success || result == TimerResult::StartLimitHit {
        timer.result = result;
    }

    timer_set_state(
        timer,
        if timer.result == TimerResult::Success {
            TimerState::Dead
        } else {
            TimerState::Failed
        },
    );
}

pub fn timer_enter_elapsed(timer: &mut Timer, leave_around: bool) {
    if timer.remain_after_elapse || leave_around {
        timer_set_state(timer, TimerState::Elapsed);
    } else {
        timer_enter_dead(timer, TimerResult::Success);
    }
}

pub fn timer_enter_waiting(timer: &mut Timer, monotonic: Option<u64>, realtime: Option<u64>) {
    timer_set_state(timer, TimerState::Waiting);
    timer.event_sources_enabled = true;
    timer.next_elapse_monotonic_or_boottime = monotonic;
    timer.next_elapse_realtime = realtime;
}

pub fn timer_start(
    timer: &mut Timer,
    stamp_mtime_realtime: Option<u64>,
    now_realtime: u64,
) -> Result<bool> {
    for value in &mut timer.values {
        if value.base == TimerBase::Active {
            value.disabled = false;
        }
    }

    if let Some(stamp) = stamp_mtime_realtime.filter(|ts| *ts < now_realtime) {
        timer.last_trigger_realtime = Some(stamp);
    }

    timer.result = TimerResult::Success;
    timer_enter_waiting(
        timer,
        Some(timer.accuracy_usec),
        timer.last_trigger_realtime,
    );
    Ok(true)
}

pub fn timer_stop(timer: &mut Timer) -> bool {
    timer_enter_dead(timer, TimerResult::Success);
    true
}

pub fn timer_active_state(timer: &Timer) -> UnitActiveState {
    match timer.state {
        TimerState::Dead => UnitActiveState::Inactive,
        TimerState::Waiting | TimerState::Running | TimerState::Elapsed => UnitActiveState::Active,
        TimerState::Failed => UnitActiveState::Failed,
    }
}

pub fn timer_sub_state_to_string(timer: &Timer) -> &'static str {
    timer.state.as_str()
}

pub fn timer_can_clean(timer: &Timer) -> bool {
    timer.persistent
}

pub fn timer_clean(timer: &Timer, mask: CleanMask) -> Result<Option<&str>> {
    if timer.state != TimerState::Dead {
        return Err(TimerError::Busy);
    }

    if mask != CleanMask::State {
        return Err(TimerError::UnsupportedCleanMask);
    }

    Ok(timer.stamp_path.as_deref())
}

pub fn timer_test_startable(trigger_loaded: bool, start_limit_ok: bool) -> Result<bool> {
    if !trigger_loaded {
        return Err(TimerError::NoValueConfiguration);
    }

    if !start_limit_ok {
        return Err(TimerError::StartLimitHit);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_rejects_timer_without_any_trigger_source() {
        let timer = Timer::new("demo.timer", 1000);
        assert_eq!(timer_verify(&timer), Err(TimerError::NoValueConfiguration));
    }

    #[test]
    fn verify_accepts_value_and_clock_change_triggers() {
        let mut timer = Timer::new("demo.timer", 1000);
        timer.values.push(TimerValue {
            base: TimerBase::Active,
            value_usec: 10,
            disabled: false,
        });
        assert!(timer_verify(&timer).is_ok());

        timer.values.clear();
        timer.on_clock_change = true;
        assert!(timer_verify(&timer).is_ok());
    }

    #[test]
    fn default_dependencies_follow_c_shape() {
        let deps = timer_add_default_dependencies(true, true, true);
        assert!(deps.contains(&"timers.target"));
        assert!(deps.contains(&"sysinit.target"));
        assert!(deps.contains(&"time-sync.target"));
    }

    #[test]
    fn setup_persistent_chooses_system_and_user_paths() {
        let mut system_timer = Timer::new("a.timer", 1);
        system_timer.persistent = true;
        assert_eq!(
            timer_setup_persistent(&mut system_timer, true, None, None).unwrap(),
            Some("/var/lib/systemd/timers/stamp-a.timer".into())
        );

        let mut user_timer = Timer::new("b.timer", 1);
        user_timer.persistent = true;
        assert_eq!(
            timer_setup_persistent(&mut user_timer, false, Some("/tmp/xdg"), None).unwrap(),
            Some("/tmp/xdg/systemd/timers/stamp-b.timer".into())
        );
    }

    #[test]
    fn fixed_delay_hash_is_stable_for_same_inputs() {
        let a = timer_get_fixed_delay_hash("demo.timer", true, 1000);
        let b = timer_get_fixed_delay_hash("demo.timer", true, 1000);
        let c = timer_get_fixed_delay_hash("demo.timer", false, 1000);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn set_state_clears_event_sources_when_not_waiting() {
        let mut timer = Timer::new("demo.timer", 5);
        timer_enter_waiting(&mut timer, Some(10), Some(20));
        timer_set_state(&mut timer, TimerState::Running);
        assert!(!timer.event_sources_enabled);
        assert_eq!(timer.next_elapse_monotonic_or_boottime, None);
        assert_eq!(timer.next_elapse_realtime, None);
    }

    #[test]
    fn start_uses_past_stamp_and_enables_waiting() {
        let mut timer = Timer::new("demo.timer", 5);
        timer.values.push(TimerValue {
            base: TimerBase::Active,
            value_usec: 10,
            disabled: true,
        });
        timer_start(&mut timer, Some(50), 100).unwrap();
        assert_eq!(timer.last_trigger_realtime, Some(50));
        assert_eq!(timer.state, TimerState::Waiting);
        assert!(!timer.values[0].disabled);
    }

    #[test]
    fn elapsed_enters_dead_or_elapsed_depending_on_flags() {
        let mut timer = Timer::new("demo.timer", 5);
        timer.remain_after_elapse = false;
        timer_enter_elapsed(&mut timer, false);
        assert_eq!(timer.state, TimerState::Dead);

        timer.remain_after_elapse = true;
        timer_enter_elapsed(&mut timer, false);
        assert_eq!(timer.state, TimerState::Elapsed);
    }

    #[test]
    fn clean_checks_state_mask_and_persistence() {
        let mut timer = Timer::new("demo.timer", 5);
        timer.persistent = true;
        timer.stamp_path = Some("/tmp/stamp".into());
        assert_eq!(
            timer_clean(&timer, CleanMask::State).unwrap(),
            Some("/tmp/stamp")
        );
        assert_eq!(
            timer_clean(&timer, CleanMask::Other),
            Err(TimerError::UnsupportedCleanMask)
        );

        timer.state = TimerState::Waiting;
        assert_eq!(timer_clean(&timer, CleanMask::State), Err(TimerError::Busy));
    }

    #[test]
    fn test_startable_propagates_start_limit_failure() {
        assert_eq!(
            timer_test_startable(true, false),
            Err(TimerError::StartLimitHit)
        );
        assert_eq!(timer_test_startable(true, true), Ok(true));
    }
}
