// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-event/test-event.c
//
// Simplified event loop primitives covering priority, oneshot, clocks, and queued signals.

use std::collections::{BTreeMap, VecDeque};

pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_BOOTTIME: i32 = 7;
pub const CLOCK_REALTIME_ALARM: i32 = 8;
pub const CLOCK_BOOTTIME_ALARM: i32 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceState {
    Off,
    On,
    Oneshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSource {
    pub id: usize,
    pub priority: i32,
    pub state: SourceState,
    pub pending: usize,
    pub dispatch_count: usize,
}

impl EventSource {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            priority: 0,
            state: SourceState::On,
            pending: 0,
            dispatch_count: 0,
        }
    }

    pub fn trigger(&mut self) {
        self.pending += 1;
    }

    pub fn dispatch(&mut self) -> bool {
        if self.state == SourceState::Off || self.pending == 0 {
            return false;
        }
        self.pending -= 1;
        self.dispatch_count += 1;
        if self.state == SourceState::Oneshot {
            self.state = SourceState::Off;
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventError {
    UnsupportedClock,
    RateLimited,
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedClock => f.write_str("unsupported clock"),
            Self::RateLimited => f.write_str("event is rate limited"),
        }
    }
}

impl std::error::Error for EventError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimit {
    burst: usize,
    seen: usize,
}

impl RateLimit {
    pub fn new(burst: usize) -> Self {
        Self { burst, seen: 0 }
    }

    pub fn check(&mut self) -> Result<(), EventError> {
        if self.seen >= self.burst {
            return Err(EventError::RateLimited);
        }
        self.seen += 1;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct EventLoop {
    pub sources: Vec<EventSource>,
    now_cache: BTreeMap<i32, u64>,
    rt_signals: VecDeque<(i32, i32, i32)>,
    non_rt_signals: BTreeMap<i32, i32>,
}

impl EventLoop {
    pub fn now(&mut self, clock: i32) -> Result<u64, EventError> {
        match clock {
            CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME | CLOCK_REALTIME_ALARM
            | CLOCK_BOOTTIME_ALARM => {
                let next = self.now_cache.entry(clock).or_insert(1);
                Ok(*next)
            }
            _ => Err(EventError::UnsupportedClock),
        }
    }

    pub fn advance_now(&mut self, clock: i32, value: u64) {
        self.now_cache.insert(clock, value);
    }

    pub fn run_once(&mut self) -> Option<usize> {
        let idx = self
            .sources
            .iter()
            .enumerate()
            .filter(|(_, source)| source.pending > 0 && source.state != SourceState::Off)
            .min_by_key(|(_, source)| source.priority)
            .map(|(idx, _)| idx)?;

        self.sources[idx].dispatch();
        Some(self.sources[idx].id)
    }

    pub fn queue_signal(&mut self, signo: i32, priority: i32, value: i32, realtime: bool) {
        if realtime {
            self.rt_signals.push_back((signo, priority, value));
        } else {
            self.non_rt_signals.entry(signo).or_insert(value);
        }
    }

    pub fn dispatch_signal(&mut self) -> Option<(i32, i32, i32)> {
        if let Some(index) = self
            .rt_signals
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, priority, _))| *priority)
            .map(|(index, _)| index)
        {
            return self.rt_signals.remove(index);
        }

        if let Some((&signo, &value)) = self.non_rt_signals.iter().next() {
            self.non_rt_signals.remove(&signo);
            return Some((signo, 0, value));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oneshot_source_turns_off_after_dispatch() {
        let mut source = EventSource::new(1);
        source.state = SourceState::Oneshot;
        source.trigger();
        assert!(source.dispatch());
        assert_eq!(source.state, SourceState::Off);
    }

    #[test]
    fn off_source_does_not_dispatch() {
        let mut source = EventSource::new(1);
        source.state = SourceState::Off;
        source.trigger();
        assert!(!source.dispatch());
    }

    #[test]
    fn lower_priority_value_runs_first() {
        let mut event = EventLoop::default();
        let mut a = EventSource::new(1);
        a.priority = 99;
        a.trigger();
        let mut b = EventSource::new(2);
        b.priority = 50;
        b.trigger();
        event.sources = vec![a, b];
        assert_eq!(event.run_once(), Some(2));
    }

    #[test]
    fn now_supports_known_clocks() {
        let mut event = EventLoop::default();
        assert!(event.now(CLOCK_MONOTONIC).unwrap() > 0);
        assert!(event.now(CLOCK_REALTIME).unwrap() > 0);
    }

    #[test]
    fn now_rejects_unknown_clock() {
        assert_eq!(
            EventLoop::default().now(900).unwrap_err(),
            EventError::UnsupportedClock
        );
    }

    #[test]
    fn rate_limit_blocks_after_burst() {
        let mut limit = RateLimit::new(2);
        assert!(limit.check().is_ok());
        assert!(limit.check().is_ok());
        assert_eq!(limit.check().unwrap_err(), EventError::RateLimited);
    }

    #[test]
    fn realtime_signals_dispatch_by_priority_before_non_realtime() {
        let mut event = EventLoop::default();
        event.queue_signal(34, -10, 2, true);
        event.queue_signal(35, 0, 1, true);
        event.queue_signal(12, 0, 99, false);
        assert_eq!(event.dispatch_signal(), Some((34, -10, 2)));
        assert_eq!(event.dispatch_signal(), Some((35, 0, 1)));
        assert_eq!(event.dispatch_signal(), Some((12, 0, 99)));
    }

    #[test]
    fn non_realtime_signal_is_coalesced() {
        let mut event = EventLoop::default();
        event.queue_signal(12, 0, 3, false);
        event.queue_signal(12, 0, 5, false);
        assert_eq!(event.dispatch_signal(), Some((12, 0, 3)));
        assert_eq!(event.dispatch_signal(), None);
    }

    #[test]
    fn dispatch_increments_counter() {
        let mut source = EventSource::new(1);
        source.trigger();
        assert!(source.dispatch());
        assert_eq!(source.dispatch_count, 1);
    }
}
