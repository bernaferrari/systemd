// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/libsystemd/sd-event/sd-event.c, src/libsystemd/sd-event/event-source.h

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventSourceType {
    Io = 0,
    TimeRealtime = 1,
    TimeBoottime = 2,
    TimeMonotonic = 3,
    TimeRealtimeAlarm = 4,
    TimeBoottimeAlarm = 5,
    Signal = 6,
    Child = 7,
    Defer = 8,
    Post = 9,
    Exit = 10,
    Watchdog = 11,
    Inotify = 12,
    MemoryPressure = 13,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WakeupType {
    None = 0,
    EventSource = 1,
    ClockData = 2,
    SignalData = 3,
    InotifyData = 4,
}

impl EventSourceType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::TimeRealtime => "realtime",
            Self::TimeBoottime => "boottime",
            Self::TimeMonotonic => "monotonic",
            Self::TimeRealtimeAlarm => "realtime-alarm",
            Self::TimeBoottimeAlarm => "boottime-alarm",
            Self::Signal => "signal",
            Self::Child => "child",
            Self::Defer => "defer",
            Self::Post => "post",
            Self::Exit => "exit",
            Self::Watchdog => "watchdog",
            Self::Inotify => "inotify",
            Self::MemoryPressure => "memory-pressure",
        }
    }

    pub fn is_time(self) -> bool {
        matches!(
            self,
            Self::TimeRealtime
                | Self::TimeBoottime
                | Self::TimeMonotonic
                | Self::TimeRealtimeAlarm
                | Self::TimeBoottimeAlarm
        )
    }

    pub fn can_rate_limit(self) -> bool {
        matches!(
            self,
            Self::Io
                | Self::TimeRealtime
                | Self::TimeBoottime
                | Self::TimeMonotonic
                | Self::TimeRealtimeAlarm
                | Self::TimeBoottimeAlarm
                | Self::Signal
                | Self::Defer
                | Self::Inotify
                | Self::MemoryPressure
        )
    }

    pub fn uses_time_prioq(self) -> bool {
        self.can_rate_limit()
    }
}

pub fn event_source_type_from_string(s: &str) -> Result<EventSourceType> {
    match s {
        "io" => Ok(EventSourceType::Io),
        "realtime" => Ok(EventSourceType::TimeRealtime),
        "boottime" => Ok(EventSourceType::TimeBoottime),
        "monotonic" => Ok(EventSourceType::TimeMonotonic),
        "realtime-alarm" => Ok(EventSourceType::TimeRealtimeAlarm),
        "boottime-alarm" => Ok(EventSourceType::TimeBoottimeAlarm),
        "signal" => Ok(EventSourceType::Signal),
        "child" => Ok(EventSourceType::Child),
        "defer" => Ok(EventSourceType::Defer),
        "post" => Ok(EventSourceType::Post),
        "exit" => Ok(EventSourceType::Exit),
        "watchdog" => Ok(EventSourceType::Watchdog),
        "inotify" => Ok(EventSourceType::Inotify),
        "memory-pressure" => Ok(EventSourceType::MemoryPressure),
        _ => Err(NEG_EINVAL),
    }
}

pub fn event_source_type_to_string(kind: EventSourceType) -> &'static str {
    kind.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats_event_source_type() {
        assert_eq!(event_source_type_to_string(EventSourceType::Io), "io");
    }
    #[test]
    fn parses_event_source_type() {
        assert_eq!(
            event_source_type_from_string("watchdog"),
            Ok(EventSourceType::Watchdog)
        );
    }
    #[test]
    fn rejects_unknown_event_source_type() {
        assert_eq!(event_source_type_from_string("timerfd"), Err(NEG_EINVAL));
    }
    #[test]
    fn recognizes_time_sources() {
        assert!(EventSourceType::TimeMonotonic.is_time());
    }
    #[test]
    fn rejects_non_time_source() {
        assert!(!EventSourceType::Signal.is_time());
    }
    #[test]
    fn recognizes_rate_limited_sources() {
        assert!(EventSourceType::Inotify.can_rate_limit());
    }
    #[test]
    fn rejects_non_rate_limited_source() {
        assert!(!EventSourceType::Child.can_rate_limit());
    }
    #[test]
    fn time_prioq_matches_rate_limit_predicate() {
        assert_eq!(
            EventSourceType::Defer.uses_time_prioq(),
            EventSourceType::Defer.can_rate_limit()
        );
    }
    #[test]
    fn wakeup_type_values_are_stable() {
        assert_eq!(WakeupType::InotifyData as i32, 4);
    }
}
