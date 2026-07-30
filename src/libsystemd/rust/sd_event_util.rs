// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-event/event-util.c
//

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -libc::EINVAL;
pub const NEG_ESRCH: i32 = -libc::ESRCH;
pub const NEG_EREMOTE: i32 = -libc::EREMOTE;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventSourceKind {
    Time {
        clock: libc::clockid_t,
        usec: u64,
        accuracy: u64,
    },
    Io {
        fd: i32,
        events: u32,
    },
    Signal {
        sig: i32,
    },
    Child {
        pid: libc::pid_t,
        options: i32,
    },
    Defer,
    Post,
    Exit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventSource {
    pub kind: EventSourceKind,
    pub enabled: bool,
    pub priority: i64,
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub now_realtime: u64,
    pub now_monotonic: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PidRef {
    pub pid: libc::pid_t,
    pub fd: i32,
    pub remote: bool,
}

// Mirrors the corresponding C helper's call shape so its port remains easy to
// compare and callers do not need an artificial parameter object.
#[allow(clippy::too_many_arguments)]
pub fn event_reset_time(
    _event: &Event,
    source: &mut Option<EventSource>,
    clock: libc::clockid_t,
    usec: u64,
    accuracy: u64,
    priority: i64,
    description: Option<&str>,
    force_reset: bool,
) -> Result<bool> {
    if let Some(existing) = source.as_mut() {
        let EventSourceKind::Time {
            clock: current_clock,
            usec: current_usec,
            accuracy: current_accuracy,
        } = &mut existing.kind
        else {
            return Err(NEG_EINVAL);
        };

        if !force_reset && existing.enabled {
            return Ok(false);
        }
        if *current_clock != clock {
            return Err(NEG_EINVAL);
        }

        *current_usec = usec;
        *current_accuracy = accuracy;
        existing.enabled = true;
        existing.priority = priority;
        existing.description = description.map(str::to_string);
        return Ok(false);
    }

    *source = Some(EventSource {
        kind: EventSourceKind::Time {
            clock,
            usec,
            accuracy,
        },
        enabled: true,
        priority,
        description: description.map(str::to_string),
    });
    Ok(true)
}

// Keep this signature aligned with `event_reset_time` and the C helper.
#[allow(clippy::too_many_arguments)]
pub fn event_reset_time_relative(
    event: &Event,
    source: &mut Option<EventSource>,
    clock: libc::clockid_t,
    usec: u64,
    accuracy: u64,
    priority: i64,
    description: Option<&str>,
    force_reset: bool,
) -> Result<bool> {
    let base = match clock {
        libc::CLOCK_REALTIME => event.now_realtime,
        libc::CLOCK_MONOTONIC => event.now_monotonic,
        _ => return Err(NEG_EINVAL),
    };

    event_reset_time(
        event,
        source,
        clock,
        if usec > 0 {
            base.saturating_add(usec)
        } else {
            0
        },
        accuracy,
        priority,
        description,
        force_reset,
    )
}

pub fn event_add_io(fd: i32, events: u32) -> Result<EventSource> {
    (fd >= 0)
        .then_some(EventSource {
            kind: EventSourceKind::Io { fd, events },
            enabled: true,
            priority: 0,
            description: None,
        })
        .ok_or(NEG_EINVAL)
}

pub fn event_add_signal(sig: i32) -> Result<EventSource> {
    (sig > 0)
        .then_some(EventSource {
            kind: EventSourceKind::Signal { sig },
            enabled: true,
            priority: 0,
            description: None,
        })
        .ok_or(NEG_EINVAL)
}

pub fn event_add_child(pid: libc::pid_t, options: i32) -> Result<EventSource> {
    (pid > 0)
        .then_some(EventSource {
            kind: EventSourceKind::Child { pid, options },
            enabled: true,
            priority: 0,
            description: None,
        })
        .ok_or(NEG_EINVAL)
}

pub fn event_add_child_pidref(pidref: PidRef, options: i32) -> Result<EventSource> {
    if pidref.pid <= 0 {
        return Err(NEG_ESRCH);
    }
    if pidref.remote {
        return Err(NEG_EREMOTE);
    }
    event_add_child(pidref.pid, options)
}

pub fn event_dual_timestamp_now(event: &Event) -> (u64, u64) {
    (event.now_realtime, event.now_monotonic)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> Event {
        Event {
            now_realtime: 100,
            now_monotonic: 200,
        }
    }

    #[test]
    fn reset_time_creates_source() {
        let mut source = None;
        assert_eq!(
            event_reset_time(
                &event(),
                &mut source,
                libc::CLOCK_REALTIME,
                5,
                1,
                7,
                Some("timer"),
                false
            ),
            Ok(true)
        );
    }

    #[test]
    fn reset_time_skips_enabled_source_without_force() {
        let mut source = Some(EventSource {
            kind: EventSourceKind::Time {
                clock: libc::CLOCK_REALTIME,
                usec: 5,
                accuracy: 1,
            },
            enabled: true,
            priority: 0,
            description: None,
        });
        assert_eq!(
            event_reset_time(
                &event(),
                &mut source,
                libc::CLOCK_REALTIME,
                10,
                2,
                1,
                None,
                false
            ),
            Ok(false)
        );
    }

    #[test]
    fn reset_time_updates_existing_source_when_forced() {
        let mut source = Some(EventSource {
            kind: EventSourceKind::Time {
                clock: libc::CLOCK_REALTIME,
                usec: 5,
                accuracy: 1,
            },
            enabled: false,
            priority: 0,
            description: None,
        });
        event_reset_time(
            &event(),
            &mut source,
            libc::CLOCK_REALTIME,
            10,
            2,
            9,
            Some("timer"),
            true,
        )
        .unwrap();
        let EventSourceKind::Time { usec, accuracy, .. } = source.unwrap().kind else {
            panic!()
        };
        assert_eq!((usec, accuracy), (10, 2));
    }

    #[test]
    fn reset_time_rejects_clock_mismatch() {
        let mut source = Some(EventSource {
            kind: EventSourceKind::Time {
                clock: libc::CLOCK_REALTIME,
                usec: 5,
                accuracy: 1,
            },
            enabled: false,
            priority: 0,
            description: None,
        });
        assert_eq!(
            event_reset_time(
                &event(),
                &mut source,
                libc::CLOCK_MONOTONIC,
                10,
                2,
                9,
                None,
                true
            ),
            Err(NEG_EINVAL)
        );
    }

    #[test]
    fn relative_reset_adds_current_time() {
        let mut source = None;
        event_reset_time_relative(
            &event(),
            &mut source,
            libc::CLOCK_MONOTONIC,
            50,
            0,
            0,
            None,
            true,
        )
        .unwrap();
        let EventSourceKind::Time { usec, .. } = source.unwrap().kind else {
            panic!()
        };
        assert_eq!(usec, 250);
    }

    #[test]
    fn add_io_requires_valid_fd() {
        assert_eq!(event_add_io(-1, 0), Err(NEG_EINVAL));
    }

    #[test]
    fn add_signal_requires_positive_signal() {
        assert_eq!(event_add_signal(0), Err(NEG_EINVAL));
    }

    #[test]
    fn add_child_pidref_rejects_remote() {
        assert_eq!(
            event_add_child_pidref(
                PidRef {
                    pid: 10,
                    fd: 3,
                    remote: true
                },
                0
            ),
            Err(NEG_EREMOTE)
        );
    }

    #[test]
    fn dual_timestamp_returns_both_clocks() {
        assert_eq!(event_dual_timestamp_now(&event()), (100, 200));
    }
}
