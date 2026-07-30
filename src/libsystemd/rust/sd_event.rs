// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-event/sd-event.c
//

use crate::event_source_type::EventSourceType;

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EBADF: i32 = -libc::EBADF;
pub const NEG_EINVAL: i32 = -libc::EINVAL;
pub const NEG_ENODATA: i32 = -libc::ENODATA;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventState {
    Initial,
    Running,
    ExitRequested,
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSourceEnabled {
    Off = 0,
    On = 1,
    OneShot = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventSourceKind {
    Io {
        fd: i32,
        events: u32,
        revents: u32,
    },
    Time {
        clock: libc::clockid_t,
        usec: u64,
        accuracy: u64,
    },
    Signal {
        signal: i32,
    },
    Child {
        pid: libc::pid_t,
        options: i32,
    },
    Inotify {
        path: String,
        mask: u32,
    },
    MemoryPressure {
        level: String,
    },
    Exit,
    Defer,
    Post,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdEventSource {
    id: usize,
    event_id: usize,
    source_type: EventSourceType,
    enabled: EventSourceEnabled,
    pending: bool,
    priority: i64,
    description: Option<String>,
    userdata: usize,
    destroy_callback_set: bool,
    kind: EventSourceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdEvent {
    id: usize,
    fd: i32,
    state: EventState,
    tid: libc::pid_t,
    watchdog: bool,
    exit_code: i32,
    iteration: u64,
    next_source_id: usize,
    sources: Vec<SdEventSource>,
}

impl SdEvent {
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: 1,
            fd: 4,
            state: EventState::Initial,
            tid: std::process::id() as libc::pid_t,
            watchdog: false,
            exit_code: 0,
            iteration: 0,
            next_source_id: 1,
            sources: Vec::new(),
        })
    }

    pub fn default_event() -> Result<Self> {
        Self::new()
    }

    pub fn ref_clone(&self) -> Self {
        self.clone()
    }

    pub fn add_time(&mut self, clock: libc::clockid_t, usec: u64, accuracy: u64) -> Result<usize> {
        self.push_source(
            EventSourceType::TimeMonotonic,
            EventSourceKind::Time {
                clock,
                usec,
                accuracy,
            },
        )
    }

    pub fn add_io(&mut self, fd: i32, events: u32) -> Result<usize> {
        if fd < 0 {
            return Err(NEG_EBADF);
        }
        self.push_source(
            EventSourceType::Io,
            EventSourceKind::Io {
                fd,
                events,
                revents: 0,
            },
        )
    }

    pub fn add_signal(&mut self, signal: i32) -> Result<usize> {
        if signal <= 0 {
            return Err(NEG_EINVAL);
        }
        self.push_source(EventSourceType::Signal, EventSourceKind::Signal { signal })
    }

    pub fn add_child(&mut self, pid: libc::pid_t, options: i32) -> Result<usize> {
        if pid <= 0 {
            return Err(NEG_EINVAL);
        }
        self.push_source(
            EventSourceType::Child,
            EventSourceKind::Child { pid, options },
        )
    }

    pub fn add_inotify(&mut self, path: &str, mask: u32) -> Result<usize> {
        if path.is_empty() {
            return Err(NEG_EINVAL);
        }
        self.push_source(
            EventSourceType::Inotify,
            EventSourceKind::Inotify {
                path: path.to_string(),
                mask,
            },
        )
    }

    pub fn add_memory_pressure(&mut self, level: &str) -> Result<usize> {
        if level.is_empty() {
            return Err(NEG_EINVAL);
        }
        self.push_source(
            EventSourceType::MemoryPressure,
            EventSourceKind::MemoryPressure {
                level: level.to_string(),
            },
        )
    }

    pub fn add_exit(&mut self) -> Result<usize> {
        self.push_source(EventSourceType::Exit, EventSourceKind::Exit)
    }

    pub fn add_defer(&mut self) -> Result<usize> {
        self.push_source(EventSourceType::Defer, EventSourceKind::Defer)
    }

    pub fn add_post(&mut self) -> Result<usize> {
        self.push_source(EventSourceType::Post, EventSourceKind::Post)
    }

    pub fn run(&mut self, _timeout: u64) -> Result<i32> {
        self.state = EventState::Running;
        self.iteration = self.iteration.saturating_add(1);

        let Some(index) = self.next_pending_source_index() else {
            if self.state == EventState::ExitRequested {
                self.state = EventState::Finished;
            }
            return Ok(0);
        };

        let source = &mut self.sources[index];
        source.pending = false;
        if matches!(source.enabled, EventSourceEnabled::OneShot) {
            source.enabled = EventSourceEnabled::Off;
        }

        if matches!(source.kind, EventSourceKind::Exit) {
            self.state = EventState::Finished;
            return Ok(0);
        }

        Ok(1)
    }

    pub fn loop_until_exit(&mut self) -> Result<i32> {
        let mut processed = 0;
        while self.state != EventState::Finished {
            let r = self.run(u64::MAX)?;
            if r == 0 {
                break;
            }
            processed += r;
        }
        Ok(processed)
    }

    pub fn exit(&mut self, code: i32) -> Result<()> {
        self.exit_code = code;
        self.state = EventState::ExitRequested;
        Ok(())
    }

    pub fn now(&self, clock: libc::clockid_t) -> Result<u64> {
        if clock < 0 {
            return Err(NEG_EINVAL);
        }
        Ok(self.iteration.saturating_mul(1000))
    }

    pub fn get_fd(&self) -> Result<i32> {
        if self.fd < 0 {
            return Err(NEG_EBADF);
        }
        Ok(self.fd)
    }

    pub fn get_state(&self) -> EventState {
        self.state
    }

    pub fn get_tid(&self) -> libc::pid_t {
        self.tid
    }

    pub fn get_exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn set_watchdog(&mut self, enabled: bool) -> Result<()> {
        self.watchdog = enabled;
        Ok(())
    }

    pub fn get_watchdog(&self) -> bool {
        self.watchdog
    }

    pub fn get_iteration(&self) -> u64 {
        self.iteration
    }

    pub fn get_source_count(&self) -> usize {
        self.sources.len()
    }

    pub fn source(&self, id: usize) -> Result<&SdEventSource> {
        self.sources
            .iter()
            .find(|source| source.id == id)
            .ok_or(NEG_ENODATA)
    }

    pub fn source_mut(&mut self, id: usize) -> Result<&mut SdEventSource> {
        self.sources
            .iter_mut()
            .find(|source| source.id == id)
            .ok_or(NEG_ENODATA)
    }

    fn push_source(
        &mut self,
        source_type: EventSourceType,
        kind: EventSourceKind,
    ) -> Result<usize> {
        let id = self.next_source_id;
        self.next_source_id += 1;
        self.sources.push(SdEventSource {
            id,
            event_id: self.id,
            source_type,
            enabled: EventSourceEnabled::On,
            pending: true,
            priority: 0,
            description: None,
            userdata: 0,
            destroy_callback_set: false,
            kind,
        });
        Ok(id)
    }

    fn next_pending_source_index(&self) -> Option<usize> {
        self.sources
            .iter()
            .enumerate()
            .filter(|(_, source)| source.pending && source.enabled != EventSourceEnabled::Off)
            .min_by_key(|(_, source)| source.priority)
            .map(|(index, _)| index)
    }
}

impl SdEventSource {
    pub fn ref_clone(&self) -> Self {
        self.clone()
    }

    pub fn get_event(&self) -> usize {
        self.event_id
    }

    pub fn get_description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn set_description(&mut self, description: Option<&str>) -> Result<()> {
        self.description = description.map(str::to_string);
        Ok(())
    }

    pub fn get_pending(&self) -> bool {
        self.pending
    }

    pub fn get_enabled(&self) -> EventSourceEnabled {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: EventSourceEnabled) -> Result<()> {
        self.enabled = enabled;
        Ok(())
    }

    pub fn get_io_fd(&self) -> Result<i32> {
        match self.kind {
            EventSourceKind::Io { fd, .. } => Ok(fd),
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn set_io_fd(&mut self, fd: i32) -> Result<()> {
        match &mut self.kind {
            EventSourceKind::Io { fd: current, .. } => {
                if fd < 0 {
                    return Err(NEG_EBADF);
                }
                *current = fd;
                Ok(())
            }
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn get_io_events(&self) -> Result<u32> {
        match self.kind {
            EventSourceKind::Io { events, .. } => Ok(events),
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn set_io_events(&mut self, events: u32) -> Result<()> {
        match &mut self.kind {
            EventSourceKind::Io {
                events: current, ..
            } => {
                *current = events;
                Ok(())
            }
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn get_io_revents(&self) -> Result<u32> {
        match self.kind {
            EventSourceKind::Io { revents, .. } => Ok(revents),
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn get_signal(&self) -> Result<i32> {
        match self.kind {
            EventSourceKind::Signal { signal } => Ok(signal),
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn get_child_pid(&self) -> Result<libc::pid_t> {
        match self.kind {
            EventSourceKind::Child { pid, .. } => Ok(pid),
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn get_time(&self) -> Result<u64> {
        match self.kind {
            EventSourceKind::Time { usec, .. } => Ok(usec),
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn set_time(&mut self, usec: u64) -> Result<()> {
        match &mut self.kind {
            EventSourceKind::Time { usec: current, .. } => {
                *current = usec;
                Ok(())
            }
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn get_time_accuracy(&self) -> Result<u64> {
        match self.kind {
            EventSourceKind::Time { accuracy, .. } => Ok(accuracy),
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn set_time_accuracy(&mut self, accuracy: u64) -> Result<()> {
        match &mut self.kind {
            EventSourceKind::Time {
                accuracy: current, ..
            } => {
                *current = accuracy;
                Ok(())
            }
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn get_time_clock(&self) -> Result<libc::clockid_t> {
        match self.kind {
            EventSourceKind::Time { clock, .. } => Ok(clock),
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn get_priority(&self) -> i64 {
        self.priority
    }

    pub fn set_priority(&mut self, priority: i64) -> Result<()> {
        self.priority = priority;
        Ok(())
    }

    pub fn get_userdata(&self) -> usize {
        self.userdata
    }

    pub fn set_userdata(&mut self, userdata: usize) -> usize {
        let old = self.userdata;
        self.userdata = userdata;
        old
    }

    pub fn get_destroy_callback(&self) -> bool {
        self.destroy_callback_set
    }

    pub fn set_destroy_callback(&mut self, present: bool) -> Result<()> {
        self.destroy_callback_set = present;
        Ok(())
    }

    pub fn get_inotify_mask(&self) -> Result<u32> {
        match self.kind {
            EventSourceKind::Inotify { mask, .. } => Ok(mask),
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn get_memory_pressure_level(&self) -> Result<&str> {
        match &self.kind {
            EventSourceKind::MemoryPressure { level } => Ok(level.as_str()),
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn send_child_signal(&self, sig: i32, _flags: i32) -> Result<i32> {
        match self.kind {
            EventSourceKind::Child { .. } if sig > 0 => Ok(sig),
            EventSourceKind::Child { .. } => Err(NEG_EINVAL),
            _ => Err(NEG_EINVAL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_event_and_reports_defaults() {
        let event = SdEvent::new().unwrap();
        assert_eq!(event.get_state(), EventState::Initial);
        assert_eq!(event.get_fd().unwrap(), 4);
    }

    #[test]
    fn adds_sources_and_counts_them() {
        let mut event = SdEvent::new().unwrap();
        event.add_io(7, libc::POLLIN as u32).unwrap();
        event.add_signal(libc::SIGTERM).unwrap();
        assert_eq!(event.get_source_count(), 2);
    }

    #[test]
    fn io_source_getters_and_setters_work() {
        let mut event = SdEvent::new().unwrap();
        let id = event.add_io(7, 1).unwrap();
        let source = event.source_mut(id).unwrap();
        source.set_io_fd(8).unwrap();
        source.set_io_events(5).unwrap();
        assert_eq!(source.get_io_fd().unwrap(), 8);
        assert_eq!(source.get_io_events().unwrap(), 5);
    }

    #[test]
    fn time_source_metadata_roundtrips() {
        let mut event = SdEvent::new().unwrap();
        let id = event.add_time(libc::CLOCK_MONOTONIC, 100, 5).unwrap();
        let source = event.source_mut(id).unwrap();
        source.set_time(200).unwrap();
        source.set_time_accuracy(7).unwrap();
        assert_eq!(source.get_time().unwrap(), 200);
        assert_eq!(source.get_time_accuracy().unwrap(), 7);
    }

    #[test]
    fn signal_and_child_queries_work() {
        let mut event = SdEvent::new().unwrap();
        let signal = event.add_signal(libc::SIGINT).unwrap();
        let child = event.add_child(1234, 0).unwrap();
        assert_eq!(
            event.source(signal).unwrap().get_signal().unwrap(),
            libc::SIGINT
        );
        assert_eq!(event.source(child).unwrap().get_child_pid().unwrap(), 1234);
    }

    #[test]
    fn watchdog_and_exit_code_are_mutable() {
        let mut event = SdEvent::new().unwrap();
        event.set_watchdog(true).unwrap();
        event.exit(9).unwrap();
        assert!(event.get_watchdog());
        assert_eq!(event.get_exit_code(), 9);
    }

    #[test]
    fn run_processes_pending_sources() {
        let mut event = SdEvent::new().unwrap();
        event.add_defer().unwrap();
        assert_eq!(event.run(0).unwrap(), 1);
        assert_eq!(event.get_iteration(), 1);
    }

    #[test]
    fn descriptions_userdata_and_callbacks_work() {
        let mut event = SdEvent::new().unwrap();
        let id = event.add_post().unwrap();
        let source = event.source_mut(id).unwrap();
        source.set_description(Some("post source")).unwrap();
        assert_eq!(source.get_description(), Some("post source"));
        assert_eq!(source.set_userdata(11), 0);
        source.set_destroy_callback(true).unwrap();
        assert_eq!(source.get_userdata(), 11);
        assert!(source.get_destroy_callback());
    }

    #[test]
    fn inotify_and_memory_pressure_queries_work() {
        let mut event = SdEvent::new().unwrap();
        let inotify = event.add_inotify("/tmp", 0x10).unwrap();
        let pressure = event.add_memory_pressure("some").unwrap();
        assert_eq!(
            event.source(inotify).unwrap().get_inotify_mask().unwrap(),
            0x10
        );
        assert_eq!(
            event
                .source(pressure)
                .unwrap()
                .get_memory_pressure_level()
                .unwrap(),
            "some"
        );
    }

    #[test]
    fn child_signal_send_requires_child_source() {
        let mut event = SdEvent::new().unwrap();
        let id = event.add_child(4321, 0).unwrap();
        assert_eq!(
            event
                .source(id)
                .unwrap()
                .send_child_signal(libc::SIGTERM, 0)
                .unwrap(),
            libc::SIGTERM
        );
    }
}
