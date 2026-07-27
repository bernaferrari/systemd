// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/sd-bus.c, src/libsystemd/sd-bus/bus-control.c

use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, BusError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusError {
    NoDefaultBus,
    InvalidDescription,
    InvalidMatch,
    MatchNotFound,
    InvalidState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum BusState {
    Unset = 0,
    Opening = 1,
    Authenticating = 2,
    Hello = 3,
    Running = 4,
    Closing = 5,
    Closed = 6,
}

pub fn bus_is_open(state: BusState) -> bool {
    matches!(state, BusState::Hello | BusState::Running)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultBusKind {
    Default,
    User,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    Match,
    AsyncMatch,
}

pub type DestroyCallback = fn();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusSlot {
    pub id: u64,
    pub kind: SlotKind,
    pub rule: String,
    pub description: Option<String>,
    pub destroy_callback: Option<DestroyCallback>,
    pub floating: bool,
}

#[derive(Debug, Clone, Default)]
pub struct BusDefaults {
    pub default_bus: Option<Bus>,
    pub user_bus: Option<Bus>,
    pub system_bus: Option<Bus>,
}

impl BusDefaults {
    pub fn resolve(&self, kind: DefaultBusKind) -> Result<&Bus> {
        self.resolve_option(kind).ok_or(BusError::NoDefaultBus)
    }

    pub fn resolve_mut(&mut self, kind: DefaultBusKind) -> Result<&mut Bus> {
        self.resolve_option_mut(kind).ok_or(BusError::NoDefaultBus)
    }

    fn resolve_option(&self, kind: DefaultBusKind) -> Option<&Bus> {
        match kind {
            DefaultBusKind::Default => self.default_bus.as_ref(),
            DefaultBusKind::User => self.user_bus.as_ref(),
            DefaultBusKind::System => self.system_bus.as_ref(),
        }
    }

    fn resolve_option_mut(&mut self, kind: DefaultBusKind) -> Option<&mut Bus> {
        match kind {
            DefaultBusKind::Default => self.default_bus.as_mut(),
            DefaultBusKind::User => self.user_bus.as_mut(),
            DefaultBusKind::System => self.system_bus.as_mut(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Bus {
    state: Option<BusState>,
    input_fd: Option<i32>,
    output_fd: Option<i32>,
    inotify_fd: Option<i32>,
    pidfd: Option<i32>,
    io_events_attached: bool,
    inotify_watches: Vec<String>,
    read_queue: Vec<String>,
    write_queue: Vec<String>,
    description: Option<String>,
    is_monitor: bool,
    next_slot_id: u64,
    slots: BTreeMap<u64, BusSlot>,
    exit_code: Option<i32>,
}

impl Bus {
    pub fn new(state: BusState) -> Self {
        Self {
            state: Some(state),
            next_slot_id: 1,
            ..Self::default()
        }
    }

    pub fn state(&self) -> BusState {
        self.state.unwrap_or(BusState::Unset)
    }

    pub fn set_io_fds(&mut self, input_fd: i32, output_fd: i32) {
        self.input_fd = Some(input_fd);
        self.output_fd = Some(output_fd);
        self.io_events_attached = true;
    }

    pub fn set_inotify_fd(&mut self, fd: i32) {
        self.inotify_fd = Some(fd);
    }

    pub fn set_pidfd(&mut self, fd: i32) {
        self.pidfd = Some(fd);
    }

    pub fn set_monitor(&mut self, is_monitor: bool) {
        self.is_monitor = is_monitor;
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn set_description(&mut self, description: impl Into<String>) -> Result<()> {
        let description = description.into();
        if description.trim().is_empty() {
            return Err(BusError::InvalidDescription);
        }

        self.description = Some(description);
        Ok(())
    }

    pub fn close_io_fds(&mut self) {
        self.detach_io_events();
        self.output_fd = None;
        self.input_fd = None;
    }

    pub fn close_inotify_fd(&mut self) {
        self.inotify_fd = None;
        self.inotify_watches.clear();
    }

    pub fn close_fds(&mut self) {
        self.close_io_fds();
        self.close_inotify_fd();
        self.pidfd = None;
    }

    pub fn detach_io_events(&mut self) {
        self.io_events_attached = false;
    }

    pub fn io_events_attached(&self) -> bool {
        self.io_events_attached
    }

    pub fn push_read_message(&mut self, message: impl Into<String>) {
        self.read_queue.push(message.into());
    }

    pub fn push_write_message(&mut self, message: impl Into<String>) {
        self.write_queue.push(message.into());
    }

    pub fn reset_queues(&mut self) {
        self.read_queue.clear();
        self.write_queue.clear();
    }

    pub fn queue_lengths(&self) -> (usize, usize) {
        (self.read_queue.len(), self.write_queue.len())
    }

    pub fn start_running(&mut self) -> Result<()> {
        if matches!(self.state(), BusState::Closing | BusState::Closed) {
            return Err(BusError::InvalidState);
        }

        self.state = Some(BusState::Running);
        Ok(())
    }

    pub fn enter_closing(&mut self, exit_code: i32) {
        self.exit_code = Some(exit_code);
        self.state = Some(BusState::Closing);
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub fn add_match(&mut self, rule: &str) -> Result<u64> {
        self.insert_match(rule, SlotKind::Match)
    }

    pub fn add_match_async(&mut self, rule: &str) -> Result<u64> {
        self.insert_match(rule, SlotKind::AsyncMatch)
    }

    fn insert_match(&mut self, rule: &str, kind: SlotKind) -> Result<u64> {
        if rule.trim().is_empty() {
            return Err(BusError::InvalidMatch);
        }

        let id = self.next_slot_id;
        self.next_slot_id += 1;
        self.slots.insert(
            id,
            BusSlot {
                id,
                kind,
                rule: append_eavesdrop(self.is_monitor, rule),
                description: None,
                destroy_callback: None,
                floating: true,
            },
        );
        Ok(id)
    }

    pub fn remove_match(&mut self, rule: &str) -> Result<()> {
        let id = self
            .slots
            .iter()
            .find_map(|(id, slot)| {
                (slot.rule == rule || slot.rule == append_eavesdrop(self.is_monitor, rule))
                    .then_some(*id)
            })
            .ok_or(BusError::MatchNotFound)?;
        self.slot_free(id)
    }

    pub fn slot(&self, id: u64) -> Option<&BusSlot> {
        self.slots.get(&id)
    }

    pub fn slot_set_destroy_callback(
        &mut self,
        id: u64,
        callback: Option<DestroyCallback>,
    ) -> Result<()> {
        let slot = self.slots.get_mut(&id).ok_or(BusError::MatchNotFound)?;
        slot.destroy_callback = callback;
        Ok(())
    }

    pub fn slot_set_description(&mut self, id: u64, description: impl Into<String>) -> Result<()> {
        let description = description.into();
        if description.trim().is_empty() {
            return Err(BusError::InvalidDescription);
        }
        let slot = self.slots.get_mut(&id).ok_or(BusError::MatchNotFound)?;
        slot.description = Some(description);
        Ok(())
    }

    pub fn slot_free(&mut self, id: u64) -> Result<()> {
        let slot = self.slots.remove(&id).ok_or(BusError::MatchNotFound)?;
        if let Some(callback) = slot.destroy_callback {
            callback();
        }
        Ok(())
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }
}

pub fn append_eavesdrop(is_monitor: bool, rule: &str) -> String {
    if !is_monitor {
        return rule.to_string();
    }
    if rule.is_empty() {
        "eavesdrop='true'".to_string()
    } else {
        format!("{rule},eavesdrop='true'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DESTROY_COUNT: AtomicUsize = AtomicUsize::new(0);

    fn bump_destroy_count() {
        DESTROY_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn open_states_match_c_logic() {
        assert!(bus_is_open(BusState::Hello));
        assert!(bus_is_open(BusState::Running));
        assert!(!bus_is_open(BusState::Opening));
        assert!(!bus_is_open(BusState::Closed));
    }

    #[test]
    fn resolves_requested_default_bus() {
        let mut defaults = BusDefaults::default();
        defaults.user_bus = Some(Bus::new(BusState::Running));
        assert_eq!(
            defaults.resolve(DefaultBusKind::User).unwrap().state(),
            BusState::Running
        );
        defaults
            .resolve_mut(DefaultBusKind::User)
            .unwrap()
            .enter_closing(7);
        assert_eq!(
            defaults.resolve(DefaultBusKind::User).unwrap().exit_code(),
            Some(7)
        );
    }

    #[test]
    fn close_io_fds_detaches_events() {
        let mut bus = Bus::new(BusState::Hello);
        bus.set_io_fds(3, 4);
        bus.close_io_fds();
        assert!(!bus.io_events_attached());
        assert_eq!(bus.input_fd, None);
        assert_eq!(bus.output_fd, None);
    }

    #[test]
    fn close_inotify_clears_watches() {
        let mut bus = Bus::new(BusState::Running);
        bus.set_inotify_fd(9);
        bus.inotify_watches.push("watch".into());
        bus.close_inotify_fd();
        assert_eq!(bus.inotify_fd, None);
        assert!(bus.inotify_watches.is_empty());
    }

    #[test]
    fn reset_queues_drops_both_sides() {
        let mut bus = Bus::new(BusState::Running);
        bus.push_read_message("a");
        bus.push_write_message("b");
        bus.reset_queues();
        assert_eq!(bus.queue_lengths(), (0, 0));
    }

    #[test]
    fn start_running_rejects_closed_bus() {
        let mut bus = Bus::new(BusState::Closed);
        assert_eq!(bus.start_running(), Err(BusError::InvalidState));
    }

    #[test]
    fn monitor_match_appends_eavesdrop() {
        let mut bus = Bus::new(BusState::Running);
        bus.set_monitor(true);
        let id = bus.add_match("type='signal'").unwrap();
        assert_eq!(bus.slot(id).unwrap().rule, "type='signal',eavesdrop='true'");
    }

    #[test]
    fn slot_destroy_callback_runs_on_free() {
        DESTROY_COUNT.store(0, Ordering::SeqCst);
        let mut bus = Bus::new(BusState::Running);
        let id = bus.add_match("type='signal'").unwrap();
        bus.slot_set_destroy_callback(id, Some(bump_destroy_count))
            .unwrap();
        bus.slot_free(id).unwrap();
        assert_eq!(DESTROY_COUNT.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn remove_match_looks_up_original_rule() {
        let mut bus = Bus::new(BusState::Running);
        bus.set_monitor(true);
        bus.add_match("sender='x'").unwrap();
        assert!(bus.remove_match("sender='x'").is_ok());
        assert_eq!(bus.slot_count(), 0);
    }

    #[test]
    fn description_must_not_be_empty() {
        let mut bus = Bus::new(BusState::Running);
        assert_eq!(bus.set_description("  "), Err(BusError::InvalidDescription));
    }
}
