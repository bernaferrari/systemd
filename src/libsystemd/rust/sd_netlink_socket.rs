// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-socket.c
//

use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type Result<T> = std::result::Result<T, SocketError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketError {
    QueueFull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedMessage {
    pub serial: u32,
    pub broadcast: bool,
    pub errno: i32,
}

#[derive(Debug, Default)]
pub struct NetlinkSocketState {
    pub broadcast_group_refs: BTreeMap<u32, u32>,
    pub ignored_serials: BTreeSet<u32>,
    pub rqueue: VecDeque<QueuedMessage>,
    pub rqueue_by_serial: BTreeMap<u32, QueuedMessage>,
    pub queue_limit: usize,
}

impl NetlinkSocketState {
    pub fn new(queue_limit: usize) -> Self {
        Self {
            queue_limit,
            ..Self::default()
        }
    }

    pub fn broadcast_group_ref(&mut self, group: u32) -> u32 {
        let next = self.broadcast_group_refs.get(&group).copied().unwrap_or(0) + 1;
        self.broadcast_group_refs.insert(group, next);
        next
    }

    pub fn broadcast_group_unref(&mut self, group: u32) -> u32 {
        let next = self
            .broadcast_group_refs
            .get(&group)
            .copied()
            .unwrap_or(0)
            .saturating_sub(1);
        self.broadcast_group_refs.insert(group, next);
        next
    }

    pub fn queue_received_message(&mut self, message: QueuedMessage) -> Result<bool> {
        if message.serial != 0 && self.ignored_serials.remove(&message.serial) {
            return Ok(false);
        }
        if self.rqueue.len() >= self.queue_limit {
            return Err(SocketError::QueueFull);
        }
        self.rqueue.push_back(message.clone());
        if !message.broadcast && message.serial != 0 {
            self.rqueue_by_serial.insert(message.serial, message);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refcount_increments_by_group() {
        let mut state = NetlinkSocketState::new(4);
        assert_eq!(state.broadcast_group_ref(8), 1);
        assert_eq!(state.broadcast_group_ref(8), 2);
    }

    #[test]
    fn refcount_unref_saturates_at_zero() {
        let mut state = NetlinkSocketState::new(4);
        assert_eq!(state.broadcast_group_unref(9), 0);
    }

    #[test]
    fn ignored_serials_are_dropped() {
        let mut state = NetlinkSocketState::new(4);
        state.ignored_serials.insert(17);
        let queued = state
            .queue_received_message(QueuedMessage {
                serial: 17,
                broadcast: false,
                errno: 0,
            })
            .unwrap();
        assert!(!queued);
    }

    #[test]
    fn queue_tracks_non_broadcast_serials() {
        let mut state = NetlinkSocketState::new(4);
        state
            .queue_received_message(QueuedMessage {
                serial: 3,
                broadcast: false,
                errno: 0,
            })
            .unwrap();
        assert!(state.rqueue_by_serial.contains_key(&3));
    }
}
