// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/sd-netlink.c

use std::collections::{BTreeMap, VecDeque};

pub type Result<T> = std::result::Result<T, NetlinkError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetlinkError {
    InvalidInput(&'static str),
    Busy,
    Closed,
    Timeout,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Reply,
    Broadcast,
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetlinkMessage {
    pub kind: MessageKind,
    pub payload: Vec<u8>,
    pub serial: Option<u32>,
    pub reply_to: Option<u32>,
    pub sealed: bool,
}

impl NetlinkMessage {
    pub fn new(kind: MessageKind, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            payload: payload.into(),
            serial: None,
            reply_to: None,
            sealed: false,
        }
    }

    pub fn is_broadcast(&self) -> bool {
        self.kind == MessageKind::Broadcast
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyCallback {
    pub serial: u32,
    pub timeout_usec: u64,
}

#[derive(Debug, Clone)]
pub struct Netlink {
    fd: i32,
    protocol: i32,
    receive_buffer_size: usize,
    open: bool,
    processing: bool,
    next_serial: u32,
    now_usec: u64,
    rqueue: VecDeque<NetlinkMessage>,
    reply_callbacks: BTreeMap<u32, ReplyCallback>,
}

impl Netlink {
    pub fn new(fd: i32, protocol: i32, _groups: u32) -> Result<Self> {
        if fd < 0 {
            return Err(NetlinkError::InvalidInput("fd"));
        }

        Ok(Self {
            fd,
            protocol,
            receive_buffer_size: 0,
            open: true,
            processing: false,
            next_serial: 1,
            now_usec: 0,
            rqueue: VecDeque::new(),
            reply_callbacks: BTreeMap::new(),
        })
    }

    pub fn queue_received(&mut self, message: NetlinkMessage) {
        self.rqueue.push_back(message);
    }

    pub fn send(&mut self, message: &mut NetlinkMessage) -> Result<u32> {
        if !self.open {
            return Err(NetlinkError::Closed);
        }
        if message.sealed {
            return Err(NetlinkError::Busy);
        }

        let serial = self.next_serial;
        self.next_serial = self.next_serial.saturating_add(1);
        message.serial = Some(serial);
        message.sealed = true;
        Ok(serial)
    }

    pub fn register_reply_callback(&mut self, serial: u32, timeout_usec: u64) {
        self.reply_callbacks.insert(
            serial,
            ReplyCallback {
                serial,
                timeout_usec,
            },
        );
    }

    pub fn process(&mut self) -> Result<Option<NetlinkMessage>> {
        if !self.open {
            return Err(NetlinkError::Closed);
        }
        if self.processing {
            return Err(NetlinkError::Busy);
        }

        self.processing = true;
        let result = self.process_inner();
        self.processing = false;
        result
    }

    fn process_inner(&mut self) -> Result<Option<NetlinkMessage>> {
        if let Some(serial) = self.next_timed_out_serial() {
            self.reply_callbacks.remove(&serial);
            return Err(NetlinkError::Timeout);
        }

        if let Some(message) = self.rqueue.pop_front() {
            if let Some(reply_to) = message.reply_to {
                self.reply_callbacks.remove(&reply_to);
            }
            return Ok(Some(message));
        }

        Ok(None)
    }

    fn next_timed_out_serial(&self) -> Option<u32> {
        self.reply_callbacks
            .values()
            .filter(|callback| {
                callback.timeout_usec != u64::MAX && callback.timeout_usec <= self.now_usec
            })
            .map(|callback| callback.serial)
            .min()
    }

    pub fn wait(&self, timeout_usec: u64) -> Result<bool> {
        if !self.open {
            return Err(NetlinkError::Closed);
        }
        if !self.rqueue.is_empty() {
            return Ok(true);
        }
        Ok(timeout_usec > 0 && self.get_timeout()?.is_some())
    }

    pub fn call(
        &mut self,
        message: &mut NetlinkMessage,
        timeout_usec: u64,
    ) -> Result<Option<NetlinkMessage>> {
        let serial = self.send(message)?;
        self.register_reply_callback(serial, self.now_usec.saturating_add(timeout_usec));
        self.read(serial, timeout_usec)
    }

    pub fn read(&mut self, serial: u32, timeout_usec: u64) -> Result<Option<NetlinkMessage>> {
        let deadline = if timeout_usec == u64::MAX {
            u64::MAX
        } else {
            self.now_usec.saturating_add(timeout_usec)
        };

        loop {
            if let Some(index) = self.rqueue.iter().position(|message| {
                message.reply_to == Some(serial) || message.serial == Some(serial)
            }) {
                let message = self.rqueue.remove(index).expect("message exists");
                self.reply_callbacks.remove(&serial);
                if message.kind == MessageKind::Done {
                    return Ok(None);
                }
                return Ok(Some(message));
            }

            if deadline != u64::MAX && self.now_usec >= deadline {
                return Err(NetlinkError::Timeout);
            }

            if self.rqueue.is_empty() {
                return Err(NetlinkError::NotFound);
            }
        }
    }

    pub fn receive(&mut self) -> Result<Option<NetlinkMessage>> {
        if !self.open {
            return Err(NetlinkError::Closed);
        }
        Ok(self.rqueue.pop_front())
    }

    pub fn flush(&mut self) -> Result<bool> {
        if !self.open {
            return Err(NetlinkError::Closed);
        }
        let had_messages = !self.rqueue.is_empty();
        self.rqueue.clear();
        Ok(had_messages)
    }

    pub fn close(&mut self) -> Result<bool> {
        let changed = self.open;
        self.open = false;
        self.rqueue.clear();
        self.reply_callbacks.clear();
        Ok(changed)
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn is_busy(&self) -> bool {
        self.processing || !self.reply_callbacks.is_empty()
    }

    pub fn get_fd(&self) -> Result<i32> {
        if !self.open {
            return Err(NetlinkError::Closed);
        }
        Ok(self.fd)
    }

    pub fn get_events(&self) -> Result<i16> {
        if !self.open {
            return Err(NetlinkError::Closed);
        }
        Ok(if self.rqueue.is_empty() {
            libc::POLLIN
        } else {
            0
        })
    }

    pub fn get_timeout(&self) -> Result<Option<u64>> {
        if !self.open {
            return Err(NetlinkError::Closed);
        }
        if !self.rqueue.is_empty() {
            return Ok(Some(0));
        }
        Ok(self
            .reply_callbacks
            .values()
            .map(|callback| callback.timeout_usec)
            .min())
    }

    pub fn get_protocol(&self) -> i32 {
        self.protocol
    }

    pub fn set_protocol(&mut self, protocol: i32) -> Result<()> {
        if !self.open {
            return Err(NetlinkError::Closed);
        }
        self.protocol = protocol;
        Ok(())
    }

    pub fn set_receive_buffer_size(&mut self, size: usize) -> Result<()> {
        if !self.open {
            return Err(NetlinkError::Closed);
        }
        self.receive_buffer_size = size;
        Ok(())
    }

    pub fn receive_buffer_size(&self) -> usize {
        self.receive_buffer_size
    }

    pub fn set_now_usec(&mut self, now_usec: u64) {
        self.now_usec = now_usec;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_seals_and_numbers_messages() {
        let mut netlink = Netlink::new(5, 16, 0).unwrap();
        let mut message = NetlinkMessage::new(MessageKind::Request, b"hello".to_vec());
        let serial = netlink.send(&mut message).unwrap();
        assert_eq!(serial, 1);
        assert_eq!(message.serial, Some(1));
        assert!(message.sealed);
    }

    #[test]
    fn process_returns_queued_message() {
        let mut netlink = Netlink::new(5, 16, 0).unwrap();
        netlink.queue_received(NetlinkMessage::new(MessageKind::Broadcast, b"msg".to_vec()));
        assert_eq!(
            netlink.process().unwrap().unwrap().kind,
            MessageKind::Broadcast
        );
    }

    #[test]
    fn timeout_is_reported_before_queue_dispatch() {
        let mut netlink = Netlink::new(5, 16, 0).unwrap();
        netlink.register_reply_callback(11, 10);
        netlink.set_now_usec(10);
        assert_eq!(netlink.process(), Err(NetlinkError::Timeout));
    }

    #[test]
    fn read_matches_reply_serial() {
        let mut netlink = Netlink::new(5, 16, 0).unwrap();
        let mut reply = NetlinkMessage::new(MessageKind::Reply, b"ok".to_vec());
        reply.reply_to = Some(9);
        netlink.queue_received(reply.clone());
        assert_eq!(netlink.read(9, 100).unwrap(), Some(reply));
    }

    #[test]
    fn read_done_message_maps_to_none() {
        let mut netlink = Netlink::new(5, 16, 0).unwrap();
        let mut done = NetlinkMessage::new(MessageKind::Done, Vec::new());
        done.reply_to = Some(3);
        netlink.queue_received(done);
        assert_eq!(netlink.read(3, 0).unwrap(), None);
    }

    #[test]
    fn get_timeout_prefers_immediate_queue_work() {
        let mut netlink = Netlink::new(5, 16, 0).unwrap();
        netlink.register_reply_callback(1, 99);
        netlink.queue_received(NetlinkMessage::new(MessageKind::Broadcast, b"x".to_vec()));
        assert_eq!(netlink.get_timeout().unwrap(), Some(0));
    }

    #[test]
    fn flush_clears_receive_queue() {
        let mut netlink = Netlink::new(5, 16, 0).unwrap();
        netlink.queue_received(NetlinkMessage::new(MessageKind::Broadcast, b"x".to_vec()));
        assert!(netlink.flush().unwrap());
        assert_eq!(netlink.receive().unwrap(), None);
    }

    #[test]
    fn close_marks_connection_closed() {
        let mut netlink = Netlink::new(5, 16, 0).unwrap();
        assert!(netlink.close().unwrap());
        assert!(!netlink.is_open());
        assert_eq!(netlink.get_fd(), Err(NetlinkError::Closed));
    }

    #[test]
    fn set_protocol_and_receive_buffer_size() {
        let mut netlink = Netlink::new(5, 16, 0).unwrap();
        netlink.set_protocol(24).unwrap();
        netlink.set_receive_buffer_size(8192).unwrap();
        assert_eq!(netlink.get_protocol(), 24);
        assert_eq!(netlink.receive_buffer_size(), 8192);
    }
}
