// SPDX-License-Identifier: GPL-2.0-or-later
// PORT-SYNC: src/udev/udev-manager.c

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use crate::udev_db_monitor::create_kobject_uevent_multicast_socket;
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UeventAction {
    Add,
    Remove,
    Change,
    Move,
    Online,
    Offline,
    Bind,
    Unbind,
    Unknown(String),
}

impl UeventAction {
    fn parse(s: &str) -> Self {
        match s {
            "add" => UeventAction::Add,
            "remove" => UeventAction::Remove,
            "change" => UeventAction::Change,
            "move" => UeventAction::Move,
            "online" => UeventAction::Online,
            "offline" => UeventAction::Offline,
            "bind" => UeventAction::Bind,
            "unbind" => UeventAction::Unbind,
            other => UeventAction::Unknown(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeventMessage {
    pub action: UeventAction,
    pub devpath: String,
    pub subsystem: Option<String>,
    pub devname: Option<String>,
    pub devtype: Option<String>,
    pub major: Option<u32>,
    pub minor: Option<u32>,
    pub seqnum: Option<u64>,
    pub properties: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UeventParseError {
    Empty,
    MissingAction,
    MissingDevpath,
    InvalidUtf8,
}

#[derive(Debug)]
pub struct OrderedUeventQueue {
    pending_by_seqnum: BTreeMap<u64, UeventMessage>,
    pending_without_seqnum: VecDeque<UeventMessage>,
    last_emitted_seqnum: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueInsertResult {
    Inserted,
    Duplicate,
}

impl OrderedUeventQueue {
    pub fn new() -> Self {
        Self {
            pending_by_seqnum: BTreeMap::new(),
            pending_without_seqnum: VecDeque::new(),
            last_emitted_seqnum: None,
        }
    }

    pub fn push(&mut self, event: UeventMessage) -> QueueInsertResult {
        if let Some(seqnum) = event.seqnum {
            if self
                .last_emitted_seqnum
                .is_some_and(|last_emitted| seqnum <= last_emitted)
            {
                return QueueInsertResult::Duplicate;
            }

            if self.pending_by_seqnum.contains_key(&seqnum) {
                return QueueInsertResult::Duplicate;
            }
            self.pending_by_seqnum.insert(seqnum, event);
            QueueInsertResult::Inserted
        } else {
            self.pending_without_seqnum.push_back(event);
            QueueInsertResult::Inserted
        }
    }

    pub fn pop_next(&mut self) -> Option<UeventMessage> {
        if let Some(next_seqnum) = self.pending_by_seqnum.first_key_value().map(|(k, _)| *k) {
            let event = self.pending_by_seqnum.remove(&next_seqnum)?;
            self.last_emitted_seqnum = Some(next_seqnum);
            return Some(event);
        }
        self.pending_without_seqnum.pop_front()
    }

    pub fn is_empty(&self) -> bool {
        self.pending_by_seqnum.is_empty() && self.pending_without_seqnum.is_empty()
    }
}

impl Default for OrderedUeventQueue {
    fn default() -> Self {
        Self::new()
    }
}

pub struct KobjectUeventReceiver {
    socket: AsyncFd<OwnedFd>,
    queue: OrderedUeventQueue,
    recv_buf: Vec<u8>,
}

impl KobjectUeventReceiver {
    pub fn new(multicast_groups: u32) -> io::Result<Self> {
        let fd = create_kobject_uevent_multicast_socket(multicast_groups)?;
        Self::from_fd(fd)
    }

    pub fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self {
            socket: AsyncFd::new(fd)?,
            queue: OrderedUeventQueue::new(),
            recv_buf: vec![0u8; 128 * 1024],
        })
    }

    pub fn queue(&self) -> &OrderedUeventQueue {
        &self.queue
    }

    pub fn queue_mut(&mut self) -> &mut OrderedUeventQueue {
        &mut self.queue
    }

    pub fn enqueue_datagram(&mut self, payload: &[u8]) -> Result<(), UeventParseError> {
        let event = parse_uevent_datagram(payload)?;
        let _ = self.queue.push(event);
        Ok(())
    }

    pub async fn next_event(&mut self) -> io::Result<UeventMessage> {
        loop {
            if let Some(event) = self.queue.pop_next() {
                return Ok(event);
            }

            let mut guard = self.socket.readable().await?;
            let recv_result =
                guard.try_io(|inner| recv_datagram(inner.get_ref(), &mut self.recv_buf));

            match recv_result {
                Ok(Ok(n)) => {
                    if n == 0 {
                        continue;
                    }

                    if let Ok(event) = parse_uevent_datagram(&self.recv_buf[..n]) {
                        let _ = self.queue.push(event);
                    }
                }
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn run(mut self, tx: mpsc::Sender<UeventMessage>) -> io::Result<()> {
        loop {
            let event = self.next_event().await?;
            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }
    }
}

fn recv_datagram(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: fd is valid and buffer is a valid mutable byte span.
    let n = unsafe_ffi!({
        libc::recv(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
            0,
        )
    });

    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(n as usize)
}

pub fn parse_uevent_datagram(payload: &[u8]) -> Result<UeventMessage, UeventParseError> {
    if payload.is_empty() {
        return Err(UeventParseError::Empty);
    }

    let mut parts = payload
        .split(|b| *b == 0)
        .filter(|slice| !slice.is_empty())
        .map(bytes_to_string)
        .collect::<Result<Vec<_>, _>>()?;

    if parts.is_empty() {
        return Err(UeventParseError::Empty);
    }

    let mut action_from_header = None;
    let mut devpath_from_header = None;
    if !parts[0].contains('=') {
        let header = parts.remove(0);
        if let Some((act, path)) = header.split_once('@') {
            action_from_header = Some(UeventAction::parse(act));
            if !path.is_empty() {
                devpath_from_header = Some(path.to_string());
            }
        }
    }

    let mut properties = BTreeMap::new();
    for part in parts {
        if let Some((k, v)) = part.split_once('=') {
            properties.insert(k.to_string(), v.to_string());
        }
    }

    let action = properties
        .get("ACTION")
        .map(|v| UeventAction::parse(v))
        .or(action_from_header)
        .ok_or(UeventParseError::MissingAction)?;

    let devpath = properties
        .get("DEVPATH")
        .cloned()
        .or(devpath_from_header)
        .ok_or(UeventParseError::MissingDevpath)?;

    let major = properties.get("MAJOR").and_then(|v| v.parse::<u32>().ok());
    let minor = properties.get("MINOR").and_then(|v| v.parse::<u32>().ok());
    let seqnum = properties.get("SEQNUM").and_then(|v| v.parse::<u64>().ok());

    Ok(UeventMessage {
        action,
        devpath,
        subsystem: properties.get("SUBSYSTEM").cloned(),
        devname: properties.get("DEVNAME").cloned(),
        devtype: properties.get("DEVTYPE").cloned(),
        major,
        minor,
        seqnum,
        properties,
    })
}

fn bytes_to_string(bytes: &[u8]) -> Result<String, UeventParseError> {
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|_| UeventParseError::InvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, IntoRawFd};
    use std::os::unix::net::UnixDatagram;

    fn uevent_bytes(seq: u64, action: &str, devpath: &str) -> Vec<u8> {
        format!(
            "{action}@{devpath}\0ACTION={action}\0DEVPATH={devpath}\0SUBSYSTEM=block\0DEVNAME=sda\0DEVTYPE=disk\0MAJOR=8\0MINOR=0\0SEQNUM={seq}\0"
        )
        .into_bytes()
    }

    #[test]
    fn parses_kernel_uevent_properties() {
        let payload = uevent_bytes(42, "add", "/devices/mock0");
        let event = parse_uevent_datagram(&payload).unwrap();

        assert_eq!(event.action, UeventAction::Add);
        assert_eq!(event.devpath, "/devices/mock0");
        assert_eq!(event.subsystem.as_deref(), Some("block"));
        assert_eq!(event.devname.as_deref(), Some("sda"));
        assert_eq!(event.devtype.as_deref(), Some("disk"));
        assert_eq!(event.major, Some(8));
        assert_eq!(event.minor, Some(0));
        assert_eq!(event.seqnum, Some(42));
    }

    #[test]
    fn parser_uses_header_fallback_when_action_or_devpath_missing() {
        let payload = b"remove@/devices/fallback\0SUBSYSTEM=block\0SEQNUM=7\0";
        let event = parse_uevent_datagram(payload).unwrap();
        assert_eq!(event.action, UeventAction::Remove);
        assert_eq!(event.devpath, "/devices/fallback");
        assert_eq!(event.seqnum, Some(7));
    }

    #[test]
    fn parser_rejects_missing_mandatory_fields() {
        let err = parse_uevent_datagram(b"\0ACTION=add\0").unwrap_err();
        assert_eq!(err, UeventParseError::MissingDevpath);

        let err = parse_uevent_datagram(b"\0DEVPATH=/devices/x\0").unwrap_err();
        assert_eq!(err, UeventParseError::MissingAction);
    }

    #[test]
    fn queue_pops_events_in_seqnum_order() {
        let mut queue = OrderedUeventQueue::new();

        let mut a = parse_uevent_datagram(&uevent_bytes(300, "add", "/devices/a")).unwrap();
        let b = parse_uevent_datagram(&uevent_bytes(100, "add", "/devices/b")).unwrap();
        let c = parse_uevent_datagram(&uevent_bytes(200, "add", "/devices/c")).unwrap();

        a.seqnum = Some(300);
        assert_eq!(queue.push(a), QueueInsertResult::Inserted);
        assert_eq!(queue.push(b), QueueInsertResult::Inserted);
        assert_eq!(queue.push(c), QueueInsertResult::Inserted);

        assert_eq!(queue.pop_next().unwrap().seqnum, Some(100));
        assert_eq!(queue.pop_next().unwrap().seqnum, Some(200));
        assert_eq!(queue.pop_next().unwrap().seqnum, Some(300));
        assert!(queue.is_empty());
    }

    #[test]
    fn queue_handles_events_without_seqnum() {
        let mut queue = OrderedUeventQueue::new();

        let mut no_seq =
            parse_uevent_datagram(&uevent_bytes(1, "change", "/devices/no-seq")).unwrap();
        no_seq.seqnum = None;

        assert_eq!(queue.push(no_seq.clone()), QueueInsertResult::Inserted);
        assert_eq!(queue.pop_next(), Some(no_seq));
    }

    #[test]
    fn queue_rejects_duplicate_seqnum() {
        let mut queue = OrderedUeventQueue::new();
        let first = parse_uevent_datagram(&uevent_bytes(12, "add", "/devices/first")).unwrap();
        let second = parse_uevent_datagram(&uevent_bytes(12, "change", "/devices/second")).unwrap();

        assert_eq!(queue.push(first.clone()), QueueInsertResult::Inserted);
        assert_eq!(queue.push(second), QueueInsertResult::Duplicate);
        assert_eq!(queue.pop_next(), Some(first));
    }

    #[test]
    fn queue_rejects_stale_seqnum_after_emission() {
        let mut queue = OrderedUeventQueue::new();
        let first = parse_uevent_datagram(&uevent_bytes(20, "add", "/devices/first")).unwrap();
        let stale = parse_uevent_datagram(&uevent_bytes(19, "change", "/devices/stale")).unwrap();

        assert_eq!(queue.push(first.clone()), QueueInsertResult::Inserted);
        assert_eq!(queue.pop_next(), Some(first));
        assert_eq!(queue.push(stale), QueueInsertResult::Duplicate);
    }

    #[tokio::test]
    async fn tokio_receiver_reads_and_parses_datagram() {
        let (left, right) = UnixDatagram::pair().unwrap();
        left.set_nonblocking(true).unwrap();
        right.set_nonblocking(true).unwrap();

        // SAFETY: ownership is transferred from the UnixDatagram into OwnedFd.
        let owned = unsafe_ffi!(OwnedFd::from_raw_fd(left.into_raw_fd()));
        let mut receiver = KobjectUeventReceiver::from_fd(owned).unwrap();

        let payload = uevent_bytes(11, "online", "/devices/tokio");
        right.send(&payload).unwrap();

        let event = receiver.next_event().await.unwrap();
        assert_eq!(event.seqnum, Some(11));
        assert_eq!(event.action, UeventAction::Online);
        assert_eq!(event.devpath, "/devices/tokio");
    }
}
