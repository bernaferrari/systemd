// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-varlink/sd-varlink.c

use std::collections::{BTreeMap, VecDeque};

pub type Result<T> = std::result::Result<T, VarlinkError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarlinkError {
    InvalidInput(&'static str),
    NotConnected,
    Busy,
    BadFd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    String(String),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    pub fn object(entries: impl IntoIterator<Item = (impl Into<String>, JsonValue)>) -> Self {
        Self::Object(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    fn by_key(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(map) => map.get(key),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarlinkState {
    IdleClient,
    IdleServer,
    AwaitingReply,
    AwaitingReplyMore,
    PendingMethod,
    PendingDisconnect,
    Disconnected,
}

impl VarlinkState {
    fn is_alive(self) -> bool {
        self != VarlinkState::Disconnected
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarlinkReply {
    pub status: i32,
    pub payload: Option<JsonValue>,
}

pub type MethodHandler = fn(&JsonValue) -> Result<JsonValue>;
pub type ReplyCallback = fn(&VarlinkReply);
pub type ConnectCallback = fn(&str);
pub type DisconnectCallback = fn();

#[derive(Debug, Clone)]
pub struct Varlink {
    state: VarlinkState,
    input_fd: Option<i32>,
    output_fd: Option<i32>,
    connecting: bool,
    read_disconnected: bool,
    write_disconnected: bool,
    output_queue: VecDeque<JsonValue>,
    current: Option<JsonValue>,
    timeout_usec: Option<u64>,
    timestamp_usec: u64,
    userdata: usize,
    reply_callback: Option<ReplyCallback>,
    methods: BTreeMap<String, MethodHandler>,
    connect_callback: Option<ConnectCallback>,
    disconnect_callback: Option<DisconnectCallback>,
    peer_pidfd: Option<i32>,
    peer_gid: Option<libc::gid_t>,
}

impl Varlink {
    pub fn new(fd: i32, server: bool) -> Result<Self> {
        if fd < 0 {
            return Err(VarlinkError::BadFd);
        }
        Ok(Self {
            state: if server {
                VarlinkState::IdleServer
            } else {
                VarlinkState::IdleClient
            },
            input_fd: Some(fd),
            output_fd: Some(fd),
            connecting: false,
            read_disconnected: false,
            write_disconnected: false,
            output_queue: VecDeque::new(),
            current: None,
            timeout_usec: None,
            timestamp_usec: 0,
            userdata: 0,
            reply_callback: None,
            methods: BTreeMap::new(),
            connect_callback: None,
            disconnect_callback: None,
            peer_pidfd: None,
            peer_gid: None,
        })
    }

    pub fn state(&self) -> VarlinkState {
        self.state
    }

    pub fn set_now_usec(&mut self, now_usec: u64) {
        self.timestamp_usec = now_usec;
    }

    pub fn process(&mut self) -> Result<i32> {
        if self.state == VarlinkState::Disconnected {
            return Err(VarlinkError::NotConnected);
        }

        if let Some(message) = self.output_queue.pop_front() {
            self.current = Some(message.clone());
            if let Some(method) = self.get_current_method()?
                && let Some(handler) = self.methods.get(method)
            {
                let parameters = self
                    .get_current_parameters()?
                    .unwrap_or(JsonValue::Object(BTreeMap::new()));
                let reply = handler(&parameters)?;
                if let Some(callback) = self.reply_callback {
                    callback(&VarlinkReply {
                        status: 0,
                        payload: Some(reply),
                    });
                }
                self.state = VarlinkState::IdleServer;
                return Ok(1);
            }
            return Ok(1);
        }

        if let Some(timeout) = self.timeout_usec
            && self.timestamp_usec >= timeout
        {
            self.state = VarlinkState::PendingDisconnect;
            return Ok(1);
        }

        Ok(0)
    }

    pub fn wait(&self, timeout_usec: u64) -> Result<bool> {
        if self.state == VarlinkState::Disconnected {
            return Err(VarlinkError::NotConnected);
        }
        if !self.output_queue.is_empty() {
            return Ok(true);
        }
        Ok(timeout_usec > 0 && self.get_timeout()?.is_some())
    }

    pub fn get_fd(&self) -> Result<i32> {
        if self.state == VarlinkState::Disconnected {
            return Err(VarlinkError::NotConnected);
        }
        match (self.input_fd, self.output_fd) {
            (Some(input), Some(output)) if input == output => Ok(input),
            _ => Err(VarlinkError::BadFd),
        }
    }

    pub fn get_send_fd(&self) -> Result<i32> {
        self.output_fd.ok_or(VarlinkError::BadFd)
    }

    pub fn get_recv_fd(&self) -> Result<i32> {
        self.input_fd.ok_or(VarlinkError::BadFd)
    }

    pub fn get_events(&self) -> Result<i16> {
        if self.state == VarlinkState::Disconnected {
            return Err(VarlinkError::NotConnected);
        }
        if self.connecting {
            return Ok(libc::POLLOUT);
        }

        let mut events = 0;
        if !self.read_disconnected
            && matches!(
                self.state,
                VarlinkState::AwaitingReply
                    | VarlinkState::AwaitingReplyMore
                    | VarlinkState::IdleServer
            )
        {
            events |= libc::POLLIN;
        }
        if !self.write_disconnected && !self.output_queue.is_empty() {
            events |= libc::POLLOUT;
        }
        Ok(events)
    }

    pub fn get_timeout(&self) -> Result<Option<u64>> {
        if self.state == VarlinkState::Disconnected {
            return Err(VarlinkError::NotConnected);
        }
        Ok(match self.state {
            VarlinkState::AwaitingReply | VarlinkState::AwaitingReplyMore => self.timeout_usec,
            _ => None,
        })
    }

    pub fn close(&mut self) -> Result<bool> {
        if self.state == VarlinkState::Disconnected {
            return Ok(false);
        }
        self.state = VarlinkState::Disconnected;
        self.output_queue.clear();
        self.current = None;
        if let Some(callback) = self.disconnect_callback {
            callback();
        }
        Ok(true)
    }

    pub fn set_userdata(&mut self, userdata: usize) -> usize {
        let old = self.userdata;
        self.userdata = userdata;
        old
    }

    pub fn get_userdata(&self) -> usize {
        self.userdata
    }

    pub fn attach_event(&mut self, _priority: i64) -> Result<()> {
        if !self.state.is_alive() {
            return Err(VarlinkError::NotConnected);
        }
        Ok(())
    }

    pub fn detach_event(&mut self) -> Result<()> {
        if !self.state.is_alive() {
            return Err(VarlinkError::NotConnected);
        }
        Ok(())
    }

    pub fn send(&mut self, method: impl Into<String>, parameters: Option<JsonValue>) -> Result<()> {
        if self.state == VarlinkState::Disconnected {
            return Err(VarlinkError::NotConnected);
        }
        if !matches!(
            self.state,
            VarlinkState::IdleClient | VarlinkState::AwaitingReply
        ) {
            return Err(VarlinkError::Busy);
        }
        let message = JsonValue::object([
            ("method", JsonValue::string(method.into())),
            (
                "parameters",
                parameters.unwrap_or(JsonValue::Object(BTreeMap::new())),
            ),
            ("oneway", JsonValue::Bool(true)),
        ]);
        self.output_queue.push_back(message);
        Ok(())
    }

    pub fn send_reply(&mut self, parameters: Option<JsonValue>) -> Result<()> {
        if self.state == VarlinkState::Disconnected {
            return Err(VarlinkError::NotConnected);
        }
        self.output_queue.push_back(JsonValue::object([(
            "parameters",
            parameters.unwrap_or(JsonValue::Object(BTreeMap::new())),
        )]));
        Ok(())
    }

    pub fn send_error(
        &mut self,
        error: impl Into<String>,
        parameters: Option<JsonValue>,
    ) -> Result<()> {
        if self.state == VarlinkState::Disconnected {
            return Err(VarlinkError::NotConnected);
        }
        self.output_queue.push_back(JsonValue::object([
            ("error", JsonValue::string(error.into())),
            (
                "parameters",
                parameters.unwrap_or(JsonValue::Object(BTreeMap::new())),
            ),
        ]));
        Ok(())
    }

    pub fn set_reply_callback(&mut self, callback: ReplyCallback) {
        self.reply_callback = Some(callback);
    }

    pub fn bind_method(
        &mut self,
        method: impl Into<String>,
        callback: MethodHandler,
    ) -> Result<()> {
        let method = method.into();
        if method.is_empty() {
            return Err(VarlinkError::InvalidInput("method"));
        }
        self.methods.insert(method, callback);
        Ok(())
    }

    pub fn bind_connect(&mut self, callback: ConnectCallback) {
        self.connect_callback = Some(callback);
    }

    pub fn bind_disconnect(&mut self, callback: DisconnectCallback) {
        self.disconnect_callback = Some(callback);
    }

    pub fn flush(&mut self) -> Result<bool> {
        if self.state == VarlinkState::Disconnected {
            return Err(VarlinkError::NotConnected);
        }
        let had_output = !self.output_queue.is_empty();
        self.output_queue.clear();
        Ok(had_output)
    }

    pub fn get_peer_gid(&self) -> Result<libc::gid_t> {
        self.peer_gid.ok_or(VarlinkError::InvalidInput("peer gid"))
    }

    pub fn set_peer_gid(&mut self, gid: libc::gid_t) {
        self.peer_gid = Some(gid);
    }

    pub fn get_peer_pidfd(&self) -> Result<i32> {
        self.peer_pidfd.ok_or(VarlinkError::BadFd)
    }

    pub fn set_peer_pidfd(&mut self, pidfd: i32) {
        self.peer_pidfd = Some(pidfd);
    }

    pub fn get_current_parameters(&self) -> Result<Option<JsonValue>> {
        let Some(current) = &self.current else {
            return Ok(None);
        };
        Ok(current.by_key("parameters").cloned())
    }

    pub fn get_current_method(&self) -> Result<Option<&str>> {
        let Some(current) = &self.current else {
            return Ok(None);
        };
        Ok(match current.by_key("method") {
            Some(JsonValue::String(value)) => Some(value.as_str()),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        static CALLBACKS: Cell<usize> = const { Cell::new(0) };
    }

    fn method_handler(parameters: &JsonValue) -> Result<JsonValue> {
        Ok(JsonValue::object([("echo", parameters.clone())]))
    }

    fn reply_callback(_reply: &VarlinkReply) {
        CALLBACKS.with(|c| c.set(c.get() + 1));
    }

    fn disconnect_callback() {
        CALLBACKS.with(|c| c.set(c.get() + 1));
    }

    #[test]
    fn new_connection_starts_connected() {
        let connection = Varlink::new(7, false).unwrap();
        assert_eq!(connection.state(), VarlinkState::IdleClient);
        assert_eq!(connection.get_fd().unwrap(), 7);
    }

    #[test]
    fn send_enqueues_oneway_message() {
        let mut connection = Varlink::new(7, false).unwrap();
        connection.send("io.test.Ping", None).unwrap();
        assert_eq!(connection.output_queue.len(), 1);
    }

    #[test]
    fn bind_and_process_method_dispatch() {
        CALLBACKS.with(|c| c.set(0));
        let mut connection = Varlink::new(7, true).unwrap();
        connection
            .bind_method("io.test.Echo", method_handler)
            .unwrap();
        connection.set_reply_callback(reply_callback);
        connection.output_queue.push_back(JsonValue::object([
            ("method", JsonValue::string("io.test.Echo")),
            (
                "parameters",
                JsonValue::object([("value", JsonValue::string("x"))]),
            ),
        ]));
        assert_eq!(connection.process().unwrap(), 1);
        assert_eq!(CALLBACKS.with(|c| c.get()), 1);
    }

    #[test]
    fn current_method_and_parameters_are_extracted() {
        let mut connection = Varlink::new(7, true).unwrap();
        connection.current = Some(JsonValue::object([
            ("method", JsonValue::string("io.test.Echo")),
            (
                "parameters",
                JsonValue::object([("value", JsonValue::string("x"))]),
            ),
        ]));
        assert_eq!(
            connection.get_current_method().unwrap(),
            Some("io.test.Echo")
        );
        assert!(matches!(
            connection.get_current_parameters().unwrap(),
            Some(JsonValue::Object(_))
        ));
    }

    #[test]
    fn separate_missing_send_fd_is_reported() {
        let mut connection = Varlink::new(7, false).unwrap();
        connection.output_fd = None;
        assert_eq!(connection.get_send_fd(), Err(VarlinkError::BadFd));
    }

    #[test]
    fn timeout_is_available_in_awaiting_reply_state() {
        let mut connection = Varlink::new(7, false).unwrap();
        connection.state = VarlinkState::AwaitingReply;
        connection.timeout_usec = Some(500);
        assert_eq!(connection.get_timeout().unwrap(), Some(500));
    }

    #[test]
    fn userdata_roundtrips() {
        let mut connection = Varlink::new(7, false).unwrap();
        assert_eq!(connection.set_userdata(99), 0);
        assert_eq!(connection.get_userdata(), 99);
    }

    #[test]
    fn flush_clears_output_queue() {
        let mut connection = Varlink::new(7, false).unwrap();
        connection.send("io.test.Ping", None).unwrap();
        assert!(connection.flush().unwrap());
        assert!(connection.output_queue.is_empty());
    }

    #[test]
    fn close_runs_disconnect_callback_once() {
        CALLBACKS.with(|c| c.set(0));
        let mut connection = Varlink::new(7, false).unwrap();
        connection.bind_disconnect(disconnect_callback);
        assert!(connection.close().unwrap());
        assert_eq!(CALLBACKS.with(|c| c.get()), 1);
        assert_eq!(connection.state(), VarlinkState::Disconnected);
    }

    #[test]
    fn peer_accessors_report_values() {
        let mut connection = Varlink::new(7, false).unwrap();
        connection.set_peer_gid(1000);
        connection.set_peer_pidfd(11);
        assert_eq!(connection.get_peer_gid().unwrap(), 1000);
        assert_eq!(connection.get_peer_pidfd().unwrap(), 11);
    }
}
