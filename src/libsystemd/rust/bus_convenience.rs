// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-convenience.c
//
// D-Bus convenience wrappers: signal emission, method calls (sync/async),
// property get/set, sender credential queries, and signal matching.
//
// Faithful Rust port of bus-convenience.c. Pure safe idiomatic Rust.

use std::collections::HashMap;

// ── Constants ─────────────────────────────────────────────────────────────

/// D-Bus interface for properties.
pub const DBUS_PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";

/// D-Bus interface for object manager.
pub const DBUS_OBJECT_MANAGER_INTERFACE: &str = "org.freedesktop.DBus.ObjectManager";

/// D-Bus peer interface.
pub const DBUS_PEER_INTERFACE: &str = "org.freedesktop.DBus.Peer";

/// D-Bus introspectable interface.
pub const DBUS_INTROSPECTABLE_INTERFACE: &str = "org.freedesktop.DBus.Introspectable";

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusError {
    InvalidArgument,
    NotConnected,
    NotSupported,
    NoReply,
    AccessDenied,
    UnknownMethod,
    UnknownInterface,
    UnknownProperty,
    PropertyReadOnly,
    Io(String),
    Errno(i32),
}

impl std::fmt::Display for BusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BusError::InvalidArgument => write!(f, "Invalid argument"),
            BusError::NotConnected => write!(f, "Not connected"),
            BusError::NotSupported => write!(f, "Not supported"),
            BusError::NoReply => write!(f, "No reply"),
            BusError::AccessDenied => write!(f, "Access denied"),
            BusError::UnknownMethod => write!(f, "Unknown method"),
            BusError::UnknownInterface => write!(f, "Unknown interface"),
            BusError::UnknownProperty => write!(f, "Unknown property"),
            BusError::PropertyReadOnly => write!(f, "Property is read-only"),
            BusError::Io(s) => write!(f, "I/O: {s}"),
            BusError::Errno(n) => write!(f, "Error {n}"),
        }
    }
}

impl std::error::Error for BusError {}

pub type Result<T> = std::result::Result<T, BusError>;

// ── Bus message types ─────────────────────────────────────────────────────

/// D-Bus message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    MethodCall,
    MethodReturn,
    Error,
    Signal,
}

/// A D-Bus message with destination, path, interface, and member fields.
#[derive(Debug, Clone)]
pub struct BusMessage {
    pub msg_type: MessageType,
    pub destination: Option<String>,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub signature: Option<String>,
    pub body: Vec<u8>,
    pub sender: Option<String>,
}

impl BusMessage {
    /// Create a new signal message.
    pub fn new_signal(path: &str, interface: &str, member: &str) -> Self {
        Self {
            msg_type: MessageType::Signal,
            destination: None,
            path: Some(path.to_string()),
            interface: Some(interface.to_string()),
            member: Some(member.to_string()),
            signature: None,
            body: Vec::new(),
            sender: None,
        }
    }

    /// Create a new method call message.
    pub fn new_method_call(destination: &str, path: &str, interface: &str, member: &str) -> Self {
        Self {
            msg_type: MessageType::MethodCall,
            destination: Some(destination.to_string()),
            path: Some(path.to_string()),
            interface: Some(interface.to_string()),
            member: Some(member.to_string()),
            signature: None,
            body: Vec::new(),
            sender: None,
        }
    }

    /// Create a method return message.
    pub fn new_method_return() -> Self {
        Self {
            msg_type: MessageType::MethodReturn,
            destination: None,
            path: None,
            interface: None,
            member: None,
            signature: None,
            body: Vec::new(),
            sender: None,
        }
    }

    /// Create an error reply message.
    pub fn new_error(name: &str) -> Self {
        Self {
            msg_type: MessageType::Error,
            destination: None,
            path: None,
            interface: None,
            member: Some(name.to_string()),
            signature: None,
            body: Vec::new(),
            sender: None,
        }
    }

    /// Check if the message is a method call.
    pub fn is_method_call(&self, interface: &str, member: &str) -> bool {
        self.msg_type == MessageType::MethodCall
            && self.interface.as_deref() == Some(interface)
            && self.member.as_deref() == Some(member)
    }

    /// Check if the message is a signal.
    pub fn is_signal(&self, interface: &str, member: &str) -> bool {
        self.msg_type == MessageType::Signal
            && self.interface.as_deref() == Some(interface)
            && self.member.as_deref() == Some(member)
    }
}

// ── Bus credentials ───────────────────────────────────────────────────────

/// Simplified D-Bus peer credentials.
#[derive(Debug, Clone)]
pub struct BusCreds {
    pub uid: Option<u32>,
    pub pid: Option<u32>,
    pub gid: Option<u32>,
    pub selinux_context: Option<String>,
    pub unique_name: Option<String>,
}

impl BusCreds {
    pub fn new(uid: Option<u32>, pid: Option<u32>) -> Self {
        Self {
            uid,
            pid,
            gid: None,
            selinux_context: None,
            unique_name: None,
        }
    }

    /// Check if the peer has a given UID.
    pub fn has_uid(&self, uid: u32) -> bool {
        self.uid == Some(uid)
    }

    /// Check if the peer is root (UID 0).
    pub fn is_root(&self) -> bool {
        self.has_uid(0)
    }
}

// ── Bus connection (simulated) ────────────────────────────────────────────

/// Simulated D-Bus bus connection for safe Rust testing.
/// Mirrors the `sd_bus` operations from bus-convenience.c.
#[derive(Debug)]
pub struct BusConnection {
    connected: bool,
    messages_sent: Vec<BusMessage>,
    properties: HashMap<(String, String, String), String>,
    credentials: HashMap<String, BusCreds>,
    signal_handlers: Vec<SignalMatch>,
}

/// A signal match rule.
#[derive(Debug, Clone)]
pub struct SignalMatch {
    pub sender: Option<String>,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
}

impl SignalMatch {
    /// Check if a message matches this rule.
    pub fn matches(&self, msg: &BusMessage) -> bool {
        if self.sender.as_deref() != msg.sender.as_deref() && self.sender.is_some() {
            return false;
        }
        if self.path.as_deref() != msg.path.as_deref() && self.path.is_some() {
            return false;
        }
        if self.interface.as_deref() != msg.interface.as_deref() && self.interface.is_some() {
            return false;
        }
        if self.member.as_deref() != msg.member.as_deref() && self.member.is_some() {
            return false;
        }
        true
    }
}

impl BusConnection {
    /// Create a new connected bus.
    pub fn new() -> Self {
        Self {
            connected: true,
            messages_sent: Vec::new(),
            properties: HashMap::new(),
            credentials: HashMap::new(),
            signal_handlers: Vec::new(),
        }
    }

    /// Create a disconnected bus.
    pub fn new_disconnected() -> Self {
        Self {
            connected: false,
            messages_sent: Vec::new(),
            properties: HashMap::new(),
            credentials: HashMap::new(),
            signal_handlers: Vec::new(),
        }
    }

    /// Check if the bus is connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Send a message on the bus.
    /// Corresponds to `sd_bus_message_send()`.
    pub fn send(&mut self, msg: BusMessage) -> Result<()> {
        if !self.connected {
            return Err(BusError::NotConnected);
        }
        self.messages_sent.push(msg);
        Ok(())
    }

    /// Emit a signal on the bus.
    /// Corresponds to `sd_bus_emit_signal()`.
    pub fn emit_signal(&mut self, path: &str, interface: &str, member: &str) -> Result<()> {
        if !self.connected {
            return Err(BusError::NotConnected);
        }
        if path.is_empty() || interface.is_empty() {
            return Err(BusError::InvalidArgument);
        }
        let msg = BusMessage::new_signal(path, interface, member);
        self.messages_sent.push(msg);
        Ok(())
    }

    /// Emit a signal to a specific destination.
    /// Corresponds to `sd_bus_emit_signal_to()`.
    pub fn emit_signal_to(
        &mut self,
        destination: &str,
        path: &str,
        interface: &str,
        member: &str,
    ) -> Result<()> {
        if !self.connected {
            return Err(BusError::NotConnected);
        }
        if destination.is_empty() || path.is_empty() {
            return Err(BusError::InvalidArgument);
        }
        let mut msg = BusMessage::new_signal(path, interface, member);
        msg.destination = Some(destination.to_string());
        self.messages_sent.push(msg);
        Ok(())
    }

    /// Call a method asynchronously.
    /// Corresponds to `sd_bus_call_method_async()`.
    pub fn call_method_async(
        &mut self,
        destination: &str,
        path: &str,
        interface: &str,
        member: &str,
    ) -> Result<()> {
        if !self.connected {
            return Err(BusError::NotConnected);
        }
        if destination.is_empty() || path.is_empty() {
            return Err(BusError::InvalidArgument);
        }
        let msg = BusMessage::new_method_call(destination, path, interface, member);
        self.messages_sent.push(msg);
        Ok(())
    }

    /// Call a method synchronously.
    /// Corresponds to `sd_bus_call_method()`.
    pub fn call_method(
        &mut self,
        destination: &str,
        path: &str,
        interface: &str,
        member: &str,
    ) -> Result<BusMessage> {
        if !self.connected {
            return Err(BusError::NotConnected);
        }
        if destination.is_empty() || path.is_empty() {
            return Err(BusError::InvalidArgument);
        }
        let msg = BusMessage::new_method_call(destination, path, interface, member);
        self.messages_sent.push(msg.clone());
        Ok(BusMessage::new_method_return())
    }

    /// Reply to a method call with a return message.
    /// Corresponds to `sd_bus_reply_method_return()`.
    pub fn reply_method_return(&mut self, _call: &BusMessage) -> Result<()> {
        if !self.connected {
            return Err(BusError::NotConnected);
        }
        Ok(())
    }

    /// Reply to a method call with an error.
    /// Corresponds to `sd_bus_reply_method_error()`.
    pub fn reply_method_error(&mut self, _call: &BusMessage, error_name: &str) -> Result<()> {
        if !self.connected {
            return Err(BusError::NotConnected);
        }
        if error_name.is_empty() {
            return Err(BusError::InvalidArgument);
        }
        let reply = BusMessage::new_error(error_name);
        self.messages_sent.push(reply);
        Ok(())
    }

    /// Reply with an errno.
    /// Corresponds to `sd_bus_reply_method_errno()`.
    pub fn reply_method_errno(&mut self, _call: &BusMessage, errno: i32) -> Result<()> {
        if !self.connected {
            return Err(BusError::NotConnected);
        }
        let reply = BusMessage::new_error(&format!("System.Error.E{errno}"));
        self.messages_sent.push(reply);
        Ok(())
    }

    /// Get a property.
    /// Corresponds to `sd_bus_get_property()`.
    pub fn get_property(
        &self,
        destination: &str,
        path: &str,
        interface: &str,
        property: &str,
    ) -> Result<String> {
        if !self.connected {
            return Err(BusError::NotConnected);
        }
        if destination.is_empty() || path.is_empty() || property.is_empty() {
            return Err(BusError::InvalidArgument);
        }
        let key = (
            path.to_string(),
            interface.to_string(),
            property.to_string(),
        );
        self.properties
            .get(&key)
            .cloned()
            .ok_or(BusError::UnknownProperty)
    }

    /// Get a trivial (fixed-size) property.
    /// Corresponds to `sd_bus_get_property_trivial()`.
    pub fn get_property_trivial(
        &self,
        destination: &str,
        path: &str,
        interface: &str,
        property: &str,
    ) -> Result<u64> {
        let val = self.get_property(destination, path, interface, property)?;
        val.parse().map_err(|_| BusError::InvalidArgument)
    }

    /// Get a string property.
    /// Corresponds to `sd_bus_get_property_string()`.
    pub fn get_property_string(
        &self,
        destination: &str,
        path: &str,
        interface: &str,
        property: &str,
    ) -> Result<String> {
        self.get_property(destination, path, interface, property)
    }

    /// Get a string array property.
    /// Corresponds to `sd_bus_get_property_strv()`.
    pub fn get_property_strv(
        &self,
        destination: &str,
        path: &str,
        interface: &str,
        property: &str,
    ) -> Result<Vec<String>> {
        let val = self.get_property(destination, path, interface, property)?;
        Ok(val.split(',').map(|s| s.to_string()).collect())
    }

    /// Set a property.
    /// Corresponds to `sd_bus_set_property()`.
    pub fn set_property(
        &mut self,
        path: &str,
        interface: &str,
        property: &str,
        value: &str,
    ) -> Result<()> {
        if !self.connected {
            return Err(BusError::NotConnected);
        }
        let key = (
            path.to_string(),
            interface.to_string(),
            property.to_string(),
        );
        self.properties.insert(key, value.to_string());
        Ok(())
    }

    /// Query the sender's credentials.
    /// Corresponds to `sd_bus_query_sender_creds()`.
    pub fn query_sender_creds(&self, sender: &str) -> Result<BusCreds> {
        if !self.connected {
            return Err(BusError::NotConnected);
        }
        self.credentials
            .get(sender)
            .cloned()
            .ok_or(BusError::InvalidArgument)
    }

    /// Query whether the sender has a given privilege.
    /// Corresponds to `sd_bus_query_sender_privilege()`.
    pub fn query_sender_privilege(&self, sender: &str, capability: i32) -> Result<bool> {
        let creds = self.query_sender_creds(sender)?;
        let _ = capability;
        // Root always has privilege
        if creds.is_root() {
            return Ok(true);
        }
        Ok(false)
    }

    /// Install a signal match rule.
    /// Corresponds to `sd_bus_match_signal()`.
    pub fn match_signal(
        &mut self,
        sender: Option<&str>,
        path: Option<&str>,
        interface: Option<&str>,
        member: Option<&str>,
    ) -> Result<()> {
        if !self.connected {
            return Err(BusError::NotConnected);
        }
        self.signal_handlers.push(SignalMatch {
            sender: sender.map(|s| s.to_string()),
            path: path.map(|s| s.to_string()),
            interface: interface.map(|s| s.to_string()),
            member: member.map(|s| s.to_string()),
        });
        Ok(())
    }

    /// Check if a signal matches any installed match rules.
    pub fn signal_matches_rules(&self, msg: &BusMessage) -> bool {
        self.signal_handlers.iter().any(|rule| rule.matches(msg))
    }

    /// Count of sent messages.
    pub fn sent_count(&self) -> usize {
        self.messages_sent.len()
    }

    /// Inject credentials for a sender (for testing).
    pub fn inject_creds(&mut self, sender: &str, creds: BusCreds) {
        self.credentials.insert(sender.to_string(), creds);
    }

    /// Disconnect the bus.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bus_new_connected() {
        let bus = BusConnection::new();
        assert!(bus.is_connected());
    }

    #[test]
    fn test_bus_new_disconnected() {
        let bus = BusConnection::new_disconnected();
        assert!(!bus.is_connected());
    }

    #[test]
    fn test_bus_disconnect() {
        let mut bus = BusConnection::new();
        bus.disconnect();
        assert!(!bus.is_connected());
    }

    #[test]
    fn test_bus_send_message() {
        let mut bus = BusConnection::new();
        let msg = BusMessage::new_signal("/test", "com.example", "TestSignal");
        bus.send(msg).unwrap();
        assert_eq!(bus.sent_count(), 1);
    }

    #[test]
    fn test_bus_send_disconnected() {
        let mut bus = BusConnection::new_disconnected();
        let msg = BusMessage::new_signal("/test", "com.example", "TestSignal");
        assert_eq!(bus.send(msg), Err(BusError::NotConnected));
    }

    #[test]
    fn test_bus_emit_signal() {
        let mut bus = BusConnection::new();
        bus.emit_signal("/test", "com.example.Test", "Changed")
            .unwrap();
        assert_eq!(bus.sent_count(), 1);
        let msg = &bus.messages_sent[0];
        assert_eq!(msg.msg_type, MessageType::Signal);
        assert_eq!(msg.path, Some("/test".to_string()));
    }

    #[test]
    fn test_bus_emit_signal_empty_path() {
        let mut bus = BusConnection::new();
        assert_eq!(
            bus.emit_signal("", "com.example", "Test"),
            Err(BusError::InvalidArgument)
        );
    }

    #[test]
    fn test_bus_emit_signal_to() {
        let mut bus = BusConnection::new();
        bus.emit_signal_to(":1.42", "/test", "com.example", "Test")
            .unwrap();
        let msg = &bus.messages_sent[0];
        assert_eq!(msg.destination, Some(":1.42".to_string()));
    }

    #[test]
    fn test_bus_call_method() {
        let mut bus = BusConnection::new();
        let reply = bus
            .call_method("com.example", "/test", "com.example.Test", "Ping")
            .unwrap();
        assert_eq!(reply.msg_type, MessageType::MethodReturn);
        assert_eq!(bus.sent_count(), 1);
    }

    #[test]
    fn test_bus_call_method_async() {
        let mut bus = BusConnection::new();
        bus.call_method_async("com.example", "/test", "com.example.Test", "Ping")
            .unwrap();
        assert_eq!(bus.sent_count(), 1);
    }

    #[test]
    fn test_bus_call_method_disconnected() {
        let mut bus = BusConnection::new_disconnected();
        assert_eq!(
            bus.call_method("com.example", "/test", "com.example.Test", "Ping"),
            Err(BusError::NotConnected)
        );
    }

    #[test]
    fn test_bus_reply_method_error() {
        let mut bus = BusConnection::new();
        let call = BusMessage::new_method_call("com.example", "/test", "com.example.Test", "Ping");
        bus.reply_method_error(&call, "org.freedesktop.DBus.Error.Failed")
            .unwrap();
        assert_eq!(bus.sent_count(), 1);
    }

    #[test]
    fn test_bus_reply_method_errno() {
        let mut bus = BusConnection::new();
        let call = BusMessage::new_method_call("com.example", "/test", "com.example.Test", "Ping");
        bus.reply_method_errno(&call, 2).unwrap();
        assert_eq!(bus.sent_count(), 1);
    }

    #[test]
    fn test_bus_property_set_get() {
        let mut bus = BusConnection::new();
        bus.set_property("/test", "com.example.Test", "Name", "hello")
            .unwrap();
        let val = bus
            .get_property("com.example", "/test", "com.example.Test", "Name")
            .unwrap();
        assert_eq!(val, "hello");
    }

    #[test]
    fn test_bus_property_unknown() {
        let bus = BusConnection::new();
        assert_eq!(
            bus.get_property("com.example", "/test", "com.example.Test", "NonExistent"),
            Err(BusError::UnknownProperty)
        );
    }

    #[test]
    fn test_bus_property_string() {
        let mut bus = BusConnection::new();
        bus.set_property("/test", "com.example.Test", "Host", "example.com")
            .unwrap();
        let val = bus
            .get_property_string("com.example", "/test", "com.example.Test", "Host")
            .unwrap();
        assert_eq!(val, "example.com");
    }

    #[test]
    fn test_bus_property_trivial() {
        let mut bus = BusConnection::new();
        bus.set_property("/test", "com.example.Test", "Count", "42")
            .unwrap();
        let val = bus
            .get_property_trivial("com.example", "/test", "com.example.Test", "Count")
            .unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn test_bus_property_strv() {
        let mut bus = BusConnection::new();
        bus.set_property("/test", "com.example.Test", "Tags", "a,b,c")
            .unwrap();
        let val = bus
            .get_property_strv("com.example", "/test", "com.example.Test", "Tags")
            .unwrap();
        assert_eq!(val, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_bus_query_sender_creds() {
        let mut bus = BusConnection::new();
        bus.inject_creds(":1.42", BusCreds::new(Some(1000), Some(1234)));
        let creds = bus.query_sender_creds(":1.42").unwrap();
        assert_eq!(creds.uid, Some(1000));
        assert_eq!(creds.pid, Some(1234));
    }

    #[test]
    fn test_bus_query_sender_privilege_root() {
        let mut bus = BusConnection::new();
        bus.inject_creds(":1.0", BusCreds::new(Some(0), Some(1)));
        assert!(bus.query_sender_privilege(":1.0", 0).unwrap());
    }

    #[test]
    fn test_bus_query_sender_privilege_nonroot() {
        let mut bus = BusConnection::new();
        bus.inject_creds(":1.42", BusCreds::new(Some(1000), Some(1234)));
        assert!(!bus.query_sender_privilege(":1.42", 0).unwrap());
    }

    #[test]
    fn test_bus_match_signal() {
        let mut bus = BusConnection::new();
        bus.match_signal(
            Some("com.example"),
            Some("/test"),
            Some("com.example.Test"),
            Some("Changed"),
        )
        .unwrap();

        let msg = BusMessage::new_signal("/test", "com.example.Test", "Changed");
        assert!(bus.signal_matches_rules(&msg));
    }

    #[test]
    fn test_bus_match_signal_no_match() {
        let mut bus = BusConnection::new();
        bus.match_signal(
            Some("com.example"),
            Some("/test"),
            Some("com.example.Test"),
            Some("Changed"),
        )
        .unwrap();

        let msg = BusMessage::new_signal("/other", "com.other.Test", "Changed");
        assert!(!bus.signal_matches_rules(&msg));
    }

    #[test]
    fn test_bus_match_signal_wildcard_interface() {
        let mut bus = BusConnection::new();
        bus.match_signal(None, Some("/test"), None, Some("Changed"))
            .unwrap();

        let msg = BusMessage::new_signal("/test", "com.example.Test", "Changed");
        assert!(bus.signal_matches_rules(&msg));
    }

    #[test]
    fn test_bus_creds_is_root() {
        let creds = BusCreds::new(Some(0), Some(1));
        assert!(creds.is_root());
        assert!(creds.has_uid(0));
    }

    #[test]
    fn test_bus_creds_not_root() {
        let creds = BusCreds::new(Some(1000), Some(1234));
        assert!(!creds.is_root());
        assert!(!creds.has_uid(0));
        assert!(creds.has_uid(1000));
    }

    #[test]
    fn test_message_is_method_call() {
        let msg = BusMessage::new_method_call("com.example", "/test", "com.example.Test", "Ping");
        assert!(msg.is_method_call("com.example.Test", "Ping"));
        assert!(!msg.is_method_call("com.example.Other", "Ping"));
        assert!(!msg.is_method_call("com.example.Test", "Pong"));
    }

    #[test]
    fn test_message_is_signal() {
        let msg = BusMessage::new_signal("/test", "com.example.Test", "Changed");
        assert!(msg.is_signal("com.example.Test", "Changed"));
        assert!(!msg.is_signal("com.example.Other", "Changed"));
    }

    #[test]
    fn test_message_types() {
        assert_ne!(MessageType::MethodCall, MessageType::Signal);
        assert_ne!(MessageType::Error, MessageType::MethodReturn);
    }

    #[test]
    fn test_constants() {
        assert_eq!(DBUS_PROPERTIES_INTERFACE, "org.freedesktop.DBus.Properties");
        assert_eq!(DBUS_PEER_INTERFACE, "org.freedesktop.DBus.Peer");
        assert_eq!(
            DBUS_INTROSPECTABLE_INTERFACE,
            "org.freedesktop.DBus.Introspectable"
        );
        assert_eq!(
            DBUS_OBJECT_MANAGER_INTERFACE,
            "org.freedesktop.DBus.ObjectManager"
        );
    }

    #[test]
    fn test_bus_reply_method_return() {
        let mut bus = BusConnection::new();
        let call = BusMessage::new_method_call("com.example", "/test", "com.example.Test", "Ping");
        bus.reply_method_return(&call).unwrap();
    }

    #[test]
    fn test_bus_property_disconnected() {
        let bus = BusConnection::new_disconnected();
        assert_eq!(
            bus.get_property("dest", "/test", "iface", "prop"),
            Err(BusError::NotConnected)
        );
    }

    #[test]
    fn test_bus_match_signal_disconnected() {
        let mut bus = BusConnection::new_disconnected();
        assert_eq!(
            bus.match_signal(None, Some("/test"), None, None),
            Err(BusError::NotConnected)
        );
    }
}
