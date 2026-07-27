// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-serialize.c
//
// Varlink server serialization and deserialization.
//
// Provides line-based serialization of varlink server socket state for
// checkpoint/restore. Each socket is written as a single line containing
// its address and a reference to a file descriptor in the FDSet.

use std::fmt;
use std::io::{self, Write};

// ── Error types ───────────────────────────────────────────────────────────

/// Errors produced by varlink serialization operations.
#[derive(Debug)]
pub enum VarlinkSerializeError {
    /// Invalid input: empty address, negative fd, malformed line.
    InvalidInput(String),
    /// An I/O error occurred during serialization.
    Io(io::Error),
    /// A file descriptor was not found in the set.
    FdNotFound(i32),
    /// The fd value is invalid (negative).
    InvalidFd(i32),
}

impl fmt::Display for VarlinkSerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VarlinkSerializeError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            VarlinkSerializeError::Io(e) => write!(f, "I/O error: {e}"),
            VarlinkSerializeError::FdNotFound(fd) => write!(f, "fd {fd} not found in set"),
            VarlinkSerializeError::InvalidFd(fd) => write!(f, "invalid file descriptor: {fd}"),
        }
    }
}

impl std::error::Error for VarlinkSerializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VarlinkSerializeError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for VarlinkSerializeError {
    fn from(e: io::Error) -> Self {
        VarlinkSerializeError::Io(e)
    }
}

// ── FDSet ─────────────────────────────────────────────────────────────────

/// Minimal FDSet for serialization — mirrors the subset of serialize::FDSet
/// needed by varlink serialization.
#[derive(Debug, Default, Clone)]
pub struct FdSet {
    fds: Vec<i32>,
}

impl FdSet {
    /// Create a new empty FdSet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a duplicate fd reference. Returns the fd on success.
    pub fn put_dup(&mut self, fd: i32) -> Result<i32, VarlinkSerializeError> {
        if fd < 0 {
            return Err(VarlinkSerializeError::InvalidFd(fd));
        }
        self.fds.push(fd);
        Ok(fd)
    }

    /// Remove and return an fd from the set by value.
    pub fn remove(&mut self, fd: i32) -> Result<i32, VarlinkSerializeError> {
        if let Some(pos) = self.fds.iter().position(|&f| f == fd) {
            Ok(self.fds.remove(pos))
        } else {
            Err(VarlinkSerializeError::FdNotFound(fd))
        }
    }

    /// Number of fds currently in the set.
    pub fn len(&self) -> usize {
        self.fds.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }
}

// ── VarlinkServerSocket ──────────────────────────────────────────────────

/// A single varlink server socket entry: an address string and file descriptor.
///
/// Mirrors the C `VarlinkServerSocket` struct from varlink-internal.h
/// (address + fd fields), without the event loop integration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarlinkServerSocket {
    /// Socket address (e.g. a Unix socket path or abstract name).
    pub address: String,
    /// File descriptor for the listening socket.
    pub fd: i32,
}

// ── Serialization line format ────────────────────────────────────────────

/// Default prefix used in serialization lines when no name is given.
pub const DEFAULT_PREFIX: &str = "varlink-server";

/// Construct the serialization line prefix from an optional name.
pub fn make_prefix(name: Option<&str>) -> String {
    match name {
        Some(n) => format!("varlink-server-{n}"),
        None => DEFAULT_PREFIX.to_string(),
    }
}

/// Parse a serialized line back into its prefix, address, and fd number.
///
/// Expected format: `<prefix>-socket-address=<addr> varlink-server-socket-fd=<fd>`
/// The prefix itself is not returned; we strip it and parse the rest.
///
/// Returns `(address, fd)` on success.
pub fn parse_socket_line(line: &str) -> Result<(String, i32), VarlinkSerializeError> {
    let v = line.strip_prefix("socket-address=").ok_or_else(|| {
        VarlinkSerializeError::InvalidInput(format!(
            "line missing 'socket-address=' prefix: {line}"
        ))
    })?;

    // Split at the space between address and fd reference
    let (address_part, rest) = match v.split_once(' ') {
        Some(pair) => pair,
        None => {
            return Err(VarlinkSerializeError::InvalidInput(format!(
                "line missing fd reference: {line}"
            )));
        }
    };

    let address = address_part.to_string();
    if address.is_empty() {
        return Err(VarlinkSerializeError::InvalidInput(
            "empty socket address".to_string(),
        ));
    }

    let fd_str = rest
        .strip_prefix("varlink-server-socket-fd=")
        .ok_or_else(|| {
            VarlinkSerializeError::InvalidInput(format!(
                "line missing 'varlink-server-socket-fd=': {line}"
            ))
        })?;

    let fd: i32 = fd_str
        .parse()
        .map_err(|_| VarlinkSerializeError::InvalidInput(format!("invalid fd number: {fd_str}")))?;

    if fd < 0 {
        return Err(VarlinkSerializeError::InvalidFd(fd));
    }

    Ok((address, fd))
}

// ── Serialize ────────────────────────────────────────────────────────────

/// Serialize a list of varlink server sockets to a writer.
///
/// Each socket is written as one line in the format:
/// `<prefix>-socket-address=<addr> varlink-server-socket-fd=<fd>`
///
/// File descriptors are registered in `fds` via `put_dup`.
pub fn varlink_server_serialize<W: Write>(
    sockets: &[VarlinkServerSocket],
    name: Option<&str>,
    w: &mut W,
    fds: &mut FdSet,
) -> Result<(), VarlinkSerializeError> {
    let prefix = make_prefix(name);

    for sock in sockets {
        if sock.address.is_empty() {
            return Err(VarlinkSerializeError::InvalidInput(
                "socket address is empty".to_string(),
            ));
        }
        if sock.fd < 0 {
            return Err(VarlinkSerializeError::InvalidFd(sock.fd));
        }

        let copy = fds.put_dup(sock.fd)?;
        writeln!(
            w,
            "{prefix}-socket-address={} varlink-server-socket-fd={copy}",
            sock.address
        )?;
    }

    Ok(())
}

// ── Deserialize ──────────────────────────────────────────────────────────

/// Deserialize a single varlink socket entry from a line (with prefix stripped).
///
/// The `value` should be the portion of the line after the `varlink-server(-name)-` prefix
/// has been removed. The fd is removed from the provided FdSet.
///
/// Returns the reconstructed `VarlinkServerSocket`.
pub fn varlink_server_deserialize_one(
    value: &str,
    fds: &mut FdSet,
) -> Result<VarlinkServerSocket, VarlinkSerializeError> {
    let (address, fd_num) = parse_socket_line(value)?;

    // Remove the fd from the set — ownership transfers to the caller
    fds.remove(fd_num)?;

    Ok(VarlinkServerSocket {
        address,
        fd: fd_num,
    })
}

// ── Contains ─────────────────────────────────────────────────────────────

/// Check whether any socket in the list has the given address.
///
/// Compares addresses as exact strings (the C version uses
/// `socket_address_equal_unix` which handles abstract sockets and
/// filesystem normalization; here we do plain string equality for
/// the safe Rust subset).
pub fn varlink_server_contains_socket(sockets: &[VarlinkServerSocket], address: &str) -> bool {
    sockets.iter().any(|s| s.address == address)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fdset_put_dup_and_remove() {
        let mut fds = FdSet::new();
        assert!(fds.is_empty());

        fds.put_dup(5).unwrap();
        fds.put_dup(10).unwrap();
        assert_eq!(fds.len(), 2);

        assert_eq!(fds.remove(5).unwrap(), 5);
        assert_eq!(fds.len(), 1);

        // Removing again should fail
        assert!(fds.remove(5).is_err());
    }

    #[test]
    fn test_fdset_put_dup_negative_fd() {
        let mut fds = FdSet::new();
        let err = fds.put_dup(-1).unwrap_err();
        assert!(matches!(err, VarlinkSerializeError::InvalidFd(-1)));
    }

    #[test]
    fn test_make_prefix_no_name() {
        assert_eq!(make_prefix(None), "varlink-server");
    }

    #[test]
    fn test_make_prefix_with_name() {
        assert_eq!(make_prefix(Some("myapp")), "varlink-server-myapp");
    }

    #[test]
    fn test_varlink_server_serialize_empty() {
        let mut fds = FdSet::new();
        let mut output = Vec::new();
        varlink_server_serialize(&[], None, &mut output, &mut fds).unwrap();
        assert!(output.is_empty());
        assert!(fds.is_empty());
    }

    #[test]
    fn test_varlink_server_serialize_single() {
        let sockets = vec![VarlinkServerSocket {
            address: "/run/foo.sock".to_string(),
            fd: 7,
        }];
        let mut fds = FdSet::new();
        let mut output = Vec::new();

        varlink_server_serialize(&sockets, None, &mut output, &mut fds).unwrap();

        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with(
            "varlink-server-socket-address=/run/foo.sock varlink-server-socket-fd=7\n"
        ));
        assert_eq!(fds.len(), 1);
    }

    #[test]
    fn test_varlink_server_serialize_with_name() {
        let sockets = vec![VarlinkServerSocket {
            address: "/run/bar.sock".to_string(),
            fd: 3,
        }];
        let mut fds = FdSet::new();
        let mut output = Vec::new();

        varlink_server_serialize(&sockets, Some("systemd"), &mut output, &mut fds).unwrap();

        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("varlink-server-systemd-socket-address=/run/bar.sock"));
    }

    #[test]
    fn test_varlink_server_serialize_empty_address_rejects() {
        let sockets = vec![VarlinkServerSocket {
            address: String::new(),
            fd: 1,
        }];
        let mut fds = FdSet::new();
        let mut output = Vec::new();

        let err = varlink_server_serialize(&sockets, None, &mut output, &mut fds);
        assert!(err.is_err());
    }

    #[test]
    fn test_varlink_server_serialize_negative_fd_rejects() {
        let sockets = vec![VarlinkServerSocket {
            address: "/run/x.sock".to_string(),
            fd: -1,
        }];
        let mut fds = FdSet::new();
        let mut output = Vec::new();

        let err = varlink_server_serialize(&sockets, None, &mut output, &mut fds);
        assert!(err.is_err());
    }

    #[test]
    fn test_parse_socket_line_valid() {
        let (addr, fd) =
            parse_socket_line("socket-address=/run/test.sock varlink-server-socket-fd=42").unwrap();
        assert_eq!(addr, "/run/test.sock");
        assert_eq!(fd, 42);
    }

    #[test]
    fn test_parse_socket_line_missing_prefix() {
        let err = parse_socket_line("garbage data").unwrap_err();
        assert!(matches!(err, VarlinkSerializeError::InvalidInput(_)));
    }

    #[test]
    fn test_parse_socket_line_missing_fd() {
        let err = parse_socket_line("socket-address=/run/test.sock").unwrap_err();
        assert!(matches!(err, VarlinkSerializeError::InvalidInput(_)));
    }

    #[test]
    fn test_parse_socket_line_empty_address() {
        let err = parse_socket_line("socket-address= varlink-server-socket-fd=1").unwrap_err();
        assert!(matches!(err, VarlinkSerializeError::InvalidInput(_)));
    }

    #[test]
    fn test_parse_socket_line_invalid_fd() {
        let err = parse_socket_line("socket-address=/run/x.sock varlink-server-socket-fd=abc")
            .unwrap_err();
        assert!(matches!(err, VarlinkSerializeError::InvalidInput(_)));
    }

    #[test]
    fn test_parse_socket_line_negative_fd() {
        let err = parse_socket_line("socket-address=/run/x.sock varlink-server-socket-fd=-3")
            .unwrap_err();
        assert!(matches!(err, VarlinkSerializeError::InvalidFd(_)));
    }

    #[test]
    fn test_varlink_server_deserialize_one() {
        let mut fds = FdSet::new();
        fds.put_dup(10).unwrap();

        let sock = varlink_server_deserialize_one(
            "socket-address=/run/restore.sock varlink-server-socket-fd=10",
            &mut fds,
        )
        .unwrap();

        assert_eq!(sock.address, "/run/restore.sock");
        assert_eq!(sock.fd, 10);
        assert!(fds.is_empty()); // fd was consumed
    }

    #[test]
    fn test_varlink_server_deserialize_one_fd_not_in_set() {
        let mut fds = FdSet::new();

        let err = varlink_server_deserialize_one(
            "socket-address=/run/missing.sock varlink-server-socket-fd=99",
            &mut fds,
        )
        .unwrap_err();
        assert!(matches!(err, VarlinkSerializeError::FdNotFound(99)));
    }

    #[test]
    fn test_varlink_server_deserialize_one_invalid_line() {
        let mut fds = FdSet::new();
        fds.put_dup(1).unwrap();

        let err = varlink_server_deserialize_one("bogus line", &mut fds).unwrap_err();
        assert!(matches!(err, VarlinkSerializeError::InvalidInput(_)));
        // fd should not be consumed
        assert_eq!(fds.len(), 1);
    }

    #[test]
    fn test_varlink_server_contains_socket_found() {
        let sockets = vec![
            VarlinkServerSocket {
                address: "/run/a.sock".to_string(),
                fd: 1,
            },
            VarlinkServerSocket {
                address: "/run/b.sock".to_string(),
                fd: 2,
            },
        ];
        assert!(varlink_server_contains_socket(&sockets, "/run/b.sock"));
    }

    #[test]
    fn test_varlink_server_contains_socket_not_found() {
        let sockets = vec![VarlinkServerSocket {
            address: "/run/a.sock".to_string(),
            fd: 1,
        }];
        assert!(!varlink_server_contains_socket(&sockets, "/run/z.sock"));
    }

    #[test]
    fn test_varlink_server_contains_socket_empty_list() {
        let sockets: Vec<VarlinkServerSocket> = vec![];
        assert!(!varlink_server_contains_socket(&sockets, "/run/x.sock"));
    }

    #[test]
    fn test_roundtrip_serialize_deserialize() {
        let original = vec![
            VarlinkServerSocket {
                address: "/run/first.sock".to_string(),
                fd: 5,
            },
            VarlinkServerSocket {
                address: "@abstract".to_string(),
                fd: 8,
            },
        ];

        // Serialize
        let mut fds = FdSet::new();
        let mut output = Vec::new();
        varlink_server_serialize(&original, Some("myname"), &mut output, &mut fds).unwrap();

        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);

        // Deserialize each line (strip the prefix first)
        let mut restored = Vec::new();
        let prefix = "varlink-server-myname-";
        for line in &lines {
            let stripped = line.strip_prefix(prefix).unwrap();
            let sock = varlink_server_deserialize_one(stripped, &mut fds).unwrap();
            restored.push(sock);
        }

        assert_eq!(restored, original);
        assert!(fds.is_empty());
    }

    #[test]
    fn test_roundtrip_serialize_deserialize_no_name() {
        let original = vec![VarlinkServerSocket {
            address: "/run/simple.sock".to_string(),
            fd: 3,
        }];

        let mut fds = FdSet::new();
        let mut output = Vec::new();
        varlink_server_serialize(&original, None, &mut output, &mut fds).unwrap();

        let text = String::from_utf8(output).unwrap();
        let prefix = "varlink-server-";
        let stripped = text.lines().next().unwrap().strip_prefix(prefix).unwrap();

        let sock = varlink_server_deserialize_one(stripped, &mut fds).unwrap();
        assert_eq!(sock, original[0]);
    }

    #[test]
    fn test_varlink_serialize_error_display() {
        let err = VarlinkSerializeError::InvalidInput("bad data".to_string());
        let msg = format!("{err}");
        assert!(msg.contains("bad data"));

        let err = VarlinkSerializeError::FdNotFound(42);
        let msg = format!("{err}");
        assert!(msg.contains("42"));

        let err = VarlinkSerializeError::InvalidFd(-1);
        let msg = format!("{err}");
        assert!(msg.contains("-1"));
    }
}
