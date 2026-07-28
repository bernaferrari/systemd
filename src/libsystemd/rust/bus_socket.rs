// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-socket.c
//
use std::collections::VecDeque;

type Result<T> = std::result::Result<T, i32>;

pub const SNDBUF_SIZE: usize = 8 * 1024 * 1024;
pub const BUS_AUTH_TIMEOUT_USEC: u64 = 90_000_000;

const EINVAL: i32 = -(libc::EINVAL as i32);
const EIO: i32 = -(libc::EIO as i32);
const EPERM: i32 = -(libc::EPERM as i32);
const EOPNOTSUPP: i32 = -(libc::EOPNOTSUPP as i32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusAuth {
    Invalid,
    Anonymous,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusState {
    Opening,
    Authenticating,
    Running,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusSide {
    Client,
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoVec {
    bytes: Vec<u8>,
    offset: usize,
}

impl IoVec {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            offset: 0,
        }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn advance(&mut self, count: usize) {
        self.offset = self.offset.saturating_add(count).min(self.bytes.len());
    }

    pub fn remaining_bytes(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }
}

#[derive(Debug, Clone)]
pub struct Bus {
    pub side: BusSide,
    pub state: BusState,
    pub anonymous_auth: bool,
    pub accept_fd: bool,
    pub can_fds: bool,
    pub ucred_valid: bool,
    pub ucred_uid: u32,
    pub auth: BusAuth,
    pub auth_iovec: Vec<IoVec>,
    pub auth_index: usize,
    pub auth_rbegin: usize,
    pub rbuffer: Vec<u8>,
    pub server_id: Option<[u8; 16]>,
    pub pending_messages: VecDeque<Vec<u8>>,
    pub incoming_messages: VecDeque<Vec<u8>>,
}

impl Bus {
    pub fn new(side: BusSide) -> Self {
        Self {
            side,
            state: BusState::Opening,
            anonymous_auth: false,
            accept_fd: false,
            can_fds: false,
            ucred_valid: false,
            ucred_uid: 0,
            auth: BusAuth::Invalid,
            auth_iovec: Vec::new(),
            auth_index: 0,
            auth_rbegin: 0,
            rbuffer: Vec::new(),
            server_id: None,
            pending_messages: VecDeque::new(),
            incoming_messages: VecDeque::new(),
        }
    }

    pub fn auth_needs_write(&self) -> bool {
        bus_socket_auth_needs_write(&self.auth_iovec, self.auth_index)
    }

    pub fn read_message_need(&self) -> usize {
        16 + 8
    }

    pub fn get_rbuffer_size(&self) -> usize {
        self.rbuffer.len()
    }

    pub fn start_auth(&mut self) -> Result<()> {
        self.state = BusState::Authenticating;
        self.auth = BusAuth::Invalid;
        self.auth_index = 0;
        self.auth_rbegin = 0;
        self.auth_iovec.clear();
        self.auth_iovec.push(IoVec::new(vec![0]));

        let mut line = if self.anonymous_auth {
            b"AUTH ANONYMOUS 73797374656d64\r\n".to_vec()
        } else {
            b"AUTH EXTERNAL\r\n".to_vec()
        };

        if self.accept_fd && self.side == BusSide::Client {
            line.extend_from_slice(b"NEGOTIATE_UNIX_FD\r\n");
        }

        self.auth_iovec.push(IoVec::new(line));
        Ok(())
    }

    pub fn connect(&mut self) -> Result<()> {
        Err(EOPNOTSUPP)
    }

    pub fn exec(&mut self) -> Result<()> {
        Err(EOPNOTSUPP)
    }

    pub fn take_fd(&mut self) -> Result<i32> {
        Err(EOPNOTSUPP)
    }

    pub fn write_message(&mut self, payload: Vec<u8>) -> Result<()> {
        self.pending_messages.push_back(payload);
        Ok(())
    }

    pub fn read_message(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(self.incoming_messages.pop_front())
    }

    pub fn process_opening(&mut self) -> Result<()> {
        self.state = BusState::Authenticating;
        Ok(())
    }

    pub fn process_authenticating(&mut self) -> Result<bool> {
        match self.side {
            BusSide::Client => bus_socket_auth_verify_client(self),
            BusSide::Server => bus_socket_auth_verify_server(self),
        }
    }

    pub fn process_cmsg(&mut self, allow_fds: bool) -> Result<()> {
        self.can_fds = self.can_fds || allow_fds;
        Ok(())
    }
}

pub fn bus_socket_setup(input_fd: i32, output_fd: i32) -> Result<()> {
    if input_fd < 0 || output_fd < 0 {
        return Err(EINVAL);
    }
    Ok(())
}

pub fn iovec_advance(iov: &mut [IoVec], idx: &mut usize, mut size: usize) {
    while size > 0 && *idx < iov.len() {
        let left = iov[*idx].remaining();
        if left > size {
            iov[*idx].advance(size);
            return;
        }

        size -= left;
        iov[*idx].advance(left);
        *idx += 1;
    }
}

pub fn bus_socket_auth_needs_write(auth_iovec: &[IoVec], auth_index: usize) -> bool {
    auth_iovec
        .get(auth_index..)
        .unwrap_or(&[])
        .iter()
        .any(|iov| iov.remaining() > 0)
}

pub fn line_equals(s: &[u8], line: &str) -> bool {
    s == line.as_bytes()
}

pub fn line_begins(s: &[u8], word: &str) -> bool {
    let word = word.as_bytes();
    s.starts_with(word) && (s.len() == word.len() || s[word.len()] == b' ')
}

pub fn verify_anonymous_token(anonymous_auth: bool, payload: &[u8]) -> bool {
    if !anonymous_auth {
        return false;
    }

    let payload = payload.strip_prefix(b" ").unwrap_or(payload);
    if payload.is_empty() {
        return true;
    }
    if payload.len() % 2 != 0 {
        return false;
    }

    let mut decoded = Vec::with_capacity(payload.len() / 2);
    for pair in payload.chunks_exact(2) {
        let (Some(hi), Some(lo)) = (hex_val(pair[0]), hex_val(pair[1])) else {
            return false;
        };
        let byte = (hi << 4) | lo;
        if byte == 0 {
            return false;
        }
        decoded.push(byte);
    }

    std::str::from_utf8(&decoded).is_ok()
}

pub fn verify_external_token(
    anonymous_auth: bool,
    ucred_valid: bool,
    ucred_uid: u32,
    payload: &[u8],
) -> bool {
    if !anonymous_auth && !ucred_valid {
        return false;
    }

    let payload = payload.strip_prefix(b" ").unwrap_or(payload);
    if payload.is_empty() {
        return true;
    }
    if payload.len() % 2 != 0 {
        return false;
    }

    let mut decoded = Vec::with_capacity(payload.len() / 2);
    for pair in payload.chunks_exact(2) {
        let (Some(hi), Some(lo)) = (hex_val(pair[0]), hex_val(pair[1])) else {
            return false;
        };
        let byte = (hi << 4) | lo;
        if byte == 0 {
            return false;
        }
        decoded.push(byte);
    }

    let Ok(text) = std::str::from_utf8(&decoded) else {
        return false;
    };
    let Ok(uid) = text.parse::<u32>() else {
        return false;
    };

    anonymous_auth || uid == ucred_uid
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn parse_server_id(line: &[u8]) -> Result<[u8; 16]> {
    if !line.starts_with(b"OK ") || line.len() != 35 {
        return Err(EPERM);
    }

    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let base = 3 + i * 2;
        let (Some(hi), Some(lo)) = (hex_val(line[base]), hex_val(line[base + 1])) else {
            return Err(EINVAL);
        };
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn bus_start_running(bus: &mut Bus) -> Result<bool> {
    bus.state = BusState::Running;
    Ok(true)
}

fn bus_socket_auth_write(bus: &mut Bus, text: &str) -> Result<()> {
    if bus.auth_iovec.is_empty() {
        bus.auth_iovec.push(IoVec::new(Vec::new()));
    }

    let first = bus
        .auth_iovec
        .first()
        .map(|iov| iov.remaining_bytes())
        .unwrap_or(&[])
        .to_vec();
    let mut merged = first;
    merged.extend_from_slice(text.as_bytes());
    bus.auth_iovec = vec![IoVec::new(merged)];
    bus.auth_index = 0;
    Ok(())
}

fn bus_socket_auth_write_ok(bus: &mut Bus) -> Result<()> {
    let server_id = bus.server_id.unwrap_or([0u8; 16]);
    let mut line = String::from("OK ");
    for byte in server_id {
        use std::fmt::Write as _;
        let _ = write!(line, "{byte:02x}");
    }
    line.push_str("\r\n");
    bus_socket_auth_write(bus, &line)
}

fn split_crlf_lines(bytes: &[u8], max_lines: usize) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    while lines.len() < max_lines {
        let Some(pos) = bytes[start..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let end = start + pos;
        lines.push(&bytes[start..end]);
        start = end + 2;
    }
    lines
}

pub fn bus_socket_auth_verify_client(bus: &mut Bus) -> Result<bool> {
    let lines = split_crlf_lines(&bus.rbuffer, 3);
    let required = (if bus.anonymous_auth { 1 } else { 2 }) + usize::from(bus.accept_fd);
    if lines.len() < required {
        return Ok(false);
    }

    let mut index = 0usize;
    if !bus.anonymous_auth {
        let first = lines[index];
        let valid = line_equals(first, "DATA") || (first.starts_with(b"OK ") && first.len() == 35);
        if !valid {
            return Err(EPERM);
        }
        index += 1;
    }

    let ok_line = lines[index];
    let peer = parse_server_id(ok_line)?;
    if let Some(expected) = bus.server_id
        && expected != peer
    {
        return Err(EPERM);
    }

    bus.server_id = Some(peer);
    bus.auth = if bus.anonymous_auth {
        BusAuth::Anonymous
    } else {
        BusAuth::External
    };
    index += 1;

    if bus.accept_fd {
        bus.can_fds = line_equals(lines[index], "AGREE_UNIX_FD");
        index += 1;
    }

    let consumed = bus
        .rbuffer
        .windows(2)
        .enumerate()
        .filter(|(_, w)| *w == b"\r\n")
        .nth(index - 1)
        .map(|(i, _)| i + 2)
        .unwrap_or(0);
    bus.rbuffer.drain(..consumed);
    bus_start_running(bus)
}

pub fn bus_socket_auth_verify_server(bus: &mut Bus) -> Result<bool> {
    if bus.rbuffer.is_empty() {
        return Ok(false);
    }
    if bus.rbuffer[0] != 0 {
        return Err(EIO);
    }
    if bus.rbuffer.len() < 3 {
        return Ok(false);
    }
    if bus.auth_rbegin == 0 {
        bus.auth_rbegin = 1;
    }

    let mut processed = false;
    loop {
        let slice = &bus.rbuffer[bus.auth_rbegin..];
        let Some(pos) = slice.windows(2).position(|w| w == b"\r\n") else {
            return Ok(processed);
        };
        let line = &slice[..pos];

        if line_begins(line, "AUTH ANONYMOUS") {
            if !verify_anonymous_token(bus.anonymous_auth, &line["AUTH ANONYMOUS".len()..]) {
                bus_socket_auth_write(bus, "REJECTED\r\n")?;
            } else {
                bus.auth = BusAuth::Anonymous;
                if line.len() <= "AUTH ANONYMOUS".len() {
                    bus_socket_auth_write(bus, "DATA\r\n")?;
                } else {
                    bus_socket_auth_write_ok(bus)?;
                }
            }
        } else if line_begins(line, "AUTH EXTERNAL") {
            if !verify_external_token(
                bus.anonymous_auth,
                bus.ucred_valid,
                bus.ucred_uid,
                &line["AUTH EXTERNAL".len()..],
            ) {
                bus_socket_auth_write(bus, "REJECTED\r\n")?;
            } else {
                bus.auth = BusAuth::External;
                if line.len() <= "AUTH EXTERNAL".len() {
                    bus_socket_auth_write(bus, "DATA\r\n")?;
                } else {
                    bus_socket_auth_write_ok(bus)?;
                }
            }
        } else if line_begins(line, "AUTH") {
            bus_socket_auth_write(bus, "REJECTED EXTERNAL ANONYMOUS\r\n")?;
        } else if line_equals(line, "CANCEL") || line_begins(line, "ERROR") {
            bus.auth = BusAuth::Invalid;
            bus_socket_auth_write(bus, "REJECTED\r\n")?;
        } else if line_equals(line, "BEGIN") {
            if bus.auth == BusAuth::Invalid {
                bus_socket_auth_write(bus, "ERROR\r\n")?;
            } else if bus.auth_needs_write() {
                return Ok(true);
            } else {
                let consumed = bus.auth_rbegin + pos + 2;
                bus.rbuffer.drain(..consumed);
                return bus_start_running(bus);
            }
        } else if line_begins(line, "DATA") {
            if bus.auth == BusAuth::Invalid {
                bus_socket_auth_write(bus, "ERROR\r\n")?;
            } else {
                let ok = match bus.auth {
                    BusAuth::Anonymous => verify_anonymous_token(bus.anonymous_auth, &line[4..]),
                    BusAuth::External => verify_external_token(
                        bus.anonymous_auth,
                        bus.ucred_valid,
                        bus.ucred_uid,
                        &line[4..],
                    ),
                    BusAuth::Invalid => false,
                };
                if !ok {
                    bus.auth = BusAuth::Invalid;
                    bus_socket_auth_write(bus, "REJECTED\r\n")?;
                } else {
                    bus_socket_auth_write_ok(bus)?;
                }
            }
        } else if line_equals(line, "NEGOTIATE_UNIX_FD") {
            if bus.auth == BusAuth::Invalid || !bus.accept_fd {
                bus_socket_auth_write(bus, "ERROR\r\n")?;
            } else {
                bus.can_fds = true;
                bus_socket_auth_write(bus, "AGREE_UNIX_FD\r\n")?;
            }
        } else {
            bus_socket_auth_write(bus, "ERROR\r\n")?;
        }

        bus.auth_rbegin += pos + 2;
        processed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advances_iovecs() {
        let mut iov = vec![IoVec::new(b"abc".to_vec()), IoVec::new(b"def".to_vec())];
        let mut idx = 0;
        iovec_advance(&mut iov, &mut idx, 4);
        assert_eq!(idx, 1);
        assert_eq!(iov[1].remaining_bytes(), b"ef");
    }

    #[test]
    fn reports_auth_write_need() {
        assert!(bus_socket_auth_needs_write(&[IoVec::new(b"x".to_vec())], 0));
        assert!(!bus_socket_auth_needs_write(&[IoVec::new(Vec::new())], 0));
    }

    #[test]
    fn matches_lines_like_c_helpers() {
        assert!(line_equals(b"BEGIN", "BEGIN"));
        assert!(line_begins(b"AUTH EXTERNAL", "AUTH"));
        assert!(!line_begins(b"AUTHX", "AUTH"));
    }

    #[test]
    fn verifies_anonymous_token() {
        assert!(verify_anonymous_token(true, b" 73797374656d64"));
        assert!(!verify_anonymous_token(false, b" 73797374656d64"));
        assert!(!verify_anonymous_token(true, b" 00"));
    }

    #[test]
    fn verifies_external_token() {
        assert!(verify_external_token(false, true, 1000, b" 31303030"));
        assert!(!verify_external_token(false, true, 1001, b" 31303030"));
        assert!(verify_external_token(true, false, 0, b" 31303030"));
    }

    #[test]
    fn client_auth_accepts_data_ok_and_fd_agreement() {
        let mut bus = Bus::new(BusSide::Client);
        bus.accept_fd = true;
        bus.rbuffer = b"DATA\r\nOK 00112233445566778899aabbccddeeff\r\nAGREE_UNIX_FD\r\n".to_vec();
        assert_eq!(bus_socket_auth_verify_client(&mut bus), Ok(true));
        assert_eq!(bus.state, BusState::Running);
        assert!(bus.can_fds);
        assert_eq!(bus.auth, BusAuth::External);
    }

    #[test]
    fn server_auth_replies_to_external_and_begin() {
        let mut bus = Bus::new(BusSide::Server);
        bus.accept_fd = true;
        bus.ucred_valid = true;
        bus.ucred_uid = 1000;
        bus.server_id = Some([0x11; 16]);
        bus.rbuffer = b"\0AUTH EXTERNAL 31303030\r\nNEGOTIATE_UNIX_FD\r\n".to_vec();
        assert_eq!(bus_socket_auth_verify_server(&mut bus), Ok(true));
        assert!(bus.auth_needs_write());
        assert!(bus.can_fds);

        bus.auth_iovec.clear();
        bus.auth_index = 0;
        bus.rbuffer.extend_from_slice(b"BEGIN\r\n");
        assert_eq!(bus_socket_auth_verify_server(&mut bus), Ok(true));
        assert_eq!(bus.state, BusState::Running);
    }

    #[test]
    fn start_auth_builds_initial_client_frames() {
        let mut bus = Bus::new(BusSide::Client);
        bus.anonymous_auth = true;
        bus.accept_fd = true;
        bus.start_auth().unwrap();
        assert_eq!(bus.state, BusState::Authenticating);
        assert_eq!(bus.auth_iovec.len(), 2);
        assert_eq!(bus.auth_iovec[0].remaining_bytes(), [0]);
        assert!(
            std::str::from_utf8(bus.auth_iovec[1].remaining_bytes())
                .unwrap()
                .contains("AUTH ANONYMOUS")
        );
    }

    #[test]
    fn setup_rejects_invalid_fd() {
        assert_eq!(bus_socket_setup(-1, 1), Err(EINVAL));
        assert_eq!(bus_socket_setup(1, 2), Ok(()));
    }
}
