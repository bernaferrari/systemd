// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/core/dbus.c (`bus_on_connection()`, `bus_check_peercred()`)

//! Bounded server-side D-Bus authentication for PID 1's private socket.
//!
//! This module implements only the authentication phase of one already
//! accepted Unix stream. The acceptor must obtain [`AuthenticatedPeer`] from
//! kernel credentials; the D-Bus authentication token is checked against that
//! identity and is never treated as a credential source.
//!
//! Input and pending output are both bounded by sd-bus' 64 KiB authentication
//! limit. Output supports partial nonblocking writes, and a pipelined `BEGIN`
//! is not accepted until every preceding response has been consumed. A
//! completed authentication hands the retained sender identity and any
//! pipelined binary bytes to the caller.
//!
//! Unix-fd negotiation is deliberately rejected. [`crate::pid1_dbus_wire`]
//! rejects messages carrying file descriptors, so advertising fd support here
//! would create a false transport invariant.

use crate::pid1_manager_commands::{AuthenticatedPeer, SenderIdentity};

const MAX_AUTH_SIZE: usize = 64 * 1024;

const DATA_RESPONSE: &[u8] = b"DATA\r\n";
const ERROR_RESPONSE: &[u8] = b"ERROR\r\n";
const REJECTED_RESPONSE: &[u8] = b"REJECTED\r\n";
const REJECTED_MECHANISMS_RESPONSE: &[u8] = b"REJECTED EXTERNAL ANONYMOUS\r\n";
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerAuthError {
    UnprivilegedPeer,
    MissingInitialNul,
    InputTooLarge,
    OutputTooLarge,
    InvalidOutputConsumption,
    AlreadyAuthenticated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerAuthProgress {
    Authenticating,
    Authenticated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mechanism {
    Invalid,
    External,
}

/// Authentication state for one accepted private-bus stream.
///
/// Construction performs the same peer-uid gate as C's
/// `bus_check_peercred()`: only uid 0 or the manager's effective uid may reach
/// the D-Bus authentication exchange.
#[derive(Debug)]
pub struct PrivateBusServerAuth {
    sender: SenderIdentity,
    peer_uid: u32,
    server_id: [u8; 16],
    input: Vec<u8>,
    input_offset: usize,
    input_received: usize,
    output: Vec<u8>,
    output_offset: usize,
    mechanism: Mechanism,
    saw_initial_nul: bool,
    authenticated: bool,
}

impl PrivateBusServerAuth {
    pub fn new(
        peer: AuthenticatedPeer,
        manager_effective_uid: u32,
        server_id: [u8; 16],
    ) -> Result<Self, ServerAuthError> {
        if peer.uid() != 0 && peer.uid() != manager_effective_uid {
            return Err(ServerAuthError::UnprivilegedPeer);
        }

        Ok(Self {
            sender: SenderIdentity::from_authenticated_peer(peer),
            peer_uid: peer.uid(),
            server_id,
            input: Vec::new(),
            input_offset: 0,
            input_received: 0,
            output: Vec::new(),
            output_offset: 0,
            mechanism: Mechanism::Invalid,
            saw_initial_nul: false,
            authenticated: false,
        })
    }

    /// Maximum bytes the caller may read into the authentication state.
    ///
    /// A nonblocking adapter should cap each read to this value. Once it
    /// reaches zero without completing authentication, the connection must be
    /// closed as oversized.
    pub const fn remaining_input_capacity(&self) -> usize {
        MAX_AUTH_SIZE - self.input_received
    }

    pub fn progress(&self) -> ServerAuthProgress {
        if self.authenticated {
            ServerAuthProgress::Authenticated
        } else {
            ServerAuthProgress::Authenticating
        }
    }

    /// Feed bytes read from the accepted stream without allocating from any
    /// peer-declared length.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<ServerAuthProgress, ServerAuthError> {
        if self.authenticated {
            return Err(ServerAuthError::AlreadyAuthenticated);
        }

        self.input_received = self
            .input_received
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_AUTH_SIZE)
            .ok_or(ServerAuthError::InputTooLarge)?;
        self.input.extend_from_slice(bytes);
        self.process()
    }

    /// Bytes currently waiting for a nonblocking socket write.
    pub fn pending_output(&self) -> &[u8] {
        &self.output[self.output_offset..]
    }

    /// Record a completed partial or full socket write.
    ///
    /// Draining output may make a pipelined `BEGIN` processable, so this also
    /// advances authentication.
    pub fn consume_output(&mut self, count: usize) -> Result<ServerAuthProgress, ServerAuthError> {
        if count > self.pending_output().len() {
            return Err(ServerAuthError::InvalidOutputConsumption);
        }

        self.output_offset += count;
        if self.output_offset == self.output.len() {
            self.output.clear();
            self.output_offset = 0;
        }
        self.process()
    }

    /// Consume a completed authentication and transfer its security identity
    /// and already-read binary bytes to the message transport.
    pub fn into_authenticated(self) -> Result<AuthenticatedPrivateBusStream, PrivateBusServerAuth> {
        if !self.authenticated || !self.pending_output().is_empty() {
            return Err(self);
        }

        Ok(AuthenticatedPrivateBusStream {
            sender: self.sender,
            buffered: self.input[self.input_offset..].to_vec(),
        })
    }

    fn process(&mut self) -> Result<ServerAuthProgress, ServerAuthError> {
        if self.authenticated {
            return Ok(ServerAuthProgress::Authenticated);
        }

        if !self.saw_initial_nul {
            let Some(first) = self.input.first() else {
                return Ok(ServerAuthProgress::Authenticating);
            };
            if *first != 0 {
                return Err(ServerAuthError::MissingInitialNul);
            }
            self.saw_initial_nul = true;
            self.input_offset = 1;
        }

        loop {
            let Some(relative_end) = self.input[self.input_offset..]
                .windows(2)
                .position(|window| window == b"\r\n")
            else {
                return Ok(ServerAuthProgress::Authenticating);
            };
            let line_end = self.input_offset + relative_end;

            if self.input[self.input_offset..line_end] == *b"BEGIN"
                && self.mechanism != Mechanism::Invalid
            {
                if !self.pending_output().is_empty() {
                    return Ok(ServerAuthProgress::Authenticating);
                }

                self.input_offset = line_end + 2;
                self.authenticated = true;
                return Ok(ServerAuthProgress::Authenticated);
            }

            let line = self.input[self.input_offset..line_end].to_vec();
            self.input_offset = line_end + 2;
            self.process_line(&line)?;
        }
    }

    fn process_line(&mut self, line: &[u8]) -> Result<(), ServerAuthError> {
        if let Some(argument) = line_argument(line, b"AUTH ANONYMOUS") {
            let _ = argument;
            self.queue_response(REJECTED_RESPONSE)
        } else if let Some(argument) = line_argument(line, b"AUTH EXTERNAL") {
            if verify_external_token(argument, self.peer_uid) {
                self.mechanism = Mechanism::External;
                if argument.is_none() {
                    self.queue_response(DATA_RESPONSE)
                } else {
                    self.queue_ok()
                }
            } else {
                self.queue_response(REJECTED_RESPONSE)
            }
        } else if line_argument(line, b"AUTH").is_some() {
            self.queue_response(REJECTED_MECHANISMS_RESPONSE)
        } else if line == b"CANCEL" || line_argument(line, b"ERROR").is_some() {
            self.mechanism = Mechanism::Invalid;
            self.queue_response(REJECTED_RESPONSE)
        } else if line == b"BEGIN" {
            self.queue_response(ERROR_RESPONSE)
        } else if let Some(argument) = line_argument(line, b"DATA") {
            if self.mechanism == Mechanism::Invalid {
                self.queue_response(ERROR_RESPONSE)
            } else if verify_external_token(argument, self.peer_uid) {
                self.queue_ok()
            } else {
                self.mechanism = Mechanism::Invalid;
                self.queue_response(REJECTED_RESPONSE)
            }
        } else {
            // This includes NEGOTIATE_UNIX_FD: the message wire codec
            // rejects fd-bearing messages, so the staged auth transport does
            // not advertise or negotiate Unix-fd passing.
            self.queue_response(ERROR_RESPONSE)
        }
    }

    fn queue_ok(&mut self) -> Result<(), ServerAuthError> {
        let mut response = Vec::with_capacity(37);
        response.extend_from_slice(b"OK ");
        for byte in self.server_id {
            response.push(HEX_DIGITS[usize::from(byte >> 4)]);
            response.push(HEX_DIGITS[usize::from(byte & 0x0f)]);
        }
        response.extend_from_slice(b"\r\n");
        self.queue_response(&response)
    }

    fn queue_response(&mut self, response: &[u8]) -> Result<(), ServerAuthError> {
        let pending = self.pending_output().len();
        if pending
            .checked_add(response.len())
            .filter(|size| *size <= MAX_AUTH_SIZE)
            .is_none()
        {
            return Err(ServerAuthError::OutputTooLarge);
        }

        if self.output_offset > 0 {
            self.output.drain(..self.output_offset);
            self.output_offset = 0;
        }
        self.output.extend_from_slice(response);
        Ok(())
    }
}

/// Security identity and bytes transferred only after a successful `BEGIN`.
#[derive(Debug)]
pub struct AuthenticatedPrivateBusStream {
    sender: SenderIdentity,
    buffered: Vec<u8>,
}

impl AuthenticatedPrivateBusStream {
    pub const fn sender(&self) -> SenderIdentity {
        self.sender
    }

    pub fn buffered(&self) -> &[u8] {
        &self.buffered
    }

    pub fn into_parts(self) -> (SenderIdentity, Vec<u8>) {
        (self.sender, self.buffered)
    }
}

fn line_argument<'a>(line: &'a [u8], word: &[u8]) -> Option<Option<&'a [u8]>> {
    if line == word {
        Some(None)
    } else {
        line.strip_prefix(word)
            .and_then(|rest| rest.strip_prefix(b" "))
            .map(Some)
    }
}

fn verify_external_token(argument: Option<&[u8]>, peer_uid: u32) -> bool {
    let Some(encoded) = argument else {
        return true;
    };
    if encoded.len() % 2 != 0 {
        return false;
    }

    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.chunks_exact(2) {
        let Some(high) = decode_hex_digit(pair[0]) else {
            return false;
        };
        let Some(low) = decode_hex_digit(pair[1]) else {
            return false;
        };
        decoded.push((high << 4) | low);
    }
    if decoded.is_empty() || decoded.contains(&0) {
        return false;
    }

    parse_external_uid(&decoded) == Some(peer_uid)
}

/// Match C's `parse_uid()` rules used by `verify_external_token()`. The
/// authentication token is textual, but it must be a canonical UID spelling,
/// not merely a value that Rust can parse as `u32`.
fn parse_external_uid(decoded: &[u8]) -> Option<u32> {
    if decoded.is_empty()
        || (decoded.len() > 1 && decoded[0] == b'0')
        || !decoded.iter().all(u8::is_ascii_digit)
    {
        return None;
    }

    let uid = std::str::from_utf8(decoded).ok()?.parse::<u32>().ok()?;
    // `uid_is_valid()` in src/basic/user-util.c rejects both libc's invalid
    // UID sentinel and the legacy 16-bit sentinel.
    if uid == u32::MAX || uid == u32::from(u16::MAX) {
        return None;
    }
    Some(uid)
}

const fn decode_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_ID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn peer(uid: u32) -> AuthenticatedPeer {
        AuthenticatedPeer::from_kernel_peer_credentials(42, uid, 7)
    }

    fn auth(uid: u32) -> PrivateBusServerAuth {
        PrivateBusServerAuth::new(peer(uid), uid, SERVER_ID).unwrap()
    }

    fn consume_all(auth: &mut PrivateBusServerAuth) -> ServerAuthProgress {
        let count = auth.pending_output().len();
        auth.consume_output(count).unwrap()
    }

    #[test]
    fn rejects_peer_before_protocol_authentication() {
        assert!(matches!(
            PrivateBusServerAuth::new(peer(1001), 1000, SERVER_ID),
            Err(ServerAuthError::UnprivilegedPeer)
        ));
        assert!(PrivateBusServerAuth::new(peer(0), 1000, SERVER_ID).is_ok());
        assert!(PrivateBusServerAuth::new(peer(1000), 1000, SERVER_ID).is_ok());
    }

    #[test]
    fn fragmented_external_challenge_retains_kernel_identity_and_binary_bytes() {
        let mut auth = auth(1000);
        assert_eq!(
            auth.receive(b"\0AUTH EXTER"),
            Ok(ServerAuthProgress::Authenticating)
        );
        assert_eq!(
            auth.receive(b"NAL\r\n"),
            Ok(ServerAuthProgress::Authenticating)
        );
        assert_eq!(auth.pending_output(), DATA_RESPONSE);
        assert_eq!(consume_all(&mut auth), ServerAuthProgress::Authenticating);

        assert_eq!(
            auth.receive(b"DATA 31303030\r\n"),
            Ok(ServerAuthProgress::Authenticating)
        );
        assert_eq!(
            auth.pending_output(),
            b"OK 00112233445566778899aabbccddeeff\r\n"
        );
        assert_eq!(consume_all(&mut auth), ServerAuthProgress::Authenticating);

        assert_eq!(
            auth.receive(b"BEGIN\r\nbinary"),
            Ok(ServerAuthProgress::Authenticated)
        );
        let stream = auth.into_authenticated().unwrap();
        assert_eq!(stream.sender().peer(), peer(1000));
        assert_eq!(stream.buffered(), b"binary");
    }

    #[test]
    fn pipelined_begin_waits_for_partial_nonblocking_output_drain() {
        let mut auth = auth(0);
        assert_eq!(
            auth.receive(b"\0AUTH EXTERNAL 30\r\nBEGIN\r\nmessage"),
            Ok(ServerAuthProgress::Authenticating)
        );
        assert_eq!(auth.pending_output().len(), 37);

        assert_eq!(
            auth.consume_output(10),
            Ok(ServerAuthProgress::Authenticating)
        );
        assert_eq!(auth.pending_output().len(), 27);
        assert_eq!(
            auth.consume_output(27),
            Ok(ServerAuthProgress::Authenticated)
        );
        assert_eq!(auth.into_authenticated().unwrap().buffered(), b"message");
    }

    #[test]
    fn external_token_must_match_kernel_uid() {
        let mut auth = auth(1000);
        assert_eq!(
            auth.receive(b"\0AUTH EXTERNAL 31303031\r\n"),
            Ok(ServerAuthProgress::Authenticating)
        );
        assert_eq!(auth.pending_output(), REJECTED_RESPONSE);
        consume_all(&mut auth);

        assert_eq!(
            auth.receive(b"BEGIN\r\n"),
            Ok(ServerAuthProgress::Authenticating)
        );
        assert_eq!(auth.pending_output(), ERROR_RESPONSE);
    }

    #[test]
    fn external_token_requires_canonical_uid_spelling() {
        let mut auth = auth(1000);
        // C's parse_uid(), called by verify_external_token(), rejects a
        // leading zero even though it denotes the same numeric UID.
        auth.receive(b"\0AUTH EXTERNAL 3031303030\r\n").unwrap();
        assert_eq!(auth.pending_output(), REJECTED_RESPONSE);

        assert!(!verify_external_token(Some(b"3031303030"), 1000));
        assert!(!verify_external_token(Some(b"2b31303030"), 1000));
        assert!(!verify_external_token(
            Some(b"3635353335"),
            u32::from(u16::MAX)
        ));
        assert!(!verify_external_token(
            Some(b"34323934393637323935"),
            u32::MAX
        ));
        assert!(verify_external_token(Some(b"30"), 0));
    }

    #[test]
    fn fd_negotiation_is_not_advertised_by_a_fd_rejecting_wire() {
        let mut auth = auth(0);
        auth.receive(b"\0AUTH EXTERNAL 30\r\n").unwrap();
        consume_all(&mut auth);
        auth.receive(b"NEGOTIATE_UNIX_FD\r\n").unwrap();
        assert_eq!(auth.pending_output(), ERROR_RESPONSE);
    }

    #[test]
    fn rejects_missing_nul_and_oversized_auth_without_growing_input() {
        let mut missing_nul = auth(0);
        assert_eq!(
            missing_nul.receive(b"AUTH EXTERNAL\r\n"),
            Err(ServerAuthError::MissingInitialNul)
        );

        let mut oversized = auth(0);
        let full = vec![0; MAX_AUTH_SIZE];
        assert_eq!(
            oversized.receive(&full),
            Ok(ServerAuthProgress::Authenticating)
        );
        assert_eq!(oversized.remaining_input_capacity(), 0);
        assert_eq!(oversized.receive(&[0]), Err(ServerAuthError::InputTooLarge));
        assert_eq!(oversized.remaining_input_capacity(), 0);
    }

    #[test]
    fn output_consumption_is_checked() {
        let mut auth = auth(0);
        auth.receive(b"\0BEGIN\r\n").unwrap();
        assert_eq!(
            auth.consume_output(ERROR_RESPONSE.len() + 1),
            Err(ServerAuthError::InvalidOutputConsumption)
        );
        assert_eq!(auth.pending_output(), ERROR_RESPONSE);
    }

    #[test]
    fn hostile_response_amplification_is_bounded() {
        let mut bytes = vec![0];
        for _ in 0..(MAX_AUTH_SIZE / ERROR_RESPONSE.len() + 1) {
            bytes.extend_from_slice(b"x\r\n");
        }
        assert!(bytes.len() < MAX_AUTH_SIZE);

        let mut auth = auth(0);
        assert_eq!(auth.receive(&bytes), Err(ServerAuthError::OutputTooLarge));
        assert!(auth.pending_output().len() <= MAX_AUTH_SIZE);
    }
}
