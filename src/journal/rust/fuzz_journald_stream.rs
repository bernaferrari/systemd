// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/fuzz-journald-stream.c
//
// Stdout stream protocol parsing and fuzz harness.
//
// The C version creates a socketpair, installs a stdout stream,
// writes fuzz data, and runs the event loop.  This Rust port
// provides a safe parser for the stdout stream wire protocol.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    InvalidUtf8,
    LineTooLong,
    UnknownPriority,
    InvalidStateTransition,
}

impl core::fmt::Display for StreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StreamError::InvalidUtf8 => write!(f, "invalid UTF-8 in stream data"),
            StreamError::LineTooLong => write!(f, "stream line exceeds maximum length"),
            StreamError::UnknownPriority => write!(f, "unknown priority value"),
            StreamError::InvalidStateTransition => write!(f, "invalid protocol state transition"),
        }
    }
}

impl std::error::Error for StreamError {}

pub const STDOUT_STREAM_LINE_MAX: usize = 65536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Waiting for the initial priority line.
    AwaitingPriority,
    /// Waiting for the identifier line (SYSLOG_IDENTIFIER).
    AwaitingIdentifier,
    /// Accepting message body lines.
    Running,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEvent {
    pub priority: u8,
    pub identifier: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct StreamParser {
    state: StreamState,
    priority: u8,
    identifier: Option<String>,
    events: Vec<StreamEvent>,
}

impl StreamParser {
    pub fn new() -> Self {
        Self {
            state: StreamState::AwaitingPriority,
            priority: 6,
            identifier: None,
            events: Vec::new(),
        }
    }

    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Feed raw bytes (may contain multiple lines) into the parser.
    pub fn process_data(&mut self, data: &[u8]) -> Result<Vec<StreamEvent>, StreamError> {
        let text = std::str::from_utf8(data).map_err(|_| StreamError::InvalidUtf8)?;
        let mut new_events = Vec::new();
        for line in text.split_terminator('\n') {
            if line.len() > STDOUT_STREAM_LINE_MAX {
                return Err(StreamError::LineTooLong);
            }
            if let Some(event) = self.process_line(line)? {
                new_events.push(event.clone());
                self.events.push(event);
            }
        }
        Ok(new_events)
    }

    fn process_line(&mut self, line: &str) -> Result<Option<StreamEvent>, StreamError> {
        match self.state {
            StreamState::AwaitingPriority => {
                let prio: u8 = line.parse().map_err(|_| StreamError::UnknownPriority)?;
                if prio > 7 {
                    return Err(StreamError::UnknownPriority);
                }
                self.priority = prio;
                self.state = StreamState::AwaitingIdentifier;
                Ok(None)
            }
            StreamState::AwaitingIdentifier => {
                self.identifier = if line.is_empty() {
                    None
                } else {
                    Some(line.to_string())
                };
                self.state = StreamState::Running;
                Ok(None)
            }
            StreamState::Running => Ok(Some(StreamEvent {
                priority: self.priority,
                identifier: self.identifier.clone(),
                message: line.to_string(),
            })),
        }
    }

    pub fn events(&self) -> &[StreamEvent] {
        &self.events
    }
}

impl Default for StreamParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_full_handshake() {
        let mut parser = StreamParser::new();
        let events = parser.process_data(b"6\nmyapp\nhello world\n").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].priority, 6);
        assert_eq!(events[0].identifier, Some("myapp".into()));
        assert_eq!(events[0].message, "hello world");
    }

    #[test]
    fn test_stream_state_transitions() {
        let mut parser = StreamParser::new();
        assert_eq!(parser.state(), StreamState::AwaitingPriority);
        parser.process_data(b"3\n").unwrap();
        assert_eq!(parser.state(), StreamState::AwaitingIdentifier);
        parser.process_data(b"testid\n").unwrap();
        assert_eq!(parser.state(), StreamState::Running);
    }

    #[test]
    fn test_stream_multiple_messages() {
        let mut parser = StreamParser::new();
        let events = parser.process_data(b"5\napp\nmsg1\nmsg2\nmsg3\n").unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].message, "msg1");
        assert_eq!(events[2].message, "msg3");
    }

    #[test]
    fn test_stream_invalid_utf8() {
        let mut parser = StreamParser::new();
        assert_eq!(
            parser.process_data(&[0xFF]).unwrap_err(),
            StreamError::InvalidUtf8
        );
    }

    #[test]
    fn test_stream_bad_priority() {
        let mut parser = StreamParser::new();
        assert_eq!(
            parser.process_data(b"abc\n").unwrap_err(),
            StreamError::UnknownPriority
        );
    }

    #[test]
    fn test_stream_priority_out_of_range() {
        let mut parser = StreamParser::new();
        assert_eq!(
            parser.process_data(b"9\n").unwrap_err(),
            StreamError::UnknownPriority
        );
    }

    #[test]
    fn test_stream_empty_identifier() {
        let mut parser = StreamParser::new();
        parser.process_data(b"6\n\n").unwrap();
        assert_eq!(parser.state(), StreamState::Running);
        let events = parser.process_data(b"msg\n").unwrap();
        assert_eq!(events[0].identifier, None);
    }

    #[test]
    fn test_stream_accumulated_events() {
        let mut parser = StreamParser::new();
        parser.process_data(b"6\nid\nfirst\n").unwrap();
        parser.process_data(b"second\n").unwrap();
        assert_eq!(parser.events().len(), 2);
    }

    #[test]
    fn test_stream_default() {
        let parser = StreamParser::default();
        assert_eq!(parser.state(), StreamState::AwaitingPriority);
    }
}
