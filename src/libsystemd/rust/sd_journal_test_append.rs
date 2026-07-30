// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-journal-append.c
//
// In-memory journal corruption-and-append reproducer.

pub const RANDOM_START_OFFSET: u64 = u64::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalMessage {
    pub offset: u64,
    pub content: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MockJournalFile {
    pub data: Vec<u8>,
    pub messages: Vec<JournalMessage>,
    pub corrupted: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendReport {
    pub initial_messages: usize,
    pub appended_messages: usize,
    pub reopen_failed: bool,
    pub corruption_points: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    EmptyMessage,
    InvalidStartOffset,
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyMessage => f.write_str("message must not be empty"),
            Self::InvalidStartOffset => f.write_str("start offset must be within the journal"),
        }
    }
}

impl std::error::Error for JournalError {}

impl MockJournalFile {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            messages: Vec::new(),
            corrupted: Vec::new(),
        }
    }

    pub fn append_message(&mut self, message: &str) -> Result<u64, JournalError> {
        if message.is_empty() {
            return Err(JournalError::EmptyMessage);
        }
        let offset = self.data.len() as u64;
        self.data.extend_from_slice(message.as_bytes());
        self.messages.push(JournalMessage {
            offset,
            content: message.into(),
        });
        Ok(offset)
    }

    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }

    pub fn corrupt_byte(&mut self, offset: u64) -> bool {
        let Some(byte) = self.data.get_mut(offset as usize) else {
            return false;
        };
        *byte |= 0x01;
        self.corrupted.push(offset);
        true
    }

    pub fn reopen(&self) -> bool {
        self.corrupted.len() <= 100
    }
}

pub fn journal_corrupt_and_append(
    mut journal: MockJournalFile,
    start_offset: u64,
    step: u64,
) -> Result<AppendReport, JournalError> {
    for i in 0..10 {
        journal.append_message(&format!("MESSAGE=Initial message {i}"))?;
    }

    let start = if start_offset == RANDOM_START_OFFSET {
        0
    } else {
        start_offset
    };
    if start >= journal.size() {
        return Err(JournalError::InvalidStartOffset);
    }

    let mut appended_messages = 0;
    let end = journal.size();
    for offset in (start..end).step_by(step.max(1) as usize) {
        journal.corrupt_byte(offset);
        if !journal.reopen() {
            return Ok(AppendReport {
                initial_messages: 10,
                appended_messages,
                reopen_failed: true,
                corruption_points: journal.corrupted,
            });
        }
        let message = format!("MESSAGE=Hello world {offset}");
        if journal.append_message(&message).is_ok() {
            appended_messages += 1;
        } else {
            break;
        }
    }

    Ok(AppendReport {
        initial_messages: 10,
        appended_messages,
        reopen_failed: false,
        corruption_points: journal.corrupted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_message_records_offsets() {
        let mut journal = MockJournalFile::new();
        assert_eq!(journal.append_message("MESSAGE=x").unwrap(), 0);
        assert_eq!(journal.messages[0].offset, 0);
    }

    #[test]
    fn empty_message_is_rejected() {
        assert_eq!(
            MockJournalFile::new().append_message("").unwrap_err(),
            JournalError::EmptyMessage
        );
    }

    #[test]
    fn corruption_flips_existing_byte_only() {
        let mut journal = MockJournalFile::new();
        journal.append_message("A").unwrap();
        assert!(journal.corrupt_byte(0));
        assert!(!journal.corrupt_byte(10));
    }

    #[test]
    fn reopen_succeeds_for_small_corruption_sets() {
        let mut journal = MockJournalFile::new();
        journal.append_message("AAAA").unwrap();
        journal.corrupt_byte(0);
        assert!(journal.reopen());
    }

    #[test]
    fn reopen_fails_for_heavy_corruption() {
        let mut journal = MockJournalFile::new();
        journal.data = vec![0; 101];
        journal.corrupted = (0..101).collect();
        assert!(!journal.reopen());
    }

    #[test]
    fn corrupt_and_append_seeds_initial_messages() {
        let report =
            journal_corrupt_and_append(MockJournalFile::new(), RANDOM_START_OFFSET, 31).unwrap();
        assert_eq!(report.initial_messages, 10);
    }

    #[test]
    fn invalid_start_offset_is_reported() {
        assert_eq!(
            journal_corrupt_and_append(MockJournalFile::new(), 10_000, 31).unwrap_err(),
            JournalError::InvalidStartOffset
        );
    }

    #[test]
    fn sequential_corruption_records_offsets() {
        let report =
            journal_corrupt_and_append(MockJournalFile::new(), RANDOM_START_OFFSET, 5).unwrap();
        assert!(!report.corruption_points.is_empty());
    }

    #[test]
    fn appended_messages_are_counted() {
        let report =
            journal_corrupt_and_append(MockJournalFile::new(), RANDOM_START_OFFSET, 31).unwrap();
        assert!(report.appended_messages <= report.corruption_points.len());
    }
}
