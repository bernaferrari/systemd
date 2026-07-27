// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-journal-flush.c

const NEG_EBADMSG: i32 = -(libc::EBADMSG as i32);
const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
const NEG_EIO: i32 = -(libc::EIO as i32);
const NEG_EPROTONOSUPPORT: i32 = -(libc::EPROTONOSUPPORT as i32);
const NEG_EREMCHG: i32 = -78;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalState {
    Online,
    Archive,
    Offline,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntry {
    pub seqnum: u64,
    pub message: String,
    pub copy_error: Option<i32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MockJournal {
    pub entries: Vec<JournalEntry>,
    pub position: Option<usize>,
    pub state: Option<JournalState>,
}

pub fn copy_entry(entry: &JournalEntry, destination: &mut MockJournal) -> Result<(), i32> {
    if let Some(code) = entry.copy_error {
        if matches!(
            code,
            NEG_EBADMSG | NEG_EPROTONOSUPPORT | NEG_EIO | NEG_EREMCHG
        ) {
            return Err(code);
        }
        return Err(NEG_EINVAL);
    }
    destination.entries.push(entry.clone());
    Ok(())
}

pub fn flush_journal(source: &MockJournal, limit: usize) -> Result<MockJournal, i32> {
    let mut destination = MockJournal {
        entries: Vec::new(),
        position: None,
        state: Some(JournalState::Online),
    };
    for entry in source.entries.iter().take(limit) {
        let _ = copy_entry(entry, &mut destination);
    }
    if destination.entries.is_empty() {
        return Err(NEG_EINVAL);
    }
    Ok(destination)
}

impl MockJournal {
    pub fn seek_tail(&mut self) -> Result<(), i32> {
        self.position = self.entries.len().checked_sub(1);
        Ok(())
    }

    pub fn step_one(&mut self) -> Result<bool, i32> {
        match self.position {
            Some(idx) if idx < self.entries.len() => Ok(true),
            _ => Err(NEG_EINVAL),
        }
    }

    pub fn current_message(&self) -> Result<&str, i32> {
        let idx = self.position.ok_or(NEG_EINVAL)?;
        Ok(self.entries.get(idx).ok_or(NEG_EINVAL)?.message.as_str())
    }

    pub fn archive(&mut self) -> Result<(), i32> {
        self.state = Some(JournalState::Archive);
        Ok(())
    }

    pub fn set_offline(&mut self) -> Result<(), i32> {
        if self.state != Some(JournalState::Archive) {
            return Err(NEG_EINVAL);
        }
        self.state = Some(JournalState::Offline);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> MockJournal {
        MockJournal {
            entries: vec![
                JournalEntry {
                    seqnum: 1,
                    message: "one".into(),
                    copy_error: None,
                },
                JournalEntry {
                    seqnum: 2,
                    message: "two".into(),
                    copy_error: Some(NEG_EBADMSG),
                },
                JournalEntry {
                    seqnum: 3,
                    message: "three".into(),
                    copy_error: None,
                },
            ],
            position: None,
            state: Some(JournalState::Online),
        }
    }

    #[test]
    fn copy_entry_succeeds_for_clean_entries() {
        let mut dst = MockJournal::default();
        assert_eq!(copy_entry(&source().entries[0], &mut dst), Ok(()));
        assert_eq!(dst.entries.len(), 1);
    }

    #[test]
    fn allowed_copy_error_is_returned() {
        let mut dst = MockJournal::default();
        assert_eq!(copy_entry(&source().entries[1], &mut dst), Err(NEG_EBADMSG));
    }

    #[test]
    fn flush_copies_only_successful_entries() {
        let dst = flush_journal(&source(), 10).unwrap();
        assert_eq!(
            dst.entries.iter().map(|e| e.seqnum).collect::<Vec<_>>(),
            vec![1, 3]
        );
    }

    #[test]
    fn flush_requires_at_least_one_copied_entry() {
        let src = MockJournal {
            entries: vec![JournalEntry {
                seqnum: 1,
                message: "x".into(),
                copy_error: Some(NEG_EIO),
            }],
            ..MockJournal::default()
        };
        assert_eq!(flush_journal(&src, 10), Err(NEG_EINVAL));
    }

    #[test]
    fn seek_tail_points_to_last_entry() {
        let mut dst = flush_journal(&source(), 10).unwrap();
        dst.seek_tail().unwrap();
        assert_eq!(dst.current_message().unwrap(), "three");
    }

    #[test]
    fn step_one_requires_valid_position() {
        assert_eq!(
            flush_journal(&source(), 10).unwrap().step_one(),
            Err(NEG_EINVAL)
        );
    }

    #[test]
    fn archive_then_offline_matches_lifecycle() {
        let mut dst = flush_journal(&source(), 10).unwrap();
        dst.archive().unwrap();
        dst.set_offline().unwrap();
        assert_eq!(dst.state, Some(JournalState::Offline));
    }

    #[test]
    fn offline_requires_archive_first() {
        let mut dst = flush_journal(&source(), 10).unwrap();
        assert_eq!(dst.set_offline(), Err(NEG_EINVAL));
    }
}
