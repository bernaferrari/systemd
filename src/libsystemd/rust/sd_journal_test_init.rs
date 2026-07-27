// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-journal-init.c

const NEG_ECHILD: i32 = -(libc::ECHILD as i32);
const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
pub const SD_JOURNAL_ASSUME_IMMUTABLE: i32 = 2;
pub const SD_JOURNAL_LOCAL_ONLY: i32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Location {
    Head,
    Tail,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockJournal {
    is_open: bool,
    current_location: Location,
}

impl MockJournal {
    pub fn open(flags: i32) -> Result<Self, i32> {
        let valid = SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_ASSUME_IMMUTABLE;
        if flags & !valid != 0 {
            return Err(NEG_EINVAL);
        }
        Ok(Self {
            is_open: true,
            current_location: Location::Head,
        })
    }

    pub fn open_directory(_path: &str, flags: i32) -> Result<Self, i32> {
        if flags == SD_JOURNAL_LOCAL_ONLY {
            return Err(NEG_EINVAL);
        }
        Ok(Self {
            is_open: true,
            current_location: Location::Head,
        })
    }

    pub fn seek_head(&mut self) -> Result<(), i32> {
        self.current_location = Location::Head;
        Ok(())
    }

    pub fn seek_tail(&mut self) -> Result<(), i32> {
        self.current_location = Location::Tail;
        Ok(())
    }

    pub fn get_realtime_usec(&self, is_child: bool) -> Result<u64, i32> {
        if is_child {
            return Err(NEG_ECHILD);
        }
        if !self.is_open {
            return Err(NEG_EINVAL);
        }
        Ok(0)
    }

    pub fn close(&mut self) {
        self.is_open = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_with_valid_flags_succeeds() {
        assert!(MockJournal::open(SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_ASSUME_IMMUTABLE).is_ok());
    }

    #[test]
    fn open_with_invalid_flags_fails() {
        assert_eq!(MockJournal::open(8), Err(NEG_EINVAL));
    }

    #[test]
    fn open_directory_with_local_only_is_rejected() {
        assert_eq!(
            MockJournal::open_directory("/tmp", SD_JOURNAL_LOCAL_ONLY),
            Err(NEG_EINVAL)
        );
    }

    #[test]
    fn seek_head_sets_expected_location() {
        let mut j = MockJournal::open(0).unwrap();
        j.seek_tail().unwrap();
        j.seek_head().unwrap();
        assert_eq!(j.current_location, Location::Head);
    }

    #[test]
    fn seek_tail_sets_expected_location() {
        let mut j = MockJournal::open(0).unwrap();
        j.seek_tail().unwrap();
        assert_eq!(j.current_location, Location::Tail);
    }

    #[test]
    fn child_access_is_rejected() {
        let j = MockJournal::open(0).unwrap();
        assert_eq!(j.get_realtime_usec(true), Err(NEG_ECHILD));
    }

    #[test]
    fn closed_journal_rejects_realtime_queries() {
        let mut j = MockJournal::open(0).unwrap();
        j.close();
        assert_eq!(j.get_realtime_usec(false), Err(NEG_EINVAL));
    }

    #[test]
    fn repeated_open_close_cycles_work() {
        for _ in 0..4 {
            let mut j = MockJournal::open(0).unwrap();
            j.close();
            assert_eq!(j.get_realtime_usec(false), Err(NEG_EINVAL));
        }
    }
}
