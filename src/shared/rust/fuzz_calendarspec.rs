// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fuzz/fuzz-calendarspec.c
//
// Deterministic Rust fuzz harness for calendar spec parsing.

use crate::calendarspec::{calendar_spec_from_string, calendar_spec_next_usec};

pub const MAX_FUZZ_INPUT_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarFuzzOutcome {
    Skipped,
    Parsed,
}

pub fn fuzz_calendarspec(data: &[u8]) -> CalendarFuzzOutcome {
    if data.is_empty() || data.len() > MAX_FUZZ_INPUT_SIZE {
        return CalendarFuzzOutcome::Skipped;
    }

    let input = String::from_utf8_lossy(data);
    if input.trim().is_empty() {
        return CalendarFuzzOutcome::Skipped;
    }

    match calendar_spec_from_string(input.as_ref()) {
        Ok(spec) => {
            let _ = calendar_spec_next_usec(&spec, 0);
            CalendarFuzzOutcome::Parsed
        }
        Err(_) => CalendarFuzzOutcome::Skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_empty_input() {
        assert_eq!(fuzz_calendarspec(b""), CalendarFuzzOutcome::Skipped);
    }

    #[test]
    fn skips_oversized_input() {
        let input = vec![b'a'; MAX_FUZZ_INPUT_SIZE + 1];
        assert_eq!(fuzz_calendarspec(&input), CalendarFuzzOutcome::Skipped);
    }

    #[test]
    fn parses_known_expression() {
        assert_eq!(fuzz_calendarspec(b"Mon..Fri 10:15"), CalendarFuzzOutcome::Parsed);
    }

    #[test]
    fn tolerates_invalid_expression() {
        assert_eq!(
            fuzz_calendarspec(b"this is not a valid calendar expression"),
            CalendarFuzzOutcome::Skipped
        );
    }
}
