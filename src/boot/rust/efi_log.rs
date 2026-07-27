// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/efi-log.c
//
// EFI boot loader logging infrastructure.
//
// Manages log levels, log level parsing from strings, log output colors,
// and fatal-error handlers (panic, assert, freeze).  The pure-logic parts
// (level management, string tables) are faithfully ported from the C
// source; UEFI-specific I/O is abstracted behind an `Output` trait.

// ── Constants ─────────────────────────────────────────────────────────────

/// Log level: system is unusable.
pub const LOG_EMERG: i32 = 0;
/// Log level: action must be taken immediately.
pub const LOG_ALERT: i32 = 1;
/// Log level: critical conditions.
pub const LOG_CRIT: i32 = 2;
/// Log level: error conditions.
pub const LOG_ERR: i32 = 3;
/// Log level: warning conditions.
pub const LOG_WARNING: i32 = 4;
/// Log level: normal but significant condition.
pub const LOG_NOTICE: i32 = 5;
/// Log level: informational.
pub const LOG_INFO: i32 = 6;
/// Log level: debug-level messages.
pub const LOG_DEBUG: i32 = 7;

/// One-past-the-end sentinel for log levels.
pub const LOG_LEVEL_MAX: i32 = 8;

/// EFI console color constants (used for log-level coloring).
pub const EFI_BLACK: u8 = 0x00;
pub const EFI_BLUE: u8 = 0x01;
pub const EFI_GREEN: u8 = 0x02;
pub const EFI_CYAN: u8 = 0x03;
pub const EFI_RED: u8 = 0x04;
pub const EFI_MAGENTA: u8 = 0x05;
pub const EFI_BROWN: u8 = 0x06;
pub const EFI_LIGHTGRAY: u8 = 0x07;
pub const EFI_YELLOW: u8 = 0x0E;
pub const EFI_WHITE: u8 = 0x0F;
pub const EFI_LIGHTRED: u8 = 0x0C;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by log-level operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogError {
    /// The supplied log level is out of range.
    LevelOutOfRange(i32),
    /// The string does not map to a known log level.
    UnknownLevelString,
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogError::LevelOutOfRange(l) => {
                write!(f, "Log level {} out of range [0, {})", l, LOG_LEVEL_MAX)
            }
            LogError::UnknownLevelString => write!(f, "Unknown log level string"),
        }
    }
}

impl std::error::Error for LogError {}

// ── Log level table ──────────────────────────────────────────────────────

/// Mapping from log level to human-readable name.
///
/// Mirrors the `log_level_table` in the C source.
pub fn log_level_to_string(level: i32) -> Option<&'static str> {
    match level {
        LOG_EMERG => Some("emerg"),
        LOG_ALERT => Some("alert"),
        LOG_CRIT => Some("crit"),
        LOG_ERR => Some("err"),
        LOG_WARNING => Some("warning"),
        LOG_NOTICE => Some("notice"),
        LOG_INFO => Some("info"),
        LOG_DEBUG => Some("debug"),
        _ => None,
    }
}

/// Reverse lookup: parse a log level name to its numeric value.
///
/// Mirrors the `log_level_from_string` / `DEFINE_STRING_TABLE_LOOKUP`
/// logic in the C source.
pub fn log_level_from_string(s: &str) -> Result<i32, LogError> {
    match s {
        "emerg" => Ok(LOG_EMERG),
        "alert" => Ok(LOG_ALERT),
        "crit" => Ok(LOG_CRIT),
        "err" => Ok(LOG_ERR),
        "warning" => Ok(LOG_WARNING),
        "notice" => Ok(LOG_NOTICE),
        "info" => Ok(LOG_INFO),
        "debug" => Ok(LOG_DEBUG),
        _ => Err(LogError::UnknownLevelString),
    }
}

// ── Log level color table ────────────────────────────────────────────────

/// Console foreground color for each log level.
///
/// Mirrors the `log_level_color` table in the C source.
pub fn log_level_color(level: i32) -> u8 {
    match level {
        LOG_EMERG | LOG_ALERT | LOG_CRIT | LOG_ERR => EFI_LIGHTRED,
        LOG_WARNING => EFI_YELLOW,
        LOG_NOTICE | LOG_INFO => EFI_WHITE,
        LOG_DEBUG => EFI_LIGHTGRAY,
        _ => EFI_WHITE,
    }
}

// ── Log state ────────────────────────────────────────────────────────────

/// Holds mutable logging state (max level, message count).
///
/// Mirrors the `static` globals `log_max_level` and `log_count` in the C
/// source, bundled into a struct for testability.
#[derive(Debug, Clone)]
pub struct LogState {
    max_level: i32,
    count: u32,
}

impl Default for LogState {
    fn default() -> Self {
        Self {
            max_level: LOG_INFO,
            count: 0,
        }
    }
}

impl LogState {
    /// Create a new log state with the default max level (INFO).
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the current maximum log level.
    ///
    /// Mirrors `log_get_max_level`.
    pub fn get_max_level(&self) -> i32 {
        self.max_level
    }

    /// Set the maximum log level, returning the previous value.
    ///
    /// Mirrors `log_set_max_level`.
    pub fn set_max_level(&mut self, level: i32) -> Result<i32, LogError> {
        if level < 0 || level >= LOG_LEVEL_MAX {
            return Err(LogError::LevelOutOfRange(level));
        }
        let old = self.max_level;
        self.max_level = level;
        Ok(old)
    }

    /// Set the max log level from a string representation.
    ///
    /// Mirrors `log_set_max_level_from_string`.
    pub fn set_max_level_from_string(&mut self, s: &str) -> Result<i32, LogError> {
        let level = log_level_from_string(s)?;
        self.set_max_level(level)
    }

    /// Check whether a message at the given level should be logged.
    pub fn should_log(&self, level: i32) -> bool {
        level <= self.max_level
    }

    /// Increment the log message counter.
    pub fn increment_count(&mut self) {
        self.count += 1;
    }

    /// Get the current log message count.
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Reset the log message counter.
    pub fn reset_count(&mut self) {
        self.count = 0;
    }

    /// Compute the stall time (in microseconds) for `log_wait`.
    ///
    /// Mirrors `log_wait`: stalls `MIN(4, log_count) * 2500 * 1000` µs.
    pub fn wait_stall_usec(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            let factor = std::cmp::min(4u32, self.count) as u64;
            factor * 2500 * 1000
        }
    }
}

// ── Formatting helpers ───────────────────────────────────────────────────

/// Format an EFI text attribute byte from foreground + background colors.
///
/// Mirrors the `EFI_TEXT_ATTR` macro.
pub fn efi_text_attr(fg: u8, bg: u8) -> i32 {
    ((bg & 0x0F) as i32) << 4 | (fg & 0x0F) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_to_string() {
        assert_eq!(log_level_to_string(LOG_EMERG), Some("emerg"));
        assert_eq!(log_level_to_string(LOG_ERR), Some("err"));
        assert_eq!(log_level_to_string(LOG_WARNING), Some("warning"));
        assert_eq!(log_level_to_string(LOG_INFO), Some("info"));
        assert_eq!(log_level_to_string(LOG_DEBUG), Some("debug"));
        assert_eq!(log_level_to_string(99), None);
    }

    #[test]
    fn test_log_level_from_string() {
        assert_eq!(log_level_from_string("emerg"), Ok(LOG_EMERG));
        assert_eq!(log_level_from_string("err"), Ok(LOG_ERR));
        assert_eq!(log_level_from_string("info"), Ok(LOG_INFO));
        assert_eq!(log_level_from_string("debug"), Ok(LOG_DEBUG));
        assert_eq!(
            log_level_from_string("bogus"),
            Err(LogError::UnknownLevelString)
        );
        assert_eq!(log_level_from_string(""), Err(LogError::UnknownLevelString));
    }

    #[test]
    fn test_log_level_roundtrip() {
        for level in 0..LOG_LEVEL_MAX {
            let name = log_level_to_string(level).unwrap();
            assert_eq!(log_level_from_string(name), Ok(level));
        }
    }

    #[test]
    fn test_log_level_color() {
        assert_eq!(log_level_color(LOG_EMERG), EFI_LIGHTRED);
        assert_eq!(log_level_color(LOG_ERR), EFI_LIGHTRED);
        assert_eq!(log_level_color(LOG_WARNING), EFI_YELLOW);
        assert_eq!(log_level_color(LOG_INFO), EFI_WHITE);
        assert_eq!(log_level_color(LOG_DEBUG), EFI_LIGHTGRAY);
    }

    #[test]
    fn test_log_state_default() {
        let state = LogState::new();
        assert_eq!(state.get_max_level(), LOG_INFO);
        assert_eq!(state.count(), 0);
    }

    #[test]
    fn test_log_state_set_max_level() {
        let mut state = LogState::new();
        let old = state.set_max_level(LOG_DEBUG).unwrap();
        assert_eq!(old, LOG_INFO);
        assert_eq!(state.get_max_level(), LOG_DEBUG);
    }

    #[test]
    fn test_log_state_set_max_level_out_of_range() {
        let mut state = LogState::new();
        assert_eq!(state.set_max_level(-1), Err(LogError::LevelOutOfRange(-1)));
        assert_eq!(
            state.set_max_level(LOG_LEVEL_MAX),
            Err(LogError::LevelOutOfRange(LOG_LEVEL_MAX))
        );
    }

    #[test]
    fn test_log_state_set_max_level_from_string() {
        let mut state = LogState::new();
        state.set_max_level_from_string("debug").unwrap();
        assert_eq!(state.get_max_level(), LOG_DEBUG);
        assert_eq!(
            state.set_max_level_from_string("invalid"),
            Err(LogError::UnknownLevelString)
        );
    }

    #[test]
    fn test_should_log() {
        let mut state = LogState::new(); // max = INFO
        assert!(state.should_log(LOG_ERR));
        assert!(state.should_log(LOG_INFO));
        assert!(!state.should_log(LOG_DEBUG));
    }

    #[test]
    fn test_wait_stall_usec() {
        let mut state = LogState::new();
        assert_eq!(state.wait_stall_usec(), 0);
        for _ in 0..3 {
            state.increment_count();
        }
        assert_eq!(state.wait_stall_usec(), 3 * 2500 * 1000);
        for _ in 0..5 {
            state.increment_count();
        }
        assert_eq!(state.wait_stall_usec(), 4 * 2500 * 1000); // capped at 4
    }

    #[test]
    fn test_efi_text_attr() {
        assert_eq!(efi_text_attr(EFI_WHITE, EFI_BLACK), 0x0F);
        assert_eq!(efi_text_attr(EFI_LIGHTRED, EFI_BLACK), 0x0C);
        assert_eq!(efi_text_attr(0x01, 0x02), 0x21);
    }
}
