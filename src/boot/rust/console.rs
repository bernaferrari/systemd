// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/console.c
//
// Console management for the systemd-boot EFI bootloader.
//
// Handles console mode selection, screen resolution queries, key input
// reading with timeout support, and automatic mode detection for
// high-resolution displays.

// ── Constants ─────────────────────────────────────────────────────────────

/// System font width in pixels.
pub const SYSTEM_FONT_WIDTH: u32 = 8;
/// System font height in pixels.
pub const SYSTEM_FONT_HEIGHT: u32 = 19;
/// Maximum acceptable horizontal resolution (Full HD).
pub const HORIZONTAL_MAX_OK: u32 = 1920;
/// Maximum acceptable vertical resolution (Full HD).
pub const VERTICAL_MAX_OK: u32 = 1080;
/// Ratio of screen area to text viewport area threshold.
pub const VIEWPORT_RATIO: u64 = 10;

/// Console mode: 80x25 text mode.
pub const CONSOLE_MODE_80_25: i64 = 0;
/// Console mode: 80x50 text mode.
pub const CONSOLE_MODE_80_50: i64 = 1;
/// First firmware-specific mode.
pub const CONSOLE_MODE_FIRMWARE_FIRST: i64 = 2;

/// Special mode: keep current mode.
pub const CONSOLE_MODE_KEEP: i64 = -1;
/// Special mode: auto-select best mode.
pub const CONSOLE_MODE_AUTO: i64 = -2;
/// Special mode: next available mode.
pub const CONSOLE_MODE_NEXT: i64 = -3;
/// Special mode: maximum firmware mode.
pub const CONSOLE_MODE_FIRMWARE_MAX: i64 = -4;

/// Minimum valid console mode number.
pub const CONSOLE_MODE_RANGE_MIN: i64 = 0;
/// Maximum valid console mode number.
pub const CONSOLE_MODE_RANGE_MAX: i64 = 255;

/// Default watchdog timeout in seconds.
pub const WATCHDOG_TIMEOUT_SEC: u64 = 5 * 60;

/// Watchdog ping interval in microseconds (half the timeout).
pub const WATCHDOG_PING_USEC: u64 = WATCHDOG_TIMEOUT_SEC / 2 * 1_000_000;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur during console operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleError {
    /// Failed to create a timer event.
    TimerCreateFailed,
    /// Failed to arm the timer.
    TimerArmFailed,
    /// Error waiting for events.
    WaitForEventFailed,
    /// Input timeout expired.
    Timeout,
    /// Failed to change console mode.
    ModeChangeFailed,
    /// Failed to query screen resolution.
    ResolutionQueryFailed,
    /// The device reported an error.
    DeviceError,
    /// No modes are available.
    NoModes,
    /// Invalid mode number.
    InvalidMode,
    /// Console input not ready.
    NotReady,
}

impl std::fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsoleError::TimerCreateFailed => write!(f, "failed to create timer event"),
            ConsoleError::TimerArmFailed => write!(f, "failed to arm timer event"),
            ConsoleError::WaitForEventFailed => write!(f, "error waiting for events"),
            ConsoleError::Timeout => write!(f, "input timeout expired"),
            ConsoleError::ModeChangeFailed => write!(f, "failed to change console mode"),
            ConsoleError::ResolutionQueryFailed => write!(f, "failed to query screen resolution"),
            ConsoleError::DeviceError => write!(f, "device error"),
            ConsoleError::NoModes => write!(f, "no modes available"),
            ConsoleError::InvalidMode => write!(f, "invalid mode number"),
            ConsoleError::NotReady => write!(f, "console input not ready"),
        }
    }
}

impl std::error::Error for ConsoleError {}

// ── Data structures ───────────────────────────────────────────────────────

/// Information about the current console state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleState {
    /// Current mode number.
    pub current_mode: i64,
    /// Total number of available modes.
    pub max_mode: i64,
}

impl ConsoleState {
    /// Create a new console state with the given mode info.
    pub fn new(current_mode: i64, max_mode: i64) -> Self {
        Self {
            current_mode,
            max_mode,
        }
    }

    /// Check if the current mode is valid.
    pub fn is_mode_valid(&self) -> bool {
        self.current_mode >= CONSOLE_MODE_RANGE_MIN && self.current_mode < self.max_mode
    }
}

/// Screen resolution dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenResolution {
    pub width: u32,
    pub height: u32,
}

impl ScreenResolution {
    pub fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }

    /// Check if this resolution is at or below Full HD.
    pub fn is_acceptable(&self) -> bool {
        self.width <= HORIZONTAL_MAX_OK && self.height <= VERTICAL_MAX_OK
    }

    /// Calculate the total screen area in pixels.
    pub fn area(&self) -> u64 {
        self.width as u64 * self.height as u64
    }
}

// ── Core functions ────────────────────────────────────────────────────────

/// Determine the next mode number when cycling through available modes.
///
/// `direction` should be 1 (forward) or -1 (backward).
/// Wraps around when reaching the limits of the available mode range.
pub fn next_mode(mode: i64, direction: i64, max_mode: i64) -> i64 {
    assert!(direction == 1 || direction == -1);
    assert!(max_mode > 0);

    if direction > 0 {
        if mode < CONSOLE_MODE_RANGE_MIN || mode >= max_mode - 1 {
            return CONSOLE_MODE_RANGE_MIN;
        }
    } else {
        if mode <= CONSOLE_MODE_RANGE_MIN || mode > max_mode - 1 {
            return max_mode - 1;
        }
    }

    mode + direction
}

/// Determine the optimal console mode automatically.
///
/// Checks the screen resolution and text viewport area ratio.
/// If the text is readable (resolution <= Full HD or viewport ratio < 10),
/// keeps the current mode. Otherwise tries firmware-specific modes.
pub fn get_auto_mode(
    current_mode: i64,
    max_mode: i64,
    resolution: Option<ScreenResolution>,
    text_area: u64,
) -> i64 {
    if let Some(res) = resolution {
        if res.is_acceptable() {
            return current_mode;
        }

        let screen_area = res.area();
        if text_area != 0 && screen_area / text_area < VIEWPORT_RATIO {
            return current_mode;
        }
    }

    // High resolution with tiny text - try better modes
    if max_mode > CONSOLE_MODE_FIRMWARE_FIRST {
        return CONSOLE_MODE_FIRMWARE_FIRST;
    }
    if max_mode > CONSOLE_MODE_80_50 {
        return CONSOLE_MODE_80_50;
    }

    CONSOLE_MODE_80_25
}

/// Select the target mode for `console_set_mode`.
///
/// Maps special mode constants to actual mode numbers.
pub fn select_target_mode(
    requested_mode: i64,
    state: &ConsoleState,
    resolution: Option<ScreenResolution>,
    text_area: u64,
) -> Result<(i64, i64), ConsoleError> {
    if state.max_mode <= 0 {
        return if requested_mode == CONSOLE_MODE_KEEP {
            Ok((CONSOLE_MODE_80_25, 1))
        } else {
            Err(ConsoleError::NoModes)
        };
    }

    let (target, direction) = match requested_mode {
        CONSOLE_MODE_KEEP => {
            if state.is_mode_valid() {
                return Ok((state.current_mode, 1));
            }
            (CONSOLE_MODE_RANGE_MIN, 1)
        }
        CONSOLE_MODE_NEXT => (next_mode(state.current_mode, 1, state.max_mode), 1),
        CONSOLE_MODE_AUTO => (
            get_auto_mode(state.current_mode, state.max_mode, resolution, text_area),
            1,
        ),
        CONSOLE_MODE_FIRMWARE_MAX => (state.max_mode - 1, -1),
        m if m >= CONSOLE_MODE_RANGE_MIN && m <= CONSOLE_MODE_RANGE_MAX => (m, 1),
        _ => return Err(ConsoleError::InvalidMode),
    };

    Ok((target, direction))
}

/// Calculate the text viewport area based on console dimensions.
pub fn calculate_text_area(cols: usize, rows: usize) -> u64 {
    SYSTEM_FONT_WIDTH as u64 * SYSTEM_FONT_HEIGHT as u64 * cols as u64 * rows as u64
}

/// Get fallback console dimensions for a given mode number.
pub fn fallback_mode_dimensions(mode: i64) -> (usize, usize) {
    match mode {
        CONSOLE_MODE_80_50 => (80, 50),
        _ => (80, 25),
    }
}

/// Calculate the watchdog ping interval for a given timeout.
///
/// Returns the effective wait time in microseconds, which is the minimum
/// of the requested timeout and half the watchdog period.
pub fn calculate_watchdog_ping(timeout_usec: u64) -> u64 {
    std::cmp::min(timeout_usec, WATCHDOG_PING_USEC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_mode_forward() {
        assert_eq!(next_mode(0, 1, 5), 1);
        assert_eq!(next_mode(3, 1, 5), 4);
    }

    #[test]
    fn test_next_mode_forward_wrap() {
        assert_eq!(next_mode(4, 1, 5), 0);
        assert_eq!(next_mode(-1, 1, 5), 0);
    }

    #[test]
    fn test_next_mode_backward() {
        assert_eq!(next_mode(3, -1, 5), 2);
        assert_eq!(next_mode(4, -1, 5), 3);
    }

    #[test]
    fn test_next_mode_backward_wrap() {
        assert_eq!(next_mode(0, -1, 5), 4);
    }

    #[test]
    fn test_screen_resolution_acceptable() {
        assert!(ScreenResolution::new(1920, 1080).is_acceptable());
        assert!(ScreenResolution::new(1280, 720).is_acceptable());
    }

    #[test]
    fn test_screen_resolution_unacceptable() {
        assert!(!ScreenResolution::new(2560, 1440).is_acceptable());
        assert!(!ScreenResolution::new(3840, 2160).is_acceptable());
    }

    #[test]
    fn test_screen_resolution_area() {
        let res = ScreenResolution::new(1920, 1080);
        assert_eq!(res.area(), 2_073_600);
    }

    #[test]
    fn test_get_auto_mode_keep_current() {
        // Full HD or smaller should keep current mode
        let res = ScreenResolution::new(1920, 1080);
        assert_eq!(get_auto_mode(1, 5, Some(res), 0), 1);
    }

    #[test]
    fn test_get_auto_mode_high_res_with_viewport() {
        // High res but good viewport ratio
        let res = ScreenResolution::new(3840, 2160);
        let text_area = res.area() / 5; // ratio would be 5, which is < 10
        assert_eq!(get_auto_mode(1, 5, Some(res), text_area), 1);
    }

    #[test]
    fn test_get_auto_mode_high_res_tiny_text() {
        let res = ScreenResolution::new(3840, 2160);
        let text_area = 100; // Very small text area
        assert_eq!(get_auto_mode(1, 5, Some(res), text_area), 2); // FIRMWARE_FIRST
    }

    #[test]
    fn test_get_auto_mode_no_firmware_modes() {
        let res = ScreenResolution::new(3840, 2160);
        assert_eq!(get_auto_mode(1, 2, Some(res), 100), 1); // Falls to 80x50
    }

    #[test]
    fn test_console_state_valid() {
        let state = ConsoleState::new(1, 5);
        assert!(state.is_mode_valid());
    }

    #[test]
    fn test_console_state_invalid() {
        let state = ConsoleState::new(-1, 5);
        assert!(!state.is_mode_valid());
        let state = ConsoleState::new(5, 5);
        assert!(!state.is_mode_valid());
    }

    #[test]
    fn test_select_target_mode_keep() {
        let state = ConsoleState::new(1, 5);
        let (target, _) = select_target_mode(CONSOLE_MODE_KEEP, &state, None, 0).unwrap();
        assert_eq!(target, 1);
    }

    #[test]
    fn test_select_target_mode_next() {
        let state = ConsoleState::new(1, 5);
        let (target, _) = select_target_mode(CONSOLE_MODE_NEXT, &state, None, 0).unwrap();
        assert_eq!(target, 2);
    }

    #[test]
    fn test_select_target_mode_firmware_max() {
        let state = ConsoleState::new(1, 5);
        let (target, dir) = select_target_mode(CONSOLE_MODE_FIRMWARE_MAX, &state, None, 0).unwrap();
        assert_eq!(target, 4);
        assert_eq!(dir, -1);
    }

    #[test]
    fn test_select_target_mode_specific() {
        let state = ConsoleState::new(0, 5);
        let (target, _) = select_target_mode(3, &state, None, 0).unwrap();
        assert_eq!(target, 3);
    }

    #[test]
    fn test_calculate_text_area() {
        assert_eq!(calculate_text_area(80, 25), 8 * 19 * 80 * 25);
    }

    #[test]
    fn test_fallback_mode_dimensions() {
        assert_eq!(fallback_mode_dimensions(CONSOLE_MODE_80_50), (80, 50));
        assert_eq!(fallback_mode_dimensions(CONSOLE_MODE_80_25), (80, 25));
        assert_eq!(fallback_mode_dimensions(99), (80, 25));
    }

    #[test]
    fn test_calculate_watchdog_ping() {
        assert_eq!(calculate_watchdog_ping(u64::MAX), WATCHDOG_PING_USEC);
        assert_eq!(calculate_watchdog_ping(1000), 1000);
    }
}
