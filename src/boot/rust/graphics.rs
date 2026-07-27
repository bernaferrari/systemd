// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/graphics.c
//
// EFI console graphics mode management.
//
// Provides switching between text and graphics screen modes via the
// EFI_CONSOLE_CONTROL_PROTOCOL. Handles the case where the protocol
// is not available (non-standard) gracefully.

// ── Constants ─────────────────────────────────────────────────────────────

/// EFI success status code
pub const EFI_SUCCESS: usize = 0;
/// EFI not found status code
pub const EFI_NOT_FOUND: usize = 14;

/// Console control screen mode: text
pub const SCREEN_TEXT: u32 = 0;
/// Console control screen mode: graphics
pub const SCREEN_GRAPHICS: u32 = 1;

// ── Types ─────────────────────────────────────────────────────────────────

/// Represents a console screen mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenMode {
    Text,
    Graphics,
}

/// Result of a graphics mode operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphicsModeError {
    /// The console control protocol was not found (non-standard, may not exist)
    ProtocolNotFound,
    /// Failed to get the current mode from the protocol
    GetModeFailed,
    /// Failed to set the requested mode
    SetModeFailed,
    /// An unexpected error occurred
    Unexpected(usize),
}

impl std::fmt::Display for GraphicsModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GraphicsModeError::ProtocolNotFound => write!(f, "console control protocol not found"),
            GraphicsModeError::GetModeFailed => write!(f, "failed to get current console mode"),
            GraphicsModeError::SetModeFailed => write!(f, "failed to set console mode"),
            GraphicsModeError::Unexpected(code) => write!(f, "unexpected EFI error: {}", code),
        }
    }
}

impl std::error::Error for GraphicsModeError {}

// ── Core logic ────────────────────────────────────────────────────────────

/// Tracks the state of a simulated console control protocol.
/// Used for pure-Rust testing without actual EFI firmware.
#[derive(Debug, Clone)]
pub struct ConsoleState {
    /// Whether the console control protocol is available
    protocol_available: bool,
    /// Current screen mode
    current_mode: ScreenMode,
    /// Whether get_mode should fail (simulates firmware error)
    get_mode_fails: bool,
    /// Whether set_mode should fail (simulates firmware error)
    set_mode_fails: bool,
    /// Whether set_mode was called (for verification in tests)
    set_mode_called: bool,
    /// The mode that was requested in the last set_mode call
    last_requested_mode: Option<ScreenMode>,
}

impl Default for ConsoleState {
    fn default() -> Self {
        Self {
            protocol_available: true,
            current_mode: ScreenMode::Text,
            get_mode_fails: false,
            set_mode_fails: false,
            set_mode_called: false,
            last_requested_mode: None,
        }
    }
}

impl ConsoleState {
    /// Create a new console state with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a console state where the protocol is not available
    pub fn without_protocol() -> Self {
        Self {
            protocol_available: false,
            ..Self::default()
        }
    }

    /// Create a console state starting in graphics mode
    pub fn in_graphics_mode() -> Self {
        Self {
            current_mode: ScreenMode::Graphics,
            ..Self::default()
        }
    }

    /// Set whether the protocol is available
    pub fn with_protocol_available(mut self, available: bool) -> Self {
        self.protocol_available = available;
        self
    }

    /// Set whether get_mode should fail
    pub fn with_get_mode_failing(mut self, fails: bool) -> Self {
        self.get_mode_fails = fails;
        self
    }

    /// Set whether set_mode should fail
    pub fn with_set_mode_failing(mut self, fails: bool) -> Self {
        self.set_mode_fails = fails;
        self
    }

    /// Get the current screen mode
    pub fn current_mode(&self) -> ScreenMode {
        self.current_mode
    }

    /// Check if set_mode was called
    pub fn was_set_mode_called(&self) -> bool {
        self.set_mode_called
    }

    /// Get the last requested mode
    pub fn last_requested_mode(&self) -> Option<ScreenMode> {
        self.last_requested_mode
    }
}

/// Convert a boolean "on" flag to a ScreenMode
pub fn on_to_screen_mode(on: bool) -> ScreenMode {
    if on {
        ScreenMode::Graphics
    } else {
        ScreenMode::Text
    }
}

/// Convert a ScreenMode to a raw u32 value (for EFI interop)
pub fn screen_mode_to_raw(mode: ScreenMode) -> u32 {
    match mode {
        ScreenMode::Text => SCREEN_TEXT,
        ScreenMode::Graphics => SCREEN_GRAPHICS,
    }
}

/// Convert a raw u32 to a ScreenMode
pub fn raw_to_screen_mode(raw: u32) -> Option<ScreenMode> {
    match raw {
        SCREEN_TEXT => Some(ScreenMode::Text),
        SCREEN_GRAPHICS => Some(ScreenMode::Graphics),
        _ => None,
    }
}

/// Switch the console graphics mode.
///
/// This is the main entry point matching the C `graphics_mode(bool on)`.
/// It implements the same logic:
/// 1. Try to locate the console control protocol
/// 2. If not found (non-standard), return success
/// 3. Check the current mode
/// 4. If already in the desired mode, return success
/// 5. Otherwise, switch to the new mode
///
/// The `ConsoleState` parameter provides a testable abstraction over
/// EFI firmware calls.
pub fn graphics_mode(on: bool, state: &mut ConsoleState) -> Result<(), GraphicsModeError> {
    // Step 1: Try to locate the console control protocol
    if !state.protocol_available {
        // Console control protocol is nonstandard and might not exist.
        // In C, this returns EFI_SUCCESS for NOT_FOUND.
        return Ok(());
    }

    // Step 2: Check current mode via GetMode
    if state.get_mode_fails {
        return Err(GraphicsModeError::GetModeFailed);
    }

    let new_mode = on_to_screen_mode(on);

    // Step 3: Do not touch the mode if already in the desired state
    if new_mode == state.current_mode {
        return Ok(());
    }

    // Step 4: Switch mode via SetMode
    state.set_mode_called = true;
    state.last_requested_mode = Some(new_mode);

    if state.set_mode_fails {
        return Err(GraphicsModeError::SetModeFailed);
    }

    state.current_mode = new_mode;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_screen_mode_conversion_text() {
        assert_eq!(on_to_screen_mode(false), ScreenMode::Text);
        assert_eq!(screen_mode_to_raw(ScreenMode::Text), SCREEN_TEXT);
        assert_eq!(raw_to_screen_mode(SCREEN_TEXT), Some(ScreenMode::Text));
    }

    #[test]
    fn test_screen_mode_conversion_graphics() {
        assert_eq!(on_to_screen_mode(true), ScreenMode::Graphics);
        assert_eq!(screen_mode_to_raw(ScreenMode::Graphics), SCREEN_GRAPHICS);
        assert_eq!(
            raw_to_screen_mode(SCREEN_GRAPHICS),
            Some(ScreenMode::Graphics)
        );
    }

    #[test]
    fn test_raw_to_screen_mode_invalid() {
        assert_eq!(raw_to_screen_mode(99), None);
        assert_eq!(raw_to_screen_mode(u32::MAX), None);
    }

    #[test]
    fn test_graphics_mode_protocol_not_found() {
        let mut state = ConsoleState::without_protocol();
        // When protocol is not found, should succeed (matching C behavior)
        assert!(graphics_mode(true, &mut state).is_ok());
        assert!(!state.was_set_mode_called());
    }

    #[test]
    fn test_graphics_mode_already_in_desired_mode() {
        let mut state = ConsoleState::new(); // starts in Text mode
                                             // Requesting text mode when already in text mode → no-op
        assert!(graphics_mode(false, &mut state).is_ok());
        assert!(!state.was_set_mode_called());

        let mut state = ConsoleState::in_graphics_mode();
        assert!(graphics_mode(true, &mut state).is_ok());
        assert!(!state.was_set_mode_called());
    }

    #[test]
    fn test_graphics_mode_switch_text_to_graphics() {
        let mut state = ConsoleState::new();
        assert!(graphics_mode(true, &mut state).is_ok());
        assert!(state.was_set_mode_called());
        assert_eq!(state.current_mode(), ScreenMode::Graphics);
        assert_eq!(state.last_requested_mode(), Some(ScreenMode::Graphics));
    }

    #[test]
    fn test_graphics_mode_switch_graphics_to_text() {
        let mut state = ConsoleState::in_graphics_mode();
        assert!(graphics_mode(false, &mut state).is_ok());
        assert!(state.was_set_mode_called());
        assert_eq!(state.current_mode(), ScreenMode::Text);
    }

    #[test]
    fn test_graphics_mode_get_mode_failure() {
        let mut state = ConsoleState::new().with_get_mode_failing(true);
        let result = graphics_mode(true, &mut state);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), GraphicsModeError::GetModeFailed);
    }

    #[test]
    fn test_graphics_mode_set_mode_failure() {
        let mut state = ConsoleState::new().with_set_mode_failing(true);
        let result = graphics_mode(true, &mut state);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), GraphicsModeError::SetModeFailed);
        // set_mode was called even though it failed
        assert!(state.was_set_mode_called());
    }

    #[test]
    fn test_console_state_default() {
        let state = ConsoleState::default();
        assert_eq!(state.current_mode(), ScreenMode::Text);
        assert!(!state.was_set_mode_called());
        assert_eq!(state.last_requested_mode(), None);
    }

    #[test]
    fn test_error_display() {
        assert!(GraphicsModeError::ProtocolNotFound
            .to_string()
            .contains("not found"));
        assert!(GraphicsModeError::GetModeFailed
            .to_string()
            .contains("get current"));
        assert!(GraphicsModeError::SetModeFailed
            .to_string()
            .contains("set console"));
        assert!(GraphicsModeError::Unexpected(42).to_string().contains("42"));
    }

    #[test]
    fn test_graphics_mode_multiple_switches() {
        let mut state = ConsoleState::new();

        assert!(graphics_mode(true, &mut state).is_ok());
        assert_eq!(state.current_mode(), ScreenMode::Graphics);

        // Already in graphics mode → no-op
        state.set_mode_called = false;
        assert!(graphics_mode(true, &mut state).is_ok());
        assert!(!state.was_set_mode_called());

        assert!(graphics_mode(false, &mut state).is_ok());
        assert_eq!(state.current_mode(), ScreenMode::Text);
    }
}
