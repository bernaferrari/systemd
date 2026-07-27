// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/mute-console/mute-console.c
//
// Console output muting for PID 1 and kernel printk.
//
// Manages temporary suppression of status output from systemd (PID 1)
// and the kernel console log level.  Used during boot splash and quiet
// boot to eliminate visual noise.

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub type Result<T> = std::result::Result<T, Errno>;

// ── Constants ─────────────────────────────────────────────────────────────

/// Minimum valid printk log level.
pub const PRINTK_LEVEL_MIN: i32 = 0;

/// Maximum valid printk log level (kernel allows up to 15).
pub const PRINTK_LEVEL_MAX: i32 = 15;

/// Sentinel value indicating no saved kernel level.
pub const PRINTK_LEVEL_NONE: i32 = -1;

// ── Context ───────────────────────────────────────────────────────────────

/// Tracks the mute state for PID 1 status output and kernel printk level.
///
/// Mirrors the C `Context` struct which carries `mute_pid1`, `mute_kernel`,
/// `muted_pid1`, and `saved_kernel`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuteContext {
    /// Whether PID 1 status output should be muted.
    pub mute_pid1: bool,
    /// Whether kernel printk output should be muted.
    pub mute_kernel: bool,
    /// Whether PID 1 status output has been muted.
    pub muted_pid1: bool,
    /// The saved kernel printk level before muting, or `PRINTK_LEVEL_NONE`.
    pub saved_kernel_level: i32,
}

impl Default for MuteContext {
    fn default() -> Self {
        Self {
            mute_pid1: true,
            mute_kernel: true,
            muted_pid1: false,
            saved_kernel_level: PRINTK_LEVEL_NONE,
        }
    }
}

impl MuteContext {
    pub fn new(mute_pid1: bool, mute_kernel: bool) -> Self {
        Self {
            mute_pid1,
            mute_kernel,
            muted_pid1: false,
            saved_kernel_level: PRINTK_LEVEL_NONE,
        }
    }

    /// Whether any muting was requested.
    pub fn needs_mute(&self) -> bool {
        self.mute_pid1 || self.mute_kernel
    }

    /// Mark PID 1 status output as now muted.
    pub fn mark_pid1_muted(&mut self) {
        self.muted_pid1 = true;
    }

    /// Mark PID 1 status output as restored.
    pub fn mark_pid1_unmuted(&mut self) {
        self.muted_pid1 = false;
    }

    /// Save a kernel printk level for later restoration.
    pub fn save_kernel_level(&mut self, level: i32) {
        self.saved_kernel_level = level;
    }

    /// Clear the saved kernel level (nothing to restore).
    pub fn clear_kernel_level(&mut self) {
        self.saved_kernel_level = PRINTK_LEVEL_NONE;
    }

    /// Whether there is a saved kernel level that should be restored.
    pub fn needs_kernel_restore(&self) -> bool {
        self.saved_kernel_level >= 0
    }

    /// Whether PID 1 muting has been performed.
    pub fn is_pid1_muted(&self) -> bool {
        self.muted_pid1
    }
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Check whether a printk log level is within the valid range [0, 15].
pub fn is_valid_printk_level(level: i32) -> bool {
    (PRINTK_LEVEL_MIN..=PRINTK_LEVEL_MAX).contains(&level)
}

/// Check whether kernel muting should be skipped because the level is already 0.
///
/// Corresponds to the C check: `if (level == 0) { log_info("already disabled"); ... }`.
pub fn should_skip_kernel_mute(level: i32) -> bool {
    level == 0
}

/// Determine what action to take for kernel muting.
///
/// Returns `None` if muting is not needed (already disabled or not requested),
/// or `Some(level)` with the current level to save before setting to 0.
pub fn determine_kernel_mute_action(
    mute_kernel: bool,
    current_level: i32,
    is_container: bool,
) -> Option<i32> {
    if !mute_kernel {
        return None;
    }
    if is_container {
        return None;
    }
    if current_level == 0 {
        return None;
    }
    Some(current_level)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_context() {
        let ctx = MuteContext::default();
        assert!(ctx.mute_pid1);
        assert!(ctx.mute_kernel);
        assert!(!ctx.muted_pid1);
        assert_eq!(ctx.saved_kernel_level, PRINTK_LEVEL_NONE);
    }

    #[test]
    fn custom_context_both_mute() {
        let ctx = MuteContext::new(true, true);
        assert!(ctx.mute_pid1);
        assert!(ctx.mute_kernel);
        assert!(!ctx.muted_pid1);
    }

    #[test]
    fn custom_context_neither_mute() {
        let ctx = MuteContext::new(false, false);
        assert!(!ctx.mute_pid1);
        assert!(!ctx.mute_kernel);
    }

    #[test]
    fn needs_mute() {
        assert!(MuteContext::new(true, false).needs_mute());
        assert!(MuteContext::new(false, true).needs_mute());
        assert!(!MuteContext::new(false, false).needs_mute());
    }

    #[test]
    fn pid1_lifecycle() {
        let mut ctx = MuteContext::new(true, false);
        assert!(!ctx.is_pid1_muted());
        ctx.mark_pid1_muted();
        assert!(ctx.is_pid1_muted());
        ctx.mark_pid1_unmuted();
        assert!(!ctx.is_pid1_muted());
    }

    #[test]
    fn kernel_level_lifecycle() {
        let mut ctx = MuteContext::new(true, true);
        assert!(!ctx.needs_kernel_restore());
        ctx.save_kernel_level(7);
        assert!(ctx.needs_kernel_restore());
        assert_eq!(ctx.saved_kernel_level, 7);
        ctx.clear_kernel_level();
        assert!(!ctx.needs_kernel_restore());
        assert_eq!(ctx.saved_kernel_level, PRINTK_LEVEL_NONE);
    }

    #[test]
    fn valid_printk_levels() {
        assert!(is_valid_printk_level(0));
        assert!(is_valid_printk_level(4));
        assert!(is_valid_printk_level(7));
        assert!(is_valid_printk_level(15));
        assert!(!is_valid_printk_level(-1));
        assert!(!is_valid_printk_level(16));
    }

    #[test]
    fn skip_kernel_mute_when_zero() {
        assert!(should_skip_kernel_mute(0));
        assert!(!should_skip_kernel_mute(4));
        assert!(!should_skip_kernel_mute(7));
    }

    #[test]
    fn determine_kernel_mute_action_normal() {
        // Normal case: level 7, not container, mute requested
        assert_eq!(determine_kernel_mute_action(true, 7, false), Some(7));
    }

    #[test]
    fn determine_kernel_mute_action_not_requested() {
        assert_eq!(determine_kernel_mute_action(false, 7, false), None);
    }

    #[test]
    fn determine_kernel_mute_action_container() {
        assert_eq!(determine_kernel_mute_action(true, 7, true), None);
    }

    #[test]
    fn determine_kernel_mute_action_already_zero() {
        assert_eq!(determine_kernel_mute_action(true, 0, false), None);
    }
}
