// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/mute-console/mute-console.c
//
// Mutes PID 1 and kernel console status output temporarily.
//
// This tool runs as a daemon that mutes console output on startup and
// restores it on shutdown (SIGINT/SIGTERM) or Varlink disconnect.
// Supports two mute targets: PID 1 show-status and kernel printk level.

// ── Error type ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum valid kernel printk console log level.
pub const PRINTK_LEVEL_MAX: i32 = 15;

/// Sentinel value meaning "no saved level / don't restore".
pub const PRINTK_LEVEL_NONE: i32 = -1;

// ── Context ───────────────────────────────────────────────────────────────

/// Tracks the mute state for both PID 1 and kernel console output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuteContext {
    /// Whether PID 1 status muting was requested.
    pub mute_pid1: bool,
    /// Whether kernel printk muting was requested.
    pub mute_kernel: bool,
    /// Whether PID 1 has actually been muted.
    pub muted_pid1: bool,
    /// The saved kernel printk level (or -1 if not saved).
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

    /// Returns true if at least one mute target is enabled.
    pub fn needs_mute(&self) -> bool {
        self.mute_pid1 || self.mute_kernel
    }

    /// Record that PID 1 has been muted.
    pub fn mark_pid1_muted(&mut self) {
        self.muted_pid1 = true;
    }

    /// Record that PID 1 has been unmuted.
    pub fn mark_pid1_unmuted(&mut self) {
        self.muted_pid1 = false;
    }

    /// Save a kernel printk level for later restoration.
    pub fn save_kernel_level(&mut self, level: i32) {
        self.saved_kernel_level = level;
    }

    /// Clear the saved kernel level (e.g. because restore is done).
    pub fn clear_kernel_level(&mut self) {
        self.saved_kernel_level = PRINTK_LEVEL_NONE;
    }

    /// Returns true if there is a saved kernel level to restore.
    pub fn needs_kernel_restore(&self) -> bool {
        self.saved_kernel_level >= 0
    }

    /// Determine the mute action for PID 1.
    /// Returns the value to pass to SetShowStatus.
    pub fn pid1_mute_value(&self) -> Option<&'static str> {
        if self.mute_pid1 { Some("no") } else { None }
    }

    /// Determine the value to restore PID 1 show-status to.
    pub fn pid1_unmute_value(&self) -> Option<&'static str> {
        if self.muted_pid1 { Some("") } else { None }
    }
}

// ── Validation ────────────────────────────────────────────────────────────

/// Check if a printk level is within valid range [0, 15].
pub fn is_valid_printk_level(level: i32) -> bool {
    (0..=PRINTK_LEVEL_MAX).contains(&level)
}

/// Determine whether we should skip kernel muting because it is already at 0.
pub fn should_skip_kernel_mute(level: i32) -> bool {
    level == 0
}

/// Determine whether we should skip kernel unmuting because the level
/// has been changed externally (is no longer 0).
pub fn should_skip_kernel_unmute(current_level: i32) -> bool {
    current_level != 0
}

// ── Varlink context ───────────────────────────────────────────────────────

/// Parameters received from the Varlink Mute method call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarlinkMuteParams {
    pub mute_pid1: bool,
    pub mute_kernel: bool,
}

impl Default for VarlinkMuteParams {
    fn default() -> Self {
        Self {
            mute_pid1: true,
            mute_kernel: true,
        }
    }
}

/// Parse mute parameters from a key-value map (e.g. JSON dispatch table).
pub fn parse_varlink_params(kernel: Option<bool>, pid1: Option<bool>) -> VarlinkMuteParams {
    VarlinkMuteParams {
        mute_kernel: kernel.unwrap_or(true),
        mute_pid1: pid1.unwrap_or(true),
    }
}

/// Create a MuteContext from Varlink parameters.
pub fn context_from_varlink(params: &VarlinkMuteParams) -> MuteContext {
    MuteContext::new(params.mute_pid1, params.mute_kernel)
}

// ── Command-line parsing helpers ──────────────────────────────────────────

/// Parse a boolean argument string ("yes"/"true"/"1" or "no"/"false"/"0").
pub fn parse_boolean_arg(value: &str) -> Result<bool> {
    match value.to_lowercase().as_str() {
        "yes" | "true" | "1" => Ok(true),
        "no" | "false" | "0" => Ok(false),
        _ => Err(Errno(-libc::EINVAL)),
    }
}

/// Build the notify message for mute-console startup.
pub fn format_startup_notify() -> &'static str {
    "READY=1\nSTATUS=Console status output muted temporarily."
}

/// Build the stopping notify message.
pub fn format_stopping_notify() -> &'static str {
    "STOPPING=1\nSTATUS=Console status output unmuted."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_context_values() {
        let ctx = MuteContext::default();
        assert!(ctx.mute_pid1);
        assert!(ctx.mute_kernel);
        assert!(!ctx.muted_pid1);
        assert_eq!(ctx.saved_kernel_level, PRINTK_LEVEL_NONE);
    }

    #[test]
    fn custom_context() {
        let ctx = MuteContext::new(false, true);
        assert!(!ctx.mute_pid1);
        assert!(ctx.mute_kernel);
    }

    #[test]
    fn needs_mute_logic() {
        let ctx = MuteContext::new(true, false);
        assert!(ctx.needs_mute());
        let ctx2 = MuteContext::new(false, false);
        assert!(!ctx2.needs_mute());
        let ctx3 = MuteContext::new(false, true);
        assert!(ctx3.needs_mute());
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
    }

    #[test]
    fn valid_printk_levels() {
        assert!(is_valid_printk_level(0));
        assert!(is_valid_printk_level(7));
        assert!(is_valid_printk_level(15));
        assert!(!is_valid_printk_level(-1));
        assert!(!is_valid_printk_level(16));
    }

    #[test]
    fn skip_mute_when_zero() {
        assert!(should_skip_kernel_mute(0));
        assert!(!should_skip_kernel_mute(4));
    }

    #[test]
    fn skip_unmute_when_not_zero() {
        assert!(should_skip_kernel_unmute(5));
        assert!(!should_skip_kernel_unmute(0));
    }

    #[test]
    fn pid1_mute_values() {
        let ctx = MuteContext::new(true, false);
        assert_eq!(ctx.pid1_mute_value(), Some("no"));
        let ctx2 = MuteContext::new(false, false);
        assert_eq!(ctx2.pid1_mute_value(), None);
    }

    #[test]
    fn pid1_unmute_values() {
        let mut ctx = MuteContext::new(true, false);
        assert_eq!(ctx.pid1_unmute_value(), None);
        ctx.mark_pid1_muted();
        assert_eq!(ctx.pid1_unmute_value(), Some(""));
        ctx.mark_pid1_unmuted();
        assert_eq!(ctx.pid1_unmute_value(), None);
    }

    #[test]
    fn parse_boolean_arguments() {
        assert!(parse_boolean_arg("yes").unwrap());
        assert!(!parse_boolean_arg("NO").unwrap());
        assert!(parse_boolean_arg("1").unwrap());
        assert!(!parse_boolean_arg("0").unwrap());
        assert!(parse_boolean_arg("maybe").is_err());
    }

    #[test]
    fn varlink_params_defaults() {
        let params = VarlinkMuteParams::default();
        assert!(params.mute_pid1);
        assert!(params.mute_kernel);
    }

    #[test]
    fn varlink_params_parse() {
        let params = parse_varlink_params(Some(false), Some(true));
        assert!(!params.mute_kernel);
        assert!(params.mute_pid1);
    }

    #[test]
    fn format_notify_messages() {
        assert!(format_startup_notify().contains("READY=1"));
        assert!(format_stopping_notify().contains("STOPPING=1"));
    }
}
