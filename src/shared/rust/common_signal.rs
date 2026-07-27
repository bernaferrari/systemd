// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/common-signal.c, src/shared/common-signal.h
//
// Common signal handling utilities for SIGRTMIN+18 control signals.

// ── Constants ─────────────────────────────────────────────────────────────

/// Base value for log-level control commands.
use crate::ffi::*;
pub const COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE: u32 = 0x100;

/// Highest log-level control command value (LOG_DEBUG = 7).
pub const COMMON_SIGNAL_COMMAND_LOG_LEVEL_END: u32 = 0x107;

/// First value reserved for private / per-service commands.
pub const COMMON_SIGNAL_COMMAND_PRIVATE_BASE: u32 = 0x500;

/// Last value reserved for private / per-service commands.
pub const COMMON_SIGNAL_COMMAND_PRIVATE_END: u32 = 0xfff;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Recognised SIGRTMIN+18 control commands.
///
/// Each variant stores the raw command word so that callers can round-trip
/// arbitrary valid values without losing information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CommonSignalCommand {
    LogEmerg = 0x100,
    LogAlert = 0x101,
    LogCrit = 0x102,
    LogErr = 0x103,
    LogWarning = 0x104,
    LogNotice = 0x105,
    LogInfo = 0x106,
    LogDebug = 0x107,

    Console = 0x200,
    Journal = 0x201,
    Kmsg = 0x202,
    Null = 0x203,

    MemoryPressure = 0x300,
    MallocInfo = 0x301,
}

impl CommonSignalCommand {
    const ALL: [Self; 14] = [
        Self::LogEmerg,
        Self::LogAlert,
        Self::LogCrit,
        Self::LogErr,
        Self::LogWarning,
        Self::LogNotice,
        Self::LogInfo,
        Self::LogDebug,
        Self::Console,
        Self::Journal,
        Self::Kmsg,
        Self::Null,
        Self::MemoryPressure,
        Self::MallocInfo,
    ];

    pub const fn is_log_level(self) -> bool {
        let v = self as u32;
        v >= COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE && v <= COMMON_SIGNAL_COMMAND_LOG_LEVEL_END
    }

    pub const fn log_level(self) -> Option<u32> {
        if self.is_log_level() {
            Some(self as u32 - COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE)
        } else {
            None
        }
    }

    /// Try to interpret a raw `u32` as a well-known command.
    ///
    /// Returns `None` for values in the private range (0x500–0xfff) since
    /// those are per-service and cannot be mapped to enum variants.
    /// Use [`is_valid_command`] to check the full valid range.
    pub fn from_raw(value: u32) -> Option<Self> {
        match value {
            0x100 => Some(Self::LogEmerg),
            0x101 => Some(Self::LogAlert),
            0x102 => Some(Self::LogCrit),
            0x103 => Some(Self::LogErr),
            0x104 => Some(Self::LogWarning),
            0x105 => Some(Self::LogNotice),
            0x106 => Some(Self::LogInfo),
            0x107 => Some(Self::LogDebug),
            0x200 => Some(Self::Console),
            0x201 => Some(Self::Journal),
            0x202 => Some(Self::Kmsg),
            0x203 => Some(Self::Null),
            0x300 => Some(Self::MemoryPressure),
            0x301 => Some(Self::MallocInfo),
            _ => None,
        }
    }

    pub const fn as_raw(self) -> u32 {
        self as u32
    }
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Check whether `value` falls in the valid command range
/// (well-known commands and per-service private range).
pub fn is_valid_command(value: u32) -> bool {
    let is_log = (COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE..=COMMON_SIGNAL_COMMAND_LOG_LEVEL_END)
        .contains(&value);
    let is_target = (0x200..=0x203).contains(&value);
    let is_maintenance = value == 0x300 || value == 0x301;
    let is_private =
        (COMMON_SIGNAL_COMMAND_PRIVATE_BASE..=COMMON_SIGNAL_COMMAND_PRIVATE_END).contains(&value);

    is_log || is_target || is_maintenance || is_private
}

/// Classify a command value into a human-readable category.
pub fn command_category(value: u32) -> &'static str {
    if (COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE..=COMMON_SIGNAL_COMMAND_LOG_LEVEL_END).contains(&value)
    {
        "log-level"
    } else if (0x200..=0x203).contains(&value) {
        "log-target"
    } else if value == 0x300 || value == 0x301 {
        "maintenance"
    } else if (COMMON_SIGNAL_COMMAND_PRIVATE_BASE..=COMMON_SIGNAL_COMMAND_PRIVATE_END)
        .contains(&value)
    {
        "private"
    } else {
        "unknown"
    }
}

// ── Signal helpers ────────────────────────────────────────────────────────

/// Returns `true` if the signal was sent by a user-space process
/// (`SI_USER` from `kill()` or `SI_QUEUE` from `sigqueue()`).
#[cfg(target_os = "linux")]
pub fn si_code_from_process(code: i32) -> bool {
    code == libc::SI_USER || code == SI_QUEUE
}

#[cfg(not(target_os = "linux"))]
pub const fn si_code_from_process(_code: i32) -> bool {
    false
}

/// Returns the signal number for SIGRTMIN+18 if available.
#[cfg(target_os = "linux")]
pub fn sigrtmin18_number() -> Option<i32> {
    // SAFETY: sysconf is async-signal-safe and has no mutable globals.
    let sigrtmin = unsafe { libc::sysconf(libc::_SC_SIGRT_MIN) };
    if sigrtmin < 0 {
        None
    } else {
        Some(sigrtmin as i32 + 18)
    }
}

#[cfg(not(target_os = "linux"))]
pub const fn sigrtmin18_number() -> Option<i32> {
    None
}

// ── Handler infrastructure ───────────────────────────────────────────────

/// Result of processing a single SIGRTMIN+18 command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandResult {
    Handled,
    Unknown,
    NotFromProcess,
    NoCommandValue,
}

/// Trait for objects that react to SIGRTMIN+18 commands.
///
/// Services implement this to customise behaviour. Default implementations
/// are no-ops so only the desired overrides need to be provided.
pub trait Sigrtmin18Handler {
    fn set_log_level(&mut self, _level: u32) {}
    fn set_log_target(&mut self, _target: &str) {}

    fn trim_memory(&mut self) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: malloc_trim is async-signal-safe on glibc.
            unsafe {
                libc::malloc_trim(0);
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    }

    fn dump_malloc_info(&mut self) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: malloc_info writes XML to the given FILE*.
            let ret = unsafe { libc::malloc_info(0, libc::stderr()) };
            if ret != 0 {
                Err("malloc_info() failed".into())
            } else {
                Ok(())
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("malloc_info not supported on this platform".into())
        }
    }
}

/// Dispatch a SIGRTMIN+18 command to the given handler.
pub fn dispatch_sigrtmin18<H: Sigrtmin18Handler>(
    handler: &mut H,
    si_code: i32,
    cmd_value: u32,
) -> CommandResult {
    if !si_code_from_process(si_code) {
        return CommandResult::NotFromProcess;
    }

    if si_code != SI_QUEUE {
        return CommandResult::NoCommandValue;
    }

    if !is_valid_command(cmd_value) {
        return CommandResult::Unknown;
    }

    if let Some(cmd) = CommonSignalCommand::from_raw(cmd_value) {
        match cmd {
            CommonSignalCommand::LogEmerg => handler.set_log_level(0),
            CommonSignalCommand::LogAlert => handler.set_log_level(1),
            CommonSignalCommand::LogCrit => handler.set_log_level(2),
            CommonSignalCommand::LogErr => handler.set_log_level(3),
            CommonSignalCommand::LogWarning => handler.set_log_level(4),
            CommonSignalCommand::LogNotice => handler.set_log_level(5),
            CommonSignalCommand::LogInfo => handler.set_log_level(6),
            CommonSignalCommand::LogDebug => handler.set_log_level(7),
            CommonSignalCommand::Console => handler.set_log_target("console"),
            CommonSignalCommand::Journal => handler.set_log_target("journal"),
            CommonSignalCommand::Kmsg => handler.set_log_target("kmsg"),
            CommonSignalCommand::Null => handler.set_log_target("null"),
            CommonSignalCommand::MemoryPressure => {
                let _ = handler.trim_memory();
            }
            CommonSignalCommand::MallocInfo => {
                let _ = handler.dump_malloc_info();
            }
        }
    }

    CommandResult::Handled
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_flags() {
        for cmd in &CommonSignalCommand::ALL {
            let is_ll = matches!(
                cmd,
                CommonSignalCommand::LogEmerg
                    | CommonSignalCommand::LogAlert
                    | CommonSignalCommand::LogCrit
                    | CommonSignalCommand::LogErr
                    | CommonSignalCommand::LogWarning
                    | CommonSignalCommand::LogNotice
                    | CommonSignalCommand::LogInfo
                    | CommonSignalCommand::LogDebug
            );
            assert_eq!(cmd.is_log_level(), is_ll);
        }
    }

    #[test]
    fn test_log_level_extraction() {
        assert_eq!(CommonSignalCommand::LogEmerg.log_level(), Some(0));
        assert_eq!(CommonSignalCommand::LogAlert.log_level(), Some(1));
        assert_eq!(CommonSignalCommand::LogCrit.log_level(), Some(2));
        assert_eq!(CommonSignalCommand::LogErr.log_level(), Some(3));
        assert_eq!(CommonSignalCommand::LogWarning.log_level(), Some(4));
        assert_eq!(CommonSignalCommand::LogNotice.log_level(), Some(5));
        assert_eq!(CommonSignalCommand::LogInfo.log_level(), Some(6));
        assert_eq!(CommonSignalCommand::LogDebug.log_level(), Some(7));
        assert_eq!(CommonSignalCommand::Console.log_level(), None);
        assert_eq!(CommonSignalCommand::MemoryPressure.log_level(), None);
    }

    #[test]
    fn test_from_raw_round_trip() {
        for cmd in &CommonSignalCommand::ALL {
            let raw = cmd.as_raw();
            assert_eq!(CommonSignalCommand::from_raw(raw), Some(*cmd));
        }
    }

    #[test]
    fn test_from_raw_unknown() {
        assert_eq!(CommonSignalCommand::from_raw(0x000), None);
        assert_eq!(CommonSignalCommand::from_raw(0x050), None);
        assert_eq!(CommonSignalCommand::from_raw(0x108), None);
        assert_eq!(CommonSignalCommand::from_raw(0x500), None);
        assert_eq!(CommonSignalCommand::from_raw(0xfff), None);
    }

    #[test]
    fn test_as_raw_values() {
        assert_eq!(CommonSignalCommand::LogEmerg.as_raw(), 0x100);
        assert_eq!(CommonSignalCommand::LogDebug.as_raw(), 0x107);
        assert_eq!(CommonSignalCommand::Console.as_raw(), 0x200);
        assert_eq!(CommonSignalCommand::Null.as_raw(), 0x203);
        assert_eq!(CommonSignalCommand::MemoryPressure.as_raw(), 0x300);
        assert_eq!(CommonSignalCommand::MallocInfo.as_raw(), 0x301);
    }

    #[test]
    fn test_is_valid_command_known() {
        assert!(is_valid_command(0x100));
        assert!(is_valid_command(0x107));
        assert!(is_valid_command(0x200));
        assert!(is_valid_command(0x203));
        assert!(is_valid_command(0x300));
        assert!(is_valid_command(0x301));
    }

    #[test]
    fn test_is_valid_command_private_range() {
        assert!(is_valid_command(0x500));
        assert!(is_valid_command(0x600));
        assert!(is_valid_command(0xfff));
    }

    #[test]
    fn test_is_valid_command_invalid() {
        assert!(!is_valid_command(0x000));
        assert!(!is_valid_command(0x050));
        assert!(!is_valid_command(0x108));
        assert!(!is_valid_command(0x204));
        assert!(!is_valid_command(0x302));
        assert!(!is_valid_command(0x4ff));
        assert!(!is_valid_command(0x1000));
    }

    #[test]
    fn test_command_category_all() {
        assert_eq!(command_category(0x100), "log-level");
        assert_eq!(command_category(0x107), "log-level");
        assert_eq!(command_category(0x200), "log-target");
        assert_eq!(command_category(0x203), "log-target");
        assert_eq!(command_category(0x300), "maintenance");
        assert_eq!(command_category(0x301), "maintenance");
        assert_eq!(command_category(0x500), "private");
        assert_eq!(command_category(0xfff), "private");
        assert_eq!(command_category(0x000), "unknown");
        assert_eq!(command_category(0x1000), "unknown");
    }

    #[test]
    fn test_si_code_from_process() {
        #[cfg(target_os = "linux")]
        {
            assert!(si_code_from_process(libc::SI_USER));
            assert!(si_code_from_process(SI_QUEUE));
            assert!(!si_code_from_process(0x42));
            assert!(!si_code_from_process(-2));
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!si_code_from_process(0));
            assert!(!si_code_from_process(-1));
            assert!(!si_code_from_process(42));
        }
    }

    #[derive(Default)]
    struct MockHandler {
        log_level: Option<u32>,
        log_target: Option<String>,
        trim_called: bool,
        malloc_info_called: bool,
    }

    impl Sigrtmin18Handler for MockHandler {
        fn set_log_level(&mut self, level: u32) {
            self.log_level = Some(level);
        }
        fn set_log_target(&mut self, target: &str) {
            self.log_target = Some(target.to_string());
        }
        fn trim_memory(&mut self) -> Result<(), String> {
            self.trim_called = true;
            Ok(())
        }
        fn dump_malloc_info(&mut self) -> Result<(), String> {
            self.malloc_info_called = true;
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dispatch_log_level() {
        let mut h = MockHandler::default();
        let r = dispatch_sigrtmin18(&mut h, SI_QUEUE, 0x103);
        assert_eq!(r, CommandResult::Handled);
        assert_eq!(h.log_level, Some(3));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dispatch_log_target() {
        let mut h = MockHandler::default();
        let r = dispatch_sigrtmin18(&mut h, SI_QUEUE, 0x201);
        assert_eq!(r, CommandResult::Handled);
        assert_eq!(h.log_target.as_deref(), Some("journal"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dispatch_memory_pressure() {
        let mut h = MockHandler::default();
        let r = dispatch_sigrtmin18(&mut h, SI_QUEUE, 0x300);
        assert_eq!(r, CommandResult::Handled);
        assert!(h.trim_called);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dispatch_malloc_info() {
        let mut h = MockHandler::default();
        let r = dispatch_sigrtmin18(&mut h, SI_QUEUE, 0x301);
        assert_eq!(r, CommandResult::Handled);
        assert!(h.malloc_info_called);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dispatch_unknown_command() {
        let mut h = MockHandler::default();
        let r = dispatch_sigrtmin18(&mut h, SI_QUEUE, 0x000);
        assert_eq!(r, CommandResult::Unknown);
    }

    #[test]
    fn test_dispatch_not_from_process() {
        let mut h = MockHandler::default();
        let r = dispatch_sigrtmin18(&mut h, 0x42, 0x300);
        assert_eq!(r, CommandResult::NotFromProcess);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dispatch_no_command_value() {
        let mut h = MockHandler::default();
        let si_code = libc::SI_USER;
        let r = dispatch_sigrtmin18(&mut h, si_code, 0x300);
        assert_eq!(r, CommandResult::NoCommandValue);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dispatch_private_range_handled() {
        let mut h = MockHandler::default();
        let r = dispatch_sigrtmin18(&mut h, SI_QUEUE, 0x600);
        assert_eq!(r, CommandResult::Handled);
        assert_eq!(h.log_level, None);
        assert!(!h.trim_called);
    }
}
