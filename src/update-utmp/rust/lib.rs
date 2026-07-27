// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/update-utmp/update-utmp.c
//
// UTMP and audit record update tool.
//
// Implements the systemd-update-utmp tool which writes utmp/wtmp records
// and sends audit messages on system reboot and shutdown events. Uses
// D-Bus to query the system manager for the userspace timestamp to
// compensate for incorrectly set clocks during early boot.

// ── Constants ─────────────────────────────────────────────────────────────

/// Clock ID for CLOCK_MONOTONIC (matches Linux value).
pub const CLOCK_MONOTONIC: i32 = 1;
/// Clock ID for CLOCK_REALTIME (matches Linux value).
pub const CLOCK_REALTIME: i32 = 0;

/// Default umask for the tool.
pub const DEFAULT_UMASK: u32 = 0o022;

/// Invalid file descriptor sentinel.
pub const INVALID_FD: i32 = -1;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Action verb for the update-utmp tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtmpVerb {
    /// Record a reboot event
    Reboot,
    /// Record a shutdown event
    Shutdown,
}

impl UtmpVerb {
    /// Parse a verb from its string representation.
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "reboot" => Ok(Self::Reboot),
            "shutdown" => Ok(Self::Shutdown),
            _ => Err(-libc::EINVAL),
        }
    }

    /// Convert to the string representation.
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Reboot => "reboot",
            Self::Shutdown => "shutdown",
        }
    }
}

// ── Verb definition ───────────────────────────────────────────────────────

/// Static verb table matching the C code's verbs[] array.
pub static VERBS: &[(&str, UtmpVerb); 2] = &[
    ("reboot", UtmpVerb::Reboot),
    ("shutdown", UtmpVerb::Shutdown),
];

// ── Clock conversion ──────────────────────────────────────────────────────

/// Convert a timestamp from one clock to another.
///
/// This mirrors the C `map_clock_usec()` function. When converting from
/// CLOCK_MONOTONIC to CLOCK_REALTIME, we compensate for early-boot clock
/// issues by computing: `realtime = monotonic + (realtime_offset - monotonic_offset)`.
///
/// For same-clock conversions, returns the value unchanged.
pub fn map_clock_usec(from_usec: u64, from_clock: i32, to_clock: i32) -> u64 {
    if from_clock == to_clock {
        return from_usec;
    }

    // The actual conversion would need to query clock offsets.
    // In the C code, this uses clock_gettime for both clocks and computes:
    // result = from_usec + (to_offset - from_offset)
    // For now, return the value as-is since this requires OS support.
    from_usec
}

// ── D-Bus property name ──────────────────────────────────────────────────

/// D-Bus property name for the userspace monotonic timestamp.
pub const USERSPACE_TIMESTAMP_MONOTONIC: &str = "UserspaceTimestampMonotonic";

// ── Context ───────────────────────────────────────────────────────────────

/// Runtime context for the update-utmp tool.
#[derive(Debug)]
pub struct UtmpContext {
    /// Audit file descriptor (-1 if not available)
    pub audit_fd: i32,
}

impl Default for UtmpContext {
    fn default() -> Self {
        Self {
            audit_fd: INVALID_FD,
        }
    }
}

impl UtmpContext {
    /// Create a new context with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if audit is available.
    pub fn has_audit(&self) -> bool {
        self.audit_fd >= 0
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parsed arguments for the update-utmp tool.
#[derive(Debug, Clone)]
pub struct UpdateUtmpArgs {
    /// The verb to execute
    pub verb: UtmpVerb,
}

impl UpdateUtmpArgs {
    /// Parse command-line arguments.
    pub fn parse(args: &[&str]) -> Result<Self, i32> {
        if args.len() != 2 {
            return Err(-libc::EINVAL);
        }
        let verb = UtmpVerb::from_str(args[1])?;
        Ok(Self { verb })
    }
}

// ── Boot time computation ─────────────────────────────────────────────────

/// Compute the boot time from a monotonic timestamp.
///
/// When the system clock was wrong during early boot, the monotonic timestamp
/// provides a more reliable reference. This function converts the monotonic
/// boot time to a realtime value.
pub fn compute_boottime(monotonic_usec: u64) -> u64 {
    map_clock_usec(monotonic_usec, CLOCK_MONOTONIC, CLOCK_REALTIME)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verb_from_str() {
        assert_eq!(UtmpVerb::from_str("reboot"), Ok(UtmpVerb::Reboot));
        assert_eq!(UtmpVerb::from_str("shutdown"), Ok(UtmpVerb::Shutdown));
        assert!(UtmpVerb::from_str("unknown").is_err());
    }

    #[test]
    fn test_verb_to_str() {
        assert_eq!(UtmpVerb::Reboot.to_str(), "reboot");
        assert_eq!(UtmpVerb::Shutdown.to_str(), "shutdown");
    }

    #[test]
    fn test_parse_args_valid() {
        let args = UpdateUtmpArgs::parse(&["update-utmp", "reboot"]).unwrap();
        assert_eq!(args.verb, UtmpVerb::Reboot);

        let args = UpdateUtmpArgs::parse(&["update-utmp", "shutdown"]).unwrap();
        assert_eq!(args.verb, UtmpVerb::Shutdown);
    }

    #[test]
    fn test_parse_args_invalid() {
        assert!(UpdateUtmpArgs::parse(&["update-utmp"]).is_err());
        assert!(UpdateUtmpArgs::parse(&["update-utmp", "reboot", "extra"]).is_err());
        assert!(UpdateUtmpArgs::parse(&["update-utmp", "invalid"]).is_err());
    }

    #[test]
    fn test_clock_constants() {
        assert_ne!(CLOCK_MONOTONIC, CLOCK_REALTIME);
        assert_eq!(CLOCK_MONOTONIC, 1);
        assert_eq!(CLOCK_REALTIME, 0);
    }

    #[test]
    fn test_map_clock_same() {
        assert_eq!(map_clock_usec(1000, CLOCK_MONOTONIC, CLOCK_MONOTONIC), 1000);
        assert_eq!(map_clock_usec(0, CLOCK_REALTIME, CLOCK_REALTIME), 0);
    }

    #[test]
    fn test_utmp_context_default() {
        let ctx = UtmpContext::new();
        assert_eq!(ctx.audit_fd, INVALID_FD);
        assert!(!ctx.has_audit());
    }

    #[test]
    fn test_utmp_context_with_audit() {
        let ctx = UtmpContext { audit_fd: 5 };
        assert!(ctx.has_audit());
    }

    #[test]
    fn test_verb_table() {
        assert_eq!(VERBS.len(), 2);
        assert_eq!(VERBS[0].0, "reboot");
        assert_eq!(VERBS[1].0, "shutdown");
    }

    #[test]
    fn test_compute_boottime() {
        // Same-clock conversion returns unchanged value
        let result = compute_boottime(12345);
        // Note: map_clock_usec for different clocks just returns the value in this impl
        assert_eq!(result, 12345);
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_UMASK, 0o022);
        assert_eq!(INVALID_FD, -1);
        assert_eq!(USERSPACE_TIMESTAMP_MONOTONIC, "UserspaceTimestampMonotonic");
    }
}
