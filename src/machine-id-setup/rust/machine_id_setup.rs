// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/machine-id-setup/machine-id-setup-main.c
//
// Machine ID setup and validation utilities.
//
// Provides types and functions for initializing, validating, and
// formatting /etc/machine-id values.  The machine ID is a 128-bit
// value represented as 32 lowercase hexadecimal characters.

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

/// Length of a machine ID string in characters (128 bits = 16 bytes = 32 hex chars).
pub const MACHINE_ID_LEN: usize = 32;

/// Length of a machine ID in bytes.
pub const MACHINE_ID_SIZE: usize = 16;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Action that machine-id-setup will perform.
///
/// Mirrors the `--commit` / default distinction in the C tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineIdAction {
    /// Commit a transient machine ID to disk.
    Commit,
    /// Generate or read the machine ID (default).
    Initialize,
}

// ── Argument bundle ───────────────────────────────────────────────────────

/// Parsed command-line arguments for `systemd-machine-id-setup`.
///
/// Faithfully mirrors `arg_root`, `arg_image`, `arg_commit`, `arg_print`
/// from the C source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineIdSetupArgs {
    /// Alternate filesystem root (--root=).
    pub root: Option<String>,
    /// Disk image to operate on (--image=).
    pub image: Option<String>,
    /// Commit transient ID (--commit).
    pub commit: bool,
    /// Print the resulting ID (--print).
    pub print: bool,
}

impl Default for MachineIdSetupArgs {
    fn default() -> Self {
        Self {
            root: None,
            image: None,
            commit: false,
            print: false,
        }
    }
}

impl MachineIdSetupArgs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate that mutually exclusive options are not both set.
    ///
    /// Corresponds to the check in `parse_argv()`:
    /// `if (arg_image && arg_root) return -EINVAL`.
    pub fn validate(&self) -> Result<()> {
        if self.root.is_some() && self.image.is_some() {
            return Err(Errno(-22)); // -EINVAL
        }
        Ok(())
    }

    /// Determine the action from the arguments.
    pub fn determine_action(&self) -> MachineIdAction {
        if self.commit {
            MachineIdAction::Commit
        } else {
            MachineIdAction::Initialize
        }
    }
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Check whether a string is a valid machine ID (32 lowercase hex chars).
///
/// In the C source the ID is validated via `sd_id128_from_string()` which
/// accepts both upper and lower case; we accept any ASCII hex digit here
/// to match that behaviour.
pub fn is_valid_machine_id(id: &str) -> bool {
    id.len() == MACHINE_ID_LEN && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Format a raw 16-byte machine ID as a 32-character lowercase hex string.
///
/// Equivalent to `SD_ID128_TO_STRING()` in the C code.
pub fn format_machine_id(id: &[u8; MACHINE_ID_SIZE]) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Parse a 32-character hex string into a 16-byte machine ID.
///
/// Returns `Err(EINVAL)` when the string is not exactly 32 hex characters.
/// Mirrors `sd_id128_from_string()`.
pub fn parse_machine_id(s: &str) -> Result<[u8; MACHINE_ID_SIZE]> {
    if s.len() != MACHINE_ID_LEN {
        return Err(Errno(-22)); // -EINVAL
    }
    let mut id = [0u8; MACHINE_ID_SIZE];
    for i in 0..MACHINE_ID_SIZE {
        id[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| Errno(-22))?;
    }
    Ok(id)
}

/// Normalise a machine ID string by forcing all hex digits to lowercase.
///
/// The C `SD_ID128_TO_STRING()` always produces lowercase; this helper
/// mirrors that canonical form.
pub fn normalize_machine_id(id: &str) -> Result<String> {
    let bytes = parse_machine_id(id)?;
    Ok(format_machine_id(&bytes))
}

/// Generate a zeroed (uninitialized) machine ID string.
///
/// Corresponds to `SD_ID128_NULL` which is all-zero bytes.
pub fn null_machine_id_str() -> String {
    "00000000000000000000000000000000".to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_args() {
        let args = MachineIdSetupArgs::new();
        assert!(!args.commit);
        assert!(!args.print);
        assert!(args.root.is_none());
        assert!(args.image.is_none());
    }

    #[test]
    fn validate_ok_both_none() {
        let args = MachineIdSetupArgs::new();
        assert!(args.validate().is_ok());
    }

    #[test]
    fn validate_root_and_image_conflict() {
        let args = MachineIdSetupArgs {
            root: Some("/".into()),
            image: Some("disk.img".into()),
            ..Default::default()
        };
        assert!(args.validate().is_err());
    }

    #[test]
    fn validate_root_only_ok() {
        let args = MachineIdSetupArgs {
            root: Some("/mnt".into()),
            ..Default::default()
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn validate_image_only_ok() {
        let args = MachineIdSetupArgs {
            image: Some("disk.raw".into()),
            ..Default::default()
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn determine_action_commit() {
        let args = MachineIdSetupArgs {
            commit: true,
            ..Default::default()
        };
        assert_eq!(args.determine_action(), MachineIdAction::Commit);
    }

    #[test]
    fn determine_action_initialize() {
        let args = MachineIdSetupArgs::new();
        assert_eq!(args.determine_action(), MachineIdAction::Initialize);
    }

    #[test]
    fn valid_machine_id_lowercase() {
        assert!(is_valid_machine_id("f47ac10b58cc4582ae851e7396c8051d"));
    }

    #[test]
    fn valid_machine_id_uppercase() {
        assert!(is_valid_machine_id("F47AC10B58CC4582AE851E7396C8051D"));
    }

    #[test]
    fn invalid_machine_id_short() {
        assert!(!is_valid_machine_id("abc"));
    }

    #[test]
    fn invalid_machine_id_non_hex() {
        assert!(!is_valid_machine_id("gggggggggggggggggggggggggggggggg"));
    }

    #[test]
    fn invalid_machine_id_too_long() {
        assert!(!is_valid_machine_id("f47ac10b58cc4582ae851e7396c8051d00"));
    }

    #[test]
    fn format_and_parse_roundtrip() {
        let id: [u8; 16] = [
            0xf4, 0x7a, 0xc1, 0x0b, 0x58, 0xcc, 0x45, 0x82, 0xae, 0x85, 0x1e, 0x73, 0x96, 0xc8,
            0x05, 0x1d,
        ];
        let formatted = format_machine_id(&id);
        assert_eq!(formatted, "f47ac10b58cc4582ae851e7396c8051d");
        let parsed = parse_machine_id(&formatted).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn parse_invalid_length() {
        assert!(parse_machine_id("abc").is_err());
    }

    #[test]
    fn parse_invalid_hex() {
        assert!(parse_machine_id("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    #[test]
    fn normalize_machine_id_mixed_case() {
        let result = normalize_machine_id("F47AC10B58cc4582AE851E7396C8051D").unwrap();
        assert_eq!(result, "f47ac10b58cc4582ae851e7396c8051d");
    }

    #[test]
    fn null_machine_id() {
        let null = null_machine_id_str();
        assert_eq!(null.len(), 32);
        assert!(null.chars().all(|c| c == '0'));
        assert!(is_valid_machine_id(&null));
    }
}
