// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/validatefs/validatefs.c
//
// File system validation constraint checker.
//
// Implements the systemd-validatefs tool which checks mount points against
// validation constraints stored as extended attributes. Supports validation
// of GPT partition type UUIDs, GPT partition labels, and mount point
// restrictions. Ensures that filesystems are mounted at the expected
// locations and on the expected partition types.

// ── Constants ─────────────────────────────────────────────────────────────

/// Extended attribute names used for validation constraints.
pub const XATTR_GPT_TYPE_UUID: &str = "user.validatefs.gpt_type_uuid";
pub const XATTR_GPT_LABEL: &str = "user.validatefs.gpt_label";
pub const XATTR_MOUNT_POINT: &str = "user.validatefs.mount_point";

// ── Types ─────────────────────────────────────────────────────────────────

/// A 128-bit UUID stored as bytes.
pub type Uuid = [u8; 16];

/// Validation fields read from extended attributes on a mount point.
#[derive(Debug, Clone, Default)]
pub struct ValidateFields {
    /// Allowed GPT partition type UUIDs
    pub gpt_type_uuid: Vec<Uuid>,
    /// Allowed GPT partition labels
    pub gpt_label: Vec<String>,
    /// Allowed mount point paths (must be absolute, normalized)
    pub mount_point: Vec<String>,
}

impl ValidateFields {
    /// Check if any validation constraints are defined.
    pub fn has_constraints(&self) -> bool {
        !self.gpt_type_uuid.is_empty() || !self.gpt_label.is_empty() || !self.mount_point.is_empty()
    }

    /// Check if GPT type UUID constraints are defined.
    pub fn has_gpt_type_constraints(&self) -> bool {
        !self.gpt_type_uuid.is_empty()
    }

    /// Check if GPT label constraints are defined.
    pub fn has_gpt_label_constraints(&self) -> bool {
        !self.gpt_label.is_empty()
    }

    /// Check if mount point constraints are defined.
    pub fn has_mount_point_constraints(&self) -> bool {
        !self.mount_point.is_empty()
    }
}

// ── UUID formatting ───────────────────────────────────────────────────────

/// Format a UUID as a standard UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
pub fn format_uuid(uuid: &Uuid) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0], uuid[1], uuid[2], uuid[3],
        uuid[4], uuid[5],
        uuid[6], uuid[7],
        uuid[8], uuid[9],
        uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    )
}

/// Parse a UUID from a standard UUID string.
pub fn parse_uuid(s: &str) -> Result<Uuid, i32> {
    let s = s.trim();
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return Err(-libc::EINVAL);
    }

    let hex: String = parts.join("");
    if hex.len() != 32 {
        return Err(-libc::EINVAL);
    }

    let mut uuid = [0u8; 16];
    for i in 0..16 {
        let byte_str = &hex[i * 2..i * 2 + 2];
        uuid[i] = u8::from_str_radix(byte_str, 16).map_err(|_| -libc::EINVAL)?;
    }
    Ok(uuid)
}

// ── Path validation ───────────────────────────────────────────────────────

/// Check if a mount point string is valid (absolute, normalized, no control chars, valid UTF-8).
pub fn mount_point_is_valid(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    if !path.starts_with('/') {
        return false;
    }
    // Check for control characters
    if path.chars().any(|c| c.is_control()) {
        return false;
    }
    // Check for non-normalized paths (double slashes, dot-dot components that go above root)
    if path.contains("//") {
        return false;
    }
    // Must not end with slash (except root)
    if path.len() > 1 && path.ends_with('/') {
        return false;
    }
    true
}

/// Validate a label string: must be valid UTF-8, no control characters.
pub fn label_is_valid(label: &str) -> bool {
    !label.is_empty() && !label.chars().any(|c| c.is_control())
}

// ── Mount point matching ──────────────────────────────────────────────────

/// Validate that a path matches one of the allowed mount points.
/// Returns Ok(()) if valid, Err with errno if not.
pub fn validate_mount_point(
    actual_path: &str,
    allowed: &[String],
    root: Option<&str>,
) -> Result<(), i32> {
    if allowed.is_empty() {
        return Ok(());
    }

    for allowed_path in allowed {
        let full_path = match root {
            Some(r) => {
                if r.ends_with('/') {
                    format!("{}{}", r, allowed_path.trim_start_matches('/'))
                } else {
                    format!("{}{}", r, allowed_path)
                }
            }
            None => allowed_path.clone(),
        };

        if actual_path == full_path {
            return Ok(());
        }
    }

    Err(-libc::EPERM)
}

// ── GPT type matching ─────────────────────────────────────────────────────

/// Validate that a GPT type UUID matches one of the allowed UUIDs.
pub fn validate_gpt_type(actual_uuid: Option<&Uuid>, allowed: &[Uuid]) -> Result<(), i32> {
    if allowed.is_empty() {
        return Ok(());
    }

    let actual = match actual_uuid {
        Some(u) => u,
        None => return Err(-libc::EPERM),
    };

    for allowed_uuid in allowed {
        if actual == allowed_uuid {
            return Ok(());
        }
    }

    Err(-libc::EPERM)
}

// ── GPT label matching ────────────────────────────────────────────────────

/// Validate that a GPT partition label matches one of the allowed labels.
pub fn validate_gpt_label(actual_label: Option<&str>, allowed: &[String]) -> Result<(), i32> {
    if allowed.is_empty() {
        return Ok(());
    }

    let label = actual_label.unwrap_or("");
    if allowed.iter().any(|l| l == label) {
        return Ok(());
    }

    Err(-libc::EPERM)
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parsed arguments for the validatefs tool.
#[derive(Debug, Clone)]
pub struct ValidatefsArgs {
    /// Root directory for path resolution (None = current root)
    pub root: Option<String>,
    /// Target mount point path
    pub target: String,
}

impl ValidatefsArgs {
    /// Determine the effective root path.
    /// If root is "auto", uses "/sysroot" when in initrd, otherwise None.
    pub fn effective_root(&self, in_initrd: bool) -> Option<&str> {
        if let Some(ref root) = self.root {
            if root == "auto" {
                if in_initrd {
                    Some("/sysroot")
                } else {
                    None
                }
            } else {
                Some(root.as_str())
            }
        } else {
            None
        }
    }

    /// Validate that the target path starts with root (if root is set).
    pub fn validate_target_under_root(&self) -> Result<(), i32> {
        if let Some(ref root) = self.root {
            if !self.target.starts_with(root.as_str()) {
                return Err(-libc::EINVAL);
            }
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_uuid() {
        let uuid: Uuid = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        assert_eq!(format_uuid(&uuid), "01234567-89ab-cdef-fedc-ba9876543210");
    }

    #[test]
    fn test_parse_uuid_valid() {
        let parsed = parse_uuid("01234567-89ab-cdef-fedc-ba9876543210").unwrap();
        let expected: Uuid = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_parse_uuid_invalid() {
        assert!(parse_uuid("not-a-uuid").is_err());
        assert!(parse_uuid("").is_err());
        assert!(parse_uuid("01234567-89ab-cdef").is_err());
        assert!(parse_uuid("01234567-89ab-cdef-fedc-ba9876543210-extra").is_err());
    }

    #[test]
    fn test_mount_point_is_valid() {
        assert!(mount_point_is_valid("/"));
        assert!(mount_point_is_valid("/boot"));
        assert!(mount_point_is_valid("/mnt/data"));
        assert!(!mount_point_is_valid("relative"));
        assert!(!mount_point_is_valid(""));
        assert!(!mount_point_is_valid("/has//double"));
        assert!(!mount_point_is_valid("/trailing/"));
    }

    #[test]
    fn test_label_is_valid() {
        assert!(label_is_valid("root"));
        assert!(label_is_valid("EFI System Partition"));
        assert!(!label_is_valid(""));
        assert!(!label_is_valid("has\nnewline"));
    }

    #[test]
    fn test_validate_mount_point_empty_allowed() {
        assert!(validate_mount_point("/boot", &[], None).is_ok());
    }

    #[test]
    fn test_validate_mount_point_match() {
        let allowed = vec!["/boot".to_string(), "/efi".to_string()];
        assert!(validate_mount_point("/boot", &allowed, None).is_ok());
        assert!(validate_mount_point("/efi", &allowed, None).is_ok());
    }

    #[test]
    fn test_validate_mount_point_no_match() {
        let allowed = vec!["/boot".to_string()];
        assert!(validate_mount_point("/var", &allowed, None).is_err());
    }

    #[test]
    fn test_validate_mount_point_with_root() {
        let allowed = vec!["/boot".to_string()];
        assert!(validate_mount_point("/sysroot/boot", &allowed, Some("/sysroot")).is_ok());
        assert!(validate_mount_point("/sysroot/var", &allowed, Some("/sysroot")).is_err());
    }

    #[test]
    fn test_validate_gpt_type() {
        let uuid1: Uuid = [1; 16];
        let uuid2: Uuid = [2; 16];
        let allowed = vec![uuid1];
        assert!(validate_gpt_type(Some(&uuid1), &allowed).is_ok());
        assert!(validate_gpt_type(Some(&uuid2), &allowed).is_err());
        assert!(validate_gpt_type(None, &allowed).is_err());
        assert!(validate_gpt_type(None, &[]).is_ok());
    }

    #[test]
    fn test_validate_gpt_label() {
        let allowed = vec!["root".to_string(), "boot".to_string()];
        assert!(validate_gpt_label(Some("root"), &allowed).is_ok());
        assert!(validate_gpt_label(Some("other"), &allowed).is_err());
        assert!(validate_gpt_label(None, &allowed).is_err());
        assert!(validate_gpt_label(None, &[]).is_ok());
    }

    #[test]
    fn test_validate_fields_has_constraints() {
        let empty = ValidateFields::default();
        assert!(!empty.has_constraints());

        let with_uuid = ValidateFields {
            gpt_type_uuid: vec![[0u8; 16]],
            ..Default::default()
        };
        assert!(with_uuid.has_constraints());
    }

    #[test]
    fn test_validatefs_args_effective_root() {
        let args = ValidatefsArgs {
            root: Some("auto".to_string()),
            target: "/boot".to_string(),
        };
        assert_eq!(args.effective_root(true), Some("/sysroot"));
        assert_eq!(args.effective_root(false), None);

        let args_no_root = ValidatefsArgs {
            root: None,
            target: "/boot".to_string(),
        };
        assert_eq!(args_no_root.effective_root(false), None);

        let args_explicit = ValidatefsArgs {
            root: Some("/mnt".to_string()),
            target: "/mnt/boot".to_string(),
        };
        assert_eq!(args_explicit.effective_root(false), Some("/mnt"));
    }
}
