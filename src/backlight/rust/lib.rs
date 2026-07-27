// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/backlight/backlight.c
//
// Save and restore backlight brightness at shutdown and boot.
// Handles validation, clamping, and device management for backlight/LEDs.

// ── Constants ─────────────────────────────────────────────────────────────

/// PCI class for graphics cards.
pub const PCI_CLASS_GRAPHICS_CARD: u32 = 0x30000;

/// Default clamp percentage for backlight devices.
pub const DEFAULT_CLAMP_PERCENT: u32 = 1;

/// Base path for saved backlight state.
pub const BACKLIGHT_VAR_PATH: &str = "/var/lib/systemd/backlight/";

/// Supported subsystem names.
pub const VALID_SUBSYSTEMS: &[&str] = &["backlight", "leds"];

// ── Types ─────────────────────────────────────────────────────────────────

/// Verb (subcommand) for the backlight tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BacklightVerb {
    /// Save current brightness.
    Save,
    /// Load previously saved brightness.
    Load,
}

impl BacklightVerb {
    /// Parse verb from string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "save" => Some(BacklightVerb::Save),
            "load" => Some(BacklightVerb::Load),
            _ => None,
        }
    }
}

/// Backlight device type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BacklightType {
    /// Firmware (ACPI) controlled backlight.
    Firmware,
    /// Platform (EC) controlled backlight.
    Platform,
    /// Raw (graphics card) controlled backlight.
    Raw,
    /// LED device.
    Leds,
}

impl BacklightType {
    /// Parse backlight type from the sysfs "type" attribute.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "firmware" => Some(BacklightType::Firmware),
            "platform" => Some(BacklightType::Platform),
            "raw" => Some(BacklightType::Raw),
            _ => None,
        }
    }

    /// Check if this type is firmware or platform (preferred over raw).
    pub fn is_preferred(&self) -> bool {
        matches!(self, BacklightType::Firmware | BacklightType::Platform)
    }
}

// ── Device argument parsing ───────────────────────────────────────────────

/// Parsed device specifier (subsystem:sysname).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSpec {
    /// Subsystem name ("backlight" or "leds").
    pub subsystem: String,
    /// Sysname (device name within the subsystem).
    pub sysname: String,
}

impl DeviceSpec {
    /// Parse a device specifier string like "backlight:intel_backlight".
    ///
    /// Returns an error if the format is invalid or the subsystem is unsupported.
    pub fn parse(s: &str) -> Result<Self, i32> {
        let (subsystem, sysname) = s.split_once(':').ok_or(-libc::EINVAL)?;

        if subsystem.is_empty() || sysname.is_empty() {
            return Err(-libc::EINVAL);
        }

        if !VALID_SUBSYSTEMS.contains(&subsystem) {
            return Err(-libc::EINVAL);
        }

        Ok(Self {
            subsystem: subsystem.to_string(),
            sysname: sysname.to_string(),
        })
    }
}

// ── Brightness operations ─────────────────────────────────────────────────

/// Clamp brightness to a valid range.
///
/// `percent` is the minimum percentage of `max_brightness`.
/// For backlight subsystems, the minimum is at least 1.
///
/// Returns the clamped brightness value.
pub fn clamp_brightness(
    brightness: u32,
    max_brightness: u32,
    percent: u32,
    is_backlight: bool,
) -> u32 {
    let min_brightness = ((max_brightness as u64 * percent as u64) / 100) as u32;
    let min_brightness = if is_backlight {
        std::cmp::max(1, min_brightness)
    } else {
        min_brightness
    };
    brightness.clamp(min_brightness, max_brightness)
}

/// Determine whether clamping should be applied and at what percent.
///
/// For backlight devices: defaults to `DEFAULT_CLAMP_PERCENT`.
/// For LED devices: defaults to 0 (no clamping).
///
/// The `property` value can be a boolean string ("yes"/"no") or a percentage.
pub fn parse_clamp_property(value: Option<&str>, is_backlight: bool) -> Result<u32, i32> {
    let default = if is_backlight {
        DEFAULT_CLAMP_PERCENT
    } else {
        0
    };

    match value {
        None => Ok(default),
        Some(s) => match s {
            "yes" | "true" | "1" | "on" => Ok(DEFAULT_CLAMP_PERCENT),
            "no" | "false" | "0" | "off" => Ok(0),
            other => {
                let pct: u32 = other.parse().map_err(|_| -libc::EINVAL)?;
                if pct > 100 {
                    Err(-libc::EINVAL)
                } else {
                    Ok(pct)
                }
            }
        },
    }
}

/// Validate that max_brightness is usable.
///
/// Returns `Ok(true)` if valid, `Ok(false)` if max is 0 (invalid device).
pub fn validate_max_brightness(max_brightness: u32) -> Result<bool, i32> {
    if max_brightness == 0 {
        Ok(false)
    } else {
        Ok(true)
    }
}

/// Build the save file path for a device.
///
/// Format: `/var/lib/systemd/backlight/[:escaped_path_id:]escaped_subsystem:escaped_sysname`
pub fn build_save_file_path(subsystem: &str, sysname: &str, path_id: Option<&str>) -> String {
    let escaped_subsystem = cescape(subsystem);
    let escaped_sysname = cescape(sysname);

    match path_id {
        Some(pid) => {
            let escaped_path_id = cescape(pid);
            format!(
                "{}{}:{}:{}",
                BACKLIGHT_VAR_PATH, escaped_path_id, escaped_subsystem, escaped_sysname
            )
        }
        None => {
            format!(
                "{}{}:{}",
                BACKLIGHT_VAR_PATH, escaped_subsystem, escaped_sysname
            )
        }
    }
}

/// Escape a string for use in a filename (C-style escaping).
///
/// Mirrors the C `cescape()` function: escapes control characters and
/// special chars using `\x..` sequences.
pub fn cescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Validate a backlight device against its type.
///
/// Non-raw types (firmware/platform) and LED devices are always valid.
/// Raw devices need further validation (not duplicated by a preferred type).
pub fn is_device_type_valid(bl_type: Option<BacklightType>, is_leds: bool) -> bool {
    if is_leds {
        return true;
    }
    match bl_type {
        Some(BacklightType::Raw) => false, // needs further validation
        Some(_) => true,                   // firmware/platform are always valid
        None => true,                      // unknown type, assume valid
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verb_from_str() {
        assert_eq!(BacklightVerb::from_str("save"), Some(BacklightVerb::Save));
        assert_eq!(BacklightVerb::from_str("load"), Some(BacklightVerb::Load));
        assert_eq!(BacklightVerb::from_str("other"), None);
    }

    #[test]
    fn test_backlight_type_from_str() {
        assert_eq!(
            BacklightType::from_str("firmware"),
            Some(BacklightType::Firmware)
        );
        assert_eq!(
            BacklightType::from_str("platform"),
            Some(BacklightType::Platform)
        );
        assert_eq!(BacklightType::from_str("raw"), Some(BacklightType::Raw));
        assert_eq!(BacklightType::from_str("other"), None);
    }

    #[test]
    fn test_backlight_type_is_preferred() {
        assert!(BacklightType::Firmware.is_preferred());
        assert!(BacklightType::Platform.is_preferred());
        assert!(!BacklightType::Raw.is_preferred());
    }

    #[test]
    fn test_device_spec_parse_valid() {
        let spec = DeviceSpec::parse("backlight:intel_backlight").unwrap();
        assert_eq!(spec.subsystem, "backlight");
        assert_eq!(spec.sysname, "intel_backlight");
    }

    #[test]
    fn test_device_spec_parse_leds() {
        let spec = DeviceSpec::parse("leds:input0::capslock").unwrap();
        assert_eq!(spec.subsystem, "leds");
        assert_eq!(spec.sysname, "input0::capslock");
    }

    #[test]
    fn test_device_spec_parse_no_colon() {
        assert!(DeviceSpec::parse("nocolon").is_err());
    }

    #[test]
    fn test_device_spec_parse_invalid_subsystem() {
        assert!(DeviceSpec::parse("net:eth0").is_err());
    }

    #[test]
    fn test_device_spec_parse_empty() {
        assert!(DeviceSpec::parse("").is_err());
        assert!(DeviceSpec::parse(":name").is_err());
        assert!(DeviceSpec::parse("backlight:").is_err());
    }

    #[test]
    fn test_clamp_brightness_backlight() {
        // 1% of 100 = 1, min is max(1,1)=1
        assert_eq!(clamp_brightness(0, 100, 1, true), 1);
        assert_eq!(clamp_brightness(50, 100, 1, true), 50);
        assert_eq!(clamp_brightness(200, 100, 1, true), 100);
    }

    #[test]
    fn test_clamp_brightness_leds() {
        // LEDs: 0% of 100 = 0, min is 0
        assert_eq!(clamp_brightness(0, 100, 0, false), 0);
        assert_eq!(clamp_brightness(50, 100, 0, false), 50);
    }

    #[test]
    fn test_clamp_brightness_high_percent() {
        // 50% of 100 = 50
        assert_eq!(clamp_brightness(10, 100, 50, true), 50);
    }

    #[test]
    fn test_parse_clamp_property_default_backlight() {
        assert_eq!(
            parse_clamp_property(None, true).unwrap(),
            DEFAULT_CLAMP_PERCENT
        );
    }

    #[test]
    fn test_parse_clamp_property_default_leds() {
        assert_eq!(parse_clamp_property(None, false).unwrap(), 0);
    }

    #[test]
    fn test_parse_clamp_property_yes() {
        assert_eq!(
            parse_clamp_property(Some("yes"), true).unwrap(),
            DEFAULT_CLAMP_PERCENT
        );
    }

    #[test]
    fn test_parse_clamp_property_no() {
        assert_eq!(parse_clamp_property(Some("no"), true).unwrap(), 0);
    }

    #[test]
    fn test_parse_clamp_property_percent() {
        assert_eq!(parse_clamp_property(Some("5"), true).unwrap(), 5);
    }

    #[test]
    fn test_parse_clamp_property_over_100() {
        assert!(parse_clamp_property(Some("200"), true).is_err());
    }

    #[test]
    fn test_validate_max_brightness() {
        assert!(validate_max_brightness(100).unwrap());
        assert!(!validate_max_brightness(0).unwrap());
    }

    #[test]
    fn test_cescape_plain() {
        assert_eq!(cescape("hello"), "hello");
    }

    #[test]
    fn test_cescape_backslash() {
        assert_eq!(cescape("a\\b"), "a\\\\b");
    }

    #[test]
    fn test_cescape_newline() {
        assert_eq!(cescape("a\nb"), "a\\nb");
    }

    #[test]
    fn test_build_save_file_path_with_id() {
        let path = build_save_file_path("backlight", "intel", Some("pci-0000:00:02.0"));
        assert!(path.starts_with(BACKLIGHT_VAR_PATH));
        assert!(path.contains("pci-0000:00:02.0"));
        assert!(path.contains("backlight"));
        assert!(path.contains("intel"));
    }

    #[test]
    fn test_build_save_file_path_without_id() {
        let path = build_save_file_path("backlight", "intel", None);
        assert_eq!(path, format!("{}backlight:intel", BACKLIGHT_VAR_PATH));
    }

    #[test]
    fn test_is_device_type_valid_leds() {
        assert!(is_device_type_valid(None, true));
    }

    #[test]
    fn test_is_device_type_valid_raw() {
        assert!(!is_device_type_valid(Some(BacklightType::Raw), false));
    }

    #[test]
    fn test_is_device_type_valid_firmware() {
        assert!(is_device_type_valid(Some(BacklightType::Firmware), false));
    }
}
