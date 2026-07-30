// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/vconsole/vconsole-setup.c
//
// Virtual console (keyboard and font) configuration tool.
//
// Implements the systemd-vconsole-setup tool which configures the virtual
// console keyboard mapping and console font based on configuration from
// /etc/vconsole.conf, kernel command line parameters, and system credentials.
// It handles UTF-8 mode toggling, keyboard layout loading via loadkeys,
// and font loading via setfont, propagating settings to all allocated VCs.

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum number of virtual consoles to scan.
pub const VC_MAX: u32 = 63;

/// Default keymap used when no keymap is configured.
pub const SYSTEMD_DEFAULT_KEYMAP: &str = "us";

/// Keyboard binary paths.
pub const KBD_LOADKEYS: &str = "/usr/bin/loadkeys";
pub const KBD_SETFONT: &str = "/usr/bin/setfont";

/// Configuration file path.
pub const VCONSOLE_CONF: &str = "/etc/vconsole.conf";

/// Default file mode for directories created by this tool.
pub const DEFAULT_UMASK: u32 = 0o022;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Result of loading a keyboard or font configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadResult {
    /// Nothing to do (no configuration provided)
    Skipped,
    /// Configuration was loaded successfully
    Applied,
    /// Tool not available, operation skipped
    NotAvailable,
}

// ── Console context ───────────────────────────────────────────────────────

/// Virtual console configuration context.
///
/// Holds all configurable parameters read from various sources
/// (credentials, config file, kernel command line).
#[derive(Debug, Clone, Default)]
pub struct VconsoleContext {
    /// Keyboard mapping name (e.g., "us", "de-latin1")
    pub keymap: Option<String>,
    /// Toggle keymap for keyboard layout switching
    pub keymap_toggle: Option<String>,
    /// Console font name
    pub font: Option<String>,
    /// Console font map file
    pub font_map: Option<String>,
    /// Console font Unicode map file
    pub font_unimap: Option<String>,
}

fn merge_field(dst: &mut Option<String>, src: &Option<String>, compat: Option<&Option<String>>) {
    if src.is_some() {
        *dst = src.clone();
    } else if let Some(Some(compat_val)) = compat {
        *dst = Some(compat_val.clone());
    }
}

impl VconsoleContext {
    /// Create a new empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge another context into this one, taking non-None values from `src`.
    /// If `src_compat` is provided and `src` has None, try `src_compat`.
    pub fn merge(&mut self, src: &VconsoleContext, src_compat: Option<&VconsoleContext>) {
        merge_field(&mut self.keymap, &src.keymap, src_compat.map(|c| &c.keymap));
        merge_field(
            &mut self.keymap_toggle,
            &src.keymap_toggle,
            src_compat.map(|c| &c.keymap_toggle),
        );
        merge_field(&mut self.font, &src.font, src_compat.map(|c| &c.font));
        merge_field(
            &mut self.font_map,
            &src.font_map,
            src_compat.map(|c| &c.font_map),
        );
        merge_field(
            &mut self.font_unimap,
            &src.font_unimap,
            src_compat.map(|c| &c.font_unimap),
        );
    }
}

// ── Credential key names ──────────────────────────────────────────────────

/// Credential keys for vconsole configuration.
pub const CRED_KEYMAP: &str = "vconsole.keymap";
pub const CRED_KEYMAP_TOGGLE: &str = "vconsole.keymap_toggle";
pub const CRED_FONT: &str = "vconsole.font";
pub const CRED_FONT_MAP: &str = "vconsole.font_map";
pub const CRED_FONT_UNIMAP: &str = "vconsole.font_unimap";

// ── Config file keys ──────────────────────────────────────────────────────

/// Configuration file keys for /etc/vconsole.conf.
pub const CONF_KEYMAP: &str = "KEYMAP";
pub const CONF_KEYMAP_TOGGLE: &str = "KEYMAP_TOGGLE";
pub const CONF_FONT: &str = "FONT";
pub const CONF_FONT_MAP: &str = "FONT_MAP";
pub const CONF_FONT_UNIMAP: &str = "FONT_UNIMAP";

// ── Kernel command line keys ──────────────────────────────────────────────

/// Kernel command line parameter names.
pub const CMDLINE_KEYMAP: &str = "vconsole.keymap";
pub const CMDLINE_KEYMAP_TOGGLE: &str = "vconsole.keymap_toggle";
pub const CMDLINE_FONT: &str = "vconsole.font";
pub const CMDLINE_FONT_MAP: &str = "vconsole.font_map";
pub const CMDLINE_FONT_UNIMAP: &str = "vconsole.font_unimap";

/// Compatibility (obsolete multi-dot) kernel cmdline keys.
pub const CMDLINE_KEYMAP_TOGGLE_COMPAT: &str = "vconsole.keymap.toggle";
pub const CMDLINE_FONT_MAP_COMPAT: &str = "vconsole.font.map";
pub const CMDLINE_FONT_UNIMAP_COMPAT: &str = "vconsole.font.unimap";

// ── UTF-8 toggle helpers ──────────────────────────────────────────────────

/// Escape sequence to enable UTF-8 on terminal.
pub const UTF8_ENABLE_SEQ: &[u8] = b"\x1b%G";
/// Escape sequence to disable UTF-8 on terminal.
pub const UTF8_DISABLE_SEQ: &[u8] = b"\x1b%@";

/// Sysfs path for the default UTF-8 flag.
pub const SYSFS_UTF8_PATH: &str = "/sys/module/vt/parameters/default_utf8";

// ── Keyboard load args builder ────────────────────────────────────────────

/// Build the loadkeys argument list.
pub fn build_loadkeys_args(
    vc: &str,
    keymap: &str,
    keymap_toggle: Option<&str>,
    utf8: bool,
) -> Vec<String> {
    let mut args = vec![
        KBD_LOADKEYS.to_string(),
        "-q".to_string(),
        "-C".to_string(),
        vc.to_string(),
    ];
    if utf8 {
        args.push("-u".to_string());
    }
    args.push(keymap.to_string());
    if let Some(toggle) = keymap_toggle {
        args.push(toggle.to_string());
    }
    args
}

/// Build the setfont argument list.
pub fn build_setfont_args(
    vc: &str,
    font: Option<&str>,
    font_map: Option<&str>,
    font_unimap: Option<&str>,
) -> Vec<String> {
    let mut args = vec![KBD_SETFONT.to_string(), "-C".to_string(), vc.to_string()];
    if let Some(map) = font_map {
        args.push("-m".to_string());
        args.push(map.to_string());
    }
    if let Some(unimap) = font_unimap {
        args.push("-u".to_string());
        args.push(unimap.to_string());
    }
    if let Some(f) = font {
        args.push(f.to_string());
    }
    args
}

/// Resolve the effective keymap: use the configured keymap or fall back to the default.
/// Returns None if the keymap is "@kernel" (meaning: skip loading).
pub fn effective_keymap(keymap: Option<&str>) -> Option<&str> {
    let km = keymap.unwrap_or(SYSTEMD_DEFAULT_KEYMAP);
    if km.is_empty() {
        return Some(SYSTEMD_DEFAULT_KEYMAP);
    }
    if km == "@kernel" {
        return None;
    }
    Some(km)
}

/// Check whether font loading should be attempted.
/// Font loading is needed if any of font, font_map, or font_unimap is configured.
pub fn font_loading_needed(ctx: &VconsoleContext) -> bool {
    ctx.font.is_some() || ctx.font_map.is_some() || ctx.font_unimap.is_some()
}

// ── VC path helpers ───────────────────────────────────────────────────────

/// Generate the device path for a virtual console by index.
pub fn vc_path(idx: u32) -> String {
    format!("/dev/tty{}", idx)
}

/// Generate the VCS path for checking VC allocation.
pub fn vcs_path(idx: u32) -> String {
    format!("/dev/vcs{}", idx)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vconsole_context_merge_basic() {
        let mut dst = VconsoleContext::default();
        let src = VconsoleContext {
            keymap: Some("de-latin1".to_string()),
            font: Some("latarcyrheb-sun16".to_string()),
            ..Default::default()
        };
        dst.merge(&src, None);
        assert_eq!(dst.keymap, Some("de-latin1".to_string()));
        assert_eq!(dst.font, Some("latarcyrheb-sun16".to_string()));
        assert!(dst.keymap_toggle.is_none());
    }

    #[test]
    fn test_vconsole_context_merge_compat() {
        let mut dst = VconsoleContext::default();
        let src = VconsoleContext::default();
        let compat = VconsoleContext {
            keymap_toggle: Some("de-latin1-nodeadkeys".to_string()),
            ..Default::default()
        };
        dst.merge(&src, Some(&compat));
        assert_eq!(dst.keymap_toggle, Some("de-latin1-nodeadkeys".to_string()));
    }

    #[test]
    fn test_vconsole_context_merge_src_priority() {
        let mut dst = VconsoleContext::default();
        let src = VconsoleContext {
            keymap: Some("us".to_string()),
            ..Default::default()
        };
        let compat = VconsoleContext {
            keymap: Some("de".to_string()),
            ..Default::default()
        };
        dst.merge(&src, Some(&compat));
        assert_eq!(dst.keymap, Some("us".to_string()));
    }

    #[test]
    fn test_effective_keymap_configured() {
        assert_eq!(effective_keymap(Some("de-latin1")), Some("de-latin1"));
    }

    #[test]
    fn test_effective_keymap_default() {
        assert_eq!(effective_keymap(None), Some(SYSTEMD_DEFAULT_KEYMAP));
        assert_eq!(effective_keymap(Some("")), Some(SYSTEMD_DEFAULT_KEYMAP));
    }

    #[test]
    fn test_effective_keymap_kernel() {
        assert_eq!(effective_keymap(Some("@kernel")), None);
    }

    #[test]
    fn test_build_loadkeys_args() {
        let args = build_loadkeys_args("/dev/tty1", "us", None, true);
        assert_eq!(
            args,
            vec!["/usr/bin/loadkeys", "-q", "-C", "/dev/tty1", "-u", "us"]
        );

        let args_no_utf8 = build_loadkeys_args("/dev/tty1", "de", Some("de-nodeadkeys"), false);
        assert_eq!(
            args_no_utf8,
            vec![
                "/usr/bin/loadkeys",
                "-q",
                "-C",
                "/dev/tty1",
                "de",
                "de-nodeadkeys"
            ]
        );
    }

    #[test]
    fn test_build_setfont_args() {
        let args = build_setfont_args("/dev/tty1", Some("latarcyrheb-sun16"), None, None);
        assert_eq!(
            args,
            vec!["/usr/bin/setfont", "-C", "/dev/tty1", "latarcyrheb-sun16"]
        );

        let args_full = build_setfont_args("/dev/tty1", Some("font"), Some("map"), Some("unimap"));
        assert_eq!(
            args_full,
            vec![
                "/usr/bin/setfont",
                "-C",
                "/dev/tty1",
                "-m",
                "map",
                "-u",
                "unimap",
                "font"
            ]
        );
    }

    #[test]
    fn test_font_loading_needed() {
        let ctx_empty = VconsoleContext::default();
        assert!(!font_loading_needed(&ctx_empty));

        let ctx_font = VconsoleContext {
            font: Some("test".to_string()),
            ..Default::default()
        };
        assert!(font_loading_needed(&ctx_font));

        let ctx_map = VconsoleContext {
            font_map: Some("test".to_string()),
            ..Default::default()
        };
        assert!(font_loading_needed(&ctx_map));
    }

    #[test]
    fn test_vc_path() {
        assert_eq!(vc_path(1), "/dev/tty1");
        assert_eq!(vc_path(63), "/dev/tty63");
    }

    #[test]
    fn test_vcs_path() {
        assert_eq!(vcs_path(1), "/dev/vcs1");
        assert_eq!(vcs_path(10), "/dev/vcs10");
    }

    #[test]
    fn test_load_result() {
        assert_eq!(LoadResult::Skipped, LoadResult::Skipped);
        assert_ne!(LoadResult::Skipped, LoadResult::Applied);
        assert_ne!(LoadResult::Applied, LoadResult::NotAvailable);
    }
}
