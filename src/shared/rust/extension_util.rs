// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/extension-util.c, src/shared/extension-util.h
//
// Extension image utilities for SYSEXT and CONFEXT.
//
// Handles validation of extension images against host OS release data,
// parsing of extension hierarchy environment variables, and default
// hierarchy management for system extension and configuration extension
// images.

// ── Enums ─────────────────────────────────────────────────────────────────

/// Extension image class: sysext or confext.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ImageClass {
    /// Configuration extension (merged under /etc).
    Confext,
    /// System extension (merged under /usr, /opt).
    #[default]
    Sysext,
}

impl ImageClass {
    /// The environment variable key for the extension level field.
    pub const fn level_key(self) -> &'static str {
        match self {
            ImageClass::Confext => "CONFEXT_LEVEL",
            ImageClass::Sysext => "SYSEXT_LEVEL",
        }
    }

    /// The environment variable key for the extension scope field.
    pub const fn scope_key(self) -> &'static str {
        match self {
            ImageClass::Confext => "CONFEXT_SCOPE",
            ImageClass::Sysext => "SYSEXT_SCOPE",
        }
    }

    /// The default hierarchy count for this image class.
    pub const fn default_hierarchy_count(self) -> usize {
        match self {
            ImageClass::Confext => 1,
            ImageClass::Sysext => 2,
        }
    }

    /// The default hierarchy environment variable name for this class.
    pub const fn hierarchy_env(self) -> &'static str {
        match self {
            ImageClass::Confext => "SYSTEMD_CONFEXT_HIERARCHIES",
            ImageClass::Sysext => "SYSTEMD_SYSEXT_HIERARCHIES",
        }
    }

    /// The default filesystem hierarchy paths for this image class.
    pub const fn default_hierarchies(self) -> &'static [&'static str] {
        match self {
            ImageClass::Confext => &["/etc"],
            ImageClass::Sysext => &["/usr", "/opt"],
        }
    }
}

// ── Environment variable names ────────────────────────────────────────────

/// Combined hierarchy environment variable (both sysext and confext).
pub const COMBINED_HIERARCHY_ENV: &str = "SYSTEMD_SYSEXT_AND_CONFEXT_HIERARCHIES";

/// Default scope entries when none are declared in the extension image.
pub const DEFAULT_SCOPE: &[&str] = &["system", "portable"];

/// The wildcard ID meaning the extension matches any host OS.
pub const ANY_ID: &str = "_any";

// ── Validation ────────────────────────────────────────────────────────────

/// Validate that an extension image is compatible with the host OS.
///
/// Checks the extension's release metadata (ID, VERSION_ID, extension level,
/// scope) against the host OS release data. Returns `true` if the extension
/// is compatible, `false` otherwise.
///
/// # Matching rules
///
/// 1. If the extension declares no `ID`, it is rejected.
/// 2. If the extension `ID` is `_any`, it matches any host.
/// 3. The extension `ID` must match the host `ID` or one of the `ID_LIKE` entries.
/// 4. If a `host_scope` is given, the extension's scope list must contain it.
/// 5. If both host and extension declare an extension level, they must match.
/// 6. Otherwise, if both declare a `VERSION_ID`, they must match.
/// 7. If no version information is available on either side, it matches.
pub fn extension_release_validate(
    host_id: &str,
    host_id_like: &[&str],
    host_version: Option<&str>,
    host_level: Option<&str>,
    host_scope: Option<&str>,
    extension: &[(&str, &str)],
    image_class: ImageClass,
) -> bool {
    /// Look up a key in the extension release key-value pairs.
    fn get<'a>(extension: &'a [(&str, &str)], key: &str) -> Option<&'a str> {
        extension
            .iter()
            .find_map(|(k, v)| (*k == key).then_some(*v))
    }

    // An extension with no release data cannot be validated.
    if extension.is_empty() {
        return false;
    }

    // Scope check: if the host specifies a scope, the extension must declare it.
    if let Some(scope) = host_scope {
        let listed = get(extension, image_class.scope_key()).unwrap_or("system portable");
        if !listed.split_whitespace().any(|v| v == scope) {
            return false;
        }
    }

    // ID check: required, "_any" is a wildcard.
    let ext_id = match get(extension, "ID") {
        Some(v) if v.is_empty() => return false,
        Some(ANY_ID) => return true,
        Some(v) => v,
        None => return false,
    };

    if ext_id != host_id && !host_id_like.contains(&ext_id) {
        return false;
    }

    // If neither host version nor host level is available, accept (rolling release).
    if host_version.is_none() && host_level.is_none() {
        return true;
    }

    // Level takes priority over VERSION_ID.
    match (host_level, get(extension, image_class.level_key())) {
        (Some(hl), Some(el)) if !hl.is_empty() && !el.is_empty() => return hl == el,
        _ => {}
    }

    // Fall back to VERSION_ID comparison.
    match (host_version, get(extension, "VERSION_ID")) {
        (Some(hv), Some(ev)) if !hv.is_empty() && !ev.is_empty() => hv == ev,
        _ => true,
    }
}

// ── Hierarchy parsing ─────────────────────────────────────────────────────

/// Parse an extension hierarchy environment variable.
///
/// If `value` is `Some`, splits it on `':'` and returns the non-empty entries.
/// If `value` is `None`, returns the default hierarchy for the recognized
/// environment variable names:
///
/// - `SYSTEMD_CONFEXT_HIERARCHIES` → `["/etc"]`
/// - `SYSTEMD_SYSEXT_HIERARCHIES` → `["/usr", "/opt"]`
/// - `SYSTEMD_SYSEXT_AND_CONFEXT_HIERARCHIES` → `["/usr", "/opt", "/etc"]`
///
/// Returns `Err(-libc::ENXIO)` for unrecognized variable names with no value.
pub fn parse_env_extension_hierarchies(
    name: &str,
    value: Option<&str>,
) -> Result<Vec<String>, i32> {
    match value {
        Some(v) => Ok(v
            .split(':')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()),
        None => match name {
            "SYSTEMD_CONFEXT_HIERARCHIES" => Ok(vec![String::from("/etc")]),
            "SYSTEMD_SYSEXT_HIERARCHIES" => Ok(vec![String::from("/usr"), String::from("/opt")]),
            "SYSTEMD_SYSEXT_AND_CONFEXT_HIERARCHIES" => Ok(vec![
                String::from("/usr"),
                String::from("/opt"),
                String::from("/etc"),
            ]),
            _ => Err(-libc::ENXIO),
        },
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ImageClass ─────────────────────────────────────────────────────

    #[test]
    fn image_class_default_is_sysext() {
        assert_eq!(ImageClass::default(), ImageClass::Sysext);
    }

    #[test]
    fn image_class_level_key() {
        assert_eq!(ImageClass::Sysext.level_key(), "SYSEXT_LEVEL");
        assert_eq!(ImageClass::Confext.level_key(), "CONFEXT_LEVEL");
    }

    #[test]
    fn image_class_scope_key() {
        assert_eq!(ImageClass::Sysext.scope_key(), "SYSEXT_SCOPE");
        assert_eq!(ImageClass::Confext.scope_key(), "CONFEXT_SCOPE");
    }

    #[test]
    fn image_class_hierarchy_count() {
        assert_eq!(ImageClass::Sysext.default_hierarchy_count(), 2);
        assert_eq!(ImageClass::Confext.default_hierarchy_count(), 1);
    }

    #[test]
    fn image_class_default_hierarchies() {
        assert_eq!(ImageClass::Sysext.default_hierarchies(), &["/usr", "/opt"]);
        assert_eq!(ImageClass::Confext.default_hierarchies(), &["/etc"]);
    }

    // ── extension_release_validate ─────────────────────────────────────

    #[test]
    fn validate_matches_host_version() {
        let ext = [("ID", "fedora"), ("VERSION_ID", "40")];
        assert!(extension_release_validate(
            "fedora",
            &[],
            Some("40"),
            None,
            None,
            &ext,
            ImageClass::Sysext
        ));
    }

    #[test]
    fn validate_rejects_version_mismatch() {
        let ext = [("ID", "fedora"), ("VERSION_ID", "39")];
        assert!(!extension_release_validate(
            "fedora",
            &[],
            Some("40"),
            None,
            None,
            &ext,
            ImageClass::Sysext
        ));
    }

    #[test]
    fn validate_accepts_any_id() {
        let ext = [("ID", "_any")];
        assert!(extension_release_validate(
            "ubuntu",
            &[],
            Some("24.04"),
            None,
            None,
            &ext,
            ImageClass::Sysext
        ));
    }

    #[test]
    fn validate_rejects_missing_id() {
        assert!(!extension_release_validate(
            "fedora",
            &[],
            Some("40"),
            None,
            None,
            &[],
            ImageClass::Sysext
        ));
    }

    #[test]
    fn validate_rejects_id_mismatch() {
        let ext = [("ID", "debian")];
        assert!(!extension_release_validate(
            "fedora",
            &[],
            Some("40"),
            None,
            None,
            &ext,
            ImageClass::Sysext
        ));
    }

    #[test]
    fn validate_matches_via_id_like() {
        let ext = [("ID", "rhel"), ("VERSION_ID", "9")];
        assert!(extension_release_validate(
            "fedora",
            &["rhel"],
            Some("9"),
            None,
            None,
            &ext,
            ImageClass::Sysext
        ));
    }

    #[test]
    fn validate_rolling_release_no_version() {
        let ext = [("ID", "arch")];
        // Host has no version info — rolling release, should pass.
        assert!(extension_release_validate(
            "arch",
            &[],
            None,
            None,
            None,
            &ext,
            ImageClass::Sysext
        ));
    }

    #[test]
    fn validate_level_takes_priority_over_version() {
        let ext = [("ID", "fedora"), ("SYSEXT_LEVEL", "5")];
        // Host level matches, VERSION_ID on host is ignored.
        assert!(extension_release_validate(
            "fedora",
            &[],
            Some("40"),
            Some("5"),
            None,
            &ext,
            ImageClass::Sysext
        ));
    }

    #[test]
    fn validate_rejects_level_mismatch() {
        let ext = [("ID", "fedora"), ("SYSEXT_LEVEL", "4")];
        assert!(!extension_release_validate(
            "fedora",
            &[],
            Some("40"),
            Some("5"),
            None,
            &ext,
            ImageClass::Sysext
        ));
    }

    #[test]
    fn validate_scope_rejects_unknown_scope() {
        let ext = [("ID", "fedora"), ("SYSEXT_SCOPE", "initrd")];
        assert!(!extension_release_validate(
            "fedora",
            &[],
            None,
            None,
            Some("portable"),
            &ext,
            ImageClass::Sysext
        ));
    }

    #[test]
    fn validate_scope_accepts_matching_scope() {
        let ext = [("ID", "fedora"), ("SYSEXT_SCOPE", "system portable")];
        assert!(extension_release_validate(
            "fedora",
            &[],
            None,
            None,
            Some("portable"),
            &ext,
            ImageClass::Sysext
        ));
    }

    #[test]
    fn validate_confext_level_key() {
        let ext = [("ID", "fedora"), ("CONFEXT_LEVEL", "2")];
        assert!(extension_release_validate(
            "fedora",
            &[],
            None,
            Some("2"),
            None,
            &ext,
            ImageClass::Confext
        ));
    }

    // ── parse_env_extension_hierarchies ────────────────────────────────

    #[test]
    fn hierarchies_custom_value() {
        assert_eq!(
            parse_env_extension_hierarchies("SYSTEMD_SYSEXT_HIERARCHIES", Some("/usr:/opt:/srv"))
                .unwrap(),
            vec!["/usr", "/opt", "/srv"]
        );
    }

    #[test]
    fn hierarchies_custom_value_skips_empty() {
        assert_eq!(
            parse_env_extension_hierarchies("SYSTEMD_SYSEXT_HIERARCHIES", Some("::/usr::/opt"))
                .unwrap(),
            vec!["/usr", "/opt"]
        );
    }

    #[test]
    fn hierarchies_default_sysext() {
        assert_eq!(
            parse_env_extension_hierarchies("SYSTEMD_SYSEXT_HIERARCHIES", None).unwrap(),
            vec!["/usr", "/opt"]
        );
    }

    #[test]
    fn hierarchies_default_confext() {
        assert_eq!(
            parse_env_extension_hierarchies("SYSTEMD_CONFEXT_HIERARCHIES", None).unwrap(),
            vec!["/etc"]
        );
    }

    #[test]
    fn hierarchies_default_combined() {
        assert_eq!(
            parse_env_extension_hierarchies("SYSTEMD_SYSEXT_AND_CONFEXT_HIERARCHIES", None)
                .unwrap(),
            vec!["/usr", "/opt", "/etc"]
        );
    }

    #[test]
    fn hierarchies_unknown_env_returns_enxio() {
        assert_eq!(
            parse_env_extension_hierarchies("SOME_UNKNOWN_VAR", None).unwrap_err(),
            -libc::ENXIO
        );
    }
}
