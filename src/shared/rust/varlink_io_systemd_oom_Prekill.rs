// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.oom.Prekill.c
//
// Varlink interface definition for io.systemd.oom.Prekill.
//
// Prekill notifications from oomd. The Notify method is called when
// a cgroup is about to be killed due to memory pressure.

// ── Constants ─────────────────────────────────────────────────────────────

/// Fully qualified varlink interface name.
pub const INTERFACE_NAME: &str = "io.systemd.oom.Prekill";

/// Method name for prekill notification.
pub const METHOD_NOTIFY: &str = "Notify";

// ── Method identifiers ────────────────────────────────────────────────────

/// All method names defined by this interface.
pub fn method_names() -> &'static [&'static str] {
    &[METHOD_NOTIFY]
}

/// Check whether a method name belongs to this interface.
pub fn has_method(name: &str) -> bool {
    method_names().contains(&name)
}

/// Typed method identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrekillMethod {
    Notify,
}

impl PrekillMethod {
    /// Return the varlink method name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Notify => METHOD_NOTIFY,
        }
    }
}

/// Parse a method name into a typed identifier.
pub fn parse_method(name: &str) -> Result<PrekillMethod, String> {
    match name {
        METHOD_NOTIFY => Ok(PrekillMethod::Notify),
        _ => Err(format!("unknown method: {name}")),
    }
}

// ── Method I/O structs ────────────────────────────────────────────────────

/// Input parameters for the Notify method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyInput {
    /// The cgroup which is going to be killed.
    pub cgroup: String,
}

impl NotifyInput {
    /// Create a new NotifyInput with the given cgroup path.
    pub fn new(cgroup: &str) -> Self {
        Self {
            cgroup: cgroup.to_string(),
        }
    }

    /// Validate the input. The cgroup path must be non-empty.
    pub fn validate(&self) -> Result<(), String> {
        if self.cgroup.is_empty() {
            return Err("cgroup must not be empty".to_string());
        }
        Ok(())
    }
}

/// Error names defined by this interface.
pub fn error_names() -> &'static [&'static str] {
    &[]
}

/// Check if a cgroup path looks like a valid cgroup v2 path.
pub fn is_valid_cgroup_path(path: &str) -> bool {
    !path.is_empty() && path.starts_with('/')
}

/// Extract the last component of a cgroup path.
pub fn cgroup_name(path: &str) -> Option<&str> {
    if path.is_empty() {
        return None;
    }
    path.trim_end_matches('/').rsplit('/').next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.oom.Prekill");
    }

    #[test]
    fn test_method_names() {
        assert_eq!(method_names().len(), 1);
        assert!(method_names().contains(&METHOD_NOTIFY));
    }

    #[test]
    fn test_has_method() {
        assert!(has_method("Notify"));
        assert!(!has_method("Unknown"));
    }

    #[test]
    fn test_parse_method_notify() {
        assert_eq!(parse_method("Notify"), Ok(PrekillMethod::Notify));
    }

    #[test]
    fn test_parse_method_unknown() {
        assert!(parse_method("bogus").is_err());
    }

    #[test]
    fn test_method_name_roundtrip() {
        let m = parse_method("Notify").unwrap();
        assert_eq!(m.name(), "Notify");
    }

    #[test]
    fn test_notify_input_new() {
        let input = NotifyInput::new("/sys/fs/cgroup/test.slice");
        assert_eq!(input.cgroup, "/sys/fs/cgroup/test.slice");
    }

    #[test]
    fn test_notify_input_validate() {
        let input = NotifyInput::new("/sys/fs/cgroup/test");
        assert!(input.validate().is_ok());

        let empty = NotifyInput::new("");
        assert!(empty.validate().is_err());
    }

    #[test]
    fn test_error_names_empty() {
        assert!(error_names().is_empty());
    }

    #[test]
    fn test_is_valid_cgroup_path() {
        assert!(is_valid_cgroup_path("/sys/fs/cgroup/test"));
        assert!(!is_valid_cgroup_path(""));
        assert!(!is_valid_cgroup_path("relative/path"));
    }

    #[test]
    fn test_cgroup_name() {
        assert_eq!(cgroup_name("/sys/fs/cgroup/test.slice"), Some("test.slice"));
        assert_eq!(cgroup_name("/test"), Some("test"));
        assert_eq!(cgroup_name("/"), Some(""));
        assert_eq!(cgroup_name(""), None);
    }

    #[test]
    fn test_prekill_method_name() {
        assert_eq!(PrekillMethod::Notify.name(), "Notify");
    }
}
