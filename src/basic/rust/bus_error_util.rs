// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-error.c
//
// D-Bus error accessor functions: is_dirty, is_set, has_name.

// ── SdBusError struct ─────────────────────────────────────────────────────

/// Mirrors C struct sd_bus_error from sd-bus-protocol.h.
#[derive(Debug, Clone)]
pub struct SdBusError {
    pub name: Option<String>,
    pub message: Option<String>,
    pub need_free: bool,
}

impl Default for SdBusError {
    fn default() -> Self {
        Self {
            name: None,
            message: None,
            need_free: false,
        }
    }
}

impl SdBusError {
    /// Create a null/empty error (SD_BUS_ERROR_NULL).
    pub fn null() -> Self {
        Self::default()
    }

    /// Create a const error from static name and message (SD_BUS_ERROR_MAKE_CONST).
    pub fn make_const(name: &str, message: &str) -> Self {
        Self {
            name: Some(name.to_owned()),
            message: Some(message.to_owned()),
            need_free: false,
        }
    }
}

// ── bus_error_is_dirty ────────────────────────────────────────────────────

/// Check if the error struct has been modified (has name, message, or need_free set).
/// Matches C bus_error_is_dirty(): true if any field is non-zero/non-NULL.
pub fn bus_error_is_dirty(e: Option<&SdBusError>) -> bool {
    match e {
        None => false,
        Some(err) => err.name.is_some() || err.message.is_some() || err.need_free,
    }
}

// ── sd_bus_error_is_set ───────────────────────────────────────────────────

/// Check if the error has a name set (i.e., is in an error state).
/// Matches C sd_bus_error_is_set(): true iff name is non-NULL.
pub fn sd_bus_error_is_set(e: Option<&SdBusError>) -> bool {
    match e {
        None => false,
        Some(err) => err.name.is_some(),
    }
}

// ── sd_bus_error_has_name ─────────────────────────────────────────────────

/// Check if the error has a specific name.
/// Matches C sd_bus_error_has_name(): streq_ptr semantics —
/// both NULL → true, one NULL → false, both non-NULL → string equality.
pub fn sd_bus_error_has_name(e: Option<&SdBusError>, name: Option<&str>) -> bool {
    match (e, name) {
        (None, _) => false,
        (Some(err), None) => err.name.is_none(),
        (Some(err), Some(n)) => match &err.name {
            None => false,
            Some(en) => en == n,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_error(name: &str, message: &str) -> SdBusError {
        SdBusError {
            name: Some(name.to_owned()),
            message: Some(message.to_owned()),
            need_free: true,
        }
    }

    #[test]
    fn test_bus_error_is_dirty_null() {
        assert!(!bus_error_is_dirty(None));
    }

    #[test]
    fn test_bus_error_is_dirty_default() {
        let e = SdBusError::default();
        assert!(!bus_error_is_dirty(Some(&e)));
    }

    #[test]
    fn test_bus_error_is_dirty_with_name() {
        let e = SdBusError {
            name: Some("org.freedesktop.DBus.Error.Failed".to_owned()),
            message: None,
            need_free: false,
        };
        assert!(bus_error_is_dirty(Some(&e)));
    }

    #[test]
    fn test_bus_error_is_dirty_with_message() {
        let e = SdBusError {
            name: None,
            message: Some("something failed".to_owned()),
            need_free: false,
        };
        assert!(bus_error_is_dirty(Some(&e)));
    }

    #[test]
    fn test_bus_error_is_dirty_with_need_free() {
        let e = SdBusError {
            name: None,
            message: None,
            need_free: true,
        };
        assert!(bus_error_is_dirty(Some(&e)));
    }

    #[test]
    fn test_sd_bus_error_is_set_null() {
        assert!(!sd_bus_error_is_set(None));
    }

    #[test]
    fn test_sd_bus_error_is_set_default() {
        let e = SdBusError::default();
        assert!(!sd_bus_error_is_set(Some(&e)));
    }

    #[test]
    fn test_sd_bus_error_is_set_with_name() {
        let e = make_error("org.freedesktop.DBus.Error.Failed", "oops");
        assert!(sd_bus_error_is_set(Some(&e)));
    }

    #[test]
    fn test_sd_bus_error_has_name_null_error() {
        assert!(!sd_bus_error_has_name(None, Some("test")));
    }

    #[test]
    fn test_sd_bus_error_has_name_both_none() {
        let e = SdBusError::default();
        assert!(sd_bus_error_has_name(Some(&e), None));
    }

    #[test]
    fn test_sd_bus_error_has_name_match() {
        let e = make_error("org.freedesktop.DBus.Error.Failed", "oops");
        assert!(sd_bus_error_has_name(
            Some(&e),
            Some("org.freedesktop.DBus.Error.Failed")
        ));
    }

    #[test]
    fn test_sd_bus_error_has_name_no_match() {
        let e = make_error("org.freedesktop.DBus.Error.Failed", "oops");
        assert!(!sd_bus_error_has_name(
            Some(&e),
            Some("org.freedesktop.DBus.Error.IOError")
        ));
    }

    #[test]
    fn test_sd_bus_error_has_name_error_without_name() {
        let e = SdBusError {
            name: None,
            message: Some("msg".to_owned()),
            need_free: false,
        };
        assert!(!sd_bus_error_has_name(Some(&e), Some("test")));
    }

    #[test]
    fn test_sd_bus_error_make_const() {
        let e = SdBusError::make_const("Test.Error", "message");
        assert_eq!(e.name.as_deref(), Some("Test.Error"));
        assert_eq!(e.message.as_deref(), Some("message"));
        assert!(!e.need_free);
    }

    #[test]
    fn test_sd_bus_error_null() {
        let e = SdBusError::null();
        assert!(e.name.is_none());
        assert!(e.message.is_none());
        assert!(!e.need_free);
        assert!(!bus_error_is_dirty(Some(&e)));
        assert!(!sd_bus_error_is_set(Some(&e)));
    }
}
