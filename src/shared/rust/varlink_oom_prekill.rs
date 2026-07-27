// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.oom.Prekill.c
//
// Varlink interface definition for io.systemd.oom.Prekill
// Prekill notifications from oomd. Available through /run/systemd/oomd.prekill.hook/

pub const INTERFACE_NAME: &str = "io.systemd.oom.Prekill";

pub const METHOD_NOTIFY: &str = "io.systemd.oom.Prekill.Notify";

pub const PARAM_CGROUP: &str = "cgroup";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrekillError {
    EmptyCgroup,
    InvalidCgroupPath(String),
    UnknownMethod(String),
}

impl std::fmt::Display for PrekillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrekillError::EmptyCgroup => write!(f, "cgroup path must not be empty"),
            PrekillError::InvalidCgroupPath(p) => write!(f, "invalid cgroup path: {p}"),
            PrekillError::UnknownMethod(m) => write!(f, "unknown method: {m}"),
        }
    }
}

impl std::error::Error for PrekillError {}

pub fn get_interface_definition() -> &'static str {
    r#"{
  "types": [],
  "methods": {
    "Notify": {
      "description": "Notify about an imminent OOM kill",
      "parameters": {
        "cgroup": {
          "type": "string",
          "description": "The cgroup which is going to be killed"
        }
      },
      "return": {}
    }
  },
  "interface": "io.systemd.oom.Prekill",
  "description": "Prekill notifications from oomd"
}"#
}

#[derive(Debug, Clone)]
pub struct NotifyParams {
    pub cgroup: String,
}

impl NotifyParams {
    pub fn new(cgroup: impl Into<String>) -> Self {
        Self {
            cgroup: cgroup.into(),
        }
    }

    pub fn validate(&self) -> Result<(), PrekillError> {
        if self.cgroup.is_empty() {
            return Err(PrekillError::EmptyCgroup);
        }
        if !self.cgroup.starts_with('/') {
            return Err(PrekillError::InvalidCgroupPath(self.cgroup.clone()));
        }
        Ok(())
    }

    pub fn slice_name(&self) -> Option<&str> {
        let trimmed = self.cgroup.trim_start_matches('/');
        let start = trimmed.find(".slice/")?;
        let end = start + ".slice".len();
        let candidate = &trimmed[..end];
        if candidate.ends_with(".slice") {
            Some(candidate)
        } else {
            None
        }
    }

    pub fn is_system_slice(&self) -> bool {
        self.cgroup.contains("system.slice")
    }

    pub fn is_user_slice(&self) -> bool {
        self.cgroup.contains("user.slice") || self.cgroup.contains("user-")
    }
}

pub fn validate_method_name(method: &str) -> Result<&str, PrekillError> {
    if method == METHOD_NOTIFY {
        Ok(method)
    } else {
        Err(PrekillError::UnknownMethod(method.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.oom.Prekill");
    }

    #[test]
    fn test_method_name() {
        assert_eq!(METHOD_NOTIFY, "io.systemd.oom.Prekill.Notify");
    }

    #[test]
    fn test_param_name() {
        assert_eq!(PARAM_CGROUP, "cgroup");
    }

    #[test]
    fn test_interface_definition_valid_json() {
        let json = get_interface_definition();
        assert!(json.contains("io.systemd.oom.Prekill"));
        assert!(json.contains("Notify"));
        assert!(json.contains("cgroup"));
        assert!(json.contains("The cgroup which is going to be killed"));
    }

    #[test]
    fn test_notify_params() {
        let params = NotifyParams::new("/user.slice/user-1000.slice/session-1.scope");
        assert_eq!(params.cgroup, "/user.slice/user-1000.slice/session-1.scope");
    }

    #[test]
    fn test_notify_params_from_string() {
        let cgroup = String::from("/system.slice/nginx.service");
        let params = NotifyParams::new(cgroup);
        assert_eq!(params.cgroup, "/system.slice/nginx.service");
    }

    #[test]
    fn test_notify_params_clone() {
        let params = NotifyParams::new("/test.cgroup");
        let cloned = params.clone();
        assert_eq!(params.cgroup, cloned.cgroup);
    }

    #[test]
    fn test_notify_params_validate_ok() {
        let params = NotifyParams::new("/system.slice/test.service");
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_notify_params_validate_empty() {
        let params = NotifyParams::new("");
        assert_eq!(params.validate(), Err(PrekillError::EmptyCgroup));
    }

    #[test]
    fn test_notify_params_validate_no_slash() {
        let params = NotifyParams::new("relative/path");
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_notify_params_is_system_slice() {
        let params = NotifyParams::new("/system.slice/nginx.service");
        assert!(params.is_system_slice());
        assert!(!params.is_user_slice());
    }

    #[test]
    fn test_notify_params_is_user_slice() {
        let params = NotifyParams::new("/user.slice/user-1000.slice/session-1.scope");
        assert!(params.is_user_slice());
        assert!(!params.is_system_slice());
    }

    #[test]
    fn test_validate_method_name_ok() {
        assert!(validate_method_name(METHOD_NOTIFY).is_ok());
    }

    #[test]
    fn test_validate_method_name_unknown() {
        assert!(validate_method_name("io.systemd.oom.Prekill.Bogus").is_err());
    }

    #[test]
    fn test_notify_params_debug_format() {
        let params = NotifyParams::new("/test.slice");
        let debug = format!("{params:?}");
        assert!(debug.contains("cgroup"));
        assert!(debug.contains("/test.slice"));
    }
}
