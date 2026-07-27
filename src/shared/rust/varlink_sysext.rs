// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.sysext.c
//
// Varlink interface definition for io.systemd.sysext
// System extension image management.

pub const INTERFACE_NAME: &str = "io.systemd.sysext";

pub const METHOD_MERGE: &str = "io.systemd.sysext.Merge";
pub const METHOD_UNMERGE: &str = "io.systemd.sysext.Unmerge";
pub const METHOD_REFRESH: &str = "io.systemd.sysext.Refresh";
pub const METHOD_LIST: &str = "io.systemd.sysext.List";

pub const ERROR_NO_IMAGES_FOUND: &str = "io.systemd.sysext.NoImagesFound";
pub const ERROR_ALREADY_MERGED: &str = "io.systemd.sysext.AlreadyMerged";

pub const PARAM_CLASS: &str = "class";
pub const PARAM_FORCE: &str = "force";
pub const PARAM_NO_RELOAD: &str = "noReload";
pub const PARAM_NOEXEC: &str = "noexec";
pub const PARAM_ALWAYS_REFRESH: &str = "alwaysRefresh";
pub const PARAM_HIERARCHY: &str = "hierarchy";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageClass {
    Sysext,
    Confext,
}

impl ImageClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            ImageClass::Sysext => "sysext",
            ImageClass::Confext => "confext",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "sysext" => Some(ImageClass::Sysext),
            "confext" => Some(ImageClass::Confext),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageType {
    Directory,
    Subvolume,
    Raw,
    Block,
    Mstack,
}

impl ImageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ImageType::Directory => "directory",
            ImageType::Subvolume => "subvolume",
            ImageType::Raw => "raw",
            ImageType::Block => "block",
            ImageType::Mstack => "mstack",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "directory" => Some(ImageType::Directory),
            "subvolume" => Some(ImageType::Subvolume),
            "raw" => Some(ImageType::Raw),
            "block" => Some(ImageType::Block),
            "mstack" => Some(ImageType::Mstack),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysextError {
    UnknownMethod(String),
    InvalidClass(String),
}

impl std::fmt::Display for SysextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SysextError::UnknownMethod(m) => write!(f, "unknown method: {m}"),
            SysextError::InvalidClass(c) => write!(f, "invalid image class: {c}"),
        }
    }
}

impl std::error::Error for SysextError {}

pub fn get_interface_definition() -> &'static str {
    r#"{
  "types": [
    {
      "name": "ImageClass",
      "type": "enum",
      "values": ["sysext", "confext"]
    },
    {
      "name": "ImageType",
      "type": "enum",
      "values": ["directory", "subvolume", "raw", "block", "mstack"]
    }
  ],
  "methods": {
    "Merge": {
      "parameters": {
        "class": { "type": "ImageClass", "nullable": true },
        "force": { "type": "bool", "nullable": true },
        "noReload": { "type": "bool", "nullable": true },
        "noexec": { "type": "bool", "nullable": true }
      }
    },
    "Unmerge": {
      "parameters": {
        "class": { "type": "ImageClass", "nullable": true },
        "noReload": { "type": "bool", "nullable": true }
      }
    },
    "Refresh": {
      "parameters": {
        "class": { "type": "ImageClass", "nullable": true },
        "force": { "type": "bool", "nullable": true },
        "noReload": { "type": "bool", "nullable": true },
        "alwaysRefresh": { "type": "bool", "nullable": true },
        "noexec": { "type": "bool", "nullable": true }
      }
    },
    "List": {
      "parameters": {
        "class": { "type": "ImageClass", "nullable": true }
      },
      "return": {
        "Class": { "type": "ImageClass" },
        "Type": { "type": "ImageType" },
        "Name": { "type": "string" },
        "Path": { "type": "string", "nullable": true },
        "ReadOnly": { "type": "bool" },
        "CreationTimestamp": { "type": "int", "nullable": true },
        "ModificationTimestamp": { "type": "int", "nullable": true },
        "Usage": { "type": "int", "nullable": true },
        "UsageExclusive": { "type": "int", "nullable": true },
        "Limit": { "type": "int", "nullable": true },
        "LimitExclusive": { "type": "int", "nullable": true }
      },
      "flags": ["more"]
    }
  },
  "errors": {
    "NoImagesFound": { "description": "No images found." },
    "AlreadyMerged": {
      "description": "Already merged.",
      "fields": { "hierarchy": { "type": "string" } }
    }
  },
  "interface": "io.systemd.sysext"
}"#
}

#[derive(Debug, Clone, Default)]
pub struct MergeParams {
    pub class: Option<ImageClass>,
    pub force: Option<bool>,
    pub no_reload: Option<bool>,
    pub noexec: Option<bool>,
}

impl MergeParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn class(mut self, c: ImageClass) -> Self {
        self.class = Some(c);
        self
    }

    pub fn force(mut self, v: bool) -> Self {
        self.force = Some(v);
        self
    }

    pub fn no_reload(mut self, v: bool) -> Self {
        self.no_reload = Some(v);
        self
    }

    pub fn noexec(mut self, v: bool) -> Self {
        self.noexec = Some(v);
        self
    }

    pub fn validate(&self) -> Result<(), SysextError> {
        Ok(())
    }
}

pub fn validate_method_name(method: &str) -> Result<&str, SysextError> {
    match method {
        METHOD_MERGE | METHOD_UNMERGE | METHOD_REFRESH | METHOD_LIST => Ok(method),
        _ => Err(SysextError::UnknownMethod(method.to_string())),
    }
}

pub fn validate_class(s: &str) -> Result<ImageClass, SysextError> {
    ImageClass::from_str(s).ok_or_else(|| SysextError::InvalidClass(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.sysext");
    }

    #[test]
    fn test_method_names() {
        assert!(METHOD_MERGE.contains("Merge"));
        assert!(METHOD_UNMERGE.contains("Unmerge"));
        assert!(METHOD_REFRESH.contains("Refresh"));
        assert!(METHOD_LIST.contains("List"));
    }

    #[test]
    fn test_error_names() {
        assert_eq!(ERROR_NO_IMAGES_FOUND, "io.systemd.sysext.NoImagesFound");
        assert_eq!(ERROR_ALREADY_MERGED, "io.systemd.sysext.AlreadyMerged");
    }

    #[test]
    fn test_interface_definition_valid() {
        let json = get_interface_definition();
        assert!(json.contains("io.systemd.sysext"));
        assert!(json.contains("Merge"));
        assert!(json.contains("Unmerge"));
        assert!(json.contains("Refresh"));
        assert!(json.contains("List"));
        assert!(json.contains("ImageClass"));
        assert!(json.contains("ImageType"));
    }

    #[test]
    fn test_image_class_roundtrip() {
        assert_eq!(ImageClass::from_str("sysext"), Some(ImageClass::Sysext));
        assert_eq!(ImageClass::from_str("confext"), Some(ImageClass::Confext));
        assert_eq!(ImageClass::Sysext.as_str(), "sysext");
        assert_eq!(ImageClass::Confext.as_str(), "confext");
    }

    #[test]
    fn test_image_class_unknown() {
        assert_eq!(ImageClass::from_str("unknown"), None);
    }

    #[test]
    fn test_image_type_roundtrip() {
        let all = [
            ImageType::Directory,
            ImageType::Subvolume,
            ImageType::Raw,
            ImageType::Block,
            ImageType::Mstack,
        ];
        for t in &all {
            assert_eq!(ImageType::from_str(t.as_str()), Some(*t));
        }
    }

    #[test]
    fn test_image_type_unknown() {
        assert_eq!(ImageType::from_str("unknown"), None);
    }

    #[test]
    fn test_merge_params_builder() {
        let params = MergeParams::new()
            .class(ImageClass::Sysext)
            .force(true)
            .no_reload(false)
            .noexec(true);
        assert_eq!(params.class, Some(ImageClass::Sysext));
        assert_eq!(params.force, Some(true));
        assert_eq!(params.no_reload, Some(false));
        assert_eq!(params.noexec, Some(true));
    }

    #[test]
    fn test_merge_params_validate() {
        assert!(MergeParams::new().validate().is_ok());
        assert!(MergeParams::new()
            .class(ImageClass::Sysext)
            .validate()
            .is_ok());
    }

    #[test]
    fn test_validate_method_name_known() {
        assert!(validate_method_name(METHOD_MERGE).is_ok());
        assert!(validate_method_name(METHOD_UNMERGE).is_ok());
        assert!(validate_method_name(METHOD_REFRESH).is_ok());
        assert!(validate_method_name(METHOD_LIST).is_ok());
    }

    #[test]
    fn test_validate_method_name_unknown() {
        assert!(validate_method_name("io.systemd.sysext.Bogus").is_err());
    }

    #[test]
    fn test_validate_class_ok() {
        assert_eq!(validate_class("sysext"), Ok(ImageClass::Sysext));
        assert_eq!(validate_class("confext"), Ok(ImageClass::Confext));
    }

    #[test]
    fn test_validate_class_invalid() {
        assert!(validate_class("invalid").is_err());
    }
}
