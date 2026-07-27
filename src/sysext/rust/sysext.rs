// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/sysext/sysext.c
//
pub const MUTABLE_EXTENSIONS_BASE_DIR: &str = "/var/lib/extensions.mutable";
pub const MUTABLE_EXTENSIONS_MOUNT_OPTIONS: &str = "redirect_dir=on,noatime,metacopy=off,index=off";
pub const MERGE_EXIT_NOTHING_FOUND: i32 = 123;
pub const MERGE_EXIT_SKIP_REFRESH: i32 = 124;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutableMode {
    No,
    Yes,
    Auto,
    Import,
    Ephemeral,
    EphemeralImport,
}

impl MutableMode {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "no" => Some(Self::No),
            "yes" => Some(Self::Yes),
            "auto" => Some(Self::Auto),
            "import" => Some(Self::Import),
            "ephemeral" => Some(Self::Ephemeral),
            "ephemeral-import" => Some(Self::EphemeralImport),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageClass {
    Sysext,
    Confext,
}

pub fn short_identifier(class: ImageClass) -> &'static str {
    match class {
        ImageClass::Sysext => "sysext",
        ImageClass::Confext => "confext",
    }
}

pub fn short_identifier_plural(class: ImageClass) -> &'static str {
    match class {
        ImageClass::Sysext => "extensions",
        ImageClass::Confext => "confexts",
    }
}

pub fn dot_directory_name(class: ImageClass) -> &'static str {
    match class {
        ImageClass::Sysext => ".systemd-sysext",
        ImageClass::Confext => ".systemd-confext",
    }
}

pub fn default_hierarchies(class: ImageClass) -> Vec<&'static str> {
    match class {
        ImageClass::Sysext => vec!["/usr", "/opt"],
        ImageClass::Confext => vec!["/etc"],
    }
}

pub fn need_reload(no_reload: bool, extension_release_pairs: &[(&str, &str)]) -> bool {
    if no_reload {
        return false;
    }
    extension_release_pairs
        .iter()
        .any(|(k, v)| *k == "EXTENSION_RELOAD_MANAGER" && matches!(*v, "1" | "yes" | "true" | "on"))
}

pub fn merge_exit_code(nothing_found: bool, skip_refresh: bool) -> i32 {
    if nothing_found {
        MERGE_EXIT_NOTHING_FOUND
    } else if skip_refresh {
        MERGE_EXIT_SKIP_REFRESH
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mutable_mode() {
        assert_eq!(MutableMode::parse("auto"), Some(MutableMode::Auto));
    }

    #[test]
    fn rejects_invalid_mutable_mode() {
        assert_eq!(MutableMode::parse("bad"), None);
    }

    #[test]
    fn sysext_identifier_is_correct() {
        assert_eq!(short_identifier(ImageClass::Sysext), "sysext");
    }

    #[test]
    fn confext_plural_is_correct() {
        assert_eq!(short_identifier_plural(ImageClass::Confext), "confexts");
    }

    #[test]
    fn sysext_dot_dir_is_correct() {
        assert_eq!(dot_directory_name(ImageClass::Sysext), ".systemd-sysext");
    }

    #[test]
    fn default_hierarchies_follow_c_behavior() {
        assert_eq!(default_hierarchies(ImageClass::Confext), vec!["/etc"]);
    }

    #[test]
    fn reload_requested_when_metadata_says_so() {
        assert!(need_reload(false, &[("EXTENSION_RELOAD_MANAGER", "yes")]));
    }

    #[test]
    fn merge_exit_code_prefers_nothing_found() {
        assert_eq!(merge_exit_code(true, true), MERGE_EXIT_NOTHING_FOUND);
    }
}
