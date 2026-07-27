// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/dissect/dissect.c

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Dissect,
    Mount,
    Umount,
    Attach,
    Detach,
    List,
    Mtree,
    With,
    CopyFrom,
    CopyTo,
    Discover,
    Validate,
    MakeArchive,
    Shift,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    RootDirectory,
    ImageFile,
}
pub fn parse_action(flag: &str) -> Option<Action> {
    Some(match flag {
        "--mount" => Action::Mount,
        "--umount" => Action::Umount,
        "--attach" => Action::Attach,
        "--detach" => Action::Detach,
        "--list" => Action::List,
        "--mtree" => Action::Mtree,
        "--with" => Action::With,
        "--copy-from" => Action::CopyFrom,
        "--copy-to" => Action::CopyTo,
        "--discover" => Action::Discover,
        "--validate" => Action::Validate,
        "--make-archive" => Action::MakeArchive,
        "--shift" => Action::Shift,
        _ => return None,
    })
}
pub fn classify_path_argument(path: &str, looks_like_dir: bool) -> PathKind {
    if looks_like_dir || path.ends_with('/') {
        PathKind::RootDirectory
    } else {
        PathKind::ImageFile
    }
}
pub fn mount_target(root: Option<&str>, path: &str) -> String {
    match root {
        Some(r) => format!(
            "{}/{}",
            r.trim_end_matches('/'),
            path.trim_start_matches('/')
        ),
        None => path.into(),
    }
}
pub fn quiet_exit_code(ok: bool, quiet: bool) -> (Option<&'static str>, i32) {
    (
        if quiet {
            None
        } else if ok {
            Some("ok")
        } else {
            Some("failed")
        },
        if ok { 0 } else { 1 },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_mount_action() {
        assert_eq!(parse_action("--mount"), Some(Action::Mount));
    }
    #[test]
    fn parses_validate_action() {
        assert_eq!(parse_action("--validate"), Some(Action::Validate));
    }
    #[test]
    fn unknown_action_is_none() {
        assert_eq!(parse_action("--x"), None);
    }
    #[test]
    fn classify_directory_by_slash() {
        assert_eq!(
            classify_path_argument("/root/", false),
            PathKind::RootDirectory
        );
    }
    #[test]
    fn classify_directory_by_probe() {
        assert_eq!(
            classify_path_argument("/root", true),
            PathKind::RootDirectory
        );
    }
    #[test]
    fn classify_image_file() {
        assert_eq!(
            classify_path_argument("disk.raw", false),
            PathKind::ImageFile
        );
    }
    #[test]
    fn mount_target_without_root() {
        assert_eq!(mount_target(None, "/var"), "/var");
    }
    #[test]
    fn mount_target_with_root() {
        assert_eq!(mount_target(Some("/sysroot"), "/var"), "/sysroot/var");
    }
    #[test]
    fn quiet_success_has_no_text() {
        assert_eq!(quiet_exit_code(true, true), (None, 0));
    }
    #[test]
    fn noisy_failure_has_text() {
        assert_eq!(quiet_exit_code(false, false), (Some("failed"), 1));
    }
}
