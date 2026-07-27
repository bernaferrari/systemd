// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/gpt-auto-generator/gpt-auto-generator.c

pub const MOUNT_RW: u32 = 1 << 0;
pub const MOUNT_GROWFS: u32 = 1 << 1;
pub const MOUNT_MEASURE: u32 = 1 << 2;
pub const MOUNT_VALIDATEFS: u32 = 1 << 3;
pub const EINVAL: i32 = -22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Root,
    Esp,
    Xbootldr,
    Swap,
    Home,
    Srv,
    Var,
    Tmp,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub i32);
pub type Result<T> = std::result::Result<T, Error>;

pub fn classify(guid: &str) -> Role {
    match guid.to_ascii_lowercase().as_str() {
        "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"
        | "44479540-f297-41b2-9af7-d131d5f0458a"
        | "69dad710-2ce4-4e3c-b16c-21a1d49abed3"
        | "b921b045-1df0-41c3-af44-4c6f280d3fae"
        | "0fc63daf-8483-4772-8e79-3d69d8477de4" => Role::Root,
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => Role::Esp,
        "bc13c2ff-59e6-4262-a352-b275fd6f7172" => Role::Xbootldr,
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => Role::Swap,
        "933ac7e1-2eb4-4f13-b844-0e14e2aef915" => Role::Home,
        "3b8f8425-20e0-4f3b-907f-1a25a76f98e8" => Role::Srv,
        "4d21b016-b534-45c2-a9fb-5c16e091fd2d" => Role::Var,
        "7ec6f557-3bc5-4aca-b293-16ef5df639d1" => Role::Tmp,
        _ => Role::Unknown,
    }
}
pub fn mount_point(role: Role) -> Option<&'static str> {
    match role {
        Role::Root => Some("/"),
        Role::Esp => Some("/efi"),
        Role::Xbootldr => Some("/boot"),
        Role::Home => Some("/home"),
        Role::Srv => Some("/srv"),
        Role::Var => Some("/var"),
        Role::Tmp => Some("/var/tmp"),
        _ => None,
    }
}
pub fn mount_unit_name(path: &str) -> String {
    let n = path.trim_matches('/').replace('/', "-");
    if n.is_empty() {
        "-.mount".into()
    } else {
        format!("{n}.mount")
    }
}
pub fn root_options(rw: bool, flags: u32) -> &'static str {
    if rw || flags & MOUNT_RW != 0 {
        "rw"
    } else {
        "ro"
    }
}
pub fn parse_roothash(s: &str) -> Result<String> {
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        Err(Error(EINVAL))
    } else {
        Ok(s.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_guid_is_recognized() {
        assert_eq!(classify("4f68bce3-e8cd-4db1-96e7-fbcaf984b709"), Role::Root);
    }
    #[test]
    fn esp_guid_is_recognized() {
        assert_eq!(classify("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"), Role::Esp);
    }
    #[test]
    fn unknown_guid_stays_unknown() {
        assert_eq!(classify("x"), Role::Unknown);
    }
    #[test]
    fn root_mount_point() {
        assert_eq!(mount_point(Role::Root), Some("/"));
    }
    #[test]
    fn swap_has_no_mount_point() {
        assert_eq!(mount_point(Role::Swap), None);
    }
    #[test]
    fn unit_name_for_root() {
        assert_eq!(mount_unit_name("/"), "-.mount");
    }
    #[test]
    fn unit_name_for_var() {
        assert_eq!(mount_unit_name("/var/lib"), "var-lib.mount");
    }
    #[test]
    fn rw_option_prefers_explicit_rw() {
        assert_eq!(root_options(true, 0), "rw");
    }
    #[test]
    fn roothash_accepts_hex() {
        assert!(parse_roothash("abc123").is_ok());
    }
    #[test]
    fn roothash_rejects_non_hex() {
        assert!(parse_roothash("gh!").is_err());
    }
}
