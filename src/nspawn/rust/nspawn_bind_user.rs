// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/nspawn-bind-user.c

use crate::common::{Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/nspawn/nspawn-bind-user.c";
pub const EXTRACTED_FUNCTIONS: &[&str] =
    &["bind_user_setup", "write_and_symlink", "write_membership"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedWrite {
    pub path: String,
    pub symlink_path: String,
    pub mode: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindUserRecord {
    pub user_name: String,
    pub uid: u32,
    pub group_name: String,
    pub gid: u32,
}

pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "nspawn_bind_user",
        source_path: SOURCE_PATH,
        source_lines: 217,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}

pub fn write_and_symlink(
    root: &str,
    name: &str,
    uid: u32,
    suffix: &str,
    mode: u32,
) -> Result<PlannedWrite, Errno> {
    if root.is_empty() || name.is_empty() || suffix.is_empty() {
        return Err(Errno::new(-22));
    }

    let file_name = format!("{name}{suffix}");
    Ok(PlannedWrite {
        path: format!("{root}/run/host/userdb/{file_name}"),
        symlink_path: format!("{root}/run/host/userdb/{uid}{suffix}"),
        mode,
    })
}

pub fn write_membership(root: &str, user: &str, group: &str) -> Result<String, Errno> {
    if user.is_empty() || group.is_empty() {
        return Err(Errno::new(-22));
    }

    Ok(format!("{root}/run/host/userdb/{user}:{group}.membership"))
}

pub fn bind_user_setup(root: &str, records: &[BindUserRecord]) -> Result<Vec<PlannedWrite>, Errno> {
    let mut planned = Vec::new();
    for record in records {
        planned.push(write_and_symlink(
            root,
            &record.group_name,
            record.gid,
            ".group",
            0o644,
        )?);
        planned.push(write_and_symlink(
            root,
            &record.user_name,
            record.uid,
            ".user",
            0o644,
        )?);
    }
    Ok(planned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_paths_match_userdb_layout() {
        let planned = write_and_symlink("/root", "alice", 1000, ".user", 0o644).unwrap();
        assert!(planned.path.ends_with("/run/host/userdb/alice.user"));
        assert!(planned.symlink_path.ends_with("/run/host/userdb/1000.user"));
    }

    #[test]
    fn membership_names_follow_c_format() {
        assert_eq!(
            write_membership("/root", "alice", "wheel").unwrap(),
            "/root/run/host/userdb/alice:wheel.membership"
        );
    }
}
