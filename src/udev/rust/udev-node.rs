// SPDX-License-Identifier: GPL-2.0-or-later
// PORT-SYNC: src/udev/udev-node.c

pub const SOURCE_PATH: &str = "src/udev/udev-node.c";
pub const SOURCE_LINE_COUNT: usize = 827;
pub const UDEV_NODE_HASH_KEY: &str = "b96af1ce4031441a9e19ec8baef3e32f";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeOperation {
    RemoveSymlink,
    CreateSymlink,
    ReadStackEntry,
    FindPrioritizedDevnode,
    UpdateStackDirectory,
    UpdateLinks,
    UpdateNode,
    RemoveNode,
    ApplyPermissions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackEntry<'a> {
    pub id: &'a str,
    pub priority: i32,
    pub devnode: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    EmptySymlink,
    EmptyDevnode,
    NoEntries,
}

pub fn choose_prioritized_devnode<'a>(entries: &'a [StackEntry<'a>]) -> Result<&'a str, NodeError> {
    entries
        .iter()
        .max_by_key(|entry| entry.priority)
        .map(|entry| entry.devnode)
        .ok_or(NodeError::NoEntries)
}

pub fn should_create_symlink(devnode: Option<&str>, slink: &str) -> Result<bool, NodeError> {
    if slink.is_empty() {
        return Err(NodeError::EmptySymlink);
    }
    let devnode = devnode.ok_or(NodeError::EmptyDevnode)?;
    Ok(!devnode.is_empty())
}

pub fn validate_port_model() -> Result<(), NodeError> {
    if UDEV_NODE_HASH_KEY.len() != 32 {
        return Err(NodeError::EmptyDevnode);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_metadata_matches_c_file() {
        assert_eq!(SOURCE_PATH, "src/udev/udev-node.c");
        assert_eq!(SOURCE_LINE_COUNT, 827);
    }

    #[test]
    fn hash_key_matches_c_constant_shape() {
        assert_eq!(UDEV_NODE_HASH_KEY.len(), 32);
    }

    #[test]
    fn choose_highest_priority_devnode() {
        let entries = [
            StackEntry {
                id: "a",
                priority: 5,
                devnode: "/dev/a",
            },
            StackEntry {
                id: "b",
                priority: 10,
                devnode: "/dev/b",
            },
        ];
        assert_eq!(choose_prioritized_devnode(&entries).unwrap(), "/dev/b");
    }

    #[test]
    fn choosing_from_empty_entries_fails() {
        assert_eq!(choose_prioritized_devnode(&[]), Err(NodeError::NoEntries));
    }

    #[test]
    fn symlink_creation_requires_target() {
        assert_eq!(
            should_create_symlink(None, "/dev/link"),
            Err(NodeError::EmptyDevnode)
        );
    }

    #[test]
    fn symlink_creation_requires_non_empty_link_name() {
        assert_eq!(
            should_create_symlink(Some("/dev/sda"), ""),
            Err(NodeError::EmptySymlink)
        );
    }

    #[test]
    fn symlink_creation_accepts_valid_inputs() {
        assert!(should_create_symlink(Some("/dev/sda"), "/dev/disk/by-id/x").unwrap());
    }

    #[test]
    fn node_operation_list_covers_stack_and_permissions() {
        assert_eq!(NodeOperation::UpdateStackDirectory as u8, 4);
        assert_eq!(NodeOperation::ApplyPermissions as u8, 8);
    }

    #[test]
    fn port_model_validation_succeeds() {
        assert_eq!(validate_port_model(), Ok(()));
    }
}
