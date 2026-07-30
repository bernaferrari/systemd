// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/sysusers/sysusers.c
//
// System user and group management tool.
//
// Implements the systemd-sysusers tool which creates system users and groups
// based on configuration files. Supports adding users, groups, group members,
// and UID/GID ranges. Reads configuration from /etc/sysusers.d/ and
// /usr/lib/sysusers.d/ directories, and can operate on an alternative root
// or within a disk image.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default umask for the tool.
pub const DEFAULT_UMASK: u32 = 0o022;

/// Password field indicating the password is in the shadow file.
pub const PASSWORD_SEE_SHADOW: &str = "x";

/// Password field for locked + invalid accounts.
pub const PASSWORD_LOCKED_AND_INVALID: &str = "!*";

/// Password field for unprovisioned root accounts.
pub const PASSWORD_UNPROVISIONED: &str = "!";

/// nologin shell path.
pub const NOLOGIN_SHELL: &str = "/sbin/nologin";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Configuration item types, matching the C enum ItemType.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemType {
    /// Add a user entry
    AddUser,
    /// Add a group entry
    AddGroup,
    /// Add a member to a group
    AddMember,
    /// Add a UID/GID range
    AddRange,
}

impl ItemType {
    /// Parse from the single-character type code used in config files.
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'u' => Some(Self::AddUser),
            'g' => Some(Self::AddGroup),
            'm' => Some(Self::AddMember),
            'r' => Some(Self::AddRange),
            _ => None,
        }
    }

    /// Convert to the single-character type code.
    pub fn to_char(self) -> char {
        match self {
            Self::AddUser => 'u',
            Self::AddGroup => 'g',
            Self::AddMember => 'm',
            Self::AddRange => 'r',
        }
    }

    /// Human-readable type name.
    pub fn to_str(self) -> &'static str {
        match self {
            Self::AddUser => "user",
            Self::AddGroup => "group",
            Self::AddMember => "member",
            Self::AddRange => "range",
        }
    }
}

// ── Configuration item ────────────────────────────────────────────────────

/// A single configuration item parsed from a sysusers config file.
#[derive(Debug, Clone)]
pub struct Item {
    /// The type of this item
    pub item_type: ItemType,

    /// Name (user/group name)
    pub name: String,
    /// Group name (for user items)
    pub group_name: Option<String>,
    /// Path to read UID from
    pub uid_path: Option<String>,
    /// Path to read GID from
    pub gid_path: Option<String>,
    /// GECOS/description field
    pub description: Option<String>,
    /// Home directory
    pub home: Option<String>,
    /// Login shell
    pub shell: Option<String>,

    /// GID value (if set)
    pub gid: u32,
    /// UID value (if set)
    pub uid: u32,

    /// Source filename
    pub filename: Option<String>,
    /// Line number in source file
    pub line: u32,

    /// Whether GID was explicitly set
    pub gid_set: bool,
    /// Whether UID/GID must already exist (strict mode)
    pub id_set_strict: bool,
    /// Whether UID was explicitly set
    pub uid_set: bool,
    /// Whether the account should be locked
    pub locked: bool,

    /// Whether this user needs to be created
    pub todo_user: bool,
    /// Whether this group needs to be created
    pub todo_group: bool,
}

impl Item {
    /// Create a new item with the given type and name.
    pub fn new(item_type: ItemType, name: String) -> Self {
        Self {
            item_type,
            name,
            group_name: None,
            uid_path: None,
            gid_path: None,
            description: None,
            home: None,
            shell: None,
            gid: 0,
            uid: 0,
            filename: None,
            line: 0,
            gid_set: false,
            id_set_strict: false,
            uid_set: false,
            locked: false,
            todo_user: false,
            todo_group: false,
        }
    }

    /// Determine the shell for a user item.
    /// Returns the configured shell, the root shell for UID 0, or nologin.
    pub fn pick_shell(&self, default_root_shell: &str) -> Option<String> {
        if self.item_type != ItemType::AddUser {
            return None;
        }
        if let Some(ref shell) = self.shell {
            return Some(shell.clone());
        }
        if self.uid_set && self.uid == 0 {
            return Some(default_root_shell.to_string());
        }
        Some(NOLOGIN_SHELL.to_string())
    }

    /// Get the home directory, defaulting to "/".
    pub fn home_dir(&self) -> &str {
        self.home.as_deref().unwrap_or("/")
    }
}

// ── UID/GID range ─────────────────────────────────────────────────────────

/// A UID or GID allocation range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdRange {
    /// Start of the range (inclusive)
    pub start: u32,
    /// End of the range (inclusive)
    pub end: u32,
}

impl IdRange {
    /// Create a new range.
    pub fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// Check if an ID falls within this range.
    pub fn contains(&self, id: u32) -> bool {
        id >= self.start && id <= self.end
    }

    /// Check if the range is valid (start <= end).
    pub fn is_valid(&self) -> bool {
        self.start <= self.end
    }
}

/// Default UID allocation range (SYSTEM_ALLOC_UID_MIN..=SYSTEM_UID_MAX).
pub const SYSTEM_ALLOC_UID_MIN: u32 = 1;
pub const SYSTEM_UID_MAX: u32 = 999;
pub const SYSTEM_ALLOC_GID_MIN: u32 = 1;
pub const SYSTEM_GID_MAX: u32 = 999;

/// UID range for regular (non-system) users.
pub const REGULAR_UID_MIN: u32 = 1000;
pub const REGULAR_UID_MAX: u32 = 60000;

// ── Configuration line parsing ────────────────────────────────────────────

/// Parse a single configuration line.
/// Returns the parsed item or an error.
pub fn parse_config_line(line: &str, filename: &str, line_num: u32) -> Result<Item, i32> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Err(-libc::ENOENT); // Skip empty/comment lines
    }

    let chars: Vec<char> = line.chars().collect();
    if chars.is_empty() {
        return Err(-libc::ENOENT);
    }

    let item_type = ItemType::from_char(chars[0]).ok_or(-libc::EINVAL)?;

    // Split the rest of the line into fields
    let rest: String = chars[1..].iter().collect();
    let rest = rest.trim_start();
    let fields: Vec<&str> = rest.splitn(4, char::is_whitespace).collect();

    match item_type {
        ItemType::AddUser => {
            let name = fields.first().ok_or(-libc::EINVAL)?.to_string();
            if name.is_empty() {
                return Err(-libc::EINVAL);
            }
            let mut item = Item::new(item_type, name);

            // Parse optional UID and GID specifications
            if fields.len() > 1 {
                let uid_spec = fields[1];
                if let Some(uid_str) = uid_spec.strip_prefix('/') {
                    item.uid_path = Some(uid_str.to_string());
                } else if !uid_spec.is_empty()
                    && let Ok(uid) = uid_spec.parse::<u32>()
                {
                    item.uid = uid;
                    item.uid_set = true;
                }
            }

            if fields.len() > 2 {
                let gid_spec = fields[2];
                if !gid_spec.is_empty() {
                    if let Some(gid_str) = gid_spec.strip_prefix('/') {
                        item.gid_path = Some(gid_str.to_string());
                    } else if let Ok(gid) = gid_spec.parse::<u32>() {
                        item.gid = gid;
                        item.gid_set = true;
                    }
                }
            }

            if fields.len() > 3 {
                let desc = fields[3];
                if !desc.is_empty() {
                    item.description = Some(desc.to_string());
                }
            }

            item.filename = Some(filename.to_string());
            item.line = line_num;
            Ok(item)
        }
        ItemType::AddGroup => {
            let name = fields.first().ok_or(-libc::EINVAL)?.to_string();
            if name.is_empty() {
                return Err(-libc::EINVAL);
            }
            let mut item = Item::new(item_type, name);

            if fields.len() > 1 {
                let gid_spec = fields[1];
                if !gid_spec.is_empty()
                    && let Ok(gid) = gid_spec.parse::<u32>()
                {
                    item.gid = gid;
                    item.gid_set = true;
                }
            }

            item.filename = Some(filename.to_string());
            item.line = line_num;
            Ok(item)
        }
        ItemType::AddMember => {
            let user = fields.first().ok_or(-libc::EINVAL)?.to_string();
            let group = fields.get(1).ok_or(-libc::EINVAL)?.to_string();
            let mut item = Item::new(item_type, user);
            item.group_name = Some(group);
            item.filename = Some(filename.to_string());
            item.line = line_num;
            Ok(item)
        }
        ItemType::AddRange => {
            let range_spec = fields.first().ok_or(-libc::EINVAL)?.to_string();
            let (start, end) = parse_range(&range_spec)?;
            let mut item = Item::new(item_type, format!("{}-{}", start, end));
            item.uid = start;
            item.gid = end;
            item.uid_set = true;
            item.gid_set = true;
            item.filename = Some(filename.to_string());
            item.line = line_num;
            Ok(item)
        }
    }
}

/// Parse a UID/GID range specification (e.g., "1000-60000").
fn parse_range(spec: &str) -> Result<(u32, u32), i32> {
    let parts: Vec<&str> = spec.split('-').collect();
    if parts.len() != 2 {
        return Err(-libc::EINVAL);
    }
    let start: u32 = parts[0].parse().map_err(|_| -libc::EINVAL)?;
    let end: u32 = parts[1].parse().map_err(|_| -libc::EINVAL)?;
    if start > end {
        return Err(-libc::EINVAL);
    }
    Ok((start, end))
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parsed arguments for the sysusers tool.
#[derive(Debug, Clone, Default)]
pub struct SysusersArgs {
    /// Root directory for operations
    pub root: Option<String>,
    /// Disk image to operate on
    pub image: Option<String>,
    /// Dry run mode (no changes written)
    pub dry_run: bool,
    /// Inline mode (read config from command line)
    pub inline: bool,
    /// Replace mode (only process specified config)
    pub replace: Option<String>,
}

// ── Backup file path ──────────────────────────────────────────────────────

/// Generate the backup file path for a system file.
pub fn backup_path(path: &str) -> String {
    format!("{}-", path)
}

// ── Database file paths ───────────────────────────────────────────────────

/// Standard system database file paths.
pub const PASSWD_PATH: &str = "/etc/passwd";
pub const SHADOW_PATH: &str = "/etc/shadow";
pub const GROUP_PATH: &str = "/etc/group";
pub const GSHADOW_PATH: &str = "/etc/gshadow";

/// Get the passwd path relative to root.
pub fn passwd_path(root: Option<&str>) -> String {
    match root {
        Some(r) => format!("{}{}", r, PASSWD_PATH),
        None => PASSWD_PATH.to_string(),
    }
}

/// Get the group path relative to root.
pub fn group_path(root: Option<&str>) -> String {
    match root {
        Some(r) => format!("{}{}", r, GROUP_PATH),
        None => GROUP_PATH.to_string(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_item_type_from_char() {
        assert_eq!(ItemType::from_char('u'), Some(ItemType::AddUser));
        assert_eq!(ItemType::from_char('g'), Some(ItemType::AddGroup));
        assert_eq!(ItemType::from_char('m'), Some(ItemType::AddMember));
        assert_eq!(ItemType::from_char('r'), Some(ItemType::AddRange));
        assert_eq!(ItemType::from_char('x'), None);
    }

    #[test]
    fn test_item_type_to_char() {
        assert_eq!(ItemType::AddUser.to_char(), 'u');
        assert_eq!(ItemType::AddGroup.to_char(), 'g');
        assert_eq!(ItemType::AddMember.to_char(), 'm');
        assert_eq!(ItemType::AddRange.to_char(), 'r');
    }

    #[test]
    fn test_item_type_to_str() {
        assert_eq!(ItemType::AddUser.to_str(), "user");
        assert_eq!(ItemType::AddGroup.to_str(), "group");
        assert_eq!(ItemType::AddMember.to_str(), "member");
        assert_eq!(ItemType::AddRange.to_str(), "range");
    }

    #[test]
    fn test_item_pick_shell() {
        let item_user = Item::new(ItemType::AddUser, "test".to_string());
        assert_eq!(
            item_user.pick_shell("/bin/bash"),
            Some("/sbin/nologin".to_string())
        );

        let item_root = Item {
            item_type: ItemType::AddUser,
            uid_set: true,
            uid: 0,
            ..Item::new(ItemType::AddUser, "root".to_string())
        };
        assert_eq!(
            item_root.pick_shell("/bin/bash"),
            Some("/bin/bash".to_string())
        );

        let item_with_shell = Item {
            item_type: ItemType::AddUser,
            shell: Some("/bin/zsh".to_string()),
            ..Item::new(ItemType::AddUser, "user".to_string())
        };
        assert_eq!(
            item_with_shell.pick_shell("/bin/bash"),
            Some("/bin/zsh".to_string())
        );

        let item_group = Item::new(ItemType::AddGroup, "group".to_string());
        assert_eq!(item_group.pick_shell("/bin/bash"), None);
    }

    #[test]
    fn test_item_home_dir() {
        let item_default = Item::new(ItemType::AddUser, "test".to_string());
        assert_eq!(item_default.home_dir(), "/");

        let item_home = Item {
            home: Some("/home/test".to_string()),
            ..Item::new(ItemType::AddUser, "test".to_string())
        };
        assert_eq!(item_home.home_dir(), "/home/test");
    }

    #[test]
    fn test_id_range() {
        let range = IdRange::new(1000, 60000);
        assert!(range.contains(1000));
        assert!(range.contains(60000));
        assert!(range.contains(50000));
        assert!(!range.contains(999));
        assert!(!range.contains(60001));
        assert!(range.is_valid());

        let invalid_range = IdRange::new(60000, 1000);
        assert!(!invalid_range.is_valid());
    }

    #[test]
    fn test_parse_config_line_user() {
        let item = parse_config_line("u systemd-network - - - Network Management", "test.conf", 1)
            .unwrap();
        assert_eq!(item.item_type, ItemType::AddUser);
        assert_eq!(item.name, "systemd-network");
        assert!(item.description.is_some());
    }

    #[test]
    fn test_parse_config_line_group() {
        let item = parse_config_line("g input - - -", "test.conf", 1).unwrap();
        assert_eq!(item.item_type, ItemType::AddGroup);
        assert_eq!(item.name, "input");
    }

    #[test]
    fn test_parse_config_line_member() {
        let item = parse_config_line("m wheel root", "test.conf", 1).unwrap();
        assert_eq!(item.item_type, ItemType::AddMember);
        assert_eq!(item.name, "wheel");
        assert_eq!(item.group_name.as_deref(), Some("root"));
    }

    #[test]
    fn test_parse_config_line_comment() {
        assert!(parse_config_line("# comment", "test.conf", 1).is_err());
        assert!(parse_config_line("", "test.conf", 1).is_err());
    }

    #[test]
    fn test_backup_path() {
        assert_eq!(backup_path("/etc/passwd"), "/etc/passwd-");
        assert_eq!(backup_path("/etc/group"), "/etc/group-");
    }

    #[test]
    fn test_passwd_path() {
        assert_eq!(passwd_path(None), "/etc/passwd");
        assert_eq!(passwd_path(Some("/mnt")), "/mnt/etc/passwd");
    }

    #[test]
    fn test_group_path() {
        assert_eq!(group_path(None), "/etc/group");
        assert_eq!(group_path(Some("/sysroot")), "/sysroot/etc/group");
    }
}
