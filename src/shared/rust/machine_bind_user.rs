// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/machine-bind-user.c, src/shared/machine-bind-user.h
//
// User binding for machines/containers — maps host users to container users.
//
// Resolves users specified in a bind list, generates minimalized user + group
// records to place into the container, allocates a UID/GID from the MAP range,
// and checks for name/UID/GID collisions against the machine's /etc/passwd
// and /etc/group databases.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

// ── Constants ─────────────────────────────────────────────────────────────

/// Minimum UID for mapped users (corresponds to C's MAP_UID_MIN)
pub const MAP_UID_MIN: u32 = 60000;

/// Maximum UID for mapped users (corresponds to C's MAP_UID_MAX)
pub const MAP_UID_MAX: u32 = 60512;

/// Sentinel value representing an invalid UID (maps to C's UID_INVALID)
pub const UID_INVALID: u32 = u32::MAX;

/// Sentinel value representing an invalid GID (maps to C's GID_INVALID)
pub const GID_INVALID: u32 = u32::MAX;

/// The "nobody" UID used across Linux distros
pub const NOBODY_UID: u32 = 65534;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Errors that can occur during machine user binding.
#[derive(Debug)]
pub enum BindUserError {
    /// No suitable UID available in the configured MAP range.
    NoFreeUid,
    /// The user name already exists in the machine's /etc/passwd.
    PasswdCollision(String),
    /// The group name already exists in the machine's /etc/group.
    GroupCollision(String),
    /// Mapping the root user is not supported.
    RootUserUnsupported,
    /// Mapping the nobody user is not supported.
    NobodyUserUnsupported,
    /// The user record has no valid UID.
    InvalidUid,
    /// The user does not have a matching private group (names differ).
    NoPrivateGroup,
    /// No group record found for the user's GID.
    MissingGroup(u32),
    /// I/O error while reading /etc/passwd or /etc/group.
    Io(std::io::Error),
}

impl std::fmt::Display for BindUserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoFreeUid => write!(
                f,
                "No suitable available UID in range {}…{} in machine detected, can't map user",
                MAP_UID_MIN, MAP_UID_MAX
            ),
            Self::PasswdCollision(name) => {
                write!(f, "User '{}' already exists in the machine", name)
            }
            Self::GroupCollision(name) => {
                write!(f, "Group '{}' already exists in the machine", name)
            }
            Self::RootUserUnsupported => write!(f, "Mapping 'root' user not supported, sorry"),
            Self::NobodyUserUnsupported => write!(f, "Mapping 'nobody' user not supported, sorry"),
            Self::InvalidUid => write!(f, "Cannot bind user with no UID, refusing"),
            Self::NoPrivateGroup => write!(
                f,
                "Mapping users without private groups is currently not supported"
            ),
            Self::MissingGroup(gid) => write!(f, "No group found with GID {}", gid),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for BindUserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for BindUserError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ── Parsed entry types ───────────────────────────────────────────────────

/// A parsed entry from an /etc/passwd line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

/// A parsed entry from an /etc/group line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

// ── Simplified record types ──────────────────────────────────────────────

/// Simplified user record used for bind-user conversion.
///
/// Captures the fields from the full C `UserRecord` that are relevant
/// for the machine bind-user workflow.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub user_name: String,
    pub uid: u32,
    pub gid: u32,
    pub shell: Option<String>,
    pub home: Option<String>,
    pub hashed_password: Vec<String>,
}

impl UserRecord {
    /// Returns `true` if this is the root user (UID 0).
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }

    /// Returns `true` if this is the "nobody" user (UID 65534 or name "nobody").
    pub fn is_nobody(&self) -> bool {
        self.uid == NOBODY_UID || self.user_name == "nobody"
    }
}

/// Simplified group record used for bind-user conversion.
///
/// Captures the fields from the full C `GroupRecord` that are relevant
/// for the machine bind-user workflow.
#[derive(Debug, Clone)]
pub struct GroupRecord {
    pub group_name: String,
    pub gid: u32,
}

// ── Bind data types ──────────────────────────────────────────────────────

/// Data for a single user binding — holds both the host-side and
/// payload (container) side user/group records.
#[derive(Debug)]
pub struct MachineBindUserData {
    /// The host's user record.
    pub host_user: UserRecord,
    /// The host's group record.
    pub host_group: GroupRecord,
    /// The mapped user record for the container.
    pub payload_user: UserRecord,
    /// The mapped group record for the container.
    pub payload_group: GroupRecord,
}

/// Context holding all user binding data for a machine.
///
/// In C this is a manually-managed heap-allocated array with an explicit
/// `_free()` destructor. Here, `Vec` + `Default`/`Drop` handle lifetime
/// automatically.
#[derive(Debug, Default)]
pub struct MachineBindUserContext {
    /// Per-user binding entries.
    pub data: Vec<MachineBindUserData>,
}

// ── Configuration ────────────────────────────────────────────────────────

/// Configuration for the user binding preparation.
#[derive(Debug, Clone)]
pub struct BindUserConfig<'a> {
    /// Root directory of the machine filesystem (for /etc/passwd, /etc/group
    /// collision checks). Pass `None` to skip collision checks.
    pub directory: Option<&'a Path>,
    /// Shell to assign to bound users. Ignored when `shell_copy` is true.
    pub shell: Option<&'a str>,
    /// If true, copy the shell from the host user record instead of using
    /// the configured `shell`.
    pub shell_copy: bool,
    /// Directory where home directories are bind-mounted into the container.
    /// The home path is constructed as `<home_mount_directory>/<user_name>`.
    pub home_mount_directory: Option<&'a Path>,
    /// Additional groups that bound users should be members of.
    pub groups: Vec<String>,
}

impl<'a> Default for BindUserConfig<'a> {
    fn default() -> Self {
        Self {
            directory: None,
            shell: None,
            shell_copy: false,
            home_mount_directory: None,
            groups: Vec::new(),
        }
    }
}

// ── Utility functions ────────────────────────────────────────────────────

/// Check if a UID is valid (i.e., not `UID_INVALID`).
pub fn uid_is_valid(uid: u32) -> bool {
    uid != UID_INVALID
}

/// Check if a GID is valid (i.e., not `GID_INVALID`).
pub fn gid_is_valid(gid: u32) -> bool {
    gid != GID_INVALID
}

// ── Collision checking ───────────────────────────────────────────────────

/// Check for name or UID collisions in a machine's `/etc/passwd`.
///
/// - `directory`: the machine root (used to locate `etc/passwd`). `None`
///   skips the check and returns `Ok(false)`.
/// - `name`: if `Some`, checks for a name collision.
/// - `uid`: if `Some(uid)` where `uid_is_valid(uid)` is true, checks for
///   a UID collision.
///
/// At least one of `name` or `uid` must be provided.
///
/// Returns `Ok(true)` if a collision was found, `Ok(false)` if not.
/// Returns `Err` on I/O failures.
pub fn check_etc_passwd_collisions(
    directory: Option<&Path>,
    name: Option<&str>,
    uid: Option<u32>,
) -> Result<bool, BindUserError> {
    let Some(directory) = directory else {
        return Ok(false);
    };

    if name.is_none() && uid.map_or(true, |u| !uid_is_valid(u)) {
        return Ok(false);
    }

    let passwd_path = directory.join("etc/passwd");
    let file = match fs::File::open(&passwd_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(BindUserError::from(e)),
    };

    let reader = BufReader::new(file);
    for line_result in reader.lines() {
        let line = line_result?;
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }

        if let Some(target_name) = name {
            if fields[0] == target_name {
                return Ok(true);
            }
        }

        if let Some(target_uid) = uid {
            if uid_is_valid(target_uid) {
                if let Ok(file_uid) = fields[2].parse::<u32>() {
                    if file_uid == target_uid {
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}

/// Check for name or GID collisions in a machine's `/etc/group`.
///
/// - `directory`: the machine root (used to locate `etc/group`). `None`
///   skips the check and returns `Ok(false)`.
/// - `name`: if `Some`, checks for a name collision.
/// - `gid`: if `Some(gid)` where `gid_is_valid(gid)` is true, checks for
///   a GID collision.
///
/// At least one of `name` or `gid` must be provided.
///
/// Returns `Ok(true)` if a collision was found, `Ok(false)` if not.
/// Returns `Err` on I/O failures.
pub fn check_etc_group_collisions(
    directory: Option<&Path>,
    name: Option<&str>,
    gid: Option<u32>,
) -> Result<bool, BindUserError> {
    debug_assert!(
        name.is_some() || gid.map_or(false, gid_is_valid),
        "at least one of name or valid gid must be provided"
    );

    let Some(directory) = directory else {
        return Ok(false);
    };

    let group_path = directory.join("etc/group");
    let file = match fs::File::open(&group_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(BindUserError::from(e)),
    };

    let reader = BufReader::new(file);
    for line_result in reader.lines() {
        let line = line_result?;
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 4 {
            continue;
        }

        if let Some(target_name) = name {
            if fields[0] == target_name {
                return Ok(true);
            }
        }

        if let Some(target_gid) = gid {
            if gid_is_valid(target_gid) {
                if let Ok(file_gid) = fields[2].parse::<u32>() {
                    if file_gid == target_gid {
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}

// ── UID allocation ───────────────────────────────────────────────────────

/// Find a free UID in the `[MAP_UID_MIN, MAP_UID_MAX]` range that has no
/// collision in the machine's `/etc/passwd` or `/etc/group`.
///
/// The same UID is used as both UID and GID (private group model), so both
/// files are checked. The search starts at `starting_uid` and scans upward.
///
/// Returns the first free UID, or `Err(BindUserError::NoFreeUid)` if the
/// range is exhausted.
pub fn find_free_uid(directory: Option<&Path>, starting_uid: u32) -> Result<u32, BindUserError> {
    let mut current = starting_uid;

    loop {
        if current > MAP_UID_MAX {
            return Err(BindUserError::NoFreeUid);
        }

        // Check /etc/passwd for UID collision
        if check_etc_passwd_collisions(directory, None, Some(current))? {
            current += 1;
            continue;
        }

        // Use the UID also as GID — check /etc/group too
        if !check_etc_group_collisions(directory, None, Some(current))? {
            return Ok(current);
        }

        current += 1;
    }
}

// ── User conversion ──────────────────────────────────────────────────────

/// Convert a host user/group pair into payload (container) user/group records.
///
/// This checks for name collisions in the machine's user/group databases,
/// builds the home directory path, selects the shell, and constructs the
/// converted records with the allocated UID.
///
/// The caller must ensure `host_user.gid == host_group.gid`.
fn convert_user(
    config: &BindUserConfig<'_>,
    host_user: &UserRecord,
    host_group: &GroupRecord,
    allocate_uid: u32,
) -> Result<(UserRecord, GroupRecord), BindUserError> {
    // Check name collision in machine's /etc/passwd
    if check_etc_passwd_collisions(config.directory, Some(&host_user.user_name), None)? {
        return Err(BindUserError::PasswdCollision(host_user.user_name.clone()));
    }

    // Check name collision in machine's /etc/group
    if check_etc_group_collisions(config.directory, Some(&host_group.group_name), None)? {
        return Err(BindUserError::GroupCollision(host_group.group_name.clone()));
    }

    // Determine shell: copy from host user if shell_copy is set
    let shell = if config.shell_copy {
        host_user.shell.clone()
    } else {
        config.shell.map(String::from)
    };

    // Build home directory path
    let home = config
        .home_mount_directory
        .map(|dir| dir.join(&host_user.user_name).to_string_lossy().to_string());

    // Build the payload user record
    let payload_user = UserRecord {
        user_name: host_user.user_name.clone(),
        uid: allocate_uid,
        gid: allocate_uid,
        shell,
        home,
        hashed_password: host_user.hashed_password.clone(),
    };

    // Build the payload group record
    let payload_group = GroupRecord {
        group_name: host_group.group_name.clone(),
        gid: allocate_uid,
    };

    Ok((payload_user, payload_group))
}

// ── Public API ───────────────────────────────────────────────────────────

/// Release the resources held by a [`MachineBindUserContext`].
///
/// In the C implementation this is a dedicated `_free()` function that
/// unrefs each user/group record and frees the context. In Rust the
/// context is dropped automatically via `Drop`, but this function is
/// provided as the direct equivalent of the C API.
pub fn machine_bind_user_context_free(_ctx: MachineBindUserContext) {
    // All fields are owned Rust types — Drop handles cleanup automatically.
}

/// Prepare user bindings for a machine/container.
///
/// For each user in `bind_users` this function:
/// 1. Validates the user (not root, not nobody, has a valid UID, has a
///    private group).
/// 2. Checks for name collisions in the machine's `/etc/passwd` and
///    `/etc/group`.
/// 3. Allocates a UID from the MAP range (`MAP_UID_MIN..=MAP_UID_MAX`).
/// 4. Converts the host user/group records into payload records suitable
///    for placement inside the container.
///
/// Returns `Ok(None)` if `bind_users` is empty.
/// Returns `Ok(Some(ctx))` with the binding data on success.
pub fn machine_bind_user_prepare(
    config: &BindUserConfig<'_>,
    bind_users: &[UserRecord],
    bind_groups: &[GroupRecord],
) -> Result<Option<MachineBindUserContext>, BindUserError> {
    if bind_users.is_empty() {
        return Ok(None);
    }

    let mut ctx = MachineBindUserContext::default();
    let mut current_uid = MAP_UID_MIN;

    for host_user in bind_users.iter() {
        // Refuse to map root
        if host_user.is_root() {
            return Err(BindUserError::RootUserUnsupported);
        }

        // Refuse to map nobody
        if host_user.is_nobody() {
            return Err(BindUserError::NobodyUserUnsupported);
        }

        // Refuse users without a valid UID
        if !uid_is_valid(host_user.uid) {
            return Err(BindUserError::InvalidUid);
        }

        // Look up the host group by GID
        let host_group = bind_groups
            .iter()
            .find(|g| g.gid == host_user.gid)
            .ok_or_else(|| BindUserError::MissingGroup(host_user.gid))?;

        // The user must have a private group (name must match)
        if host_user.user_name != host_group.group_name {
            return Err(BindUserError::NoPrivateGroup);
        }

        // Allocate a free UID in the MAP range
        let allocated_uid = find_free_uid(config.directory, current_uid)?;
        current_uid = allocated_uid + 1;

        // Convert the user/group records for the container
        let (payload_user, payload_group) =
            convert_user(config, host_user, host_group, allocated_uid)?;

        ctx.data.push(MachineBindUserData {
            host_user: host_user.clone(),
            host_group: host_group.clone(),
            payload_user,
            payload_group,
        });
    }

    Ok(Some(ctx))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Utility helpers ───────────────────────────────────────────────

    /// Create a temporary directory with an `etc/passwd` file containing
    /// the given lines, and an empty `etc/group` file.
    fn setup_passwd_dir(passwd_lines: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        fs::create_dir_all(&etc).unwrap();
        fs::write(etc.join("passwd"), passwd_lines.join("\n")).unwrap();
        fs::write(etc.join("group"), "").unwrap();
        dir
    }

    /// Create a temporary directory with an `etc/group` file containing
    /// the given lines, and an empty `etc/passwd` file.
    fn setup_group_dir(group_lines: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        fs::create_dir_all(&etc).unwrap();
        fs::write(etc.join("group"), group_lines.join("\n")).unwrap();
        fs::write(etc.join("passwd"), "").unwrap();
        dir
    }

    /// Create an empty temporary directory (no etc/ at all).
    fn setup_empty_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn make_user(name: &str, uid: u32, gid: u32) -> UserRecord {
        UserRecord {
            user_name: name.to_string(),
            uid,
            gid,
            shell: Some("/bin/bash".to_string()),
            home: Some(format!("/home/{}", name)),
            hashed_password: Vec::new(),
        }
    }

    fn make_group(name: &str, gid: u32) -> GroupRecord {
        GroupRecord {
            group_name: name.to_string(),
            gid,
        }
    }

    // ── Constants ────────────────────────────────────────────────────

    #[test]
    fn test_uid_is_valid() {
        assert!(uid_is_valid(0));
        assert!(uid_is_valid(1000));
        assert!(uid_is_valid(MAP_UID_MIN));
        assert!(uid_is_valid(MAP_UID_MAX));
        assert!(!uid_is_valid(UID_INVALID));
        assert!(!uid_is_valid(u32::MAX));
    }

    #[test]
    fn test_gid_is_valid() {
        assert!(gid_is_valid(0));
        assert!(gid_is_valid(1000));
        assert!(!gid_is_valid(GID_INVALID));
        assert!(!gid_is_valid(u32::MAX));
    }

    #[test]
    fn test_map_uid_range() {
        assert!(MAP_UID_MIN < MAP_UID_MAX);
        assert_eq!(MAP_UID_MIN, 60000);
        assert_eq!(MAP_UID_MAX, 60512);
    }

    // ── Context ──────────────────────────────────────────────────────

    #[test]
    fn test_context_default() {
        let ctx = MachineBindUserContext::default();
        assert!(ctx.data.is_empty());
    }

    #[test]
    fn test_context_free_explicit() {
        let ctx = MachineBindUserContext::default();
        machine_bind_user_context_free(ctx);
        // Should not panic
    }

    // ── UserRecord predicates ────────────────────────────────────────

    #[test]
    fn test_user_is_root() {
        let root = make_user("root", 0, 0);
        assert!(root.is_root());

        let normal = make_user("alice", 1000, 1000);
        assert!(!normal.is_root());
    }

    #[test]
    fn test_user_is_nobody() {
        let nobody_uid = make_user("nobody", NOBODY_UID, NOBODY_UID);
        assert!(nobody_uid.is_nobody());

        let nobody_name = make_user("nobody", 12345, 12345);
        assert!(nobody_name.is_nobody());

        let normal = make_user("alice", 1000, 1000);
        assert!(!normal.is_nobody());
    }

    // ── Passwd collision checking ────────────────────────────────────

    #[test]
    fn test_passwd_collision_null_directory() {
        assert_eq!(
            check_etc_passwd_collisions(None, Some("root"), Some(0)).unwrap(),
            false
        );
    }

    #[test]
    fn test_passwd_collision_no_etc_dir() {
        let dir = setup_empty_dir();
        assert_eq!(
            check_etc_passwd_collisions(Some(dir.path()), Some("root"), Some(0)).unwrap(),
            false
        );
    }

    #[test]
    fn test_passwd_collision_name_hit() {
        let dir = setup_passwd_dir(&["root:x:0:0:root:/root:/bin/bash"]);
        assert_eq!(
            check_etc_passwd_collisions(Some(dir.path()), Some("root"), None).unwrap(),
            true
        );
    }

    #[test]
    fn test_passwd_collision_name_miss() {
        let dir = setup_passwd_dir(&["root:x:0:0:root:/root:/bin/bash"]);
        assert_eq!(
            check_etc_passwd_collisions(Some(dir.path()), Some("alice"), None).unwrap(),
            false
        );
    }

    #[test]
    fn test_passwd_collision_uid_hit() {
        let dir = setup_passwd_dir(&["root:x:0:0:root:/root:/bin/bash"]);
        assert_eq!(
            check_etc_passwd_collisions(Some(dir.path()), None, Some(0)).unwrap(),
            true
        );
    }

    #[test]
    fn test_passwd_collision_uid_miss() {
        let dir = setup_passwd_dir(&["root:x:0:0:root:/root:/bin/bash"]);
        assert_eq!(
            check_etc_passwd_collisions(Some(dir.path()), None, Some(9999)).unwrap(),
            false
        );
    }

    #[test]
    fn test_passwd_collision_multiple_entries() {
        let dir = setup_passwd_dir(&[
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
        ]);
        // Name hit on second entry
        assert_eq!(
            check_etc_passwd_collisions(Some(dir.path()), Some("daemon"), None).unwrap(),
            true
        );
        // UID hit on third entry
        assert_eq!(
            check_etc_passwd_collisions(Some(dir.path()), None, Some(1000)).unwrap(),
            true
        );
        // Neither name nor UID matches
        assert_eq!(
            check_etc_passwd_collisions(Some(dir.path()), Some("bob"), Some(2000)).unwrap(),
            false
        );
    }

    #[test]
    fn test_passwd_collision_invalid_uid_skipped() {
        let dir = setup_passwd_dir(&["root:x:0:0:root:/root:/bin/bash"]);
        // UID_INVALID should not match any UID
        assert_eq!(
            check_etc_passwd_collisions(Some(dir.path()), None, Some(UID_INVALID)).unwrap(),
            false
        );
    }

    // ── Group collision checking ─────────────────────────────────────

    #[test]
    fn test_group_collision_null_directory() {
        assert_eq!(
            check_etc_group_collisions(None, Some("root"), Some(0)).unwrap(),
            false
        );
    }

    #[test]
    fn test_group_collision_no_etc_dir() {
        let dir = setup_empty_dir();
        assert_eq!(
            check_etc_group_collisions(Some(dir.path()), Some("root"), Some(0)).unwrap(),
            false
        );
    }

    #[test]
    fn test_group_collision_name_hit() {
        let dir = setup_group_dir(&["root:x:0:"]);
        assert_eq!(
            check_etc_group_collisions(Some(dir.path()), Some("root"), None).unwrap(),
            true
        );
    }

    #[test]
    fn test_group_collision_gid_hit() {
        let dir = setup_group_dir(&["root:x:0:"]);
        assert_eq!(
            check_etc_group_collisions(Some(dir.path()), None, Some(0)).unwrap(),
            true
        );
    }

    #[test]
    fn test_group_collision_both_miss() {
        let dir = setup_group_dir(&["root:x:0:"]);
        assert_eq!(
            check_etc_group_collisions(Some(dir.path()), Some("alice"), Some(1000)).unwrap(),
            false
        );
    }

    // ── UID allocation ───────────────────────────────────────────────

    #[test]
    fn test_find_free_uid_empty_machine() {
        let dir = setup_empty_dir();
        let uid = find_free_uid(Some(dir.path()), MAP_UID_MIN).unwrap();
        assert_eq!(uid, MAP_UID_MIN);
    }

    #[test]
    fn test_find_free_uid_skips_collision() {
        // Put a user at MAP_UID_MIN in both passwd and group
        let dir = setup_passwd_dir(&[&format!(
            "mapped:x:{}:{}:mapped:/home/mapped:/bin/bash",
            MAP_UID_MIN, MAP_UID_MIN
        )]);
        // Also add to group
        fs::write(
            dir.path().join("etc/group"),
            format!("mapped:x:{}:\n", MAP_UID_MIN),
        )
        .unwrap();

        // Should skip MAP_UID_MIN and return MAP_UID_MIN + 1
        let uid = find_free_uid(Some(dir.path()), MAP_UID_MIN).unwrap();
        assert_eq!(uid, MAP_UID_MIN + 1);
    }

    #[test]
    fn test_find_free_uid_exhausted() {
        // Create a dir with all UIDs in range taken
        let dir = setup_empty_dir();
        fs::create_dir_all(dir.path().join("etc")).unwrap();
        let passwd_lines: Vec<String> = (MAP_UID_MIN..=MAP_UID_MAX)
            .map(|uid| format!("u{}:x:{}:{}:u:/home/u{}:/bin/bash", uid, uid, uid, uid))
            .collect();
        fs::write(dir.path().join("etc/passwd"), passwd_lines.join("\n")).unwrap();
        let group_lines: Vec<String> = (MAP_UID_MIN..=MAP_UID_MAX)
            .map(|gid| format!("g{}:x:{}:", gid, gid))
            .collect();
        fs::write(dir.path().join("etc/group"), group_lines.join("\n")).unwrap();

        let result = find_free_uid(Some(dir.path()), MAP_UID_MIN);
        assert!(matches!(result, Err(BindUserError::NoFreeUid)));
    }

    // ── machine_bind_user_prepare ────────────────────────────────────

    #[test]
    fn test_prepare_empty_users() {
        let config = BindUserConfig::default();
        let result = machine_bind_user_prepare(&config, &[], &[]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_prepare_root_rejected() {
        let config = BindUserConfig::default();
        let root = make_user("root", 0, 0);
        let root_group = make_group("root", 0);
        let result = machine_bind_user_prepare(&config, &[root], &[root_group]);
        assert!(matches!(result, Err(BindUserError::RootUserUnsupported)));
    }

    #[test]
    fn test_prepare_nobody_rejected() {
        let config = BindUserConfig::default();
        let nobody = make_user("nobody", NOBODY_UID, NOBODY_UID);
        let nobody_group = make_group("nobody", NOBODY_UID);
        let result = machine_bind_user_prepare(&config, &[nobody], &[nobody_group]);
        assert!(matches!(result, Err(BindUserError::NobodyUserUnsupported)));
    }

    #[test]
    fn test_prepare_invalid_uid_rejected() {
        let config = BindUserConfig::default();
        let invalid = UserRecord {
            user_name: "bad".to_string(),
            uid: UID_INVALID,
            gid: 1000,
            shell: None,
            home: None,
            hashed_password: Vec::new(),
        };
        let result = machine_bind_user_prepare(&config, &[invalid], &[]);
        assert!(matches!(result, Err(BindUserError::InvalidUid)));
    }

    #[test]
    fn test_prepare_no_private_group_rejected() {
        let config = BindUserConfig::default();
        let user = make_user("alice", 1000, 100);
        let group = make_group("users", 100); // name doesn't match
        let result = machine_bind_user_prepare(&config, &[user], &[group]);
        assert!(matches!(result, Err(BindUserError::NoPrivateGroup)));
    }

    #[test]
    fn test_prepare_missing_group_rejected() {
        let config = BindUserConfig::default();
        let user = make_user("alice", 1000, 9999); // no group with GID 9999
        let result = machine_bind_user_prepare(&config, &[user], &[]);
        assert!(matches!(result, Err(BindUserError::MissingGroup(9999))));
    }

    #[test]
    fn test_prepare_success_single_user() {
        let dir = setup_empty_dir();
        let config = BindUserConfig {
            directory: Some(dir.path()),
            ..Default::default()
        };
        let user = make_user("alice", 1000, 1000);
        let group = make_group("alice", 1000);
        let result = machine_bind_user_prepare(&config, &[user], &[group]).unwrap();

        let ctx = result.unwrap();
        assert_eq!(ctx.data.len(), 1);

        let entry = &ctx.data[0];
        assert_eq!(entry.host_user.user_name, "alice");
        assert_eq!(entry.host_group.group_name, "alice");
        assert_eq!(entry.payload_user.uid, MAP_UID_MIN);
        assert_eq!(entry.payload_user.gid, MAP_UID_MIN);
        assert_eq!(entry.payload_group.gid, MAP_UID_MIN);
    }

    #[test]
    fn test_prepare_success_multiple_users() {
        let dir = setup_empty_dir();
        let config = BindUserConfig {
            directory: Some(dir.path()),
            shell: Some("/bin/sh"),
            ..Default::default()
        };
        let users = vec![make_user("alice", 1000, 1000), make_user("bob", 1001, 1001)];
        let groups = vec![make_group("alice", 1000), make_group("bob", 1001)];
        let result = machine_bind_user_prepare(&config, &users, &groups).unwrap();

        let ctx = result.unwrap();
        assert_eq!(ctx.data.len(), 2);

        assert_eq!(ctx.data[0].payload_user.uid, MAP_UID_MIN);
        assert_eq!(ctx.data[0].payload_user.shell.as_deref(), Some("/bin/sh"));

        assert_eq!(ctx.data[1].payload_user.uid, MAP_UID_MIN + 1);
        assert_eq!(ctx.data[1].payload_user.shell.as_deref(), Some("/bin/sh"));
    }

    #[test]
    fn test_prepare_shell_copy() {
        let dir = setup_empty_dir();
        let config = BindUserConfig {
            directory: Some(dir.path()),
            shell: Some("/bin/zsh"), // should be ignored
            shell_copy: true,
            ..Default::default()
        };
        let user = UserRecord {
            user_name: "alice".to_string(),
            uid: 1000,
            gid: 1000,
            shell: Some("/bin/fish".to_string()),
            home: None,
            hashed_password: Vec::new(),
        };
        let group = make_group("alice", 1000);
        let result = machine_bind_user_prepare(&config, &[user], &[group]).unwrap();

        let ctx = result.unwrap();
        assert_eq!(ctx.data[0].payload_user.shell.as_deref(), Some("/bin/fish"));
    }

    #[test]
    fn test_prepare_home_mount_directory() {
        let dir = setup_empty_dir();
        let home_base = tempfile::tempdir().unwrap();
        let config = BindUserConfig {
            directory: Some(dir.path()),
            home_mount_directory: Some(home_base.path()),
            ..Default::default()
        };
        let user = make_user("alice", 1000, 1000);
        let group = make_group("alice", 1000);
        let result = machine_bind_user_prepare(&config, &[user], &[group]).unwrap();

        let ctx = result.unwrap();
        let expected_home = home_base.path().join("alice").to_string_lossy().to_string();
        assert_eq!(
            ctx.data[0].payload_user.home.as_deref(),
            Some(expected_home.as_str())
        );
    }

    #[test]
    fn test_prepare_no_home_mount() {
        let dir = setup_empty_dir();
        let config = BindUserConfig {
            directory: Some(dir.path()),
            home_mount_directory: None,
            ..Default::default()
        };
        let user = make_user("alice", 1000, 1000);
        let group = make_group("alice", 1000);
        let result = machine_bind_user_prepare(&config, &[user], &[group]).unwrap();

        let ctx = result.unwrap();
        assert!(ctx.data[0].payload_user.home.is_none());
    }

    #[test]
    fn test_prepare_no_directory_skips_collision_checks() {
        // With directory=None, collision checks are skipped
        let config = BindUserConfig {
            directory: None,
            ..Default::default()
        };
        // Use a user named "root" as a host user (name exists in most machines)
        // — but since directory is None, collision checks are skipped
        // — wait, root UID 0 would still be rejected by is_root()
        // Use a non-root user instead
        let user = make_user("daemon", 1, 1); // "daemon" typically exists in machines
        let group = make_group("daemon", 1);
        let result = machine_bind_user_prepare(&config, &[user], &[group]).unwrap();
        // Should succeed because no collision checks are done
        assert!(result.is_some());
    }

    // ── Error display ────────────────────────────────────────────────

    #[test]
    fn test_error_display_messages() {
        assert!(!BindUserError::NoFreeUid.to_string().is_empty());
        assert!(!BindUserError::RootUserUnsupported.to_string().is_empty());
        assert!(!BindUserError::NobodyUserUnsupported.to_string().is_empty());
        assert!(!BindUserError::InvalidUid.to_string().is_empty());
        assert!(!BindUserError::NoPrivateGroup.to_string().is_empty());

        let col = BindUserError::PasswdCollision("alice".to_string());
        assert!(col.to_string().contains("alice"));

        let col = BindUserError::GroupCollision("wheel".to_string());
        assert!(col.to_string().contains("wheel"));

        let miss = BindUserError::MissingGroup(42);
        assert!(miss.to_string().contains("42"));
    }

    // ── PasswdEntry / GroupEntry ─────────────────────────────────────

    #[test]
    fn test_passwd_entry_equality() {
        let a = PasswdEntry {
            name: "root".into(),
            uid: 0,
            gid: 0,
            gecos: "root".into(),
            home: "/root".into(),
            shell: "/bin/bash".into(),
        };
        let b = PasswdEntry {
            name: "root".into(),
            uid: 0,
            gid: 0,
            gecos: "root".into(),
            home: "/root".into(),
            shell: "/bin/bash".into(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_group_entry_equality() {
        let a = GroupEntry {
            name: "wheel".into(),
            gid: 10,
            members: vec!["alice".into()],
        };
        let b = GroupEntry {
            name: "wheel".into(),
            gid: 10,
            members: vec!["alice".into()],
        };
        assert_eq!(a, b);
    }
}
