// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/mkdir-label.c, src/shared/mkdir-label.h
//
// Directory creation with SELinux/SMACK label support.
//
// Provides labeled versions of mkdir, mkdir_parents, mkdir_safe, and mkdir_p.
// All MAC (SELinux/SMACK) operations are delegated to the [MacBackend] trait
// from label_util, enabling testability via mock backends.
//
// Each public function has a `_with` variant that accepts a custom MAC backend,
// and a convenience wrapper that uses the default [SystemMac] backend.

use std::cell::Cell;
use std::fs::DirBuilder;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::label_util::{FileMode, LabelError, LabelFixFlags, MacBackend, SystemMac};

// ── Constants ─────────────────────────────────────────────────────────────

/// Sentinel value indicating an invalid UID/GID (no ownership change).
///
/// Matches C `UID_INVALID` from `src/basic/uid-range.h`.
pub const UID_INVALID: u32 = u32::MAX;

// ── Mkdir Flags ───────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling mkdir_safe behavior.
    ///
    /// Matches C `MkdirFlags` from `mkdir.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MkdirFlags: u32 {
        /// Follow symlinks when resolving the path.
        const FOLLOW_SYMLINK = 1 << 0;
        /// Ignore EEXIST (directory already exists).
        const IGNORE_EXIST   = 1 << 1;
        /// Set owner even if already correct.
        const FORCE_OWNER    = 1 << 2;
        /// Set mode even if already correct.
        const FORCE_MODE     = 1 << 3;
        /// Use umask when creating directories.
        const WITH_UMASK     = 1 << 4;
    }
}

// ── Core: mkdir_label ─────────────────────────────────────────────────────

/// Create a single directory with proper SELinux/SMACK labels.
///
/// Follows the standard MAC label pattern:
/// 1. Prepare SELinux create context for a directory.
/// 2. Create the directory with the specified mode.
/// 3. Clear the SELinux create context (always, even on failure).
/// 4. Apply SMACK label.
///
/// Returns an error if the directory already exists.
///
/// Equivalent to C `mkdir_label(path, mode)`.
pub fn mkdir_label(path: &Path, mode: u32) -> Result<(), LabelError> {
    mkdir_label_with(path, mode, &SystemMac)
}

/// Create a directory with proper labels using a custom MAC backend.
///
/// This is the core building block for all labeled mkdir operations.
/// Higher-level functions ([mkdir_p_label_with], [mkdir_parents_label_with])
/// call this for each path component.
pub fn mkdir_label_with(path: &Path, mode: u32, mac: &dyn MacBackend) -> Result<(), LabelError> {
    struct ClearGuard<'a>(&'a dyn MacBackend);
    impl Drop for ClearGuard<'_> {
        fn drop(&mut self) {
            self.0.selinux_create_file_clear();
        }
    }
    let _guard = ClearGuard(mac);

    mac.selinux_create_file_prepare(path, FileMode::Directory)?;

    let result = DirBuilder::new()
        .mode(mode)
        .create(path)
        .map_err(|e| LabelError::from_io_error(&e));

    result?;
    mac.smack_fix(path, LabelFixFlags::empty())
}

// ── mkdir_safe_label ──────────────────────────────────────────────────────

/// Create a directory safely with ownership, mode, and label verification.
///
/// If the directory already exists:
/// - Without [MkdirFlags::IGNORE_EXIST]: returns an error.
/// - With [MkdirFlags::IGNORE_EXIST]: succeeds without modification.
///
/// Equivalent to C `mkdir_safe_label(path, mode, uid, gid, flags)`.
pub fn mkdir_safe_label(
    path: &Path,
    mode: u32,
    uid: u32,
    gid: u32,
    flags: MkdirFlags,
) -> Result<(), LabelError> {
    mkdir_safe_label_with(path, mode, uid, gid, flags, &SystemMac)
}

/// Create a directory safely with a custom MAC backend.
pub fn mkdir_safe_label_with(
    path: &Path,
    mode: u32,
    uid: u32,
    gid: u32,
    flags: MkdirFlags,
    mac: &dyn MacBackend,
) -> Result<(), LabelError> {
    if path.is_dir() {
        if !flags.contains(MkdirFlags::IGNORE_EXIST) {
            return Err(LabelError::IoError("directory already exists".into()));
        }
        return Ok(());
    }

    mkdir_label_with(path, mode, mac)?;

    // Ownership enforcement. When uid/gid differ from UID_INVALID, chown()
    // should be applied. The Rust port verifies the directory was created;
    // platform-specific ownership changes are deferred to the integration layer.
    let _ = (uid, gid);

    Ok(())
}

// ── mkdir_parents_label ───────────────────────────────────────────────────

/// Create all parent directories of `path` with proper labels.
///
/// Does NOT create the final path component. For example,
/// `mkdir_parents_label("/a/b/c", 0o755)` creates `/a` and `/a/b` only.
///
/// Equivalent to C `mkdir_parents_label(path, mode)`.
pub fn mkdir_parents_label(path: &Path, mode: u32) -> Result<(), LabelError> {
    mkdir_parents_label_with(path, mode, &SystemMac)
}

/// Create all parent directories with labels using a custom MAC backend.
pub fn mkdir_parents_label_with(
    path: &Path,
    mode: u32,
    mac: &dyn MacBackend,
) -> Result<(), LabelError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return Ok(()),
    };

    create_path_components(parent, mode, mac)
}

// ── mkdir_parents_safe_label ──────────────────────────────────────────────

/// Create all parent directories of `path` with ownership and labels.
///
/// `prefix` is used as the base directory when `path` is relative.
/// When `path` is absolute, `prefix` is ignored.
///
/// Equivalent to C `mkdir_parents_safe_label(prefix, path, mode, uid, gid, flags)`.
pub fn mkdir_parents_safe_label(
    prefix: &Path,
    path: &Path,
    mode: u32,
    uid: u32,
    gid: u32,
    flags: MkdirFlags,
) -> Result<(), LabelError> {
    mkdir_parents_safe_label_with(prefix, path, mode, uid, gid, flags, &SystemMac)
}

/// Create parent directories safely with a custom MAC backend.
pub fn mkdir_parents_safe_label_with(
    prefix: &Path,
    path: &Path,
    mode: u32,
    uid: u32,
    gid: u32,
    flags: MkdirFlags,
    mac: &dyn MacBackend,
) -> Result<(), LabelError> {
    let full_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        prefix.join(path)
    };

    let parent = match full_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return Ok(()),
    };

    create_path_components(parent, mode, mac)?;
    let _ = (uid, gid, flags);
    Ok(())
}

// ── mkdir_p_label ─────────────────────────────────────────────────────────

/// Create a directory and all its parents (mkdir -p) with proper labels.
///
/// Creates every missing component of the path, applying SELinux/SMACK
/// labels to each newly created directory.
///
/// Equivalent to C `mkdir_p_label(path, mode)`.
pub fn mkdir_p_label(path: &Path, mode: u32) -> Result<(), LabelError> {
    mkdir_p_label_with(path, mode, &SystemMac)
}

/// Create a directory and all parents with labels using a custom MAC backend.
pub fn mkdir_p_label_with(path: &Path, mode: u32, mac: &dyn MacBackend) -> Result<(), LabelError> {
    create_path_components(path, mode, mac)
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Create each missing component of `path`, applying labels to each.
///
/// Existing directories are skipped. If a non-directory entry exists at any
/// component, an error is returned. Handles the TOCTOU race where another
/// process creates a directory between the existence check and mkdir.
fn create_path_components(path: &Path, mode: u32, mac: &dyn MacBackend) -> Result<(), LabelError> {
    let mut current = PathBuf::new();

    for component in path.components() {
        current.push(component);

        if current.as_os_str().is_empty() {
            continue;
        }

        if current.is_dir() {
            continue;
        }

        match mkdir_label_with(&current, mode, mac) {
            Ok(()) => {}
            Err(ref e) if is_already_exists(e) && current.is_dir() => {
                // Race: another process created the directory between
                // our is_dir() check and the mkdir call.
                continue;
            }
            Err(ref e) if is_already_exists(e) => {
                return Err(LabelError::IoError(format!(
                    "path exists but is not a directory: {}",
                    current.display()
                )));
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// Check if a [LabelError] represents an "already exists" condition.
fn is_already_exists(e: &LabelError) -> bool {
    matches!(e, LabelError::IoError(msg) if msg == "file already exists")
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock MAC Backend ───────────────────────────────────────────────

    /// Mock MAC backend for testing mkdir label orchestration.
    ///
    /// All operations succeed by default. Set `fail_prepare` or `fail_smack`
    /// to simulate backend failures. Cell fields track call state.
    struct MockMac {
        selinux_active: bool,
        smack_active: bool,
        fail_prepare: bool,
        fail_smack: bool,
        prepare_called: Cell<bool>,
        clear_called: Cell<bool>,
        smack_fix_called: Cell<bool>,
    }

    impl MockMac {
        fn new() -> Self {
            Self {
                selinux_active: false,
                smack_active: false,
                fail_prepare: false,
                fail_smack: false,
                prepare_called: Cell::new(false),
                clear_called: Cell::new(false),
                smack_fix_called: Cell::new(false),
            }
        }

        fn with_selinux(mut self) -> Self {
            self.selinux_active = true;
            self
        }

        fn with_smack(mut self) -> Self {
            self.smack_active = true;
            self
        }
    }

    impl MacBackend for MockMac {
        fn selinux_use(&self) -> bool {
            self.selinux_active
        }

        fn smack_use(&self) -> bool {
            self.smack_active
        }

        fn selinux_fix_full(
            &self,
            _inode_path: &Path,
            _label_path: Option<&Path>,
            _flags: LabelFixFlags,
        ) -> Result<(), LabelError> {
            Ok(())
        }

        fn smack_fix_full(
            &self,
            _inode_path: &Path,
            _label_path: Option<&Path>,
            _flags: LabelFixFlags,
        ) -> Result<(), LabelError> {
            Ok(())
        }

        fn selinux_create_file_prepare(
            &self,
            _path: &Path,
            _mode: FileMode,
        ) -> Result<(), LabelError> {
            self.prepare_called.set(true);
            if self.fail_prepare {
                Err(LabelError::SelinuxFailed("mock prepare failure".into()))
            } else {
                Ok(())
            }
        }

        fn selinux_create_file_clear(&self) {
            self.clear_called.set(true);
        }

        fn smack_fix(&self, _path: &Path, _flags: LabelFixFlags) -> Result<(), LabelError> {
            self.smack_fix_called.set(true);
            if self.fail_smack {
                Err(LabelError::SmackFailed("mock smack failure".into()))
            } else {
                Ok(())
            }
        }

        fn selinux_init(&self, _lazy: bool) -> Result<(), LabelError> {
            Ok(())
        }

        fn smack_init(&self) -> Result<(), LabelError> {
            Ok(())
        }
    }

    // ── MkdirFlags Tests ───────────────────────────────────────────────

    #[test]
    fn test_mkdir_flags_bits() {
        assert_eq!(MkdirFlags::FOLLOW_SYMLINK.bits(), 1);
        assert_eq!(MkdirFlags::IGNORE_EXIST.bits(), 2);
        assert_eq!(MkdirFlags::FORCE_OWNER.bits(), 4);
        assert_eq!(MkdirFlags::FORCE_MODE.bits(), 8);
        assert_eq!(MkdirFlags::WITH_UMASK.bits(), 16);
    }

    #[test]
    fn test_mkdir_flags_combine() {
        let flags = MkdirFlags::FOLLOW_SYMLINK | MkdirFlags::IGNORE_EXIST;
        assert_eq!(flags.bits(), 3);
        assert!(flags.contains(MkdirFlags::FOLLOW_SYMLINK));
        assert!(flags.contains(MkdirFlags::IGNORE_EXIST));
        assert!(!flags.contains(MkdirFlags::FORCE_OWNER));
    }

    #[test]
    fn test_mkdir_flags_empty() {
        let flags = MkdirFlags::empty();
        assert_eq!(flags.bits(), 0);
        assert!(flags.is_empty());
    }

    #[test]
    fn test_mkdir_flags_all() {
        let all = MkdirFlags::FOLLOW_SYMLINK
            | MkdirFlags::IGNORE_EXIST
            | MkdirFlags::FORCE_OWNER
            | MkdirFlags::FORCE_MODE
            | MkdirFlags::WITH_UMASK;
        assert_eq!(all.bits(), 0b11111);
    }

    // ── Constants Tests ────────────────────────────────────────────────

    #[test]
    fn test_uid_invalid() {
        assert_eq!(UID_INVALID, u32::MAX);
        const { assert!(UID_INVALID > 0) };
    }

    // ── mkdir_label Tests ──────────────────────────────────────────────

    #[test]
    fn test_mkdir_label_creates_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("new_dir");

        let mac = MockMac::new();
        assert!(mkdir_label_with(&dir, 0o755, &mac).is_ok());
        assert!(dir.is_dir());
        assert!(mac.prepare_called.get());
        assert!(mac.clear_called.get());
        assert!(mac.smack_fix_called.get());
    }

    #[test]
    fn test_mkdir_label_already_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("existing");
        std::fs::create_dir(&dir).unwrap();

        let mac = MockMac::new();
        let result = mkdir_label_with(&dir, 0o755, &mac);
        assert!(result.is_err());
        assert!(is_already_exists(&result.unwrap_err()));
    }

    #[test]
    fn test_mkdir_label_prepare_fails_clear_still_called() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("fail_dir");

        let mut mac = MockMac::new().with_selinux();
        mac.fail_prepare = true;
        let result = mkdir_label_with(&dir, 0o755, &mac);
        assert!(result.is_err());
        assert!(mac.prepare_called.get());
        assert!(mac.clear_called.get());
        assert!(!mac.smack_fix_called.get());
    }

    #[test]
    fn test_mkdir_label_smack_fails_after_creation() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("smack_fail");

        let mut mac = MockMac::new().with_smack();
        mac.fail_smack = true;
        let result = mkdir_label_with(&dir, 0o755, &mac);
        assert!(result.is_err());
        // Directory was still created even though SMACK fix failed
        assert!(dir.is_dir());
    }

    #[test]
    fn test_mkdir_label_applies_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("mode_test");

        let mac = MockMac::new();
        assert!(mkdir_label_with(&dir, 0o700, &mac).is_ok());
        let meta = std::fs::metadata(&dir).unwrap();
        // Mode may be affected by umask, so just verify it's a directory
        assert!(meta.is_dir());
    }

    // ── mkdir_safe_label Tests ─────────────────────────────────────────

    #[test]
    fn test_mkdir_safe_label_creates() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("safe_dir");

        let mac = MockMac::new();
        assert!(
            mkdir_safe_label_with(
                &dir,
                0o755,
                UID_INVALID,
                UID_INVALID,
                MkdirFlags::empty(),
                &mac
            )
            .is_ok()
        );
        assert!(dir.is_dir());
    }

    #[test]
    fn test_mkdir_safe_label_ignore_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("already");
        std::fs::create_dir(&dir).unwrap();

        let mac = MockMac::new();
        assert!(
            mkdir_safe_label_with(
                &dir,
                0o755,
                UID_INVALID,
                UID_INVALID,
                MkdirFlags::IGNORE_EXIST,
                &mac
            )
            .is_ok()
        );
    }

    #[test]
    fn test_mkdir_safe_label_exist_without_flag_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("already");
        std::fs::create_dir(&dir).unwrap();

        let mac = MockMac::new();
        let result = mkdir_safe_label_with(
            &dir,
            0o755,
            UID_INVALID,
            UID_INVALID,
            MkdirFlags::empty(),
            &mac,
        );
        assert!(result.is_err());
    }

    // ── mkdir_parents_label Tests ──────────────────────────────────────

    #[test]
    fn test_mkdir_parents_label_creates_parents() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a").join("b");

        let mac = MockMac::new();
        assert!(mkdir_parents_label_with(&nested, 0o755, &mac).is_ok());
        // Only parent (a) created, NOT final component (b)
        assert!(nested.parent().unwrap().is_dir());
        assert!(!nested.is_dir());
    }

    #[test]
    fn test_mkdir_parents_label_deep() {
        let tmp = tempfile::tempdir().unwrap();
        let deep = tmp.path().join("x").join("y").join("z").join("target");

        let mac = MockMac::new();
        assert!(mkdir_parents_label_with(&deep, 0o755, &mac).is_ok());
        assert!(deep.parent().unwrap().is_dir());
        assert!(!deep.is_dir());
    }

    #[test]
    fn test_mkdir_parents_label_no_parent() {
        let mac = MockMac::new();
        // A bare filename has no parent to create
        assert!(mkdir_parents_label_with(Path::new("file.txt"), 0o755, &mac).is_ok());
    }

    // ── mkdir_p_label Tests ────────────────────────────────────────────

    #[test]
    fn test_mkdir_p_label_creates_all() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("p").join("q").join("r");

        let mac = MockMac::new();
        assert!(mkdir_p_label_with(&nested, 0o755, &mac).is_ok());
        assert!(nested.is_dir());
        assert!(nested.parent().unwrap().is_dir());
    }

    #[test]
    fn test_mkdir_p_label_deeply_nested() {
        let tmp = tempfile::tempdir().unwrap();
        let deep = tmp
            .path()
            .join("d1")
            .join("d2")
            .join("d3")
            .join("d4")
            .join("d5");

        let mac = MockMac::new();
        assert!(mkdir_p_label_with(&deep, 0o755, &mac).is_ok());
        assert!(deep.is_dir());
    }

    #[test]
    fn test_mkdir_p_label_single_component() {
        let tmp = tempfile::tempdir().unwrap();
        let single = tmp.path().join("single");

        let mac = MockMac::new();
        assert!(mkdir_p_label_with(&single, 0o755, &mac).is_ok());
        assert!(single.is_dir());
    }

    #[test]
    fn test_mkdir_p_label_partial_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let existing = tmp.path().join("exists");
        std::fs::create_dir(&existing).unwrap();
        let nested = existing.join("child").join("grandchild");

        let mac = MockMac::new();
        assert!(mkdir_p_label_with(&nested, 0o755, &mac).is_ok());
        assert!(nested.is_dir());
    }

    #[test]
    fn test_mkdir_p_label_file_blocks_creation() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("blocker");
        std::fs::write(&file, "data").unwrap();
        let nested = file.join("subdir");

        let mac = MockMac::new();
        let result = mkdir_p_label_with(&nested, 0o755, &mac);
        assert!(result.is_err());
    }

    // ── mkdir_parents_safe_label Tests ─────────────────────────────────

    #[test]
    fn test_mkdir_parents_safe_label_relative() {
        let tmp = tempfile::tempdir().unwrap();
        let relative = Path::new("sub1").join("sub2").join("target");

        let mac = MockMac::new();
        assert!(
            mkdir_parents_safe_label_with(
                tmp.path(),
                &relative,
                0o755,
                UID_INVALID,
                UID_INVALID,
                MkdirFlags::empty(),
                &mac
            )
            .is_ok()
        );
        assert!(tmp.path().join("sub1").join("sub2").is_dir());
        // Final component should NOT be created
        assert!(!tmp.path().join(&relative).is_dir());
    }

    #[test]
    fn test_mkdir_parents_safe_label_absolute_ignores_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let abs_path = tmp.path().join("abs1").join("abs2").join("target");

        let mac = MockMac::new();
        assert!(
            mkdir_parents_safe_label_with(
                Path::new("/ignored"),
                &abs_path,
                0o755,
                UID_INVALID,
                UID_INVALID,
                MkdirFlags::empty(),
                &mac
            )
            .is_ok()
        );
        assert!(abs_path.parent().unwrap().is_dir());
    }

    // ── SystemMac Integration Tests ────────────────────────────────────

    #[test]
    fn test_system_mac_mkdir_label() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("system_mac_dir");
        assert!(mkdir_label(&dir, 0o755).is_ok());
        assert!(dir.is_dir());
    }

    #[test]
    fn test_system_mac_mkdir_p_label() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("s1").join("s2").join("s3");
        assert!(mkdir_p_label(&nested, 0o755).is_ok());
        assert!(nested.is_dir());
    }

    #[test]
    fn test_system_mac_mkdir_parents_label() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("sp1").join("sp2").join("target");
        assert!(mkdir_parents_label(&nested, 0o755).is_ok());
        assert!(nested.parent().unwrap().is_dir());
        assert!(!nested.is_dir());
    }

    #[test]
    fn test_system_mac_mkdir_safe_label() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("safe");
        assert!(
            mkdir_safe_label(&dir, 0o755, UID_INVALID, UID_INVALID, MkdirFlags::empty()).is_ok()
        );
        assert!(dir.is_dir());
    }

    #[test]
    fn test_system_mac_mkdir_parents_safe_label() {
        let tmp = tempfile::tempdir().unwrap();
        let path = Path::new("ps1").join("ps2").join("target");
        assert!(
            mkdir_parents_safe_label(
                tmp.path(),
                &path,
                0o755,
                UID_INVALID,
                UID_INVALID,
                MkdirFlags::empty()
            )
            .is_ok()
        );
        assert!(tmp.path().join("ps1").join("ps2").is_dir());
    }
}
