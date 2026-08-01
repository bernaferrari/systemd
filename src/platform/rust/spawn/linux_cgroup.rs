// SPDX-License-Identifier: LGPL-2.1-or-later

//! Parent-side delegated-cgroup access handoff.
//!
//! The broad launch plan owns only borrowed capabilities. This module contains
//! the one Linux ownership ABI call and keeps all traversal rooted at those
//! descriptors, separate from the post-fork child path.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;

pub(super) fn delegate_cgroup_access(
    delegate_root: BorrowedFd<'_>,
    target: BorrowedFd<'_>,
    uid: Option<u32>,
    gid: Option<u32>,
    recursive_target_access: bool,
) -> Result<(), String> {
    let uid = uid.unwrap_or(u32::MAX) as libc::uid_t;
    let gid = gid.unwrap_or(u32::MAX) as libc::gid_t;

    fn chown_entry(
        directory: BorrowedFd<'_>,
        name: &CStr,
        uid: libc::uid_t,
        gid: libc::gid_t,
        required: bool,
    ) -> Result<(), String> {
        let flags = if name.to_bytes().is_empty() {
            libc::AT_EMPTY_PATH
        } else {
            libc::AT_SYMLINK_NOFOLLOW
        };
        // `directory` is live and `name` NUL-terminated. Empty names use only
        // AT_EMPTY_PATH; nonempty names are confined and never follow links.
        // SAFETY: all fchownat pointer, descriptor, and flag contracts hold.
        let result = unsafe_ffi!(libc::fchownat(
            directory.as_raw_fd(),
            name.as_ptr(),
            uid,
            gid,
            flags
        ));
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if required {
            Err(format!(
                "failed to delegate cgroup entry {:?}: {error}",
                name.to_string_lossy()
            ))
        } else {
            Ok(())
        }
    }

    fn chown_access_root(
        directory: BorrowedFd<'_>,
        uid: libc::uid_t,
        gid: libc::gid_t,
    ) -> Result<(), String> {
        fn chmod_entry(
            directory: BorrowedFd<'_>,
            name: &CStr,
            mode: u32,
            required: bool,
        ) -> Result<(), String> {
            let mut path =
                std::path::PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
            if !name.to_bytes().is_empty() {
                path.push(OsStr::from_bytes(name.to_bytes()));
            }
            match std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)) {
                Ok(()) => Ok(()),
                Err(_) if !required => Ok(()),
                Err(error) => Err(format!(
                    "failed to set delegated cgroup mode on {}: {error}",
                    path.display()
                )),
            }
        }

        // cg_set_access() restores the delegation ABI modes as well as owners.
        chmod_entry(directory, c"", 0o755, true)?;
        chown_entry(directory, c"", uid, gid, true)?;
        chmod_entry(directory, c"cgroup.procs", 0o644, true)?;
        chown_entry(directory, c"cgroup.procs", uid, gid, true)?;
        chmod_entry(directory, c"cgroup.subtree_control", 0o644, true)?;
        chown_entry(directory, c"cgroup.subtree_control", uid, gid, true)?;
        chmod_entry(directory, c"cgroup.threads", 0o644, false)?;
        chown_entry(directory, c"cgroup.threads", uid, gid, false)?;
        chmod_entry(directory, c"memory.oom.group", 0o644, false)?;
        chown_entry(directory, c"memory.oom.group", uid, gid, false)?;
        chmod_entry(directory, c"memory.reclaim", 0o644, false)?;
        chown_entry(directory, c"memory.reclaim", uid, gid, false)
    }

    fn chown_access_recursive(
        directory: BorrowedFd<'_>,
        uid: libc::uid_t,
        gid: libc::gid_t,
    ) -> Result<(), String> {
        const MAX_DEPTH: usize = 256;
        const MAX_ENTRIES: usize = 65_536;

        fn visit(
            directory: BorrowedFd<'_>,
            uid: libc::uid_t,
            gid: libc::gid_t,
            depth: usize,
            entries_seen: &mut usize,
        ) -> Result<(), String> {
            if depth > MAX_DEPTH || *entries_seen >= MAX_ENTRIES {
                return Err(
                    "delegated cgroup hierarchy exceeds the ownership traversal bound".into(),
                );
            }
            *entries_seen += 1;
            chown_entry(directory, c"", uid, gid, true)?;
            let path = format!("/proc/self/fd/{}", directory.as_raw_fd());
            let entries = std::fs::read_dir(&path)
                .map_err(|error| format!("failed to enumerate delegated cgroup {path}: {error}"))?;
            for entry in entries {
                if *entries_seen >= MAX_ENTRIES {
                    return Err(
                        "delegated cgroup hierarchy exceeds the ownership traversal bound".into(),
                    );
                }
                *entries_seen += 1;
                let entry = entry
                    .map_err(|error| format!("failed to enumerate delegated cgroup: {error}"))?;
                let name = CString::new(entry.file_name().as_bytes()).map_err(|_| {
                    format!(
                        "delegated cgroup contains an invalid component {:?}",
                        entry.file_name()
                    )
                })?;
                chown_entry(directory, &name, uid, gid, true)?;
                if entry
                    .file_type()
                    .map_err(|error| {
                        format!(
                            "failed to inspect delegated cgroup entry {:?}: {error}",
                            entry.file_name()
                        )
                    })?
                    .is_dir()
                {
                    // `entry.path()` is rooted at `/proc/self/fd/N`, hence at
                    // the retained target capability rather than the original
                    // hierarchy pathname. cgroupfs does not expose symlinked
                    // cgroup directories.
                    let child = File::open(entry.path()).map_err(|error| {
                        format!(
                            "failed to open delegated cgroup child {:?}: {error}",
                            entry.file_name()
                        )
                    })?;
                    visit(child.as_fd(), uid, gid, depth + 1, entries_seen)?;
                }
            }
            Ok(())
        }

        let mut entries_seen = 0;
        visit(directory, uid, gid, 0, &mut entries_seen)
    }

    // Match cg_set_access() for the unit root. A distinct DelegateSubgroup or
    // `.control` target receives cg_set_access_recursive() semantics.
    chown_access_root(delegate_root, uid, gid)?;
    if recursive_target_access {
        chown_access_recursive(target, uid, gid)
    } else {
        Ok(())
    }
}
