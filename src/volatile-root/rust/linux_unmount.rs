// SPDX-License-Identifier: LGPL-2.1-or-later

//! Linux recursive no-follow unmount support for the volatile-root transition.
//!
//! This is kept separate from the orchestration and mount transaction so the
//! mountinfo parser and restart-after-success loop remain independently
//! reviewable and testable.

use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// C-compatible, best-effort recursive unmount using a pinned mountinfo file.
///
/// C's `umount_recursive_full()` restarts its reverse mountinfo walk after
/// every successful unmount. This matters for stacked mounts: unmounting the
/// visible mount can expose another entry at the same path, which must be
/// discovered from a freshly parsed mountinfo view. Individual unmount
/// failures are ignored exactly as C does; failure to obtain or parse
/// mountinfo remains fatal.
pub(crate) fn unmount_tree_nofollow(prefix: &Path) -> io::Result<()> {
    let mut mountinfo = std::fs::File::open("/proc/self/mountinfo")?;
    unmount_tree_with(
        prefix,
        || {
            mountinfo.seek(SeekFrom::Start(0))?;
            let mut snapshot = String::new();
            mountinfo.read_to_string(&mut snapshot)?;
            Ok(snapshot)
        },
        |target| {
            systemd_shared_rs::mount_util::umount_verbose_path(
                target,
                systemd_shared_rs::mount_util::UMOUNT_NOFOLLOW,
            )
        },
    )
}

/// Run C's restart-after-success recursive-unmount loop with injectable
/// mountinfo reads and unmount operations.
pub(crate) fn unmount_tree_with(
    prefix: &Path,
    mut read_mountinfo: impl FnMut() -> io::Result<String>,
    mut unmount: impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    loop {
        let mountinfo = read_mountinfo()?;
        let mut unmounted = false;

        for target in mount_targets_beneath(&mountinfo, prefix)?.into_iter().rev() {
            if unmount(&target).is_ok() {
                unmounted = true;
                break;
            }
        }

        if !unmounted {
            return Ok(());
        }
    }
}

/// Extract mount targets that are `prefix` or descendants, decoding the
/// octal quoting used by `/proc/*/mountinfo` before byte-wise path matching.
pub(crate) fn mount_targets_beneath(mountinfo: &str, prefix: &Path) -> io::Result<Vec<PathBuf>> {
    let prefix = prefix.as_os_str().as_bytes();
    let mut targets = Vec::new();

    for line in mountinfo.lines() {
        let mount_point = line.split_ascii_whitespace().nth(4).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "truncated mountinfo entry")
        })?;
        let mount_point = unescape_mountinfo_path(mount_point)?;
        if path_is_prefix(prefix, &mount_point) {
            targets.push(PathBuf::from(std::ffi::OsString::from_vec(mount_point)));
        }
    }
    Ok(targets)
}

fn path_is_prefix(prefix: &[u8], path: &[u8]) -> bool {
    prefix == b"/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.first() == Some(&b'/'))
}

fn unescape_mountinfo_path(path: &str) -> io::Result<Vec<u8>> {
    let bytes = path.as_bytes();
    let mut unescaped = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            let Some(octal) = bytes.get(index + 1..index + 4) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated mountinfo escape",
                ));
            };
            if !octal.iter().all(u8::is_ascii_digit) || octal.iter().any(|byte| *byte > b'7') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid mountinfo escape",
                ));
            }
            unescaped.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + octal[2] - b'0');
            index += 4;
        } else {
            unescaped.push(bytes[index]);
            index += 1;
        }
    }
    Ok(unescaped)
}
