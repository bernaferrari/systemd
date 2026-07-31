// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/mount-util.c, src/shared/mount-util.h

use crate::ffi::*;
use std::ffi::CString;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub const MS_RDONLY: u64 = 1;
pub const MS_NOSUID: u64 = 2;
pub const MS_NODEV: u64 = 4;
pub const MS_NOEXEC: u64 = 8;
pub const MS_SYNCHRONOUS: u64 = 16;
pub const MS_REMOUNT: u64 = 32;
pub const MS_MANDLOCK: u64 = 64;
pub const MS_DIRSYNC: u64 = 128;
pub const MS_NOATIME: u64 = 1024;
pub const MS_NODIRATIME: u64 = 2048;
pub const MS_BIND: u64 = 4096;
pub const MS_MOVE: u64 = 8192;
pub const MS_REC: u64 = 16384;
pub const MS_SILENT: u64 = 32768;
pub const MS_POSIXACL: u64 = 1 << 16;
pub const MS_UNBINDABLE: u64 = 1 << 17;
pub const MS_PRIVATE: u64 = 1 << 18;
pub const MS_SLAVE: u64 = 1 << 19;
pub const MS_SHARED: u64 = 1 << 20;
pub const MS_RELATIME: u64 = 1 << 21;
pub const MS_KERNMOUNT: u64 = 1 << 22;
pub const MS_I_VERSION: u64 = 1 << 23;
pub const MS_STRICTATIME: u64 = 1 << 24;
pub const MS_LAZYTIME: u64 = 1 << 25;
pub const MS_NOSYMFOLLOW: u64 = 1 << 26;

/// Flags convertible to mount_attr for mount_setattr().
pub const MS_CONVERTIBLE_FLAGS: u64 = MS_RDONLY
    | MS_NOSUID
    | MS_NODEV
    | MS_NOEXEC
    | MS_NOSYMFOLLOW
    | MS_RELATIME
    | MS_NOATIME
    | MS_STRICTATIME
    | MS_NODIRATIME;

pub const MNT_DETACH: i32 = 2;
pub const UMOUNT_NOFOLLOW: i32 = 8;

// ── Types ──────────────────────────────────────────────────────────────────

/// Sub-mount information tracked during bind-mount operations.
#[derive(Debug)]
pub struct SubMount {
    /// Mount point path.
    pub path: String,
    /// Open file descriptor for the mount.
    pub mount_fd: i32,
}

impl SubMount {
    /// Takes exclusive ownership of `mount_fd`, which must either be a valid
    /// open file descriptor or a negative sentinel. The caller must not close
    /// or otherwise transfer a non-negative descriptor after constructing this
    /// value.
    pub fn new(path: String, mount_fd: i32) -> Self {
        Self { path, mount_fd }
    }
}

impl Drop for SubMount {
    fn drop(&mut self) {
        if self.mount_fd >= 0 {
            // SAFETY: mount_fd is a valid file descriptor owned exclusively by this struct.
            unsafe { libc::close(self.mount_fd) };
        }
    }
}

bitflags::bitflags! {
    /// Flags controlling mount-in-namespace operations.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MountInNamespaceFlags: u32 {
        const READ_ONLY              = 1 << 0;
        const MAKE_FILE_OR_DIRECTORY = 1 << 1;
        const IS_IMAGE               = 1 << 2;
    }
}

/// ID mapping mode for remount operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RemountIdmapping {
    /// No ID mapping.
    None = 0,
    /// Map host root to UID 0 on uidmapped fs.
    HostRoot = 1,
    /// Map from foreign UID range with host root.
    ForeignWithHostRoot = 2,
    /// Map container root to owner of bind-mounted directory.
    HostOwner = 3,
    /// Map bind-target owner to host owner.
    HostOwnerToTargetOwner = 4,
}

// ── Mount flags to string ──────────────────────────────────────────────────

struct MountFlagEntry {
    flag: u64,
    name: &'static str,
}

static MOUNT_FLAG_TABLE: &[MountFlagEntry] = &[
    MountFlagEntry {
        flag: MS_RDONLY,
        name: "MS_RDONLY",
    },
    MountFlagEntry {
        flag: MS_NOSUID,
        name: "MS_NOSUID",
    },
    MountFlagEntry {
        flag: MS_NODEV,
        name: "MS_NODEV",
    },
    MountFlagEntry {
        flag: MS_NOEXEC,
        name: "MS_NOEXEC",
    },
    MountFlagEntry {
        flag: MS_SYNCHRONOUS,
        name: "MS_SYNCHRONOUS",
    },
    MountFlagEntry {
        flag: MS_REMOUNT,
        name: "MS_REMOUNT",
    },
    MountFlagEntry {
        flag: MS_MANDLOCK,
        name: "MS_MANDLOCK",
    },
    MountFlagEntry {
        flag: MS_DIRSYNC,
        name: "MS_DIRSYNC",
    },
    MountFlagEntry {
        flag: MS_NOSYMFOLLOW,
        name: "MS_NOSYMFOLLOW",
    },
    MountFlagEntry {
        flag: MS_NOATIME,
        name: "MS_NOATIME",
    },
    MountFlagEntry {
        flag: MS_NODIRATIME,
        name: "MS_NODIRATIME",
    },
    MountFlagEntry {
        flag: MS_BIND,
        name: "MS_BIND",
    },
    MountFlagEntry {
        flag: MS_MOVE,
        name: "MS_MOVE",
    },
    MountFlagEntry {
        flag: MS_REC,
        name: "MS_REC",
    },
    MountFlagEntry {
        flag: MS_SILENT,
        name: "MS_SILENT",
    },
    MountFlagEntry {
        flag: MS_POSIXACL,
        name: "MS_POSIXACL",
    },
    MountFlagEntry {
        flag: MS_UNBINDABLE,
        name: "MS_UNBINDABLE",
    },
    MountFlagEntry {
        flag: MS_PRIVATE,
        name: "MS_PRIVATE",
    },
    MountFlagEntry {
        flag: MS_SLAVE,
        name: "MS_SLAVE",
    },
    MountFlagEntry {
        flag: MS_SHARED,
        name: "MS_SHARED",
    },
    MountFlagEntry {
        flag: MS_RELATIME,
        name: "MS_RELATIME",
    },
    MountFlagEntry {
        flag: MS_KERNMOUNT,
        name: "MS_KERNMOUNT",
    },
    MountFlagEntry {
        flag: MS_I_VERSION,
        name: "MS_I_VERSION",
    },
    MountFlagEntry {
        flag: MS_STRICTATIME,
        name: "MS_STRICTATIME",
    },
    MountFlagEntry {
        flag: MS_LAZYTIME,
        name: "MS_LAZYTIME",
    },
];

/// Convert mount flags to a human-readable pipe-separated string.
///
/// Named flags are expanded to their `MS_*` names. Any remaining
/// unknown bits are appended in hexadecimal.
pub fn mount_flags_to_string(flags: u64) -> String {
    let mut result = String::new();
    let mut remaining = flags;

    for entry in MOUNT_FLAG_TABLE {
        if flags & entry.flag != 0 {
            if !result.is_empty() {
                result.push('|');
            }
            result.push_str(entry.name);
            remaining &= !entry.flag;
        }
    }

    // Match C behavior: append hex if no names matched or unknown bits remain
    if result.is_empty() || remaining != 0 {
        if !result.is_empty() {
            result.push('|');
        }
        result.push_str(&format!("{remaining:x}"));
    }

    result
}

// ── Mount option parsing ───────────────────────────────────────────────────

struct MountOptEntry {
    name: &'static str,
    flag: u64,
    clear: bool,
    rec: bool,
}

static MOUNT_OPT_TABLE: &[MountOptEntry] = &[
    MountOptEntry {
        name: "ro",
        flag: MS_RDONLY,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "rw",
        flag: MS_RDONLY,
        clear: true,
        rec: false,
    },
    MountOptEntry {
        name: "nosuid",
        flag: MS_NOSUID,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "suid",
        flag: MS_NOSUID,
        clear: true,
        rec: false,
    },
    MountOptEntry {
        name: "nodev",
        flag: MS_NODEV,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "dev",
        flag: MS_NODEV,
        clear: true,
        rec: false,
    },
    MountOptEntry {
        name: "noexec",
        flag: MS_NOEXEC,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "exec",
        flag: MS_NOEXEC,
        clear: true,
        rec: false,
    },
    MountOptEntry {
        name: "sync",
        flag: MS_SYNCHRONOUS,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "async",
        flag: MS_SYNCHRONOUS,
        clear: true,
        rec: false,
    },
    MountOptEntry {
        name: "dirsync",
        flag: MS_DIRSYNC,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "noatime",
        flag: MS_NOATIME,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "atime",
        flag: MS_NOATIME,
        clear: true,
        rec: false,
    },
    MountOptEntry {
        name: "nodiratime",
        flag: MS_NODIRATIME,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "diratime",
        flag: MS_NODIRATIME,
        clear: true,
        rec: false,
    },
    MountOptEntry {
        name: "relatime",
        flag: MS_RELATIME,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "norelatime",
        flag: MS_RELATIME,
        clear: true,
        rec: false,
    },
    MountOptEntry {
        name: "strictatime",
        flag: MS_STRICTATIME,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "lazytime",
        flag: MS_LAZYTIME,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "nolazytime",
        flag: MS_LAZYTIME,
        clear: true,
        rec: false,
    },
    MountOptEntry {
        name: "nosymfollow",
        flag: MS_NOSYMFOLLOW,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "symfollow",
        flag: MS_NOSYMFOLLOW,
        clear: true,
        rec: false,
    },
    MountOptEntry {
        name: "silent",
        flag: MS_SILENT,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "quiet",
        flag: MS_SILENT,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "loud",
        flag: MS_SILENT,
        clear: true,
        rec: false,
    },
    MountOptEntry {
        name: "mand",
        flag: MS_MANDLOCK,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "nomand",
        flag: MS_MANDLOCK,
        clear: true,
        rec: false,
    },
    MountOptEntry {
        name: "bind",
        flag: MS_BIND,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "rbind",
        flag: MS_BIND,
        clear: false,
        rec: true,
    },
    MountOptEntry {
        name: "remount",
        flag: MS_REMOUNT,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "move",
        flag: MS_MOVE,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "private",
        flag: MS_PRIVATE,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "rprivate",
        flag: MS_PRIVATE,
        clear: false,
        rec: true,
    },
    MountOptEntry {
        name: "shared",
        flag: MS_SHARED,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "rshared",
        flag: MS_SHARED,
        clear: false,
        rec: true,
    },
    MountOptEntry {
        name: "slave",
        flag: MS_SLAVE,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "rslave",
        flag: MS_SLAVE,
        clear: false,
        rec: true,
    },
    MountOptEntry {
        name: "unbindable",
        flag: MS_UNBINDABLE,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "runbindable",
        flag: MS_UNBINDABLE,
        clear: false,
        rec: true,
    },
    MountOptEntry {
        name: "acl",
        flag: MS_POSIXACL,
        clear: false,
        rec: false,
    },
    MountOptEntry {
        name: "noacl",
        flag: MS_POSIXACL,
        clear: true,
        rec: false,
    },
];

/// Parse mount options string and merge with flag-based options.
///
/// Extracts known mount flags from the comma-separated options string,
/// and stores non-mount-flag options (excluding `x-` prefixed vendor
/// extensions) separately.
///
/// Returns `(merged_mount_flags, remaining_options)`.
/// If no non-flag options remain, `remaining_options` is `None`.
pub fn mount_option_mangle(options: Option<&str>, mount_flags: u64) -> (u64, Option<String>) {
    let options = match options {
        Some(o) => o,
        None => return (mount_flags, None),
    };

    let mut flags = mount_flags;
    let mut remaining = String::new();

    for opt in options.split(',') {
        if opt.is_empty() {
            continue;
        }

        let mut matched = false;
        for entry in MOUNT_OPT_TABLE {
            if entry.name != opt {
                continue;
            }
            matched = true;
            if entry.clear {
                flags &= !entry.flag;
            } else {
                flags |= entry.flag;
            }
            if entry.rec {
                flags |= MS_REC;
            }
            break;
        }

        // Unknown options that are not vendor extensions go to remaining
        if !matched && !opt.to_ascii_lowercase().starts_with("x-") {
            if !remaining.is_empty() {
                remaining.push(',');
            }
            remaining.push_str(opt);
        }
    }

    (
        flags,
        if remaining.is_empty() {
            None
        } else {
            Some(remaining)
        },
    )
}

// ── Mount flag helpers ─────────────────────────────────────────────────────

/// A tight set of mount flags for credentials mounts.
pub const fn credentials_fs_mount_flags(ro: bool) -> u64 {
    let mut flags = MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_NOSYMFOLLOW;
    if ro {
        flags |= MS_RDONLY;
    }
    flags
}

/// Convert MS-style flags to mount_attr set bits.
pub fn ms_flags_to_mount_attr(flags: u64) -> u64 {
    let mut attr = 0u64;
    if flags & MS_RDONLY != 0 {
        attr |= 1;
    } // MOUNT_ATTR_RDONLY
    if flags & MS_NOSUID != 0 {
        attr |= 2;
    } // MOUNT_ATTR_NOSUID
    if flags & MS_NODEV != 0 {
        attr |= 4;
    } // MOUNT_ATTR_NODEV
    if flags & MS_NOEXEC != 0 {
        attr |= 8;
    } // MOUNT_ATTR_NOEXEC
    if flags & MS_NOSYMFOLLOW != 0 {
        attr |= 1 << 7;
    } // MOUNT_ATTR_NOSYMFOLLOW
    if flags & MS_RELATIME != 0 {
        attr |= 1 << 8;
    } // MOUNT_ATTR_RELATIME
    if flags & MS_NOATIME != 0 {
        attr |= 1 << 10;
    } // MOUNT_ATTR_NOATIME
    if flags & MS_STRICTATIME != 0 {
        attr |= 1 << 11;
    } // MOUNT_ATTR_STRICTATIME
    if flags & MS_NODIRATIME != 0 {
        attr |= 1 << 12;
    } // MOUNT_ATTR_NODIRATIME
    attr
}

// ── Inaccessible node resolution ───────────────────────────────────────────

/// Convert an inode mode to a type string like `"blk"`, `"chr"`, `"reg"`.
pub fn inode_type_to_string(mode: u32) -> Option<&'static str> {
    match mode & 0o170000 {
        0o040000 => Some("dir"),
        0o100000 => Some("reg"),
        0o060000 => Some("blk"),
        0o020000 => Some("chr"),
        0o140000 => Some("sock"),
        0o010000 => Some("fifo"),
        _ => None,
    }
}

/// Map an inode type to the path of the corresponding inaccessible node.
///
/// Falls back from block → char → socket nodes if the preferred type
/// doesn't exist on this kernel.
pub fn mode_to_inaccessible_node(runtime_dir: Option<&str>, mode: u32) -> io::Result<String> {
    let runtime_dir = runtime_dir.unwrap_or("/run");

    if (mode & 0o170000) == 0o120000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "symlinks have no inaccessible node",
        ));
    }

    let node = inode_type_to_string(mode)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unknown inode type"))?;

    let mut path = format!("{runtime_dir}/systemd/inaccessible/{node}");

    // Block device not available → fall back to character device
    if (mode & 0o170000) == 0o060000 && !Path::new(&path).exists() {
        path = format!("{runtime_dir}/systemd/inaccessible/chr");
    }

    // Character/block device not available → fall back to socket
    let is_device = matches!(mode & 0o170000, 0o060000 | 0o020000);
    if is_device && !Path::new(&path).exists() {
        path = format!("{runtime_dir}/systemd/inaccessible/sock");
    }

    Ok(path)
}

// ── Mount point detection ──────────────────────────────────────────────────

/// Check if a path is a mount point by comparing device numbers.
pub fn path_is_mount_point(path: &Path) -> io::Result<bool> {
    let metadata = std::fs::metadata(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let parent_metadata = std::fs::metadata(parent)?;
    Ok(metadata.dev() != parent_metadata.dev())
}

// ── Filesystem classification ──────────────────────────────────────────────

/// Check if a filesystem type is a network filesystem.
pub fn fstype_is_network(fstype: &str) -> bool {
    matches!(
        fstype,
        "nfs"
            | "nfs4"
            | "cifs"
            | "smb"
            | "smb2"
            | "smb3"
            | "ceph"
            | "fuse.sshfs"
            | "9p"
            | "nbd"
            | "fuse.glusterfs"
            | "fuse.ctdb"
    )
}

// ── Internal helpers ───────────────────────────────────────────────────────

fn to_cstring(s: &str) -> io::Result<CString> {
    CString::new(s)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null byte"))
}

/// Open a mount target without following its final component.
///
/// This is the descriptor half of C's `mount_nofollow()`: `/proc/self/fd/N`
/// names the pinned target for the subsequent legacy `mount(2)` call. As in
/// the C implementation, symlinks in parent components are allowed, while a
/// final symlink is kept as the mount target rather than being followed.
#[cfg(target_os = "linux")]
fn open_mount_target_nofollow(target: &CString) -> io::Result<OwnedFd> {
    // SAFETY: target is a retained, NUL-terminated pathname. O_PATH avoids
    // opening FIFOs/devices for I/O; O_NOFOLLOW pins the final directory entry
    // itself, and successful open() returns a uniquely owned descriptor.
    let fd = unsafe {
        libc::open(
            target.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: open() above returned a fresh non-negative descriptor whose
    // ownership has not been transferred elsewhere.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// ── Mount/umount operations (Linux only) ───────────────────────────────────

/// Mount a filesystem.
///
/// Wraps the `mount(2)` syscall. `what` is the source, `where_` is the
/// target mount point, `fstype` is the filesystem type (e.g. `"ext4"`),
/// and `options` are filesystem-specific options.
#[cfg(target_os = "linux")]
pub fn mount_verbose_full(
    what: &str,
    where_: &str,
    fstype: Option<&str>,
    flags: u64,
    options: Option<&str>,
    follow_symlink: bool,
) -> io::Result<()> {
    mount_verbose_full_path(
        Path::new(what),
        Path::new(where_),
        fstype,
        flags,
        options,
        follow_symlink,
    )
}

/// Path-oriented form of [`mount_verbose_full`].
///
/// Linux mount paths are byte strings, not necessarily UTF-8. Keeping this
/// small boundary byte-preserving avoids making callers either lossy or
/// needlessly unable to operate on a valid mount with a non-UTF-8 name.
#[cfg(target_os = "linux")]
pub fn mount_verbose_full_path(
    what: &Path,
    where_: &Path,
    fstype: Option<&str>,
    flags: u64,
    options: Option<&str>,
    follow_symlink: bool,
) -> io::Result<()> {
    // Match mount_verbose_full(): mount-related options become flags and only
    // filesystem-specific options are passed to mount(2).
    let (flags, remaining_options) = mount_option_mangle(options, flags);
    let c_what = path_to_cstring(what)?;
    let c_where = path_to_cstring(where_)?;
    let c_fstype = fstype.map(to_cstring).transpose()?;
    let c_options = remaining_options.as_deref().map(to_cstring).transpose()?;

    let fstype_ptr = c_fstype.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
    let options_ptr = c_options
        .as_ref()
        .map_or(std::ptr::null(), |s| s.as_ptr() as *const libc::c_void);
    let target_fd = if follow_symlink {
        None
    } else {
        Some(open_mount_target_nofollow(&c_where)?)
    };
    let proc_fd_target = target_fd
        .as_ref()
        .map(|fd| to_cstring(&format!("/proc/self/fd/{}", fd.as_raw_fd())))
        .transpose()?;
    let target_ptr = proc_fd_target
        .as_ref()
        .map_or(c_where.as_ptr(), |s| s.as_ptr());

    // SAFETY: All CString pointers are valid null-terminated strings. The
    // `options_ptr` either is null or points to the retained `c_options` for
    // the duration of the call.
    // `target_fd`, when present, remains alive so its procfs path identifies
    // the pinned final target for the whole mount call.
    // SAFETY: all retained pointer arguments and the optional fd are valid.
    let ret = unsafe { libc::mount(c_what.as_ptr(), target_ptr, fstype_ptr, flags, options_ptr) };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn path_to_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

/// Mount a filesystem, following symlinks in the target path.
#[cfg(target_os = "linux")]
pub fn mount_follow_verbose(
    what: &str,
    where_: &str,
    fstype: Option<&str>,
    flags: u64,
    options: Option<&str>,
) -> io::Result<()> {
    mount_verbose_full(what, where_, fstype, flags, options, true)
}

/// Mount a filesystem without following a final target symlink.
///
/// Parent-directory symlinks retain the C implementation's normal resolution
/// semantics; the final path component is pinned through `/proc/self/fd`.
#[cfg(target_os = "linux")]
pub fn mount_nofollow_verbose(
    what: &str,
    where_: &str,
    fstype: Option<&str>,
    flags: u64,
    options: Option<&str>,
) -> io::Result<()> {
    mount_verbose_full(what, where_, fstype, flags, options, false)
}

/// Mount a filesystem without following the final target symlink, preserving
/// the byte spelling of source and target paths.
#[cfg(target_os = "linux")]
pub fn mount_nofollow_verbose_path(
    what: &Path,
    where_: &Path,
    fstype: Option<&str>,
    flags: u64,
    options: Option<&str>,
) -> io::Result<()> {
    mount_verbose_full_path(what, where_, fstype, flags, options, false)
}

/// Unmount a filesystem.
///
/// Wraps the `umount2(2)` syscall.
#[cfg(target_os = "linux")]
pub fn umount_verbose(where_: &str, flags: i32) -> io::Result<()> {
    umount_verbose_path(Path::new(where_), flags)
}

/// Unmount a filesystem while preserving a potentially non-UTF-8 path.
#[cfg(target_os = "linux")]
pub fn umount_verbose_path(where_: &Path, flags: i32) -> io::Result<()> {
    let c_where = path_to_cstring(where_)?;

    // SAFETY: c_where is a valid null-terminated string.
    let ret = unsafe { libc::umount2(c_where.as_ptr(), flags) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Repeatedly unmount a path until it fails (handles stacked mounts).
///
/// Returns `Ok(true)` if at least one mount was successfully unmounted,
/// `Ok(false)` if the path was not mounted to begin with (EINVAL on
/// first attempt).
#[cfg(target_os = "linux")]
pub fn repeat_unmount(path: &str, flags: i32) -> io::Result<bool> {
    let c_path = to_cstring(path)?;
    let mut done = false;

    loop {
        // SAFETY: c_path is a valid null-terminated string.
        let ret = unsafe { libc::umount2(c_path.as_ptr(), flags) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINVAL) {
                return Ok(done);
            }
            return Err(err);
        }
        done = true;
    }
}

/// Make a path into a mount point.
///
/// If the path is already a mount point, does nothing and returns `Ok(false)`.
/// If it is not, bind-mounts it and returns `Ok(true)`.
#[cfg(target_os = "linux")]
pub fn make_mount_point(path: &str) -> io::Result<bool> {
    if path_is_mount_point(Path::new(path))? {
        return Ok(false);
    }
    mount_nofollow_verbose(path, path, None, MS_BIND | MS_REC, None)?;
    Ok(true)
}

/// Trigger an automount by probing a nonexistent child path.
#[cfg(target_os = "linux")]
pub fn trigger_automount_at(dir_fd: i32, path: &str) -> io::Result<()> {
    let nested = format!("{path}/a");
    let c_nested = to_cstring(&nested)?;

    // SAFETY: dir_fd is a valid directory fd, c_nested is a valid path.
    // Return value is intentionally ignored — we only care about
    // the side effect of triggering automounts.
    unsafe {
        libc::faccessat(dir_fd, c_nested.as_ptr(), libc::F_OK, 0);
    }
    Ok(())
}

// ── Mountinfo parsing ──────────────────────────────────────────────────────

/// Read /proc/self/mountinfo and extract mount points under a prefix.
///
/// Returns mount point paths sorted lexicographically, excluding the
/// prefix itself.
#[cfg(target_os = "linux")]
pub fn read_mountinfo(prefix: &str) -> io::Result<Vec<String>> {
    let content = std::fs::read_to_string("/proc/self/mountinfo")?;
    let prefix_path = Path::new(prefix);

    let mut result = Vec::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // mountinfo format: mount_id parent_id major:minor root mount_point ...
        // mount_point is field index 4
        if fields.len() > 4 {
            let mount_point = fields[4];
            let mount_path = Path::new(mount_point);
            if mount_path.starts_with(prefix_path) && mount_path != prefix_path {
                result.push(mount_point.to_string());
            }
        }
    }

    result.sort();
    Ok(result)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_flags_to_string_zero() {
        assert_eq!(mount_flags_to_string(0), "0");
    }

    #[test]
    fn test_mount_flags_to_string_single() {
        assert_eq!(mount_flags_to_string(MS_RDONLY), "MS_RDONLY");
    }

    #[test]
    fn test_mount_flags_to_string_multiple() {
        let flags = MS_RDONLY | MS_NOSUID | MS_NOEXEC;
        let s = mount_flags_to_string(flags);
        assert!(s.contains("MS_RDONLY"));
        assert!(s.contains("MS_NOSUID"));
        assert!(s.contains("MS_NOEXEC"));
        assert_eq!(s.matches('|').count(), 2);
    }

    #[test]
    fn test_mount_flags_to_string_unknown_flags() {
        let flags = 0x80000000;
        let s = mount_flags_to_string(flags);
        assert_eq!(s, "80000000");
    }

    #[test]
    fn test_mount_flags_to_string_mixed() {
        let flags = MS_RDONLY | 0x80000000;
        let s = mount_flags_to_string(flags);
        assert!(s.starts_with("MS_RDONLY|"));
        assert!(s.contains("80000000"));
    }

    #[test]
    fn test_mount_option_mangle_null() {
        let (flags, remaining) = mount_option_mangle(None, MS_BIND);
        assert_eq!(flags, MS_BIND);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_mount_option_mangle_empty() {
        let (flags, remaining) = mount_option_mangle(Some(""), 0);
        assert_eq!(flags, 0);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_mount_option_mangle_ro_bind() {
        let (flags, remaining) = mount_option_mangle(Some("ro,bind"), 0);
        assert_eq!(flags, MS_RDONLY | MS_BIND);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_mount_option_mangle_rw_clears() {
        let (flags, remaining) = mount_option_mangle(Some("rw"), MS_RDONLY);
        assert_eq!(flags, 0);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_mount_option_mangle_rbind_sets_rec() {
        let (flags, remaining) = mount_option_mangle(Some("rbind"), 0);
        assert_eq!(flags, MS_BIND | MS_REC);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_mount_option_mangle_with_extra() {
        let (flags, remaining) = mount_option_mangle(Some("ro,size=1630748k"), 0);
        assert_eq!(flags, MS_RDONLY);
        let rem = remaining.unwrap();
        assert_eq!(rem, "size=1630748k");
    }

    #[test]
    fn test_mount_option_mangle_x_prefix_skipped() {
        let (flags, remaining) = mount_option_mangle(Some("ro,x-custom=42"), 0);
        assert_eq!(flags, MS_RDONLY);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_mount_option_mangle_propagation() {
        let (flags, remaining) = mount_option_mangle(Some("rshared"), 0);
        assert_eq!(flags, MS_SHARED | MS_REC);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_mount_option_mangle_conflicting() {
        // "ro" then "rw" → rw wins (last wins)
        let (flags, remaining) = mount_option_mangle(Some("ro,rw"), 0);
        assert_eq!(flags, 0);
    }

    #[test]
    fn test_inode_type_to_string() {
        assert_eq!(inode_type_to_string(0o040755), Some("dir"));
        assert_eq!(inode_type_to_string(0o100644), Some("reg"));
        assert_eq!(inode_type_to_string(0o060660), Some("blk"));
        assert_eq!(inode_type_to_string(0o020666), Some("chr"));
        assert_eq!(inode_type_to_string(0o140777), Some("sock"));
        assert_eq!(inode_type_to_string(0o010444), Some("fifo"));
        assert_eq!(inode_type_to_string(0), None);
    }

    #[test]
    fn test_mode_to_inaccessible_node_symlink_rejected() {
        let mode = 0o120777; // symlink
        let result = mode_to_inaccessible_node(None, mode);
        assert!(result.is_err());
    }

    #[test]
    fn test_mode_to_inaccessible_node_unknown_rejected() {
        let mode = 0o170000; // no valid type bits
        let result = mode_to_inaccessible_node(None, mode);
        assert!(result.is_err());
    }

    #[test]
    fn test_mode_to_inaccessible_node_dir() {
        let mode = 0o040755; // directory
        let result = mode_to_inaccessible_node(Some("/run"), mode).unwrap();
        assert_eq!(result, "/run/systemd/inaccessible/dir");
    }

    #[test]
    fn test_mode_to_inaccessible_node_custom_runtime() {
        let mode = 0o100644; // regular file
        let result = mode_to_inaccessible_node(Some("/var/run"), mode).unwrap();
        assert_eq!(result, "/var/run/systemd/inaccessible/reg");
    }

    #[test]
    fn test_mode_to_inaccessible_node_default_runtime() {
        let mode = 0o060660; // block device
        let result = mode_to_inaccessible_node(None, mode).unwrap();
        assert!(result.contains("/run/systemd/inaccessible/"));
    }

    #[test]
    fn test_fstype_is_network() {
        assert!(fstype_is_network("nfs"));
        assert!(fstype_is_network("nfs4"));
        assert!(fstype_is_network("cifs"));
        assert!(fstype_is_network("smb3"));
        assert!(fstype_is_network("ceph"));
        assert!(fstype_is_network("fuse.sshfs"));
        assert!(fstype_is_network("9p"));
        assert!(fstype_is_network("nbd"));
    }

    #[test]
    fn test_fstype_is_not_network() {
        assert!(!fstype_is_network("ext4"));
        assert!(!fstype_is_network("xfs"));
        assert!(!fstype_is_network("tmpfs"));
        assert!(!fstype_is_network("btrfs"));
        assert!(!fstype_is_network("vfat"));
    }

    #[test]
    fn test_credentials_fs_mount_flags() {
        let ro = credentials_fs_mount_flags(true);
        assert_eq!(
            ro,
            MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_NOSYMFOLLOW | MS_RDONLY
        );

        let rw = credentials_fs_mount_flags(false);
        assert_eq!(rw, MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_NOSYMFOLLOW);
    }

    #[test]
    fn test_ms_flags_to_mount_attr() {
        let attr = ms_flags_to_mount_attr(MS_RDONLY | MS_NOEXEC);
        assert_ne!(attr, 0);
        assert_ne!(attr & 1, 0); // RDON bit set
        assert_ne!(attr & 8, 0); // NOEXEC bit set
    }

    #[test]
    fn test_ms_flags_to_mount_attr_zero() {
        assert_eq!(ms_flags_to_mount_attr(0), 0);
    }

    #[test]
    fn test_mount_in_namespace_flags() {
        let f = MountInNamespaceFlags::READ_ONLY | MountInNamespaceFlags::IS_IMAGE;
        assert!(f.contains(MountInNamespaceFlags::READ_ONLY));
        assert!(f.contains(MountInNamespaceFlags::IS_IMAGE));
        assert!(!f.contains(MountInNamespaceFlags::MAKE_FILE_OR_DIRECTORY));
    }

    #[test]
    fn test_remount_idmapping_values() {
        assert_eq!(RemountIdmapping::None as i32, 0);
        assert_eq!(RemountIdmapping::HostRoot as i32, 1);
        assert_eq!(RemountIdmapping::ForeignWithHostRoot as i32, 2);
        assert_eq!(RemountIdmapping::HostOwner as i32, 3);
        assert_eq!(RemountIdmapping::HostOwnerToTargetOwner as i32, 4);
    }

    #[test]
    fn test_ms_convertible_flags() {
        // MS_BIND and MS_MOVE should NOT be in convertible flags
        assert_eq!(MS_CONVERTIBLE_FLAGS & MS_BIND, 0);
        assert_eq!(MS_CONVERTIBLE_FLAGS & MS_MOVE, 0);
        assert_ne!(MS_CONVERTIBLE_FLAGS & MS_RDONLY, 0);
        assert_ne!(MS_CONVERTIBLE_FLAGS & MS_NOSUID, 0);
    }

    #[test]
    fn test_mount_option_mangle_merge_with_existing_flags() {
        let (flags, remaining) = mount_option_mangle(Some("noexec"), MS_RDONLY | MS_NODEV);
        assert_eq!(flags, MS_RDONLY | MS_NODEV | MS_NOEXEC);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_mount_option_mangle_consecutive_commas() {
        let (flags, remaining) = mount_option_mangle(Some("ro,,bind,,"), 0);
        assert_eq!(flags, MS_RDONLY | MS_BIND);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_mount_option_mangle_x_prefix_case_insensitive() {
        let (flags, remaining) = mount_option_mangle(Some("ro,X-Custom=val"), 0);
        assert_eq!(flags, MS_RDONLY);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_sub_mount_new() {
        let sm = SubMount::new("/mnt/child".to_string(), 42);
        assert_eq!(sm.path, "/mnt/child");
        assert_eq!(sm.mount_fd, 42);
    }
}
