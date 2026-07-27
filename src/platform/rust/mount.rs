// SPDX-License-Identifier: LGPL-2.1-or-later

use std::io;

bitflags::bitflags! {
    /// Flags for the `mount()` system call.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MountFlags: u64 {
        const MS_NOSUID     = 2;
        const MS_NODEV      = 4;
        const MS_NOEXEC     = 8;
        const MS_NOATIME    = 1024;
        const MS_NOSYMFOLLOW = 8388608;
        const MS_REMOUNT    = 32;
        const MS_BIND       = 4096;
        const MS_PRIVATE    = 262144;
        const MS_SLAVE      = 524288;
        const MS_SHARED     = 1 << 20;
    }
}

/// Mount a filesystem.
#[cfg(target_os = "linux")]
pub fn mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: MountFlags,
    data: &str,
) -> io::Result<()> {
    use std::ffi::CString;
    let src = if source.is_empty() {
        None
    } else {
        Some(CString::new(source).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?)
    };
    let tgt = CString::new(target).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let fs = if fstype.is_empty() {
        None
    } else {
        Some(CString::new(fstype).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?)
    };
    let dat = if data.is_empty() {
        None
    } else {
        Some(CString::new(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?)
    };

    nix::mount::mount(
        src.as_deref(),
        tgt.as_c_str(),
        fs.as_deref(),
        nix::mount::MsFlags::from_bits_truncate(flags.bits()),
        dat.as_deref(),
    )
    .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Mount a filesystem (stub on non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn mount(
    _source: &str,
    _target: &str,
    _fstype: &str,
    _flags: MountFlags,
    _data: &str,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "mount is only available on Linux",
    ))
}

/// Unmount a filesystem.
#[cfg(target_os = "linux")]
pub fn umount(target: &str) -> io::Result<()> {
    use std::ffi::CString;
    let tgt = CString::new(target).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    nix::mount::umount(tgt.as_c_str()).map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Unmount a filesystem (stub on non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn umount(_target: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "umount is only available on Linux",
    ))
}
