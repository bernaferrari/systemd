// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/resize-fs.c, src/shared/resize-fs.h,
//            src/include/uapi/linux/btrfs.h, src/include/override/linux/xfs.h
//
// Filesystem resize utilities for ext4, btrfs, and xfs.
//
// Provides safe wrappers around filesystem-resize ioctls. `unsafe` is
// confined to the ioctl / fstatfs syscall wrappers; all public APIs
// return `Result<T, ResizeFsError>`.

use std::fs::File;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::unix::io::AsRawFd;

// ── Filesystem magic numbers (linux/magic.h) ───────────────────────────────

/// ext2/ext3/ext4 superblock magic.
pub const EXT4_SUPER_MAGIC: u64 = 0xEF53;
/// Btrfs superblock magic.
pub const BTRFS_SUPER_MAGIC: u64 = 0x9123_683E;
/// XFS superblock magic.
pub const XFS_SUPER_MAGIC: u64 = 0x5846_5342;

// ── Minimum filesystem sizes ────────────────────────────────────────────────

/// Minimum size for ext4 resize (32 MiB).
pub const EXT4_MINIMAL_SIZE: u64 = 32 * 1024 * 1024;
/// Minimum size for btrfs resize (256 MiB, enforced by kernel).
pub const BTRFS_MINIMAL_SIZE: u64 = 256 * 1024 * 1024;
/// Minimum size for XFS resize (300 MiB).
pub const XFS_MINIMAL_SIZE: u64 = 300 * 1024 * 1024;

// ── Ioctl request codes ─────────────────────────────────────────────────────

// Linux `_IOC` encoding, from `linux/ioctl.h`.
const IOC_NRSHIFT: libc::c_ulong = 0;
const IOC_TYPESHIFT: libc::c_ulong = 8;
const IOC_SIZESHIFT: libc::c_ulong = 16;
const IOC_DIRSHIFT: libc::c_ulong = 30;
const IOC_WRITE: libc::c_ulong = 1;
const IOC_READ: libc::c_ulong = 2;

const fn ioc_request(
    direction: libc::c_ulong,
    ioctl_type: u8,
    number: u8,
    size: usize,
) -> libc::c_ulong {
    (direction << IOC_DIRSHIFT)
        | ((size as libc::c_ulong) << IOC_SIZESHIFT)
        | ((ioctl_type as libc::c_ulong) << IOC_TYPESHIFT)
        | ((number as libc::c_ulong) << IOC_NRSHIFT)
}

// ── Kernel ioctl structs (repr(C) for FFI) ─────────────────────────────────

/// `xfs_fsop_geom_t` — XFS filesystem geometry.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct XfsFsopGeom {
    blocksize: u32,
    rtextsize: u32,
    agblocks: u32,
    agcount: u32,
    logblocks: u32,
    sectsize: u32,
    inodesize: u32,
    imaxpct: u32,
    datablocks: u64,
    rtblocks: u64,
    rtextents: u64,
    logstart: u64,
    uuid: [u8; 16],
    sunit: u32,
    swidth: u32,
    version: i32,
    flags: u32,
    logsectsize: u32,
    rtsectsize: u32,
    dirblocksize: u32,
    logsunit: u32,
}

/// `xfs_growfs_data_t` — XFS growfs data space parameters.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct XfsGrowfsData {
    newblocks: u64,
    imaxpct: u32,
}

/// `btrfs_ioctl_vol_args` — Btrfs resize ioctl argument.
/// `name` carries the target size as a decimal string.
#[repr(C)]
struct BtrfsIoctlVolArgs {
    fd: i64,
    name: [libc::c_char; BTRFS_VOL_ARGS_NAME_LEN],
}

/// Size of the `name` field in `btrfs_ioctl_vol_args`.
const BTRFS_VOL_ARGS_NAME_LEN: usize = 4088;

// EXT4_IOC_RESIZE_FS — `_IOW('f', 16, __u64)`.
const EXT4_IOC_RESIZE_FS: libc::c_ulong = ioc_request(IOC_WRITE, b'f', 16, size_of::<u64>());
// BTRFS_IOC_RESIZE — `_IOW(BTRFS_IOCTL_MAGIC, 3, struct btrfs_ioctl_vol_args)`.
const BTRFS_IOC_RESIZE: libc::c_ulong =
    ioc_request(IOC_WRITE, 0x94, 3, size_of::<BtrfsIoctlVolArgs>());
// XFS_IOC_FSGEOMETRY — `_IOR('X', 124, struct xfs_fsop_geom)`.
const XFS_IOC_FSGEOMETRY: libc::c_ulong =
    ioc_request(IOC_READ, b'X', 124, size_of::<XfsFsopGeom>());
// XFS_IOC_FSGROWFSDATA — `_IOW('X', 110, struct xfs_growfs_data)`.
const XFS_IOC_FSGROWFSDATA: libc::c_ulong =
    ioc_request(IOC_WRITE, b'X', 110, size_of::<XfsGrowfsData>());

// Keep the Rust ioctl mirrors tied to the checked-in Linux UAPI headers even
// when the runtime-only tests are not executed.
const _: [(); 4096] = [(); size_of::<BtrfsIoctlVolArgs>()];
const _: [(); 0] = [(); std::mem::offset_of!(BtrfsIoctlVolArgs, fd)];
const _: [(); 8] = [(); std::mem::offset_of!(BtrfsIoctlVolArgs, name)];
const _: [(); 0x5000_9403] = [(); BTRFS_IOC_RESIZE as usize];
const _: [(); 112] = [(); size_of::<XfsFsopGeom>()];
const _: [(); 32] = [(); std::mem::offset_of!(XfsFsopGeom, datablocks)];
const _: [(); 64] = [(); std::mem::offset_of!(XfsFsopGeom, uuid)];
const _: [(); 80] = [(); std::mem::offset_of!(XfsFsopGeom, sunit)];
const _: [(); 108] = [(); std::mem::offset_of!(XfsFsopGeom, logsunit)];
const _: [(); 0x8070_587c] = [(); XFS_IOC_FSGEOMETRY as usize];
const _: [(); 0] = [(); std::mem::offset_of!(XfsGrowfsData, newblocks)];
const _: [(); 8] = [(); std::mem::offset_of!(XfsGrowfsData, imaxpct)];

#[cfg(target_pointer_width = "64")]
const _: [(); 16] = [(); size_of::<XfsGrowfsData>()];
#[cfg(target_pointer_width = "64")]
const _: [(); 0x4010_586e] = [(); XFS_IOC_FSGROWFSDATA as usize];

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors returned by filesystem-resize operations.
#[derive(Debug)]
pub enum ResizeFsError {
    /// Requested size is zero, `u64::MAX`, or below the filesystem minimum.
    OutOfRange,
    /// The filesystem type on the given fd is not supported for resizing.
    NotSupported,
    /// An I/O or syscall error occurred (fstatfs / ioctl).
    Io(io::Error),
}

impl std::fmt::Display for ResizeFsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResizeFsError::OutOfRange => write!(f, "requested size is out of valid range"),
            ResizeFsError::NotSupported => write!(f, "filesystem type not supported for resize"),
            ResizeFsError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ResizeFsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ResizeFsError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ResizeFsError {
    fn from(e: io::Error) -> Self {
        ResizeFsError::Io(e)
    }
}

// ── Filesystem type detection ───────────────────────────────────────────────

/// Filesystem attributes used by the resize ioctls.
struct FsInfo {
    magic: libc::c_long,
    block_size: u64,
}

/// Reads the filesystem type and block size via one `fstatfs(2)` call.
fn fs_info(fd: i32) -> io::Result<FsInfo> {
    let mut statfs_buf = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: statfs_buf provides valid writable storage for fstatfs(). On success, fstatfs()
    // initializes the complete struct before it is read below.
    let rc = unsafe { libc::fstatfs(fd, statfs_buf.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the successful fstatfs() call above initialized statfs_buf.
    let statfs_buf = unsafe { statfs_buf.assume_init() };
    Ok(FsInfo {
        magic: statfs_buf.f_type as libc::c_long,
        block_size: statfs_buf.f_bsize as u64,
    })
}

// ── Raw ioctl helpers (unsafe, syscall wrappers) ────────────────────────────

/// Wrapper around `ioctl(fd, EXT4_IOC_RESIZE_FS, &block_count)`.
fn ioctl_ext4_resize(fd: i32, block_count: &mut u64) -> io::Result<()> {
    // SAFETY: block_count is a live writable u64 for the duration of ioctl().
    let rc = unsafe { libc::ioctl(fd, EXT4_IOC_RESIZE_FS, block_count) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wrapper around `ioctl(fd, BTRFS_IOC_RESIZE, &args)`.
fn ioctl_btrfs_resize(fd: i32, args: &BtrfsIoctlVolArgs) -> io::Result<()> {
    // SAFETY: args is a live properly aligned BtrfsIoctlVolArgs for the duration of ioctl().
    let rc = unsafe { libc::ioctl(fd, BTRFS_IOC_RESIZE, args) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wrapper around `ioctl(fd, XFS_IOC_FSGEOMETRY, &geo)`.
fn ioctl_xfs_geometry(fd: i32, geo: &mut XfsFsopGeom) -> io::Result<()> {
    // SAFETY: geo is a live writable XfsFsopGeom for the duration of ioctl().
    let rc = unsafe { libc::ioctl(fd, XFS_IOC_FSGEOMETRY, geo) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wrapper around `ioctl(fd, XFS_IOC_FSGROWFSDATA, &data)`.
fn ioctl_xfs_growfs(fd: i32, data: &mut XfsGrowfsData) -> io::Result<()> {
    // SAFETY: data is a live writable XfsGrowfsData for the duration of ioctl().
    let rc = unsafe { libc::ioctl(fd, XFS_IOC_FSGROWFSDATA, data) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ── Per-FS resize helpers ───────────────────────────────────────────────────

/// Resize an ext4 filesystem. Rounds `sz` down to the block size.
/// Returns the actual size after rounding.
fn resize_ext4(fd: i32, sz: u64, block_size: u64) -> io::Result<u64> {
    let mut block_count = sz / block_size;
    ioctl_ext4_resize(fd, &mut block_count)?;
    Ok(block_count * block_size)
}

/// Resize a btrfs filesystem. Rounds `sz` down to the block size.
/// Returns the actual size after rounding.
fn resize_btrfs(fd: i32, sz: u64, block_size: u64) -> io::Result<u64> {
    let actual_sz = sz - (sz % block_size);

    let mut args = BtrfsIoctlVolArgs {
        fd: 0,
        name: [0; BTRFS_VOL_ARGS_NAME_LEN],
    };
    let sz_str = format!("{actual_sz}");
    let bytes = sz_str.as_bytes();
    let copy_len = bytes.len().min(BTRFS_VOL_ARGS_NAME_LEN - 1);
    for (i, &b) in bytes[..copy_len].iter().enumerate() {
        args.name[i] = b as libc::c_char;
    }
    ioctl_btrfs_resize(fd, &args)?;
    Ok(actual_sz)
}

/// Resize an XFS filesystem. Returns the actual size after block-size rounding.
fn resize_xfs(fd: i32, sz: u64) -> io::Result<u64> {
    let mut geo = XfsFsopGeom::default();
    ioctl_xfs_geometry(fd, &mut geo)?;

    let blocksize = geo.blocksize as u64;
    let mut data = XfsGrowfsData {
        imaxpct: geo.imaxpct,
        newblocks: sz / blocksize,
        ..Default::default()
    };
    ioctl_xfs_growfs(fd, &mut data)?;
    Ok(data.newblocks * blocksize)
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Resize the filesystem opened on `file` to approximately `sz` bytes.
///
/// The size is rounded down to the filesystem's native block size. On
/// success, returns the actual size (after rounding) that the filesystem
/// was resized to.
///
/// # Errors
///
/// * `ResizeFsError::OutOfRange` — `sz` is 0, `u64::MAX`, or below the
///   filesystem's minimum resize size.
/// * `ResizeFsError::NotSupported` — the filesystem type is not ext4,
///   btrfs, or xfs.
/// * `ResizeFsError::Io` — an underlying syscall (fstatfs, ioctl) failed.
pub fn resize_fs(file: &File, sz: u64) -> Result<u64, ResizeFsError> {
    if sz == 0 || sz == u64::MAX {
        return Err(ResizeFsError::OutOfRange);
    }

    let fd = file.as_raw_fd();
    let fs_info = fs_info(fd)?;

    let actual_size = match fs_info.magic {
        magic if magic == EXT4_SUPER_MAGIC as libc::c_long => {
            if sz < EXT4_MINIMAL_SIZE {
                return Err(ResizeFsError::OutOfRange);
            }
            resize_ext4(fd, sz, fs_info.block_size)?
        }
        magic if magic == BTRFS_SUPER_MAGIC as libc::c_long => {
            if sz < BTRFS_MINIMAL_SIZE {
                return Err(ResizeFsError::OutOfRange);
            }
            resize_btrfs(fd, sz, fs_info.block_size)?
        }
        magic if magic == XFS_SUPER_MAGIC as libc::c_long => {
            if sz < XFS_MINIMAL_SIZE {
                return Err(ResizeFsError::OutOfRange);
            }
            resize_xfs(fd, sz)?
        }
        _ => return Err(ResizeFsError::NotSupported),
    };

    Ok(actual_size)
}

/// Returns the minimum resize size for a filesystem identified by its
/// magic number, or `None` if the filesystem type is not recognised.
pub fn minimal_size_by_fs_magic(magic: u64) -> Option<u64> {
    match magic {
        EXT4_SUPER_MAGIC => Some(EXT4_MINIMAL_SIZE),
        BTRFS_SUPER_MAGIC => Some(BTRFS_MINIMAL_SIZE),
        XFS_SUPER_MAGIC => Some(XFS_MINIMAL_SIZE),
        _ => None,
    }
}

/// Returns the minimum resize size for a filesystem identified by name
/// (e.g. `"ext4"`, `"xfs"`, `"btrfs"`), or `None` if the name is not
/// recognised.
pub fn minimal_size_by_fs_name(name: &str) -> Option<u64> {
    match name {
        "ext4" => Some(EXT4_MINIMAL_SIZE),
        "xfs" => Some(XFS_MINIMAL_SIZE),
        "btrfs" => Some(BTRFS_MINIMAL_SIZE),
        _ => None,
    }
}

/// Returns `true` for the only filesystem type that can online shrink
/// *and* grow (btrfs).
pub fn fs_can_online_shrink_and_grow(magic: u64) -> bool {
    magic == BTRFS_SUPER_MAGIC
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    // ── minimal_size_by_fs_magic ─────────────────────────────────────────

    #[test]
    fn test_minimal_size_ext4_magic() {
        assert_eq!(
            minimal_size_by_fs_magic(EXT4_SUPER_MAGIC),
            Some(EXT4_MINIMAL_SIZE)
        );
    }

    #[test]
    fn test_minimal_size_btrfs_magic() {
        assert_eq!(
            minimal_size_by_fs_magic(BTRFS_SUPER_MAGIC),
            Some(BTRFS_MINIMAL_SIZE)
        );
    }

    #[test]
    fn test_minimal_size_xfs_magic() {
        assert_eq!(
            minimal_size_by_fs_magic(XFS_SUPER_MAGIC),
            Some(XFS_MINIMAL_SIZE)
        );
    }

    #[test]
    fn test_minimal_size_unknown_magic() {
        assert_eq!(minimal_size_by_fs_magic(0), None);
        assert_eq!(minimal_size_by_fs_magic(u64::MAX), None);
        assert_eq!(minimal_size_by_fs_magic(0xDEAD_BEEF), None);
    }

    // ── minimal_size_by_fs_name ──────────────────────────────────────────

    #[test]
    fn test_minimal_size_ext4_name() {
        assert_eq!(minimal_size_by_fs_name("ext4"), Some(EXT4_MINIMAL_SIZE));
    }

    #[test]
    fn test_minimal_size_btrfs_name() {
        assert_eq!(minimal_size_by_fs_name("btrfs"), Some(BTRFS_MINIMAL_SIZE));
    }

    #[test]
    fn test_minimal_size_xfs_name() {
        assert_eq!(minimal_size_by_fs_name("xfs"), Some(XFS_MINIMAL_SIZE));
    }

    #[test]
    fn test_minimal_size_unknown_name() {
        assert_eq!(minimal_size_by_fs_name("ext3"), None);
        assert_eq!(minimal_size_by_fs_name("ntfs"), None);
        assert_eq!(minimal_size_by_fs_name(""), None);
        assert_eq!(minimal_size_by_fs_name("EXT4"), None); // case-sensitive
    }

    // ── fs_can_online_shrink_and_grow ────────────────────────────────────

    #[test]
    fn test_btrfs_can_shrink_and_grow() {
        assert!(fs_can_online_shrink_and_grow(BTRFS_SUPER_MAGIC));
    }

    #[test]
    fn test_ext4_cannot_shrink_and_grow() {
        assert!(!fs_can_online_shrink_and_grow(EXT4_SUPER_MAGIC));
    }

    #[test]
    fn test_xfs_cannot_shrink_and_grow() {
        assert!(!fs_can_online_shrink_and_grow(XFS_SUPER_MAGIC));
    }

    #[test]
    fn test_unknown_cannot_shrink_and_grow() {
        assert!(!fs_can_online_shrink_and_grow(0));
        assert!(!fs_can_online_shrink_and_grow(u64::MAX));
    }

    // ── resize_fs: argument validation (uses /dev/null which is not a
    //    block device, so we only test the pre-ioctl validation path) ────

    #[test]
    fn test_resize_fs_zero_size() {
        let file = File::open("/dev/null").unwrap();
        let err = resize_fs(&file, 0).unwrap_err();
        assert!(matches!(err, ResizeFsError::OutOfRange));
    }

    #[test]
    fn test_resize_fs_max_size() {
        let file = File::open("/dev/null").unwrap();
        let err = resize_fs(&file, u64::MAX).unwrap_err();
        assert!(matches!(err, ResizeFsError::OutOfRange));
    }

    // ── Constants ────────────────────────────────────────────────────────

    #[test]
    fn test_magic_values() {
        assert_eq!(EXT4_SUPER_MAGIC, 0xEF53);
        assert_eq!(BTRFS_SUPER_MAGIC, 0x9123_683E);
        assert_eq!(XFS_SUPER_MAGIC, 0x5846_5342);
    }

    #[test]
    fn test_minimal_size_values() {
        assert_eq!(EXT4_MINIMAL_SIZE, 32 * 1024 * 1024);
        assert_eq!(BTRFS_MINIMAL_SIZE, 256 * 1024 * 1024);
        assert_eq!(XFS_MINIMAL_SIZE, 300 * 1024 * 1024);
    }

    #[test]
    fn test_ext4_min_smaller_than_xfs_min() {
        assert!(EXT4_MINIMAL_SIZE < XFS_MINIMAL_SIZE);
    }

    #[test]
    fn test_btrfs_vol_args_name_len() {
        // Must be at least long enough to hold the string representation
        // of any u64 value (max 20 digits for u64::MAX = 18446744073709551615).
        assert!(BTRFS_VOL_ARGS_NAME_LEN >= 20);
    }

    #[test]
    fn test_ioctl_abi_matches_linux_headers() {
        assert_eq!(size_of::<BtrfsIoctlVolArgs>(), 4096);
        assert_eq!(std::mem::offset_of!(BtrfsIoctlVolArgs, fd), 0);
        assert_eq!(std::mem::offset_of!(BtrfsIoctlVolArgs, name), 8);
        assert_eq!(BTRFS_IOC_RESIZE, 0x5000_9403);

        assert_eq!(size_of::<XfsFsopGeom>(), 112);
        assert_eq!(std::mem::offset_of!(XfsFsopGeom, datablocks), 32);
        assert_eq!(std::mem::offset_of!(XfsFsopGeom, uuid), 64);
        assert_eq!(std::mem::offset_of!(XfsFsopGeom, sunit), 80);
        assert_eq!(std::mem::offset_of!(XfsFsopGeom, logsunit), 108);
        assert_eq!(XFS_IOC_FSGEOMETRY, 0x8070_587c);

        assert_eq!(std::mem::offset_of!(XfsGrowfsData, newblocks), 0);
        assert_eq!(std::mem::offset_of!(XfsGrowfsData, imaxpct), 8);
        assert_eq!(
            XFS_IOC_FSGROWFSDATA,
            ioc_request(IOC_WRITE, b'X', 110, size_of::<XfsGrowfsData>())
        );

        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(size_of::<XfsGrowfsData>(), 16);
            assert_eq!(XFS_IOC_FSGROWFSDATA, 0x4010_586e);
        }
    }

    // ── Error display ────────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = ResizeFsError::OutOfRange;
        assert!(!e.to_string().is_empty());

        let e = ResizeFsError::NotSupported;
        assert!(!e.to_string().is_empty());

        let e = ResizeFsError::Io(io::Error::new(io::ErrorKind::NotFound, "test"));
        assert!(e.to_string().contains("test"));
    }

    #[test]
    fn test_error_source() {
        let e = ResizeFsError::OutOfRange;
        assert!(e.source().is_none());

        let io_err = io::Error::new(io::ErrorKind::NotFound, "not found");
        let e = ResizeFsError::Io(io_err);
        assert!(e.source().is_some());
    }
}
