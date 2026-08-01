// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/smack-util.c, src/shared/smack-util.h
//
// SMACK (Simplified Mandatory Access Control Kernel) utilities.
//
// Safe Rust abstractions for SMACK label management on Linux:
// reading/writing SMACK xattrs, fixing labels in /dev, applying
// labels to processes, MAC address to SMACK label conversion,
// and SMACK netlabel configuration.

use std::ffi::CString;
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

pub use crate::label_util::LabelFixFlags;

// ── Constants ─────────────────────────────────────────────────────────────

const SMACKFS_PATH: &str = "/sys/fs/smackfs/";

pub const SMACK_FLOOR_LABEL: &str = "_";
pub const SMACK_STAR_LABEL: &str = "*";

const XATTR_SMACK64: &[u8] = b"security.SMACK64\0";
const AT_FDCWD: i32 = -100;
const O_NOFOLLOW: i32 = 0x10000;
const O_CLOEXEC: i32 = 0x80000;
const O_PATH: i32 = 0o10000000;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmackError {
    NotAvailable,
    XattrNotSupported,
    ReadOnlyFs,
    NotInDev(PathBuf),
    NotFound(PathBuf),
    Io(io::ErrorKind, Option<i32>),
    InvalidLabel,
    InvalidFd,
}

impl std::fmt::Display for SmackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmackError::NotAvailable => write!(f, "SMACK is not available"),
            SmackError::XattrNotSupported => {
                write!(f, "filesystem does not support extended attributes")
            }
            SmackError::ReadOnlyFs => write!(f, "filesystem is read-only"),
            SmackError::NotInDev(p) => write!(f, "path '{}' is not in /dev", p.display()),
            SmackError::NotFound(p) => write!(f, "path '{}' not found", p.display()),
            SmackError::Io(kind, Some(errno)) => {
                write!(f, "I/O error ({kind:?}, errno={errno})")
            }
            SmackError::Io(kind, None) => write!(f, "I/O error ({kind:?})"),
            SmackError::InvalidLabel => write!(f, "invalid SMACK label"),
            SmackError::InvalidFd => write!(f, "invalid file descriptor"),
        }
    }
}

impl std::error::Error for SmackError {}

impl From<io::Error> for SmackError {
    fn from(e: io::Error) -> Self {
        SmackError::Io(e.kind(), e.raw_os_error())
    }
}

// ── SmackAttr enum ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmackAttr {
    Access,
    Exec,
    Mmap,
    Transmute,
    IpIn,
    IpOut,
}

impl SmackAttr {
    fn as_xattr_bytes(self) -> &'static [u8] {
        match self {
            Self::Access => b"security.SMACK64\0",
            Self::Exec => b"security.SMACK64EXEC\0",
            Self::Mmap => b"security.SMACK64MMAP\0",
            Self::Transmute => b"security.SMACK64TRANSMUTE\0",
            Self::IpIn => b"security.SMACK64IPIN\0",
            Self::IpOut => b"security.SMACK64IPOUT\0",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Access => "security.SMACK64",
            Self::Exec => "security.SMACK64EXEC",
            Self::Mmap => "security.SMACK64MMAP",
            Self::Transmute => "security.SMACK64TRANSMUTE",
            Self::IpIn => "security.SMACK64IPIN",
            Self::IpOut => "security.SMACK64IPOUT",
        }
    }
}

/// Return an xattr name as the C string pointer required by the Linux ABI.
///
/// Attribute names in this module are static NUL-terminated byte strings.
/// Keeping them as bytes avoids an allocation, while this cast preserves that
/// representation on targets where `libc::c_char` is signed.
#[cfg(target_os = "linux")]
fn xattr_name_ptr(xattr_name: &[u8]) -> *const libc::c_char {
    debug_assert_eq!(xattr_name.last(), Some(&0));
    xattr_name.as_ptr().cast()
}

// ── Availability check ───────────────────────────────────────────────────

static SMACK_USE_CACHED: AtomicI32 = AtomicI32::new(-1);

pub fn mac_smack_use() -> bool {
    let cached = SMACK_USE_CACHED.load(Ordering::Relaxed);
    if cached >= 0 {
        return cached != 0;
    }

    let available = fs::metadata(SMACKFS_PATH).is_ok();
    let value = if available { 1 } else { 0 };

    let _ = SMACK_USE_CACHED.compare_exchange(-1, value, Ordering::SeqCst, Ordering::Relaxed);

    SMACK_USE_CACHED.load(Ordering::Relaxed) != 0
}

#[cfg(test)]
fn reset_smack_use_cache() {
    SMACK_USE_CACHED.store(-1, Ordering::SeqCst);
}

// ── Read SMACK label ─────────────────────────────────────────────────────

pub fn mac_smack_read(path: &Path, attr: SmackAttr) -> Result<Option<String>, SmackError> {
    if !mac_smack_use() {
        return Ok(None);
    }
    read_xattr_path(path, attr.as_xattr_bytes())
}

pub fn mac_smack_read_fd(fd: i32, attr: SmackAttr) -> Result<Option<String>, SmackError> {
    if !mac_smack_use() {
        return Ok(None);
    }
    read_xattr_fd(fd, attr.as_xattr_bytes())
}

#[cfg(target_os = "linux")]
fn read_xattr_path(path: &Path, xattr_name: &[u8]) -> Result<Option<String>, SmackError> {
    let path_cstr =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| SmackError::InvalidLabel)?;
    // SAFETY: path_cstr and xattr_name are valid null-terminated byte strings.
    let buf_size = unsafe_ffi!({
        libc::lgetxattr(
            path_cstr.as_ptr(),
            xattr_name_ptr(xattr_name),
            std::ptr::null_mut(),
            0,
        )
    });
    if buf_size < 0 {
        let errno = std::io::Error::last_os_error();
        let code = errno.raw_os_error().unwrap_or(0);
        if code == libc::ENODATA || code == libc::ENOTSUP {
            return Ok(None);
        }
        return Err(SmackError::from(errno));
    }
    if buf_size == 0 {
        return Ok(Some(String::new()));
    }
    let mut buf = vec![0u8; buf_size as usize];
    // SAFETY: buf correctly sized, all pointers valid.
    let read = unsafe_ffi!({
        libc::lgetxattr(
            path_cstr.as_ptr(),
            xattr_name_ptr(xattr_name),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    });
    if read < 0 {
        return Err(SmackError::from(std::io::Error::last_os_error()));
    }
    Ok(Some(
        String::from_utf8_lossy(&buf[..read as usize])
            .trim_end_matches('\0')
            .to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn read_xattr_fd(fd: i32, xattr_name: &[u8]) -> Result<Option<String>, SmackError> {
    // SAFETY: xattr_name is a valid null-terminated byte string.
    let buf_size = unsafe_ffi!(libc::fgetxattr(
        fd,
        xattr_name_ptr(xattr_name),
        std::ptr::null_mut(),
        0
    ));
    if buf_size < 0 {
        let errno = std::io::Error::last_os_error();
        let code = errno.raw_os_error().unwrap_or(0);
        if code == libc::ENODATA || code == libc::ENOTSUP {
            return Ok(None);
        }
        return Err(SmackError::from(errno));
    }
    if buf_size == 0 {
        return Ok(Some(String::new()));
    }
    let mut buf = vec![0u8; buf_size as usize];
    // SAFETY: buf correctly sized, fd assumed valid.
    let read = unsafe_ffi!({
        libc::fgetxattr(
            fd,
            xattr_name_ptr(xattr_name),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    });
    if read < 0 {
        return Err(SmackError::from(std::io::Error::last_os_error()));
    }
    Ok(Some(
        String::from_utf8_lossy(&buf[..read as usize])
            .trim_end_matches('\0')
            .to_string(),
    ))
}

#[cfg(not(target_os = "linux"))]
fn read_xattr_path(_path: &Path, _xattr_name: &[u8]) -> Result<Option<String>, SmackError> {
    Err(SmackError::NotAvailable)
}

#[cfg(not(target_os = "linux"))]
fn read_xattr_fd(_fd: i32, _xattr_name: &[u8]) -> Result<Option<String>, SmackError> {
    Err(SmackError::NotAvailable)
}

// ── Apply SMACK label ────────────────────────────────────────────────────

pub fn mac_smack_apply(
    path: &Path,
    attr: SmackAttr,
    label: Option<&str>,
) -> Result<(), SmackError> {
    if !mac_smack_use() {
        return Ok(());
    }
    apply_xattr_path(path, attr.as_xattr_bytes(), label)
}

pub fn mac_smack_apply_fd(fd: i32, attr: SmackAttr, label: Option<&str>) -> Result<(), SmackError> {
    if !mac_smack_use() {
        return Ok(());
    }
    apply_xattr_fd(fd, attr.as_xattr_bytes(), label)
}

#[cfg(target_os = "linux")]
fn apply_xattr_path(path: &Path, xattr_name: &[u8], label: Option<&str>) -> Result<(), SmackError> {
    let path_cstr =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| SmackError::InvalidLabel)?;
    match label {
        Some(value) => {
            let c_label = CString::new(value).map_err(|_| SmackError::InvalidLabel)?;
            // SAFETY: `path_cstr` and `xattr_name` are NUL-terminated. `c_label`
            // points to `as_bytes().len()` initialized bytes; the CString terminator
            // is intentionally excluded because xattr values are raw bytes and C
            // passes `strlen(label)` to xsetxattr().
            // SAFETY: all raw pointers and the value length are valid for this call.
            let ret = unsafe_ffi!({
                libc::lsetxattr(
                    path_cstr.as_ptr(),
                    xattr_name_ptr(xattr_name),
                    c_label.as_ptr() as *const libc::c_void,
                    c_label.as_bytes().len(),
                    0,
                )
            });
            if ret < 0 {
                Err(SmackError::from(std::io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }
        None => {
            // SAFETY: pointers are valid.
            let ret = unsafe_ffi!(libc::lremovexattr(
                path_cstr.as_ptr(),
                xattr_name_ptr(xattr_name)
            ));
            if ret < 0 {
                Err(SmackError::from(std::io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn apply_xattr_fd(fd: i32, xattr_name: &[u8], label: Option<&str>) -> Result<(), SmackError> {
    match label {
        Some(value) => {
            let c_label = CString::new(value).map_err(|_| SmackError::InvalidLabel)?;
            // SAFETY: `fd` is passed through to the kernel. `xattr_name` is
            // NUL-terminated and `c_label` points to the initialized raw value
            // bytes, excluding its CString terminator as required by xattr(7).
            let ret = unsafe_ffi!({
                libc::fsetxattr(
                    fd,
                    xattr_name_ptr(xattr_name),
                    c_label.as_ptr() as *const libc::c_void,
                    c_label.as_bytes().len(),
                    0,
                )
            });
            if ret < 0 {
                Err(SmackError::from(std::io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }
        None => {
            // SAFETY: `fd` is passed through to the kernel and `xattr_name` is
            // a valid NUL-terminated attribute name.
            let ret = unsafe_ffi!(libc::fremovexattr(fd, xattr_name_ptr(xattr_name)));
            if ret < 0 {
                Err(SmackError::from(std::io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn apply_xattr_path(
    _path: &Path,
    _xattr_name: &[u8],
    _label: Option<&str>,
) -> Result<(), SmackError> {
    Err(SmackError::NotAvailable)
}

#[cfg(not(target_os = "linux"))]
fn apply_xattr_fd(_fd: i32, _xattr_name: &[u8], _label: Option<&str>) -> Result<(), SmackError> {
    Err(SmackError::NotAvailable)
}

// ── Apply SMACK label to process ─────────────────────────────────────────

pub fn mac_smack_apply_pid(pid: u32, label: &str) -> Result<(), SmackError> {
    if !mac_smack_use() {
        return Ok(());
    }
    let path = PathBuf::from(format!("/proc/{}/attr/current", pid));
    fs::write(&path, label).map_err(|e| {
        let code = e.raw_os_error();
        if code == Some(libc::ENOENT) {
            SmackError::NotFound(path)
        } else {
            SmackError::from(e)
        }
    })
}

// ── SMACK label fix ──────────────────────────────────────────────────────

fn label_for_file_type(mode: u32) -> Option<&'static str> {
    match mode & S_IFMT {
        S_IFDIR | S_IFCHR => Some(SMACK_STAR_LABEL),
        S_IFLNK => Some(SMACK_FLOOR_LABEL),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn smack_fix_fd_inner(fd: i32, label_path: &Path, flags: LabelFixFlags) -> Result<(), SmackError> {
    if !label_path.is_absolute() || !label_path.starts_with("/dev") {
        return Ok(());
    }

    let mut stat_buf = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat_buf` points to writable, properly aligned storage for a
    // complete stat result. The kernel reports an invalid descriptor as an
    // error without initializing that storage.
    if unsafe_ffi!(libc::fstat(fd, stat_buf.as_mut_ptr())) < 0 {
        return Err(SmackError::from(std::io::Error::last_os_error()));
    }
    // SAFETY: successful fstat(2) initialized the entire output struct.
    let stat_buf = unsafe_ffi!(stat_buf.assume_init());

    let label = match label_for_file_type(stat_buf.st_mode as u32) {
        Some(l) => l,
        None => return Ok(()),
    };

    let c_label = CString::new(label).unwrap();
    // xsetxattr_full() in the C implementation uses /proc/self/fd for O_PATH
    // descriptors, because fsetxattr(2) rejects them with EBADF. Keep that
    // behavior here: mac_smack_fix_full() deliberately opens named inodes with
    // O_PATH|O_NOFOLLOW to pin them without following a final symlink.
    // SAFETY: F_GETFL neither dereferences Rust memory nor takes ownership of
    // `fd`; every branch passes NUL-terminated attribute and path names plus
    // a live raw label slice to the kernel for the duration of this call.
    let ret = unsafe_ffi!({
        let fd_flags = libc::fcntl(fd, libc::F_GETFL);
        if fd_flags >= 0 && (fd_flags & O_PATH) != 0 {
            let proc_fd_path = CString::new(format!("/proc/self/fd/{fd}"))
                .expect("a decimal file descriptor contains no NUL bytes");
            libc::setxattr(
                proc_fd_path.as_ptr(),
                xattr_name_ptr(XATTR_SMACK64),
                c_label.as_ptr() as *const libc::c_void,
                c_label.as_bytes().len(),
                0,
            )
        } else {
            libc::fsetxattr(
                fd,
                xattr_name_ptr(XATTR_SMACK64),
                c_label.as_ptr() as *const libc::c_void,
                c_label.as_bytes().len(),
                0,
            )
        }
    });

    if ret >= 0 {
        return Ok(());
    }

    let errno = std::io::Error::last_os_error();
    let code = errno.raw_os_error().unwrap_or(0);

    if code == libc::ENOTSUP || code == libc::EOPNOTSUPP {
        return Ok(());
    }
    if code == libc::EROFS && flags.contains(LabelFixFlags::LABEL_IGNORE_EROFS) {
        return Ok(());
    }
    if let Ok(Some(old)) = read_xattr_fd(fd, SmackAttr::Access.as_xattr_bytes()) {
        if old == label {
            return Ok(());
        }
    }

    Err(SmackError::from(errno))
}

#[cfg(not(target_os = "linux"))]
fn smack_fix_fd_inner(
    _fd: i32,
    _label_path: &Path,
    _flags: LabelFixFlags,
) -> Result<(), SmackError> {
    Ok(())
}

pub fn mac_smack_fix(path: &Path, flags: LabelFixFlags) -> Result<(), SmackError> {
    mac_smack_fix_full(AT_FDCWD, Some(path), Some(path), flags)
}

pub fn mac_smack_fix_full(
    atfd: i32,
    inode_path: Option<&Path>,
    label_path: Option<&Path>,
    flags: LabelFixFlags,
) -> Result<(), SmackError> {
    if !mac_smack_use() {
        return Ok(());
    }

    if let Some(path) = inode_path {
        let path_cstr =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| SmackError::InvalidLabel)?;

        // SAFETY: path_cstr valid null-terminated, atfd assumed valid.
        let fd = unsafe_ffi!(libc::openat(
            atfd,
            path_cstr.as_ptr(),
            O_NOFOLLOW | O_CLOEXEC | O_PATH,
            0
        ));

        if fd < 0 {
            let errno = std::io::Error::last_os_error();
            let code = errno.raw_os_error().unwrap_or(0);
            if code == libc::ENOENT && flags.contains(LabelFixFlags::LABEL_IGNORE_ENOENT) {
                return Ok(());
            }
            return Err(SmackError::from(errno));
        }

        let _guard = FdGuard(fd);

        let resolved_label = match label_path {
            Some(lp) => lp.to_path_buf(),
            None => {
                if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    fd_get_path(fd)?
                }
            }
        };

        smack_fix_fd_inner(fd, &resolved_label, flags)
    } else {
        let resolved_label = match label_path {
            Some(lp) => lp.to_path_buf(),
            None => fd_get_path(atfd)?,
        };
        smack_fix_fd_inner(atfd, &resolved_label, flags)
    }
}

struct FdGuard(i32);

impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: fd is valid and owned by this guard.
            unsafe_ffi!({
                libc::close(self.0);
            })
        }
    }
}

fn fd_get_path(fd: i32) -> Result<PathBuf, SmackError> {
    let link = PathBuf::from(format!("/proc/self/fd/{}", fd));
    fs::read_link(&link).map_err(SmackError::from)
}

// ── Relabel /dev ─────────────────────────────────────────────────────────

pub fn smack_relabel_in_dev(dev_path: &Path) -> Result<(), SmackError> {
    if !mac_smack_use() {
        return Ok(());
    }
    if !dev_path.starts_with("/dev") {
        return Err(SmackError::NotInDev(dev_path.to_path_buf()));
    }
    relabel_dir_inner(dev_path)
}

fn relabel_dir_inner(dir: &Path) -> Result<(), SmackError> {
    let entries = fs::read_dir(dir).map_err(SmackError::from)?;
    for entry in entries {
        let entry = entry.map_err(SmackError::from)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(SmackError::from)?;

        let label = if file_type.is_dir() {
            Some(SMACK_STAR_LABEL)
        } else if file_type.is_symlink() {
            Some(SMACK_FLOOR_LABEL)
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                let meta = match fs::metadata(&path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if meta.file_type().is_char_device() {
                    Some(SMACK_STAR_LABEL)
                } else {
                    None
                }
            }
            #[cfg(not(unix))]
            {
                None
            }
        };

        if let Some(lbl) = label {
            let _ = mac_smack_apply(&path, SmackAttr::Access, Some(lbl));
        }

        if file_type.is_dir() {
            let _ = relabel_dir_inner(&path);
        }
    }
    Ok(())
}

// ── Rename with floor label ──────────────────────────────────────────────

pub fn rename_and_apply_smack_floor_label(from: &Path, to: &Path) -> Result<(), SmackError> {
    renameat_and_apply_smack_floor_label_inner(AT_FDCWD, from, AT_FDCWD, to)
}

fn renameat_and_apply_smack_floor_label_inner(
    fdf: i32,
    from: &Path,
    fdt: i32,
    to: &Path,
) -> Result<(), SmackError> {
    let from_cstr =
        CString::new(from.as_os_str().as_bytes()).map_err(|_| SmackError::InvalidLabel)?;
    let to_cstr = CString::new(to.as_os_str().as_bytes()).map_err(|_| SmackError::InvalidLabel)?;

    // SAFETY: all pointers are valid null-terminated byte strings.
    let ret = unsafe_ffi!(libc::renameat(
        fdf,
        from_cstr.as_ptr(),
        fdt,
        to_cstr.as_ptr()
    ));
    if ret < 0 {
        return Err(SmackError::from(std::io::Error::last_os_error()));
    }

    if mac_smack_use() {
        mac_smack_apply(to, SmackAttr::Access, Some(SMACK_FLOOR_LABEL))?;
    }

    Ok(())
}

// ── MAC address to SMACK label conversion ────────────────────────────────

pub fn mac_to_smack_label(mac: &[u8]) -> Result<String, SmackError> {
    if mac.len() != 6 {
        return Err(SmackError::InvalidLabel);
    }
    Ok(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ))
}

pub fn smack_label_to_mac(s: &str) -> Result<[u8; 6], SmackError> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        return Err(SmackError::InvalidLabel);
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| SmackError::InvalidLabel)?;
    }
    Ok(mac)
}

pub fn is_valid_smack_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 255
        && label.bytes().all(|b| b >= 0x20 && b <= 0x7e && b != b'/')
}

// ── SMACK netlabel configuration ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmackNetDirection {
    IpIn,
    IpOut,
}

pub fn smack_netlabel_set_port(
    port: u16,
    label: &str,
    direction: SmackNetDirection,
) -> Result<(), SmackError> {
    if !mac_smack_use() {
        return Err(SmackError::NotAvailable);
    }
    let filename = match direction {
        SmackNetDirection::IpIn => format!("ip-in/{}", port),
        SmackNetDirection::IpOut => format!("ip-out/{}", port),
    };
    let path = PathBuf::from(SMACKFS_PATH).join(&filename);
    fs::write(&path, label).map_err(SmackError::from)
}

pub fn smack_netlabel_remove_port(
    port: u16,
    direction: SmackNetDirection,
) -> Result<(), SmackError> {
    if !mac_smack_use() {
        return Err(SmackError::NotAvailable);
    }
    let filename = match direction {
        SmackNetDirection::IpIn => format!("ip-in/{}", port),
        SmackNetDirection::IpOut => format!("ip-out/{}", port),
    };
    let path = PathBuf::from(SMACKFS_PATH).join(&filename);
    fs::remove_file(&path).map_err(SmackError::from)
}

// ── Label operations ─────────────────────────────────────────────────────

pub fn smack_label_post(dir_fd: i32, path: &Path, created: bool) -> Result<(), SmackError> {
    if !created {
        return Ok(());
    }
    mac_smack_fix_full(dir_fd, Some(path), None, LabelFixFlags::empty())
}

pub fn smack_label_pre(_dir_fd: i32, _path: &Path) -> Result<(), SmackError> {
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smack_floor_and_star_labels() {
        assert_eq!(SMACK_FLOOR_LABEL, "_");
        assert_eq!(SMACK_STAR_LABEL, "*");
        assert!(!SMACK_FLOOR_LABEL.is_empty());
        assert!(!SMACK_STAR_LABEL.is_empty());
    }

    #[test]
    fn test_smack_attr_as_str() {
        assert_eq!(SmackAttr::Access.as_str(), "security.SMACK64");
        assert_eq!(SmackAttr::Exec.as_str(), "security.SMACK64EXEC");
        assert_eq!(SmackAttr::Mmap.as_str(), "security.SMACK64MMAP");
        assert_eq!(SmackAttr::Transmute.as_str(), "security.SMACK64TRANSMUTE");
        assert_eq!(SmackAttr::IpIn.as_str(), "security.SMACK64IPIN");
        assert_eq!(SmackAttr::IpOut.as_str(), "security.SMACK64IPOUT");
    }

    #[test]
    fn test_smack_attr_xattr_bytes_null_terminated() {
        for attr in [
            SmackAttr::Access,
            SmackAttr::Exec,
            SmackAttr::Mmap,
            SmackAttr::Transmute,
            SmackAttr::IpIn,
            SmackAttr::IpOut,
        ] {
            let bytes = attr.as_xattr_bytes();
            assert!(bytes.ends_with(b"\0"));
            assert!(bytes.len() > 1);
        }
    }

    #[test]
    fn test_smack_attr_str_matches_bytes() {
        for attr in [
            SmackAttr::Access,
            SmackAttr::Exec,
            SmackAttr::Mmap,
            SmackAttr::Transmute,
            SmackAttr::IpIn,
            SmackAttr::IpOut,
        ] {
            let s = attr.as_str();
            let bytes = attr.as_xattr_bytes();
            assert_eq!(s.as_bytes(), &bytes[..bytes.len() - 1]);
        }
    }

    #[test]
    fn test_mac_smack_use_caching() {
        reset_smack_use_cache();
        let result1 = mac_smack_use();
        let result2 = mac_smack_use();
        assert_eq!(result1, result2);
        let cached = SMACK_USE_CACHED.load(Ordering::Relaxed);
        assert!(cached == 0 || cached == 1);
    }

    #[test]
    fn test_mac_smack_use_returns_bool() {
        let result = mac_smack_use();
        assert!(result || !result);
    }

    #[test]
    fn test_label_for_file_type() {
        assert_eq!(label_for_file_type(S_IFDIR), Some(SMACK_STAR_LABEL));
        assert_eq!(label_for_file_type(S_IFCHR), Some(SMACK_STAR_LABEL));
        assert_eq!(label_for_file_type(S_IFLNK), Some(SMACK_FLOOR_LABEL));
        assert_eq!(label_for_file_type(0o100000), None);
        assert_eq!(label_for_file_type(0o060000), None);
        assert_eq!(label_for_file_type(0o010000), None);
    }

    #[test]
    fn test_mac_to_smack_label_valid() {
        assert_eq!(
            mac_to_smack_label(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).unwrap(),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            mac_to_smack_label(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap(),
            "00:00:00:00:00:00"
        );
        assert_eq!(
            mac_to_smack_label(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap(),
            "ff:ff:ff:ff:ff:ff"
        );
    }

    #[test]
    fn test_mac_to_smack_label_invalid_length() {
        assert!(mac_to_smack_label(&[0xaa; 5]).is_err());
        assert!(mac_to_smack_label(&[0xaa; 7]).is_err());
        assert!(mac_to_smack_label(&[]).is_err());
    }

    #[test]
    fn test_smack_label_to_mac_valid() {
        assert_eq!(
            smack_label_to_mac("aa:bb:cc:dd:ee:ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert_eq!(
            smack_label_to_mac("AA:BB:CC:DD:EE:FF").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert_eq!(
            smack_label_to_mac("AA-BB-CC-DD-EE-FF").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn test_smack_label_to_mac_invalid() {
        assert!(smack_label_to_mac("not-a-mac").is_err());
        assert!(smack_label_to_mac("aa:bb:cc").is_err());
        assert!(smack_label_to_mac("").is_err());
    }

    #[test]
    fn test_mac_roundtrip() {
        let original = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let label = mac_to_smack_label(&original).unwrap();
        let recovered = smack_label_to_mac(&label).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_is_valid_smack_label() {
        assert!(is_valid_smack_label("System"));
        assert!(is_valid_smack_label("*"));
        assert!(is_valid_smack_label("_"));
        assert!(is_valid_smack_label("User_Token"));
        assert!(is_valid_smack_label("abc123"));
        assert!(is_valid_smack_label("A B C"));

        assert!(!is_valid_smack_label(""));
        assert!(!is_valid_smack_label("a/b"));
    }

    #[test]
    fn test_is_valid_smack_label_max_length() {
        assert!(is_valid_smack_label(&"a".repeat(255)));
        assert!(!is_valid_smack_label(&"a".repeat(256)));
    }

    #[test]
    fn test_smack_error_display() {
        assert!(!SmackError::NotAvailable.to_string().is_empty());
        assert!(
            SmackError::NotInDev(PathBuf::from("/tmp/foo"))
                .to_string()
                .contains("/tmp/foo")
        );
        assert!(
            SmackError::NotFound(PathBuf::from("/dev/null2"))
                .to_string()
                .contains("/dev/null2")
        );
        assert!(!SmackError::InvalidLabel.to_string().is_empty());
    }

    #[test]
    fn test_smack_label_pre_noop() {
        assert!(smack_label_pre(0, Path::new("/dev/null")).is_ok());
    }

    #[test]
    fn test_smack_net_direction() {
        assert_ne!(SmackNetDirection::IpIn, SmackNetDirection::IpOut);
    }

    #[test]
    fn test_smack_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "perm denied");
        let smack_err: SmackError = io_err.into();
        match smack_err {
            SmackError::Io(kind, _) => assert_eq!(kind, io::ErrorKind::PermissionDenied),
            _ => panic!("expected Io variant"),
        }
    }

    #[test]
    fn test_label_fix_flags_compat() {
        assert_eq!(LabelFixFlags::LABEL_IGNORE_ENOENT.bits(), 1);
        assert_eq!(LabelFixFlags::LABEL_IGNORE_EROFS.bits(), 2);
    }
}
