// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/hibernate-util.c, src/shared/hibernate-util.h
//
// Hibernation device discovery, resume configuration, and safety checks.
//
// Replaces the C FFI stubs with idiomatic safe Rust. `unsafe` is confined
// to the `FS_IOC_FIEMAP` ioctl in `read_fiemap` and raw fd accessors.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use crate::ffi::Errno;

// ── Constants ─────────────────────────────────────────────────────────────

const HIBERNATION_SWAP_THRESHOLD: f64 = 0.98;

const SYS_POWER_RESUME: &str = "/sys/power/resume";
const SYS_POWER_RESUME_OFFSET: &str = "/sys/power/resume_offset";
const PROC_SWAPS: &str = "/proc/swaps";
const PROC_MEMINFO: &str = "/proc/meminfo";
const PROC_CMDLINE: &str = "/proc/cmdline";
const ENV_BYPASS_HIBERNATION_MEMORY_CHECK: &str = "SYSTEMD_BYPASS_HIBERNATION_MEMORY_CHECK";
const DELETED_SWAP_SUFFIX: &str = "\\040(deleted)";
const FS_IOC_FIEMAP: u64 = 0xC020660B;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by hibernation utility operations.
#[derive(Debug)]
pub enum HibernateError {
    Errno(Errno),
    NotARegularFile,
    NotABlockDevice,
    NoBlockDevice,
    UnsupportedMedium,
    NoResumeSet,
    OffsetWithoutDevice,
    NoSwapSpace,
    ResumeDeviceNotFound,
    NotEfiAndNoResume,
    NotEnoughSwap,
    ParseError(String),
    InvalidDevnum(String),
    Io(io::Error),
}

impl HibernateError {
    pub fn from_io(err: io::Error) -> Self {
        let raw = err.raw_os_error().unwrap_or(libc::EIO);
        match Errno_from_raw(raw) {
            Some(e) => HibernateError::Errno(e),
            None => HibernateError::Errno(Errno::EIO),
        }
    }

    pub fn errno(&self) -> Option<Errno> {
        match self {
            HibernateError::Errno(e) => Some(*e),
            _ => None,
        }
    }
}

impl std::fmt::Display for HibernateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HibernateError::Errno(e) => write!(f, "hibernate error: errno {:?}", e),
            HibernateError::NotARegularFile => write!(f, "not a regular file"),
            HibernateError::NotABlockDevice => write!(f, "not a block device"),
            HibernateError::NoBlockDevice => write!(f, "no backing block device"),
            HibernateError::UnsupportedMedium => {
                write!(f, "unsupported medium type for swap file resume")
            }
            HibernateError::NoResumeSet => {
                write!(f, "'noresume' kernel command line option is set")
            }
            HibernateError::OffsetWithoutDevice => {
                write!(f, "resume_offset set but resume device is zero")
            }
            HibernateError::NoSwapSpace => write!(f, "no swap space available"),
            HibernateError::ResumeDeviceNotFound => {
                write!(f, "resume device not found in swap entries")
            }
            HibernateError::NotEfiAndNoResume => {
                write!(f, "not running on EFI and resume= is not set")
            }
            HibernateError::NotEnoughSwap => write!(f, "not enough swap space"),
            HibernateError::ParseError(s) => write!(f, "parse error: {}", s),
            HibernateError::InvalidDevnum(s) => {
                write!(f, "invalid device number: {}", s)
            }
            HibernateError::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for HibernateError {}

impl From<io::Error> for HibernateError {
    fn from(err: io::Error) -> Self {
        HibernateError::from_io(err)
    }
}

impl From<Errno> for HibernateError {
    fn from(e: Errno) -> Self {
        HibernateError::Errno(e)
    }
}

fn Errno_from_raw(raw: i32) -> Option<Errno> {
    match raw {
        1 => Some(Errno::EPERM),
        2 => Some(Errno::ENOENT),
        5 => Some(Errno::EIO),
        6 => Some(Errno::ENXIO),
        9 => Some(Errno::EBADF),
        11 => Some(Errno::EAGAIN),
        12 => Some(Errno::ENOMEM),
        13 => Some(Errno::EACCES),
        15 => Some(Errno::ENOTBLK),
        16 => Some(Errno::EBUSY),
        19 => Some(Errno::ENODEV),
        21 => Some(Errno::EISDIR),
        22 => Some(Errno::EINVAL),
        25 => Some(Errno::ENOTTY),
        28 => Some(Errno::ENOSPC),
        34 => Some(Errno::ERANGE),
        38 => Some(Errno::ENOSYS),
        39 => Some(Errno::ENOTEMPTY),
        40 => Some(Errno::ELOOP),
        61 => Some(Errno::ENODATA),
        75 => Some(Errno::EOVERFLOW),
        76 => Some(Errno::ENOTUNIQ),
        116 => Some(Errno::ESTALE),
        117 => Some(Errno::ESTALE),
        123 => Some(Errno::ENOMEDIUM),
        124 => Some(Errno::EMEDIUMTYPE),
        131 => Some(Errno::ENOTRECOVERABLE),
        _ => None,
    }
}

pub type Result<T> = std::result::Result<T, HibernateError>;

// ── Data structures ───────────────────────────────────────────────────────

/// Values for `/sys/power/resume` and `/sys/power/resume_offset` and the device path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HibernationDevice {
    pub devno: u64,
    pub offset: u64,
    pub path: String,
}

impl Default for HibernationDevice {
    fn default() -> Self {
        Self {
            devno: 0,
            offset: 0,
            path: String::new(),
        }
    }
}

/// A single extent from a fiemap ioctl response. Matches the kernel's `struct fiemap_extent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct FiemapExtent {
    pub fe_logical: u64,
    pub fe_physical: u64,
    pub fe_length: u64,
    pub fe_reserved64: [u64; 4],
    pub fe_flags: u32,
    pub fe_reserved: [u32; 3],
}

/// Result of a fiemap ioctl, containing all extents of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fiemap {
    pub fm_mapped_extents: u32,
    pub fm_flags: u32,
    pub extents: Vec<FiemapExtent>,
}

/// An entry parsed from `/proc/swaps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapEntry {
    pub path: String,
    pub swapfile: bool,
    pub size: u64,
    pub used: u64,
    pub priority: i32,
    pub devno: u64,
    pub offset: u64,
}

impl Default for SwapEntry {
    fn default() -> Self {
        Self {
            path: String::new(),
            swapfile: false,
            size: 0,
            used: 0,
            priority: -1,
            devno: 0,
            offset: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HibernateLocation {
    pub device: HibernationDevice,
    pub size: u64,
    pub used: u64,
    pub resume_set: bool,
}

// ── dev_t helpers ─────────────────────────────────────────────────────────

#[inline]
pub fn dev_major(devt: u64) -> u32 {
    ((devt >> 32) & 0xFFFF_FFFF) as u32
}

#[inline]
pub fn dev_minor(devt: u64) -> u32 {
    (devt & 0xFFFF_FFFF) as u32
}

#[inline]
pub fn make_dev(major: u32, minor: u32) -> u64 {
    ((major as u64) << 32) | (minor as u64)
}

pub fn format_devnum(devt: u64) -> String {
    format!("{}:{}", dev_major(devt), dev_minor(devt))
}

pub fn parse_devnum(s: &str) -> Result<u64> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 2 {
        return Err(HibernateError::InvalidDevnum(s.to_string()));
    }
    let major: u32 = parts[0]
        .parse()
        .map_err(|_| HibernateError::InvalidDevnum(s.to_string()))?;
    let minor: u32 = parts[1]
        .parse()
        .map_err(|_| HibernateError::InvalidDevnum(s.to_string()))?;
    Ok(make_dev(major, minor))
}

// ── sysfs / proc helpers ──────────────────────────────────────────────────

fn read_one_line(path: &str) -> Result<String> {
    let content = fs::read_to_string(path).map_err(HibernateError::from_io)?;
    Ok(content.trim().to_string())
}

fn write_sysfs(path: &str, value: &str) -> Result<()> {
    fs::write(path, value).map_err(HibernateError::from_io)
}

fn proc_cmdline_has_noresume() -> Result<bool> {
    let cmdline = fs::read_to_string(PROC_CMDLINE).map_err(HibernateError::from_io)?;
    for arg in cmdline.split_whitespace() {
        if arg == "noresume" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_efi_boot() -> bool {
    Path::new("/sys/firmware/efi").exists()
}

fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

fn parse_u64(s: &str, context: &str) -> Result<u64> {
    s.trim()
        .parse::<u64>()
        .map_err(|_| HibernateError::ParseError(context.to_string()))
}

fn parse_i32(s: &str, context: &str) -> Result<i32> {
    s.trim()
        .parse::<i32>()
        .map_err(|_| HibernateError::ParseError(context.to_string()))
}

// ── fiemap ────────────────────────────────────────────────────────────────

const FIEMAP_FLAG_SYNC: u32 = 0x00000001;
const FIEMAP_EXTENT_LAST: u32 = 0x00000001;

/// Read the fiemap for a file descriptor, collecting all extents.
/// Handles the XFS quirk where `FS_IOC_FIEMAP` returns extents for only one
/// block-group at a time, looping from the end of each last extent.
pub fn read_fiemap(fd: &impl AsRawFd) -> Result<Fiemap> {
    let raw_fd = fd.as_raw_fd();
    let metadata =
        fs::metadata(format!("/proc/self/fd/{}", raw_fd)).map_err(HibernateError::from_io)?;

    if !metadata.is_file() {
        return Err(HibernateError::NotARegularFile);
    }

    let file_size = metadata.len();

    let fiemap_header_size = std::mem::size_of::<FiemapExtent>();
    let n_extra =
        (std::mem::size_of::<u32>() * 2 + fiemap_header_size - 1) / fiemap_header_size;

    let mut all_extents: Vec<FiemapExtent> = Vec::new();
    let mut fiemap_start: u64 = 0;

    while fiemap_start < file_size {
        let mut fiemap_extents = vec![FiemapExtent::default(); n_extra + 256];

        // Kernel struct fiemap: 32-bit lo/hi pairs for start, length; then flags and counts
        let mut fiemap_start_lo = (fiemap_start & 0xFFFFFFFF) as u32;
        let mut fiemap_start_hi = (fiemap_start >> 32) as u32;
        let mut fiemap_length_lo = (file_size & 0xFFFFFFFF) as u32;
        let mut fiemap_length_hi = (file_size >> 32) as u32;
        let mut fm_flags: u32 = FIEMAP_FLAG_SYNC;
        let mut fm_mapped_extents: u32 = 0;
        let mut fm_extent_count: u32 = (fiemap_extents.len() - n_extra) as u32;

        // SAFETY: valid fd, correctly sized buffer for kernel write
        #[repr(C)]
        struct KernelFiemap {
            fm_start_lo: u32,
            fm_start_hi: u32,
            fm_length_lo: u32,
            fm_length_hi: u32,
            fm_flags: u32,
            fm_mapped_extents: u32,
            fm_extent_count: u32,
            fm_reserved: u32,
        }

        let mut kfiemap = KernelFiemap {
            fm_start_lo: fiemap_start_lo,
            fm_start_hi: fiemap_start_hi,
            fm_length_lo: fiemap_length_lo,
            fm_length_hi: fiemap_length_hi,
            fm_flags,
            fm_mapped_extents,
            fm_extent_count,
            fm_reserved: 0,
        };

        let ret = unsafe { libc::ioctl(raw_fd, FS_IOC_FIEMAP, &mut kfiemap) };
        if ret < 0 {
            return Err(HibernateError::from_io(io::Error::last_os_error()));
        }

        if kfiemap.fm_mapped_extents == 0 {
            break;
        }

        let actual_count = kfiemap.fm_mapped_extents as usize;
        if actual_count > fiemap_extents.len() {
            fiemap_extents.resize(n_extra + actual_count, FiemapExtent::default());
        }
        kfiemap.fm_extent_count = actual_count as u32;
        kfiemap.fm_mapped_extents = 0;

        let ret = unsafe { libc::ioctl(raw_fd, FS_IOC_FIEMAP, &mut kfiemap) };
        if ret < 0 {
            return Err(HibernateError::from_io(io::Error::last_os_error()));
        }

        let returned = kfiemap.fm_mapped_extents as usize;
        if returned > 0 {
            // Kernel requires struct fiemap + extents to be contiguous in memory
            let total_bytes = std::mem::size_of::<KernelFiemap>()
                + fiemap_extents.len() * std::mem::size_of::<FiemapExtent>();
            let mut buf: Vec<u8> = vec![0u8; total_bytes];

            unsafe {
                std::ptr::copy_nonoverlapping(
                    &kfiemap as *const KernelFiemap as *const u8,
                    buf.as_mut_ptr(),
                    std::mem::size_of::<KernelFiemap>(),
                );
            }
            unsafe {
                std::ptr::copy_nonoverlapping(
                    fiemap_extents.as_ptr() as *const u8,
                    buf.as_mut_ptr().add(std::mem::size_of::<KernelFiemap>()),
                    fiemap_extents.len() * std::mem::size_of::<FiemapExtent>(),
                );
            }

            let ret = unsafe { libc::ioctl(raw_fd, FS_IOC_FIEMAP, buf.as_mut_ptr()) };
            if ret < 0 {
                return Err(HibernateError::from_io(io::Error::last_os_error()));
            }

            let result_header: KernelFiemap =
                unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const KernelFiemap) };

            let actual_returned = result_header.fm_mapped_extents as usize;
            let extents_byte_offset = std::mem::size_of::<KernelFiemap>();

            for i in 0..actual_returned.min(fiemap_extents.len()) {
                let offset = extents_byte_offset + i * std::mem::size_of::<FiemapExtent>();
                if offset + std::mem::size_of::<FiemapExtent>() <= buf.len() {
                    let extent: FiemapExtent = unsafe {
                        std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const FiemapExtent)
                    };
                    all_extents.push(extent);
                }
            }

            if let Some(last) = all_extents.last() {
                fiemap_start = last.fe_logical + last.fe_length;
                if last.fe_flags & FIEMAP_EXTENT_LAST != 0 {
                    break;
                }
            }
        }
    }

    Ok(Fiemap {
        fm_mapped_extents: all_extents.len() as u32,
        fm_flags: 0,
        extents: all_extents,
    })
}

// ── Resume config ─────────────────────────────────────────────────────────

/// Resume configuration read from sysfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeConfig {
    pub devno: u64,
    pub offset: u64,
}

pub fn read_resume_config() -> Result<ResumeConfig> {
    if proc_cmdline_has_noresume()? {
        return Err(HibernateError::NoResumeSet);
    }

    let devno_str = read_one_line(SYS_POWER_RESUME)?;
    let devno = parse_devnum(&devno_str)?;

    let offset_str = read_one_line(SYS_POWER_RESUME_OFFSET)?;
    let offset = parse_u64(&offset_str, "resume_offset")?;

    if devno == 0 && offset > 0 {
        return Err(HibernateError::OffsetWithoutDevice);
    }

    Ok(ResumeConfig { devno, offset })
}

// ── Swap entries ──────────────────────────────────────────────────────────

pub fn read_swap_entries() -> Result<Vec<SwapEntry>> {
    let content = fs::read_to_string(PROC_SWAPS).map_err(HibernateError::from_io)?;
    let mut entries = Vec::new();

    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let path = parts[0].to_string();
        let swap_type = parts[1];
        let size = parse_u64(parts[2], "swap size")?;
        let used = parse_u64(parts[3], "swap used")?;
        let priority = parse_i32(parts[4], "swap priority")?;

        if swap_type == "file" {
            if path.ends_with(DELETED_SWAP_SUFFIX) {
                continue;
            }
            entries.push(SwapEntry {
                path,
                swapfile: true,
                size,
                used,
                priority,
                devno: 0,
                offset: 0,
            });
        } else if swap_type == "partition" {
            if let Some(node) = path.strip_prefix("/dev/") {
                if node.starts_with("zram") {
                    continue;
                }
            }
            entries.push(SwapEntry {
                path,
                swapfile: false,
                size,
                used,
                priority,
                devno: 0,
                offset: 0,
            });
        }
    }

    Ok(entries)
}

fn swap_entry_get_resume_config(swap: &mut SwapEntry) -> Result<()> {
    let metadata = fs::metadata(&swap.path).map_err(HibernateError::from_io)?;

    if !swap.swapfile {
        #[cfg(target_os = "linux")]
        let is_blk = metadata.file_type().is_block_device();
        #[cfg(not(target_os = "linux"))]
        let is_blk = metadata.rdev() != 0;
        if !is_blk {
            return Err(HibernateError::NotABlockDevice);
        }
        swap.devno = metadata.rdev() as u64;
        swap.offset = 0;
        return Ok(());
    }

    if !metadata.is_file() {
        return Err(HibernateError::NotARegularFile);
    }

    let devno = metadata.dev();
    let dev_major_val = dev_major(devno);
    let dev_minor_val = dev_minor(devno);

    if dev_major_val == 0 {
        return Err(HibernateError::NoBlockDevice);
    }

    swap.devno = make_dev(dev_major_val, dev_minor_val);

    let file = fs::File::open(&swap.path).map_err(HibernateError::from_io)?;
    let fiemap = read_fiemap(&file)?;

    if let Some(first_extent) = fiemap.extents.first() {
        let page_sz = page_size();
        swap.offset = first_extent.fe_physical / page_sz as u64;
    }

    Ok(())
}

// ── Find hibernation device ───────────────────────────────────────────────

/// Find a suitable device for hibernation by parsing `/proc/swaps`, `/sys/power/resume`,
/// and `/sys/power/resume_offset`.
///
/// # Security
///
/// Never use a device that hasn't been specified by a user with full system memory
/// access (via `/sys/power/resume`) or isn't an already active swap area.
pub fn find_hibernate_location() -> Result<HibernateLocation> {
    let resume_config = read_resume_config()?;

    let mut entries = read_swap_entries()?;

    let mut best_entry: Option<usize> = None;
    let mut best_priority: i32 = i32::MIN;
    let mut best_available: u64 = 0;

    for (i, swap) in entries.iter_mut().enumerate() {
        if let Err(e) = swap_entry_get_resume_config(swap) {
            match e {
                HibernateError::UnsupportedMedium => continue,
                _ => return Err(e),
            }
        }

        if swap.devno == 0 {
            continue;
        }

        if resume_config.devno > 0 {
            if swap.devno == resume_config.devno
                && (!swap.swapfile || swap.offset == resume_config.offset)
            {
                best_entry = Some(i);
                break;
            }
            continue;
        }

        if best_entry.is_some() {
            if swap.priority > best_priority
                || (swap.priority == best_priority && swap.size - swap.used > best_available)
            {
                best_entry = Some(i);
                best_priority = swap.priority;
                best_available = swap.size - swap.used;
            }
        } else {
            best_entry = Some(i);
            best_priority = swap.priority;
            best_available = swap.size - swap.used;
        }
    }

    let entry_idx = best_entry.ok_or_else(|| {
        if resume_config.devno > 0 {
            HibernateError::ResumeDeviceNotFound
        } else {
            HibernateError::NoSwapSpace
        }
    })?;

    let entry = &entries[entry_idx];
    let path = if entry.swapfile {
        format!("/sys/dev/block/{}", format_devnum(entry.devno))
    } else {
        entry.path.clone()
    };

    Ok(HibernateLocation {
        device: HibernationDevice {
            devno: entry.devno,
            offset: entry.offset,
            path,
        },
        size: entry.size,
        used: entry.used,
        resume_set: resume_config.devno > 0,
    })
}

// ── Memory info ───────────────────────────────────────────────────────────

pub fn get_proc_meminfo_active() -> Result<u64> {
    let content = fs::read_to_string(PROC_MEMINFO).map_err(HibernateError::from_io)?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Active(anon):") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if !parts.is_empty() {
                return parse_u64(parts[0], "Active(anon)");
            }
        }
    }
    Err(HibernateError::ParseError(
        "Active(anon) not found in /proc/meminfo".to_string(),
    ))
}

// ── Hibernation safety ────────────────────────────────────────────────────

/// Check whether hibernation is safe to perform.
pub fn hibernation_is_safe() -> Result<bool> {
    let bypass_space_check = std::env::var(ENV_BYPASS_HIBERNATION_MEMORY_CHECK).is_ok();

    let location = match find_hibernate_location() {
        Ok(loc) => loc,
        Err(HibernateError::NoSwapSpace | HibernateError::ResumeDeviceNotFound) => {
            if bypass_space_check {
                return Ok(true);
            }
            return Err(HibernateError::NoSwapSpace);
        }
        Err(e) => return Err(e),
    };

    if !location.resume_set && !is_efi_boot() {
        return Err(HibernateError::NotEfiAndNoResume);
    }

    if bypass_space_check {
        return Ok(true);
    }

    let active = get_proc_meminfo_active()?;
    let available = location.size - location.used;
    let enough = active as f64 <= available as f64 * HIBERNATION_SWAP_THRESHOLD;

    if !enough {
        return Err(HibernateError::NotEnoughSwap);
    }

    Ok(true)
}

// ── Write resume config ───────────────────────────────────────────────────

pub fn write_resume_config(devno: u64, offset: u64, device: &str) -> Result<()> {
    if devno == 0 {
        return Err(HibernateError::Errno(Errno::EINVAL));
    }

    let offset_str = offset.to_string();
    write_sysfs(SYS_POWER_RESUME_OFFSET, &offset_str)?;

    let devno_str = format_devnum(devno);
    write_sysfs(SYS_POWER_RESUME, &devno_str)?;

    Ok(())
}

// ── EFI hibernate location ────────────────────────────────────────────────

pub fn clear_efi_hibernate_location() -> Result<bool> {
    if !is_efi_boot() {
        return Ok(false);
    }

    let efi_path =
        "/sys/firmware/efi/efivars/HibernateLocation-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

    match fs::remove_file(efi_path) {
        Ok(()) => Ok(true),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(e) => Err(HibernateError::from_io(e)),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dev_major_minor_roundtrip() {
        let dev = make_dev(8, 1);
        assert_eq!(dev_major(dev), 8);
        assert_eq!(dev_minor(dev), 1);
    }

    #[test]
    fn test_format_devnum() {
        let dev = make_dev(253, 2);
        assert_eq!(format_devnum(dev), "253:2");
    }

    #[test]
    fn test_parse_devnum_valid() {
        let dev = parse_devnum("8:1").unwrap();
        assert_eq!(dev_major(dev), 8);
        assert_eq!(dev_minor(dev), 1);
    }

    #[test]
    fn test_parse_devnum_whitespace() {
        let dev = parse_devnum("  253:2  ").unwrap();
        assert_eq!(dev_major(dev), 253);
        assert_eq!(dev_minor(dev), 2);
    }

    #[test]
    fn test_parse_devnum_invalid_format() {
        assert!(parse_devnum("abc").is_err());
        assert!(parse_devnum("8").is_err());
        assert!(parse_devnum("8:1:2").is_err());
    }

    #[test]
    fn test_hibernation_device_default() {
        let device = HibernationDevice::default();
        assert_eq!(device.devno, 0);
        assert_eq!(device.offset, 0);
        assert!(device.path.is_empty());
    }

    #[test]
    fn test_swap_entry_default() {
        let entry = SwapEntry::default();
        assert!(entry.path.is_empty());
        assert!(!entry.swapfile);
        assert_eq!(entry.size, 0);
        assert_eq!(entry.used, 0);
        assert_eq!(entry.priority, -1);
        assert_eq!(entry.devno, 0);
        assert_eq!(entry.offset, 0);
    }

    #[test]
    fn test_resume_config_zero_devno_with_offset_is_error() {
        let config = ResumeConfig {
            devno: 0,
            offset: 4096,
        };
        assert!(config.devno == 0 && config.offset > 0);
    }

    #[test]
    fn test_resume_config_valid() {
        let config = ResumeConfig {
            devno: make_dev(8, 1),
            offset: 0,
        };
        assert_eq!(dev_major(config.devno), 8);
        assert_eq!(config.offset, 0);
    }

    #[test]
    fn test_fiemap_extent_default() {
        let extent = FiemapExtent::default();
        assert_eq!(extent.fe_logical, 0);
        assert_eq!(extent.fe_physical, 0);
        assert_eq!(extent.fe_length, 0);
        assert_eq!(extent.fe_flags, 0);
    }

    #[test]
    fn test_hibernate_location_fields() {
        let loc = HibernateLocation {
            device: HibernationDevice {
                devno: make_dev(8, 2),
                offset: 0,
                path: "/dev/sda2".to_string(),
            },
            size: 8_388_608,
            used: 1_048_576,
            resume_set: true,
        };
        assert_eq!(loc.device.devno, make_dev(8, 2));
        assert_eq!(loc.size, 8_388_608);
        assert!(loc.resume_set);
    }

    #[test]
    fn test_hibernate_error_display() {
        let err = HibernateError::NoSwapSpace;
        assert_eq!(format!("{}", err), "no swap space available");

        let err = HibernateError::NoResumeSet;
        assert!(format!("{}", err).contains("noresume"));

        let err = HibernateError::NotEfiAndNoResume;
        assert!(format!("{}", err).contains("EFI"));

        let err = HibernateError::ParseError("bad value".to_string());
        assert!(format!("{}", err).contains("bad value"));
    }

    #[test]
    fn test_hibernate_error_errno_conversion() {
        let err = HibernateError::from(Errno::ENOMEM);
        assert_eq!(err.errno(), Some(Errno::ENOMEM));

        let err = HibernateError::NoSwapSpace;
        assert_eq!(err.errno(), None);
    }

    #[test]
    fn test_page_size_is_power_of_two() {
        let ps = page_size();
        assert!(ps > 0);
        assert!(ps.is_power_of_two());
    }

    #[test]
    fn test_swap_threshold_value() {
        assert!(
            (HIBERNATION_SWAP_THRESHOLD - 0.98).abs() < f64::EPSILON,
            "HIBERNATION_SWAP_THRESHOLD should be 0.98"
        );
    }

    #[test]
    fn test_swap_entry_partition_has_zero_offset() {
        let entry = SwapEntry {
            path: "/dev/sda2".to_string(),
            swapfile: false,
            size: 1_000_000,
            used: 100_000,
            priority: -1,
            devno: 0,
            offset: 0,
        };
        assert_eq!(entry.offset, 0);
    }

    #[test]
    fn test_deleted_swap_suffix_detection() {
        let deleted_path = "/swapfile\\040(deleted)";
        assert!(deleted_path.ends_with(DELETED_SWAP_SUFFIX));

        let normal_path = "/swapfile";
        assert!(!normal_path.ends_with(DELETED_SWAP_SUFFIX));
    }

    #[test]
    fn test_parse_u64_valid() {
        assert_eq!(parse_u64("12345", "test").unwrap(), 12345);
        assert_eq!(parse_u64("  67890  ", "test").unwrap(), 67890);
    }

    #[test]
    fn test_parse_u64_invalid() {
        assert!(parse_u64("abc", "test").is_err());
        assert!(parse_u64("", "test").is_err());
    }

    #[test]
    fn test_constants_are_correct_paths() {
        assert!(SYS_POWER_RESUME.starts_with("/sys/"));
        assert!(SYS_POWER_RESUME_OFFSET.starts_with("/sys/"));
        assert!(PROC_SWAPS.starts_with("/proc/"));
        assert!(PROC_MEMINFO.starts_with("/proc/"));
        assert!(PROC_CMDLINE.starts_with("/proc/"));
    }
}
