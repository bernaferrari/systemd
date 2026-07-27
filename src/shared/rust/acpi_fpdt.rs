// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/acpi-fpdt.c, src/shared/acpi-fpdt.h
//
// ACPI FPDT (Firmware Performance Data Table) parsing.
// Reads boot timing information from ACPI tables via sysfs or /dev/mem fallback.

use std::fs;
use std::io::{self, Read as _, Seek, SeekFrom};

use crate::ffi::Errno;

// ── Type aliases and constants ──────────────────────────────────────────────

pub type usec_t = u64;

pub const NSEC_PER_HOUR: u64 = 3600 * 1_000_000_000;
pub const NSEC_PER_USEC: u64 = 1000;

// ── ACPI FPDT record types ─────────────────────────────────────────────────

const ACPI_FPDT_TYPE_BOOT: u16 = 0;
const ACPI_FPDT_TYPE_S3PERF: u16 = 1;

const ACPI_FPDT_S3PERF_RESUME_REC: u16 = 0;
const ACPI_FPDT_S3PERF_SUSPEND_REC: u16 = 1;
const ACPI_FPDT_BOOT_REC: u16 = 2;

// ── ACPI table header (packed, 36 bytes) ────────────────────────────────────

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct AcpiTableHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    asl_compiler_id: [u8; 4],
    asl_compiler_revision: u32,
}

const ACPI_TABLE_HEADER_SIZE: usize = 4 + 4 + 1 + 1 + 6 + 8 + 4 + 4 + 4;

// ── FPDT header record (16 bytes) ──────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct AcpiFpdtHeader {
    rec_type: u16,
    length: u8,
    revision: u8,
    reserved: [u8; 4],
    ptr: u64,
}

const ACPI_FPDT_HEADER_SIZE: usize = 2 + 1 + 1 + 4 + 8;

// ── FPDT boot header (8 bytes) ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct AcpiFpdtBootHeader {
    signature: [u8; 4],
    length: u32,
}

const ACPI_FPDT_BOOT_HEADER_SIZE: usize = 4 + 4;

// ── FPDT boot record (40 bytes) ────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct AcpiFpdtBoot {
    rec_type: u16,
    length: u8,
    revision: u8,
    reserved: [u8; 4],
    reset_end: u64,
    load_start: u64,
    startup_start: u64,
    exit_services_entry: u64,
}

const ACPI_FPDT_BOOT_SIZE: usize = 2 + 1 + 1 + 4 + 8 + 8 + 8 + 8;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors that can occur when reading ACPI FPDT boot timing data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiFpdtError {
    /// The requested sysfs file or ACPI table does not exist.
    NoEntry,
    /// The data exists but is invalid or malformed.
    InvalidData,
    /// An I/O error occurred (carries raw errno value).
    Io(i32),
}

impl AcpiFpdtError {
    /// Convert to a negative errno value (systemd convention).
    pub fn to_neg_errno(self) -> i32 {
        match self {
            AcpiFpdtError::NoEntry => Errno::ENOENT.to_neg_errno(),
            AcpiFpdtError::InvalidData => Errno::EINVAL.to_neg_errno(),
            AcpiFpdtError::Io(e) => -e.abs(),
        }
    }
}

impl std::fmt::Display for AcpiFpdtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcpiFpdtError::NoEntry => write!(f, "ACPI FPDT entry not found"),
            AcpiFpdtError::InvalidData => write!(f, "ACPI FPDT data is invalid"),
            AcpiFpdtError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for AcpiFpdtError {}

// ── Boot timing result ─────────────────────────────────────────────────────

/// Boot timing information from ACPI FPDT, in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootTiming {
    /// Loader start time in microseconds.
    pub loader_start: usec_t,
    /// Loader exit time in microseconds.
    pub loader_exit: usec_t,
}

// ── Helper: read u64 from a sysfs timestamp file ───────────────────────────

/// Read a nanosecond timestamp from a sysfs file containing a decimal integer.
fn read_timestamp_file(path: &str) -> io::Result<u64> {
    let content = fs::read_to_string(path)?;
    content
        .trim()
        .parse::<u64>()
        .map_err(|e: std::num::ParseIntError| io::Error::new(io::ErrorKind::InvalidData, e))
}

// ── Helper: parse u32 LE from byte slice ────────────────────────────────────

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

// ── Kernel-parsed sysfs path ────────────────────────────────────────────────

/// Try to get boot timing from kernel-parsed sysfs files (kernel 5.12+ on x86, 6.2+ on arm64).
fn acpi_get_boot_usec_kernel_parsed() -> Result<BootTiming, AcpiFpdtError> {
    let end = read_timestamp_file("/sys/firmware/acpi/fpdt/boot/exitbootservice_end_ns")
        .map_err(|_| AcpiFpdtError::NoEntry)?;

    if end == 0 {
        // Non-UEFI compatible boot
        return Err(AcpiFpdtError::NoEntry);
    }

    let start = read_timestamp_file("/sys/firmware/acpi/fpdt/boot/bootloader_launch_ns")
        .map_err(|_| AcpiFpdtError::NoEntry)?;

    if start == 0 || end < start {
        return Err(AcpiFpdtError::InvalidData);
    }
    if end > NSEC_PER_HOUR {
        return Err(AcpiFpdtError::InvalidData);
    }

    Ok(BootTiming {
        loader_start: start / NSEC_PER_USEC,
        loader_exit: end / NSEC_PER_USEC,
    })
}

// ── FPDT table parsing via /sys/firmware/acpi/tables/FPDT ──────────────────

/// Parse the ACPI FPDT table from raw bytes, find the boot record pointer.
/// Returns the physical address of the boot record data (for /dev/mem read).
fn parse_fpdt_table_find_boot_ptr(buf: &[u8]) -> Result<u64, AcpiFpdtError> {
    if buf.len() < ACPI_TABLE_HEADER_SIZE + ACPI_FPDT_HEADER_SIZE {
        return Err(AcpiFpdtError::InvalidData);
    }

    // Validate table header
    let table_length = read_u32_le(buf, 4) as usize;
    if buf.len() != table_length {
        return Err(AcpiFpdtError::InvalidData);
    }

    if &buf[0..4] != b"FPDT" {
        return Err(AcpiFpdtError::InvalidData);
    }

    // Iterate over FPDT header records after the table header
    let mut offset = ACPI_TABLE_HEADER_SIZE;
    let mut ptr: u64 = 0;

    while offset + 4 <= buf.len() {
        // Need at least type (2) + length (1) + revision (1) to read record header
        let rec_length = buf[offset + 2] as usize;
        if rec_length == 0 {
            break;
        }
        if rec_length < 4 {
            // Record too small to even have a valid header, skip by 1 to avoid infinite loop
            // (matches C behavior of breaking on length <= 0)
            break;
        }

        let rec_type = read_u16_le(buf, offset);

        if rec_type == ACPI_FPDT_TYPE_BOOT && rec_length == ACPI_FPDT_HEADER_SIZE {
            // Found Firmware Basic Boot Performance Pointer Record
            if offset + ACPI_FPDT_HEADER_SIZE <= buf.len() {
                ptr = read_u64_le(buf, offset + 8); // reserved(4) then ptr(8)
                break;
            }
        }

        offset += rec_length;
    }

    if ptr == 0 {
        return Err(AcpiFpdtError::NoEntry);
    }

    Ok(ptr)
}

/// Read boot record from /dev/mem at the given physical address.
fn read_boot_record_from_dev_mem(ptr: u64) -> Result<BootTiming, AcpiFpdtError> {
    let mut fd = fs::File::open("/dev/mem").map_err(|e| {
        AcpiFpdtError::Io(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(e.raw_os_error().unwrap_or(libc::EIO)),
        )
    })?;

    // Read boot header first
    let mut hbrec_buf = [0u8; ACPI_FPDT_BOOT_HEADER_SIZE];
    fd.seek(SeekFrom::Start(ptr))
        .map_err(|e| AcpiFpdtError::Io(e.raw_os_error().unwrap_or(libc::EIO)))?;
    fd.read_exact(&mut hbrec_buf)
        .map_err(|e| AcpiFpdtError::Io(e.raw_os_error().unwrap_or(libc::EIO)))?;

    if &hbrec_buf[0..4] != b"FBPT" {
        return Err(AcpiFpdtError::InvalidData);
    }

    let hbrec_length = read_u32_le(&hbrec_buf, 4) as usize;
    if hbrec_length < ACPI_FPDT_BOOT_HEADER_SIZE + ACPI_FPDT_BOOT_SIZE {
        return Err(AcpiFpdtError::InvalidData);
    }

    // Read the boot record
    let mut brec_buf = [0u8; ACPI_FPDT_BOOT_SIZE];
    fd.seek(SeekFrom::Start(ptr + ACPI_FPDT_BOOT_HEADER_SIZE as u64))
        .map_err(|e| AcpiFpdtError::Io(e.raw_os_error().unwrap_or(libc::EIO)))?;
    fd.read_exact(&mut brec_buf)
        .map_err(|e| AcpiFpdtError::Io(e.raw_os_error().unwrap_or(libc::EIO)))?;

    // Validate boot record
    let brec_length = brec_buf[2] as usize; // length field at offset 2
    if brec_length != ACPI_FPDT_BOOT_SIZE {
        return Err(AcpiFpdtError::InvalidData);
    }

    let brec_type = read_u16_le(&brec_buf, 0);
    if brec_type != ACPI_FPDT_BOOT_REC {
        return Err(AcpiFpdtError::InvalidData);
    }

    // Fields in AcpiFpdtBoot: offset 24 = exit_services_entry (after type(2)+length(1)+revision(1)+reserved(4)+reset_end(8)+load_start(8))
    let exit_services_entry = read_u64_le(&brec_buf, 24);
    // startup_start is at offset 16 (type(2)+length(1)+revision(1)+reserved(4)+reset_end(8))
    let startup_start = read_u64_le(&brec_buf, 16);

    if exit_services_entry == 0 {
        // Non-UEFI compatible boot
        return Err(AcpiFpdtError::NoEntry);
    }

    if startup_start == 0 || exit_services_entry < startup_start {
        return Err(AcpiFpdtError::InvalidData);
    }
    if exit_services_entry > NSEC_PER_HOUR {
        return Err(AcpiFpdtError::InvalidData);
    }

    Ok(BootTiming {
        loader_start: startup_start / NSEC_PER_USEC,
        loader_exit: exit_services_entry / NSEC_PER_USEC,
    })
}

/// Parse FPDT boot timing via the ACPI table file + /dev/mem fallback path.
fn acpi_get_boot_usec_dev_mem() -> Result<BootTiming, AcpiFpdtError> {
    let buf = fs::read("/sys/firmware/acpi/tables/FPDT").map_err(|_| AcpiFpdtError::NoEntry)?;

    let ptr = parse_fpdt_table_find_boot_ptr(&buf)?;
    read_boot_record_from_dev_mem(ptr)
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Get boot timing from ACPI FPDT table.
///
/// Tries the kernel-parsed sysfs interface first (kernel 5.12+), falling back
/// to reading the raw ACPI table via `/sys/firmware/acpi/tables/FPDT` and then
/// fetching the boot record from `/dev/mem`.
///
/// Returns boot timing in microseconds, or an error if unavailable.
pub fn acpi_get_boot_usec() -> Result<BootTiming, AcpiFpdtError> {
    // Try kernel-parsed sysfs files first
    match acpi_get_boot_usec_kernel_parsed() {
        Ok(timing) => return Ok(timing),
        Err(AcpiFpdtError::NoEntry) => {
            // Fall through to /dev/mem fallback only if kernel doesn't
            // support the new sysfs files
        }
        Err(e) => return Err(e),
    }

    // Fallback: parse ACPI table directly and read from /dev/mem
    acpi_get_boot_usec_dev_mem()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants tests ─────────────────────────────────────────────────

    #[test]
    fn test_nsec_per_hour() {
        assert_eq!(NSEC_PER_HOUR, 3_600_000_000_000);
    }

    #[test]
    fn test_nsec_per_usec() {
        assert_eq!(NSEC_PER_USEC, 1000);
    }

    #[test]
    fn test_struct_sizes() {
        assert_eq!(ACPI_TABLE_HEADER_SIZE, 36);
        assert_eq!(ACPI_FPDT_HEADER_SIZE, 16);
        assert_eq!(ACPI_FPDT_BOOT_HEADER_SIZE, 8);
        assert_eq!(ACPI_FPDT_BOOT_SIZE, 40);
    }

    // ── Record type constants ───────────────────────────────────────────

    #[test]
    fn test_fpdt_record_types() {
        assert_eq!(ACPI_FPDT_TYPE_BOOT, 0);
        assert_eq!(ACPI_FPDT_TYPE_S3PERF, 1);
        assert_eq!(ACPI_FPDT_S3PERF_RESUME_REC, 0);
        assert_eq!(ACPI_FPDT_S3PERF_SUSPEND_REC, 1);
        assert_eq!(ACPI_FPDT_BOOT_REC, 2);
    }

    // ── Byte reading helpers ────────────────────────────────────────────

    #[test]
    fn test_read_u16_le() {
        let data: &[u8] = &[0x34, 0x12];
        assert_eq!(read_u16_le(data, 0), 0x1234);
    }

    #[test]
    fn test_read_u32_le() {
        let data: &[u8] = &[0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(data, 0), 0x12345678);
    }

    #[test]
    fn test_read_u64_le() {
        let data: &[u8] = &[0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        assert_eq!(read_u64_le(data, 0), 0x0123456789ABCDEF);
    }

    // ── FPDT table parsing ─────────────────────────────────────────────

    #[test]
    fn test_parse_fpdt_table_too_small() {
        let tiny = vec![0u8; 10];
        assert_eq!(
            parse_fpdt_table_find_boot_ptr(&tiny),
            Err(AcpiFpdtError::InvalidData)
        );
    }

    #[test]
    fn test_parse_fpdt_table_bad_signature() {
        // Build a buffer that looks like a valid-length table but wrong signature
        let mut buf = vec![0u8; ACPI_TABLE_HEADER_SIZE + ACPI_FPDT_HEADER_SIZE];
        // Write "XXXX" as signature (wrong)
        buf[0..4].copy_from_slice(b"XXXX");
        // Write table length at offset 4
        let len = buf.len() as u32;
        buf[4..8].copy_from_slice(&len.to_le_bytes());
        assert_eq!(
            parse_fpdt_table_find_boot_ptr(&buf),
            Err(AcpiFpdtError::InvalidData)
        );
    }

    #[test]
    fn test_parse_fpdt_table_wrong_length() {
        let mut buf = vec![0u8; 100];
        buf[0..4].copy_from_slice(b"FPDT");
        // Write a length that doesn't match buffer size
        let wrong_len = 50u32;
        buf[4..8].copy_from_slice(&wrong_len.to_le_bytes());
        assert_eq!(
            parse_fpdt_table_find_boot_ptr(&buf),
            Err(AcpiFpdtError::InvalidData)
        );
    }

    #[test]
    fn test_parse_fpdt_table_no_boot_record() {
        let mut buf = vec![0u8; ACPI_TABLE_HEADER_SIZE + ACPI_FPDT_HEADER_SIZE];
        buf[0..4].copy_from_slice(b"FPDT");
        let len = buf.len() as u32;
        buf[4..8].copy_from_slice(&len.to_le_bytes());
        // Put a valid record header but with S3PERF type (not BOOT)
        let offset = ACPI_TABLE_HEADER_SIZE;
        let rec_type = ACPI_FPDT_TYPE_S3PERF.to_le_bytes();
        buf[offset] = rec_type[0];
        buf[offset + 1] = rec_type[1];
        buf[offset + 2] = ACPI_FPDT_HEADER_SIZE as u8; // length
        assert_eq!(
            parse_fpdt_table_find_boot_ptr(&buf),
            Err(AcpiFpdtError::NoEntry)
        );
    }

    #[test]
    fn test_parse_fpdt_table_valid_boot_ptr() {
        // Construct a valid FPDT table with a boot record pointer
        let mut buf = vec![0u8; ACPI_TABLE_HEADER_SIZE + ACPI_FPDT_HEADER_SIZE];
        buf[0..4].copy_from_slice(b"FPDT");
        let len = buf.len() as u32;
        buf[4..8].copy_from_slice(&len.to_le_bytes());

        // Write FPDT header record at offset ACPI_TABLE_HEADER_SIZE
        let off = ACPI_TABLE_HEADER_SIZE;
        let rec_type = ACPI_FPDT_TYPE_BOOT.to_le_bytes();
        buf[off] = rec_type[0];
        buf[off + 1] = rec_type[1];
        buf[off + 2] = ACPI_FPDT_HEADER_SIZE as u8; // length

        // Write the pointer value (8 bytes, starting at off + 8)
        let ptr_val: u64 = 0xDEADBEEF00000000;
        buf[off + 8..off + 16].copy_from_slice(&ptr_val.to_le_bytes());

        let result = parse_fpdt_table_find_boot_ptr(&buf);
        assert_eq!(result, Ok(0xDEADBEEF00000000));
    }

    // ── Error type tests ────────────────────────────────────────────────

    #[test]
    fn test_acpi_fpdt_error_to_neg_errno() {
        assert_eq!(
            AcpiFpdtError::NoEntry.to_neg_errno(),
            Errno::ENOENT.to_neg_errno()
        );
        assert_eq!(
            AcpiFpdtError::InvalidData.to_neg_errno(),
            Errno::EINVAL.to_neg_errno()
        );
        assert_eq!(AcpiFpdtError::Io(5).to_neg_errno(), -5);
    }

    #[test]
    fn test_acpi_fpdt_error_display() {
        assert!(!AcpiFpdtError::NoEntry.to_string().is_empty());
        assert!(!AcpiFpdtError::InvalidData.to_string().is_empty());
        assert!(!AcpiFpdtError::Io(42).to_string().is_empty());
    }

    // ── BootTiming tests ────────────────────────────────────────────────

    #[test]
    fn test_boot_timing() {
        let t = BootTiming {
            loader_start: 1000,
            loader_exit: 5000,
        };
        assert_eq!(t.loader_start, 1000);
        assert_eq!(t.loader_exit, 5000);
    }

    #[test]
    fn test_boot_timing_equality() {
        let a = BootTiming {
            loader_start: 100,
            loader_exit: 200,
        };
        let b = BootTiming {
            loader_start: 100,
            loader_exit: 200,
        };
        assert_eq!(a, b);
    }

    // ── nsec→usec conversion consistency ────────────────────────────────

    #[test]
    fn test_nsec_to_usec_conversion() {
        let nsec: u64 = 1_234_567_890;
        let usec = nsec / NSEC_PER_USEC;
        assert_eq!(usec, 1_234_567);
    }

    #[test]
    fn test_hour_threshold_in_usec() {
        let hour_usec = NSEC_PER_HOUR / NSEC_PER_USEC;
        assert_eq!(hour_usec, 3_600_000_000); // 1 hour in microseconds
    }

    // ── Multi-record iteration ──────────────────────────────────────────

    #[test]
    fn test_parse_fpdt_table_skips_non_boot_records() {
        // Build a table with two records: first S3PERF (skipped), then BOOT
        let s3perf_size = 16usize;
        let boot_size = ACPI_FPDT_HEADER_SIZE;
        let total = ACPI_TABLE_HEADER_SIZE + s3perf_size + boot_size;
        let mut buf = vec![0u8; total];

        // Header
        buf[0..4].copy_from_slice(b"FPDT");
        buf[4..8].copy_from_slice(&(total as u32).to_le_bytes());

        // Record 1: S3PERF
        let off1 = ACPI_TABLE_HEADER_SIZE;
        let t1 = ACPI_FPDT_TYPE_S3PERF.to_le_bytes();
        buf[off1] = t1[0];
        buf[off1 + 1] = t1[1];
        buf[off1 + 2] = s3perf_size as u8;

        // Record 2: BOOT
        let off2 = off1 + s3perf_size;
        let t2 = ACPI_FPDT_TYPE_BOOT.to_le_bytes();
        buf[off2] = t2[0];
        buf[off2 + 1] = t2[1];
        buf[off2 + 2] = boot_size as u8;
        let ptr_val: u64 = 0xCAFEBABE00000000;
        buf[off2 + 8..off2 + 16].copy_from_slice(&ptr_val.to_le_bytes());

        let result = parse_fpdt_table_find_boot_ptr(&buf);
        assert_eq!(result, Ok(0xCAFEBABE00000000));
    }
}
