// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.procfs-util; authority=src/basic/procfs-util.c,src/basic/procfs-util.h
//
// Procfs sysctl and accounting helpers. The parsing and file handling core is
// safe Rust. The only unsafe operations are the audited C ABI entry points and
// `sysconf(_SC_CLK_TCK)`, which has no safe standard-library equivalent.

use crate::ffi::Errno;
use libc::c_char;
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

const TASKS_MAX: u64 = 4_194_303;
const TASKS_MIN: u64 = 20;
const LONG_LINE_MAX: usize = 1024 * 1024;
const NSEC_PER_SEC: u64 = 1_000_000_000;

const PID_MAX_PATH: &str = "/proc/sys/kernel/pid_max";
const THREADS_MAX_PATH: &str = "/proc/sys/kernel/threads-max";
const LOADAVG_PATH: &str = "/proc/loadavg";
const STAT_PATH: &str = "/proc/stat";
const MEMINFO_PATH: &str = "/proc/meminfo";

fn errno_from_io(error: &io::Error) -> Errno {
    error
        .raw_os_error()
        .and_then(Errno::from_raw)
        .unwrap_or(Errno::EIO)
}

fn io_result<T>(result: io::Result<T>) -> Result<T, Errno> {
    result.map_err(|error| errno_from_io(&error))
}

fn is_ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// Safe equivalent of systemd's `safe_atou64()` base-zero grammar.
///
/// This deliberately accepts the systemd extensions `0b` and `0o`, accepts
/// leading ASCII whitespace and a leading plus sign, rejects trailing bytes,
/// and preserves the C `strtoull()` treatment of negative zero.
fn parse_u64_systemd_bytes(input: &[u8]) -> Result<u64, Errno> {
    let mut input = input;
    while input.first().is_some_and(|byte| is_ascii_whitespace(*byte)) {
        input = &input[1..];
    }

    // `mangle_base()` recognizes systemd's 0b/0o extensions before libc
    // processes an optional sign. Consequently, signed 0b/0o forms are
    // rejected even though signed libc-native hexadecimal/octal is accepted.
    let allow_systemd_prefix = !matches!(input.first(), Some(b'+' | b'-'));
    let negative = match input.first() {
        Some(b'+') => {
            input = &input[1..];
            false
        }
        Some(b'-') => {
            input = &input[1..];
            true
        }
        _ => false,
    };

    let (base, digits) =
        if allow_systemd_prefix && (input.starts_with(b"0b") || input.starts_with(b"0B")) {
            (2, &input[2..])
        } else if allow_systemd_prefix && (input.starts_with(b"0o") || input.starts_with(b"0O")) {
            (8, &input[2..])
        } else if input.starts_with(b"0x") || input.starts_with(b"0X") {
            (16, &input[2..])
        } else if input.starts_with(b"0") && input.len() > 1 {
            (8, input)
        } else {
            (10, input)
        };

    if digits.is_empty() {
        return Err(Errno::EINVAL);
    }

    let mut value = 0_u64;
    for &byte in digits {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(Errno::EINVAL),
        };
        if digit >= base {
            return Err(Errno::EINVAL);
        }
        value = value
            .checked_mul(base as u64)
            .and_then(|value| value.checked_add(digit as u64))
            .ok_or(Errno::ERANGE)?;
    }

    if negative && value != 0 {
        return Err(Errno::ERANGE);
    }
    Ok(value)
}

fn parse_u64_systemd(value: &str) -> Result<u64, Errno> {
    parse_u64_systemd_bytes(value.as_bytes())
}

/// Read one C `read_one_line_file()`/`read_line()` compatible line without
/// allocating more than `LONG_LINE_MAX` bytes. Procfs values are bytes, not
/// UTF-8, so invalid bytes are left for the numeric parser to reject.
fn read_one_line(path: &Path) -> Result<Vec<u8>, Errno> {
    let file = io_result(File::open(path))?;
    let mut reader = BufReader::new(file);
    Ok(read_proc_line(&mut reader)?.unwrap_or_default())
}

fn open_proc_reader(path: &Path) -> Result<BufReader<File>, Errno> {
    io_result(File::open(path)).map(BufReader::new)
}

fn read_proc_line(reader: &mut BufReader<File>) -> Result<Option<Vec<u8>>, Errno> {
    let mut line = Vec::new();
    loop {
        let (consumed, complete) = {
            let buffer = io_result(reader.fill_buf())?;
            if buffer.is_empty() {
                if line.len() >= LONG_LINE_MAX {
                    return Err(Errno::ENOBUFS);
                }
                return if line.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(line))
                };
            }

            // `read_line_full()` recognizes CR, LF, and NUL as line delimiters.
            // Consume at most a bounded chunk so an unterminated procfs record
            // never makes Rust allocate past LONG_LINE_MAX.
            let marker = buffer
                .iter()
                .position(|byte| matches!(*byte, b'\n' | b'\r' | 0));
            let content_len = marker.unwrap_or(buffer.len());
            if line.len().saturating_add(content_len) >= LONG_LINE_MAX {
                return Err(Errno::ENOBUFS);
            }
            line.try_reserve(content_len).map_err(|_| Errno::ENOMEM)?;
            line.extend_from_slice(&buffer[..content_len]);
            (
                marker.map_or(buffer.len(), |index| index + 1),
                marker.is_some(),
            )
        };
        reader.consume(consumed);
        if complete {
            return Ok(Some(line));
        }
    }
}

fn write_sysctl(path: &Path, value: u64) -> Result<(), Errno> {
    // `write_string_file(..., WRITE_STRING_FILE_DISABLE_BUFFER)` opens the
    // existing sysctl for writing without O_TRUNC and writes one newline-
    // terminated record. Do the same; avoiding `std::fs::write()` is
    // important because it would add O_TRUNC on normal fixture files.
    let mut file = io_result(OpenOptions::new().write(true).open(path))?;
    let mut encoded = value.to_string();
    encoded.push('\n');
    io_result(file.write_all(encoded.as_bytes()))?;
    io_result(file.flush())
}

fn first_word_after<'a>(line: &'a [u8], word: &[u8]) -> Option<&'a [u8]> {
    if word.is_empty() {
        return Some(line);
    }
    let rest = line.strip_prefix(word)?;
    if rest.is_empty() {
        return Some(rest);
    }
    if !is_ascii_whitespace(rest[0]) {
        return None;
    }
    Some(
        &rest[rest
            .iter()
            .take_while(|byte| is_ascii_whitespace(**byte))
            .count()..],
    )
}

fn calc_gcd64(mut a: u64, mut b: u64) -> u64 {
    while b > 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

fn clock_ticks_per_second() -> Result<u64, Errno> {
    // SAFETY: `sysconf` has no pointer or ownership preconditions. C caches
    // this exact `_SC_CLK_TCK` value; querying it per call is semantically
    // equivalent for the POSIX constant and avoids mutable global state.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 {
        // Current C asserts here. Returning a deterministic error is safer in
        // a C ABI library while preserving the no-output-on-failure contract.
        return Err(Errno::EIO);
    }
    Ok(ticks as u64)
}

fn parse_cpu_field(value: &[u8]) -> Option<libc::c_ulong> {
    // /proc/stat is parsed by `sscanf("%lu")`, which is decimal (unlike
    // `safe_atou64()`'s base-zero grammar) and accepts an optional sign.
    let (negative, digits) = match value.first() {
        Some(b'+') => (false, &value[1..]),
        Some(b'-') => (true, &value[1..]),
        _ => (false, value),
    };
    if digits.is_empty() {
        return None;
    }
    let mut result: libc::c_ulong = 0;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        result = result
            .checked_mul(10)?
            .checked_add((byte - b'0') as libc::c_ulong)?;
    }
    Some(if negative {
        result.wrapping_neg()
    } else {
        result
    })
}

fn procfs_get_u64(path: &Path) -> Result<u64, Errno> {
    let value = read_one_line(path)?;
    parse_u64_systemd_bytes(&value)
}

fn procfs_get_pid_max_at(path: &Path) -> Result<u64, Errno> {
    procfs_get_u64(path)
}

fn procfs_get_threads_max_at(path: &Path) -> Result<u64, Errno> {
    procfs_get_u64(path)
}

fn procfs_tasks_set_limit_at(
    pid_max_path: &Path,
    threads_max_path: &Path,
    limit: u64,
) -> Result<(), Errno> {
    if limit == 0 {
        return Err(Errno::EINVAL);
    }

    let limit = limit.clamp(TASKS_MIN, TASKS_MAX);
    let pid_max = procfs_get_pid_max_at(pid_max_path)?;

    // Keep C's unsigned `pid_max - 1` semantics even for malformed fixture
    // input, but spell them explicitly so Rust cannot panic in debug builds.
    let pid_limit = pid_max.wrapping_sub(1);
    if limit > pid_limit {
        let new_pid_max = limit.checked_add(1).ok_or(Errno::ERANGE)?;
        write_sysctl(pid_max_path, new_pid_max)?;
    }

    match write_sysctl(threads_max_path, limit) {
        Ok(()) => Ok(()),
        Err(original_error) => match procfs_get_threads_max_at(threads_max_path) {
            Ok(threads_max) if pid_limit.min(threads_max) == limit => Ok(()),
            _ => Err(original_error),
        },
    }
}

fn procfs_tasks_get_current_at(path: &Path) -> Result<u64, Errno> {
    let value = read_one_line(path)?;
    let slash = value
        .iter()
        .position(|byte| *byte == b'/')
        .ok_or(Errno::EINVAL)?;
    let digits_len = value[slash + 1..]
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    parse_u64_systemd_bytes(&value[slash + 1..slash + 1 + digits_len])
}

fn procfs_cpu_get_usage_at(path: &Path) -> Result<u64, Errno> {
    let first_line = read_one_line(path)?;
    let fields = first_word_after(&first_line, b"cpu").ok_or(Errno::EINVAL)?;
    let mut fields = fields
        .split(|byte| is_ascii_whitespace(*byte))
        .filter(|field| !field.is_empty());
    let mut next_required = || fields.next().and_then(parse_cpu_field).ok_or(Errno::EINVAL);
    let user_ticks = next_required()?;
    let nice_ticks = next_required()?;
    let system_ticks = next_required()?;
    let _idle_ticks = next_required()?;
    let _iowait_ticks = next_required()?;
    let irq_ticks = next_required()?;
    let softirq_ticks = next_required()?;

    // C's sscanf() only insists on the five assigned fields above. Failure or
    // absence at the eighth (discarded) conversion stops the scan after those
    // assignments and leaves both optional guest counters at zero.
    let mut guest_ticks = 0;
    let mut guest_nice_ticks = 0;
    if fields.next().and_then(parse_cpu_field).is_some() {
        if let Some(value) = fields.next().and_then(parse_cpu_field) {
            guest_ticks = value;
            if let Some(value) = fields.next().and_then(parse_cpu_field) {
                guest_nice_ticks = value;
            }
        }
    }

    let sum = (user_ticks as u64)
        .wrapping_add(nice_ticks as u64)
        .wrapping_add(system_ticks as u64)
        .wrapping_add(irq_ticks as u64)
        .wrapping_add(softirq_ticks as u64)
        .wrapping_add(guest_ticks as u64)
        .wrapping_add(guest_nice_ticks as u64);

    let ticks_per_second = clock_ticks_per_second()?;
    let gcd = calc_gcd64(NSEC_PER_SEC, ticks_per_second);
    let numerator_factor = NSEC_PER_SEC / gcd;
    let denominator_factor = ticks_per_second / gcd;
    let value = sum.wrapping_mul(numerator_factor);
    Ok(value / denominator_factor + u64::from(!value.is_multiple_of(denominator_factor)))
}

/// Parse a meminfo value string and convert to bytes.
pub fn convert_meminfo_value_to_uint64_bytes(s: &str) -> Result<u64, Errno> {
    let Some((word, remainder)) = crate::extract_word::extract_first_word(s, None, 0)? else {
        return Err(Errno::EINVAL);
    };
    if remainder != "kB" {
        return Err(Errno::EINVAL);
    }

    let v = parse_u64_systemd(&word)?;
    if v == u64::MAX {
        return Err(Errno::EINVAL);
    }
    v.checked_mul(1024).ok_or(Errno::EOVERFLOW)
}

fn convert_meminfo_value_to_bytes(value: &[u8]) -> Result<u64, Errno> {
    let mut value = value;
    while value.first().is_some_and(|byte| is_ascii_whitespace(*byte)) {
        value = &value[1..];
    }
    let number_len = value
        .iter()
        .position(|byte| is_ascii_whitespace(*byte))
        .unwrap_or(value.len());
    let number = &value[..number_len];
    let mut unit = &value[number_len..];
    while unit.first().is_some_and(|byte| is_ascii_whitespace(*byte)) {
        unit = &unit[1..];
    }
    // C checks `streq(s, "kB")` after extracting the first word, so even
    // trailing whitespace after the unit is significant and must be rejected.
    if unit != b"kB" {
        return Err(Errno::EINVAL);
    }
    let number = parse_u64_systemd_bytes(number)?;
    if number == u64::MAX {
        return Err(Errno::EINVAL);
    }
    number.checked_mul(1024).ok_or(Errno::EOVERFLOW)
}

fn procfs_memory_get_at(path: &Path) -> Result<(u64, u64), Errno> {
    let mut reader = open_proc_reader(path)?;
    let mut total = None;
    let mut available = None;

    while total.is_none() || available.is_none() {
        let line = read_proc_line(&mut reader)?.ok_or(Errno::EINVAL)?;
        if let Some(value) = first_word_after(&line, b"MemTotal:") {
            total = Some(convert_meminfo_value_to_bytes(value)?);
        } else if let Some(value) = first_word_after(&line, b"MemAvailable:") {
            available = Some(convert_meminfo_value_to_bytes(value)?);
        }
    }

    let (Some(total), Some(available)) = (total, available) else {
        // The loop condition makes this unreachable unless the control flow
        // above changes. Keep the daemon-facing API fail-closed instead of
        // retaining a panic as an undocumented invariant.
        return Err(Errno::EIO);
    };
    if available > total {
        return Err(Errno::EINVAL);
    }
    Ok((total, total - available))
}

pub fn procfs_get_pid_max() -> Result<u64, Errno> {
    procfs_get_pid_max_at(Path::new(PID_MAX_PATH))
}

pub fn procfs_get_threads_max() -> Result<u64, Errno> {
    procfs_get_threads_max_at(Path::new(THREADS_MAX_PATH))
}

pub fn procfs_tasks_set_limit(limit: u64) -> Result<(), Errno> {
    procfs_tasks_set_limit_at(Path::new(PID_MAX_PATH), Path::new(THREADS_MAX_PATH), limit)
}

pub fn procfs_tasks_get_current() -> Result<u64, Errno> {
    procfs_tasks_get_current_at(Path::new(LOADAVG_PATH))
}

pub fn procfs_cpu_get_usage() -> Result<u64, Errno> {
    procfs_cpu_get_usage_at(Path::new(STAT_PATH))
}

pub fn procfs_memory_get() -> Result<(u64, u64), Errno> {
    procfs_memory_get_at(Path::new(MEMINFO_PATH))
}

/// # Safety
/// `s` must point to a live NUL-terminated C string and `ret` must point to
/// writable `uint64_t` storage for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_convert_meminfo_value_to_uint64_bytes(
    s: *const c_char,
    ret: *mut u64,
) -> libc::c_int {
    if s.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: required by the entry point contract and checked for NULL.
    let input = match unsafe { CStr::from_ptr(s) }.to_str() {
        Ok(input) => input,
        Err(_) => return Errno::EINVAL.to_neg_errno(),
    };
    let value = match convert_meminfo_value_to_uint64_bytes(input) {
        Ok(value) => value,
        Err(error) => return error.to_neg_errno(),
    };
    // SAFETY: `ret` is non-NULL and writable by the entry point contract.
    unsafe { *ret = value };
    0
}

/// # Safety
/// `ret` must point to writable `uint64_t` storage for the duration of this
/// call. A NULL output is rejected with `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_procfs_get_pid_max(ret: *mut u64) -> libc::c_int {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    let value = match procfs_get_pid_max() {
        Ok(value) => value,
        Err(error) => return error.to_neg_errno(),
    };
    // SAFETY: validated non-NULL output required by this ABI.
    unsafe { *ret = value };
    0
}

/// # Safety
/// `ret` must point to writable `uint64_t` storage for the duration of this
/// call. A NULL output is rejected with `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_procfs_get_threads_max(ret: *mut u64) -> libc::c_int {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    let value = match procfs_get_threads_max() {
        Ok(value) => value,
        Err(error) => return error.to_neg_errno(),
    };
    // SAFETY: validated non-NULL output required by this ABI.
    unsafe { *ret = value };
    0
}

/// # Safety
/// `ret` must point to writable `uint64_t` storage for the duration of this
/// call. A NULL output is rejected with `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_procfs_tasks_get_current(ret: *mut u64) -> libc::c_int {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    let value = match procfs_tasks_get_current() {
        Ok(value) => value,
        Err(error) => return error.to_neg_errno(),
    };
    // SAFETY: validated non-NULL output required by this ABI.
    unsafe { *ret = value };
    0
}

/// # Safety
/// `ret` must point to writable `uint64_t` storage for the duration of this
/// call. A NULL output is rejected with `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_procfs_cpu_get_usage(ret: *mut u64) -> libc::c_int {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    let value = match procfs_cpu_get_usage() {
        Ok(value) => value,
        Err(error) => return error.to_neg_errno(),
    };
    // SAFETY: validated non-NULL output required by this ABI.
    unsafe { *ret = value };
    0
}

/// # Safety
/// Both outputs are optional, exactly as in `procfs_memory_get()`. Any
/// non-NULL pointer must designate writable `uint64_t` storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_procfs_memory_get(
    ret_total: *mut u64,
    ret_used: *mut u64,
) -> libc::c_int {
    let (total, used) = match procfs_memory_get() {
        Ok(value) => value,
        Err(error) => return error.to_neg_errno(),
    };
    // SAFETY: optional outputs are written only after successful validation.
    unsafe {
        if !ret_total.is_null() {
            *ret_total = total;
        }
        if !ret_used.is_null() {
            *ret_used = used;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_procfs_tasks_set_limit(limit: u64) -> libc::c_int {
    match procfs_tasks_set_limit(limit) {
        Ok(()) => 0,
        Err(error) => error.to_neg_errno(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_base_zero_matches_safe_atou64_contract() {
        assert_eq!(parse_u64_systemd_bytes(b"0x10"), Ok(16));
        assert_eq!(parse_u64_systemd_bytes(b"0b11"), Ok(3));
        assert_eq!(parse_u64_systemd_bytes(b"0o10"), Ok(8));
        assert_eq!(parse_u64_systemd_bytes(b"  +42"), Ok(42));
        assert_eq!(parse_u64_systemd_bytes(b"+0b1"), Err(Errno::EINVAL));
        assert_eq!(parse_u64_systemd_bytes(b"-0o0"), Err(Errno::EINVAL));
        assert_eq!(parse_u64_systemd_bytes(b"-0"), Ok(0));
        assert_eq!(parse_u64_systemd_bytes(b"09"), Err(Errno::EINVAL));
        assert_eq!(parse_u64_systemd_bytes(b"-1"), Err(Errno::ERANGE));
    }

    #[test]
    fn meminfo_value_parser_requires_exact_unit_and_overflow_rules() {
        assert_eq!(convert_meminfo_value_to_bytes(b"1 kB"), Ok(1024));
        assert_eq!(convert_meminfo_value_to_bytes(b"1 KB"), Err(Errno::EINVAL));
        assert_eq!(
            convert_meminfo_value_to_bytes(b"18446744073709551615 kB"),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            convert_meminfo_value_to_bytes(b"18014398509481984 kB"),
            Err(Errno::EOVERFLOW)
        );
    }
}
