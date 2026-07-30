// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/cpu-set-util.c, src/shared/cpu-set-util.h
//
// CPU set management utilities.
//
// Wraps the Linux CPU_SET / sched_getaffinity / sched_setaffinity APIs
// for managing which CPUs a process can run on. Uses BTreeSet<u32>
// internally for ergonomic, safe CPU membership tracking with
// deterministic iteration order.

use std::collections::BTreeSet;
use std::fmt;
#[cfg(target_os = "linux")]
use std::fs;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum number of CPUs supported (kernel 5.1+ PowerPC allows 8192).
pub const CPU_SET_MAX_NCPU: u32 = 8192;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors produced by CPU set operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuSetError {
    /// CPU number exceeds the maximum supported value.
    CpuTooLarge(u32),
    /// CPU range is invalid (start > end).
    InvalidRange { start: u32, end: u32 },
    /// Failed to parse a CPU set string.
    InvalidFormat(String),
    /// The CPU set is empty where a non-empty set was required.
    EmptySet,
    /// OS error from sched_getaffinity / sched_setaffinity.
    OsError(i32),
    /// sysconf(_SC_NPROCESSORS_ONLN) failed or returned zero.
    NprocessorsFailed(i32),
}

impl fmt::Display for CpuSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CpuTooLarge(cpu) => {
                write!(f, "CPU {} exceeds maximum ({})", cpu, CPU_SET_MAX_NCPU)
            }
            Self::InvalidRange { start, end } => {
                write!(f, "Invalid CPU range: {} > {}", start, end)
            }
            Self::InvalidFormat(s) => write!(f, "Invalid CPU set format: {}", s),
            Self::EmptySet => write!(f, "CPU set is empty"),
            Self::OsError(e) => write!(f, "OS error: {}", e),
            Self::NprocessorsFailed(e) => {
                write!(f, "Failed to get number of processors: {}", e)
            }
        }
    }
}

impl std::error::Error for CpuSetError {}

// ── CpuSet struct ─────────────────────────────────────────────────────────

/// A set of CPU identifiers, backed by a `BTreeSet<u32>`.
///
/// Supports range-based parsing (`"0-3,5,7"`), serialization in multiple
/// formats (individual, range-compressed, hex mask), and interaction with
/// Linux scheduler affinity syscalls.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct CpuSet {
    cpus: BTreeSet<u32>,
}

impl CpuSet {
    // ── Construction ──────────────────────────────────────────────────

    /// Create a new empty CPU set.
    pub fn new() -> Self {
        Self {
            cpus: BTreeSet::new(),
        }
    }

    // ── Mutation ──────────────────────────────────────────────────────

    /// Add a single CPU to the set.
    ///
    /// Returns an error if `cpu` exceeds `CPU_SET_MAX_NCPU`.
    pub fn add(&mut self, cpu: u32) -> Result<(), CpuSetError> {
        if cpu >= CPU_SET_MAX_NCPU {
            return Err(CpuSetError::CpuTooLarge(cpu));
        }
        self.cpus.insert(cpu);
        Ok(())
    }

    /// Remove a single CPU from the set. No-op if not present.
    pub fn remove(&mut self, cpu: u32) {
        self.cpus.remove(&cpu);
    }

    /// Add a range of CPUs `[start, end]` inclusive.
    ///
    /// Returns an error if `start > end` or `end` exceeds `CPU_SET_MAX_NCPU`.
    pub fn add_range(&mut self, start: u32, end: u32) -> Result<(), CpuSetError> {
        if start > end {
            return Err(CpuSetError::InvalidRange { start, end });
        }
        if end >= CPU_SET_MAX_NCPU {
            return Err(CpuSetError::CpuTooLarge(end));
        }
        for cpu in start..=end {
            self.cpus.insert(cpu);
        }
        Ok(())
    }

    /// Add all CPUs from another CPU set into this one.
    pub fn add_set(&mut self, src: &CpuSet) -> Result<(), CpuSetError> {
        for &cpu in &src.cpus {
            self.add(cpu)?;
        }
        Ok(())
    }

    /// Add all online CPUs as reported by `sysconf(_SC_NPROCESSORS_ONLN)`.
    #[cfg(target_os = "linux")]
    pub fn add_all(&mut self) -> Result<(), CpuSetError> {
        // SAFETY: sysconf is a simple read-only syscall wrapper.
        let nprocs = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if nprocs < 0 {
            let errno = crate::ffi::get_errno();
            return Err(CpuSetError::NprocessorsFailed(errno));
        }
        if nprocs == 0 {
            return Err(CpuSetError::NprocessorsFailed(0));
        }
        self.add_range(0, (nprocs as u32) - 1)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn add_all(&mut self) -> Result<(), CpuSetError> {
        Err(CpuSetError::OsError(-1))
    }

    // ── Query ─────────────────────────────────────────────────────────

    /// Check whether the set contains the given CPU.
    pub fn contains(&self, cpu: u32) -> bool {
        self.cpus.contains(&cpu)
    }

    /// Count the number of CPUs in the set.
    pub fn count(&self) -> usize {
        self.cpus.len()
    }

    /// Check if the CPU set is empty.
    pub fn is_empty(&self) -> bool {
        self.cpus.is_empty()
    }

    /// Equality comparison (also available via `==` through the `PartialEq` derive).
    pub fn equal(&self, other: &CpuSet) -> bool {
        self.cpus == other.cpus
    }

    /// Return an iterator over the CPUs in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.cpus.iter().copied()
    }

    // ── Parsing ───────────────────────────────────────────────────────

    /// Parse a CPU set from a string (strict mode).
    ///
    /// Supports comma-or-whitespace-separated CPU numbers and ranges.
    ///
    /// ```ignore
    /// let set = CpuSet::parse("0-3,5,7").unwrap();
    /// ```
    ///
    /// Any parse error is returned immediately.
    pub fn parse(s: &str) -> Result<Self, CpuSetError> {
        Self::parse_full(s, false)
    }

    /// Parse a CPU set from a string with configurable strictness.
    ///
    /// When `lenient` is true, invalid tokens are silently skipped
    /// (matching the C `config_parse_cpu_set` behaviour with `ltype=0`).
    /// When `lenient` is false, the first parse error is returned.
    pub fn parse_full(s: &str, lenient: bool) -> Result<Self, CpuSetError> {
        let mut set = Self::new();
        let input = s.trim();

        if input.is_empty() {
            return Ok(set);
        }

        for token in input.split(|c: char| c == ',' || c.is_whitespace()) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }

            if let Some(dash_pos) = token.find('-') {
                let start_str = &token[..dash_pos];
                let end_str = &token[dash_pos + 1..];

                let start: u32 = match start_str.parse() {
                    Ok(v) => v,
                    Err(_) if lenient => continue,
                    Err(_) => {
                        return Err(CpuSetError::InvalidFormat(format!(
                            "invalid CPU number: {}",
                            start_str
                        )));
                    }
                };
                let end: u32 = match end_str.parse() {
                    Ok(v) => v,
                    Err(_) if lenient => continue,
                    Err(_) => {
                        return Err(CpuSetError::InvalidFormat(format!(
                            "invalid CPU number: {}",
                            end_str
                        )));
                    }
                };

                if start > end {
                    if lenient {
                        continue;
                    }
                    return Err(CpuSetError::InvalidRange { start, end });
                }

                match set.add_range(start, end) {
                    Ok(()) => {}
                    Err(_) if lenient => continue,
                    Err(e) => return Err(e),
                }
            } else {
                let cpu: u32 = match token.parse() {
                    Ok(v) => v,
                    Err(_) if lenient => continue,
                    Err(_) => {
                        return Err(CpuSetError::InvalidFormat(format!(
                            "invalid CPU number: {}",
                            token
                        )));
                    }
                };

                match set.add(cpu) {
                    Ok(()) => {}
                    Err(_) if lenient => continue,
                    Err(e) => return Err(e),
                }
            }
        }

        Ok(set)
    }

    // ── Serialization ─────────────────────────────────────────────────

    /// Serialize as a space-separated list of individual CPU numbers.
    ///
    /// Example: `CpuSet` containing {0, 5, 10} → `"0 5 10"`
    #[expect(
        clippy::inherent_to_string_shadow_display,
        reason = "the established API exposes individual CPUs while Display intentionally renders ranges"
    )]
    pub fn to_string(&self) -> String {
        self.cpus
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Serialize as a space-separated list of CPU ranges.
    ///
    /// Example: `CpuSet` containing {0,1,2,3,5,7,8,9} → `"0-3 5 7-9"`
    pub fn to_range_string(&self) -> String {
        if self.cpus.is_empty() {
            return String::new();
        }

        let mut parts: Vec<String> = Vec::new();
        let mut iter = self.cpus.iter().peekable();

        while let Some(&start) = iter.next() {
            let mut end = start;
            while iter.peek() == Some(&&(end + 1)) {
                end += 1;
                iter.next();
            }
            if start == end {
                parts.push(start.to_string());
            } else {
                parts.push(format!("{}-{}", start, end));
            }
        }

        parts.join(" ")
    }

    /// Serialize as a hexadecimal bitmask string.
    ///
    /// Groups of 32 CPUs are represented as hex values, separated by commas.
    /// The most-significant non-zero group omits leading zeros.
    ///
    /// | CPUs        | Output             |
    /// |-------------|--------------------|
    /// | {0}         | `"1"`              |
    /// | {1}         | `"2"`              |
    /// | {0,1}       | `"3"`              |
    /// | {0-3}       | `"f"`              |
    /// | {0-7}       | `"ff"`             |
    /// | {4-7}       | `"f0"`             |
    /// | {7}         | `"80"`             |
    /// | {}          | `"0"`              |
    /// | {0-47}      | `"ffff,ffffffff"`  |
    pub fn to_mask_string(&self) -> String {
        if self.cpus.is_empty() {
            return "0".to_string();
        }

        let max_cpu = *self.cpus.last().unwrap();
        let num_groups = ((max_cpu as usize + 32) / 32).max(1);
        let mut groups: Vec<u32> = vec![0u32; num_groups];

        for &cpu in &self.cpus {
            let group_idx = cpu as usize / 32;
            let bit_idx = cpu as usize % 32;
            groups[group_idx] |= 1u32 << bit_idx;
        }

        // Trim trailing zero groups.
        let mut highest = groups.len();
        while highest > 0 && groups[highest - 1] == 0 {
            highest -= 1;
        }
        if highest == 0 {
            return "0".to_string();
        }

        let mut result = String::new();
        let mut found_nonzero = false;
        for i in (0..highest).rev() {
            if !found_nonzero {
                if groups[i] == 0 {
                    continue;
                }
                result.push_str(&format!("{:x}", groups[i]));
                found_nonzero = true;
            } else {
                result.push_str(&format!(",{:08x}", groups[i]));
            }
        }

        result
    }

    // ── D-Bus serialization ───────────────────────────────────────────

    /// Convert to a byte array suitable for D-Bus transmission.
    ///
    /// Each byte represents 8 CPUs (bit 0 = lowest CPU in that byte).
    pub fn to_dbus(&self) -> Vec<u8> {
        if self.cpus.is_empty() {
            return Vec::new();
        }

        let max_cpu = *self.cpus.last().unwrap();
        let size = (max_cpu as usize).div_ceil(8);
        let mut buf = vec![0u8; size];

        for &cpu in &self.cpus {
            let byte_idx = cpu as usize / 8;
            let bit_idx = cpu as usize % 8;
            buf[byte_idx] |= 1u8 << bit_idx;
        }

        buf
    }

    /// Parse a CPU set from a byte array received via D-Bus.
    ///
    /// Each byte represents 8 CPUs (bit 0 = lowest CPU in that byte).
    /// CPUs at or above `CPU_SET_MAX_NCPU` are silently ignored.
    pub fn from_dbus(bits: &[u8]) -> Self {
        let mut set = Self::new();
        for (byte_idx, &byte) in bits.iter().enumerate() {
            for bit_idx in 0..8u32 {
                if byte & (1u8 << bit_idx) != 0 {
                    let cpu = (byte_idx as u32) * 8 + bit_idx;
                    if cpu < CPU_SET_MAX_NCPU {
                        set.cpus.insert(cpu);
                    }
                }
            }
        }
        set
    }
}

impl fmt::Display for CpuSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_range_string())
    }
}

// ── Scheduler affinity ────────────────────────────────────────────────────

/// Count the number of CPUs in the current process's affinity mask.
///
/// Uses `sched_getaffinity()` with progressively larger buffers until
/// the call succeeds (mirrors the C retry-loop pattern).
#[cfg(target_os = "linux")]
pub fn cpus_in_affinity_mask() -> Result<usize, CpuSetError> {
    let mut n = 16usize;

    loop {
        let size = n.div_ceil(8);
        let mut mask: Vec<u8> = vec![0u8; size];

        // SAFETY: pid=0 (current process), buffer is valid and sized.
        let ret =
            unsafe { libc::sched_getaffinity(0, size, mask.as_mut_ptr() as *mut libc::cpu_set_t) };

        if ret == 0 {
            let count = mask.iter().map(|&b| b.count_ones() as usize).sum();
            if count == 0 {
                return Err(CpuSetError::OsError(libc::EINVAL));
            }
            return Ok(count);
        }

        // SAFETY: reading errno after a failed syscall.
        let errno = crate::ffi::get_errno();
        if errno != libc::EINVAL {
            return Err(CpuSetError::OsError(errno));
        }
        if n > usize::MAX / 2 {
            return Err(CpuSetError::OsError(libc::ENOMEM));
        }
        n *= 2;
    }
}

/// Return the number of CPUs available to the systemd process.
///
/// This starts with the host online-CPU count and, when cgroup v2 exposes an
/// effective cpuset, clamps it to that container limit. This mirrors
/// `cpus_online()` and avoids sizing worker pools for CPUs unavailable to the
/// current cgroup.
#[cfg(target_os = "linux")]
pub fn cpus_online() -> Result<u32, CpuSetError> {
    // SAFETY: sysconf only reads the kernel's online CPU count.
    let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if online < 0 {
        return Err(CpuSetError::NprocessorsFailed(crate::ffi::get_errno()));
    }

    let online = u32::try_from(online).unwrap_or(u32::MAX).max(1);
    let cgroup_limit = fs::read_to_string("/sys/fs/cgroup/cpuset.cpus.effective")
        .ok()
        .and_then(|value| CpuSet::parse(&value).ok())
        .map(|set| u32::try_from(set.count()).unwrap_or(u32::MAX))
        .filter(|count| *count > 0);

    Ok(cgroup_limit.unwrap_or(online).min(online).max(1))
}

#[cfg(not(target_os = "linux"))]
pub fn cpus_online() -> Result<u32, CpuSetError> {
    Err(CpuSetError::OsError(-1))
}

#[cfg(not(target_os = "linux"))]
pub fn cpus_in_affinity_mask() -> Result<usize, CpuSetError> {
    Err(CpuSetError::OsError(-1))
}

/// Get the CPU affinity mask for a process as a `CpuSet`.
///
/// `pid` is the process ID (0 = current process).
#[cfg(target_os = "linux")]
pub fn sched_getaffinity(pid: libc::pid_t) -> Result<CpuSet, CpuSetError> {
    let mut n = 16usize;

    loop {
        let size = n.div_ceil(8);
        let mut mask: Vec<u8> = vec![0u8; size];

        // SAFETY: buffer is valid and sized.
        let ret = unsafe {
            libc::sched_getaffinity(pid, size, mask.as_mut_ptr() as *mut libc::cpu_set_t)
        };

        if ret == 0 {
            return Ok(CpuSet::from_dbus(&mask));
        }

        let errno = crate::ffi::get_errno();
        if errno != libc::EINVAL {
            return Err(CpuSetError::OsError(errno));
        }
        if n > usize::MAX / 2 {
            return Err(CpuSetError::OsError(libc::ENOMEM));
        }
        n *= 2;
    }
}

#[cfg(not(target_os = "linux"))]
pub fn sched_getaffinity(_pid: i32) -> Result<CpuSet, CpuSetError> {
    Err(CpuSetError::OsError(-1))
}

/// Set the CPU affinity mask for a process.
///
/// `pid` is the process ID (0 = current process). Returns `EmptySet` if
/// the set contains no CPUs.
#[cfg(target_os = "linux")]
pub fn sched_setaffinity(pid: libc::pid_t, set: &CpuSet) -> Result<(), CpuSetError> {
    if set.is_empty() {
        return Err(CpuSetError::EmptySet);
    }

    let bytes = set.to_dbus();
    let size = bytes.len();

    // SAFETY: buffer is derived from a valid CpuSet and is correctly sized.
    let ret =
        unsafe { libc::sched_setaffinity(pid, size, bytes.as_ptr() as *const libc::cpu_set_t) };

    if ret == 0 {
        Ok(())
    } else {
        let errno = crate::ffi::get_errno();
        Err(CpuSetError::OsError(errno))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn sched_setaffinity(_pid: i32, _set: &CpuSet) -> Result<(), CpuSetError> {
    Err(CpuSetError::OsError(-1))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Construction ──────────────────────────────────────────────────

    #[test]
    fn test_new_empty() {
        let set = CpuSet::new();
        assert!(set.is_empty());
        assert_eq!(set.count(), 0);
    }

    #[test]
    fn test_default_empty() {
        let set = CpuSet::default();
        assert!(set.is_empty());
        assert_eq!(set.count(), 0);
    }

    // ── Add / remove / contains ───────────────────────────────────────

    #[test]
    fn test_add_and_contains() {
        let mut set = CpuSet::new();
        assert!(!set.contains(0));
        set.add(0).unwrap();
        assert!(set.contains(0));
        set.add(5).unwrap();
        assert!(set.contains(5));
        set.add(8191).unwrap();
        assert!(set.contains(8191));
        assert!(!set.contains(4));
    }

    #[test]
    fn test_add_too_large() {
        let mut set = CpuSet::new();
        let err = set.add(8192).unwrap_err();
        assert_eq!(err, CpuSetError::CpuTooLarge(8192));
    }

    #[test]
    fn test_remove() {
        let mut set = CpuSet::new();
        set.add(3).unwrap();
        set.add(7).unwrap();
        assert!(set.contains(3));
        set.remove(3);
        assert!(!set.contains(3));
        assert!(set.contains(7));
        // Removing non-existent CPU is a no-op.
        set.remove(42);
        assert_eq!(set.count(), 1);
    }

    #[test]
    fn test_add_duplicate() {
        let mut set = CpuSet::new();
        set.add(3).unwrap();
        set.add(3).unwrap();
        assert_eq!(set.count(), 1);
    }

    // ── add_range ─────────────────────────────────────────────────────

    #[test]
    fn test_add_range() {
        let mut set = CpuSet::new();
        set.add_range(2, 5).unwrap();
        assert_eq!(set.count(), 4);
        assert!(set.contains(2));
        assert!(set.contains(3));
        assert!(set.contains(4));
        assert!(set.contains(5));
        assert!(!set.contains(1));
        assert!(!set.contains(6));
    }

    #[test]
    fn test_add_range_single() {
        let mut set = CpuSet::new();
        set.add_range(7, 7).unwrap();
        assert_eq!(set.count(), 1);
        assert!(set.contains(7));
    }

    #[test]
    fn test_add_range_invalid() {
        let mut set = CpuSet::new();
        let err = set.add_range(5, 3).unwrap_err();
        assert_eq!(err, CpuSetError::InvalidRange { start: 5, end: 3 });
    }

    #[test]
    fn test_add_range_too_large() {
        let mut set = CpuSet::new();
        let err = set.add_range(8190, 8192).unwrap_err();
        assert_eq!(err, CpuSetError::CpuTooLarge(8192));
    }

    // ── add_set ───────────────────────────────────────────────────────

    #[test]
    fn test_add_set() {
        let mut a = CpuSet::new();
        let mut b = CpuSet::new();
        a.add(1).unwrap();
        a.add(2).unwrap();
        b.add(2).unwrap();
        b.add(3).unwrap();
        a.add_set(&b).unwrap();
        assert_eq!(a.count(), 3);
        assert!(a.contains(1));
        assert!(a.contains(2));
        assert!(a.contains(3));
    }

    #[test]
    fn test_add_set_empty() {
        let mut a = CpuSet::new();
        let b = CpuSet::new();
        a.add(1).unwrap();
        a.add_set(&b).unwrap();
        assert_eq!(a.count(), 1);
    }

    // ── Equality ──────────────────────────────────────────────────────

    #[test]
    fn test_equality() {
        let mut a = CpuSet::new();
        let mut b = CpuSet::new();
        a.add(1).unwrap();
        a.add(5).unwrap();
        b.add(1).unwrap();
        b.add(5).unwrap();
        assert_eq!(a, b);
        assert!(a.equal(&b));

        b.add(10).unwrap();
        assert_ne!(a, b);
        assert!(!a.equal(&b));
    }

    // ── Parsing ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_simple() {
        let set = CpuSet::parse("0,1,2,3").unwrap();
        assert_eq!(set.count(), 4);
        for i in 0..=3u32 {
            assert!(set.contains(i));
        }
    }

    #[test]
    fn test_parse_ranges() {
        let set = CpuSet::parse("0-3,5,7-9").unwrap();
        assert_eq!(set.count(), 8);
        for i in 0..=3u32 {
            assert!(set.contains(i));
        }
        assert!(set.contains(5));
        for i in 7..=9u32 {
            assert!(set.contains(i));
        }
        assert!(!set.contains(4));
        assert!(!set.contains(6));
        assert!(!set.contains(10));
    }

    #[test]
    fn test_parse_whitespace() {
        let set = CpuSet::parse("0 1 2 3 5").unwrap();
        assert_eq!(set.count(), 5);
        assert!(set.contains(0));
        assert!(set.contains(5));
    }

    #[test]
    fn test_parse_mixed_separators() {
        let set = CpuSet::parse("0-3,5 7").unwrap();
        assert_eq!(set.count(), 6);
        for i in 0..=3u32 {
            assert!(set.contains(i));
        }
        assert!(set.contains(5));
        assert!(set.contains(7));
    }

    #[test]
    fn test_parse_empty_string() {
        let set = CpuSet::parse("").unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn test_parse_whitespace_only() {
        let set = CpuSet::parse("   \t  ").unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn test_parse_invalid_token() {
        assert!(CpuSet::parse("abc").is_err());
        assert!(CpuSet::parse("0-abc").is_err());
        assert!(CpuSet::parse("abc-3").is_err());
    }

    #[test]
    fn test_parse_invalid_range_strict() {
        assert!(CpuSet::parse("5-3").is_err());
    }

    #[test]
    fn test_parse_full_lenient_skips_bad_tokens() {
        let set = CpuSet::parse_full("0,abc,3-5,5-3,7", true).unwrap();
        assert_eq!(set.count(), 5); // 0, 3, 4, 5, 7
        assert!(set.contains(0));
        for i in 3..=5u32 {
            assert!(set.contains(i));
        }
        assert!(set.contains(7));
    }

    #[test]
    fn test_parse_full_strict_fails_on_bad_tokens() {
        assert!(CpuSet::parse_full("0,abc,3", false).is_err());
    }

    #[test]
    fn test_parse_roundtrip() {
        let mut original = CpuSet::new();
        original.add_range(0, 3).unwrap();
        original.add(7).unwrap();
        original.add_range(15, 17).unwrap();
        let s = original.to_range_string();
        let recovered = CpuSet::parse(&s).unwrap();
        assert_eq!(original, recovered);
    }

    // ── Serialization: individual ─────────────────────────────────────

    #[test]
    fn test_to_string_individual() {
        let mut set = CpuSet::new();
        set.add(0).unwrap();
        set.add(5).unwrap();
        set.add(10).unwrap();
        assert_eq!(set.to_string(), "0 5 10");
    }

    #[test]
    fn test_to_string_empty() {
        let set = CpuSet::new();
        assert_eq!(set.to_string(), "");
    }

    // ── Serialization: range ──────────────────────────────────────────

    #[test]
    fn test_to_range_string() {
        let mut set = CpuSet::new();
        set.add_range(0, 3).unwrap();
        set.add(5).unwrap();
        set.add_range(7, 9).unwrap();
        assert_eq!(set.to_range_string(), "0-3 5 7-9");
    }

    #[test]
    fn test_to_range_string_single() {
        let mut set = CpuSet::new();
        set.add(5).unwrap();
        assert_eq!(set.to_range_string(), "5");
    }

    #[test]
    fn test_to_range_string_empty() {
        let set = CpuSet::new();
        assert_eq!(set.to_range_string(), "");
    }

    // ── Serialization: hex mask ───────────────────────────────────────

    #[test]
    fn test_to_mask_string_cpu0() {
        let mut set = CpuSet::new();
        set.add(0).unwrap();
        assert_eq!(set.to_mask_string(), "1");
    }

    #[test]
    fn test_to_mask_string_cpu1() {
        let mut set = CpuSet::new();
        set.add(1).unwrap();
        assert_eq!(set.to_mask_string(), "2");
    }

    #[test]
    fn test_to_mask_string_cpu01() {
        let mut set = CpuSet::new();
        set.add(0).unwrap();
        set.add(1).unwrap();
        assert_eq!(set.to_mask_string(), "3");
    }

    #[test]
    fn test_to_mask_string_nibble() {
        let mut set = CpuSet::new();
        set.add_range(0, 3).unwrap();
        assert_eq!(set.to_mask_string(), "f");
    }

    #[test]
    fn test_to_mask_string_byte() {
        let mut set = CpuSet::new();
        set.add_range(0, 7).unwrap();
        assert_eq!(set.to_mask_string(), "ff");
    }

    #[test]
    fn test_to_mask_string_high_bits() {
        let mut set = CpuSet::new();
        set.add(4).unwrap();
        set.add(5).unwrap();
        set.add(6).unwrap();
        set.add(7).unwrap();
        assert_eq!(set.to_mask_string(), "f0");
    }

    #[test]
    fn test_to_mask_string_cpu7() {
        let mut set = CpuSet::new();
        set.add(7).unwrap();
        assert_eq!(set.to_mask_string(), "80");
    }

    #[test]
    fn test_to_mask_string_empty() {
        let set = CpuSet::new();
        assert_eq!(set.to_mask_string(), "0");
    }

    #[test]
    fn test_to_mask_string_multi_group_48() {
        let mut set = CpuSet::new();
        set.add_range(0, 47).unwrap();
        // CPUs 0-31 → group 0 = 0xffffffff, CPUs 32-47 → group 1 = 0x0000ffff
        assert_eq!(set.to_mask_string(), "ffff,ffffffff");
    }

    #[test]
    fn test_to_mask_string_multi_group_64() {
        let mut set = CpuSet::new();
        set.add_range(0, 63).unwrap();
        assert_eq!(set.to_mask_string(), "ffffffff,ffffffff");
    }

    #[test]
    fn test_to_mask_string_multi_group_72() {
        let mut set = CpuSet::new();
        set.add_range(0, 71).unwrap();
        // Group 0: CPUs 0-31 = 0xffffffff
        // Group 1: CPUs 32-63 = 0xffffffff
        // Group 2: CPUs 64-71 = 0x000000ff
        assert_eq!(set.to_mask_string(), "ff,ffffffff,ffffffff");
    }

    // ── D-Bus roundtrip ───────────────────────────────────────────────

    #[test]
    fn test_to_dbus_roundtrip() {
        let mut set = CpuSet::new();
        set.add(0).unwrap();
        set.add(5).unwrap();
        set.add(15).unwrap();
        let bytes = set.to_dbus();
        let recovered = CpuSet::from_dbus(&bytes);
        assert_eq!(set, recovered);
    }

    #[test]
    fn test_from_dbus_empty() {
        let set = CpuSet::from_dbus(&[]);
        assert!(set.is_empty());
    }

    #[test]
    fn test_from_dbus_bits() {
        let bytes = vec![0xff, 0x01]; // CPUs 0-7, and CPU 8
        let set = CpuSet::from_dbus(&bytes);
        assert_eq!(set.count(), 9);
        for i in 0..=8u32 {
            assert!(set.contains(i));
        }
    }

    // ── Iterator ──────────────────────────────────────────────────────

    #[test]
    fn test_iter_sorted() {
        let mut set = CpuSet::new();
        set.add(5).unwrap();
        set.add(1).unwrap();
        set.add(3).unwrap();
        let collected: Vec<u32> = set.iter().collect();
        assert_eq!(collected, vec![1, 3, 5]);
    }

    // ── Display ───────────────────────────────────────────────────────

    #[test]
    fn test_display_trait() {
        let mut set = CpuSet::new();
        set.add_range(0, 2).unwrap();
        set.add(5).unwrap();
        assert_eq!(format!("{}", set), "0-2 5");
    }

    // ── Clone ─────────────────────────────────────────────────────────

    #[test]
    fn test_clone_independence() {
        let mut set = CpuSet::new();
        set.add(1).unwrap();
        set.add(5).unwrap();
        let mut clone = set.clone();
        clone.add(10).unwrap();
        assert_eq!(set.count(), 2);
        assert_eq!(clone.count(), 3);
        assert!(!set.contains(10));
        assert!(clone.contains(10));
    }

    // ── Count ─────────────────────────────────────────────────────────

    #[test]
    fn test_count_growth() {
        let mut set = CpuSet::new();
        assert_eq!(set.count(), 0);
        set.add(0).unwrap();
        assert_eq!(set.count(), 1);
        set.add_range(10, 19).unwrap();
        assert_eq!(set.count(), 11);
    }

    // ── Error display ─────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        assert!(!CpuSetError::CpuTooLarge(9999).to_string().is_empty());
        assert!(
            !CpuSetError::InvalidRange { start: 5, end: 3 }
                .to_string()
                .is_empty()
        );
        assert!(
            !CpuSetError::InvalidFormat("bad".into())
                .to_string()
                .is_empty()
        );
        assert!(!CpuSetError::EmptySet.to_string().is_empty());
        assert!(!CpuSetError::OsError(22).to_string().is_empty());
    }
}
