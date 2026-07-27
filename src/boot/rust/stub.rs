// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/stub.c
//
// systemd-stub UKI (Unified Kernel Image) boot logic.
//
// Implements the stub's role in combining initrds, measuring sections,
// processing command line arguments, loading addons, and exporting
// EFI variables for the booted system.

// ── Constants ─────────────────────────────────────────────────────────────

/// Initrd slot indices, matching the C enum.
pub const INITRD_UCODE: usize = 0;
pub const INITRD_BASE: usize = 1;
pub const INITRD_CREDENTIAL: usize = 2;
pub const INITRD_GLOBAL_CREDENTIAL: usize = 3;
pub const INITRD_SYSEXT: usize = 4;
pub const INITRD_GLOBAL_SYSEXT: usize = 5;
pub const INITRD_CONFEXT: usize = 6;
pub const INITRD_GLOBAL_CONFEXT: usize = 7;
pub const INITRD_PCRSIG: usize = 8;
pub const INITRD_PCRPKEY: usize = 9;
pub const INITRD_OSREL: usize = 10;
pub const INITRD_PROFILE: usize = 11;
pub const INITRD_BOOT_SECRET: usize = 12;
pub const INITRD_MAX: usize = 13;
pub const INITRD_DYNAMIC_FIRST: usize = 2;

/// Stub feature flags exported via EFI variables.
pub const EFI_STUB_FEATURE_REPORT_BOOT_PARTITION: u64 = 1 << 0;
pub const EFI_STUB_FEATURE_PICK_UP_CREDENTIALS: u64 = 1 << 1;
pub const EFI_STUB_FEATURE_PICK_UP_SYSEXTS: u64 = 1 << 2;
pub const EFI_STUB_FEATURE_PICK_UP_CONFEXTS: u64 = 1 << 3;
pub const EFI_STUB_FEATURE_THREE_PCRS: u64 = 1 << 4;
pub const EFI_STUB_FEATURE_RANDOM_SEED: u64 = 1 << 5;
pub const EFI_STUB_FEATURE_CMDLINE_ADDONS: u64 = 1 << 6;
pub const EFI_STUB_FEATURE_CMDLINE_SMBIOS: u64 = 1 << 7;
pub const EFI_STUB_FEATURE_DEVICETREE_ADDONS: u64 = 1 << 8;
pub const EFI_STUB_FEATURE_MULTI_PROFILE_UKI: u64 = 1 << 9;
pub const EFI_STUB_FEATURE_REPORT_STUB_PARTITION: u64 = 1 << 10;
pub const EFI_STUB_FEATURE_REPORT_URL: u64 = 1 << 11;

// ── Types ─────────────────────────────────────────────────────────────────

/// Represents an initrd iovec (base pointer + length).
#[derive(Debug, Clone, Default)]
pub struct InitrdSegment {
    pub data: Vec<u8>,
}

/// Named addon with filename and blob.
#[derive(Debug, Clone, Default)]
pub struct NamedAddon {
    pub filename: String,
    pub data: Vec<u8>,
}

/// Error type for stub operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StubError {
    /// Invalid parameter.
    InvalidParameter,
    /// Out of resources.
    OutOfResources,
    /// Section not found.
    NotFound,
    /// Image lacks .linux section.
    NoLinuxSection,
    /// Profile parsing failed.
    InvalidProfile,
}

impl std::fmt::Display for StubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StubError::InvalidParameter => write!(f, "invalid parameter"),
            StubError::OutOfResources => write!(f, "out of resources"),
            StubError::NotFound => write!(f, "section not found"),
            StubError::NoLinuxSection => write!(f, "image lacks .linux section"),
            StubError::InvalidProfile => write!(f, "invalid profile"),
        }
    }
}

impl std::error::Error for StubError {}

// ── Measured flag logic ───────────────────────────────────────────────────

/// Combine the "measured" flag sensibly.
///
/// Mirrors `combine_measured_flag()` in C.
/// - `value < 0`: nothing submitted for measurement yet, keep current.
/// - First write: take as-is.
/// - Later writes: AND with current (can only turn off).
pub fn combine_measured_flag(value: &mut i32, measured: i32) {
    if measured < 0 {
        return;
    }
    *value = if *value < 0 {
        measured
    } else {
        (*value != 0 && measured != 0) as i32
    };
}

// ── Initrd combining ─────────────────────────────────────────────────────

/// Combine multiple initrd segments by concatenation with 4-byte alignment.
///
/// Mirrors `combine_initrds()` in C.
pub fn combine_initrds(initrds: &[Option<&InitrdSegment>]) -> Result<Vec<u8>, StubError> {
    let mut total = 0usize;
    for initrd in initrds.iter().flatten() {
        let padded = (initrd.data.len() + 3) & !3;
        total = total.checked_add(padded).ok_or(StubError::OutOfResources)?;
    }

    let mut result = Vec::with_capacity(total);
    for initrd in initrds.iter().flatten() {
        result.extend_from_slice(&initrd.data);
        let pad = (4 - (initrd.data.len() % 4)) % 4;
        result.extend(std::iter::repeat(0u8).take(pad));
    }

    Ok(result)
}

// ── Profile parsing ───────────────────────────────────────────────────────

/// Parse a profile number from a command line string starting with '@'.
///
/// Mirrors `parse_profile_from_cmdline()` in C.
/// Returns (remaining_cmdline, profile_number).
pub fn parse_profile_from_cmdline(cmdline: &str) -> Result<(&str, u32), StubError> {
    if !cmdline.starts_with('@') {
        return Err(StubError::InvalidProfile);
    }

    let after_at = &cmdline[1..];
    let (num_str, tail) = match after_at.find(|c: char| !c.is_ascii_digit()) {
        Some(pos) => (&after_at[..pos], &after_at[pos..]),
        None => (after_at, ""),
    };

    if num_str.is_empty() {
        return Err(StubError::InvalidProfile);
    }

    let num: u64 = num_str.parse().map_err(|_| StubError::InvalidProfile)?;
    if num > u32::MAX as u64 {
        return Err(StubError::InvalidProfile);
    }

    let remaining = if tail.starts_with(' ') {
        &tail[1..]
    } else {
        tail
    };
    Ok((remaining, num as u32))
}

/// Parse a profile number from a standalone argument.
///
/// Mirrors `parse_profile_from_argument()` in C.
pub fn parse_profile_from_argument(arg: &str) -> Result<u32, StubError> {
    if !arg.starts_with('@') {
        return Err(StubError::InvalidProfile);
    }

    let num_str = &arg[1..];
    let num: u64 = num_str.parse().map_err(|_| StubError::InvalidProfile)?;
    if num > u32::MAX as u64 {
        return Err(StubError::InvalidProfile);
    }

    Ok(num as u32)
}

// ── Stub feature flags ───────────────────────────────────────────────────

/// Build the combined stub features bitmask.
pub fn stub_features() -> u64 {
    EFI_STUB_FEATURE_REPORT_BOOT_PARTITION
        | EFI_STUB_FEATURE_PICK_UP_CREDENTIALS
        | EFI_STUB_FEATURE_PICK_UP_SYSEXTS
        | EFI_STUB_FEATURE_PICK_UP_CONFEXTS
        | EFI_STUB_FEATURE_THREE_PCRS
        | EFI_STUB_FEATURE_RANDOM_SEED
        | EFI_STUB_FEATURE_CMDLINE_ADDONS
        | EFI_STUB_FEATURE_CMDLINE_SMBIOS
        | EFI_STUB_FEATURE_DEVICETREE_ADDONS
        | EFI_STUB_FEATURE_MULTI_PROFILE_UKI
        | EFI_STUB_FEATURE_REPORT_STUB_PARTITION
        | EFI_STUB_FEATURE_REPORT_URL
}

// ── Iovec array extend ───────────────────────────────────────────────────

/// Extend an initrd array with a new segment if non-empty.
///
/// Mirrors `iovec_array_extend()` in C.
pub fn iovec_array_extend(arr: &mut Vec<InitrdSegment>, elem: InitrdSegment) {
    if elem.data.is_empty() {
        return;
    }
    arr.push(elem);
}

// ── Initrds free ──────────────────────────────────────────────────────────

/// Free dynamic initrds (indices >= INITRD_DYNAMIC_FIRST).
///
/// Mirrors `initrds_free()` in C.
pub fn initrds_free_dynamic(initrds: &mut [Option<InitrdSegment>; INITRD_MAX]) {
    for i in INITRD_DYNAMIC_FIRST..INITRD_MAX {
        initrds[i] = None;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combine_measured_flag_negative_measured() {
        let mut val = -1i32;
        combine_measured_flag(&mut val, -1);
        assert_eq!(val, -1);
    }

    #[test]
    fn test_combine_measured_flag_first_write() {
        let mut val = -1i32;
        combine_measured_flag(&mut val, 1);
        assert_eq!(val, 1);
    }

    #[test]
    fn test_combine_measured_flag_first_write_zero() {
        let mut val = -1i32;
        combine_measured_flag(&mut val, 0);
        assert_eq!(val, 0);
    }

    #[test]
    fn test_combine_measured_flag_and_reduce() {
        let mut val = 1i32;
        combine_measured_flag(&mut val, 0);
        assert_eq!(val, 0);
    }

    #[test]
    fn test_combine_measured_flag_stays_true() {
        let mut val = 1i32;
        combine_measured_flag(&mut val, 1);
        assert_eq!(val, 1);
    }

    #[test]
    fn test_combine_initrds_empty() {
        let result = combine_initrds(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_combine_initrds_single() {
        let seg = InitrdSegment {
            data: vec![1, 2, 3],
        };
        let result = combine_initrds(&[Some(&seg)]).unwrap();
        assert_eq!(&result[..3], &[1, 2, 3]);
        assert_eq!(result.len(), 4); // padded to 4
        assert_eq!(result[3], 0);
    }

    #[test]
    fn test_combine_initrds_multiple() {
        let seg1 = InitrdSegment {
            data: vec![0xAA; 5],
        };
        let seg2 = InitrdSegment {
            data: vec![0xBB; 3],
        };
        let result = combine_initrds(&[Some(&seg1), Some(&seg2)]).unwrap();
        assert_eq!(result.len(), 8 + 4); // 5->8 padded + 3->4 padded
    }

    #[test]
    fn test_parse_profile_from_cmdline_valid() {
        let (rest, profile) = parse_profile_from_cmdline("@5 root=/dev/sda1").unwrap();
        assert_eq!(profile, 5);
        assert_eq!(rest, "root=/dev/sda1");
    }

    #[test]
    fn test_parse_profile_from_cmdline_no_space() {
        let (rest, profile) = parse_profile_from_cmdline("@3").unwrap();
        assert_eq!(profile, 3);
        assert_eq!(rest, "");
    }

    #[test]
    fn test_parse_profile_from_cmdline_no_at() {
        assert!(parse_profile_from_cmdline("no_profile").is_err());
    }

    #[test]
    fn test_parse_profile_from_argument_valid() {
        assert_eq!(parse_profile_from_argument("@42").unwrap(), 42);
    }

    #[test]
    fn test_parse_profile_from_argument_invalid() {
        assert!(parse_profile_from_argument("no_at").is_err());
        assert!(parse_profile_from_argument("@not_a_number").is_err());
    }

    #[test]
    fn test_stub_features() {
        let features = stub_features();
        assert_ne!(features, 0);
        assert!(features & EFI_STUB_FEATURE_REPORT_BOOT_PARTITION != 0);
        assert!(features & EFI_STUB_FEATURE_RANDOM_SEED != 0);
    }

    #[test]
    fn test_iovec_array_extend_empty() {
        let mut arr = Vec::new();
        iovec_array_extend(&mut arr, InitrdSegment { data: vec![] });
        assert!(arr.is_empty());
    }

    #[test]
    fn test_iovec_array_extend_nonempty() {
        let mut arr = Vec::new();
        iovec_array_extend(
            &mut arr,
            InitrdSegment {
                data: vec![1, 2, 3],
            },
        );
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn test_initrds_free_dynamic() {
        let mut initrds: [Option<InitrdSegment>; INITRD_MAX] = Default::default();
        initrds[0] = Some(InitrdSegment { data: vec![1] });
        initrds[INITRD_CREDENTIAL] = Some(InitrdSegment { data: vec![2] });
        initrds_free_dynamic(&mut initrds);
        assert!(initrds[0].is_some()); // UCARD not freed
        assert!(initrds[INITRD_CREDENTIAL].is_none()); // dynamic freed
    }
}
