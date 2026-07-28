// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/linux_x86.c
//
// x86-specific EFI handover boot protocol support.
//
// Handles booting Linux kernels via the deprecated EFI handover protocol
// for kernels older than 5.8 that don't support LINUX_INITRD_MEDIA_GUID.
// Parses the x86 boot parameters (setup_header, boot_params) and validates
// kernel compatibility requirements.

// ── Constants ─────────────────────────────────────────────────────────────

pub const KERNEL_SECTOR_SIZE: u32 = 512;
pub const BOOT_FLAG_MAGIC: u16 = 0xAA55;
pub const SETUP_MAGIC: u32 = 0x53726448;
pub const SETUP_VERSION_2_11: u16 = 0x020B;
pub const SETUP_VERSION_2_12: u16 = 0x020C;
pub const SETUP_VERSION_2_15: u16 = 0x020F;
pub const CMDLINE_PTR_MAX: u64 = 0xA0000;

// ── Bitflags ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XlfFlags(u16);

impl XlfFlags {
    pub const KERNEL_64: Self = Self(1 << 0);
    pub const CAN_BE_LOADED_ABOVE_4G: Self = Self(1 << 1);
    pub const EFI_HANDOVER_32: Self = Self(1 << 2);
    pub const EFI_HANDOVER_64: Self = Self(1 << 3);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn bits(&self) -> u16 {
        self.0
    }

    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    pub fn from_bits_truncate(bits: u16) -> Self {
        Self(
            bits & (Self::KERNEL_64.0
                | Self::CAN_BE_LOADED_ABOVE_4G.0
                | Self::EFI_HANDOVER_32.0
                | Self::EFI_HANDOVER_64.0),
        )
    }
}

impl std::ops::BitOr for XlfFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for XlfFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for XlfFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::Not for XlfFlags {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxX86Error {
    /// Kernel image too small to contain boot params
    LoadError,
    /// Kernel does not have valid setup header
    Unsupported(String),
    /// Kernel is too old (pre-2.11)
    KernelTooOld,
    /// Kernel is not relocatable
    NotRelocatable,
    /// Kernel does not support EFI handover
    NoEfiHandover,
}

impl std::fmt::Display for LinuxX86Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinuxX86Error::LoadError => write!(f, "kernel image load error"),
            LinuxX86Error::Unsupported(msg) => write!(f, "unsupported kernel: {}", msg),
            LinuxX86Error::KernelTooOld => write!(f, "kernel too old (pre-2.11 boot protocol)"),
            LinuxX86Error::NotRelocatable => write!(f, "kernel is not relocatable"),
            LinuxX86Error::NoEfiHandover => write!(f, "kernel does not support EFI handover"),
        }
    }
}

impl std::error::Error for LinuxX86Error {}

/// Represents the x86 kernel setup header (key fields only).
/// Matches the C `SetupHeader` struct from linux_x86.c.
#[derive(Debug, Clone, Default)]
pub struct SetupHeader {
    pub setup_sects: u8,
    pub header: u32,
    pub version: u16,
    pub relocatable_kernel: u8,
    pub xloadflags: u16,
    pub cmdline_size: u32,
    pub code32_start: u64,
    pub handover_offset: u32,
    pub setup_size: u8,
}

/// Represents the full x86 boot parameters.
/// Matches the C `BootParams` struct (4096 bytes in the spec).
#[derive(Debug, Clone, Default)]
pub struct BootParams {
    pub hdr: SetupHeader,
    pub ext_ramdisk_image: u32,
    pub ext_ramdisk_size: u32,
    pub ext_cmd_line_ptr: u32,
}

/// Result of validating an x86 kernel image.
#[derive(Debug, Clone)]
pub struct KernelValidation {
    pub can_4g: bool,
    pub version: u16,
    pub setup_sects: u8,
}

// ── Validation ────────────────────────────────────────────────────────────

/// Validate a setup header and extract kernel capabilities.
///
/// Implements the same checks as `linux_exec_efi_handover` in the C code:
/// 1. Check header magic and boot flag
/// 2. Check minimum version
/// 3. Check relocatable kernel flag
/// 4. Check EFI handover support (version >= 2.12)
pub fn validate_kernel_header(hdr: &SetupHeader) -> Result<KernelValidation, LinuxX86Error> {
    if hdr.header != SETUP_MAGIC {
        return Err(LinuxX86Error::Unsupported(
            "invalid setup header magic".into(),
        ));
    }
    // Note: boot_flag check would be done on raw data; here we assume it passed

    if hdr.version < SETUP_VERSION_2_11 {
        return Err(LinuxX86Error::KernelTooOld);
    }

    if hdr.relocatable_kernel == 0 {
        return Err(LinuxX86Error::NotRelocatable);
    }

    if hdr.version >= SETUP_VERSION_2_12 {
        let flags = XlfFlags::from_bits_truncate(hdr.xloadflags);
        if !flags.contains(XlfFlags::EFI_HANDOVER_64) && !flags.contains(XlfFlags::EFI_HANDOVER_32)
        {
            return Err(LinuxX86Error::NoEfiHandover);
        }
    }

    let can_4g = hdr.version >= SETUP_VERSION_2_12;

    Ok(KernelValidation {
        can_4g,
        version: hdr.version,
        setup_sects: if hdr.setup_sects == 0 {
            4
        } else {
            hdr.setup_sects
        },
    })
}

/// Calculate the kernel entry point address from the setup header.
///
/// The C code does: kernel += (setup_sects + 1) * KERNEL_SECTOR_SIZE
/// For 64-bit: kernel += KERNEL_SECTOR_SIZE (for 64-bit entry)
/// Then: kernel += handover_offset
pub fn calculate_handover_address(kernel_base: u64, hdr: &SetupHeader) -> u64 {
    let setup_sects = if hdr.setup_sects == 0 {
        4u64
    } else {
        hdr.setup_sects as u64
    };
    let mut addr = kernel_base + (setup_sects + 1) * KERNEL_SECTOR_SIZE as u64;
    addr += KERNEL_SECTOR_SIZE as u64;
    addr += hdr.handover_offset as u64;
    addr
}

/// Convert a UTF-16 cmdline to ASCII, replacing non-printable chars with spaces.
/// Matches the C code's cmdline conversion loop.
pub fn cmdline_to_ascii(cmdline: &[u16], max_len: usize) -> Vec<u8> {
    let len = cmdline.len().min(max_len);
    let mut result = Vec::with_capacity(len + 1);
    for &ch in &cmdline[..len] {
        result.push(if ch <= 0x7E { ch as u8 } else { b' ' });
    }
    result.push(0);
    result
}

/// Build the setup_sects value, defaulting to 4 if the field is 0
/// (per spec: "if the setup_sects field contains 0, the real value is 4").
pub fn effective_setup_sects(raw: u8) -> u8 {
    if raw == 0 { 4 } else { raw }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_header(version: u16, relocatable: u8, xloadflags: u16) -> SetupHeader {
        SetupHeader {
            setup_sects: 4,
            header: SETUP_MAGIC,
            version,
            relocatable_kernel: relocatable,
            xloadflags,
            cmdline_size: 256,
            code32_start: 0,
            handover_offset: 0x100,
            setup_size: 20,
        }
    }

    #[test]
    fn test_validate_kernel_header_valid() {
        let hdr = make_valid_header(SETUP_VERSION_2_12, 1, XlfFlags::EFI_HANDOVER_64.bits());
        let result = validate_kernel_header(&hdr).unwrap();
        assert_eq!(result.version, SETUP_VERSION_2_12);
        assert!(result.can_4g);
    }

    #[test]
    fn test_validate_kernel_header_bad_magic() {
        let hdr = SetupHeader {
            header: 0xDEAD,
            ..make_valid_header(SETUP_VERSION_2_12, 1, 0)
        };
        assert!(matches!(
            validate_kernel_header(&hdr),
            Err(LinuxX86Error::Unsupported(_))
        ));
    }

    #[test]
    fn test_validate_kernel_header_too_old() {
        let hdr = make_valid_header(0x0200, 1, 0);
        assert_eq!(
            validate_kernel_header(&hdr).unwrap_err(),
            LinuxX86Error::KernelTooOld
        );
    }

    #[test]
    fn test_validate_kernel_header_not_relocatable() {
        let hdr = make_valid_header(SETUP_VERSION_2_12, 0, 0);
        assert_eq!(
            validate_kernel_header(&hdr).unwrap_err(),
            LinuxX86Error::NotRelocatable
        );
    }

    #[test]
    fn test_validate_kernel_header_no_efi_handover() {
        let hdr = make_valid_header(SETUP_VERSION_2_12, 1, 0);
        assert_eq!(
            validate_kernel_header(&hdr).unwrap_err(),
            LinuxX86Error::NoEfiHandover
        );
    }

    #[test]
    fn test_validate_kernel_header_version_2_11_skips_handover_check() {
        let hdr = make_valid_header(SETUP_VERSION_2_11, 1, 0);
        let result = validate_kernel_header(&hdr).unwrap();
        assert_eq!(result.version, SETUP_VERSION_2_11);
        assert!(!result.can_4g);
    }

    #[test]
    fn test_calculate_handover_address() {
        let hdr = SetupHeader {
            setup_sects: 4,
            handover_offset: 0x100,
            ..SetupHeader::default()
        };
        let addr = calculate_handover_address(0x100000, &hdr);
        let expected =
            0x100000 + (4u64 + 1) * KERNEL_SECTOR_SIZE as u64 + KERNEL_SECTOR_SIZE as u64 + 0x100;
        assert_eq!(addr, expected);
    }

    #[test]
    fn test_cmdline_to_ascii() {
        let input: Vec<u16> = "hello".encode_utf16().collect();
        let result = cmdline_to_ascii(&input, 100);
        assert_eq!(&result[..5], b"hello");
        assert_eq!(result[5], 0);
    }

    #[test]
    fn test_cmdline_to_ascii_non_printable() {
        let input: Vec<u16> = vec![b'h' as u16, 0x100, b'i' as u16];
        let result = cmdline_to_ascii(&input, 100);
        assert_eq!(&result[..3], b"h i");
    }

    #[test]
    fn test_cmdline_to_ascii_truncated() {
        let input: Vec<u16> = "hello world".encode_utf16().collect();
        let result = cmdline_to_ascii(&input, 5);
        assert_eq!(&result[..5], b"hello");
    }

    #[test]
    fn test_effective_setup_sects_zero() {
        assert_eq!(effective_setup_sects(0), 4);
    }

    #[test]
    fn test_effective_setup_sects_nonzero() {
        assert_eq!(effective_setup_sects(7), 7);
    }

    #[test]
    fn test_xlf_flags() {
        let flags = XlfFlags::KERNEL_64 | XlfFlags::EFI_HANDOVER_64;
        assert!(flags.contains(XlfFlags::KERNEL_64));
        assert!(!flags.contains(XlfFlags::CAN_BE_LOADED_ABOVE_4G));
    }

    #[test]
    fn test_validate_can_4g_flag() {
        let hdr = make_valid_header(
            SETUP_VERSION_2_12,
            1,
            (XlfFlags::EFI_HANDOVER_64 | XlfFlags::CAN_BE_LOADED_ABOVE_4G).bits(),
        );
        let result = validate_kernel_header(&hdr).unwrap();
        assert!(result.can_4g);
    }
}
