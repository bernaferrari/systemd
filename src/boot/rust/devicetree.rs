// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/devicetree.c
//
// Device tree (FDT/DTB) management for systemd-boot.
//
// Handles loading, installing, and matching device tree blobs.
// Parses FDT headers to extract compatible strings for hardware
// matching against firmware-provided device trees.

// ── Constants ─────────────────────────────────────────────────────────────

/// FDT magic number (0xD00DFEED in big-endian).
pub const FDT_MAGIC: u32 = 0xD00D_FEED;

/// Minimum FDT v1 header size (7 × 4 bytes).
pub const FDT_V1_SIZE: usize = 7 * 4;

/// Maximum allowed device tree blob size (32 MB).
pub const FDT_MAX_SIZE: usize = 32 * 1024 * 1024;

/// EFI page size (4 KB).
pub const EFI_PAGE_SIZE: usize = 4096;

/// FDT token: beginning of a node.
pub const FDT_BEGIN_NODE: u32 = 0x0000_0001;
/// FDT token: end of a node.
pub const FDT_END_NODE: u32 = 0x0000_0002;
/// FDT token: property.
pub const FDT_PROP: u32 = 0x0000_0003;
/// FDT token: no-op.
pub const FDT_NOP: u32 = 0x0000_0004;
/// FDT token: end of the structure block.
pub const FDT_END: u32 = 0x0000_0009;

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicetreeError {
    InvalidParameter,
    NotFound,
    Unsupported,
    DeviceError,
    OutOfResources,
    BufferTooSmall,
    InvalidMagic,
    InvalidAlignment,
    BadHeader,
    NoCompatible,
    MatchFailed,
}

impl std::fmt::Display for DevicetreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DevicetreeError::InvalidParameter => write!(f, "invalid parameter"),
            DevicetreeError::NotFound => write!(f, "not found"),
            DevicetreeError::Unsupported => write!(f, "unsupported"),
            DevicetreeError::DeviceError => write!(f, "device error"),
            DevicetreeError::OutOfResources => write!(f, "out of resources"),
            DevicetreeError::BufferTooSmall => write!(f, "buffer too small"),
            DevicetreeError::InvalidMagic => write!(f, "invalid FDT magic"),
            DevicetreeError::InvalidAlignment => write!(f, "invalid alignment"),
            DevicetreeError::BadHeader => write!(f, "bad FDT header"),
            DevicetreeError::NoCompatible => write!(f, "no compatible string"),
            DevicetreeError::MatchFailed => write!(f, "compatible match failed"),
        }
    }
}

impl std::error::Error for DevicetreeError {}

// ── Data structures ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdtHeader {
    pub magic: u32,
    pub total_size: u32,
    pub off_dt_struct: u32,
    pub off_dt_strings: u32,
    pub off_mem_rsvmap: u32,
    pub version: u32,
    pub last_comp_version: u32,
    pub boot_cpuid_phys: u32,
    pub size_dt_strings: u32,
    pub size_dt_struct: u32,
}

impl FdtHeader {
    pub fn parse(data: &[u8]) -> Result<Self, DevicetreeError> {
        if data.len() < FDT_V1_SIZE {
            return Err(DevicetreeError::BufferTooSmall);
        }

        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != FDT_MAGIC {
            return Err(DevicetreeError::InvalidMagic);
        }

        let total_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let off_dt_struct = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let off_dt_strings = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let off_mem_rsvmap = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let version = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let last_comp_version = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
        let boot_cpuid_phys = u32::from_be_bytes([data[28], data[29], data[30], data[31]]);
        let size_dt_strings = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
        let size_dt_struct = u32::from_be_bytes([data[36], data[37], data[38], data[39]]);

        Ok(Self {
            magic,
            total_size,
            off_dt_struct,
            off_dt_strings,
            off_mem_rsvmap,
            version,
            last_comp_version,
            boot_cpuid_phys,
            size_dt_strings,
            size_dt_struct,
        })
    }

    pub fn validate(&self, data_len: usize) -> Result<(), DevicetreeError> {
        if self.total_size as usize > data_len {
            return Err(DevicetreeError::BadHeader);
        }

        let strings_end = self.off_dt_strings as u64 + self.size_dt_strings as u64;
        if strings_end > self.total_size as u64 {
            return Err(DevicetreeError::BadHeader);
        }

        if !self.off_dt_struct.is_multiple_of(4) {
            return Err(DevicetreeError::BadHeader);
        }

        if !self.size_dt_struct.is_multiple_of(4) {
            return Err(DevicetreeError::BadHeader);
        }

        let struct_end = self.off_dt_struct as u64 + self.size_dt_struct as u64;
        if struct_end > self.off_dt_strings as u64 {
            return Err(DevicetreeError::BadHeader);
        }

        Ok(())
    }
}

/// State for a loaded device tree.
#[derive(Debug, Clone, Default)]
pub struct DevicetreeState {
    pub addr: u64,
    pub pages: usize,
    pub orig: u64,
}

impl DevicetreeState {
    pub fn allocated_size(&self) -> usize {
        self.pages * EFI_PAGE_SIZE
    }

    pub fn is_loaded(&self) -> bool {
        self.pages > 0
    }
}

// ── Core functions ────────────────────────────────────────────────────────

/// Calculate the number of pages needed for a given size.
#[expect(
    clippy::manual_div_ceil,
    reason = "Mirrors the C round-up expression, including its established overflow behavior."
)]
pub fn pages_for_size(size: usize) -> usize {
    (size + EFI_PAGE_SIZE - 1) / EFI_PAGE_SIZE
}

/// Validate a device tree blob size.
pub fn validate_dtb_size(size: usize) -> Result<(), DevicetreeError> {
    if size < FDT_V1_SIZE {
        return Err(DevicetreeError::BufferTooSmall);
    }
    if size > FDT_MAX_SIZE {
        return Err(DevicetreeError::InvalidParameter);
    }
    Ok(())
}

/// Extract the first compatible string from a device tree blob.
pub fn devicetree_get_compatible(dtb: &[u8]) -> Result<String, DevicetreeError> {
    let header = FdtHeader::parse(dtb)?;
    header.validate(dtb.len())?;

    let struct_size = header.size_dt_struct as usize;
    let strings_block_start = header.off_dt_strings as usize;
    let strings_size = header.size_dt_strings as usize;

    let struct_start = header.off_dt_struct as usize;
    let struct_end = struct_start + struct_size;

    if struct_end > dtb.len() || strings_block_start + strings_size > dtb.len() {
        return Err(DevicetreeError::BadHeader);
    }

    let struct_data = &dtb[struct_start..struct_end];
    let strings_data = &dtb[strings_block_start..strings_block_start + strings_size];

    let size_words = struct_size / 4;
    let mut i = 0;

    while i < size_words {
        let token = u32::from_be_bytes([
            struct_data[i * 4],
            struct_data[i * 4 + 1],
            struct_data[i * 4 + 2],
            struct_data[i * 4 + 3],
        ]);

        match token {
            FDT_BEGIN_NODE => {
                i += 1;
                if i >= size_words {
                    return Err(DevicetreeError::BadHeader);
                }
                let node_name_start = i * 4;
                let name_null = struct_data[node_name_start..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(0);
                let name_words = (name_null + 4) / 4;
                i += name_words;
            }
            FDT_NOP => {
                i += 1;
            }
            FDT_PROP => {
                if i + 3 >= size_words {
                    return Err(DevicetreeError::BadHeader);
                }
                let len = u32::from_be_bytes([
                    struct_data[(i + 1) * 4],
                    struct_data[(i + 1) * 4 + 1],
                    struct_data[(i + 1) * 4 + 2],
                    struct_data[(i + 1) * 4 + 3],
                ]);
                let name_off = u32::from_be_bytes([
                    struct_data[(i + 2) * 4],
                    struct_data[(i + 2) * 4 + 1],
                    struct_data[(i + 2) * 4 + 2],
                    struct_data[(i + 2) * 4 + 3],
                ]) as usize;

                #[expect(
                    clippy::manual_div_ceil,
                    reason = "Mirrors the C FDT property-word round-up expression."
                )]
                let len_words = ((len as usize) + 3) / 4;

                if name_off + "compatible".len() < strings_size {
                    let name_end = strings_data[name_off..]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(strings_size - name_off);
                    let prop_name =
                        std::str::from_utf8(&strings_data[name_off..name_off + name_end])
                            .unwrap_or("");

                    if prop_name == "compatible" {
                        let data_start = (i + 3) * 4;
                        if len == 0 || data_start + len as usize > struct_data.len() {
                            return Err(DevicetreeError::NoCompatible);
                        }
                        let compat_data = &struct_data[data_start..data_start + len as usize];
                        let compat_str = compat_data
                            .iter()
                            .take_while(|&&b| b != 0)
                            .copied()
                            .collect::<Vec<u8>>();

                        return std::str::from_utf8(&compat_str)
                            .map(|s| s.to_string())
                            .map_err(|_| DevicetreeError::NoCompatible);
                    }
                }

                i += 3 + len_words;
            }
            FDT_END_NODE | FDT_END => {
                i += 1;
            }
            _ => {
                return Err(DevicetreeError::BadHeader);
            }
        }
    }

    Err(DevicetreeError::NoCompatible)
}

/// Match a device tree blob's compatible string against an expected value.
pub fn devicetree_match_by_compatible(dtb: &[u8], compat: &str) -> Result<(), DevicetreeError> {
    if compat.is_empty() {
        return Err(DevicetreeError::InvalidParameter);
    }

    let dt_compat = devicetree_get_compatible(dtb)?;
    if dt_compat == compat {
        Ok(())
    } else {
        Err(DevicetreeError::MatchFailed)
    }
}

/// Match a UKI device tree against the firmware-provided one.
pub fn devicetree_match(uki_dtb: &[u8], fw_compat: &str) -> Result<(), DevicetreeError> {
    if fw_compat.is_empty() {
        return Err(DevicetreeError::Unsupported);
    }
    devicetree_match_by_compatible(uki_dtb, fw_compat)
}

/// Check if the device tree alignment is valid.
pub fn is_valid_alignment(ptr: usize) -> bool {
    ptr.is_multiple_of(std::mem::align_of::<u32>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pages_for_size() {
        assert_eq!(pages_for_size(0), 0);
        assert_eq!(pages_for_size(1), 1);
        assert_eq!(pages_for_size(4096), 1);
        assert_eq!(pages_for_size(4097), 2);
    }

    #[test]
    fn test_validate_dtb_size() {
        assert!(validate_dtb_size(28).is_ok());
        assert_eq!(validate_dtb_size(20), Err(DevicetreeError::BufferTooSmall));
        assert_eq!(
            validate_dtb_size(FDT_MAX_SIZE + 1),
            Err(DevicetreeError::InvalidParameter)
        );
    }

    #[test]
    fn test_fdt_header_parse_too_small() {
        assert_eq!(
            FdtHeader::parse(&[0; 20]),
            Err(DevicetreeError::BufferTooSmall)
        );
    }

    #[test]
    fn test_fdt_header_parse_bad_magic() {
        let mut data = vec![0u8; 40];
        data[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        assert_eq!(FdtHeader::parse(&data), Err(DevicetreeError::InvalidMagic));
    }

    #[test]
    fn test_devicetree_state_defaults() {
        let state = DevicetreeState::default();
        assert_eq!(state.pages, 0);
        assert!(!state.is_loaded());
        assert_eq!(state.allocated_size(), 0);
    }

    #[test]
    fn test_devicetree_state_loaded() {
        let state = DevicetreeState {
            addr: 0x1000,
            pages: 2,
            orig: 0,
        };
        assert!(state.is_loaded());
        assert_eq!(state.allocated_size(), 8192);
    }

    #[test]
    fn test_is_valid_alignment() {
        assert!(is_valid_alignment(0));
        assert!(is_valid_alignment(4));
        assert!(is_valid_alignment(8));
        assert!(!is_valid_alignment(1));
        assert!(!is_valid_alignment(3));
    }

    #[test]
    fn test_devicetree_match_by_compatible_empty() {
        let data = vec![0u8; 64];
        assert_eq!(
            devicetree_match_by_compatible(&data, ""),
            Err(DevicetreeError::InvalidParameter)
        );
    }

    #[test]
    fn test_devicetree_match_no_fw_compat() {
        let data = vec![0u8; 64];
        assert_eq!(
            devicetree_match(&data, ""),
            Err(DevicetreeError::Unsupported)
        );
    }

    #[test]
    fn test_error_display() {
        assert!(!DevicetreeError::InvalidMagic.to_string().is_empty());
        assert!(!DevicetreeError::MatchFailed.to_string().is_empty());
    }
}
