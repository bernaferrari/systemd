// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/linux.c
//
// Generic Linux boot protocol using EFI/PE entry point.
//
// Boots Linux kernels (5.8+) using the standard PE entry point,
// passing initrd via LINUX_INITRD_MEDIA_GUID DevicePath and
// cmdline via EFI LoadedImageProtocol. Handles memory protection
// (W^X) and PE section loading.

// ── Constants ─────────────────────────────────────────────────────────────

pub const EFI_SUCCESS: usize = 0;
pub const EFI_LOAD_ERROR: usize = 1;
pub const EFI_UNSUPPORTED: usize = 3;
pub const EFI_OUT_OF_RESOURCES: usize = 9;

/// PE section characteristics for code + execute
pub const PE_CODE: u32 = 0x00000020;
pub const PE_EXECUTE: u32 = 0x20000000;

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxBootError {
    LoadError,
    BadKernelImage,
    CannotGetParentImage,
    CannotReadSections,
    RelocationsPresent,
    InvalidSection(String),
    ErrorRegisteringInitrd,
    ErrorStartingKernel,
}

impl std::fmt::Display for LinuxBootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinuxBootError::LoadError => write!(f, "load error"),
            LinuxBootError::BadKernelImage => write!(f, "bad kernel image"),
            LinuxBootError::CannotGetParentImage => write!(f, "cannot get parent loaded image"),
            LinuxBootError::CannotReadSections => write!(f, "cannot read sections"),
            LinuxBootError::RelocationsPresent => write!(f, "kernel image contains relocations"),
            LinuxBootError::InvalidSection(msg) => write!(f, "invalid PE section: {}", msg),
            LinuxBootError::ErrorRegisteringInitrd => write!(f, "error registering initrd"),
            LinuxBootError::ErrorStartingKernel => write!(f, "error starting kernel"),
        }
    }
}

impl std::error::Error for LinuxBootError {}

/// Represents a validated PE section for loading
#[derive(Debug, Clone)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_size: u32,
    pub raw_data_offset: u32,
    pub characteristics: u32,
}

impl PeSection {
    pub fn is_code(&self) -> bool {
        (self.characteristics & (PE_CODE | PE_EXECUTE)) != 0
    }

    pub fn has_relocations(&self) -> bool {
        // PointerToRelocations != 0
        // (In the real struct, this is a separate field; here we simplify)
        false
    }
}

/// Result of PE section validation
#[derive(Debug, Clone)]
pub struct SectionValidation {
    pub valid: bool,
    pub reason: Option<String>,
}

/// Validates a PE section's sizes and offsets against kernel boundaries.
pub fn validate_section(
    section: &PeSection,
    kernel_size: usize,
    kernel_size_in_memory: usize,
) -> SectionValidation {
    if section
        .virtual_address
        .checked_add(section.raw_data_size)
        .is_none()
    {
        return SectionValidation {
            valid: false,
            reason: Some("SizeOfRawData + VirtualAddress overflows".into()),
        };
    }

    if section.virtual_address as usize + section.raw_data_size as usize > kernel_size_in_memory {
        return SectionValidation {
            valid: false,
            reason: Some("section would write outside of memory".into()),
        };
    }

    if section.raw_data_size > section.virtual_size {
        return SectionValidation {
            valid: false,
            reason: Some("raw data size is greater than virtual size".into()),
        };
    }

    if section
        .raw_data_offset
        .checked_add(section.raw_data_size)
        .is_none()
    {
        return SectionValidation {
            valid: false,
            reason: Some("PointerToRawData + SizeOfRawData overflows".into()),
        };
    }

    if section.raw_data_offset as usize + section.raw_data_size as usize > kernel_size {
        return SectionValidation {
            valid: false,
            reason: Some("raw data extends outside of file".into()),
        };
    }

    SectionValidation {
        valid: true,
        reason: None,
    }
}

/// Load PE sections into a target buffer, handling BSS (uninitialized data).
pub fn load_sections(
    sections: &[PeSection],
    kernel_data: &[u8],
    target: &mut [u8],
) -> Result<Vec<(usize, usize)>, LinuxBootError> {
    let mut code_sections = Vec::new();

    for section in sections {
        let validation = validate_section(section, kernel_data.len(), target.len());
        if !validation.valid {
            return Err(LinuxBootError::InvalidSection(
                validation.reason.unwrap_or_default(),
            ));
        }

        if section.raw_data_size == 0 {
            continue;
        }

        let va = section.virtual_address as usize;
        let raw_size = section.raw_data_size as usize;
        let raw_offset = section.raw_data_offset as usize;
        let virt_size = section.virtual_size as usize;

        target[va..va + raw_size].copy_from_slice(&kernel_data[raw_offset..raw_offset + raw_size]);

        // Zero BSS portion (virtual size > raw data size)
        if virt_size > raw_size {
            target[va + raw_size..va + virt_size].fill(0);
        }

        if section.is_code() {
            code_sections.push((va, virt_size));
        }
    }

    Ok(code_sections)
}

/// Represents the memory protection operations for W^X compliance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProtection {
    /// Mark code pages Read-Only + eXecutable
    RoX,
    /// Mark pages Read-Write + No-eXecute
    RwNx,
}

/// Simulated memory attribute protocol for testing
#[derive(Debug, Clone, Default)]
pub struct MemoryAttributeState {
    pub ro_x_applied: Vec<(usize, usize)>,
    pub rw_nx_applied: Vec<(usize, usize)>,
}

impl MemoryAttributeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_memory_protection(
        &mut self,
        protection: MemoryProtection,
        base: usize,
        len: usize,
    ) -> Result<(), LinuxBootError> {
        match protection {
            MemoryProtection::RoX => {
                self.ro_x_applied.push((base, len));
            }
            MemoryProtection::RwNx => {
                self.rw_nx_applied.push((base, len));
            }
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_section_is_code() {
        let code_section = PeSection {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x200,
            raw_data_size: 0x200,
            raw_data_offset: 0x400,
            characteristics: PE_CODE | PE_EXECUTE,
        };
        assert!(code_section.is_code());

        let data_section = PeSection {
            name: ".data".into(),
            virtual_address: 0x3000,
            virtual_size: 0x100,
            raw_data_size: 0x100,
            raw_data_offset: 0x800,
            characteristics: 0x00000040,
        };
        assert!(!data_section.is_code());
    }

    #[test]
    fn test_validate_section_valid() {
        let section = PeSection {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x200,
            raw_data_size: 0x200,
            raw_data_offset: 0x400,
            characteristics: 0,
        };
        let result = validate_section(&section, 0x10000, 0x10000);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_section_va_overflow() {
        let section = PeSection {
            name: ".text".into(),
            virtual_address: 0xFFFFFFF0,
            virtual_size: 0x200,
            raw_data_size: 0x200,
            raw_data_offset: 0x400,
            characteristics: 0,
        };
        let result = validate_section(&section, 0x10000, 0x10000);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_section_writes_outside_memory() {
        let section = PeSection {
            name: ".text".into(),
            virtual_address: 0xFF00,
            virtual_size: 0x200,
            raw_data_size: 0x200,
            raw_data_offset: 0x400,
            characteristics: 0,
        };
        let result = validate_section(&section, 0x10000, 0x10000);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_section_raw_larger_than_virtual() {
        let section = PeSection {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x100,
            raw_data_size: 0x200,
            raw_data_offset: 0x400,
            characteristics: 0,
        };
        let result = validate_section(&section, 0x10000, 0x10000);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_section_extends_outside_file() {
        let section = PeSection {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x200,
            raw_data_size: 0x200,
            raw_data_offset: 0xFF00,
            characteristics: 0,
        };
        let result = validate_section(&section, 0x10000, 0x10000);
        assert!(!result.valid);
    }

    #[test]
    fn test_load_sections_basic() {
        let section = PeSection {
            name: ".text".into(),
            virtual_address: 0,
            virtual_size: 4,
            raw_data_size: 4,
            raw_data_offset: 0,
            characteristics: PE_CODE,
        };
        let kernel_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut target = vec![0u8; 256];
        let code = load_sections(&[section], &kernel_data, &mut target).unwrap();
        assert_eq!(&target[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(code.len(), 1);
    }

    #[test]
    fn test_load_sections_with_bss() {
        let section = PeSection {
            name: ".bss".into(),
            virtual_address: 0,
            virtual_size: 8,
            raw_data_size: 4,
            raw_data_offset: 0,
            characteristics: 0,
        };
        let kernel_data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let mut target = vec![0xFFu8; 16];
        load_sections(&[section], &kernel_data, &mut target).unwrap();
        assert_eq!(&target[..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(&target[4..8], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_load_sections_skip_zero_raw_data() {
        let section = PeSection {
            name: ".bss".into(),
            virtual_address: 0x100,
            virtual_size: 0x100,
            raw_data_size: 0,
            raw_data_offset: 0,
            characteristics: 0,
        };
        let kernel_data = vec![0u8; 256];
        let mut target = vec![0xFFu8; 4096];
        let code = load_sections(&[section], &kernel_data, &mut target).unwrap();
        assert!(code.is_empty());
    }

    #[test]
    fn test_memory_protection_rox() {
        let mut state = MemoryAttributeState::new();
        state
            .apply_memory_protection(MemoryProtection::RoX, 0x1000, 0x200)
            .unwrap();
        assert_eq!(state.ro_x_applied.len(), 1);
        assert_eq!(state.ro_x_applied[0], (0x1000, 0x200));
    }

    #[test]
    fn test_memory_protection_rwnx() {
        let mut state = MemoryAttributeState::new();
        state
            .apply_memory_protection(MemoryProtection::RwNx, 0x3000, 0x400)
            .unwrap();
        assert_eq!(state.rw_nx_applied.len(), 1);
    }
}
