// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/pe.c
//
// PE (Portable Executable) file format parsing for EFI boot.
//
// Provides DOS/PE header validation, section table parsing,
// section lookup, and kernel image info extraction. Supports
// both PE32 and PE32+ formats with NX compatibility checking.

// ── Constants ─────────────────────────────────────────────────────────────

pub const DOS_FILE_MAGIC: &[u8; 2] = b"MZ";
pub const PE_FILE_MAGIC: &[u8; 4] = b"PE\0\0";
pub const OPTHDR32_MAGIC: u16 = 0x10B;
pub const OPTHDR64_MAGIC: u16 = 0x20B;
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
pub const BASE_RELOCATION_TABLE_DATA_DIRECTORY_ENTRY: usize = 5;
pub const SECTION_TABLE_BYTES_MAX: usize = 16 * 1024 * 1024;
pub const PE_SECTION_NAME_SIZE: usize = 8;

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeError {
    LoadError,
    Unsupported,
    OutOfResources,
    NotFound,
}

impl std::fmt::Display for PeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeError::LoadError => write!(f, "PE load error"),
            PeError::Unsupported => write!(f, "unsupported PE format"),
            PeError::OutOfResources => write!(f, "out of resources"),
            PeError::NotFound => write!(f, "section not found"),
        }
    }
}

impl std::error::Error for PeError {}

/// DOS file header
#[derive(Debug, Clone)]
pub struct DosFileHeader {
    pub magic: [u8; 2],
    pub exe_header: u32,
}

/// PE optional header (simplified, key fields)
#[derive(Debug, Clone)]
pub struct PeOptionalHeader {
    pub magic: u16,
    pub address_of_entry_point: u32,
    pub size_of_image: u32,
    pub dll_characteristics: u16,
    pub major_image_version: u16,
    pub size_of_optional_header: u16,
    pub base_relocation_size: u32,
}

/// PE file header
#[derive(Debug, Clone)]
pub struct PeFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// Full PE header
#[derive(Debug, Clone)]
pub struct PeHeader {
    pub file_header: PeFileHeader,
    pub optional_header: PeOptionalHeader,
}

/// PE section header
#[derive(Debug, Clone)]
pub struct PeSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub characteristics: u32,
}

impl PeSectionHeader {
    pub fn name_str(&self) -> &str {
        let nul_pos = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        std::str::from_utf8(&self.name[..nul_pos]).unwrap_or("")
    }
}

/// PE section vector (location info for a found section)
#[derive(Debug, Clone, Default)]
pub struct PeSectionVector {
    pub memory_size: u32,
    pub memory_offset: u32,
    pub file_size: u32,
    pub file_offset: u32,
}

impl PeSectionVector {
    pub fn is_set(&self) -> bool {
        self.memory_size > 0 || self.file_size > 0
    }
}

// ── DOS/PE verification ───────────────────────────────────────────────────

/// Verify a DOS file header
pub fn verify_dos(dos: &DosFileHeader) -> bool {
    &dos.magic == DOS_FILE_MAGIC && dos.exe_header >= std::mem::size_of::<DosFileHeader>() as u32
}

/// Verify a PE file header
pub fn verify_pe(
    _dos: &DosFileHeader,
    pe: &PeFileHeader,
    opt: &PeOptionalHeader,
    target_machine: u16,
    compat_machine: u16,
    allow_compatibility: bool,
) -> bool {
    let machine_ok = pe.machine == target_machine
        || (allow_compatibility && pe.machine == compat_machine && compat_machine != 0);

    machine_ok
        && pe.number_of_sections > 0
        && (opt.magic == OPTHDR32_MAGIC || opt.magic == OPTHDR64_MAGIC)
}

// ── Section table operations ──────────────────────────────────────────────

/// Calculate section table offset from DOS and PE headers
pub fn section_table_offset(dos: &DosFileHeader, pe_offset: usize, opt_header_size: u16) -> usize {
    dos.exe_header as usize + pe_offset + opt_header_size as usize
}

/// Check if two PE section names are equal (up to 8 chars, C `pe_section_name_equal`)
pub fn pe_section_name_equal(a: &[u8; 8], b: &[u8; 8]) -> bool {
    for i in 0..PE_SECTION_NAME_SIZE {
        if a[i] != b[i] {
            return false;
        }
        if a[i] == 0 {
            return true;
        }
    }
    true
}

/// Search for sections by name in a section table
pub fn locate_sections(
    section_table: &[PeSectionHeader],
    section_names: &[&[u8; 8]],
) -> Vec<Option<PeSectionVector>> {
    let mut results: Vec<Option<PeSectionVector>> = vec![None; section_names.len()];

    for (i, name) in section_names.iter().enumerate() {
        for section in section_table {
            if !pe_section_name_equal(&section.name, name) {
                continue;
            }

            let size_max = u32::MAX - section.pointer_to_raw_data;
            if section.size_of_raw_data > size_max {
                continue;
            }

            let size_max2 = u32::MAX - section.virtual_address;
            if section.virtual_size > size_max2 {
                continue;
            }

            results[i] = Some(PeSectionVector {
                memory_size: section.virtual_size,
                memory_offset: section.virtual_address,
                file_size: section.size_of_raw_data.min(section.virtual_size),
                file_offset: section.pointer_to_raw_data,
            });
            break;
        }
    }

    results
}

// ── Kernel info extraction ────────────────────────────────────────────────

/// Result of `pe_kernel_info`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelInfo {
    pub entry_point: u32,
    pub compat_entry_point: u32,
    pub size_in_memory: usize,
}

/// Extract kernel information from PE headers
pub fn pe_kernel_info(
    dos: &DosFileHeader,
    pe: &PeFileHeader,
    opt: &PeOptionalHeader,
    target_machine: u16,
    compat_machine: u16,
) -> Result<KernelInfo, PeError> {
    if !verify_dos(dos) {
        return Err(PeError::LoadError);
    }

    if !verify_pe(dos, pe, opt, target_machine, compat_machine, true) {
        return Err(PeError::LoadError);
    }

    if opt.major_image_version < 1 {
        return Err(PeError::Unsupported);
    }

    let size_in_memory = opt.size_of_image as usize;

    if pe.machine == target_machine {
        return Ok(KernelInfo {
            entry_point: opt.address_of_entry_point,
            compat_entry_point: 0,
            size_in_memory,
        });
    }

    Ok(KernelInfo {
        entry_point: 0,
        compat_entry_point: 0,
        size_in_memory,
    })
}

/// Check if PE image has NX compatibility
pub fn pe_kernel_check_nx_compat(opt: &PeOptionalHeader) -> bool {
    opt.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0
}

/// Check for base relocations in PE image
pub fn pe_kernel_check_no_relocation(relocation_size: u32) -> Result<(), PeError> {
    if relocation_size != 0 {
        return Err(PeError::LoadError);
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dos_header() -> DosFileHeader {
        DosFileHeader {
            magic: *DOS_FILE_MAGIC,
            exe_header: 128,
        }
    }

    fn make_pe_file_header(machine: u16, n_sections: u16) -> PeFileHeader {
        PeFileHeader {
            machine,
            number_of_sections: n_sections,
            size_of_optional_header: 240,
            characteristics: 0,
        }
    }

    fn make_optional_header(magic: u16) -> PeOptionalHeader {
        PeOptionalHeader {
            magic,
            address_of_entry_point: 0x1000,
            size_of_image: 0x10000,
            dll_characteristics: IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
            major_image_version: 1,
            size_of_optional_header: 240,
            base_relocation_size: 0,
        }
    }

    fn make_section(name: &str, va: u32, vs: u32, rds: u32, rdo: u32) -> PeSectionHeader {
        let mut name_arr = [0u8; 8];
        let bytes = name.as_bytes();
        let len = bytes.len().min(8);
        name_arr[..len].copy_from_slice(&bytes[..len]);
        PeSectionHeader {
            name: name_arr,
            virtual_size: vs,
            virtual_address: va,
            size_of_raw_data: rds,
            pointer_to_raw_data: rdo,
            pointer_to_relocations: 0,
            characteristics: 0,
        }
    }

    #[test]
    fn test_verify_dos_valid() {
        let dos = make_dos_header();
        assert!(verify_dos(&dos));
    }

    #[test]
    fn test_verify_dos_bad_magic() {
        let dos = DosFileHeader {
            magic: *b"XX",
            exe_header: 128,
        };
        assert!(!verify_dos(&dos));
    }

    #[test]
    fn test_verify_dos_exe_header_too_small() {
        let dos = DosFileHeader {
            magic: *DOS_FILE_MAGIC,
            exe_header: 4,
        };
        assert!(!verify_dos(&dos));
    }

    #[test]
    fn test_verify_pe_valid() {
        let dos = make_dos_header();
        let pe = make_pe_file_header(0x8664, 4);
        let opt = make_optional_header(OPTHDR64_MAGIC);
        assert!(verify_pe(&dos, &pe, &opt, 0x8664, 0, false));
    }

    #[test]
    fn test_verify_pe_wrong_machine() {
        let dos = make_dos_header();
        let pe = make_pe_file_header(0x014C, 4);
        let opt = make_optional_header(OPTHDR64_MAGIC);
        assert!(!verify_pe(&dos, &pe, &opt, 0x8664, 0, false));
    }

    #[test]
    fn test_verify_pe_compat_machine() {
        let dos = make_dos_header();
        let pe = make_pe_file_header(0x8664, 4);
        let opt = make_optional_header(OPTHDR64_MAGIC);
        assert!(verify_pe(&dos, &pe, &opt, 0x014C, 0x8664, true));
    }

    #[test]
    fn test_verify_pe_zero_sections() {
        let dos = make_dos_header();
        let pe = make_pe_file_header(0x8664, 0);
        let opt = make_optional_header(OPTHDR64_MAGIC);
        assert!(!verify_pe(&dos, &pe, &opt, 0x8664, 0, false));
    }

    #[test]
    fn test_pe_section_name_equal() {
        let mut a = [0u8; 8];
        a[..5].copy_from_slice(b".text");
        let mut b = [0u8; 8];
        b[..5].copy_from_slice(b".text");
        assert!(pe_section_name_equal(&a, &b));

        let mut c = [0u8; 8];
        c[..5].copy_from_slice(b".data");
        assert!(!pe_section_name_equal(&a, &c));
    }

    #[test]
    fn test_pe_section_name_equal_full_8() {
        let a = [b'A'; 8];
        let b = [b'A'; 8];
        assert!(pe_section_name_equal(&a, &b));

        let mut c = [b'A'; 8];
        c[7] = b'B';
        assert!(!pe_section_name_equal(&a, &c));
    }

    #[test]
    fn test_section_name_str() {
        let section = make_section(".text", 0, 0, 0, 0);
        assert_eq!(section.name_str(), ".text");
    }

    #[test]
    fn test_pe_section_vector_is_set() {
        let v = PeSectionVector::default();
        assert!(!v.is_set());

        let v = PeSectionVector {
            memory_size: 100,
            memory_offset: 0,
            file_size: 50,
            file_offset: 0,
        };
        assert!(v.is_set());
    }

    #[test]
    fn test_locate_sections_found() {
        let sections = vec![
            make_section(".text", 0x1000, 0x200, 0x200, 0x400),
            make_section(".data", 0x3000, 0x100, 0x100, 0x800),
        ];
        let mut text_name = [0u8; 8];
        text_name[..5].copy_from_slice(b".text");
        let names: Vec<&[u8; 8]> = vec![&text_name];
        let results = locate_sections(&sections, &names);
        assert!(results[0].is_some());
        assert_eq!(results[0].as_ref().unwrap().memory_offset, 0x1000);
    }

    #[test]
    fn test_locate_sections_not_found() {
        let sections = vec![make_section(".text", 0x1000, 0x200, 0x200, 0x400)];
        let mut data_name = [0u8; 8];
        data_name[..5].copy_from_slice(b".data");
        let names: Vec<&[u8; 8]> = vec![&data_name];
        let results = locate_sections(&sections, &names);
        assert!(results[0].is_none());
    }

    #[test]
    fn test_pe_kernel_info_valid() {
        let dos = make_dos_header();
        let pe = make_pe_file_header(0x8664, 4);
        let opt = make_optional_header(OPTHDR64_MAGIC);
        let info = pe_kernel_info(&dos, &pe, &opt, 0x8664, 0).unwrap();
        assert_eq!(info.entry_point, 0x1000);
        assert_eq!(info.compat_entry_point, 0);
        assert_eq!(info.size_in_memory, 0x10000);
    }

    #[test]
    fn test_pe_kernel_info_bad_dos() {
        let dos = DosFileHeader {
            magic: *b"XX",
            exe_header: 128,
        };
        let pe = make_pe_file_header(0x8664, 4);
        let opt = make_optional_header(OPTHDR64_MAGIC);
        assert!(pe_kernel_info(&dos, &pe, &opt, 0x8664, 0).is_err());
    }

    #[test]
    fn test_pe_kernel_info_too_old() {
        let dos = make_dos_header();
        let pe = make_pe_file_header(0x8664, 4);
        let mut opt = make_optional_header(OPTHDR64_MAGIC);
        opt.major_image_version = 0;
        assert_eq!(
            pe_kernel_info(&dos, &pe, &opt, 0x8664, 0),
            Err(PeError::Unsupported)
        );
    }

    #[test]
    fn test_pe_kernel_check_nx_compat() {
        let opt = make_optional_header(OPTHDR64_MAGIC);
        assert!(pe_kernel_check_nx_compat(&opt));

        let mut opt_no_nx = make_optional_header(OPTHDR64_MAGIC);
        opt_no_nx.dll_characteristics = 0;
        assert!(!pe_kernel_check_nx_compat(&opt_no_nx));
    }

    #[test]
    fn test_pe_kernel_check_no_relocation() {
        assert!(pe_kernel_check_no_relocation(0).is_ok());
        assert_eq!(pe_kernel_check_no_relocation(100), Err(PeError::LoadError));
    }

    #[test]
    fn test_section_table_offset() {
        let dos = make_dos_header();
        let offset = section_table_offset(&dos, 4, 240);
        assert_eq!(offset, 128 + 4 + 240);
    }
}
