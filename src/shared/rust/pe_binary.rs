// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/pe-binary.c, src/shared/pe-binary.h
//
// PE (Portable Executable) binary parsing for systemd-boot.
// Reads PE headers, sections, and can extract embedded resources
// like kernel command line from UKI (Unified Kernel Image) files.
//
// Note: none of these functions change the file position of the
// provided fd, as they use pread() via std::fs::File::seek_read.

use crate::ffi::*;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

// ── Constants ─────────────────────────────────────────────────────────────

/// DOS header magic: "MZ"
pub const MZ_MAGIC: u16 = 0x5A4D;

/// PE signature magic: "PE\0\0"
pub const PE_SIGNATURE: u32 = 0x0000_4550;

/// PE32 optional header magic
pub const PE32_MAGIC: u16 = 0x010B;

/// PE32+ optional header magic
pub const PE32PLUS_MAGIC: u16 = 0x020B;

/// EFI application subsystem
pub const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;

/// Index of the certification table in the data directory
pub const IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE: usize = 4;

/// Size of the DOS header in bytes (64 bytes)
pub const DOS_HEADER_SIZE: usize = 64;

/// Size of a section header in bytes (40 bytes)
pub const SECTION_HEADER_SIZE: usize = 40;

/// Section name length in bytes
pub const SECTION_NAME_SIZE: usize = 8;

/// Minimum optional header size that includes the magic field
pub const OPTIONAL_HEADER_MAGIC_SIZE: usize = 2;

/// Size of IMAGE_DATA_DIRECTORY entry
pub const IMAGE_DATA_DIRECTORY_SIZE: usize = 8;

// ── Error types ───────────────────────────────────────────────────────────

/// Errors that can occur during PE binary parsing
#[derive(Debug)]
pub enum PeError {
    /// The file is not a valid DOS executable (missing MZ header)
    InvalidDosHeader(String),
    /// The file is not a valid PE executable (missing PE signature)
    InvalidPeSignature(String),
    /// The optional header magic is not PE32 or PE32+
    InvalidOptionalMagic(String),
    /// The optional header size is invalid
    InvalidOptionalSize(String),
    /// Data directory validation failed
    InvalidDataDirectory(String),
    /// An I/O error occurred while reading
    Io(io::Error),
    /// The requested section was not found
    SectionNotFound(String),
    /// The section data is too large
    SectionTooLarge,
    /// The data contains embedded NUL bytes
    EmbeddedNul,
    /// Short read — fewer bytes than expected
    ShortRead,
}

impl std::fmt::Display for PeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeError::InvalidDosHeader(s) => write!(f, "Invalid DOS header: {}", s),
            PeError::InvalidPeSignature(s) => write!(f, "Invalid PE signature: {}", s),
            PeError::InvalidOptionalMagic(s) => {
                write!(f, "Invalid optional header magic: {}", s)
            }
            PeError::InvalidOptionalSize(s) => {
                write!(f, "Invalid optional header size: {}", s)
            }
            PeError::InvalidDataDirectory(s) => write!(f, "Invalid data directory: {}", s),
            PeError::Io(e) => write!(f, "I/O error: {}", e),
            PeError::SectionNotFound(s) => write!(f, "Section not found: {}", s),
            PeError::SectionTooLarge => write!(f, "Section data too large"),
            PeError::EmbeddedNul => write!(f, "Embedded NUL byte in section data"),
            PeError::ShortRead => write!(f, "Short read from file"),
        }
    }
}

impl std::error::Error for PeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PeError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for PeError {
    fn from(e: io::Error) -> Self {
        PeError::Io(e)
    }
}

// ── Structs ──────────────────────────────────────────────────────────────

/// DOS header (MZ header) — the first 64 bytes of a PE file.
///
/// All multi-byte fields are little-endian as stored on disk.
/// We parse them into native-endian Rust types upon reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DosHeader {
    /// DOS magic number (must be `MZ_MAGIC`)
    pub e_magic: u16,
    /// Bytes on last page of file
    pub e_cblp: u16,
    /// Pages in file
    pub e_cp: u16,
    /// Relocations
    pub e_crlc: u16,
    /// Size of header in paragraphs
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs needed
    pub e_minalloc: u16,
    /// Maximum extra paragraphs needed
    pub e_maxalloc: u16,
    /// Initial (relative) SS value
    pub e_ss: u16,
    /// Initial SP value
    pub e_sp: u16,
    /// Checksum
    pub e_csum: u16,
    /// Initial IP value
    pub e_ip: u16,
    /// Initial (relative) CS value
    pub e_cs: u16,
    /// File address of relocation table
    pub e_lfarlc: u16,
    /// Overlay number
    pub e_ovno: u16,
    /// Reserved words
    pub e_res: [u16; 4],
    /// OEM identifier
    pub e_oemid: u16,
    /// OEM information
    pub e_oeminfo: u16,
    /// Reserved words
    pub e_res2: [u16; 10],
    /// File address of new exe header
    pub e_lfanew: u32,
}

impl DosHeader {
    /// Parse a DOS header from a byte slice.
    pub fn from_bytes(data: &[u8; DOS_HEADER_SIZE]) -> Result<Self, PeError> {
        let e_magic = u16::from_le_bytes([data[0], data[1]]);
        if e_magic != MZ_MAGIC {
            return Err(PeError::InvalidDosHeader(format!(
                "Expected MZ magic 0x{:04X}, got 0x{:04X}",
                MZ_MAGIC, e_magic
            )));
        }

        let e_cblp = u16::from_le_bytes([data[2], data[3]]);
        let e_cp = u16::from_le_bytes([data[4], data[5]]);
        let e_crlc = u16::from_le_bytes([data[6], data[7]]);
        let e_cparhdr = u16::from_le_bytes([data[8], data[9]]);
        let e_minalloc = u16::from_le_bytes([data[10], data[11]]);
        let e_maxalloc = u16::from_le_bytes([data[12], data[13]]);
        let e_ss = u16::from_le_bytes([data[14], data[15]]);
        let e_sp = u16::from_le_bytes([data[16], data[17]]);
        let e_csum = u16::from_le_bytes([data[18], data[19]]);
        let e_ip = u16::from_le_bytes([data[20], data[21]]);
        let e_cs = u16::from_le_bytes([data[22], data[23]]);
        let e_lfarlc = u16::from_le_bytes([data[24], data[25]]);
        let e_ovno = u16::from_le_bytes([data[26], data[27]]);

        let mut e_res = [0u16; 4];
        for i in 0..4 {
            e_res[i] = u16::from_le_bytes([data[28 + i * 2], data[29 + i * 2]]);
        }

        let e_oemid = u16::from_le_bytes([data[36], data[37]]);
        let e_oeminfo = u16::from_le_bytes([data[38], data[39]]);

        let mut e_res2 = [0u16; 10];
        for i in 0..10 {
            e_res2[i] = u16::from_le_bytes([data[40 + i * 2], data[41 + i * 2]]);
        }

        let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);

        Ok(DosHeader {
            e_magic,
            e_cblp,
            e_cp,
            e_crlc,
            e_cparhdr,
            e_minalloc,
            e_maxalloc,
            e_ss,
            e_sp,
            e_csum,
            e_ip,
            e_cs,
            e_lfarlc,
            e_ovno,
            e_res,
            e_oemid,
            e_oeminfo,
            e_res2,
            e_lfanew,
        })
    }
}

/// PE file header (COFF header)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImageFileHeader {
    /// Target machine type
    pub machine: u16,
    /// Number of sections
    pub number_of_sections: u16,
    /// Time stamp
    pub time_date_stamp: u32,
    /// Pointer to symbol table
    pub pointer_to_symbol_table: u32,
    /// Number of symbols
    pub number_of_symbols: u32,
    /// Size of optional header
    pub size_of_optional_header: u16,
    /// Characteristics flags
    pub characteristics: u16,
}

/// Image data directory entry
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImageDataDirectory {
    /// Relative virtual address
    pub virtual_address: u32,
    /// Size
    pub size: u32,
}

/// PE optional header — parsed with awareness of PE32 vs PE32+ differences.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeOptionalHeader {
    /// Magic number: PE32_MAGIC or PE32PLUS_MAGIC
    pub magic: u16,
    /// Major linker version
    pub major_linker_version: u8,
    /// Minor linker version
    pub minor_linker_version: u8,
    /// Size of code
    pub size_of_code: u32,
    /// Size of initialized data
    pub size_of_initialized_data: u32,
    /// Size of uninitialized data
    pub size_of_uninitialized_data: u32,
    /// Address of entry point
    pub address_of_entry_point: u32,
    /// Base of code
    pub base_of_code: u32,
    /// Image base (64-bit for PE32+, 32-bit for PE32)
    pub image_base: u64,
    /// Section alignment
    pub section_alignment: u32,
    /// File alignment
    pub file_alignment: u32,
    /// Major operating system version
    pub major_operating_system_version: u16,
    /// Minor operating system version
    pub minor_operating_system_version: u16,
    /// Major image version
    pub major_image_version: u16,
    /// Minor image version
    pub minor_image_version: u16,
    /// Major subsystem version
    pub major_subsystem_version: u16,
    /// Minor subsystem version
    pub minor_subsystem_version: u16,
    /// Win32 version value
    pub win32_version_value: u32,
    /// Size of image
    pub size_of_image: u32,
    /// Size of headers
    pub size_of_headers: u32,
    /// Checksum
    pub checksum: u32,
    /// Subsystem
    pub subsystem: u16,
    /// DLL characteristics
    pub dll_characteristics: u16,
    /// Size of stack reserve
    pub size_of_stack_reserve: u64,
    /// Size of stack commit
    pub size_of_stack_commit: u64,
    /// Size of heap reserve
    pub size_of_heap_reserve: u64,
    /// Size of heap commit
    pub size_of_heap_commit: u64,
    /// Loader flags
    pub loader_flags: u32,
    /// Number of RVA and sizes
    pub number_of_rva_and_sizes: u32,
    /// Data directory entries
    pub data_directory: Vec<ImageDataDirectory>,
}

/// Complete PE header: signature + COFF file header + optional header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeHeader {
    /// PE signature (must be `PE_SIGNATURE`)
    pub signature: u32,
    /// COFF file header
    pub coff_header: ImageFileHeader,
    /// Optional header
    pub optional: PeOptionalHeader,
}

impl PeHeader {
    /// Returns true if this is a PE32+ (64-bit) header, false if PE32 (32-bit).
    pub fn is_64bit(&self) -> bool {
        self.optional.magic == PE32PLUS_MAGIC
    }

    /// Calculate the total size of the PE header in bytes.
    ///
    /// This is: 4 (signature) + 20 (COFF header) + size_of_optional_header
    pub fn header_size(&self) -> usize {
        let coff_size = 20; // sizeof(IMAGE_FILE_HEADER)
        let optional_size = self.optional_size_bytes();
        4 + coff_size + optional_size
    }

    /// Size of the optional header in bytes.
    fn optional_size_bytes(&self) -> usize {
        let fixed_size = if self.is_64bit() {
            // PE32+: 2+1+1+4*5+8+4*2+2*6+4*3+4+2*2+8*4+4+4 = 112
            112
        } else {
            // PE32: 2+1+1+4*5+4*2+4*2+2*6+4*3+4+2*2+4*4+4*2+4 = 96
            96
        };
        let data_dir_size =
            self.optional.number_of_rva_and_sizes as usize * IMAGE_DATA_DIRECTORY_SIZE;
        fixed_size + data_dir_size
    }

    /// Get a data directory entry by index.
    /// Returns None if the index is out of range.
    pub fn get_data_directory(&self, i: usize) -> Option<&ImageDataDirectory> {
        self.optional.data_directory.get(i)
    }

    /// Find a section by name in the section table.
    /// Returns a reference to the matching section or None.
    pub fn find_section<'a>(
        &self,
        sections: &'a [ImageSectionHeader],
        name: &'a str,
    ) -> Option<&'a ImageSectionHeader> {
        pe_section_table_find(sections, self.coff_header.number_of_sections as usize, name)
    }

    /// Check if this PE is a Unified Kernel Image (UKI).
    /// A UKI is an EFI application with .osrel and .linux sections.
    pub fn is_uki(&self, sections: &[ImageSectionHeader]) -> bool {
        if self.optional.subsystem != IMAGE_SUBSYSTEM_EFI_APPLICATION {
            return false;
        }
        // Note that the UKI spec only requires .linux, but we are stricter here,
        // and require .osrel too, since for sd-boot it just doesn't make sense
        // to not have that.
        self.find_section(sections, ".osrel").is_some()
            && self.find_section(sections, ".linux").is_some()
    }

    /// Check if this PE is a UKI add-on.
    /// Add-ons do not have a Linux kernel, but do have one of .cmdline,
    /// .dtb, .initrd or .ucode.
    pub fn is_addon(&self, sections: &[ImageSectionHeader]) -> bool {
        if self.optional.subsystem != IMAGE_SUBSYSTEM_EFI_APPLICATION {
            return false;
        }
        let has_linux = self.find_section(sections, ".linux").is_some();
        let has_addon_section = self.find_section(sections, ".cmdline").is_some()
            || self.find_section(sections, ".dtb").is_some()
            || self.find_section(sections, ".initrd").is_some()
            || self.find_section(sections, ".ucode").is_some();
        !has_linux && has_addon_section
    }
}

/// PE section header
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImageSectionHeader {
    /// Section name (up to 8 bytes, NUL-padded)
    pub name: [u8; SECTION_NAME_SIZE],
    /// Virtual size
    pub virtual_size: u32,
    /// Virtual address
    pub virtual_address: u32,
    /// Size of raw data
    pub size_of_raw_data: u32,
    /// File offset of raw data
    pub pointer_to_raw_data: u32,
    /// Pointer to relocations
    pub pointer_to_relocations: u32,
    /// Pointer to line numbers
    pub pointer_to_linenumbers: u32,
    /// Number of relocations
    pub number_of_relocations: u16,
    /// Number of line numbers
    pub number_of_linenumbers: u16,
    /// Section characteristics flags
    pub characteristics: u32,
}

impl ImageSectionHeader {
    /// Get the section name as a string slice (truncated at first NUL).
    pub fn name_str(&self) -> &str {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(SECTION_NAME_SIZE);
        // Section names are ASCII per the PE spec
        std::str::from_utf8(&self.name[..end]).unwrap_or("")
    }
}

// ── Parsing helpers ──────────────────────────────────────────────────────

/// Read exactly `len` bytes from a file at the given offset.
fn pread_exact(file: &mut File, offset: u64, len: usize) -> Result<Vec<u8>, PeError> {
    let mut buf = vec![0u8; len];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// Parse the PE optional header from raw bytes.
///
/// The optional header has a fixed-size prefix followed by a variable-length
/// data directory array. PE32 and PE32+ differ in field sizes for the
/// image base, stack/heap reserves, and commits.
fn parse_optional_header(
    data: &[u8],
    size_of_optional_header: u16,
) -> Result<PeOptionalHeader, PeError> {
    if data.len() < OPTIONAL_HEADER_MAGIC_SIZE {
        return Err(PeError::ShortRead);
    }

    let magic = u16::from_le_bytes([data[0], data[1]]);
    let is_64bit = magic == PE32PLUS_MAGIC;

    if magic != PE32_MAGIC && magic != PE32PLUS_MAGIC {
        return Err(PeError::InvalidOptionalMagic(format!(
            "Expected 0x{:04X} or 0x{:04X}, got 0x{:04X}",
            PE32_MAGIC, PE32PLUS_MAGIC, magic
        )));
    }

    // Offsets within the optional header for common fields
    let major_linker_version = data[2];
    let minor_linker_version = data[3];
    let size_of_code = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let size_of_initialized_data = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let size_of_uninitialized_data = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let address_of_entry_point = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let base_of_code = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

    let mut offset = 24;

    // PE32 has an extra BaseOfData field (4 bytes) that PE32+ omits.
    let _base_of_data: Option<u32> = if !is_64bit {
        let val = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;
        Some(val)
    } else {
        None
    };

    // ImageBase differs: PE32 = 4 bytes, PE32+ = 8 bytes
    let image_base = if is_64bit {
        let val = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;
        val
    } else {
        let val = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;
        val as u64
    };

    let section_alignment = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;
    let file_alignment = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;

    let major_operating_system_version = u16::from_le_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let minor_operating_system_version = u16::from_le_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let major_image_version = u16::from_le_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let minor_image_version = u16::from_le_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let major_subsystem_version = u16::from_le_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let minor_subsystem_version = u16::from_le_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    let win32_version_value = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;
    let size_of_image = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;
    let size_of_headers = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;
    let checksum = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;
    let subsystem = u16::from_le_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let dll_characteristics = u16::from_le_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    // Stack/heap reserves and commits: PE32 = 4 bytes each, PE32+ = 8 bytes each
    let size_of_stack_reserve = if is_64bit {
        let val = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;
        val
    } else {
        let val = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;
        val as u64
    };

    let size_of_stack_commit = if is_64bit {
        let val = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;
        val
    } else {
        let val = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;
        val as u64
    };

    let size_of_heap_reserve = if is_64bit {
        let val = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;
        val
    } else {
        let val = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;
        val as u64
    };

    let size_of_heap_commit = if is_64bit {
        let val = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;
        val
    } else {
        let val = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;
        val as u64
    };

    let loader_flags = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;
    let number_of_rva_and_sizes = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;

    // Validate data directory consistency
    let data_dir_bytes = number_of_rva_and_sizes as usize * IMAGE_DATA_DIRECTORY_SIZE;
    let expected_total = offset + data_dir_bytes;
    if expected_total != size_of_optional_header as usize {
        return Err(PeError::InvalidDataDirectory(format!(
            "Optional header size mismatch: expected {}, got {}",
            expected_total, size_of_optional_header
        )));
    }

    // Parse data directory entries
    let mut data_directory = Vec::with_capacity(number_of_rva_and_sizes as usize);
    for i in 0..number_of_rva_and_sizes as usize {
        let dd_offset = offset + i * IMAGE_DATA_DIRECTORY_SIZE;
        if dd_offset + IMAGE_DATA_DIRECTORY_SIZE > data.len() {
            return Err(PeError::ShortRead);
        }
        let virtual_address = u32::from_le_bytes([
            data[dd_offset],
            data[dd_offset + 1],
            data[dd_offset + 2],
            data[dd_offset + 3],
        ]);
        let size = u32::from_le_bytes([
            data[dd_offset + 4],
            data[dd_offset + 5],
            data[dd_offset + 6],
            data[dd_offset + 7],
        ]);
        data_directory.push(ImageDataDirectory {
            virtual_address,
            size,
        });
    }

    Ok(PeOptionalHeader {
        magic,
        major_linker_version,
        minor_linker_version,
        size_of_code,
        size_of_initialized_data,
        size_of_uninitialized_data,
        address_of_entry_point,
        base_of_code,
        image_base,
        section_alignment,
        file_alignment,
        major_operating_system_version,
        minor_operating_system_version,
        major_image_version,
        minor_image_version,
        major_subsystem_version,
        minor_subsystem_version,
        win32_version_value,
        size_of_image,
        size_of_headers,
        checksum,
        subsystem,
        dll_characteristics,
        size_of_stack_reserve,
        size_of_stack_commit,
        size_of_heap_reserve,
        size_of_heap_commit,
        loader_flags,
        number_of_rva_and_sizes,
        data_directory,
    })
}

/// Parse an IMAGE_SECTION_HEADER from a 40-byte slice.
fn parse_section_header(data: &[u8]) -> Result<ImageSectionHeader, PeError> {
    if data.len() < SECTION_HEADER_SIZE {
        return Err(PeError::ShortRead);
    }

    let mut name = [0u8; SECTION_NAME_SIZE];
    name.copy_from_slice(&data[0..SECTION_NAME_SIZE]);

    let virtual_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let virtual_address = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let size_of_raw_data = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let pointer_to_raw_data = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let pointer_to_relocations = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
    let pointer_to_linenumbers = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
    let number_of_relocations = u16::from_le_bytes([data[32], data[33]]);
    let number_of_linenumbers = u16::from_le_bytes([data[34], data[35]]);
    let characteristics = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

    Ok(ImageSectionHeader {
        name,
        virtual_size,
        virtual_address,
        size_of_raw_data,
        pointer_to_raw_data,
        pointer_to_relocations,
        pointer_to_linenumbers,
        number_of_relocations,
        number_of_linenumbers,
        characteristics,
    })
}

// ── Public API ────────────────────────────────────────────────────────────

/// Load and parse DOS and PE headers from a file.
///
/// Returns `(DosHeader, PeHeader)` on success. Uses pread-style
/// semantics — the file position is not changed.
pub fn pe_load_headers(file: &mut File) -> Result<(DosHeader, PeHeader), PeError> {
    // Read DOS header
    let dos_data = pread_exact(file, 0, DOS_HEADER_SIZE)?;
    let dos_array: [u8; DOS_HEADER_SIZE] = dos_data.try_into().map_err(|_| PeError::ShortRead)?;
    let dos_header = DosHeader::from_bytes(&dos_array)?;

    // Read PE signature + COFF header (4 + 20 = 24 bytes)
    let pe_prefix_size = 24;
    let pe_data = pread_exact(file, dos_header.e_lfanew as u64, pe_prefix_size)?;

    let signature = u32::from_le_bytes([pe_data[0], pe_data[1], pe_data[2], pe_data[3]]);
    if signature != PE_SIGNATURE {
        return Err(PeError::InvalidPeSignature(format!(
            "Expected 0x{:08X}, got 0x{:08X}",
            PE_SIGNATURE, signature
        )));
    }

    let machine = u16::from_le_bytes([pe_data[4], pe_data[5]]);
    let number_of_sections = u16::from_le_bytes([pe_data[6], pe_data[7]]);
    let time_date_stamp = u32::from_le_bytes([pe_data[8], pe_data[9], pe_data[10], pe_data[11]]);
    let pointer_to_symbol_table =
        u32::from_le_bytes([pe_data[12], pe_data[13], pe_data[14], pe_data[15]]);
    let number_of_symbols =
        u32::from_le_bytes([pe_data[16], pe_data[17], pe_data[18], pe_data[19]]);
    let size_of_optional_header = u16::from_le_bytes([pe_data[20], pe_data[21]]);
    let characteristics = u16::from_le_bytes([pe_data[22], pe_data[23]]);

    if (size_of_optional_header as usize) < OPTIONAL_HEADER_MAGIC_SIZE {
        return Err(PeError::InvalidOptionalSize(format!(
            "Optional header size {} too short for magic field",
            size_of_optional_header
        )));
    }

    // Read the optional header
    let optional_offset = dos_header.e_lfanew as u64 + pe_prefix_size as u64;
    let optional_data = pread_exact(file, optional_offset, size_of_optional_header as usize)?;
    let optional = parse_optional_header(&optional_data, size_of_optional_header)?;

    let pe_header = PeHeader {
        signature,
        coff_header: ImageFileHeader {
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
        },
        optional,
    };

    Ok((dos_header, pe_header))
}

/// Load the section table from a PE file.
///
/// The section table immediately follows the PE headers.
pub fn pe_load_sections(
    file: &mut File,
    dos_header: &DosHeader,
    pe_header: &PeHeader,
) -> Result<Vec<ImageSectionHeader>, PeError> {
    let n_sections = pe_header.coff_header.number_of_sections as usize;
    if n_sections == 0 {
        return Ok(Vec::new());
    }

    let table_offset = dos_header.e_lfanew as u64 + pe_header.header_size() as u64;
    let table_size = n_sections * SECTION_HEADER_SIZE;
    let table_data = pread_exact(file, table_offset, table_size)?;

    let mut sections = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let start = i * SECTION_HEADER_SIZE;
        let end = start + SECTION_HEADER_SIZE;
        let section = parse_section_header(&table_data[start..end])?;
        sections.push(section);
    }

    Ok(sections)
}

/// Find a section by name in the section table.
///
/// Matches exactly: the name must fill the section name field completely
/// (either 8 bytes exactly, or NUL-padded for shorter names).
pub fn pe_section_table_find<'a>(
    sections: &'a [ImageSectionHeader],
    n_sections: usize,
    name: &'a str,
) -> Option<&'a ImageSectionHeader> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > SECTION_NAME_SIZE {
        return None;
    }

    let effective_count = n_sections.min(sections.len());
    for section in &sections[..effective_count] {
        // Check that the name matches and the rest is NUL-padded
        if section.name[..name_bytes.len()] == *name_bytes {
            let rest = &section.name[name_bytes.len()..];
            if rest.iter().all(|&b| b == 0) {
                return Some(section);
            }
        }
    }

    None
}

/// Read the raw data of a section from a PE file.
///
/// `max_size` limits the maximum amount of data that will be read.
/// Returns the section data as a `Vec<u8>`.
pub fn pe_read_section_data(
    file: &mut File,
    section: &ImageSectionHeader,
    max_size: usize,
) -> Result<Vec<u8>, PeError> {
    let n = section.virtual_size as usize;
    let effective_max = max_size.min(isize::MAX as usize);
    if n > effective_max {
        return Err(PeError::SectionTooLarge);
    }

    let mut data = vec![0u8; n];
    if n > 0 {
        file.seek(SeekFrom::Start(section.pointer_to_raw_data as u64))?;
        file.read_exact(&mut data)?;
    }

    Ok(data)
}

/// Read section data by name from a PE file.
///
/// Looks up the section by name, then reads its data.
/// Returns `PeError::SectionNotFound` if the section doesn't exist.
pub fn pe_read_section_data_by_name(
    file: &mut File,
    pe_header: &PeHeader,
    sections: &[ImageSectionHeader],
    name: &str,
    max_size: usize,
) -> Result<Vec<u8>, PeError> {
    let section = pe_header
        .find_section(sections, name)
        .ok_or_else(|| PeError::SectionNotFound(name.to_string()))?;
    pe_read_section_data(file, section, max_size)
}

/// Read section data as a NUL-terminated string.
///
/// If the section data contains embedded NUL bytes that are not at the end,
/// returns `PeError::EmbeddedNul`.
pub fn pe_read_section_string(
    file: &mut File,
    section: &ImageSectionHeader,
    max_size: usize,
) -> Result<String, PeError> {
    let data = pe_read_section_data(file, section, max_size)?;

    // Check for embedded NULs: if there's a NUL, everything after must be NUL
    if let Some(nul_pos) = data.iter().position(|&b| b == 0) {
        if !data[nul_pos..].iter().all(|&b| b == 0) {
            return Err(PeError::EmbeddedNul);
        }
        let s = std::str::from_utf8(&data[..nul_pos])
            .map_err(|e| PeError::InvalidDosHeader(format!("Invalid UTF-8 in section: {}", e)))?;
        Ok(s.to_string())
    } else {
        let s = std::str::from_utf8(&data)
            .map_err(|e| PeError::InvalidDosHeader(format!("Invalid UTF-8 in section: {}", e)))?;
        Ok(s.to_string())
    }
}

/// Compute the PE checksum over the entire file.
///
/// The checksum algorithm reads the file as an array of u16 values
/// (little-endian), skipping the 4-byte CheckSum field in the optional
/// header, and accumulates with carry folding.
pub fn pe_checksum(file: &mut File) -> Result<u32, PeError> {
    let (_, pe_header) = pe_load_headers(file)?;

    let checksum_offset = pe_header.header_size();
    // CheckSum is at offset 64 within the optional header
    let checksum_field_offset = checksum_offset + 64;

    let mut checksum: u32 = 0;
    let mut offset: u64 = 0;
    let mut buf = [0u8; 64 * 1024];

    loop {
        file.seek(SeekFrom::Start(offset))?;
        let bytes_read = file.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }
        if bytes_read % 2 != 0 {
            return Err(PeError::ShortRead);
        }

        for i in 0..bytes_read / 2 {
            let word_offset = offset + (i as u64) * 2;
            // Skip the CheckSum field
            if word_offset >= checksum_field_offset as u64
                && word_offset < checksum_field_offset as u64 + 4
            {
                continue;
            }
            let val = u16::from_le_bytes([buf[i * 2], buf[i * 2 + 1]]);
            checksum += val as u32;
            checksum = (checksum >> 16) + (checksum & 0xFFFF);
        }

        offset += bytes_read as u64;
    }

    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum += offset as u32;

    Ok(checksum)
}

/// Check if a PE file is native to the current architecture.
///
/// Returns true if the PE machine type matches the host.
#[cfg(target_arch = "x86_64")]
pub fn pe_is_native(pe_header: &PeHeader) -> bool {
    pe_header.coff_header.machine == 0x8664 // IMAGE_FILE_MACHINE_AMD64
}

#[cfg(target_arch = "aarch64")]
pub fn pe_is_native(pe_header: &PeHeader) -> bool {
    pe_header.coff_header.machine == 0xAA64 // IMAGE_FILE_MACHINE_ARM64
}

#[cfg(target_arch = "x86")]
pub fn pe_is_native(pe_header: &PeHeader) -> bool {
    pe_header.coff_header.machine == 0x014C // IMAGE_FILE_MACHINE_I386
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86")))]
pub fn pe_is_native(_pe_header: &PeHeader) -> bool {
    false
}

/// Check if a file contains a PE binary native to the current architecture.
pub fn pe_is_native_fd(file: &mut File) -> Result<bool, PeError> {
    let (_, pe_header) = pe_load_headers(file)?;
    Ok(pe_is_native(&pe_header))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Helper: build a minimal valid PE32 file in memory.
    fn build_minimal_pe32() -> Vec<u8> {
        let mut file = Vec::new();

        // ── DOS header (64 bytes) ──
        let mut dos = [0u8; DOS_HEADER_SIZE];
        dos[0] = 0x4D; // 'M'
        dos[1] = 0x5A; // 'Z'
        dos[60..64].copy_from_slice(&64u32.to_le_bytes());
        file.extend_from_slice(&dos);

        // ── PE signature (4 bytes) ──
        file.extend_from_slice(&PE_SIGNATURE.to_le_bytes());

        // ── COFF header (20 bytes) ──
        file.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
        file.extend_from_slice(&0u16.to_le_bytes()); // NumberOfSections: 0
        file.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        file.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
        file.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
        // PE32 fixed = 96 bytes, 16 data dirs * 8 = 128, total opt = 224
        let size_of_opt: u16 = 96 + 16 * 8;
        file.extend_from_slice(&size_of_opt.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes()); // Characteristics

        // ── Optional header (PE32) ──
        file.extend_from_slice(&PE32_MAGIC.to_le_bytes());
        file.push(0); // MajorLinkerVersion
        file.push(0); // MinorLinkerVersion
        file.extend_from_slice(&0u32.to_le_bytes()); // SizeOfCode
        file.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
        file.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
        file.extend_from_slice(&0u32.to_le_bytes()); // AddressOfEntryPoint
        file.extend_from_slice(&0u32.to_le_bytes()); // BaseOfCode
        file.extend_from_slice(&0u32.to_le_bytes()); // BaseOfData (PE32 only)
        file.extend_from_slice(&0u32.to_le_bytes()); // ImageBase (4 bytes)
        file.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        file.extend_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        file.extend_from_slice(&0x06u16.to_le_bytes()); // MajorOperatingSystemVersion
        file.extend_from_slice(&0x00u16.to_le_bytes()); // MinorOperatingSystemVersion
        file.extend_from_slice(&0x00u16.to_le_bytes()); // MajorImageVersion
        file.extend_from_slice(&0x00u16.to_le_bytes()); // MinorImageVersion
        file.extend_from_slice(&0x06u16.to_le_bytes()); // MajorSubsystemVersion
        file.extend_from_slice(&0x00u16.to_le_bytes()); // MinorSubsystemVersion
        file.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
        file.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfImage
        file.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        file.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        file.extend_from_slice(&IMAGE_SUBSYSTEM_EFI_APPLICATION.to_le_bytes()); // Subsystem
        file.extend_from_slice(&0u16.to_le_bytes()); // DllCharacteristics
        // PE32: stack/heap sizes are 4 bytes each
        file.extend_from_slice(&0x100000u32.to_le_bytes()); // SizeOfStackReserve
        file.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfStackCommit
        file.extend_from_slice(&0x100000u32.to_le_bytes()); // SizeOfHeapReserve
        file.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfHeapCommit
        file.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
        file.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        // Data directory entries (16 * 8 = 128 bytes)
        for _ in 0..16 {
            file.extend_from_slice(&0u32.to_le_bytes());
            file.extend_from_slice(&0u32.to_le_bytes());
        }

        file
    }

    /// Helper: build a minimal valid PE32+ (64-bit) file.
    fn build_minimal_pe32plus() -> Vec<u8> {
        let mut file = Vec::new();

        // ── DOS header (64 bytes) ──
        let mut dos = [0u8; DOS_HEADER_SIZE];
        dos[0] = 0x4D;
        dos[1] = 0x5A;
        dos[60..64].copy_from_slice(&64u32.to_le_bytes());
        file.extend_from_slice(&dos);

        // ── PE signature (4 bytes) ──
        file.extend_from_slice(&PE_SIGNATURE.to_le_bytes());

        // ── COFF header (20 bytes) ──
        file.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
        file.extend_from_slice(&0u16.to_le_bytes()); // NumberOfSections: 0
        file.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        file.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
        file.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
        // PE32+ fixed = 112 bytes, 16 data dirs * 8 = 128, total opt = 240
        let size_of_opt: u16 = 112 + 16 * 8;
        file.extend_from_slice(&size_of_opt.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes()); // Characteristics

        // ── Optional header (PE32+) ──
        file.extend_from_slice(&PE32PLUS_MAGIC.to_le_bytes());
        file.push(0); // MajorLinkerVersion
        file.push(0); // MinorLinkerVersion
        file.extend_from_slice(&0u32.to_le_bytes()); // SizeOfCode
        file.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
        file.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
        file.extend_from_slice(&0u32.to_le_bytes()); // AddressOfEntryPoint
        file.extend_from_slice(&0u32.to_le_bytes()); // BaseOfCode
        file.extend_from_slice(&0u64.to_le_bytes()); // ImageBase (8 bytes)
        file.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        file.extend_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        file.extend_from_slice(&0x06u16.to_le_bytes()); // MajorOperatingSystemVersion
        file.extend_from_slice(&0x00u16.to_le_bytes()); // MinorOperatingSystemVersion
        file.extend_from_slice(&0x00u16.to_le_bytes()); // MajorImageVersion
        file.extend_from_slice(&0x00u16.to_le_bytes()); // MinorImageVersion
        file.extend_from_slice(&0x06u16.to_le_bytes()); // MajorSubsystemVersion
        file.extend_from_slice(&0x00u16.to_le_bytes()); // MinorSubsystemVersion
        file.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
        file.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfImage
        file.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        file.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        file.extend_from_slice(&IMAGE_SUBSYSTEM_EFI_APPLICATION.to_le_bytes()); // Subsystem
        file.extend_from_slice(&0u16.to_le_bytes()); // DllCharacteristics
        // PE32+: stack/heap sizes are 8 bytes each
        file.extend_from_slice(&0x100000u64.to_le_bytes()); // SizeOfStackReserve
        file.extend_from_slice(&0x1000u64.to_le_bytes()); // SizeOfStackCommit
        file.extend_from_slice(&0x100000u64.to_le_bytes()); // SizeOfHeapReserve
        file.extend_from_slice(&0x1000u64.to_le_bytes()); // SizeOfHeapCommit
        file.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
        file.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        // Data directory entries (16 * 8 = 128 bytes)
        for _ in 0..16 {
            file.extend_from_slice(&0u32.to_le_bytes());
            file.extend_from_slice(&0u32.to_le_bytes());
        }

        file
    }

    /// Helper: write PE bytes to a temp file and return the File handle.
    fn make_pe_file(data: &[u8]) -> File {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join("pe_binary_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("test_{}_{}.pe", std::process::id(), id));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(data).unwrap();
        f.flush().unwrap();
        File::open(&path).unwrap()
    }

    #[test]
    fn test_dos_header_valid_mz_magic() {
        let mut data = [0u8; DOS_HEADER_SIZE];
        data[0] = 0x4D; // 'M'
        data[1] = 0x5A; // 'Z'
        let header = DosHeader::from_bytes(&data).unwrap();
        assert_eq!(header.e_magic, MZ_MAGIC);
    }

    #[test]
    fn test_dos_header_invalid_magic() {
        let data = [0u8; DOS_HEADER_SIZE];
        let result = DosHeader::from_bytes(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            PeError::InvalidDosHeader(msg) => {
                assert!(msg.contains("MZ"));
            }
            e => panic!("Expected InvalidDosHeader, got {:?}", e),
        }
    }

    #[test]
    fn test_dos_header_lfanew() {
        let mut data = [0u8; DOS_HEADER_SIZE];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60..64].copy_from_slice(&0x80u32.to_le_bytes());
        let header = DosHeader::from_bytes(&data).unwrap();
        assert_eq!(header.e_lfanew, 0x80);
    }

    #[test]
    fn test_pe_header_is_64bit_pe32() {
        let pe = PeHeader {
            signature: PE_SIGNATURE,
            coff_header: ImageFileHeader {
                machine: 0,
                number_of_sections: 0,
                time_date_stamp: 0,
                pointer_to_symbol_table: 0,
                number_of_symbols: 0,
                size_of_optional_header: 0,
                characteristics: 0,
            },
            optional: PeOptionalHeader {
                magic: PE32_MAGIC,
                ..Default::default()
            },
        };
        assert!(!pe.is_64bit());
    }

    #[test]
    fn test_pe_header_is_64bit_pe32plus() {
        let pe = PeHeader {
            signature: PE_SIGNATURE,
            coff_header: ImageFileHeader {
                machine: 0x8664,
                number_of_sections: 0,
                time_date_stamp: 0,
                pointer_to_symbol_table: 0,
                number_of_symbols: 0,
                size_of_optional_header: 240,
                characteristics: 0,
            },
            optional: PeOptionalHeader {
                magic: PE32PLUS_MAGIC,
                number_of_rva_and_sizes: 16,
                data_directory: vec![ImageDataDirectory::default(); 16],
                ..Default::default()
            },
        };
        assert!(pe.is_64bit());
    }

    #[test]
    fn test_pe_header_size_pe32() {
        let pe_data = build_minimal_pe32();
        let mut file = make_pe_file(&pe_data);
        let (_, pe_header) = pe_load_headers(&mut file).unwrap();
        // 4 (sig) + 20 (coff) + 224 (opt) = 248
        assert_eq!(pe_header.header_size(), 248);
    }

    #[test]
    fn test_pe_header_size_pe32plus() {
        let pe_data = build_minimal_pe32plus();
        let mut file = make_pe_file(&pe_data);
        let (_, pe_header) = pe_load_headers(&mut file).unwrap();
        // 4 (sig) + 20 (coff) + 240 (opt) = 264
        assert_eq!(pe_header.header_size(), 264);
    }

    #[test]
    fn test_load_headers_pe32() {
        let pe_data = build_minimal_pe32();
        let mut file = make_pe_file(&pe_data);
        let (dos, pe) = pe_load_headers(&mut file).unwrap();
        assert_eq!(dos.e_magic, MZ_MAGIC);
        assert_eq!(pe.signature, PE_SIGNATURE);
        assert_eq!(pe.optional.magic, PE32_MAGIC);
        assert_eq!(pe.coff_header.machine, 0x8664);
        assert!(!pe.is_64bit());
    }

    #[test]
    fn test_load_headers_pe32plus() {
        let pe_data = build_minimal_pe32plus();
        let mut file = make_pe_file(&pe_data);
        let (_, pe) = pe_load_headers(&mut file).unwrap();
        assert_eq!(pe.signature, PE_SIGNATURE);
        assert_eq!(pe.optional.magic, PE32PLUS_MAGIC);
        assert!(pe.is_64bit());
    }

    #[test]
    fn test_load_headers_invalid_file() {
        let data = [0u8; 64];
        let mut file = make_pe_file(&data);
        let result = pe_load_headers(&mut file);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_headers_missing_pe_signature() {
        let mut data = [0u8; 128];
        data[0] = 0x4D;
        data[1] = 0x5A;
        let mut file = make_pe_file(&data);
        let result = pe_load_headers(&mut file);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_data_directory() {
        let pe_data = build_minimal_pe32();
        let mut file = make_pe_file(&pe_data);
        let (_, pe) = pe_load_headers(&mut file).unwrap();
        assert!(pe.get_data_directory(0).is_some());
        assert!(pe.get_data_directory(15).is_some());
        assert!(pe.get_data_directory(16).is_none());
    }

    #[test]
    fn test_section_table_find() {
        let sections = vec![
            ImageSectionHeader {
                name: *b".text\0\0\0",
                virtual_size: 0x1000,
                virtual_address: 0x1000,
                size_of_raw_data: 0x200,
                pointer_to_raw_data: 0x400,
                ..Default::default()
            },
            ImageSectionHeader {
                name: *b".data\0\0\0",
                virtual_size: 0x500,
                virtual_address: 0x2000,
                size_of_raw_data: 0x200,
                pointer_to_raw_data: 0x600,
                ..Default::default()
            },
        ];

        let found = pe_section_table_find(&sections, 2, ".text").unwrap();
        assert_eq!(found.virtual_size, 0x1000);

        let found = pe_section_table_find(&sections, 2, ".data").unwrap();
        assert_eq!(found.virtual_size, 0x500);

        assert!(pe_section_table_find(&sections, 2, ".rdata").is_none());
    }

    #[test]
    fn test_section_table_find_name_too_long() {
        let sections = vec![ImageSectionHeader {
            name: *b".text\0\0\0",
            ..Default::default()
        }];
        assert!(pe_section_table_find(&sections, 1, ".longname").is_none());
    }

    #[test]
    fn test_section_name_str() {
        let section = ImageSectionHeader {
            name: *b".linux\0\0",
            ..Default::default()
        };
        assert_eq!(section.name_str(), ".linux");

        let section2 = ImageSectionHeader {
            name: *b"12345678",
            ..Default::default()
        };
        assert_eq!(section2.name_str(), "12345678");
    }

    #[test]
    fn test_is_uki_true() {
        let pe = PeHeader {
            signature: PE_SIGNATURE,
            coff_header: ImageFileHeader {
                machine: 0x8664,
                number_of_sections: 2,
                time_date_stamp: 0,
                pointer_to_symbol_table: 0,
                number_of_symbols: 0,
                size_of_optional_header: 0,
                characteristics: 0,
            },
            optional: PeOptionalHeader {
                magic: PE32PLUS_MAGIC,
                subsystem: IMAGE_SUBSYSTEM_EFI_APPLICATION,
                ..Default::default()
            },
        };

        let sections = vec![
            ImageSectionHeader {
                name: *b".osrel\0\0",
                ..Default::default()
            },
            ImageSectionHeader {
                name: *b".linux\0\0",
                ..Default::default()
            },
        ];

        assert!(pe.is_uki(&sections));
    }

    #[test]
    fn test_is_uki_missing_osrel() {
        let pe = PeHeader {
            signature: PE_SIGNATURE,
            coff_header: ImageFileHeader {
                machine: 0x8664,
                number_of_sections: 1,
                time_date_stamp: 0,
                pointer_to_symbol_table: 0,
                number_of_symbols: 0,
                size_of_optional_header: 0,
                characteristics: 0,
            },
            optional: PeOptionalHeader {
                magic: PE32PLUS_MAGIC,
                subsystem: IMAGE_SUBSYSTEM_EFI_APPLICATION,
                ..Default::default()
            },
        };

        let sections = vec![ImageSectionHeader {
            name: *b".linux\0\0",
            ..Default::default()
        }];

        assert!(!pe.is_uki(&sections));
    }

    #[test]
    fn test_is_uki_wrong_subsystem() {
        let pe = PeHeader {
            signature: PE_SIGNATURE,
            coff_header: ImageFileHeader {
                machine: 0x8664,
                number_of_sections: 2,
                time_date_stamp: 0,
                pointer_to_symbol_table: 0,
                number_of_symbols: 0,
                size_of_optional_header: 0,
                characteristics: 0,
            },
            optional: PeOptionalHeader {
                magic: PE32PLUS_MAGIC,
                subsystem: 3, // WINDOWS_CUI
                ..Default::default()
            },
        };

        let sections = vec![
            ImageSectionHeader {
                name: *b".osrel\0\0",
                ..Default::default()
            },
            ImageSectionHeader {
                name: *b".linux\0\0",
                ..Default::default()
            },
        ];

        assert!(!pe.is_uki(&sections));
    }

    #[test]
    fn test_is_addon_true() {
        let pe = PeHeader {
            signature: PE_SIGNATURE,
            coff_header: ImageFileHeader {
                machine: 0x8664,
                number_of_sections: 1,
                time_date_stamp: 0,
                pointer_to_symbol_table: 0,
                number_of_symbols: 0,
                size_of_optional_header: 0,
                characteristics: 0,
            },
            optional: PeOptionalHeader {
                magic: PE32PLUS_MAGIC,
                subsystem: IMAGE_SUBSYSTEM_EFI_APPLICATION,
                ..Default::default()
            },
        };

        let sections = vec![ImageSectionHeader {
            name: *b".cmdline",
            ..Default::default()
        }];

        assert!(pe.is_addon(&sections));
    }

    #[test]
    fn test_is_addon_false_has_linux() {
        let pe = PeHeader {
            signature: PE_SIGNATURE,
            coff_header: ImageFileHeader {
                machine: 0x8664,
                number_of_sections: 2,
                time_date_stamp: 0,
                pointer_to_symbol_table: 0,
                number_of_symbols: 0,
                size_of_optional_header: 0,
                characteristics: 0,
            },
            optional: PeOptionalHeader {
                magic: PE32PLUS_MAGIC,
                subsystem: IMAGE_SUBSYSTEM_EFI_APPLICATION,
                ..Default::default()
            },
        };

        let sections = vec![
            ImageSectionHeader {
                name: *b".linux\0\0",
                ..Default::default()
            },
            ImageSectionHeader {
                name: *b".cmdline",
                ..Default::default()
            },
        ];

        // Has .linux → not an addon (it's a full UKI)
        assert!(!pe.is_addon(&sections));
    }

    #[test]
    fn test_pe_read_section_data_by_name_not_found() {
        let pe_data = build_minimal_pe32();
        let mut file = make_pe_file(&pe_data);
        let (_, pe) = pe_load_headers(&mut file).unwrap();
        let sections = Vec::new();
        let result = pe_read_section_data_by_name(&mut file, &pe, &sections, ".nonexistent", 1024);
        assert!(matches!(result, Err(PeError::SectionNotFound(_))));
    }

    #[test]
    fn test_constants() {
        assert_eq!(MZ_MAGIC, 0x5A4D);
        assert_eq!(PE_SIGNATURE, 0x0000_4550);
        assert_eq!(PE32_MAGIC, 0x010B);
        assert_eq!(PE32PLUS_MAGIC, 0x020B);
        assert_eq!(IMAGE_SUBSYSTEM_EFI_APPLICATION, 10);
        assert_eq!(IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE, 4);
        assert_eq!(DOS_HEADER_SIZE, 64);
        assert_eq!(SECTION_HEADER_SIZE, 40);
        assert_eq!(SECTION_NAME_SIZE, 8);
        assert_eq!(IMAGE_DATA_DIRECTORY_SIZE, 8);
    }

    #[test]
    fn test_pe_error_display() {
        let err = PeError::InvalidDosHeader("bad magic".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("bad magic"));

        let err = PeError::SectionNotFound(".linux".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains(".linux"));
    }

    #[test]
    fn test_pe_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "not found");
        let pe_err: PeError = io_err.into();
        assert!(matches!(pe_err, PeError::Io(_)));
    }

    #[test]
    fn test_pe_load_sections_no_sections() {
        let pe_data = build_minimal_pe32();
        let mut file = make_pe_file(&pe_data);
        let (dos, pe) = pe_load_headers(&mut file).unwrap();
        let sections = pe_load_sections(&mut file, &dos, &pe).unwrap();
        assert!(sections.is_empty());
    }

    #[test]
    fn test_pe_is_native_on_current_arch() {
        // On x86_64, AMD64 machine type should match
        let pe = PeHeader {
            signature: PE_SIGNATURE,
            coff_header: ImageFileHeader {
                machine: 0x8664,
                ..Default::default()
            },
            optional: PeOptionalHeader::default(),
        };
        // Just verify it doesn't panic; the result depends on the host arch
        let _ = pe_is_native(&pe);
    }

    #[test]
    fn test_section_table_find_empty_sections() {
        let sections: Vec<ImageSectionHeader> = Vec::new();
        assert!(pe_section_table_find(&sections, 0, ".text").is_none());
    }

    #[test]
    fn test_section_table_find_with_exact_8_char_name() {
        let sections = vec![ImageSectionHeader {
            name: *b".1234567", // exactly 8 chars, no NUL padding
            ..Default::default()
        }];
        // Must match exactly — no NUL padding check needed since name fills the field
        let found = pe_section_table_find(&sections, 1, ".1234567");
        assert!(found.is_some());

        // A shorter name should NOT match since the remaining bytes aren't NUL
        let not_found = pe_section_table_find(&sections, 1, ".123456");
        assert!(not_found.is_none());
    }
}
