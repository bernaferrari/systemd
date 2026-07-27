// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/elf-util.c, src/shared/elf-util.h
//
// ELF (Executable and Linkable Format) parsing utilities.
//
// Pure Rust implementation for parsing ELF files including header parsing
// (32/64-bit, little/big-endian), section lookup by name and type,
// GNU build-id extraction from note sections, program header access,
// core dump identification, and interpreter segment detection.
// No external ELF library dependencies required.

// ── Error types ────────────────────────────────────────────────────────────

/// Errors that can occur during ELF parsing.
use crate::ffi::*;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    /// Not a valid ELF file (magic number mismatch).
    InvalidMagic,
    /// File data is too short to contain the expected structure.
    TooShort,
    /// ELF class is neither 32-bit nor 64-bit.
    InvalidClass,
    /// ELF data encoding is neither little-endian nor big-endian.
    InvalidEncoding,
    /// Section index out of bounds.
    InvalidSectionIndex,
    /// Section header string table index out of bounds.
    InvalidShstrndx,
    /// Section header offset or size overflows the file.
    InvalidSectionOffset,
    /// Program header offset or size overflows the file.
    InvalidProgramOffset,
    /// String table offset overflows the section data.
    InvalidStringOffset,
    /// A NOTE section is malformed (truncated header, bad alignment, etc.).
    InvalidNote,
    /// A name string is not null-terminated within the available bounds.
    UnterminatedString,
    /// The requested section was not found.
    SectionNotFound,
}

impl std::fmt::Display for ElfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "not a valid ELF file: magic mismatch"),
            Self::TooShort => write!(f, "file too short for ELF structure"),
            Self::InvalidClass => write!(f, "invalid ELF class (not 32-bit or 64-bit)"),
            Self::InvalidEncoding => write!(f, "invalid ELF data encoding"),
            Self::InvalidSectionIndex => write!(f, "section index out of bounds"),
            Self::InvalidShstrndx => {
                write!(f, "section header string table index out of bounds")
            }
            Self::InvalidSectionOffset => {
                write!(f, "section header offset or size out of bounds")
            }
            Self::InvalidProgramOffset => {
                write!(f, "program header offset or size out of bounds")
            }
            Self::InvalidStringOffset => write!(f, "string table offset out of bounds"),
            Self::InvalidNote => write!(f, "malformed ELF note section"),
            Self::UnterminatedString => write!(f, "string not null-terminated within bounds"),
            Self::SectionNotFound => write!(f, "requested section not found"),
        }
    }
}

impl std::error::Error for ElfError {}

// ── ELF constants ──────────────────────────────────────────────────────────

/// ELF magic number: `\x7fELF`.
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF file classes.
pub const ELFCLASSNONE: u8 = 0;
pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;

/// ELF data encoding (endianness).
pub const ELFDATA2NONE: u8 = 0;
pub const ELFDATA2LSB: u8 = 1;
pub const ELFDATA2MSB: u8 = 2;

/// ELF object file types.
pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

/// ELF section header types.
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_DYNSYM: u32 = 11;

/// ELF program header types.
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;

/// Standard ELF note type for the GNU build-id.
pub const NT_GNU_BUILD_ID: u32 = 3;

/// Size of the ELF identification (`e_ident`) array.
pub const EI_NIDENT: usize = 16;

/// Index of the class byte inside `e_ident`.
pub const EI_CLASS: usize = 4;

/// Index of the data-encoding byte inside `e_ident`.
pub const EI_DATA: usize = 5;

/// Serialized size of an `Elf32_Ehdr`.
pub const ELF32_EHDR_SIZE: usize = 52;

/// Serialized size of an `Elf64_Ehdr`.
pub const ELF64_EHDR_SIZE: usize = 64;

/// Serialized size of an `Elf32_Shdr`.
pub const ELF32_SHDR_SIZE: usize = 40;

/// Serialized size of an `Elf64_Shdr`.
pub const ELF64_SHDR_SIZE: usize = 64;

/// Serialized size of an `Elf32_Phdr`.
pub const ELF32_PHDR_SIZE: usize = 32;

/// Serialized size of an `Elf64_Phdr`.
pub const ELF64_PHDR_SIZE: usize = 56;

// ── Enums & helper types ───────────────────────────────────────────────────

/// ELF file class — 32-bit or 64-bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    /// 32-bit ELF object.
    Elf32,
    /// 64-bit ELF object.
    Elf64,
}

/// ELF data encoding (byte order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfData {
    /// Little-endian byte order.
    LittleEndian,
    /// Big-endian byte order.
    BigEndian,
}

/// ELF object file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    /// No type (`ET_NONE`).
    None,
    /// Relocatable object file.
    Relocatable,
    /// Executable file.
    Executable,
    /// Position-independent shared object (or PIE executable).
    Dynamic,
    /// Core dump file.
    Core,
    /// Processor-specific or unknown type.
    Other(u16),
}

impl ElfType {
    /// Convert a raw `e_type` value to an [`ElfType`].
    pub fn from_raw(raw: u16) -> Self {
        match raw {
            ET_NONE => Self::None,
            ET_REL => Self::Relocatable,
            ET_EXEC => Self::Executable,
            ET_DYN => Self::Dynamic,
            ET_CORE => Self::Core,
            other => Self::Other(other),
        }
    }

    /// Convert back to the raw `e_type` value.
    pub fn to_raw(self) -> u16 {
        match self {
            Self::None => ET_NONE,
            Self::Relocatable => ET_REL,
            Self::Executable => ET_EXEC,
            Self::Dynamic => ET_DYN,
            Self::Core => ET_CORE,
            Self::Other(v) => v,
        }
    }
}

// ── ELF structures ─────────────────────────────────────────────────────────

/// Parsed 64-bit ELF header (`Elf64_Ehdr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64_Ehdr {
    /// Object file type.
    pub e_type: u16,
    /// Target architecture.
    pub e_machine: u16,
    /// Object file version.
    pub e_version: u32,
    /// Virtual address of the entry point.
    pub e_entry: u64,
    /// File offset of the program header table.
    pub e_phoff: u64,
    /// File offset of the section header table.
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// Size of this ELF header in bytes.
    pub e_ehsize: u16,
    /// Size of each program header entry.
    pub e_phentsize: u16,
    /// Number of program header entries.
    pub e_phnum: u16,
    /// Size of each section header entry.
    pub e_shentsize: u16,
    /// Number of section header entries.
    pub e_shnum: u16,
    /// Index of the section header string table.
    pub e_shstrndx: u16,
}

/// Parsed 32-bit ELF header (`Elf32_Ehdr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf32_Ehdr {
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// Parsed 64-bit ELF section header (`Elf64_Shdr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64_Shdr {
    /// Index into the section header string table.
    pub sh_name: u32,
    /// Section type (e.g. `SHT_NOTE`, `SHT_STRTAB`).
    pub sh_type: u32,
    /// Section flags.
    pub sh_flags: u64,
    /// Virtual address (if the section is loaded).
    pub sh_addr: u64,
    /// File offset of the section data.
    pub sh_offset: u64,
    /// Size of the section data in bytes.
    pub sh_size: u64,
    /// Link to an associated section (depends on `sh_type`).
    pub sh_link: u32,
    /// Extra type-specific information.
    pub sh_info: u32,
    /// Required alignment.
    pub sh_addralign: u64,
    /// Size of each entry (for table sections).
    pub sh_entsize: u64,
}

/// Parsed 32-bit ELF section header (`Elf32_Shdr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf32_Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u32,
    pub sh_addr: u32,
    pub sh_offset: u32,
    pub sh_size: u32,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u32,
    pub sh_entsize: u32,
}

/// Parsed 64-bit ELF program header (`Elf64_Phdr`).
///
/// Note: `p_flags` is at offset 4 in the 64-bit layout (before `p_offset`),
/// but at offset 24 in the 32-bit layout (after `p_memsz`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64_Phdr {
    /// Segment type (e.g. `PT_LOAD`, `PT_NOTE`).
    pub p_type: u32,
    /// Segment flags (`PF_R`, `PF_W`, `PF_X`).
    pub p_flags: u32,
    /// File offset of the segment data.
    pub p_offset: u64,
    /// Virtual address where the segment is loaded.
    pub p_vaddr: u64,
    /// Physical address (usually ignored on modern systems).
    pub p_paddr: u64,
    /// Size of the segment in the file.
    pub p_filesz: u64,
    /// Size of the segment in memory (may be larger than `p_filesz` for BSS).
    pub p_memsz: u64,
    /// Alignment requirement.
    pub p_align: u64,
}

/// Parsed 32-bit ELF program header (`Elf32_Phdr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf32_Phdr {
    pub p_type: u32,
    pub p_offset: u32,
    pub p_vaddr: u32,
    pub p_paddr: u32,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

/// A single parsed ELF NOTE entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfNote<'a> {
    /// Note owner / name (e.g. `"GNU"`).
    pub name: &'a str,
    /// Note type (e.g. `NT_GNU_BUILD_ID`).
    pub n_type: u32,
    /// Raw descriptor bytes.
    pub desc: &'a [u8],
}

// ── ELF file parser ───────────────────────────────────────────────────────

/// A parsed ELF file providing safe, idiomatic access to headers, sections,
/// program headers, and notes.
///
/// The parser borrows the underlying byte slice and validates structural
/// offsets on every access, returning [`ElfError`] on out-of-bounds or
/// malformed data.
#[derive(Debug)]
pub struct ElfFile<'a> {
    data: &'a [u8],
    class: ElfClass,
    data_encoding: ElfData,
}

impl<'a> ElfFile<'a> {
    /// Parse an ELF file from a byte slice.
    ///
    /// Validates the magic number, extracts the class (32/64) and
    /// endianness, and returns a handle for further queries.
    ///
    /// # Errors
    ///
    /// Returns [`ElfError::InvalidMagic`] if the first four bytes are not
    /// `\x7fELF`, [`ElfError::TooShort`] if fewer than 16 bytes are
    /// available, or [`ElfError::InvalidClass`] / [`ElfError::InvalidEncoding`]
    /// for unsupported class/encoding values.
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        if data.len() < EI_NIDENT {
            return Err(ElfError::TooShort);
        }
        if &data[0..4] != &ELF_MAGIC {
            return Err(ElfError::InvalidMagic);
        }

        let class = match data[EI_CLASS] {
            ELFCLASS32 => ElfClass::Elf32,
            ELFCLASS64 => ElfClass::Elf64,
            _ => return Err(ElfError::InvalidClass),
        };

        let data_encoding = match data[EI_DATA] {
            ELFDATA2LSB => ElfData::LittleEndian,
            ELFDATA2MSB => ElfData::BigEndian,
            _ => return Err(ElfError::InvalidEncoding),
        };

        Ok(Self {
            data,
            class,
            data_encoding,
        })
    }

    /// Returns the ELF class (32-bit or 64-bit).
    pub fn class(&self) -> ElfClass {
        self.class
    }

    /// Returns the ELF data encoding (endianness).
    pub fn encoding(&self) -> ElfData {
        self.data_encoding
    }

    /// Returns the underlying raw byte slice.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    // ── Primitive readers ────────────────────────────────────────────

    fn read_u16(&self, offset: usize) -> Result<u16, ElfError> {
        let bytes = self
            .data
            .get(offset..offset + 2)
            .ok_or(ElfError::TooShort)?;
        Ok(match self.data_encoding {
            ElfData::LittleEndian => u16::from_le_bytes([bytes[0], bytes[1]]),
            ElfData::BigEndian => u16::from_be_bytes([bytes[0], bytes[1]]),
        })
    }

    fn read_u32(&self, offset: usize) -> Result<u32, ElfError> {
        let bytes = self
            .data
            .get(offset..offset + 4)
            .ok_or(ElfError::TooShort)?;
        Ok(match self.data_encoding {
            ElfData::LittleEndian => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            ElfData::BigEndian => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
    }

    fn read_u64(&self, offset: usize) -> Result<u64, ElfError> {
        let bytes = self
            .data
            .get(offset..offset + 8)
            .ok_or(ElfError::TooShort)?;
        Ok(match self.data_encoding {
            ElfData::LittleEndian => u64::from_le_bytes(bytes.try_into().unwrap()),
            ElfData::BigEndian => u64::from_be_bytes(bytes.try_into().unwrap()),
        })
    }

    /// Read a `u32` from an arbitrary byte slice using this file's endianness.
    fn read_u32_from(&self, buf: &[u8], offset: usize) -> Result<u32, ElfError> {
        let bytes = buf.get(offset..offset + 4).ok_or(ElfError::InvalidNote)?;
        Ok(match self.data_encoding {
            ElfData::LittleEndian => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            ElfData::BigEndian => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
    }

    // ── ELF header parsing ───────────────────────────────────────────

    /// Parse the 64-bit ELF header.
    ///
    /// Returns an error if the file is 32-bit or too short.
    pub fn elf64_ehdr(&self) -> Result<Elf64_Ehdr, ElfError> {
        if self.class != ElfClass::Elf64 {
            return Err(ElfError::InvalidClass);
        }
        if self.data.len() < ELF64_EHDR_SIZE {
            return Err(ElfError::TooShort);
        }
        Ok(Elf64_Ehdr {
            e_type: self.read_u16(16)?,
            e_machine: self.read_u16(18)?,
            e_version: self.read_u32(20)?,
            e_entry: self.read_u64(24)?,
            e_phoff: self.read_u64(32)?,
            e_shoff: self.read_u64(40)?,
            e_flags: self.read_u32(48)?,
            e_ehsize: self.read_u16(52)?,
            e_phentsize: self.read_u16(54)?,
            e_phnum: self.read_u16(56)?,
            e_shentsize: self.read_u16(58)?,
            e_shnum: self.read_u16(60)?,
            e_shstrndx: self.read_u16(62)?,
        })
    }

    /// Parse the 32-bit ELF header.
    ///
    /// Returns an error if the file is 64-bit or too short.
    pub fn elf32_ehdr(&self) -> Result<Elf32_Ehdr, ElfError> {
        if self.class != ElfClass::Elf32 {
            return Err(ElfError::InvalidClass);
        }
        if self.data.len() < ELF32_EHDR_SIZE {
            return Err(ElfError::TooShort);
        }
        Ok(Elf32_Ehdr {
            e_type: self.read_u16(16)?,
            e_machine: self.read_u16(18)?,
            e_version: self.read_u32(20)?,
            e_entry: self.read_u32(24)?,
            e_phoff: self.read_u32(28)?,
            e_shoff: self.read_u32(32)?,
            e_flags: self.read_u32(36)?,
            e_ehsize: self.read_u16(40)?,
            e_phentsize: self.read_u16(42)?,
            e_phnum: self.read_u16(44)?,
            e_shentsize: self.read_u16(46)?,
            e_shnum: self.read_u16(48)?,
            e_shstrndx: self.read_u16(50)?,
        })
    }

    /// Determine the ELF object file type.
    pub fn elf_type(&self) -> Result<ElfType, ElfError> {
        let raw = match self.class {
            ElfClass::Elf64 => self.elf64_ehdr()?.e_type,
            ElfClass::Elf32 => self.elf32_ehdr()?.e_type,
        };
        Ok(ElfType::from_raw(raw))
    }

    /// Returns `true` if this is a core dump (`ET_CORE`).
    pub fn is_core(&self) -> Result<bool, ElfError> {
        Ok(self.elf_type()? == ElfType::Core)
    }

    // ── Section header parsing ───────────────────────────────────────

    /// Parse a single 64-bit section header at the given file offset.
    fn elf64_shdr_at(&self, offset: usize) -> Result<Elf64_Shdr, ElfError> {
        if self.class != ElfClass::Elf64 {
            return Err(ElfError::InvalidClass);
        }
        Ok(Elf64_Shdr {
            sh_name: self.read_u32(offset)?,
            sh_type: self.read_u32(offset + 4)?,
            sh_flags: self.read_u64(offset + 8)?,
            sh_addr: self.read_u64(offset + 16)?,
            sh_offset: self.read_u64(offset + 24)?,
            sh_size: self.read_u64(offset + 32)?,
            sh_link: self.read_u32(offset + 40)?,
            sh_info: self.read_u32(offset + 44)?,
            sh_addralign: self.read_u64(offset + 48)?,
            sh_entsize: self.read_u64(offset + 56)?,
        })
    }

    /// Parse a single 32-bit section header at the given file offset.
    fn elf32_shdr_at(&self, offset: usize) -> Result<Elf32_Shdr, ElfError> {
        if self.class != ElfClass::Elf32 {
            return Err(ElfError::InvalidClass);
        }
        Ok(Elf32_Shdr {
            sh_name: self.read_u32(offset)?,
            sh_type: self.read_u32(offset + 4)?,
            sh_flags: self.read_u32(offset + 8)?,
            sh_addr: self.read_u32(offset + 12)?,
            sh_offset: self.read_u32(offset + 16)?,
            sh_size: self.read_u32(offset + 20)?,
            sh_link: self.read_u32(offset + 24)?,
            sh_info: self.read_u32(offset + 28)?,
            sh_addralign: self.read_u32(offset + 32)?,
            sh_entsize: self.read_u32(offset + 36)?,
        })
    }

    /// Return all 64-bit section headers.
    ///
    /// Returns an empty vector if `e_shnum == 0`.
    pub fn elf64_section_headers(&self) -> Result<Vec<Elf64_Shdr>, ElfError> {
        let ehdr = self.elf64_ehdr()?;
        if ehdr.e_shoff == 0 || ehdr.e_shnum == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(ehdr.e_shnum as usize);
        for i in 0..ehdr.e_shnum {
            let off = ehdr.e_shoff as usize + i as usize * ehdr.e_shentsize as usize;
            out.push(
                self.elf64_shdr_at(off)
                    .map_err(|_| ElfError::InvalidSectionOffset)?,
            );
        }
        Ok(out)
    }

    /// Return all 32-bit section headers.
    pub fn elf32_section_headers(&self) -> Result<Vec<Elf32_Shdr>, ElfError> {
        let ehdr = self.elf32_ehdr()?;
        if ehdr.e_shoff == 0 || ehdr.e_shnum == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(ehdr.e_shnum as usize);
        for i in 0..ehdr.e_shnum {
            let off = ehdr.e_shoff as usize + i as usize * ehdr.e_shentsize as usize;
            out.push(
                self.elf32_shdr_at(off)
                    .map_err(|_| ElfError::InvalidSectionOffset)?,
            );
        }
        Ok(out)
    }

    /// Extract the raw bytes of a 64-bit section by index.
    pub fn elf64_section_data(&self, index: usize) -> Result<&'a [u8], ElfError> {
        let sections = self.elf64_section_headers()?;
        let shdr = sections.get(index).ok_or(ElfError::InvalidSectionIndex)?;
        let end = shdr
            .sh_offset
            .checked_add(shdr.sh_size)
            .ok_or(ElfError::InvalidSectionOffset)?;
        self.data
            .get(shdr.sh_offset as usize..end as usize)
            .ok_or(ElfError::InvalidSectionOffset)
    }

    /// Extract the raw bytes of a 32-bit section by index.
    pub fn elf32_section_data(&self, index: usize) -> Result<&'a [u8], ElfError> {
        let sections = self.elf32_section_headers()?;
        let shdr = sections.get(index).ok_or(ElfError::InvalidSectionIndex)?;
        let end = (shdr.sh_offset + shdr.sh_size) as usize;
        self.data
            .get(shdr.sh_offset as usize..end)
            .ok_or(ElfError::InvalidSectionOffset)
    }

    // ── Program header parsing ───────────────────────────────────────

    /// Parse a single 64-bit program header at the given file offset.
    fn elf64_phdr_at(&self, offset: usize) -> Result<Elf64_Phdr, ElfError> {
        if self.class != ElfClass::Elf64 {
            return Err(ElfError::InvalidClass);
        }
        Ok(Elf64_Phdr {
            p_type: self.read_u32(offset)?,
            p_flags: self.read_u32(offset + 4)?,
            p_offset: self.read_u64(offset + 8)?,
            p_vaddr: self.read_u64(offset + 16)?,
            p_paddr: self.read_u64(offset + 24)?,
            p_filesz: self.read_u64(offset + 32)?,
            p_memsz: self.read_u64(offset + 40)?,
            p_align: self.read_u64(offset + 48)?,
        })
    }

    /// Parse a single 32-bit program header at the given file offset.
    ///
    /// The 32-bit layout places `p_flags` *after* `p_memsz` (offset 24),
    /// unlike the 64-bit layout which places it before `p_offset`.
    fn elf32_phdr_at(&self, offset: usize) -> Result<Elf32_Phdr, ElfError> {
        if self.class != ElfClass::Elf32 {
            return Err(ElfError::InvalidClass);
        }
        Ok(Elf32_Phdr {
            p_type: self.read_u32(offset)?,
            p_offset: self.read_u32(offset + 4)?,
            p_vaddr: self.read_u32(offset + 8)?,
            p_paddr: self.read_u32(offset + 12)?,
            p_filesz: self.read_u32(offset + 16)?,
            p_memsz: self.read_u32(offset + 20)?,
            p_flags: self.read_u32(offset + 24)?,
            p_align: self.read_u32(offset + 28)?,
        })
    }

    /// Return all 64-bit program headers.
    pub fn elf64_program_headers(&self) -> Result<Vec<Elf64_Phdr>, ElfError> {
        let ehdr = self.elf64_ehdr()?;
        if ehdr.e_phoff == 0 || ehdr.e_phnum == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(ehdr.e_phnum as usize);
        for i in 0..ehdr.e_phnum {
            let off = ehdr.e_phoff as usize + i as usize * ehdr.e_phentsize as usize;
            out.push(
                self.elf64_phdr_at(off)
                    .map_err(|_| ElfError::InvalidProgramOffset)?,
            );
        }
        Ok(out)
    }

    /// Return all 32-bit program headers.
    pub fn elf32_program_headers(&self) -> Result<Vec<Elf32_Phdr>, ElfError> {
        let ehdr = self.elf32_ehdr()?;
        if ehdr.e_phoff == 0 || ehdr.e_phnum == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(ehdr.e_phnum as usize);
        for i in 0..ehdr.e_phnum {
            let off = ehdr.e_phoff as usize + i as usize * ehdr.e_phentsize as usize;
            out.push(
                self.elf32_phdr_at(off)
                    .map_err(|_| ElfError::InvalidProgramOffset)?,
            );
        }
        Ok(out)
    }

    // ── String table helpers ─────────────────────────────────────────

    /// Read a NUL-terminated string starting at `offset` within `buf`.
    fn read_cstring(buf: &'a [u8], offset: usize) -> Result<&'a str, ElfError> {
        let end = buf[offset..]
            .iter()
            .position(|&b| b == 0)
            .map(|pos| offset + pos)
            .ok_or(ElfError::UnterminatedString)?;
        std::str::from_utf8(&buf[offset..end]).map_err(|_| ElfError::InvalidStringOffset)
    }

    // ── Section lookup ───────────────────────────────────────────────

    /// Find a section by its name. Returns the section index.
    ///
    /// Uses `e_shstrndx` to locate the section header string table, then
    /// iterates all section headers until a name match is found.
    pub fn elf_find_section(&self, name: &str) -> Result<usize, ElfError> {
        self.find_section_impl(|sh_name, _| sh_name == name)
    }

    /// Find the first section with the given `sh_type`. Returns the section index.
    pub fn elf_find_section_type(&self, sh_type: u32) -> Result<usize, ElfError> {
        self.find_section_impl(|_, actual| actual == sh_type)
    }

    /// Generic section search. The closure receives `(sh_name_str, sh_type)`.
    fn find_section_impl<F>(&self, matches: F) -> Result<usize, ElfError>
    where
        F: Fn(&str, u32) -> bool,
    {
        match self.class {
            ElfClass::Elf64 => {
                let ehdr = self.elf64_ehdr()?;
                let sections = self.elf64_section_headers()?;
                if sections.is_empty() {
                    return Err(ElfError::SectionNotFound);
                }
                if ehdr.e_shstrndx as usize >= sections.len() {
                    return Err(ElfError::InvalidShstrndx);
                }
                let strtab = &sections[ehdr.e_shstrndx as usize];
                let strtab_bytes = self.section_bytes_64(strtab)?;
                for (i, sec) in sections.iter().enumerate() {
                    if let Ok(sec_name) = Self::read_cstring(strtab_bytes, sec.sh_name as usize) {
                        if matches(sec_name, sec.sh_type) {
                            return Ok(i);
                        }
                    }
                }
            }
            ElfClass::Elf32 => {
                let ehdr = self.elf32_ehdr()?;
                let sections = self.elf32_section_headers()?;
                if sections.is_empty() {
                    return Err(ElfError::SectionNotFound);
                }
                if ehdr.e_shstrndx as usize >= sections.len() {
                    return Err(ElfError::InvalidShstrndx);
                }
                let strtab = &sections[ehdr.e_shstrndx as usize];
                let strtab_bytes = self.section_bytes_32(strtab)?;
                for (i, sec) in sections.iter().enumerate() {
                    if let Ok(sec_name) = Self::read_cstring(strtab_bytes, sec.sh_name as usize) {
                        if matches(sec_name, sec.sh_type) {
                            return Ok(i);
                        }
                    }
                }
            }
        }
        Err(ElfError::SectionNotFound)
    }

    fn section_bytes_64(&self, sh: &Elf64_Shdr) -> Result<&'a [u8], ElfError> {
        let end = sh
            .sh_offset
            .checked_add(sh.sh_size)
            .ok_or(ElfError::InvalidSectionOffset)?;
        self.data
            .get(sh.sh_offset as usize..end as usize)
            .ok_or(ElfError::InvalidSectionOffset)
    }

    fn section_bytes_32(&self, sh: &Elf32_Shdr) -> Result<&'a [u8], ElfError> {
        let end = (sh.sh_offset + sh.sh_size) as usize;
        self.data
            .get(sh.sh_offset as usize..end)
            .ok_or(ElfError::InvalidSectionOffset)
    }

    // ── Note parsing ─────────────────────────────────────────────────

    /// Parse all NOTE entries from a raw note-section byte buffer.
    ///
    /// Each NOTE has a 12-byte header (`namesz`, `descsz`, `n_type`)
    /// followed by the name (padded to 4-byte alignment) and the
    /// descriptor (also padded).
    pub fn parse_notes(&self, note_data: &'a [u8]) -> Result<Vec<ElfNote<'a>>, ElfError> {
        let mut notes = Vec::new();
        let mut pos = 0usize;

        while pos.saturating_add(12) <= note_data.len() {
            let namesz = self.read_u32_from(note_data, pos)? as usize;
            let descsz = self.read_u32_from(note_data, pos + 4)? as usize;
            let n_type = self.read_u32_from(note_data, pos + 8)?;
            pos += 12;

            // Name field
            let name_end = pos.checked_add(namesz).ok_or(ElfError::InvalidNote)?;
            if name_end > note_data.len() {
                return Err(ElfError::InvalidNote);
            }
            let name_bytes = &note_data[pos..name_end];
            let name = std::str::from_utf8(name_bytes.split(|&b| b == 0).next().unwrap_or(b""))
                .unwrap_or("");
            pos = (name_end + 3) & !3; // 4-byte align

            // Descriptor field
            let desc_end = pos.checked_add(descsz).ok_or(ElfError::InvalidNote)?;
            if desc_end > note_data.len() {
                return Err(ElfError::InvalidNote);
            }
            let desc = &note_data[pos..desc_end];
            pos = (desc_end + 3) & !3; // 4-byte align

            notes.push(ElfNote { name, n_type, desc });
        }

        Ok(notes)
    }

    /// Extract the GNU build-id from this ELF file.
    ///
    /// Searches for the `.note.gnu.build-id` section, parses its NOTE
    /// entries, and returns the descriptor of the first note with
    /// `n_type == NT_GNU_BUILD_ID`.
    pub fn elf_get_build_id(&self) -> Result<Vec<u8>, ElfError> {
        let sec_idx = self.elf_find_section(".note.gnu.build-id")?;
        let note_data = match self.class {
            ElfClass::Elf64 => self.elf64_section_data(sec_idx)?,
            ElfClass::Elf32 => self.elf32_section_data(sec_idx)?,
        };

        for note in self.parse_notes(note_data)? {
            if note.n_type == NT_GNU_BUILD_ID {
                return Ok(note.desc.to_vec());
            }
        }
        Err(ElfError::SectionNotFound)
    }

    /// Retrieve basic core dump statistics.
    ///
    /// Returns `(note_segment_count, load_segment_count)`. The file must
    /// be of type `ET_CORE`; otherwise returns [`ElfError::InvalidClass`].
    pub fn elf_get_coredump(&self) -> Result<(usize, usize), ElfError> {
        if !self.is_core()? {
            return Err(ElfError::InvalidClass);
        }

        let (mut notes, mut loads) = (0usize, 0usize);
        match self.class {
            ElfClass::Elf64 => {
                for phdr in self.elf64_program_headers()? {
                    match phdr.p_type {
                        PT_NOTE => notes += 1,
                        PT_LOAD => loads += 1,
                        _ => {}
                    }
                }
            }
            ElfClass::Elf32 => {
                for phdr in self.elf32_program_headers()? {
                    match phdr.p_type {
                        PT_NOTE => notes += 1,
                        PT_LOAD => loads += 1,
                        _ => {}
                    }
                }
            }
        }
        Ok((notes, loads))
    }

    /// Check whether this ELF file contains a `PT_INTERP` program header,
    /// which indicates it is a directly-invoked executable (not a shared
    /// library opened via `dlopen`).
    pub fn has_interp_segment(&self) -> Result<bool, ElfError> {
        match self.class {
            ElfClass::Elf64 => Ok(self
                .elf64_program_headers()?
                .iter()
                .any(|p| p.p_type == PT_INTERP)),
            ElfClass::Elf32 => Ok(self
                .elf32_program_headers()?
                .iter()
                .any(|p| p.p_type == PT_INTERP)),
        }
    }
}

// ── Free-standing convenience functions ────────────────────────────────────

/// Returns `true` if `data` begins with the ELF magic number.
pub fn elf_is_elf(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == &ELF_MAGIC
}

/// Detect the ELF class (32-bit or 64-bit) from raw bytes.
pub fn elf_detect_class(data: &[u8]) -> Result<ElfClass, ElfError> {
    if data.len() < EI_NIDENT {
        return Err(ElfError::TooShort);
    }
    if &data[0..4] != &ELF_MAGIC {
        return Err(ElfError::InvalidMagic);
    }
    match data[EI_CLASS] {
        ELFCLASS32 => Ok(ElfClass::Elf32),
        ELFCLASS64 => Ok(ElfClass::Elf64),
        _ => Err(ElfError::InvalidClass),
    }
}

/// Detect the ELF data encoding (endianness) from raw bytes.
pub fn elf_detect_encoding(data: &[u8]) -> Result<ElfData, ElfError> {
    if data.len() < EI_NIDENT {
        return Err(ElfError::TooShort);
    }
    if &data[0..4] != &ELF_MAGIC {
        return Err(ElfError::InvalidMagic);
    }
    match data[EI_DATA] {
        ELFDATA2LSB => Ok(ElfData::LittleEndian),
        ELFDATA2MSB => Ok(ElfData::BigEndian),
        _ => Err(ElfError::InvalidEncoding),
    }
}

/// Convenience wrapper: parse an ELF file and extract the GNU build-id.
pub fn elf_get_build_id(data: &[u8]) -> Result<Vec<u8>, ElfError> {
    ElfFile::parse(data)?.elf_get_build_id()
}

/// Convenience wrapper: parse an ELF file and determine its type.
pub fn elf_get_type(data: &[u8]) -> Result<ElfType, ElfError> {
    ElfFile::parse(data)?.elf_type()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────

    /// Build a minimal valid 64-bit LE ELF header with the given type.
    fn make_elf64(e_type: u16, e_machine: u16) -> Vec<u8> {
        let mut d = vec![0u8; ELF64_EHDR_SIZE];
        d[0..4].copy_from_slice(&ELF_MAGIC);
        d[EI_CLASS] = ELFCLASS64;
        d[EI_DATA] = ELFDATA2LSB;
        d[16..18].copy_from_slice(&e_type.to_le_bytes());
        d[18..20].copy_from_slice(&e_machine.to_le_bytes());
        d[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
        d[52..54].copy_from_slice(&(ELF64_EHDR_SIZE as u16).to_le_bytes());
        d
    }

    /// Build a minimal valid 32-bit LE ELF header.
    fn make_elf32(e_type: u16) -> Vec<u8> {
        let mut d = vec![0u8; ELF32_EHDR_SIZE];
        d[0..4].copy_from_slice(&ELF_MAGIC);
        d[EI_CLASS] = ELFCLASS32;
        d[EI_DATA] = ELFDATA2LSB;
        d[16..18].copy_from_slice(&e_type.to_le_bytes());
        d[20..24].copy_from_slice(&1u32.to_le_bytes());
        d[40..42].copy_from_slice(&(ELF32_EHDR_SIZE as u16).to_le_bytes());
        d
    }

    /// Build a 64-bit ELF with a `.note.gnu.build-id` section containing `build_id`.
    fn make_elf64_with_build_id(build_id: &[u8]) -> Vec<u8> {
        // String table: "\0.note.gnu.build-id\0.shstrtab\0"
        let shstrtab = b"\0.note.gnu.build-id\0.shstrtab\0";
        // ".note.gnu.build-id" starts at offset 1 in the strtab.
        // ".shstrtab" starts at offset 20.

        // Build note data
        let note_name = b"GNU\0";
        let mut note = Vec::new();
        note.extend_from_slice(&(note_name.len() as u32).to_le_bytes()); // namesz
        note.extend_from_slice(&(build_id.len() as u32).to_le_bytes()); // descsz
        note.extend_from_slice(&NT_GNU_BUILD_ID.to_le_bytes()); // type
        note.extend_from_slice(note_name);
        while note.len() % 4 != 0 {
            note.push(0);
        }
        note.extend_from_slice(build_id);
        while note.len() % 4 != 0 {
            note.push(0);
        }

        // Layout: [ehdr][note_data][shstrtab][padding][shdrs]
        let note_off = ELF64_EHDR_SIZE as u64;
        let shstrtab_off = note_off + note.len() as u64;
        let mut shdr_off = shstrtab_off + shstrtab.len() as u64;
        // Align shdr_off to 8 bytes
        shdr_off = (shdr_off + 7) & !7;
        let total = shdr_off as usize + 3 * ELF64_SHDR_SIZE;

        let mut d = make_elf64(ET_EXEC, 0x3e);
        d.resize(total, 0);

        // Copy note data
        d[note_off as usize..note_off as usize + note.len()].copy_from_slice(&note);
        // Copy shstrtab
        d[shstrtab_off as usize..shstrtab_off as usize + shstrtab.len()].copy_from_slice(shstrtab);

        // Helper to write a 64-bit section header
        let mut write_shdr = |idx: usize, s: &Elf64_Shdr| {
            let base = shdr_off as usize + idx * ELF64_SHDR_SIZE;
            d[base..base + 4].copy_from_slice(&s.sh_name.to_le_bytes());
            d[base + 4..base + 8].copy_from_slice(&s.sh_type.to_le_bytes());
            d[base + 8..base + 16].copy_from_slice(&s.sh_flags.to_le_bytes());
            d[base + 16..base + 24].copy_from_slice(&s.sh_addr.to_le_bytes());
            d[base + 24..base + 32].copy_from_slice(&s.sh_offset.to_le_bytes());
            d[base + 32..base + 40].copy_from_slice(&s.sh_size.to_le_bytes());
            d[base + 40..base + 44].copy_from_slice(&s.sh_link.to_le_bytes());
            d[base + 44..base + 48].copy_from_slice(&s.sh_info.to_le_bytes());
            d[base + 48..base + 56].copy_from_slice(&s.sh_addralign.to_le_bytes());
            d[base + 56..base + 64].copy_from_slice(&s.sh_entsize.to_le_bytes());
        };

        // SHdr 0: NULL
        write_shdr(
            0,
            &Elf64_Shdr {
                sh_name: 0,
                sh_type: SHT_NULL,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: 0,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
        );
        // SHdr 1: .note.gnu.build-id
        write_shdr(
            1,
            &Elf64_Shdr {
                sh_name: 1, // offset in shstrtab
                sh_type: SHT_NOTE,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: note_off,
                sh_size: note.len() as u64,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 4,
                sh_entsize: 0,
            },
        );
        // SHdr 2: .shstrtab
        write_shdr(
            2,
            &Elf64_Shdr {
                sh_name: 20, // offset in shstrtab
                sh_type: SHT_STRTAB,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: shstrtab_off,
                sh_size: shstrtab.len() as u64,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 1,
                sh_entsize: 0,
            },
        );

        // Patch ehdr
        d[40..48].copy_from_slice(&shdr_off.to_le_bytes());
        d[58..60].copy_from_slice(&(ELF64_SHDR_SIZE as u16).to_le_bytes());
        d[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum
        d[62..64].copy_from_slice(&2u16.to_le_bytes()); // e_shstrndx

        d
    }

    // ── Magic & class detection ───────────────────────────────────────

    #[test]
    fn test_elf_is_elf_valid() {
        let mut d = vec![0u8; 16];
        d[0..4].copy_from_slice(&ELF_MAGIC);
        assert!(elf_is_elf(&d));
    }

    #[test]
    fn test_elf_is_elf_invalid() {
        assert!(!elf_is_elf(b"not elf"));
        assert!(!elf_is_elf(b""));
        assert!(!elf_is_elf(&[0x7f, b'E', b'L', b'X']));
    }

    #[test]
    fn test_elf_detect_class() {
        let mut d = vec![0u8; 16];
        d[0..4].copy_from_slice(&ELF_MAGIC);
        d[EI_CLASS] = ELFCLASS64;
        assert_eq!(elf_detect_class(&d).unwrap(), ElfClass::Elf64);
        d[EI_CLASS] = ELFCLASS32;
        assert_eq!(elf_detect_class(&d).unwrap(), ElfClass::Elf32);
        d[EI_CLASS] = 99;
        assert!(matches!(elf_detect_class(&d), Err(ElfError::InvalidClass)));
    }

    #[test]
    fn test_elf_detect_encoding() {
        let mut d = vec![0u8; 16];
        d[0..4].copy_from_slice(&ELF_MAGIC);
        d[EI_DATA] = ELFDATA2LSB;
        assert_eq!(elf_detect_encoding(&d).unwrap(), ElfData::LittleEndian);
        d[EI_DATA] = ELFDATA2MSB;
        assert_eq!(elf_detect_encoding(&d).unwrap(), ElfData::BigEndian);
    }

    // ── Header parsing ────────────────────────────────────────────────

    #[test]
    fn test_parse_elf64_header() {
        let raw = make_elf64(ET_EXEC, 0x3e);
        let elf = ElfFile::parse(&raw).unwrap();
        let h = elf.elf64_ehdr().unwrap();
        assert_eq!(h.e_type, ET_EXEC);
        assert_eq!(h.e_machine, 0x3e);
        assert_eq!(h.e_version, 1);
        assert_eq!(h.e_entry, 0);
        assert_eq!(h.e_phnum, 0);
        assert_eq!(h.e_shnum, 0);
    }

    #[test]
    fn test_parse_elf32_header() {
        let raw = make_elf32(ET_DYN);
        let elf = ElfFile::parse(&raw).unwrap();
        let h = elf.elf32_ehdr().unwrap();
        assert_eq!(h.e_type, ET_DYN);
        assert_eq!(h.e_version, 1);
    }

    #[test]
    fn test_wrong_class_rejected() {
        let raw = make_elf64(ET_EXEC, 0);
        let elf64 = ElfFile::parse(&raw).unwrap();
        assert!(elf64.elf32_ehdr().is_err());

        let raw = make_elf32(ET_EXEC);
        let elf32 = ElfFile::parse(&raw).unwrap();
        assert!(elf32.elf64_ehdr().is_err());
    }

    #[test]
    fn test_too_short_for_header() {
        let mut d = vec![0u8; 16];
        d[0..4].copy_from_slice(&ELF_MAGIC);
        d[EI_CLASS] = ELFCLASS64;
        d[EI_DATA] = ELFDATA2LSB;
        let elf = ElfFile::parse(&d).unwrap();
        assert!(matches!(elf.elf64_ehdr(), Err(ElfError::TooShort)));
    }

    // ── ELF type ──────────────────────────────────────────────────────

    #[test]
    fn test_elf_type_roundtrip() {
        assert_eq!(ElfType::from_raw(ET_EXEC).to_raw(), ET_EXEC);
        assert_eq!(ElfType::from_raw(ET_CORE).to_raw(), ET_CORE);
        assert_eq!(ElfType::from_raw(0xfe00), ElfType::Other(0xfe00));
    }

    #[test]
    fn test_elf_type_from_data() {
        assert_eq!(
            elf_get_type(&make_elf64(ET_EXEC, 0)).unwrap(),
            ElfType::Executable
        );
        assert_eq!(
            elf_get_type(&make_elf64(ET_DYN, 0)).unwrap(),
            ElfType::Dynamic
        );
        assert_eq!(
            elf_get_type(&make_elf64(ET_CORE, 0)).unwrap(),
            ElfType::Core
        );
    }

    #[test]
    fn test_is_core() {
        let raw = make_elf64(ET_CORE, 0);
        let elf = ElfFile::parse(&raw).unwrap();
        assert!(elf.is_core().unwrap());
        let raw = make_elf64(ET_EXEC, 0);
        let elf = ElfFile::parse(&raw).unwrap();
        assert!(!elf.is_core().unwrap());
    }

    // ── Empty header tables ───────────────────────────────────────────

    #[test]
    fn test_empty_section_headers() {
        let raw = make_elf64(ET_EXEC, 0);
        let elf = ElfFile::parse(&raw).unwrap();
        assert!(elf.elf64_section_headers().unwrap().is_empty());
        assert!(elf.elf32_section_headers().is_err()); // wrong class
    }

    #[test]
    fn test_empty_program_headers() {
        let raw = make_elf64(ET_EXEC, 0);
        let elf = ElfFile::parse(&raw).unwrap();
        assert!(elf.elf64_program_headers().unwrap().is_empty());
    }

    // ── Section lookup ────────────────────────────────────────────────

    #[test]
    fn test_section_not_found() {
        let raw = make_elf64(ET_EXEC, 0);
        let elf = ElfFile::parse(&raw).unwrap();
        assert!(matches!(
            elf.elf_find_section(".text"),
            Err(ElfError::SectionNotFound)
        ));
    }

    #[test]
    fn test_find_section_type_not_found() {
        let raw = make_elf64(ET_EXEC, 0);
        let elf = ElfFile::parse(&raw).unwrap();
        assert!(matches!(
            elf.elf_find_section_type(SHT_NOTE),
            Err(ElfError::SectionNotFound)
        ));
    }

    #[test]
    fn test_find_section_by_name_with_build_id() {
        let raw = make_elf64_with_build_id(&[1, 2, 3, 4]);
        let elf = ElfFile::parse(&raw).unwrap();
        let idx = elf.elf_find_section(".note.gnu.build-id").unwrap();
        assert_eq!(idx, 1);
    }

    #[test]
    fn test_find_section_by_type_with_build_id() {
        let raw = make_elf64_with_build_id(&[1, 2, 3, 4]);
        let elf = ElfFile::parse(&raw).unwrap();
        let idx = elf.elf_find_section_type(SHT_NOTE).unwrap();
        assert_eq!(idx, 1);
    }

    // ── Build ID extraction ───────────────────────────────────────────

    #[test]
    fn test_build_id_extraction() {
        let expected: &[u8] = &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22];
        let raw = make_elf64_with_build_id(expected);
        assert_eq!(elf_get_build_id(&raw).unwrap(), expected);
    }

    #[test]
    fn test_build_id_not_found() {
        let raw = make_elf64(ET_EXEC, 0);
        assert!(elf_get_build_id(&raw).is_err());
    }

    // ── Core dump info ────────────────────────────────────────────────

    #[test]
    fn test_coredump_rejected_for_non_core() {
        let raw = make_elf64(ET_EXEC, 0);
        let elf = ElfFile::parse(&raw).unwrap();
        assert!(elf.elf_get_coredump().is_err());
    }

    #[test]
    fn test_coredump_empty_core() {
        // A core file with no program headers reports (0, 0).
        let raw = make_elf64(ET_CORE, 0);
        let elf = ElfFile::parse(&raw).unwrap();
        assert_eq!(elf.elf_get_coredump().unwrap(), (0, 0));
    }

    // ── Edge cases & error paths ──────────────────────────────────────

    #[test]
    fn test_parse_empty() {
        assert!(matches!(ElfFile::parse(&[]), Err(ElfError::TooShort)));
    }

    #[test]
    fn test_parse_garbage() {
        assert!(matches!(
            ElfFile::parse(b"this is not an ELF file at all"),
            Err(ElfError::InvalidMagic)
        ));
    }

    #[test]
    fn test_error_display() {
        assert!(!ElfError::InvalidMagic.to_string().is_empty());
        assert!(!ElfError::SectionNotFound.to_string().is_empty());
        assert!(!ElfError::TooShort.to_string().is_empty());
        assert!(!ElfError::InvalidNote.to_string().is_empty());
    }

    #[test]
    fn test_interp_segment_absent() {
        let raw = make_elf64(ET_DYN, 0);
        let elf = ElfFile::parse(&raw).unwrap();
        assert!(!elf.has_interp_segment().unwrap());
    }
}
