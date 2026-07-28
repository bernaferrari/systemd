// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/kernel-image.c, src/shared/kernel-image.h

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::pe_binary::{
    ImageSectionHeader, PeError, PeHeader, pe_load_headers, pe_load_sections,
    pe_read_section_data_by_name,
};

pub const SOURCE_C_FILE: &str = "src/shared/kernel-image.c";
pub const PE_SECTION_READ_MAX: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelImageType {
    Unknown,
    Uki,
    Addon,
    Pe,
}

impl KernelImageType {
    pub const TABLE: [&str; 4] = ["unknown", "uki", "addon", "pe"];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Uki => "uki",
            Self::Addon => "addon",
            Self::Pe => "pe",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "unknown" => Some(Self::Unknown),
            "uki" => Some(Self::Uki),
            "addon" => Some(Self::Addon),
            "pe" => Some(Self::Pe),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelFileFormat {
    Unknown,
    PortableExecutable,
    Gzip,
    Xz,
    Zstd,
    Lz4,
    Bzip2,
}

impl KernelFileFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::PortableExecutable => "pe",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
            Self::Lz4 => "lz4",
            Self::Bzip2 => "bzip2",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelTimestamps {
    pub modified: Option<SystemTime>,
    pub pe_coff: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelImageMetadata {
    pub image_type: KernelImageType,
    pub file_format: KernelFileFormat,
    pub cmdline: Option<String>,
    pub uname: Option<String>,
    pub pretty_name: Option<String>,
    pub timestamps: KernelTimestamps,
    pub file_size: u64,
}

#[derive(Debug)]
pub enum KernelImageError {
    Io(io::Error),
    Pe(PeError),
    Utf8(std::str::Utf8Error),
    InvalidEnvLine(String),
    UnterminatedQuote(String),
}

impl fmt::Display for KernelImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Pe(err) => write!(f, "PE parsing error: {err}"),
            Self::Utf8(err) => write!(f, "UTF-8 decoding error: {err}"),
            Self::InvalidEnvLine(line) => write!(f, "Invalid environment assignment: {line}"),
            Self::UnterminatedQuote(line) => {
                write!(f, "Unterminated quoted environment value: {line}")
            }
        }
    }
}

impl std::error::Error for KernelImageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Pe(err) => Some(err),
            Self::Utf8(err) => Some(err),
            Self::InvalidEnvLine(_) | Self::UnterminatedQuote(_) => None,
        }
    }
}

impl From<io::Error> for KernelImageError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<PeError> for KernelImageError {
    fn from(value: PeError) -> Self {
        Self::Pe(value)
    }
}

impl From<std::str::Utf8Error> for KernelImageError {
    fn from(value: std::str::Utf8Error) -> Self {
        Self::Utf8(value)
    }
}

pub fn kernel_image_type_to_string(image_type: KernelImageType) -> &'static str {
    image_type.as_str()
}

pub fn kernel_image_type_from_string(value: &str) -> Option<KernelImageType> {
    KernelImageType::from_str(value)
}

pub fn kernel_identify(path: impl AsRef<Path>) -> Result<KernelImageType, KernelImageError> {
    inspect_kernel(path).map(|metadata| metadata.image_type)
}

pub fn read_kernel_type(path: impl AsRef<Path>) -> Result<KernelFileFormat, KernelImageError> {
    inspect_kernel(path).map(|metadata| metadata.file_format)
}

pub fn kernel_read_timestamps(
    path: impl AsRef<Path>,
) -> Result<KernelTimestamps, KernelImageError> {
    inspect_kernel(path).map(|metadata| metadata.timestamps)
}

pub fn inspect_kernel(path: impl AsRef<Path>) -> Result<KernelImageMetadata, KernelImageError> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let fs_metadata = file.metadata()?;
    let modified = fs_metadata.modified().ok();
    let file_size = fs_metadata.len();

    let prefix = read_prefix(&mut file, 8)?;
    let compressed_format = detect_compressed_format(&prefix);

    let mut image_type = KernelImageType::Unknown;
    let mut file_format = compressed_format;
    let mut cmdline = None;
    let mut uname = None;
    let mut pretty_name = None;
    let mut pe_coff = None;

    file.seek(SeekFrom::Start(0))?;
    match pe_load_headers(&mut file) {
        Ok((dos_header, pe_header)) => {
            file_format = KernelFileFormat::PortableExecutable;
            pe_coff = coff_timestamp_to_system_time(pe_header.coff_header.time_date_stamp);

            match pe_load_sections(&mut file, &dos_header, &pe_header) {
                Ok(sections) => {
                    if pe_header.is_uki(&sections) {
                        cmdline = read_optional_section_string(
                            &mut file, &pe_header, &sections, ".cmdline",
                        )?;
                        uname = read_optional_section_string(
                            &mut file, &pe_header, &sections, ".uname",
                        )?;
                        pretty_name = uki_read_pretty_name(&mut file, &pe_header, &sections)?;
                        image_type = KernelImageType::Uki;
                    } else if pe_header.is_addon(&sections) {
                        cmdline = read_optional_section_string(
                            &mut file, &pe_header, &sections, ".cmdline",
                        )?;
                        uname = read_optional_section_string(
                            &mut file, &pe_header, &sections, ".uname",
                        )?;
                        image_type = KernelImageType::Addon;
                    } else {
                        image_type = KernelImageType::Pe;
                    }
                }
                Err(err) if pe_error_means_not_pe(&err) => {
                    file_format = compressed_format;
                    pe_coff = None;
                }
                Err(err) => return Err(err.into()),
            }
        }
        Err(err) if pe_error_means_not_pe(&err) => {}
        Err(err) => return Err(err.into()),
    }

    Ok(KernelImageMetadata {
        image_type,
        file_format,
        cmdline,
        uname,
        pretty_name,
        timestamps: KernelTimestamps { modified, pe_coff },
        file_size,
    })
}

fn read_prefix(file: &mut File, len: usize) -> io::Result<Vec<u8>> {
    let mut prefix = vec![0; len];
    let bytes_read = file.read(&mut prefix)?;
    prefix.truncate(bytes_read);
    Ok(prefix)
}

fn detect_compressed_format(prefix: &[u8]) -> KernelFileFormat {
    if prefix.starts_with(&[0x1F, 0x8B]) {
        KernelFileFormat::Gzip
    } else if prefix.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        KernelFileFormat::Xz
    } else if prefix.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        KernelFileFormat::Zstd
    } else if prefix.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
        KernelFileFormat::Lz4
    } else if prefix.starts_with(b"BZh") {
        KernelFileFormat::Bzip2
    } else {
        KernelFileFormat::Unknown
    }
}

fn pe_error_means_not_pe(err: &PeError) -> bool {
    matches!(
        err,
        PeError::InvalidDosHeader(_)
            | PeError::InvalidPeSignature(_)
            | PeError::InvalidOptionalMagic(_)
            | PeError::InvalidOptionalSize(_)
            | PeError::InvalidDataDirectory(_)
            | PeError::ShortRead
            | PeError::Io(_)
    )
}

fn read_optional_section_string(
    file: &mut File,
    pe_header: &PeHeader,
    sections: &[ImageSectionHeader],
    name: &str,
) -> Result<Option<String>, KernelImageError> {
    match pe_read_section_data_by_name(file, pe_header, sections, name, PE_SECTION_READ_MAX) {
        Ok(data) => Ok(Some(read_pe_string(&data)?)),
        Err(PeError::SectionNotFound(_)) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn read_pe_string(data: &[u8]) -> Result<String, KernelImageError> {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let value = std::str::from_utf8(&data[..end])?;
    Ok(value.to_string())
}

fn uki_read_pretty_name(
    file: &mut File,
    pe_header: &PeHeader,
    sections: &[ImageSectionHeader],
) -> Result<Option<String>, KernelImageError> {
    let osrel = match pe_read_section_data_by_name(
        file,
        pe_header,
        sections,
        ".osrel",
        PE_SECTION_READ_MAX,
    ) {
        Ok(data) => data,
        Err(PeError::SectionNotFound(_)) => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    let entries = parse_env_assignments(&osrel)?;
    if let Some(value) = entries
        .iter()
        .find_map(|(key, value)| (key == "PRETTY_NAME").then(|| value.clone()))
    {
        return Ok(Some(value));
    }

    if let Some(value) = entries
        .iter()
        .find_map(|(key, value)| (key == "NAME").then(|| value.clone()))
    {
        return Ok(Some(value));
    }

    Ok(Some("Linux".to_string()))
}

fn parse_env_assignments(data: &[u8]) -> Result<Vec<(String, String)>, KernelImageError> {
    let text = std::str::from_utf8(data)?;
    let mut result = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(KernelImageError::InvalidEnvLine(line.to_string()));
        };

        if !is_valid_env_key(key) {
            return Err(KernelImageError::InvalidEnvLine(line.to_string()));
        }

        result.push((key.to_string(), parse_env_value(value.trim())?));
    }

    Ok(result)
}

fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }

    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn parse_env_value(value: &str) -> Result<String, KernelImageError> {
    if value.len() >= 2 && value.starts_with('"') {
        return parse_quoted_value(value, '"');
    }
    if value.len() >= 2 && value.starts_with('\'') {
        return parse_quoted_value(value, '\'');
    }

    Ok(value.to_string())
}

fn parse_quoted_value(value: &str, quote: char) -> Result<String, KernelImageError> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Ok(String::new());
    };

    if first != quote {
        return Ok(value.to_string());
    }

    let mut out = String::new();
    let mut escaped = false;

    for c in chars {
        if escaped {
            out.push(match c {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '\\' => '\\',
                '\'' => '\'',
                '"' => '"',
                other => other,
            });
            escaped = false;
            continue;
        }

        if c == '\\' {
            escaped = true;
            continue;
        }

        if c == quote {
            return Ok(out);
        }

        out.push(c);
    }

    Err(KernelImageError::UnterminatedQuote(value.to_string()))
}

fn coff_timestamp_to_system_time(timestamp: u32) -> Option<SystemTime> {
    Some(UNIX_EPOCH + Duration::from_secs(u64::from(timestamp)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_binary::IMAGE_SUBSYSTEM_EFI_APPLICATION;
    use tempfile::NamedTempFile;

    #[derive(Clone)]
    struct TestSection<'a> {
        name: &'a str,
        data: Vec<u8>,
    }

    #[test]
    fn kernel_image_type_round_trip_strings() {
        for image_type in [
            KernelImageType::Unknown,
            KernelImageType::Uki,
            KernelImageType::Addon,
            KernelImageType::Pe,
        ] {
            assert_eq!(
                KernelImageType::from_str(image_type.as_str()),
                Some(image_type)
            );
        }
    }

    #[test]
    fn kernel_image_type_from_string_rejects_unknown_value() {
        assert_eq!(kernel_image_type_from_string("nope"), None);
    }

    #[test]
    fn detect_gzip_format() {
        assert_eq!(
            detect_compressed_format(&[0x1F, 0x8B]),
            KernelFileFormat::Gzip
        );
    }

    #[test]
    fn detect_xz_format() {
        assert_eq!(
            detect_compressed_format(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]),
            KernelFileFormat::Xz
        );
    }

    #[test]
    fn detect_zstd_format() {
        assert_eq!(
            detect_compressed_format(&[0x28, 0xB5, 0x2F, 0xFD]),
            KernelFileFormat::Zstd
        );
    }

    #[test]
    fn detect_lz4_format() {
        assert_eq!(
            detect_compressed_format(&[0x04, 0x22, 0x4D, 0x18]),
            KernelFileFormat::Lz4
        );
    }

    #[test]
    fn detect_bzip2_format() {
        assert_eq!(detect_compressed_format(b"BZh9"), KernelFileFormat::Bzip2);
    }

    #[test]
    fn detect_unknown_format() {
        assert_eq!(
            detect_compressed_format(b"not-a-kernel"),
            KernelFileFormat::Unknown
        );
    }

    #[test]
    fn parse_pretty_name_prefers_pretty_name() {
        let entries = parse_env_assignments(b"PRETTY_NAME=\"Fancy Linux\"\nNAME=Linux\n").unwrap();
        assert_eq!(
            entries,
            vec![
                ("PRETTY_NAME".to_string(), "Fancy Linux".to_string()),
                ("NAME".to_string(), "Linux".to_string())
            ]
        );
    }

    #[test]
    fn parse_name_handles_escaped_quotes() {
        let entries = parse_env_assignments(b"NAME=\"Lin\\\"ux\"\n").unwrap();
        assert_eq!(entries[0].1, "Lin\"ux");
    }

    #[test]
    fn parse_env_rejects_invalid_key() {
        assert!(matches!(
            parse_env_assignments(b"BAD-KEY=value\n"),
            Err(KernelImageError::InvalidEnvLine(_))
        ));
    }

    #[test]
    fn parse_env_rejects_unterminated_quote() {
        assert!(matches!(
            parse_env_assignments(b"NAME=\"Linux\n"),
            Err(KernelImageError::UnterminatedQuote(_))
        ));
    }

    #[test]
    fn read_pe_string_trims_trailing_nul() {
        assert_eq!(read_pe_string(b"linux\0\0").unwrap(), "linux");
    }

    #[test]
    fn compressed_kernel_reports_unknown_image_type() {
        let file = write_temp_file(&[0x1F, 0x8B, 0x08, 0x00, 0x00]);
        let metadata = inspect_kernel(file.path()).unwrap();
        assert_eq!(metadata.image_type, KernelImageType::Unknown);
        assert_eq!(metadata.file_format, KernelFileFormat::Gzip);
        assert!(metadata.timestamps.modified.is_some());
        assert_eq!(metadata.timestamps.pe_coff, None);
    }

    #[test]
    fn plain_pe_reports_pe_type() {
        let image = build_pe_image(0x1234_5678, IMAGE_SUBSYSTEM_EFI_APPLICATION, &[]);
        let file = write_temp_file(&image);

        let metadata = inspect_kernel(file.path()).unwrap();
        assert_eq!(metadata.image_type, KernelImageType::Pe);
        assert_eq!(metadata.file_format, KernelFileFormat::PortableExecutable);
        assert_eq!(
            metadata.timestamps.pe_coff,
            Some(UNIX_EPOCH + Duration::from_secs(0x1234_5678))
        );
        assert_eq!(metadata.cmdline, None);
        assert_eq!(metadata.uname, None);
        assert_eq!(metadata.pretty_name, None);
    }

    #[test]
    fn uki_reports_metadata() {
        let image = build_pe_image(
            0x0102_0304,
            IMAGE_SUBSYSTEM_EFI_APPLICATION,
            &[
                TestSection {
                    name: ".osrel",
                    data: b"PRETTY_NAME=\"My Linux\"\nNAME=Fallback\n".to_vec(),
                },
                TestSection {
                    name: ".linux",
                    data: vec![1, 2, 3, 4],
                },
                TestSection {
                    name: ".cmdline",
                    data: b"quiet splash\0".to_vec(),
                },
                TestSection {
                    name: ".uname",
                    data: b"6.9.0-test\0".to_vec(),
                },
            ],
        );
        let file = write_temp_file(&image);

        let metadata = inspect_kernel(file.path()).unwrap();
        assert_eq!(metadata.image_type, KernelImageType::Uki);
        assert_eq!(metadata.file_format, KernelFileFormat::PortableExecutable);
        assert_eq!(metadata.cmdline.as_deref(), Some("quiet splash"));
        assert_eq!(metadata.uname.as_deref(), Some("6.9.0-test"));
        assert_eq!(metadata.pretty_name.as_deref(), Some("My Linux"));
    }

    #[test]
    fn uki_pretty_name_falls_back_to_name_then_linux() {
        let with_name = build_pe_image(
            1,
            IMAGE_SUBSYSTEM_EFI_APPLICATION,
            &[
                TestSection {
                    name: ".osrel",
                    data: b"NAME=Fallback Linux\n".to_vec(),
                },
                TestSection {
                    name: ".linux",
                    data: vec![0xAA],
                },
            ],
        );
        let with_default = build_pe_image(
            1,
            IMAGE_SUBSYSTEM_EFI_APPLICATION,
            &[
                TestSection {
                    name: ".osrel",
                    data: b"ID=linux\n".to_vec(),
                },
                TestSection {
                    name: ".linux",
                    data: vec![0xBB],
                },
            ],
        );

        let file = write_temp_file(&with_name);
        let metadata = inspect_kernel(file.path()).unwrap();
        assert_eq!(metadata.pretty_name.as_deref(), Some("Fallback Linux"));

        let file = write_temp_file(&with_default);
        let metadata = inspect_kernel(file.path()).unwrap();
        assert_eq!(metadata.pretty_name.as_deref(), Some("Linux"));
    }

    #[test]
    fn addon_reports_cmdline_and_uname_without_pretty_name() {
        let image = build_pe_image(
            7,
            IMAGE_SUBSYSTEM_EFI_APPLICATION,
            &[
                TestSection {
                    name: ".cmdline",
                    data: b"debug\0".to_vec(),
                },
                TestSection {
                    name: ".uname",
                    data: b"addon-kernel\0".to_vec(),
                },
                TestSection {
                    name: ".initrd",
                    data: vec![9, 9, 9],
                },
            ],
        );
        let file = write_temp_file(&image);

        let metadata = inspect_kernel(file.path()).unwrap();
        assert_eq!(metadata.image_type, KernelImageType::Addon);
        assert_eq!(metadata.cmdline.as_deref(), Some("debug"));
        assert_eq!(metadata.uname.as_deref(), Some("addon-kernel"));
        assert_eq!(metadata.pretty_name, None);
    }

    #[test]
    fn kernel_identify_returns_uki_type() {
        let image = build_pe_image(
            9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION,
            &[
                TestSection {
                    name: ".osrel",
                    data: b"NAME=Linux\n".to_vec(),
                },
                TestSection {
                    name: ".linux",
                    data: vec![1],
                },
            ],
        );
        let file = write_temp_file(&image);
        assert_eq!(kernel_identify(file.path()).unwrap(), KernelImageType::Uki);
    }

    #[test]
    fn read_kernel_type_reports_compression() {
        let file = write_temp_file(&[0x28, 0xB5, 0x2F, 0xFD, 0x00]);
        assert_eq!(
            read_kernel_type(file.path()).unwrap(),
            KernelFileFormat::Zstd
        );
    }

    #[test]
    fn kernel_read_timestamps_preserves_pe_timestamp() {
        let image = build_pe_image(42, IMAGE_SUBSYSTEM_EFI_APPLICATION, &[]);
        let file = write_temp_file(&image);

        let timestamps = kernel_read_timestamps(file.path()).unwrap();
        assert_eq!(
            timestamps.pe_coff,
            Some(UNIX_EPOCH + Duration::from_secs(42))
        );
        assert!(timestamps.modified.is_some());
    }

    fn write_temp_file(contents: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, contents).unwrap();
        file
    }

    fn align_up(value: usize, alignment: usize) -> usize {
        if value == 0 {
            0
        } else {
            ((value + alignment - 1) / alignment) * alignment
        }
    }

    fn build_pe_image(
        time_date_stamp: u32,
        subsystem: u16,
        sections: &[TestSection<'_>],
    ) -> Vec<u8> {
        const DOS_HEADER_SIZE: usize = 64;
        const PE_SIGNATURE_SIZE: usize = 4;
        const COFF_HEADER_SIZE: usize = 20;
        const OPTIONAL_HEADER_SIZE: usize = 240;
        const SECTION_HEADER_SIZE: usize = 40;
        const FILE_ALIGNMENT: usize = 0x200;
        const SECTION_ALIGNMENT: usize = 0x1000;

        let section_table_bytes = SECTION_HEADER_SIZE * sections.len();
        let unaligned_headers = DOS_HEADER_SIZE
            + PE_SIGNATURE_SIZE
            + COFF_HEADER_SIZE
            + OPTIONAL_HEADER_SIZE
            + section_table_bytes;
        let size_of_headers = align_up(unaligned_headers, FILE_ALIGNMENT);

        let mut raw_offset = size_of_headers;
        let mut virtual_address = SECTION_ALIGNMENT;
        let mut section_headers = Vec::with_capacity(section_table_bytes);
        let mut section_blobs = Vec::new();

        for section in sections {
            let raw_size = align_up(section.data.len(), FILE_ALIGNMENT);
            let virtual_size = section.data.len();

            let mut name = [0u8; 8];
            name[..section.name.len()].copy_from_slice(section.name.as_bytes());
            section_headers.extend_from_slice(&name);
            section_headers.extend_from_slice(&(virtual_size as u32).to_le_bytes());
            section_headers.extend_from_slice(&(virtual_address as u32).to_le_bytes());
            section_headers.extend_from_slice(&(raw_size as u32).to_le_bytes());
            section_headers.extend_from_slice(&(raw_offset as u32).to_le_bytes());
            section_headers.extend_from_slice(&0u32.to_le_bytes());
            section_headers.extend_from_slice(&0u32.to_le_bytes());
            section_headers.extend_from_slice(&0u16.to_le_bytes());
            section_headers.extend_from_slice(&0u16.to_le_bytes());
            section_headers.extend_from_slice(&0u32.to_le_bytes());

            let mut blob = section.data.clone();
            blob.resize(raw_size, 0);
            section_blobs.push(blob);

            raw_offset += raw_size;
            virtual_address += align_up(virtual_size.max(1), SECTION_ALIGNMENT);
        }

        let size_of_image = if sections.is_empty() {
            SECTION_ALIGNMENT
        } else {
            virtual_address
        } as u32;

        let mut file = Vec::with_capacity(raw_offset);

        let mut dos = [0u8; DOS_HEADER_SIZE];
        dos[0] = b'M';
        dos[1] = b'Z';
        dos[60..64].copy_from_slice(&(DOS_HEADER_SIZE as u32).to_le_bytes());
        file.extend_from_slice(&dos);

        file.extend_from_slice(&0x0000_4550u32.to_le_bytes());
        file.extend_from_slice(&0x8664u16.to_le_bytes());
        file.extend_from_slice(&(sections.len() as u16).to_le_bytes());
        file.extend_from_slice(&time_date_stamp.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&(OPTIONAL_HEADER_SIZE as u16).to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());

        file.extend_from_slice(&0x20Bu16.to_le_bytes());
        file.push(0);
        file.push(0);
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u64.to_le_bytes());
        file.extend_from_slice(&(SECTION_ALIGNMENT as u32).to_le_bytes());
        file.extend_from_slice(&(FILE_ALIGNMENT as u32).to_le_bytes());
        file.extend_from_slice(&6u16.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&6u16.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&size_of_image.to_le_bytes());
        file.extend_from_slice(&(size_of_headers as u32).to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&subsystem.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&0x10_0000u64.to_le_bytes());
        file.extend_from_slice(&0x1000u64.to_le_bytes());
        file.extend_from_slice(&0x10_0000u64.to_le_bytes());
        file.extend_from_slice(&0x1000u64.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&16u32.to_le_bytes());
        file.extend(std::iter::repeat_n(0u8, 16 * 8));

        file.extend_from_slice(&section_headers);
        file.resize(size_of_headers, 0);

        for blob in section_blobs {
            file.extend_from_slice(&blob);
        }

        file
    }
}
