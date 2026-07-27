// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/cpio.c
//
// CPIO archive generation for initrd construction.
//
// Creates newc-format CPIO archives for packaging boot data (initrds,
// credentials, etc.) to pass to the kernel. CPIO is the format used
// by the Linux kernel for initial RAM disks.

// ── Constants ─────────────────────────────────────────────────────────────

/// CPIO newc magic identifier.
pub const CPIO_MAGIC: &[u8; 6] = b"070701";

/// CPIO trailer record marker.
pub const CPIO_TRAILER_NAME: &str = "TRAILER!!!";

/// CPIO header size: 6 bytes magic + 13 fields × 8 hex chars.
pub const CPIO_HEADER_SIZE: usize = 6 + 13 * 8;

/// File mode: regular file (S_IFREG = 0100000).
pub const S_IFREG: u32 = 0o100000;

/// File mode: directory (S_IFDIR = 0040000).
pub const S_IFDIR: u32 = 0o040000;

/// Default directory permissions.
pub const DEFAULT_DIR_MODE: u32 = 0o0555;

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpioError {
    BufferOverflow,
    FileTooLarge,
    TooManyInodes,
    InvalidFilename,
    EmptyContent,
}

impl std::fmt::Display for CpioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CpioError::BufferOverflow => write!(f, "buffer overflow"),
            CpioError::FileTooLarge => write!(f, "file too large for CPIO"),
            CpioError::TooManyInodes => write!(f, "too many inodes"),
            CpioError::InvalidFilename => write!(f, "invalid filename"),
            CpioError::EmptyContent => write!(f, "empty content"),
        }
    }
}

impl std::error::Error for CpioError {}

// ── Helper functions ──────────────────────────────────────────────────────

const LOWERCASE_HEXDIGITS: &[u8; 16] = b"0123456789abcdef";

/// Write a 32-bit value as 8 lowercase hex characters into the buffer.
/// Returns the pointer past the written bytes (mirrors the C `write_cpio_word`).
pub fn write_cpio_word(buf: &mut [u8], offset: usize, v: u32) -> usize {
    for i in 0..8 {
        buf[offset + 7 - i] = LOWERCASE_HEXDIGITS[((v >> (4 * i)) & 0xF) as usize];
    }
    offset + 8
}

/// Align a length up to the next multiple of 4.
pub fn align4(len: usize) -> usize {
    (len + 3) & !3
}

/// Pad a buffer with NUL bytes to 4-byte alignment relative to start.
/// Returns the new offset after padding.
pub fn pad4(buf: &mut [u8], offset: usize, start: usize) -> usize {
    let mut pos = offset;
    while (pos - start) % 4 != 0 {
        buf[pos] = 0;
        pos += 1;
    }
    pos
}

/// Convert a UTF-16 filename to ASCII bytes (mangle_filename in C).
/// All characters must be <= 0x7F (ASCII), as enforced by the C code.
pub fn mangle_filename(utf16_chars: &[u16]) -> Result<Vec<u8>, CpioError> {
    let mut result = Vec::with_capacity(utf16_chars.len() + 1);
    for &c in utf16_chars {
        if c == 0 {
            break;
        }
        if c > 0x7F {
            return Err(CpioError::InvalidFilename);
        }
        result.push(c as u8);
    }
    result.push(0);
    Ok(result)
}

// ── CPIO record generation ────────────────────────────────────────────────

/// Build a CPIO file record header and return it as a byte vector.
pub fn pack_cpio_one(
    fname: &str,
    contents: &[u8],
    target_dir_prefix: &str,
    access_mode: u32,
    inode: u32,
) -> Result<(Vec<u8>, u32), CpioError> {
    if contents.len() > u32::MAX as usize {
        return Err(CpioError::FileTooLarge);
    }
    if inode == u32::MAX {
        return Err(CpioError::TooManyInodes);
    }

    let prefix_size = target_dir_prefix.len();
    let fname_size = fname.len();
    let total_name_size = prefix_size + 1 + fname_size + 1;

    if total_name_size >= u32::MAX as usize {
        return Err(CpioError::FileTooLarge);
    }

    let header_size = align4(CPIO_HEADER_SIZE + 1 + total_name_size);
    let content_aligned = align4(contents.len());
    let total_size = header_size + content_aligned;

    let mut buf = vec![0u8; total_size];
    let mut pos = 0;

    buf[pos..pos + 6].copy_from_slice(CPIO_MAGIC);
    pos += 6;

    pos = write_cpio_word(&mut buf, pos, inode);
    pos = write_cpio_word(&mut buf, pos, access_mode | S_IFREG);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, 1);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, contents.len() as u32);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, total_name_size as u32);
    pos = write_cpio_word(&mut buf, pos, 0);

    buf[pos..pos + prefix_size].copy_from_slice(target_dir_prefix.as_bytes());
    pos += prefix_size;
    buf[pos] = b'/';
    pos += 1;
    buf[pos..pos + fname_size].copy_from_slice(fname.as_bytes());
    pos += fname_size;
    buf[pos] = 0;
    pos += 1;

    pos = pad4(&mut buf, pos, 0);

    buf[pos..pos + contents.len()].copy_from_slice(contents);
    pos += contents.len();
    pad4(&mut buf, pos, 0);

    Ok((buf, inode.wrapping_add(1)))
}

/// Build a CPIO directory record.
pub fn pack_cpio_dir(
    path: &str,
    access_mode: u32,
    inode: u32,
) -> Result<(Vec<u8>, u32), CpioError> {
    if inode == u32::MAX {
        return Err(CpioError::TooManyInodes);
    }

    let path_size = path.len();
    let name_size = path_size + 1;
    let total_size = align4(CPIO_HEADER_SIZE + 1 + name_size);

    let mut buf = vec![0u8; total_size];
    let mut pos = 0;

    buf[pos..pos + 6].copy_from_slice(CPIO_MAGIC);
    pos += 6;

    pos = write_cpio_word(&mut buf, pos, inode);
    pos = write_cpio_word(&mut buf, pos, access_mode | S_IFDIR);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, 1);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, 0);
    pos = write_cpio_word(&mut buf, pos, name_size as u32);
    pos = write_cpio_word(&mut buf, pos, 0);

    buf[pos..pos + path_size].copy_from_slice(path.as_bytes());
    pos += path_size;
    buf[pos] = 0;
    pos += 1;

    pad4(&mut buf, pos, 0);

    Ok((buf, inode.wrapping_add(1)))
}

/// Build a CPIO trailer record.
pub fn pack_cpio_trailer() -> Vec<u8> {
    let trailer = b"070701000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000B00000000TRAILER!!!\0\0\0";
    trailer.to_vec()
}

/// Build CPIO prefix directory entries for all path components.
pub fn pack_cpio_prefix(
    path: &str,
    dir_mode: u32,
    start_inode: u32,
) -> Result<(Vec<u8>, u32), CpioError> {
    let mut result = Vec::new();
    let mut inode = start_inode;

    let mut pos = 0;
    for (i, c) in path.char_indices() {
        if c == '/' && i > pos {
            let prefix = &path[pos..i];
            let (dir_data, new_inode) = pack_cpio_dir(prefix, DEFAULT_DIR_MODE, inode)?;
            result.extend_from_slice(&dir_data);
            inode = new_inode;
            pos = i + 1;
        } else if c == '/' {
            pos = i + 1;
        }
    }

    let (final_dir, new_inode) = pack_cpio_dir(path, dir_mode, inode)?;
    result.extend_from_slice(&final_dir);

    Ok((result, new_inode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_cpio_word() {
        let mut buf = [0u8; 8];
        write_cpio_word(&mut buf, 0, 0xDEADBEEF);
        assert_eq!(&buf, b"deadbeef");
    }

    #[test]
    fn test_write_cpio_word_zero() {
        let mut buf = [0u8; 8];
        write_cpio_word(&mut buf, 0, 0);
        assert_eq!(&buf, b"00000000");
    }

    #[test]
    fn test_write_cpio_word_max() {
        let mut buf = [0u8; 8];
        write_cpio_word(&mut buf, 0, 0xFFFFFFFF);
        assert_eq!(&buf, b"ffffffff");
    }

    #[test]
    fn test_align4() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(3), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(100), 100);
    }

    #[test]
    fn test_pad4_no_padding_needed() {
        let mut buf = [0u8; 16];
        let new_pos = pad4(&mut buf, 8, 0);
        assert_eq!(new_pos, 8);
    }

    #[test]
    fn test_pad4_needs_padding() {
        let mut buf = [0xFFu8; 16];
        let new_pos = pad4(&mut buf, 5, 0);
        assert_eq!(new_pos, 8);
        assert_eq!(buf[5], 0);
        assert_eq!(buf[6], 0);
        assert_eq!(buf[7], 0);
    }

    #[test]
    fn test_mangle_filename_ascii() {
        let input: Vec<u16> = "hello.txt".encode_utf16().collect();
        let result = mangle_filename(&input).unwrap();
        assert_eq!(&result[..9], b"hello.txt");
        assert_eq!(result[9], 0);
    }

    #[test]
    fn test_mangle_filename_non_ascii() {
        let input: Vec<u16> = vec![0x80];
        assert!(mangle_filename(&input).is_err());
    }

    #[test]
    fn test_pack_cpio_trailer() {
        let trailer = pack_cpio_trailer();
        assert!(trailer.starts_with(b"070701"));
        assert!(trailer.windows(10).any(|w| w == b"TRAILER!!!"));
    }

    #[test]
    fn test_pack_cpio_dir_basic() {
        let (data, new_inode) = pack_cpio_dir("etc", 0o0555, 1).unwrap();
        assert_eq!(new_inode, 2);
        assert!(data.starts_with(CPIO_MAGIC));
    }

    #[test]
    fn test_pack_cpio_one_basic() {
        let (data, new_inode) = pack_cpio_one("test.txt", b"hello", "etc", 0o0644, 1).unwrap();
        assert_eq!(new_inode, 2);
        assert!(data.starts_with(CPIO_MAGIC));
        assert!(data.windows(5).any(|w| w == b"hello"));
    }

    #[test]
    fn test_pack_cpio_prefix() {
        let (data, new_inode) = pack_cpio_prefix("etc/systemd", 0o0755, 1).unwrap();
        assert!(new_inode > 2);
        assert!(data.starts_with(CPIO_MAGIC));
    }

    #[test]
    fn test_pack_cpio_one_too_large() {
        let big_content = vec![0u8; u32::MAX as usize + 1];
        let result = pack_cpio_one("big", &big_content, "", 0o0644, 1);
        assert_eq!(result, Err(CpioError::FileTooLarge));
    }

    #[test]
    fn test_error_display() {
        assert!(!CpioError::BufferOverflow.to_string().is_empty());
    }
}
