// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-id128/id128-util.c
//

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use crate::id128_util::{SdId128, id128_from_string_nonzero, id128_is_valid};

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
pub const NEG_ENOMEDIUM: i32 = -123;
pub const NEG_ENOPKG: i32 = -65;
pub const NEG_EUCLEAN: i32 = -117;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Id128Flags(u32);

impl Id128Flags {
    pub const FORMAT_PLAIN: Self = Self(1 << 0);
    pub const FORMAT_UUID: Self = Self(1 << 1);
    pub const REFUSE_NULL: Self = Self(1 << 2);
    pub const SYNC_ON_WRITE: Self = Self(1 << 3);
    pub const ANY: Self = Self(Self::FORMAT_PLAIN.0 | Self::FORMAT_UUID.0);

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

pub fn id128_read<R: Read>(mut reader: R, flags: Id128Flags) -> Result<SdId128> {
    let mut buffer = String::new();
    reader.read_to_string(&mut buffer).map_err(io_errno)?;
    parse_id128_text(&buffer, flags)
}

pub fn id128_write<W: Write>(mut writer: W, flags: Id128Flags, id: SdId128) -> Result<()> {
    if flags.contains(Id128Flags::REFUSE_NULL) && id.is_null() {
        return Err(NEG_ENOMEDIUM);
    }

    let mut encoded = if flags.contains(Id128Flags::FORMAT_PLAIN) {
        encode_plain(id)
    } else if flags.contains(Id128Flags::FORMAT_UUID) {
        encode_uuid(id)
    } else {
        return Err(NEG_EINVAL);
    };
    encoded.push('\n');

    writer.write_all(encoded.as_bytes()).map_err(io_errno)
}

pub fn id128_read_file(path: impl AsRef<Path>, flags: Id128Flags) -> Result<SdId128> {
    let file = fs::File::open(path).map_err(io_errno)?;
    id128_read(file, flags)
}

pub fn id128_write_file(path: impl AsRef<Path>, flags: Id128Flags, id: SdId128) -> Result<()> {
    let file = fs::File::create(path).map_err(io_errno)?;
    id128_write(file, flags, id)
}

pub fn id128_from_string_nonzero_ext(s: &str) -> Result<SdId128> {
    id128_from_string_nonzero(s)
}

pub fn id128_is_valid_ext(s: &str) -> bool {
    id128_is_valid(s)
}

fn parse_id128_text(text: &str, flags: Id128Flags) -> Result<SdId128> {
    let trimmed = text.strip_suffix('\n').unwrap_or(text);
    if trimmed.is_empty() {
        return Err(NEG_ENOMEDIUM);
    }
    if trimmed == "uninitialized" {
        return Err(NEG_ENOPKG);
    }

    let plain = trimmed.len() == 32;
    let uuid = trimmed.len() == 36;
    if !(plain || uuid) || !id128_is_valid(trimmed) {
        return Err(NEG_EUCLEAN);
    }
    if plain && !flags.contains(Id128Flags::FORMAT_PLAIN) {
        return Err(NEG_EUCLEAN);
    }
    if uuid && !flags.contains(Id128Flags::FORMAT_UUID) {
        return Err(NEG_EUCLEAN);
    }

    let id = id128_from_string_nonzero(trimmed).or_else(|errno| {
        if errno == -(libc::ENXIO as i32) && !flags.contains(Id128Flags::REFUSE_NULL) {
            Ok(SdId128([0; 16]))
        } else if errno == NEG_EINVAL {
            Err(NEG_EUCLEAN)
        } else {
            Err(errno)
        }
    })?;

    Ok(id)
}

fn encode_plain(id: SdId128) -> String {
    id.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn encode_uuid(id: SdId128) -> String {
    let plain = encode_plain(id);
    format!(
        "{}-{}-{}-{}-{}",
        &plain[0..8],
        &plain[8..12],
        &plain[12..16],
        &plain[16..20],
        &plain[20..32]
    )
}

fn io_errno(error: std::io::Error) -> i32 {
    -error.raw_os_error().unwrap_or(libc::EIO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_id() -> SdId128 {
        SdId128([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
    }

    #[test]
    fn validates_plain_string() {
        assert!(id128_is_valid_ext("00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn validates_uuid_string() {
        assert!(id128_is_valid_ext("00112233-4455-6677-8899-aabbccddeeff"));
    }

    #[test]
    fn reads_plain_id() {
        let data = Cursor::new("00112233445566778899aabbccddeeff\n");
        assert_eq!(id128_read(data, Id128Flags::FORMAT_PLAIN), Ok(sample_id()));
    }

    #[test]
    fn reads_uuid_id() {
        let data = Cursor::new("00112233-4455-6677-8899-aabbccddeeff");
        assert_eq!(id128_read(data, Id128Flags::FORMAT_UUID), Ok(sample_id()));
    }

    #[test]
    fn rejects_empty_input() {
        let data = Cursor::new("");
        assert_eq!(id128_read(data, Id128Flags::ANY), Err(NEG_ENOMEDIUM));
    }

    #[test]
    fn rejects_uninitialized_marker() {
        let data = Cursor::new("uninitialized\n");
        assert_eq!(id128_read(data, Id128Flags::ANY), Err(NEG_ENOPKG));
    }

    #[test]
    fn rejects_wrong_format() {
        let data = Cursor::new("00112233445566778899aabbccddeeff");
        assert_eq!(id128_read(data, Id128Flags::FORMAT_UUID), Err(NEG_EUCLEAN));
    }

    #[test]
    fn writes_plain_format() {
        let mut output = Vec::new();
        id128_write(&mut output, Id128Flags::FORMAT_PLAIN, sample_id()).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "00112233445566778899aabbccddeeff\n"
        );
    }

    #[test]
    fn writes_uuid_format() {
        let mut output = Vec::new();
        id128_write(&mut output, Id128Flags::FORMAT_UUID, sample_id()).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "00112233-4455-6677-8899-aabbccddeeff\n"
        );
    }
}
