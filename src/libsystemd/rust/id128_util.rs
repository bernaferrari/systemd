// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/libsystemd/sd-id128/id128-util.c, src/libsystemd/sd-id128/id128-util.h,
//            src/libsystemd/sd-id128/sd-id128.c, src/systemd/sd-id128.h

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -libc::EINVAL;
pub const NEG_ENXIO: i32 = -libc::ENXIO;

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SdId128(pub [u8; 16]);

impl SdId128 {
    pub const fn null() -> Self {
        Self([0; 16])
    }
    pub fn is_null(self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }
    pub fn is_allf(self) -> bool {
        self.0.iter().all(|b| *b == 0xFF)
    }
}

impl fmt::Display for SdId128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, byte) in self.0.iter().enumerate() {
            if matches!(idx, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for SdId128 {
    type Err = i32;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        parse_id128(s)
    }
}

pub fn id128_compare(a: &SdId128, b: &SdId128) -> i32 {
    for (lhs, rhs) in a.0.iter().zip(b.0.iter()) {
        match lhs.cmp(rhs) {
            Ordering::Less | Ordering::Greater => return (*lhs as i32) - (*rhs as i32),
            Ordering::Equal => continue,
        }
    }
    0
}

pub fn id128_make_v4_uuid(mut id: SdId128) -> SdId128 {
    id.0[6] = (id.0[6] & 0x0F) | 0x40;
    id.0[8] = (id.0[8] & 0x3F) | 0x80;
    id
}

pub fn id128_is_valid(s: &str) -> bool {
    match s.len() {
        32 => s.chars().all(|c| c.is_ascii_hexdigit()),
        36 => s.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        }),
        _ => false,
    }
}

pub fn id128_from_string_nonzero(s: &str) -> Result<SdId128> {
    let parsed = parse_id128(s)?;
    if parsed.is_null() {
        return Err(NEG_ENXIO);
    }
    Ok(parsed)
}

fn parse_id128(s: &str) -> Result<SdId128> {
    if !id128_is_valid(s) {
        return Err(NEG_EINVAL);
    }
    let mut out = [0u8; 16];
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[idx] = (hex_value(chunk[0])? << 4) | hex_value(chunk[1])?;
    }
    Ok(SdId128(out))
}

fn hex_value(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(NEG_EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STR_WALDI: &str = "0102030405060708090a0b0c0d0e0f10";
    const UUID_WALDI: &str = "01020304-0506-0708-090a-0b0c0d0e0f10";
    const WALDI: SdId128 = SdId128([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ]);
    #[test]
    fn detects_plain_id128() {
        assert!(id128_is_valid(STR_WALDI));
    }
    #[test]
    fn detects_uuid_id128() {
        assert!(id128_is_valid(UUID_WALDI));
    }
    #[test]
    fn rejects_bad_id128() {
        assert!(!id128_is_valid(""));
        assert!(!id128_is_valid("01020304-0506-0708-090a-0b0c0d0e0f101"));
        assert!(!id128_is_valid("01020304-0506-0708-090a-0b0c0d0e0f10-"));
        assert!(!id128_is_valid("01020304-0506-0708-090a0b0c0d0e0f10"));
        assert!(!id128_is_valid("010203040506-0708-090a-0b0c0d0e0f10"));
    }
    #[test]
    fn parses_nonzero_plain_id128() {
        assert_eq!(id128_from_string_nonzero(STR_WALDI).unwrap(), WALDI);
    }
    #[test]
    fn rejects_zero_nonzero_id128() {
        assert_eq!(
            id128_from_string_nonzero("00000000000000000000000000000000"),
            Err(NEG_ENXIO)
        );
    }
    #[test]
    fn rejects_invalid_nonzero_inputs() {
        assert!(id128_from_string_nonzero("01020304-0506-0708-090a-0b0c0d0e0f101").is_err());
        assert!(id128_from_string_nonzero("01020304-0506-0708-090a-0b0c0d0e0f10-").is_err());
        assert!(id128_from_string_nonzero("01020304-0506-0708-090a0b0c0d0e0f10").is_err());
        assert!(id128_from_string_nonzero("010203040506-0708-090a-0b0c0d0e0f10").is_err());
    }
    #[test]
    fn compares_equal_id128() {
        let id = SdId128([1; 16]);
        assert_eq!(id128_compare(&id, &id), 0);
    }
    #[test]
    fn compares_unequal_id128() {
        assert!(id128_compare(&SdId128([1; 16]), &SdId128([2; 16])) < 0);
    }
    #[test]
    fn makes_v4_uuid() {
        let id = id128_make_v4_uuid(SdId128([0xFF; 16]));
        assert_eq!(id.0[6] >> 4, 0x4);
        assert_eq!(id.0[8] >> 6, 0b10);
    }
    #[test]
    fn identifies_null_id() {
        assert!(SdId128::null().is_null());
    }
    #[test]
    fn identifies_allf_id() {
        assert!(SdId128([0xFF; 16]).is_allf());
    }

    #[test]
    fn display_formats_uuid() {
        assert_eq!(WALDI.to_string(), UUID_WALDI);
    }

    #[test]
    fn from_str_accepts_plain_and_uuid() {
        assert_eq!(SdId128::from_str(STR_WALDI).unwrap(), WALDI);
        assert_eq!(SdId128::from_str(UUID_WALDI).unwrap(), WALDI);
    }

    #[test]
    fn from_str_rejects_braced_ids() {
        assert_eq!(
            SdId128::from_str("{01020304-0506-0708-090a-0b0c0d0e0f10}"),
            Err(NEG_EINVAL)
        );
        assert_eq!(
            SdId128::from_str("{0102030405060708090a0b0c0d0e0f10"),
            Err(NEG_EINVAL)
        );
        assert_eq!(
            SdId128::from_str("0102030405060708090a0b0c0d0e0f10}"),
            Err(NEG_EINVAL)
        );
    }
}
