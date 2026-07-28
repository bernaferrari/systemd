// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-id128/sd-id128.c, src/systemd/sd-id128.h
//

use crate::id128_util::SdId128;

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
pub const SD_ID128_STRING_MAX: usize = 33;
pub const SD_ID128_UUID_STRING_MAX: usize = 37;

pub fn sd_id128_to_string(id: SdId128) -> String {
    id.0.iter()
        .flat_map(|b| [hexchar(b >> 4), hexchar(b & 0x0f)])
        .collect()
}

pub fn sd_id128_to_uuid_string(id: SdId128) -> String {
    let plain = sd_id128_to_string(id);
    format!(
        "{}-{}-{}-{}-{}",
        &plain[0..8],
        &plain[8..12],
        &plain[12..16],
        &plain[16..20],
        &plain[20..32],
    )
}

pub fn sd_id128_from_string(s: &str) -> Result<SdId128> {
    let bytes = s.as_bytes();
    let mut out = [0u8; 16];
    let mut n = 0;
    let mut i = 0;
    let mut is_guid = false;

    while n < out.len() {
        if i >= bytes.len() {
            return Err(NEG_EINVAL);
        }
        if bytes[i] == b'-' {
            if i == 8 {
                is_guid = true;
            } else if matches!(i, 13 | 18 | 23) {
                if !is_guid {
                    return Err(NEG_EINVAL);
                }
            } else {
                return Err(NEG_EINVAL);
            }
            i += 1;
            continue;
        }
        let a = unhexchar(bytes[i]).ok_or(NEG_EINVAL)?;
        i += 1;
        if i >= bytes.len() {
            return Err(NEG_EINVAL);
        }
        let b = unhexchar(bytes[i]).ok_or(NEG_EINVAL)?;
        i += 1;
        out[n] = (a << 4) | b;
        n += 1;
    }

    let expected = if is_guid { 36 } else { 32 };
    if i != expected || bytes.len() != expected {
        return Err(NEG_EINVAL);
    }

    Ok(SdId128(out))
}

pub fn sd_id128_string_equal(s: &str, id: SdId128) -> Result<bool> {
    Ok(sd_id128_from_string(s)? == id)
}

fn hexchar(v: u8) -> char {
    if v < 10 {
        (b'0' + v) as char
    } else {
        (b'a' + v - 10) as char
    }
}

fn unhexchar(v: u8) -> Option<u8> {
    match v {
        b'0'..=b'9' => Some(v - b'0'),
        b'a'..=b'f' => Some(v - b'a' + 10),
        b'A'..=b'F' => Some(v - b'A' + 10),
        _ => None,
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
    fn formats_plain_id128() {
        assert_eq!(sd_id128_to_string(WALDI), STR_WALDI);
    }

    #[test]
    fn formats_uuid_id128() {
        assert_eq!(sd_id128_to_uuid_string(WALDI), UUID_WALDI);
    }

    #[test]
    fn parses_plain_id128() {
        assert_eq!(sd_id128_from_string(STR_WALDI).unwrap(), WALDI);
    }

    #[test]
    fn parses_uuid_id128() {
        assert_eq!(sd_id128_from_string(UUID_WALDI).unwrap(), WALDI);
    }

    #[test]
    fn rejects_c_suite_invalid_strings() {
        assert_eq!(sd_id128_from_string(""), Err(NEG_EINVAL));
        assert_eq!(
            sd_id128_from_string("01020304-0506-0708-090a-0b0c0d0e0f101"),
            Err(NEG_EINVAL)
        );
        assert_eq!(
            sd_id128_from_string("01020304-0506-0708-090a-0b0c0d0e0f10-"),
            Err(NEG_EINVAL)
        );
        assert_eq!(
            sd_id128_from_string("01020304-0506-0708-090a0b0c0d0e0f10"),
            Err(NEG_EINVAL)
        );
        assert_eq!(
            sd_id128_from_string("010203040506-0708-090a-0b0c0d0e0f10"),
            Err(NEG_EINVAL)
        );
    }

    #[test]
    fn rejects_braced_uuid_for_c_compat() {
        assert_eq!(
            sd_id128_from_string("{01020304-0506-0708-090a-0b0c0d0e0f10}"),
            Err(NEG_EINVAL)
        );
    }

    #[test]
    fn compares_equal_string() {
        assert_eq!(sd_id128_string_equal(STR_WALDI, WALDI), Ok(true));
    }

    #[test]
    fn compares_unequal_string() {
        assert_eq!(
            sd_id128_string_equal("ffffffffffffffffffffffffffffffff", WALDI),
            Ok(false)
        );
    }
}
