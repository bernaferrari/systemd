// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-signature.c
//

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -libc::EINVAL;
pub const SD_BUS_MAXIMUM_SIGNATURE_LENGTH: usize = 255;

const BASIC_TYPES: &[u8] = b"ybnqiuxtdsogh";

pub fn signature_element_length(signature: &str) -> Result<usize> {
    signature_element_length_internal(signature.as_bytes(), true, 0, 0)
}

pub fn signature_is_single(signature: &str, allow_dict_entry: bool) -> bool {
    signature_element_length_internal(signature.as_bytes(), allow_dict_entry, 0, 0)
        .is_ok_and(|len| len == signature.len())
}

pub fn signature_is_pair(signature: &str) -> bool {
    let bytes = signature.as_bytes();
    match bytes.split_first() {
        Some((&first, rest)) if bus_type_is_basic(first) => std::str::from_utf8(rest)
            .ok()
            .is_some_and(|s| signature_is_single(s, false)),
        _ => false,
    }
}

pub fn signature_is_valid(signature: &str, allow_dict_entry: bool) -> bool {
    let bytes = signature.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        let len = match signature_element_length_internal(&bytes[offset..], allow_dict_entry, 0, 0)
        {
            Ok(len) => len,
            Err(_) => return false,
        };
        offset += len;
    }
    offset <= SD_BUS_MAXIMUM_SIGNATURE_LENGTH
}

fn signature_element_length_internal(
    s: &[u8],
    allow_dict_entry: bool,
    array_depth: u32,
    struct_depth: u32,
) -> Result<usize> {
    let Some((&first, _)) = s.split_first() else {
        return Err(NEG_EINVAL);
    };

    if bus_type_is_basic(first) || first == b'v' {
        return Ok(1);
    }

    if first == b'a' {
        if array_depth >= 32 {
            return Err(NEG_EINVAL);
        }
        return Ok(signature_element_length_internal(
            &s[1..],
            true,
            array_depth + 1,
            struct_depth,
        )? + 1);
    }

    if first == b'(' {
        if struct_depth >= 32 {
            return Err(NEG_EINVAL);
        }
        let mut p = 1;
        while s.get(p).copied() != Some(b')') {
            let len =
                signature_element_length_internal(&s[p..], false, array_depth, struct_depth + 1)?;
            p += len;
            if p >= s.len() {
                return Err(NEG_EINVAL);
            }
        }
        if p < 2 {
            return Err(NEG_EINVAL);
        }
        return Ok(p + 1);
    }

    if first == b'{' && allow_dict_entry {
        if struct_depth >= 32 {
            return Err(NEG_EINVAL);
        }
        let mut p = 1;
        let mut n = 0;
        while s.get(p).copied() != Some(b'}') {
            let Some(&current) = s.get(p) else {
                return Err(NEG_EINVAL);
            };
            if n == 0 && !bus_type_is_basic(current) {
                return Err(NEG_EINVAL);
            }
            let len =
                signature_element_length_internal(&s[p..], false, array_depth, struct_depth + 1)?;
            p += len;
            n += 1;
            if p >= s.len() {
                return Err(NEG_EINVAL);
            }
        }
        if n != 2 {
            return Err(NEG_EINVAL);
        }
        return Ok(p + 1);
    }

    Err(NEG_EINVAL)
}

fn bus_type_is_basic(c: u8) -> bool {
    BASIC_TYPES.contains(&c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measures_basic_element() {
        assert_eq!(signature_element_length("s").unwrap(), 1);
    }

    #[test]
    fn measures_array_element() {
        assert_eq!(signature_element_length("as").unwrap(), 2);
    }

    #[test]
    fn measures_struct_element() {
        assert_eq!(signature_element_length("(su)").unwrap(), 4);
    }

    #[test]
    fn rejects_empty_struct() {
        assert_eq!(signature_element_length("()"), Err(NEG_EINVAL));
    }

    #[test]
    fn validates_dict_entry() {
        assert_eq!(signature_element_length("{ss}").unwrap(), 4);
    }

    #[test]
    fn rejects_dict_with_non_basic_key() {
        assert_eq!(signature_element_length("{asv}"), Err(NEG_EINVAL));
    }

    #[test]
    fn checks_single_signature() {
        assert!(signature_is_single("a{sv}", true));
        assert!(!signature_is_single("ss", true));
    }

    #[test]
    fn checks_pair_signature() {
        assert!(signature_is_pair("sv"));
        assert!(!signature_is_pair("av"));
    }

    #[test]
    fn validates_whole_signature_length() {
        assert!(signature_is_valid("a{sv}(ss)", true));
    }
}
