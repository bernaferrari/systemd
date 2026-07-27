// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/libsystemd/sd-bus/bus-type.c, src/libsystemd/sd-bus/bus-protocol.h

use libc::c_char;

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);

pub const SD_BUS_TYPE_BYTE: c_char = b'y' as c_char;
pub const SD_BUS_TYPE_BOOLEAN: c_char = b'b' as c_char;
pub const SD_BUS_TYPE_INT16: c_char = b'n' as c_char;
pub const SD_BUS_TYPE_UINT16: c_char = b'q' as c_char;
pub const SD_BUS_TYPE_INT32: c_char = b'i' as c_char;
pub const SD_BUS_TYPE_UINT32: c_char = b'u' as c_char;
pub const SD_BUS_TYPE_INT64: c_char = b'x' as c_char;
pub const SD_BUS_TYPE_UINT64: c_char = b't' as c_char;
pub const SD_BUS_TYPE_DOUBLE: c_char = b'd' as c_char;
pub const SD_BUS_TYPE_STRING: c_char = b's' as c_char;
pub const SD_BUS_TYPE_OBJECT_PATH: c_char = b'o' as c_char;
pub const SD_BUS_TYPE_SIGNATURE: c_char = b'g' as c_char;
pub const SD_BUS_TYPE_ARRAY: c_char = b'a' as c_char;
pub const SD_BUS_TYPE_VARIANT: c_char = b'v' as c_char;
pub const SD_BUS_TYPE_STRUCT: c_char = b'r' as c_char;
pub const SD_BUS_TYPE_STRUCT_BEGIN: c_char = b'(' as c_char;
pub const SD_BUS_TYPE_STRUCT_END: c_char = b')' as c_char;
pub const SD_BUS_TYPE_DICT_ENTRY: c_char = b'e' as c_char;
pub const SD_BUS_TYPE_DICT_ENTRY_BEGIN: c_char = b'{' as c_char;
pub const SD_BUS_TYPE_DICT_ENTRY_END: c_char = b'}' as c_char;
pub const SD_BUS_TYPE_UNIX_FD: c_char = b'h' as c_char;

pub fn bus_type_is_valid(c: c_char) -> bool {
    matches!(
        c as u8,
        b'y' | b'b'
            | b'n'
            | b'q'
            | b'i'
            | b'u'
            | b'x'
            | b't'
            | b'd'
            | b's'
            | b'o'
            | b'g'
            | b'a'
            | b'v'
            | b'r'
            | b'e'
            | b'h'
    )
}

pub fn bus_type_is_basic(c: c_char) -> bool {
    matches!(
        c as u8,
        b'y' | b'b' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'd' | b's' | b'o' | b'g' | b'h'
    )
}

pub fn bus_type_is_trivial(c: c_char) -> bool {
    matches!(
        c as u8,
        b'y' | b'b' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'd'
    )
}

pub fn bus_type_is_container(c: c_char) -> bool {
    matches!(c as u8, b'a' | b'v' | b'r' | b'e')
}

pub fn bus_type_get_alignment(c: c_char) -> Result<i32> {
    match c as u8 {
        b'y' | b'g' | b'v' => Ok(1),
        b'n' | b'q' => Ok(2),
        b'b' | b'i' | b'u' | b's' | b'o' | b'a' | b'h' => Ok(4),
        b'x' | b't' | b'd' | b'r' | b'(' | b'e' | b'{' => Ok(8),
        _ => Err(NEG_EINVAL),
    }
}

pub fn bus_type_get_size(c: c_char) -> Result<i32> {
    match c as u8 {
        b'y' => Ok(1),
        b'n' | b'q' => Ok(2),
        b'b' | b'i' | b'u' | b'h' => Ok(4),
        b'x' | b't' | b'd' => Ok(8),
        _ => Err(NEG_EINVAL),
    }
}

pub fn sd_bus_interface_name_is_valid(name: &str) -> Result<bool> {
    Ok(crate::bus_internal_types::interface_name_is_valid(name))
}

pub fn sd_bus_service_name_is_valid(name: &str) -> Result<bool> {
    Ok(crate::bus_internal_types::service_name_is_valid(name))
}

pub fn sd_bus_member_name_is_valid(name: &str) -> Result<bool> {
    Ok(crate::bus_internal_types::member_name_is_valid(name))
}

pub fn sd_bus_object_path_is_valid(path: &str) -> Result<bool> {
    Ok(crate::bus_internal_types::object_path_is_valid(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_bus_types() {
        assert!(bus_type_is_valid(SD_BUS_TYPE_BYTE));
        assert!(!bus_type_is_valid(b'z' as c_char));
        assert!(!bus_type_is_valid(SD_BUS_TYPE_STRUCT_BEGIN));
    }
    #[test]
    fn identifies_basic_types() {
        assert!(bus_type_is_basic(SD_BUS_TYPE_STRING));
        assert!(!bus_type_is_basic(SD_BUS_TYPE_ARRAY));
    }
    #[test]
    fn identifies_trivial_types() {
        assert!(bus_type_is_trivial(SD_BUS_TYPE_INT64));
        assert!(!bus_type_is_trivial(SD_BUS_TYPE_STRING));
    }
    #[test]
    fn identifies_container_types() {
        assert!(bus_type_is_container(SD_BUS_TYPE_ARRAY));
        assert!(!bus_type_is_container(SD_BUS_TYPE_STRUCT_BEGIN));
        assert!(!bus_type_is_container(SD_BUS_TYPE_UNIX_FD));
    }
    #[test]
    fn returns_alignments() {
        assert_eq!(bus_type_get_alignment(SD_BUS_TYPE_BYTE), Ok(1));
        assert_eq!(bus_type_get_alignment(SD_BUS_TYPE_UINT16), Ok(2));
        assert_eq!(bus_type_get_alignment(SD_BUS_TYPE_STRING), Ok(4));
        assert_eq!(bus_type_get_alignment(SD_BUS_TYPE_STRUCT_BEGIN), Ok(8));
    }
    #[test]
    fn rejects_invalid_alignment_request() {
        assert_eq!(bus_type_get_alignment(b'z' as c_char), Err(NEG_EINVAL));
    }
    #[test]
    fn returns_sizes() {
        assert_eq!(bus_type_get_size(SD_BUS_TYPE_BYTE), Ok(1));
        assert_eq!(bus_type_get_size(SD_BUS_TYPE_BOOLEAN), Ok(4));
        assert_eq!(bus_type_get_size(SD_BUS_TYPE_DOUBLE), Ok(8));
    }
    #[test]
    fn rejects_variable_size_type_size_request() {
        assert_eq!(bus_type_get_size(SD_BUS_TYPE_STRING), Err(NEG_EINVAL));
    }
    #[test]
    fn delegates_name_validation() {
        assert_eq!(
            sd_bus_interface_name_is_valid("org.freedesktop.systemd1.Manager"),
            Ok(true)
        );
        assert_eq!(sd_bus_member_name_is_valid("Reload"), Ok(true));
        assert_eq!(
            sd_bus_object_path_is_valid("/org/freedesktop/systemd1"),
            Ok(true)
        );
    }
}
