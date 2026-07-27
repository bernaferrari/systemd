// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/libsystemd/sd-bus/bus-internal.c, src/libsystemd/sd-bus/bus-internal.h

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
pub const BUS_PATH_SIZE_MAX: usize = 64 * 1024;
pub const SD_BUS_MAXIMUM_NAME_LENGTH: usize = 255;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BusMessageType {
    MethodCall = 1,
    MethodReturn = 2,
    MethodError = 3,
    Signal = 4,
}

impl BusMessageType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MethodCall => "method_call",
            Self::MethodReturn => "method_return",
            Self::MethodError => "error",
            Self::Signal => "signal",
        }
    }
}

pub fn bus_message_type_from_string(s: &str) -> Result<BusMessageType> {
    match s {
        "signal" => Ok(BusMessageType::Signal),
        "method_call" => Ok(BusMessageType::MethodCall),
        "error" => Ok(BusMessageType::MethodError),
        "method_return" => Ok(BusMessageType::MethodReturn),
        _ => Err(NEG_EINVAL),
    }
}

pub fn bus_message_type_to_string(message_type: BusMessageType) -> &'static str {
    message_type.as_str()
}

pub fn object_path_is_valid(path: &str) -> bool {
    if path.is_empty() || !path.starts_with('/') {
        return false;
    }
    if path == "/" {
        return true;
    }

    if path.len() > BUS_PATH_SIZE_MAX || path.ends_with('/') {
        return false;
    }

    for segment in path[1..].split('/') {
        if segment.is_empty()
            || !segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return false;
        }
    }

    true
}

pub fn interface_name_is_valid(name: &str) -> bool {
    dotted_name_is_valid(name, false)
}

pub fn service_name_is_valid(name: &str) -> bool {
    if name.is_empty() || name.len() > SD_BUS_MAXIMUM_NAME_LENGTH {
        return false;
    }

    let unique = name.starts_with(':');
    let body = if unique { &name[1..] } else { name };
    if body.is_empty() {
        return false;
    }

    let mut segment_count = 0u32;
    for segment in body.split('.') {
        if segment.is_empty() {
            return false;
        }

        segment_count += 1;
        let mut chars = segment.chars();
        let first = match chars.next() {
            Some(c) => c,
            None => return false,
        };

        if !first.is_ascii_alphabetic()
            && !(unique && first.is_ascii_digit())
            && first != '_'
            && first != '-'
        {
            return false;
        }

        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return false;
        }
    }

    segment_count > 1
}

pub fn member_name_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= SD_BUS_MAXIMUM_NAME_LENGTH
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn namespace_complex_pattern(pattern: Option<&str>, value: Option<&str>) -> bool {
    complex_pattern_check('.', pattern, value)
}

pub fn path_complex_pattern(pattern: Option<&str>, value: Option<&str>) -> bool {
    complex_pattern_check('/', pattern, value)
}

pub fn namespace_simple_pattern(pattern: Option<&str>, value: Option<&str>) -> bool {
    simple_pattern_check('.', pattern, value)
}

pub fn path_simple_pattern(pattern: Option<&str>, value: Option<&str>) -> bool {
    simple_pattern_check('/', pattern, value)
}

fn dotted_name_is_valid(name: &str, allow_leading_colon: bool) -> bool {
    if name.is_empty() || name.len() > SD_BUS_MAXIMUM_NAME_LENGTH {
        return false;
    }

    let body = if allow_leading_colon && name.starts_with(':') {
        &name[1..]
    } else {
        name
    };

    let mut found_dot = false;
    for segment in body.split('.') {
        if segment.is_empty() {
            return false;
        }

        found_dot = true;
        let mut chars = segment.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }

        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }

    found_dot && !body.ends_with('.')
}

fn complex_pattern_check(separator: char, a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (None, None) => return true,
        (Some(_), None) | (None, Some(_)) => return false,
        (Some(a), Some(b)) => {
            let a = a.as_bytes();
            let b = b.as_bytes();
            let mut separator_seen = false;
            let mut i = 0usize;

            loop {
                let ac = a.get(i).copied().unwrap_or(0);
                let bc = b.get(i).copied().unwrap_or(0);

                if ac != bc {
                    return separator_seen && (ac == 0 || bc == 0);
                }
                if ac == 0 {
                    return true;
                }

                separator_seen = ac == separator as u8;
                i += 1;
            }
        }
    }
}

fn simple_pattern_check(separator: char, a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (None, None) => return true,
        (Some(_), None) | (None, Some(_)) => return false,
        (Some(a), Some(b)) => {
            let a = a.as_bytes();
            let b = b.as_bytes();
            let mut separator_seen = false;
            let mut i = 0usize;

            loop {
                let ac = a.get(i).copied().unwrap_or(0);
                let bc = b.get(i).copied().unwrap_or(0);

                if ac != bc {
                    return ac == 0 && (bc == separator as u8 || separator_seen);
                }
                if ac == 0 {
                    return true;
                }

                separator_seen = ac == separator as u8;
                i += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bus_message_types() {
        assert_eq!(
            bus_message_type_from_string("signal"),
            Ok(BusMessageType::Signal)
        );
        assert_eq!(
            bus_message_type_from_string("method_call"),
            Ok(BusMessageType::MethodCall)
        );
    }

    #[test]
    fn rejects_unknown_bus_message_type() {
        assert_eq!(bus_message_type_from_string("bogus"), Err(NEG_EINVAL));
    }

    #[test]
    fn formats_bus_message_type() {
        assert_eq!(
            bus_message_type_to_string(BusMessageType::MethodReturn),
            "method_return"
        );
    }

    #[test]
    fn validates_object_paths() {
        assert!(object_path_is_valid("/"));
        assert!(object_path_is_valid("/org/freedesktop/systemd1"));
        assert!(!object_path_is_valid("org/freedesktop"));
        assert!(!object_path_is_valid("/org//systemd"));
        assert!(!object_path_is_valid("/org/systemd/"));
    }

    #[test]
    fn validates_interface_names() {
        assert!(interface_name_is_valid("org.freedesktop.systemd1.Manager"));
        assert!(!interface_name_is_valid("org..systemd"));
        assert!(!interface_name_is_valid("123.systemd"));
    }

    #[test]
    fn validates_service_names() {
        assert!(service_name_is_valid("org.freedesktop.systemd1"));
        assert!(service_name_is_valid(":1.42"));
        assert!(!service_name_is_valid("org..bad"));
        assert!(!service_name_is_valid(":bad"));
    }

    #[test]
    fn validates_member_names() {
        assert!(member_name_is_valid("Reload"));
        assert!(member_name_is_valid("JobRemoved"));
        assert!(!member_name_is_valid(""));
        assert!(!member_name_is_valid("with-dash"));
    }

    #[test]
    fn checks_namespace_complex_patterns() {
        assert!(namespace_complex_pattern(Some("a.b"), Some("a.b")));
        assert!(namespace_complex_pattern(Some("a."), Some("a.b")));
        assert!(namespace_complex_pattern(Some("a.b"), Some("a.")));
        assert!(!namespace_complex_pattern(Some("a.b"), Some("aXb")));
    }

    #[test]
    fn checks_path_simple_patterns() {
        assert!(path_simple_pattern(Some("/foo"), Some("/foo/bar")));
        assert!(path_simple_pattern(Some("/foo/"), Some("/foo/bar")));
        assert!(!path_simple_pattern(Some("/foo"), Some("/foobar")));
    }
}
