// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/syslog-util.c

use crate::ffi::Errno;

const LOG_FACMASK: i32 = 0x03f8;
const LOG_FAC_MAX: i32 = 127;
const LOG_DEBUG: i32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFacility {
    Kern,
    User,
    Mail,
    Daemon,
    Auth,
    Syslog,
    Lpr,
    News,
    Uucp,
    Cron,
    Authpriv,
    Ftp,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

impl LogFacility {
    pub const fn unshifted_value(self) -> i32 {
        match self {
            Self::Kern => 0,
            Self::User => 1,
            Self::Mail => 2,
            Self::Daemon => 3,
            Self::Auth => 4,
            Self::Syslog => 5,
            Self::Lpr => 6,
            Self::News => 7,
            Self::Uucp => 8,
            Self::Cron => 9,
            Self::Authpriv => 10,
            Self::Ftp => 11,
            Self::Local0 => 16,
            Self::Local1 => 17,
            Self::Local2 => 18,
            Self::Local3 => 19,
            Self::Local4 => 20,
            Self::Local5 => 21,
            Self::Local6 => 22,
            Self::Local7 => 23,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Emerg,
    Alert,
    Crit,
    Err,
    Warning,
    Notice,
    Info,
    Debug,
}

impl LogLevel {
    pub const fn value(self) -> i32 {
        match self {
            Self::Emerg => 0,
            Self::Alert => 1,
            Self::Crit => 2,
            Self::Err => 3,
            Self::Warning => 4,
            Self::Notice => 5,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }
}

const LOG_FACILITY_TABLE: &[(i32, &'static str)] = &[
    (LogFacility::Kern.unshifted_value(), "kern"),
    (LogFacility::User.unshifted_value(), "user"),
    (LogFacility::Mail.unshifted_value(), "mail"),
    (LogFacility::Daemon.unshifted_value(), "daemon"),
    (LogFacility::Auth.unshifted_value(), "auth"),
    (LogFacility::Syslog.unshifted_value(), "syslog"),
    (LogFacility::Lpr.unshifted_value(), "lpr"),
    (LogFacility::News.unshifted_value(), "news"),
    (LogFacility::Uucp.unshifted_value(), "uucp"),
    (LogFacility::Cron.unshifted_value(), "cron"),
    (LogFacility::Authpriv.unshifted_value(), "authpriv"),
    (LogFacility::Ftp.unshifted_value(), "ftp"),
    (LogFacility::Local0.unshifted_value(), "local0"),
    (LogFacility::Local1.unshifted_value(), "local1"),
    (LogFacility::Local2.unshifted_value(), "local2"),
    (LogFacility::Local3.unshifted_value(), "local3"),
    (LogFacility::Local4.unshifted_value(), "local4"),
    (LogFacility::Local5.unshifted_value(), "local5"),
    (LogFacility::Local6.unshifted_value(), "local6"),
    (LogFacility::Local7.unshifted_value(), "local7"),
];

const LOG_LEVEL_TABLE: &[(i32, &'static str)] = &[
    (LogLevel::Emerg.value(), "emerg"),
    (LogLevel::Alert.value(), "alert"),
    (LogLevel::Crit.value(), "crit"),
    (LogLevel::Err.value(), "err"),
    (LogLevel::Warning.value(), "warning"),
    (LogLevel::Notice.value(), "notice"),
    (LogLevel::Info.value(), "info"),
    (LogLevel::Debug.value(), "debug"),
];

fn lookup_name(table: &[(i32, &'static str)], value: i32) -> Option<&'static str> {
    table
        .iter()
        .find_map(move |(candidate, name)| (*candidate == value).then_some(*name))
}

fn lookup_value_with_fallback(
    table: &[(i32, &'static str)],
    name: &str,
    fallback_max: i32,
) -> Result<i32, Errno> {
    if let Some(value) = table
        .iter()
        .find_map(|(value, candidate)| (*candidate == name).then_some(*value))
    {
        return Ok(value);
    }

    let parsed = name.parse::<i32>().map_err(|_| Errno::EINVAL)?;
    if !(0..=fallback_max).contains(&parsed) {
        return Err(Errno::EINVAL);
    }

    Ok(parsed)
}

pub const fn log_facility_unshifted_is_valid(facility: i32) -> bool {
    facility >= 0 && facility <= LOG_FAC_MAX
}

pub fn log_facility_unshifted_to_string(value: i32) -> Result<String, Errno> {
    if !log_facility_unshifted_is_valid(value) {
        return Err(Errno::ERANGE);
    }

    Ok(lookup_name(LOG_FACILITY_TABLE, value)
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string()))
}

pub fn log_facility_unshifted_from_string(name: &str) -> Result<i32, Errno> {
    lookup_value_with_fallback(LOG_FACILITY_TABLE, name, LOG_FAC_MAX)
}

pub const fn log_level_is_valid(level: i32) -> bool {
    level >= 0 && level <= LOG_DEBUG
}

pub fn log_level_to_string(value: i32) -> Result<String, Errno> {
    if !log_level_is_valid(value) {
        return Err(Errno::ERANGE);
    }

    Ok(lookup_name(LOG_LEVEL_TABLE, value)
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string()))
}

pub fn log_level_from_string(name: &str) -> Result<i32, Errno> {
    lookup_value_with_fallback(LOG_LEVEL_TABLE, name, LOG_DEBUG)
}

pub fn syslog_parse_priority(
    input: &str,
    priority: i32,
    with_facility: bool,
) -> Option<(&str, i32)> {
    if !input.starts_with('<') {
        return None;
    }

    let end = input.find('>')?;
    let digits = &input[1..end];
    if !(1..=3).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let mut a = 0;
    let mut b = 0;
    let c;

    match digits.as_bytes() {
        [c0] => {
            c = (c0 - b'0') as i32;
        }
        [b0, c0] => {
            b = (b0 - b'0') as i32;
            c = (c0 - b'0') as i32;
        }
        [a0, b0, c0] => {
            a = (a0 - b'0') as i32;
            b = (b0 - b'0') as i32;
            c = (c0 - b'0') as i32;
        }
        _ => return None,
    }

    if !with_facility && (a != 0 || b != 0 || c > LOG_DEBUG) {
        return None;
    }

    let parsed = if with_facility {
        a * 100 + b * 10 + c
    } else {
        (priority & LOG_FACMASK) | c
    };

    Some((&input[end + 1..], parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facility_validity_matches_c_range() {
        assert!(log_facility_unshifted_is_valid(0));
        assert!(log_facility_unshifted_is_valid(23));
        assert!(log_facility_unshifted_is_valid(127));
        assert!(!log_facility_unshifted_is_valid(-1));
        assert!(!log_facility_unshifted_is_valid(128));
    }

    #[test]
    fn facility_lookup_prefers_named_entries() {
        assert_eq!(log_facility_unshifted_to_string(0), Ok("kern".to_string()));
        assert_eq!(
            log_facility_unshifted_to_string(23),
            Ok("local7".to_string())
        );
    }

    #[test]
    fn facility_lookup_falls_back_to_numeric_strings() {
        assert_eq!(log_facility_unshifted_to_string(12), Ok("12".to_string()));
    }

    #[test]
    fn facility_lookup_rejects_out_of_range_values() {
        assert_eq!(log_facility_unshifted_to_string(-1), Err(Errno::ERANGE));
        assert_eq!(log_facility_unshifted_to_string(128), Err(Errno::ERANGE));
    }

    #[test]
    fn facility_parsing_is_case_sensitive_with_numeric_fallback() {
        assert_eq!(log_facility_unshifted_from_string("kern"), Ok(0));
        assert_eq!(log_facility_unshifted_from_string("23"), Ok(23));
        assert_eq!(
            log_facility_unshifted_from_string("KERN"),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn level_validity_matches_c_range() {
        assert!(log_level_is_valid(0));
        assert!(log_level_is_valid(7));
        assert!(!log_level_is_valid(-1));
        assert!(!log_level_is_valid(8));
    }

    #[test]
    fn level_lookup_and_parsing_match_tables() {
        assert_eq!(log_level_to_string(7), Ok("debug".to_string()));
        assert_eq!(log_level_from_string("debug"), Ok(7));
        assert_eq!(log_level_from_string("7"), Ok(7));
        assert_eq!(log_level_from_string("Debug"), Err(Errno::EINVAL));
    }

    #[test]
    fn syslog_parse_priority_handles_level_only_inputs() {
        assert_eq!(
            syslog_parse_priority("<5>rest", 0x120, false),
            Some(("rest", 0x125))
        );
        assert_eq!(
            syslog_parse_priority("<007>rest", 0x120, false),
            Some(("rest", 0x127))
        );
    }

    #[test]
    fn syslog_parse_priority_handles_facility_values() {
        assert_eq!(
            syslog_parse_priority("<191>msg", 0, true),
            Some(("msg", 191))
        );
        assert_eq!(syslog_parse_priority("<13>", 0, true), Some(("", 13)));
    }

    #[test]
    fn syslog_parse_priority_rejects_malformed_prefixes_like_c() {
        assert_eq!(syslog_parse_priority("hello", 0, false), None);
        assert_eq!(syslog_parse_priority("<8>msg", 0, false), None);
        assert_eq!(syslog_parse_priority("<abc>msg", 0, false), None);
        assert_eq!(syslog_parse_priority("<1234>msg", 0, true), None);
        assert_eq!(syslog_parse_priority("<1", 0, false), None);
    }
}
