// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.exit-status; authority=src/shared/exit-status.c,src/shared/exit-status.h,src/shared/securebits-util.c,src/shared/securebits-util.h
//
use std::collections::BTreeSet;
use std::ffi::CStr;
use std::fmt;
use std::ptr;

use bitflags::bitflags;

pub const CLD_EXITED: i32 = 1;
pub const CLD_KILLED: i32 = 2;
pub const CLD_DUMPED: i32 = 3;

const SIGHUP: i32 = 1;
const SIGINT: i32 = 2;
const SIGPIPE: i32 = 13;
const SIGTERM: i32 = 15;

const SECURE_NOROOT: i32 = 0;
const SECURE_NOROOT_LOCKED: i32 = 1;
const SECURE_NO_SETUID_FIXUP: i32 = 2;
const SECURE_NO_SETUID_FIXUP_LOCKED: i32 = 3;
const SECURE_KEEP_CAPS: i32 = 4;
const SECURE_KEEP_CAPS_LOCKED: i32 = 5;

const SECURE_ALL_BITS: i32 = (1 << SECURE_NOROOT)
    | (1 << SECURE_NO_SETUID_FIXUP)
    | (1 << SECURE_KEEP_CAPS)
    | (1 << 6)
    | (1 << 8)
    | (1 << 10);
const SECURE_ALL_LOCKS: i32 = SECURE_ALL_BITS << 1;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ExitStatusClass: u8 {
        const LIBC = 1 << 0;
        const SYSTEMD = 1 << 1;
        const LSB = 1 << 2;
        const BSD = 1 << 3;
        const FULL = Self::LIBC.bits() | Self::SYSTEMD.bits() | Self::LSB.bits() | Self::BSD.bits();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClean {
    Daemon,
    Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatusMapping {
    pub name: &'static str,
    pub class: ExitStatusClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExitStatusSet {
    statuses: BTreeSet<i32>,
    signals: BTreeSet<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatusFromStringError {
    Invalid,
}

impl fmt::Display for ExitStatusFromStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid exit status")
    }
}

impl std::error::Error for ExitStatusFromStringError {}

fn exit_status_mapping_raw(code: u8) -> Option<(&'static CStr, ExitStatusClass)> {
    let mapping = match code {
        0 => (c"SUCCESS", ExitStatusClass::LIBC),
        1 => (c"FAILURE", ExitStatusClass::LIBC),

        2 => (c"INVALIDARGUMENT", ExitStatusClass::LSB),
        3 => (c"NOTIMPLEMENTED", ExitStatusClass::LSB),
        4 => (c"NOPERMISSION", ExitStatusClass::LSB),
        5 => (c"NOTINSTALLED", ExitStatusClass::LSB),
        6 => (c"NOTCONFIGURED", ExitStatusClass::LSB),
        7 => (c"NOTRUNNING", ExitStatusClass::LSB),

        64 => (c"USAGE", ExitStatusClass::BSD),
        65 => (c"DATAERR", ExitStatusClass::BSD),
        66 => (c"NOINPUT", ExitStatusClass::BSD),
        67 => (c"NOUSER", ExitStatusClass::BSD),
        68 => (c"NOHOST", ExitStatusClass::BSD),
        69 => (c"UNAVAILABLE", ExitStatusClass::BSD),
        70 => (c"SOFTWARE", ExitStatusClass::BSD),
        71 => (c"OSERR", ExitStatusClass::BSD),
        72 => (c"OSFILE", ExitStatusClass::BSD),
        73 => (c"CANTCREAT", ExitStatusClass::BSD),
        74 => (c"IOERR", ExitStatusClass::BSD),
        75 => (c"TEMPFAIL", ExitStatusClass::BSD),
        76 => (c"PROTOCOL", ExitStatusClass::BSD),
        77 => (c"NOPERM", ExitStatusClass::BSD),
        78 => (c"CONFIG", ExitStatusClass::BSD),

        200 => (c"CHDIR", ExitStatusClass::SYSTEMD),
        201 => (c"NICE", ExitStatusClass::SYSTEMD),
        202 => (c"FDS", ExitStatusClass::SYSTEMD),
        203 => (c"EXEC", ExitStatusClass::SYSTEMD),
        204 => (c"MEMORY", ExitStatusClass::SYSTEMD),
        205 => (c"LIMITS", ExitStatusClass::SYSTEMD),
        206 => (c"OOM_ADJUST", ExitStatusClass::SYSTEMD),
        207 => (c"SIGNAL_MASK", ExitStatusClass::SYSTEMD),
        208 => (c"STDIN", ExitStatusClass::SYSTEMD),
        209 => (c"STDOUT", ExitStatusClass::SYSTEMD),
        210 => (c"CHROOT", ExitStatusClass::SYSTEMD),
        211 => (c"IOPRIO", ExitStatusClass::SYSTEMD),
        212 => (c"TIMERSLACK", ExitStatusClass::SYSTEMD),
        213 => (c"SECUREBITS", ExitStatusClass::SYSTEMD),
        214 => (c"SETSCHEDULER", ExitStatusClass::SYSTEMD),
        215 => (c"CPUAFFINITY", ExitStatusClass::SYSTEMD),
        216 => (c"GROUP", ExitStatusClass::SYSTEMD),
        217 => (c"USER", ExitStatusClass::SYSTEMD),
        218 => (c"CAPABILITIES", ExitStatusClass::SYSTEMD),
        219 => (c"CGROUP", ExitStatusClass::SYSTEMD),
        220 => (c"SETSID", ExitStatusClass::SYSTEMD),
        221 => (c"CONFIRM", ExitStatusClass::SYSTEMD),
        222 => (c"STDERR", ExitStatusClass::SYSTEMD),
        224 => (c"PAM", ExitStatusClass::SYSTEMD),
        225 => (c"NETWORK", ExitStatusClass::SYSTEMD),
        226 => (c"NAMESPACE", ExitStatusClass::SYSTEMD),
        227 => (c"NO_NEW_PRIVILEGES", ExitStatusClass::SYSTEMD),
        228 => (c"SECCOMP", ExitStatusClass::SYSTEMD),
        229 => (c"SELINUX_CONTEXT", ExitStatusClass::SYSTEMD),
        230 => (c"PERSONALITY", ExitStatusClass::SYSTEMD),
        231 => (c"APPARMOR", ExitStatusClass::SYSTEMD),
        232 => (c"ADDRESS_FAMILIES", ExitStatusClass::SYSTEMD),
        233 => (c"RUNTIME_DIRECTORY", ExitStatusClass::SYSTEMD),
        235 => (c"CHOWN", ExitStatusClass::SYSTEMD),
        236 => (c"SMACK_PROCESS_LABEL", ExitStatusClass::SYSTEMD),
        237 => (c"KEYRING", ExitStatusClass::SYSTEMD),
        238 => (c"STATE_DIRECTORY", ExitStatusClass::SYSTEMD),
        239 => (c"CACHE_DIRECTORY", ExitStatusClass::SYSTEMD),
        240 => (c"LOGS_DIRECTORY", ExitStatusClass::SYSTEMD),
        241 => (c"CONFIGURATION_DIRECTORY", ExitStatusClass::SYSTEMD),
        242 => (c"NUMA_POLICY", ExitStatusClass::SYSTEMD),
        243 => (c"CREDENTIALS", ExitStatusClass::SYSTEMD),
        244 => (c"BPF", ExitStatusClass::SYSTEMD),
        245 => (c"KSM", ExitStatusClass::SYSTEMD),
        246 => (c"MEMORY_THP", ExitStatusClass::SYSTEMD),
        255 => (c"EXCEPTION", ExitStatusClass::SYSTEMD),
        _ => return None,
    };

    Some(mapping)
}

fn exit_status_mapping(code: u8) -> Option<ExitStatusMapping> {
    let (c_name, class) = exit_status_mapping_raw(code)?;
    Some(ExitStatusMapping {
        name: c_name
            .to_str()
            .expect("exit status names are valid ASCII strings"),
        class,
    })
}

pub fn exit_status_to_string(code: i32, class: ExitStatusClass) -> Option<&'static str> {
    let code = u8::try_from(code).ok()?;
    let mapping = exit_status_mapping(code)?;
    class.contains(mapping.class).then_some(mapping.name)
}

pub fn exit_status_class(code: i32) -> Option<&'static str> {
    let code = u8::try_from(code).ok()?;
    let mapping = exit_status_mapping(code)?;

    Some(match mapping.class {
        ExitStatusClass::LIBC => "libc",
        ExitStatusClass::SYSTEMD => "systemd",
        ExitStatusClass::LSB => "LSB",
        ExitStatusClass::BSD => "BSD",
        _ => return None,
    })
}

pub fn exit_status_from_string(s: &str) -> Result<i32, ExitStatusFromStringError> {
    for code in 0u16..=u8::MAX as u16 {
        if let Some(mapping) = exit_status_mapping(code as u8) {
            if mapping.name == s {
                return Ok(i32::from(code as u8));
            }
        }
    }

    s.parse::<u8>()
        .map(i32::from)
        .map_err(|_| ExitStatusFromStringError::Invalid)
}

pub fn secure_bit_to_string(bit: i32) -> Option<&'static str> {
    secure_bit_to_c_string(bit).map(|name| {
        name.to_str()
            .expect("secure bit names are valid ASCII strings")
    })
}

fn secure_bit_to_c_string(bit: i32) -> Option<&'static CStr> {
    Some(match bit {
        SECURE_KEEP_CAPS => c"keep-caps",
        SECURE_KEEP_CAPS_LOCKED => c"keep-caps-locked",
        SECURE_NO_SETUID_FIXUP => c"no-setuid-fixup",
        SECURE_NO_SETUID_FIXUP_LOCKED => c"no-setuid-fixup-locked",
        SECURE_NOROOT => c"noroot",
        SECURE_NOROOT_LOCKED => c"noroot-locked",
        _ => return None,
    })
}

pub fn secure_bits_is_valid(bits: i32) -> bool {
    ((SECURE_ALL_BITS | SECURE_ALL_LOCKS) & bits) == bits
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_exit_status_to_string(
    code: libc::c_int,
    class: libc::c_int,
) -> *const libc::c_char {
    let Ok(code) = u8::try_from(code) else {
        return ptr::null();
    };
    let class = ExitStatusClass::from_bits_retain(class as u8);

    exit_status_mapping_raw(code)
        .filter(|(_, mapping_class)| class.contains(*mapping_class))
        .map_or(ptr::null(), |(c_name, _)| c_name.as_ptr())
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_exit_status_class(code: libc::c_int) -> *const libc::c_char {
    let Ok(code) = u8::try_from(code) else {
        return ptr::null();
    };
    let Some(mapping) = exit_status_mapping(code) else {
        return ptr::null();
    };

    match mapping.class {
        ExitStatusClass::LIBC => c"libc".as_ptr(),
        ExitStatusClass::SYSTEMD => c"systemd".as_ptr(),
        ExitStatusClass::LSB => c"LSB".as_ptr(),
        ExitStatusClass::BSD => c"BSD".as_ptr(),
        _ => ptr::null(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_secure_bit_to_string(bit: libc::c_int) -> *const libc::c_char {
    secure_bit_to_c_string(bit)
        .unwrap_or_else(|| std::process::abort())
        .as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_secure_bits_is_valid(bits: libc::c_int) -> bool {
    secure_bits_is_valid(bits)
}

impl ExitStatusSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_status(&mut self, status: i32) {
        self.statuses.insert(status);
    }

    pub fn insert_signal(&mut self, signal: i32) {
        self.signals.insert(signal);
    }

    pub fn clear(&mut self) {
        self.statuses.clear();
        self.signals.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.statuses.is_empty() && self.signals.is_empty()
    }

    pub fn test(&self, code: i32, status: i32) -> bool {
        match code {
            CLD_EXITED => self.statuses.contains(&status),
            CLD_KILLED | CLD_DUMPED => self.signals.contains(&status),
            _ => false,
        }
    }
}

pub fn is_clean_exit(
    code: i32,
    status: i32,
    clean: ExitClean,
    success_status: Option<&ExitStatusSet>,
) -> bool {
    if code == CLD_EXITED {
        return status == 0 || success_status.is_some_and(|set| set.statuses.contains(&status));
    }

    if code == CLD_KILLED {
        return (clean == ExitClean::Daemon
            && matches!(status, SIGHUP | SIGINT | SIGTERM | SIGPIPE))
            || success_status.is_some_and(|set| set.signals.contains(&status));
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_status_to_string_finds_known_code() {
        assert_eq!(
            exit_status_to_string(203, ExitStatusClass::FULL),
            Some("EXEC")
        );
    }

    #[test]
    fn exit_status_to_string_obeys_class_filter() {
        assert_eq!(exit_status_to_string(203, ExitStatusClass::LIBC), None);
    }

    #[test]
    fn exit_status_class_reports_expected_bucket() {
        assert_eq!(exit_status_class(64), Some("BSD"));
        assert_eq!(exit_status_class(225), Some("systemd"));
    }

    #[test]
    fn exit_status_from_string_accepts_symbolic_names() {
        assert_eq!(exit_status_from_string("INVALIDARGUMENT"), Ok(2));
        assert_eq!(exit_status_from_string("EXCEPTION"), Ok(255));
    }

    #[test]
    fn exit_status_from_string_accepts_numeric_values() {
        assert_eq!(exit_status_from_string("42"), Ok(42));
    }

    #[test]
    fn exit_status_from_string_rejects_invalid_values() {
        assert_eq!(
            exit_status_from_string("256"),
            Err(ExitStatusFromStringError::Invalid)
        );
        assert_eq!(
            exit_status_from_string("wat"),
            Err(ExitStatusFromStringError::Invalid)
        );
    }

    #[test]
    fn secure_bit_lookup_uses_single_bit_indices() {
        assert_eq!(secure_bit_to_string(SECURE_KEEP_CAPS), Some("keep-caps"));
        assert_eq!(secure_bit_to_string(1 << SECURE_KEEP_CAPS), None);
    }

    #[test]
    fn secure_bits_validation_matches_header_macro() {
        assert!(secure_bits_is_valid(
            (1 << SECURE_KEEP_CAPS) | (1 << SECURE_NOROOT_LOCKED)
        ));
        assert!(!secure_bits_is_valid(1 << 31));
    }

    #[test]
    fn clean_exit_accepts_zero_and_explicit_statuses() {
        let mut set = ExitStatusSet::new();
        set.insert_status(75);

        assert!(is_clean_exit(CLD_EXITED, 0, ExitClean::Command, None));
        assert!(is_clean_exit(
            CLD_EXITED,
            75,
            ExitClean::Command,
            Some(&set)
        ));
        assert!(!is_clean_exit(
            CLD_EXITED,
            74,
            ExitClean::Command,
            Some(&set)
        ));
    }

    #[test]
    fn clean_exit_accepts_daemon_termination_signals_only_for_daemons() {
        assert!(is_clean_exit(CLD_KILLED, SIGTERM, ExitClean::Daemon, None));
        assert!(!is_clean_exit(
            CLD_KILLED,
            SIGTERM,
            ExitClean::Command,
            None
        ));
    }

    #[test]
    fn exit_status_set_test_matches_c_rules() {
        let mut set = ExitStatusSet::new();
        set.insert_status(3);
        set.insert_signal(SIGINT);

        assert!(set.test(CLD_EXITED, 3));
        assert!(set.test(CLD_DUMPED, SIGINT));
        assert!(!set.test(CLD_KILLED, SIGHUP));
    }

    #[test]
    fn exit_status_set_clear_empties_both_collections() {
        let mut set = ExitStatusSet::new();
        set.insert_status(1);
        set.insert_signal(2);
        assert!(!set.is_empty());
        set.clear();
        assert!(set.is_empty());
    }
}
