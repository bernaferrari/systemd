// SPDX-License-Identifier: LGPL-2.1-or-later
/* PORT-SYNC: src/shared/exit-status.c, src/shared/exit-status.h */

use std::collections::BTreeSet;
use std::fmt;

use bitflags::bitflags;

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_FAILURE: i32 = 1;

pub const EXIT_INVALIDARGUMENT: i32 = 2;
pub const EXIT_NOTIMPLEMENTED: i32 = 3;
pub const EXIT_NOPERMISSION: i32 = 4;
pub const EXIT_NOTINSTALLED: i32 = 5;
pub const EXIT_NOTCONFIGURED: i32 = 6;
pub const EXIT_NOTRUNNING: i32 = 7;

pub const EX_USAGE: i32 = 64;
pub const EX_DATAERR: i32 = 65;
pub const EX_NOINPUT: i32 = 66;
pub const EX_NOUSER: i32 = 67;
pub const EX_NOHOST: i32 = 68;
pub const EX_UNAVAILABLE: i32 = 69;
pub const EX_SOFTWARE: i32 = 70;
pub const EX_OSERR: i32 = 71;
pub const EX_OSFILE: i32 = 72;
pub const EX_CANTCREAT: i32 = 73;
pub const EX_IOERR: i32 = 74;
pub const EX_TEMPFAIL: i32 = 75;
pub const EX_PROTOCOL: i32 = 76;
pub const EX_NOPERM: i32 = 77;
pub const EX_CONFIG: i32 = 78;

pub const EXIT_CHDIR: i32 = 200;
pub const EXIT_NICE: i32 = 201;
pub const EXIT_FDS: i32 = 202;
pub const EXIT_EXEC: i32 = 203;
pub const EXIT_MEMORY: i32 = 204;
pub const EXIT_LIMITS: i32 = 205;
pub const EXIT_OOM_ADJUST: i32 = 206;
pub const EXIT_SIGNAL_MASK: i32 = 207;
pub const EXIT_STDIN: i32 = 208;
pub const EXIT_STDOUT: i32 = 209;
pub const EXIT_CHROOT: i32 = 210;
pub const EXIT_IOPRIO: i32 = 211;
pub const EXIT_TIMERSLACK: i32 = 212;
pub const EXIT_SECUREBITS: i32 = 213;
pub const EXIT_SETSCHEDULER: i32 = 214;
pub const EXIT_CPUAFFINITY: i32 = 215;
pub const EXIT_GROUP: i32 = 216;
pub const EXIT_USER: i32 = 217;
pub const EXIT_CAPABILITIES: i32 = 218;
pub const EXIT_CGROUP: i32 = 219;
pub const EXIT_SETSID: i32 = 220;
pub const EXIT_CONFIRM: i32 = 221;
pub const EXIT_STDERR: i32 = 222;
pub const _EXIT_RESERVED: i32 = 223;
pub const EXIT_PAM: i32 = 224;
pub const EXIT_NETWORK: i32 = 225;
pub const EXIT_NAMESPACE: i32 = 226;
pub const EXIT_NO_NEW_PRIVILEGES: i32 = 227;
pub const EXIT_SECCOMP: i32 = 228;
pub const EXIT_SELINUX_CONTEXT: i32 = 229;
pub const EXIT_PERSONALITY: i32 = 230;
pub const EXIT_APPARMOR_PROFILE: i32 = 231;
pub const EXIT_ADDRESS_FAMILIES: i32 = 232;
pub const EXIT_RUNTIME_DIRECTORY: i32 = 233;
pub const _EXIT_RESERVED2: i32 = 234;
pub const EXIT_CHOWN: i32 = 235;
pub const EXIT_SMACK_PROCESS_LABEL: i32 = 236;
pub const EXIT_KEYRING: i32 = 237;
pub const EXIT_STATE_DIRECTORY: i32 = 238;
pub const EXIT_CACHE_DIRECTORY: i32 = 239;
pub const EXIT_LOGS_DIRECTORY: i32 = 240;
pub const EXIT_CONFIGURATION_DIRECTORY: i32 = 241;
pub const EXIT_NUMA_POLICY: i32 = 242;
pub const EXIT_CREDENTIALS: i32 = 243;
pub const EXIT_BPF: i32 = 244;
pub const EXIT_KSM: i32 = 245;
pub const EXIT_MEMORY_THP: i32 = 246;

pub const EXIT_EXCEPTION: i32 = 255;

pub const CLD_EXITED: i32 = 1;
pub const CLD_KILLED: i32 = 2;
pub const CLD_DUMPED: i32 = 3;

pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGPIPE: i32 = 13;
pub const SIGTERM: i32 = 15;

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

pub const EXIT_STATUS_LIBC: ExitStatusClass = ExitStatusClass::LIBC;
pub const EXIT_STATUS_SYSTEMD: ExitStatusClass = ExitStatusClass::SYSTEMD;
pub const EXIT_STATUS_LSB: ExitStatusClass = ExitStatusClass::LSB;
pub const EXIT_STATUS_BSD: ExitStatusClass = ExitStatusClass::BSD;
pub const EXIT_STATUS_FULL: ExitStatusClass = ExitStatusClass::FULL;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ExitStatus {
    Success = EXIT_SUCCESS,
    Failure = EXIT_FAILURE,
    InvalidArgument = EXIT_INVALIDARGUMENT,
    NotImplemented = EXIT_NOTIMPLEMENTED,
    NoPermission = EXIT_NOPERMISSION,
    NotInstalled = EXIT_NOTINSTALLED,
    NotConfigured = EXIT_NOTCONFIGURED,
    NotRunning = EXIT_NOTRUNNING,
    Usage = EX_USAGE,
    DataErr = EX_DATAERR,
    NoInput = EX_NOINPUT,
    NoUser = EX_NOUSER,
    NoHost = EX_NOHOST,
    Unavailable = EX_UNAVAILABLE,
    Software = EX_SOFTWARE,
    OsErr = EX_OSERR,
    OsFile = EX_OSFILE,
    CantCreate = EX_CANTCREAT,
    IoErr = EX_IOERR,
    TempFail = EX_TEMPFAIL,
    Protocol = EX_PROTOCOL,
    NoPerm = EX_NOPERM,
    Config = EX_CONFIG,
    Chdir = EXIT_CHDIR,
    Nice = EXIT_NICE,
    Fds = EXIT_FDS,
    Exec = EXIT_EXEC,
    Memory = EXIT_MEMORY,
    Limits = EXIT_LIMITS,
    OomAdjust = EXIT_OOM_ADJUST,
    SignalMask = EXIT_SIGNAL_MASK,
    Stdin = EXIT_STDIN,
    Stdout = EXIT_STDOUT,
    Chroot = EXIT_CHROOT,
    Ioprio = EXIT_IOPRIO,
    Timerslack = EXIT_TIMERSLACK,
    SecureBits = EXIT_SECUREBITS,
    SetScheduler = EXIT_SETSCHEDULER,
    CpuAffinity = EXIT_CPUAFFINITY,
    Group = EXIT_GROUP,
    User = EXIT_USER,
    Capabilities = EXIT_CAPABILITIES,
    CGroup = EXIT_CGROUP,
    SetSid = EXIT_SETSID,
    Confirm = EXIT_CONFIRM,
    Stderr = EXIT_STDERR,
    Pam = EXIT_PAM,
    Network = EXIT_NETWORK,
    Namespace = EXIT_NAMESPACE,
    NoNewPrivileges = EXIT_NO_NEW_PRIVILEGES,
    Seccomp = EXIT_SECCOMP,
    SelinuxContext = EXIT_SELINUX_CONTEXT,
    Personality = EXIT_PERSONALITY,
    AppArmor = EXIT_APPARMOR_PROFILE,
    AddressFamilies = EXIT_ADDRESS_FAMILIES,
    RuntimeDirectory = EXIT_RUNTIME_DIRECTORY,
    Chown = EXIT_CHOWN,
    SmackProcessLabel = EXIT_SMACK_PROCESS_LABEL,
    Keyring = EXIT_KEYRING,
    StateDirectory = EXIT_STATE_DIRECTORY,
    CacheDirectory = EXIT_CACHE_DIRECTORY,
    LogsDirectory = EXIT_LOGS_DIRECTORY,
    ConfigurationDirectory = EXIT_CONFIGURATION_DIRECTORY,
    NumaPolicy = EXIT_NUMA_POLICY,
    Credentials = EXIT_CREDENTIALS,
    Bpf = EXIT_BPF,
    Ksm = EXIT_KSM,
    MemoryThp = EXIT_MEMORY_THP,
    Exception = EXIT_EXCEPTION,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatusMapping {
    pub name: &'static str,
    pub class: ExitStatusClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClean {
    Daemon,
    Command,
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

const ALL_EXIT_STATUSES: [ExitStatus; 69] = [
    ExitStatus::Success,
    ExitStatus::Failure,
    ExitStatus::InvalidArgument,
    ExitStatus::NotImplemented,
    ExitStatus::NoPermission,
    ExitStatus::NotInstalled,
    ExitStatus::NotConfigured,
    ExitStatus::NotRunning,
    ExitStatus::Usage,
    ExitStatus::DataErr,
    ExitStatus::NoInput,
    ExitStatus::NoUser,
    ExitStatus::NoHost,
    ExitStatus::Unavailable,
    ExitStatus::Software,
    ExitStatus::OsErr,
    ExitStatus::OsFile,
    ExitStatus::CantCreate,
    ExitStatus::IoErr,
    ExitStatus::TempFail,
    ExitStatus::Protocol,
    ExitStatus::NoPerm,
    ExitStatus::Config,
    ExitStatus::Chdir,
    ExitStatus::Nice,
    ExitStatus::Fds,
    ExitStatus::Exec,
    ExitStatus::Memory,
    ExitStatus::Limits,
    ExitStatus::OomAdjust,
    ExitStatus::SignalMask,
    ExitStatus::Stdin,
    ExitStatus::Stdout,
    ExitStatus::Chroot,
    ExitStatus::Ioprio,
    ExitStatus::Timerslack,
    ExitStatus::SecureBits,
    ExitStatus::SetScheduler,
    ExitStatus::CpuAffinity,
    ExitStatus::Group,
    ExitStatus::User,
    ExitStatus::Capabilities,
    ExitStatus::CGroup,
    ExitStatus::SetSid,
    ExitStatus::Confirm,
    ExitStatus::Stderr,
    ExitStatus::Pam,
    ExitStatus::Network,
    ExitStatus::Namespace,
    ExitStatus::NoNewPrivileges,
    ExitStatus::Seccomp,
    ExitStatus::SelinuxContext,
    ExitStatus::Personality,
    ExitStatus::AppArmor,
    ExitStatus::AddressFamilies,
    ExitStatus::RuntimeDirectory,
    ExitStatus::Chown,
    ExitStatus::SmackProcessLabel,
    ExitStatus::Keyring,
    ExitStatus::StateDirectory,
    ExitStatus::CacheDirectory,
    ExitStatus::LogsDirectory,
    ExitStatus::ConfigurationDirectory,
    ExitStatus::NumaPolicy,
    ExitStatus::Credentials,
    ExitStatus::Bpf,
    ExitStatus::Ksm,
    ExitStatus::MemoryThp,
    ExitStatus::Exception,
];

const fn mapping(name: &'static str, class: ExitStatusClass) -> ExitStatusMapping {
    ExitStatusMapping { name, class }
}

impl ExitStatus {
    pub const fn from_i32(value: i32) -> Option<Self> {
        match value {
            EXIT_SUCCESS => Some(Self::Success),
            EXIT_FAILURE => Some(Self::Failure),
            EXIT_INVALIDARGUMENT => Some(Self::InvalidArgument),
            EXIT_NOTIMPLEMENTED => Some(Self::NotImplemented),
            EXIT_NOPERMISSION => Some(Self::NoPermission),
            EXIT_NOTINSTALLED => Some(Self::NotInstalled),
            EXIT_NOTCONFIGURED => Some(Self::NotConfigured),
            EXIT_NOTRUNNING => Some(Self::NotRunning),
            EX_USAGE => Some(Self::Usage),
            EX_DATAERR => Some(Self::DataErr),
            EX_NOINPUT => Some(Self::NoInput),
            EX_NOUSER => Some(Self::NoUser),
            EX_NOHOST => Some(Self::NoHost),
            EX_UNAVAILABLE => Some(Self::Unavailable),
            EX_SOFTWARE => Some(Self::Software),
            EX_OSERR => Some(Self::OsErr),
            EX_OSFILE => Some(Self::OsFile),
            EX_CANTCREAT => Some(Self::CantCreate),
            EX_IOERR => Some(Self::IoErr),
            EX_TEMPFAIL => Some(Self::TempFail),
            EX_PROTOCOL => Some(Self::Protocol),
            EX_NOPERM => Some(Self::NoPerm),
            EX_CONFIG => Some(Self::Config),
            EXIT_CHDIR => Some(Self::Chdir),
            EXIT_NICE => Some(Self::Nice),
            EXIT_FDS => Some(Self::Fds),
            EXIT_EXEC => Some(Self::Exec),
            EXIT_MEMORY => Some(Self::Memory),
            EXIT_LIMITS => Some(Self::Limits),
            EXIT_OOM_ADJUST => Some(Self::OomAdjust),
            EXIT_SIGNAL_MASK => Some(Self::SignalMask),
            EXIT_STDIN => Some(Self::Stdin),
            EXIT_STDOUT => Some(Self::Stdout),
            EXIT_CHROOT => Some(Self::Chroot),
            EXIT_IOPRIO => Some(Self::Ioprio),
            EXIT_TIMERSLACK => Some(Self::Timerslack),
            EXIT_SECUREBITS => Some(Self::SecureBits),
            EXIT_SETSCHEDULER => Some(Self::SetScheduler),
            EXIT_CPUAFFINITY => Some(Self::CpuAffinity),
            EXIT_GROUP => Some(Self::Group),
            EXIT_USER => Some(Self::User),
            EXIT_CAPABILITIES => Some(Self::Capabilities),
            EXIT_CGROUP => Some(Self::CGroup),
            EXIT_SETSID => Some(Self::SetSid),
            EXIT_CONFIRM => Some(Self::Confirm),
            EXIT_STDERR => Some(Self::Stderr),
            EXIT_PAM => Some(Self::Pam),
            EXIT_NETWORK => Some(Self::Network),
            EXIT_NAMESPACE => Some(Self::Namespace),
            EXIT_NO_NEW_PRIVILEGES => Some(Self::NoNewPrivileges),
            EXIT_SECCOMP => Some(Self::Seccomp),
            EXIT_SELINUX_CONTEXT => Some(Self::SelinuxContext),
            EXIT_PERSONALITY => Some(Self::Personality),
            EXIT_APPARMOR_PROFILE => Some(Self::AppArmor),
            EXIT_ADDRESS_FAMILIES => Some(Self::AddressFamilies),
            EXIT_RUNTIME_DIRECTORY => Some(Self::RuntimeDirectory),
            EXIT_CHOWN => Some(Self::Chown),
            EXIT_SMACK_PROCESS_LABEL => Some(Self::SmackProcessLabel),
            EXIT_KEYRING => Some(Self::Keyring),
            EXIT_STATE_DIRECTORY => Some(Self::StateDirectory),
            EXIT_CACHE_DIRECTORY => Some(Self::CacheDirectory),
            EXIT_LOGS_DIRECTORY => Some(Self::LogsDirectory),
            EXIT_CONFIGURATION_DIRECTORY => Some(Self::ConfigurationDirectory),
            EXIT_NUMA_POLICY => Some(Self::NumaPolicy),
            EXIT_CREDENTIALS => Some(Self::Credentials),
            EXIT_BPF => Some(Self::Bpf),
            EXIT_KSM => Some(Self::Ksm),
            EXIT_MEMORY_THP => Some(Self::MemoryThp),
            EXIT_EXCEPTION => Some(Self::Exception),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Success => "SUCCESS",
            Self::Failure => "FAILURE",
            Self::InvalidArgument => "INVALIDARGUMENT",
            Self::NotImplemented => "NOTIMPLEMENTED",
            Self::NoPermission => "NOPERMISSION",
            Self::NotInstalled => "NOTINSTALLED",
            Self::NotConfigured => "NOTCONFIGURED",
            Self::NotRunning => "NOTRUNNING",
            Self::Usage => "USAGE",
            Self::DataErr => "DATAERR",
            Self::NoInput => "NOINPUT",
            Self::NoUser => "NOUSER",
            Self::NoHost => "NOHOST",
            Self::Unavailable => "UNAVAILABLE",
            Self::Software => "SOFTWARE",
            Self::OsErr => "OSERR",
            Self::OsFile => "OSFILE",
            Self::CantCreate => "CANTCREAT",
            Self::IoErr => "IOERR",
            Self::TempFail => "TEMPFAIL",
            Self::Protocol => "PROTOCOL",
            Self::NoPerm => "NOPERM",
            Self::Config => "CONFIG",
            Self::Chdir => "CHDIR",
            Self::Nice => "NICE",
            Self::Fds => "FDS",
            Self::Exec => "EXEC",
            Self::Memory => "MEMORY",
            Self::Limits => "LIMITS",
            Self::OomAdjust => "OOM_ADJUST",
            Self::SignalMask => "SIGNAL_MASK",
            Self::Stdin => "STDIN",
            Self::Stdout => "STDOUT",
            Self::Chroot => "CHROOT",
            Self::Ioprio => "IOPRIO",
            Self::Timerslack => "TIMERSLACK",
            Self::SecureBits => "SECUREBITS",
            Self::SetScheduler => "SETSCHEDULER",
            Self::CpuAffinity => "CPUAFFINITY",
            Self::Group => "GROUP",
            Self::User => "USER",
            Self::Capabilities => "CAPABILITIES",
            Self::CGroup => "CGROUP",
            Self::SetSid => "SETSID",
            Self::Confirm => "CONFIRM",
            Self::Stderr => "STDERR",
            Self::Pam => "PAM",
            Self::Network => "NETWORK",
            Self::Namespace => "NAMESPACE",
            Self::NoNewPrivileges => "NO_NEW_PRIVILEGES",
            Self::Seccomp => "SECCOMP",
            Self::SelinuxContext => "SELINUX_CONTEXT",
            Self::Personality => "PERSONALITY",
            Self::AppArmor => "APPARMOR",
            Self::AddressFamilies => "ADDRESS_FAMILIES",
            Self::RuntimeDirectory => "RUNTIME_DIRECTORY",
            Self::Chown => "CHOWN",
            Self::SmackProcessLabel => "SMACK_PROCESS_LABEL",
            Self::Keyring => "KEYRING",
            Self::StateDirectory => "STATE_DIRECTORY",
            Self::CacheDirectory => "CACHE_DIRECTORY",
            Self::LogsDirectory => "LOGS_DIRECTORY",
            Self::ConfigurationDirectory => "CONFIGURATION_DIRECTORY",
            Self::NumaPolicy => "NUMA_POLICY",
            Self::Credentials => "CREDENTIALS",
            Self::Bpf => "BPF",
            Self::Ksm => "KSM",
            Self::MemoryThp => "MEMORY_THP",
            Self::Exception => "EXCEPTION",
        }
    }

    pub const fn class(self) -> ExitStatusClass {
        match self {
            Self::Success | Self::Failure => ExitStatusClass::LIBC,
            Self::InvalidArgument
            | Self::NotImplemented
            | Self::NoPermission
            | Self::NotInstalled
            | Self::NotConfigured
            | Self::NotRunning => ExitStatusClass::LSB,
            Self::Usage
            | Self::DataErr
            | Self::NoInput
            | Self::NoUser
            | Self::NoHost
            | Self::Unavailable
            | Self::Software
            | Self::OsErr
            | Self::OsFile
            | Self::CantCreate
            | Self::IoErr
            | Self::TempFail
            | Self::Protocol
            | Self::NoPerm
            | Self::Config => ExitStatusClass::BSD,
            _ => ExitStatusClass::SYSTEMD,
        }
    }

    pub const fn class_name(self) -> &'static str {
        match self.class() {
            ExitStatusClass::LIBC => "libc",
            ExitStatusClass::SYSTEMD => "systemd",
            ExitStatusClass::LSB => "LSB",
            ExitStatusClass::BSD => "BSD",
            _ => unreachable!(),
        }
    }

    pub const fn mapping(self) -> ExitStatusMapping {
        mapping(self.name(), self.class())
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

const fn build_exit_status_mappings() -> [Option<ExitStatusMapping>; 256] {
    let mut mappings = [None; 256];
    let mut index = 0;

    while index < ALL_EXIT_STATUSES.len() {
        let status = ALL_EXIT_STATUSES[index];
        mappings[status as usize] = Some(status.mapping());
        index += 1;
    }

    mappings
}

pub const EXIT_STATUS_MAPPINGS: [Option<ExitStatusMapping>; 256] = build_exit_status_mappings();

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

    pub fn contains_status(&self, status: i32) -> bool {
        self.statuses.contains(&status)
    }

    pub fn contains_signal(&self, signal: i32) -> bool {
        self.signals.contains(&signal)
    }

    pub fn free(&mut self) {
        self.statuses.clear();
        self.signals.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.statuses.is_empty() && self.signals.is_empty()
    }

    pub fn test(&self, code: i32, status: i32) -> bool {
        exit_status_set_test(self, code, status)
    }
}

pub fn exit_status_to_string(code: i32, class: ExitStatusClass) -> Option<&'static str> {
    if !(0..=255).contains(&code) {
        return None;
    }

    let mapping = EXIT_STATUS_MAPPINGS[code as usize]?;
    mapping.class.intersects(class).then_some(mapping.name)
}

pub fn exit_status_class(code: i32) -> Option<&'static str> {
    ExitStatus::from_i32(code).map(ExitStatus::class_name)
}

pub fn exit_status_from_string(value: &str) -> Result<i32, ExitStatusFromStringError> {
    if let Some(status) = ALL_EXIT_STATUSES
        .iter()
        .find(|status| status.name() == value)
    {
        return Ok(*status as i32);
    }

    value
        .parse::<u8>()
        .map(i32::from)
        .map_err(|_| ExitStatusFromStringError::Invalid)
}

pub fn is_clean_exit(
    code: i32,
    status: i32,
    clean: ExitClean,
    success_status: Option<&ExitStatusSet>,
) -> bool {
    if code == CLD_EXITED {
        return status == 0 || success_status.is_some_and(|set| set.contains_status(status));
    }

    if code == CLD_KILLED {
        return (clean == ExitClean::Daemon
            && matches!(status, SIGHUP | SIGINT | SIGTERM | SIGPIPE))
            || success_status.is_some_and(|set| set.contains_signal(status));
    }

    false
}

pub fn exit_status_set_free(set: &mut ExitStatusSet) {
    set.free();
}

pub fn exit_status_set_is_empty(set: Option<&ExitStatusSet>) -> bool {
    set.is_none_or(ExitStatusSet::is_empty)
}

pub fn exit_status_set_test(set: &ExitStatusSet, code: i32, status: i32) -> bool {
    match code {
        CLD_EXITED => set.contains_status(status),
        CLD_KILLED | CLD_DUMPED => set.contains_signal(status),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_named_codes_round_trip_through_enum() {
        for status in ALL_EXIT_STATUSES {
            assert_eq!(ExitStatus::from_i32(status as i32), Some(status));
            assert_eq!(
                status.mapping(),
                EXIT_STATUS_MAPPINGS[status as usize].unwrap()
            );
        }

        assert_eq!(ExitStatus::from_i32(8), None);
        assert_eq!(ExitStatus::from_i32(223), None);
        assert_eq!(ExitStatus::from_i32(234), None);
        assert_eq!(ExitStatus::from_i32(254), None);
    }

    #[test]
    fn exported_constants_match_enum_values() {
        assert_eq!(ExitStatus::Success as i32, EXIT_SUCCESS);
        assert_eq!(ExitStatus::Failure as i32, EXIT_FAILURE);
        assert_eq!(ExitStatus::InvalidArgument as i32, EXIT_INVALIDARGUMENT);
        assert_eq!(ExitStatus::Usage as i32, EX_USAGE);
        assert_eq!(ExitStatus::Chdir as i32, EXIT_CHDIR);
        assert_eq!(ExitStatus::MemoryThp as i32, EXIT_MEMORY_THP);
        assert_eq!(ExitStatus::Exception as i32, EXIT_EXCEPTION);
        assert_eq!(_EXIT_RESERVED, 223);
        assert_eq!(_EXIT_RESERVED2, 234);
    }

    #[test]
    fn exit_status_names_and_display_match_c_table() {
        assert_eq!(ExitStatus::Success.name(), "SUCCESS");
        assert_eq!(ExitStatus::Failure.name(), "FAILURE");
        assert_eq!(ExitStatus::AppArmor.name(), "APPARMOR");
        assert_eq!(
            ExitStatus::ConfigurationDirectory.name(),
            "CONFIGURATION_DIRECTORY"
        );
        assert_eq!(ExitStatus::Exception.name(), "EXCEPTION");
        assert_eq!(ExitStatus::Memory.to_string(), "MEMORY");
    }

    #[test]
    fn exit_status_classes_match_c() {
        assert_eq!(ExitStatus::Success.class(), EXIT_STATUS_LIBC);
        assert_eq!(ExitStatus::InvalidArgument.class(), EXIT_STATUS_LSB);
        assert_eq!(ExitStatus::Usage.class(), EXIT_STATUS_BSD);
        assert_eq!(ExitStatus::Chdir.class(), EXIT_STATUS_SYSTEMD);
        assert_eq!(ExitStatus::Exception.class_name(), "systemd");
    }

    #[test]
    fn exit_status_mapping_table_is_complete_and_reserved_slots_are_empty() {
        assert_eq!(EXIT_STATUS_MAPPINGS.len(), 256);
        assert_eq!(EXIT_STATUS_MAPPINGS[0].unwrap().name, "SUCCESS");
        assert_eq!(EXIT_STATUS_MAPPINGS[1].unwrap().name, "FAILURE");
        assert_eq!(EXIT_STATUS_MAPPINGS[2].unwrap().name, "INVALIDARGUMENT");
        assert_eq!(EXIT_STATUS_MAPPINGS[64].unwrap().name, "USAGE");
        assert_eq!(EXIT_STATUS_MAPPINGS[200].unwrap().name, "CHDIR");
        assert_eq!(EXIT_STATUS_MAPPINGS[255].unwrap().name, "EXCEPTION");
        assert!(EXIT_STATUS_MAPPINGS[8].is_none());
        assert!(EXIT_STATUS_MAPPINGS[223].is_none());
        assert!(EXIT_STATUS_MAPPINGS[234].is_none());
        assert!(EXIT_STATUS_MAPPINGS[254].is_none());
    }

    #[test]
    fn exit_status_to_string_is_faithful() {
        assert_eq!(
            exit_status_to_string(EXIT_SUCCESS, EXIT_STATUS_LIBC),
            Some("SUCCESS")
        );
        assert_eq!(
            exit_status_to_string(EXIT_FAILURE, EXIT_STATUS_LIBC),
            Some("FAILURE")
        );
        assert_eq!(
            exit_status_to_string(EXIT_SUCCESS, EXIT_STATUS_SYSTEMD),
            None
        );
        assert_eq!(
            exit_status_to_string(EXIT_CHDIR, EXIT_STATUS_SYSTEMD),
            Some("CHDIR")
        );
        assert_eq!(exit_status_to_string(EXIT_CHDIR, EXIT_STATUS_LIBC), None);
        assert_eq!(
            exit_status_to_string(EXIT_INVALIDARGUMENT, EXIT_STATUS_LSB),
            Some("INVALIDARGUMENT")
        );
        assert_eq!(
            exit_status_to_string(EX_USAGE, EXIT_STATUS_BSD),
            Some("USAGE")
        );
        assert_eq!(
            exit_status_to_string(EXIT_EXCEPTION, EXIT_STATUS_SYSTEMD),
            Some("EXCEPTION")
        );
        assert_eq!(
            exit_status_to_string(EXIT_SUCCESS, EXIT_STATUS_FULL),
            Some("SUCCESS")
        );
        assert_eq!(exit_status_to_string(8, EXIT_STATUS_FULL), None);
        assert_eq!(exit_status_to_string(-1, EXIT_STATUS_FULL), None);
        assert_eq!(exit_status_to_string(256, EXIT_STATUS_FULL), None);
    }

    #[test]
    fn exit_status_class_is_faithful() {
        assert_eq!(exit_status_class(EXIT_SUCCESS), Some("libc"));
        assert_eq!(exit_status_class(EXIT_CHDIR), Some("systemd"));
        assert_eq!(exit_status_class(EXIT_INVALIDARGUMENT), Some("LSB"));
        assert_eq!(exit_status_class(EX_USAGE), Some("BSD"));
        assert_eq!(exit_status_class(8), None);
        assert_eq!(exit_status_class(-1), None);
        assert_eq!(exit_status_class(256), None);
    }

    #[test]
    fn exit_status_from_string_is_case_sensitive_and_has_numeric_fallback() {
        assert_eq!(exit_status_from_string("SUCCESS"), Ok(EXIT_SUCCESS));
        assert_eq!(exit_status_from_string("FAILURE"), Ok(EXIT_FAILURE));
        assert_eq!(exit_status_from_string("CHDIR"), Ok(EXIT_CHDIR));
        assert_eq!(exit_status_from_string("USAGE"), Ok(EX_USAGE));
        assert_eq!(exit_status_from_string("EXCEPTION"), Ok(EXIT_EXCEPTION));
        assert_eq!(exit_status_from_string("0"), Ok(0));
        assert_eq!(exit_status_from_string("42"), Ok(42));
        assert_eq!(exit_status_from_string("255"), Ok(255));
        assert_eq!(
            exit_status_from_string("success"),
            Err(ExitStatusFromStringError::Invalid)
        );
        assert_eq!(
            exit_status_from_string("FOOBAR"),
            Err(ExitStatusFromStringError::Invalid)
        );
        assert_eq!(
            exit_status_from_string(""),
            Err(ExitStatusFromStringError::Invalid)
        );
        assert_eq!(
            exit_status_from_string("256"),
            Err(ExitStatusFromStringError::Invalid)
        );
        assert_eq!(
            exit_status_from_string("-1"),
            Err(ExitStatusFromStringError::Invalid)
        );
    }

    #[test]
    fn exit_status_set_free_and_empty_are_faithful() {
        let mut set = ExitStatusSet::new();
        assert!(exit_status_set_is_empty(None));
        assert!(exit_status_set_is_empty(Some(&set)));

        set.insert_status(42);
        set.insert_signal(SIGTERM);
        assert!(!set.is_empty());
        assert!(!exit_status_set_is_empty(Some(&set)));

        exit_status_set_free(&mut set);
        assert!(set.is_empty());
        assert!(exit_status_set_is_empty(Some(&set)));
    }

    #[test]
    fn exit_status_set_test_matches_c_rules() {
        let mut set = ExitStatusSet::new();
        set.insert_status(42);
        set.insert_signal(SIGTERM);

        assert!(exit_status_set_test(&set, CLD_EXITED, 42));
        assert!(!exit_status_set_test(&set, CLD_EXITED, 43));
        assert!(exit_status_set_test(&set, CLD_KILLED, SIGTERM));
        assert!(exit_status_set_test(&set, CLD_DUMPED, SIGTERM));
        assert!(!exit_status_set_test(&set, CLD_KILLED, SIGINT));
        assert!(!exit_status_set_test(&set, 0, 42));
        assert!(set.test(CLD_EXITED, 42));
        assert!(set.test(CLD_DUMPED, SIGTERM));
    }

    #[test]
    fn is_clean_exit_matches_c_rules() {
        let mut success = ExitStatusSet::new();
        success.insert_status(42);
        success.insert_signal(9);
        success.insert_signal(SIGTERM);

        assert!(is_clean_exit(CLD_EXITED, 0, ExitClean::Daemon, None));
        assert!(is_clean_exit(
            CLD_EXITED,
            42,
            ExitClean::Command,
            Some(&success)
        ));
        assert!(!is_clean_exit(
            CLD_EXITED,
            43,
            ExitClean::Daemon,
            Some(&success)
        ));

        for signal in [SIGHUP, SIGINT, SIGTERM, SIGPIPE] {
            assert!(is_clean_exit(CLD_KILLED, signal, ExitClean::Daemon, None));
            assert!(!is_clean_exit(CLD_KILLED, signal, ExitClean::Command, None));
        }

        assert!(is_clean_exit(
            CLD_KILLED,
            9,
            ExitClean::Command,
            Some(&success)
        ));
        assert!(!is_clean_exit(CLD_KILLED, 9, ExitClean::Command, None));
        assert!(!is_clean_exit(
            CLD_DUMPED,
            SIGTERM,
            ExitClean::Daemon,
            Some(&success)
        ));
        assert!(!is_clean_exit(0, 0, ExitClean::Daemon, Some(&success)));
    }

    #[test]
    fn every_named_mapping_round_trips_via_public_lookup_functions() {
        for status in ALL_EXIT_STATUSES {
            let code = status as i32;
            assert_eq!(
                exit_status_to_string(code, EXIT_STATUS_FULL),
                Some(status.name())
            );
            assert_eq!(exit_status_class(code), Some(status.class_name()));
            assert_eq!(exit_status_from_string(status.name()), Ok(code));
        }
    }
}
