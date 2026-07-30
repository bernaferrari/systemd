// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-common-errors.c, src/libsystemd/sd-bus/bus-common-errors.h

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusErrorMap {
    pub name: &'static str,
    pub errno: i32,
}

const fn error(name: &'static str, errno: i32) -> BusErrorMap {
    BusErrorMap { name, errno }
}

pub const BUS_COMMON_ERRORS: &[BusErrorMap] = &[
    error("org.freedesktop.systemd1.NoSuchUnit", libc::ENOENT),
    error("org.freedesktop.systemd1.NoSuchProcess", libc::ESRCH),
    error("org.freedesktop.systemd1.NoUnitForPID", libc::ESRCH),
    error(
        "org.freedesktop.systemd1.NoUnitForInvocationID",
        libc::ENOENT,
    ),
    error("org.freedesktop.systemd1.UnitExists", libc::EEXIST),
    error("org.freedesktop.systemd1.LoadFailed", libc::EIO),
    error("org.freedesktop.systemd1.BadUnitSetting", libc::ENOEXEC),
    error("org.freedesktop.systemd1.JobFailed", libc::EREMOTEIO),
    error("org.freedesktop.systemd1.NoSuchJob", libc::ENOENT),
    error("org.freedesktop.systemd1.NotSubscribed", libc::EINVAL),
    error("org.freedesktop.systemd1.AlreadySubscribed", libc::EINVAL),
    error("org.freedesktop.systemd1.OnlyByDependency", libc::EINVAL),
    error(
        "org.freedesktop.systemd1.TransactionJobsConflicting",
        libc::EDEADLK,
    ),
    error(
        "org.freedesktop.systemd1.TransactionOrderIsCyclic",
        libc::EDEADLK,
    ),
    error(
        "org.freedesktop.systemd1.TransactionIsDestructive",
        libc::EDEADLK,
    ),
    error("org.freedesktop.systemd1.UnitMasked", libc::ERFKILL),
    error(
        "org.freedesktop.systemd1.UnitGenerated",
        libc::EADDRNOTAVAIL,
    ),
    error("org.freedesktop.systemd1.UnitLinked", libc::ELOOP),
    error("org.freedesktop.systemd1.JobTypeNotApplicable", libc::EBADR),
    error(
        "org.freedesktop.systemd1.ConcurrencyLimitReached",
        libc::ETOOMANYREFS,
    ),
    error("org.freedesktop.systemd1.NoIsolation", libc::EPERM),
    error("org.freedesktop.systemd1.ShuttingDown", libc::ECANCELED),
    error("org.freedesktop.systemd1.ScopeNotRunning", libc::EHOSTDOWN),
    error("org.freedesktop.systemd1.NoSuchDynamicUser", libc::ESRCH),
    error("org.freedesktop.systemd1.NotReferenced", libc::EUNATCH),
    error("org.freedesktop.systemd1.UnitBusy", libc::EBUSY),
    error("org.freedesktop.systemd1.UnitInactive", libc::EHOSTDOWN),
    error("org.freedesktop.systemd1.FreezeCancelled", libc::ECANCELED),
    error(
        "org.freedesktop.systemd1.FileDescriptorStoreDisabled",
        libc::EHOSTDOWN,
    ),
    error("org.freedesktop.systemd1.FrozenByParent", libc::EDEADLK),
    error("org.freedesktop.machine1.NoSuchMachine", libc::ENXIO),
    error("org.freedesktop.machine1.NoSuchImage", libc::ENOENT),
    error("org.freedesktop.machine1.NoMachineForPID", libc::ENXIO),
    error("org.freedesktop.machine1.MachineExists", libc::EEXIST),
    error("org.freedesktop.machine1.NoPrivateNetworking", libc::ENOSYS),
    error("org.freedesktop.machine1.NoSuchUserMapping", libc::ENXIO),
    error("org.freedesktop.machine1.NoSuchGroupMapping", libc::ENXIO),
    error("org.freedesktop.portable1.NoSuchImage", libc::ENOENT),
    error("org.freedesktop.portable1.BadImageType", libc::EMEDIUMTYPE),
    error(
        "org.freedesktop.portable1.NoMatchingUnitFiles",
        libc::ENOENT,
    ),
    error("org.freedesktop.login1.NoSuchSession", libc::ENXIO),
    error("org.freedesktop.login1.NoSessionForPID", libc::ENXIO),
    error("org.freedesktop.login1.NoSuchUser", libc::ENXIO),
    error("org.freedesktop.login1.NoUserForPID", libc::ENXIO),
    error("org.freedesktop.login1.NoSuchSeat", libc::ENXIO),
    error("org.freedesktop.login1.SessionNotOnSeat", libc::EINVAL),
    error("org.freedesktop.login1.NotInControl", libc::EINVAL),
    error("org.freedesktop.login1.DeviceIsTaken", libc::EINVAL),
    error("org.freedesktop.login1.DeviceNotTaken", libc::EINVAL),
    error(
        "org.freedesktop.login1.OperationInProgress",
        libc::EINPROGRESS,
    ),
    error(
        "org.freedesktop.login1.SleepVerbNotSupported",
        libc::EOPNOTSUPP,
    ),
    error("org.freedesktop.login1.SessionBusy", libc::EBUSY),
    error("org.freedesktop.login1.NotYourDevice", libc::EPERM),
    error(
        "org.freedesktop.login1.DesignatedMaintenanceTimeNotScheduled",
        libc::EBADSLT,
    ),
    error(
        "org.freedesktop.login1.BlockedByInhibitorLock",
        libc::EACCES,
    ),
    error(
        "org.freedesktop.timedate1.AutomaticTimeSyncEnabled",
        libc::EALREADY,
    ),
    error("org.freedesktop.timedate1.NoNTPSupport", libc::EOPNOTSUPP),
    error("org.freedesktop.resolve1.NoNameServers", libc::ESRCH),
    error("org.freedesktop.resolve1.InvalidReply", libc::EINVAL),
    error("org.freedesktop.resolve1.NoSuchRR", libc::ENOENT),
    error("org.freedesktop.resolve1.CNameLoop", libc::EDEADLK),
    error("org.freedesktop.resolve1.Aborted", libc::ECANCELED),
    error("org.freedesktop.resolve1.NoSuchService", libc::EUNATCH),
    error(
        "org.freedesktop.resolve1.InconsistentServiceRecords",
        libc::EUNATCH,
    ),
    error("org.freedesktop.resolve1.DnssecFailed", libc::EHOSTUNREACH),
    error("org.freedesktop.resolve1.NoTrustAnchor", libc::EHOSTUNREACH),
    error(
        "org.freedesktop.resolve1.ResourceRecordTypeUnsupported",
        libc::EOPNOTSUPP,
    ),
    error("org.freedesktop.resolve1.NoSuchLink", libc::ENXIO),
    error("org.freedesktop.resolve1.LinkBusy", libc::EBUSY),
    error("org.freedesktop.resolve1.NetworkDown", libc::ENETDOWN),
    error("org.freedesktop.resolve1.NoSource", libc::ESRCH),
    error("org.freedesktop.resolve1.StubLoop", libc::ELOOP),
    error("org.freedesktop.resolve1.NoSuchDnssdService", libc::ENOENT),
    error("org.freedesktop.resolve1.DnssdServiceExists", libc::EEXIST),
    error("org.freedesktop.resolve1.NoSuchDelegate", libc::ENXIO),
    error("org.freedesktop.resolve1.DnsError.FORMERR", libc::EBADMSG),
    error(
        "org.freedesktop.resolve1.DnsError.SERVFAIL",
        libc::EHOSTDOWN,
    ),
    error("org.freedesktop.resolve1.DnsError.NXDOMAIN", libc::ENXIO),
    error("org.freedesktop.resolve1.DnsError.NOTIMP", libc::ENOSYS),
    error("org.freedesktop.resolve1.DnsError.REFUSED", libc::EACCES),
    error("org.freedesktop.resolve1.DnsError.YXDOMAIN", libc::EEXIST),
    error("org.freedesktop.resolve1.DnsError.YRRSET", libc::EEXIST),
    error("org.freedesktop.resolve1.DnsError.NXRRSET", libc::ENOENT),
    error("org.freedesktop.resolve1.DnsError.NOTAUTH", libc::EACCES),
    error("org.freedesktop.resolve1.DnsError.NOTZONE", libc::EREMOTE),
    error("org.freedesktop.resolve1.DnsError.BADVERS", libc::EBADMSG),
    error(
        "org.freedesktop.resolve1.DnsError.BADKEY",
        libc::EKEYREJECTED,
    ),
    error("org.freedesktop.resolve1.DnsError.BADTIME", libc::EBADMSG),
    error("org.freedesktop.resolve1.DnsError.BADMODE", libc::EBADMSG),
    error("org.freedesktop.resolve1.DnsError.BADNAME", libc::EBADMSG),
    error("org.freedesktop.resolve1.DnsError.BADALG", libc::EBADMSG),
    error("org.freedesktop.resolve1.DnsError.BADTRUNC", libc::EBADMSG),
    error("org.freedesktop.resolve1.DnsError.BADCOOKIE", libc::EBADR),
    error("org.freedesktop.import1.NoSuchTransfer", libc::ENXIO),
    error("org.freedesktop.import1.TransferInProgress", libc::EBUSY),
    error("org.freedesktop.hostname1.NoProductUUID", libc::EOPNOTSUPP),
    error(
        "org.freedesktop.hostname1.NoHardwareSerial",
        libc::EOPNOTSUPP,
    ),
    error("org.freedesktop.hostname1.FieldNotSet", libc::ENODATA),
    error("org.freedesktop.hostname1.FileIsProtected", libc::EACCES),
    error("org.freedesktop.hostname1.ReadOnlyFilesystem", libc::EROFS),
    error(
        "org.freedesktop.network1.SpeedMeterInactive",
        libc::EOPNOTSUPP,
    ),
    error(
        "org.freedesktop.network1.UnmanagedInterface",
        libc::EOPNOTSUPP,
    ),
    error("org.freedesktop.network1.AlreadyReloading", libc::EBUSY),
    error("org.freedesktop.home1.NoSuchHome", libc::EEXIST),
    error("org.freedesktop.home1.UIDInUse", libc::EEXIST),
    error("org.freedesktop.home1.UserNameExists", libc::EEXIST),
    error("org.freedesktop.home1.HomeExists", libc::EEXIST),
    error("org.freedesktop.home1.HomeAlreadyActive", libc::EALREADY),
    error("org.freedesktop.home1.HomeAlreadyFixated", libc::EALREADY),
    error("org.freedesktop.home1.HomeUnfixated", libc::EADDRNOTAVAIL),
    error("org.freedesktop.home1.HomeNotActive", libc::EALREADY),
    error("org.freedesktop.home1.HomeAbsent", libc::EREMOTE),
    error("org.freedesktop.home1.HomeBusy", libc::EBUSY),
    error("org.freedesktop.home1.BadPassword", libc::ENOKEY),
    error("org.freedesktop.home1.LowPasswordQuality", libc::EUCLEAN),
    error("org.freedesktop.home1.BadPasswordAndNoToken", libc::EBADSLT),
    error("org.freedesktop.home1.TokenPinNeeded", libc::ENOANO),
    error(
        "org.freedesktop.home1.TokenProtectedAuthenticationPathNeeded",
        libc::ERFKILL,
    ),
    error(
        "org.freedesktop.home1.TokenUserPresenceNeeded",
        libc::EMEDIUMTYPE,
    ),
    error(
        "org.freedesktop.home1.TokenUserVerificationNeeded",
        libc::ENOCSI,
    ),
    error("org.freedesktop.home1.TokenActionTimeout", libc::ENOSTR),
    error("org.freedesktop.home1.TokenPinLocked", libc::EOWNERDEAD),
    error("org.freedesktop.home1.BadPin", libc::ENOLCK),
    error(
        "org.freedesktop.home1.BadPinFewTriesLeft",
        libc::ETOOMANYREFS,
    ),
    error("org.freedesktop.home1.BadPinOneTryLeft", libc::EUCLEAN),
    error("org.freedesktop.home1.BadSignature", libc::EKEYREJECTED),
    error("org.freedesktop.home1.RecordMismatch", libc::EUCLEAN),
    error("org.freedesktop.home1.RecordDowngrade", libc::ESTALE),
    error("org.freedesktop.home1.RecordSigned", libc::EROFS),
    error("org.freedesktop.home1.BadHomeSize", libc::ERANGE),
    error("org.freedesktop.home1.NoPrivateKey", libc::ENOPKG),
    error("org.freedesktop.home1.HomeLocked", libc::ENOEXEC),
    error("org.freedesktop.home1.HomeNotLocked", libc::ENOEXEC),
    error("org.freedesktop.home1.TooManyOperations", libc::ENOBUFS),
    error(
        "org.freedesktop.home1.AuthenticationLimitHit",
        libc::ETOOMANYREFS,
    ),
    error(
        "org.freedesktop.home1.HomeCantAuthenticate",
        libc::EKEYREVOKED,
    ),
    error("org.freedesktop.home1.HomeInUse", libc::EADDRINUSE),
    error("org.freedesktop.home1.RebalanceNotNeeded", libc::EALREADY),
    error("org.freedesktop.home1.HomeNotReferenced", libc::EBADR),
    error("org.freedesktop.home1.NoSuchKey", libc::ENOKEY),
    error(
        "org.freedesktop.home1.UnrecognizedHomeFormat",
        libc::EMEDIUMTYPE,
    ),
    error("org.freedesktop.sysupdate1.NoCandidate", libc::EALREADY),
];

pub fn common_error_to_errno(name: &str) -> Result<i32, i32> {
    BUS_COMMON_ERRORS
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.errno)
        .ok_or(-5)
}

pub fn errno_to_common_error(errno: i32) -> Option<&'static str> {
    let normalized = errno.abs();
    BUS_COMMON_ERRORS
        .iter()
        .find(|entry| entry.errno == normalized)
        .map(|entry| entry.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_no_such_unit() {
        assert_eq!(
            common_error_to_errno("org.freedesktop.systemd1.NoSuchUnit"),
            Ok(libc::ENOENT)
        );
    }

    #[test]
    fn resolves_bad_password() {
        assert_eq!(
            common_error_to_errno("org.freedesktop.home1.BadPassword"),
            Ok(libc::ENOKEY)
        );
    }

    #[test]
    fn returns_eio_for_unknown_name() {
        assert_eq!(common_error_to_errno("missing.error"), Err(-libc::EIO));
    }

    #[test]
    fn resolves_errno_to_first_matching_name() {
        assert_eq!(
            errno_to_common_error(libc::EEXIST),
            Some("org.freedesktop.systemd1.UnitExists")
        );
    }

    #[test]
    fn accepts_negative_errno() {
        assert_eq!(
            errno_to_common_error(-libc::ENETDOWN),
            Some("org.freedesktop.resolve1.NetworkDown")
        );
    }

    #[test]
    fn unknown_errno_returns_none() {
        assert_eq!(errno_to_common_error(9999), None);
    }

    #[test]
    fn map_contains_sysupdate_entry() {
        assert!(
            BUS_COMMON_ERRORS
                .iter()
                .any(|entry| entry.name == "org.freedesktop.sysupdate1.NoCandidate")
        );
    }

    #[test]
    fn map_contains_resolve_service_entry() {
        assert!(BUS_COMMON_ERRORS.iter().any(|entry| entry.name
            == "org.freedesktop.resolve1.NoSuchService"
            && entry.errno == libc::EUNATCH));
    }

    #[test]
    fn map_contains_portable_no_matching_unit_files_entry() {
        assert!(BUS_COMMON_ERRORS.iter().any(|entry| entry.name
            == "org.freedesktop.portable1.NoMatchingUnitFiles"
            && entry.errno == libc::ENOENT));
    }

    #[test]
    fn map_contains_home_locked_entry() {
        assert!(
            BUS_COMMON_ERRORS
                .iter()
                .any(|entry| entry.name == "org.freedesktop.home1.HomeLocked"
                    && entry.errno == libc::ENOEXEC)
        );
    }

    #[test]
    fn includes_every_current_c_mapping() {
        assert_eq!(BUS_COMMON_ERRORS.len(), 142);
        assert_eq!(
            common_error_to_errno("org.freedesktop.resolve1.DnsError.BADKEY"),
            Ok(libc::EKEYREJECTED)
        );
        assert_eq!(
            common_error_to_errno("org.freedesktop.login1.BlockedByInhibitorLock"),
            Ok(libc::EACCES)
        );
    }
}
