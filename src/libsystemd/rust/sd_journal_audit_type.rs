// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/libsystemd/sd-journal/audit-type.c, src/libsystemd/sd-journal/test-audit-type.c

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -libc::EINVAL;

pub const AUDIT_GET: i32 = 1000;
pub const AUDIT_SET: i32 = 1001;
pub const AUDIT_LIST: i32 = 1002;
pub const AUDIT_ADD: i32 = 1003;
pub const AUDIT_DEL: i32 = 1004;
pub const AUDIT_USER: i32 = 1005;
pub const AUDIT_LOGIN: i32 = 1006;
pub const AUDIT_SIGNAL_INFO: i32 = 1010;
pub const AUDIT_ADD_RULE: i32 = 1011;
pub const AUDIT_DEL_RULE: i32 = 1012;
pub const AUDIT_TRIGGER: i32 = 1014;
pub const AUDIT_REPLACE: i32 = 1015;
pub const AUDIT_USER_AUTH: i32 = 1021;
pub const AUDIT_USER_ACCT: i32 = 1022;
pub const AUDIT_USER_MGMT: i32 = 1023;
pub const AUDIT_CRED_ACQ: i32 = 1024;
pub const AUDIT_CRED_DISP: i32 = 1025;
pub const AUDIT_USER_START: i32 = 1026;
pub const AUDIT_USER_END: i32 = 1027;
pub const AUDIT_USER_AVC: i32 = 1028;
pub const AUDIT_USER_CHAUTHTOK: i32 = 1029;
pub const AUDIT_USER_ERR: i32 = 1030;
pub const AUDIT_CRED_REFR: i32 = 1031;
pub const AUDIT_USYS_CONFIG: i32 = 1032;
pub const AUDIT_USER_LOGIN: i32 = 1033;
pub const AUDIT_USER_LOGOUT: i32 = 1034;
pub const AUDIT_USER_CMD: i32 = 1043;
pub const AUDIT_USER_TTY: i32 = 1044;
pub const AUDIT_KERNEL: i32 = 2000;
pub const AUDIT_KERNEL_OTHER: i32 = 2001;
pub const AUDIT_SECCOMP: i32 = 2002;
pub const AUDIT_PROCTITLE: i32 = 2003;
pub const AUDIT_ARCH: i32 = 2004;
pub const AUDIT_NETFILTER_PKT: i32 = 2005;
pub const AUDIT_NETFILTER_CFG: i32 = 2006;
pub const AUDIT_SECCOMP_ACTION: i32 = 2007;
pub const AUDIT_AVC: i32 = 1400;
pub const AUDIT_SELINUX_ERR: i32 = 1401;
pub const AUDIT_AVC_PATH: i32 = 1402;
pub const AUDIT_MAC_POLICY_LOAD: i32 = 1403;
pub const AUDIT_MAC_STATUS: i32 = 1404;
pub const AUDIT_FIRST_DAEMON: i32 = 1100;
pub const AUDIT_DAEMON_START: i32 = 1100;
pub const AUDIT_DAEMON_END: i32 = 1101;
pub const AUDIT_DAEMON_ABORT: i32 = 1102;
pub const AUDIT_DAEMON_CONFIG: i32 = 1103;
pub const AUDIT_DAEMON_RECONFIG: i32 = 1104;
pub const AUDIT_DAEMON_ACCEPT: i32 = 1105;
pub const AUDIT_DAEMON_CLOSE: i32 = 1106;
pub const AUDIT_DAEMON_ROTATE: i32 = 1107;
pub const AUDIT_DAEMON_RESUME: i32 = 1108;
pub const AUDIT_SYSCALL: i32 = 1300;
pub const AUDIT_PATH: i32 = 1302;
pub const AUDIT_IPC: i32 = 1303;
pub const AUDIT_SOCKETCALL: i32 = 1304;
pub const AUDIT_CONFIG_CHANGE: i32 = 1305;
pub const AUDIT_SOCKADDR: i32 = 1306;
pub const AUDIT_CWD: i32 = 1307;
pub const AUDIT_EXECVE: i32 = 1309;
pub const AUDIT_IPC_SET_PERM: i32 = 1311;
pub const AUDIT_MQ_OPEN: i32 = 1312;
pub const AUDIT_MQ_SENDRECV: i32 = 1313;
pub const AUDIT_MQ_NOTIFY: i32 = 1314;
pub const AUDIT_MQ_GETSETATTR: i32 = 1315;
pub const AUDIT_FS_INODE: i32 = 1319;
pub const AUDIT_EXECVE_WITH_ENV: i32 = 1320;
pub const AUDIT_BPRM_FCAPS: i32 = 1321;
pub const AUDIT_CAPSET: i32 = 1322;
pub const AUDIT_MMAP: i32 = 1323;
pub const AUDIT_FEATURE_CHANGE: i32 = 1326;
pub const AUDIT_KERN_MODULE: i32 = 1328;
pub const AUDIT_FANOTIFY: i32 = 1329;
pub const AUDIT_OPENAT2: i32 = 1330;
pub const AUDIT_FD_PAIR: i32 = 1333;
pub const AUDIT_OBJ_PID: i32 = 1334;
pub const AUDIT_ANOM_PROMISCUOUS: i32 = 1700;
pub const AUDIT_ANOM_ABEND: i32 = 1701;
pub const AUDIT_ANOM_LINK: i32 = 1702;
pub const AUDIT_INTEGRITY_DATA: i32 = 1800;
pub const AUDIT_INTEGRITY_METADATA: i32 = 1801;
pub const AUDIT_INTEGRITY_STATUS: i32 = 1802;
pub const AUDIT_INTEGRITY_HASH: i32 = 1803;
pub const AUDIT_INTEGRITY_PCR: i32 = 1804;
pub const AUDIT_INTEGRITY_RULE: i32 = 1805;
pub const AUDIT_INTEGRITY_EVM_XATTR: i32 = 1806;
pub const AUDIT_INTEGRITY_POLICY: i32 = 1807;
pub const AUDIT_CONTAINER_ID: i32 = 2010;

pub const AUDIT_TYPES: &[(i32, &str)] = &[
    (AUDIT_GET, "AUDIT_GET"),
    (AUDIT_SET, "AUDIT_SET"),
    (AUDIT_LIST, "AUDIT_LIST"),
    (AUDIT_ADD, "AUDIT_ADD"),
    (AUDIT_DEL, "AUDIT_DEL"),
    (AUDIT_USER, "AUDIT_USER"),
    (AUDIT_LOGIN, "AUDIT_LOGIN"),
    (AUDIT_SIGNAL_INFO, "AUDIT_SIGNAL_INFO"),
    (AUDIT_ADD_RULE, "AUDIT_ADD_RULE"),
    (AUDIT_DEL_RULE, "AUDIT_DEL_RULE"),
    (AUDIT_TRIGGER, "AUDIT_TRIGGER"),
    (AUDIT_REPLACE, "AUDIT_REPLACE"),
    (AUDIT_USER_AUTH, "AUDIT_USER_AUTH"),
    (AUDIT_USER_ACCT, "AUDIT_USER_ACCT"),
    (AUDIT_USER_MGMT, "AUDIT_USER_MGMT"),
    (AUDIT_CRED_ACQ, "AUDIT_CRED_ACQ"),
    (AUDIT_CRED_DISP, "AUDIT_CRED_DISP"),
    (AUDIT_USER_START, "AUDIT_USER_START"),
    (AUDIT_USER_END, "AUDIT_USER_END"),
    (AUDIT_USER_AVC, "AUDIT_USER_AVC"),
    (AUDIT_USER_CHAUTHTOK, "AUDIT_USER_CHAUTHTOK"),
    (AUDIT_USER_ERR, "AUDIT_USER_ERR"),
    (AUDIT_CRED_REFR, "AUDIT_CRED_REFR"),
    (AUDIT_USYS_CONFIG, "AUDIT_USYS_CONFIG"),
    (AUDIT_USER_LOGIN, "AUDIT_USER_LOGIN"),
    (AUDIT_USER_LOGOUT, "AUDIT_USER_LOGOUT"),
    (AUDIT_USER_CMD, "AUDIT_USER_CMD"),
    (AUDIT_USER_TTY, "AUDIT_USER_TTY"),
    (AUDIT_KERNEL, "AUDIT_KERNEL"),
    (AUDIT_KERNEL_OTHER, "AUDIT_KERNEL_OTHER"),
    (AUDIT_SECCOMP, "AUDIT_SECCOMP"),
    (AUDIT_PROCTITLE, "AUDIT_PROCTITLE"),
    (AUDIT_ARCH, "AUDIT_ARCH"),
    (AUDIT_NETFILTER_PKT, "AUDIT_NETFILTER_PKT"),
    (AUDIT_NETFILTER_CFG, "AUDIT_NETFILTER_CFG"),
    (AUDIT_SECCOMP_ACTION, "AUDIT_SECCOMP_ACTION"),
    (AUDIT_AVC, "AUDIT_AVC"),
    (AUDIT_SELINUX_ERR, "AUDIT_SELINUX_ERR"),
    (AUDIT_AVC_PATH, "AUDIT_AVC_PATH"),
    (AUDIT_MAC_POLICY_LOAD, "AUDIT_MAC_POLICY_LOAD"),
    (AUDIT_MAC_STATUS, "AUDIT_MAC_STATUS"),
    (AUDIT_DAEMON_START, "AUDIT_DAEMON_START"),
    (AUDIT_DAEMON_END, "AUDIT_DAEMON_END"),
    (AUDIT_DAEMON_ABORT, "AUDIT_DAEMON_ABORT"),
    (AUDIT_DAEMON_CONFIG, "AUDIT_DAEMON_CONFIG"),
    (AUDIT_DAEMON_RECONFIG, "AUDIT_DAEMON_RECONFIG"),
    (AUDIT_DAEMON_ACCEPT, "AUDIT_DAEMON_ACCEPT"),
    (AUDIT_DAEMON_CLOSE, "AUDIT_DAEMON_CLOSE"),
    (AUDIT_DAEMON_ROTATE, "AUDIT_DAEMON_ROTATE"),
    (AUDIT_DAEMON_RESUME, "AUDIT_DAEMON_RESUME"),
    (AUDIT_SYSCALL, "AUDIT_SYSCALL"),
    (AUDIT_PATH, "AUDIT_PATH"),
    (AUDIT_IPC, "AUDIT_IPC"),
    (AUDIT_SOCKETCALL, "AUDIT_SOCKETCALL"),
    (AUDIT_CONFIG_CHANGE, "AUDIT_CONFIG_CHANGE"),
    (AUDIT_SOCKADDR, "AUDIT_SOCKADDR"),
    (AUDIT_CWD, "AUDIT_CWD"),
    (AUDIT_EXECVE, "AUDIT_EXECVE"),
    (AUDIT_IPC_SET_PERM, "AUDIT_IPC_SET_PERM"),
    (AUDIT_MQ_OPEN, "AUDIT_MQ_OPEN"),
    (AUDIT_MQ_SENDRECV, "AUDIT_MQ_SENDRECV"),
    (AUDIT_MQ_NOTIFY, "AUDIT_MQ_NOTIFY"),
    (AUDIT_MQ_GETSETATTR, "AUDIT_MQ_GETSETATTR"),
    (AUDIT_FS_INODE, "AUDIT_FS_INODE"),
    (AUDIT_EXECVE_WITH_ENV, "AUDIT_EXECVE_WITH_ENV"),
    (AUDIT_BPRM_FCAPS, "AUDIT_BPRM_FCAPS"),
    (AUDIT_CAPSET, "AUDIT_CAPSET"),
    (AUDIT_MMAP, "AUDIT_MMAP"),
    (AUDIT_FEATURE_CHANGE, "AUDIT_FEATURE_CHANGE"),
    (AUDIT_KERN_MODULE, "AUDIT_KERN_MODULE"),
    (AUDIT_FANOTIFY, "AUDIT_FANOTIFY"),
    (AUDIT_OPENAT2, "AUDIT_OPENAT2"),
    (AUDIT_FD_PAIR, "AUDIT_FD_PAIR"),
    (AUDIT_OBJ_PID, "AUDIT_OBJ_PID"),
    (AUDIT_ANOM_PROMISCUOUS, "AUDIT_ANOM_PROMISCUOUS"),
    (AUDIT_ANOM_ABEND, "AUDIT_ANOM_ABEND"),
    (AUDIT_ANOM_LINK, "AUDIT_ANOM_LINK"),
    (AUDIT_INTEGRITY_DATA, "AUDIT_INTEGRITY_DATA"),
    (AUDIT_INTEGRITY_METADATA, "AUDIT_INTEGRITY_METADATA"),
    (AUDIT_INTEGRITY_STATUS, "AUDIT_INTEGRITY_STATUS"),
    (AUDIT_INTEGRITY_HASH, "AUDIT_INTEGRITY_HASH"),
    (AUDIT_INTEGRITY_PCR, "AUDIT_INTEGRITY_PCR"),
    (AUDIT_INTEGRITY_RULE, "AUDIT_INTEGRITY_RULE"),
    (AUDIT_INTEGRITY_EVM_XATTR, "AUDIT_INTEGRITY_EVM_XATTR"),
    (AUDIT_INTEGRITY_POLICY, "AUDIT_INTEGRITY_POLICY"),
    (AUDIT_CONTAINER_ID, "AUDIT_CONTAINER_ID"),
];

pub fn audit_type_to_string(audit_type: i32) -> Option<&'static str> {
    AUDIT_TYPES
        .iter()
        .find_map(|(value, name)| (*value == audit_type).then_some(*name))
}

pub fn audit_type_name_alloc(audit_type: i32) -> String {
    audit_type_to_string(audit_type)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("AUDIT{:04}", audit_type))
}

pub fn audit_type_to_string_result(audit_type: i32) -> Result<&'static str> {
    audit_type_to_string(audit_type).ok_or(NEG_EINVAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolves_known_type() {
        assert_eq!(audit_type_to_string(AUDIT_GET), Some("AUDIT_GET"));
    }
    #[test]
    fn resolves_kernel_type() {
        assert_eq!(audit_type_to_string(AUDIT_KERNEL), Some("AUDIT_KERNEL"));
    }
    #[test]
    fn resolves_integrity_type() {
        assert_eq!(
            audit_type_to_string(AUDIT_INTEGRITY_HASH),
            Some("AUDIT_INTEGRITY_HASH")
        );
    }
    #[test]
    fn rejects_unknown_type() {
        assert_eq!(audit_type_to_string(42), None);
    }
    #[test]
    fn produces_allocated_name_for_known_type() {
        assert_eq!(audit_type_name_alloc(AUDIT_EXECVE), "AUDIT_EXECVE");
    }
    #[test]
    fn produces_fallback_name_for_unknown_type() {
        assert_eq!(audit_type_name_alloc(42), "AUDIT0042");
    }
    #[test]
    fn result_api_uses_errno() {
        assert_eq!(audit_type_to_string_result(42), Err(NEG_EINVAL));
    }
    #[test]
    fn constants_remain_stable() {
        assert_eq!(AUDIT_GET, 1000);
        assert_eq!(AUDIT_SYSCALL, 1300);
        assert_eq!(AUDIT_AVC, 1400);
        assert_eq!(AUDIT_KERNEL, 2000);
    }
}
