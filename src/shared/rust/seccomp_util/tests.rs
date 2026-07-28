// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::HashSet;

use crate::Errno;

use super::{
    ParsedSyscallEntry, SCMP_ACT_ALLOW, SCMP_ACT_ERRNO_BASE, SCMP_ACT_KILL_PROCESS, SCMP_ACT_LOG,
    SCMP_ACT_TRAP, SCMP_ARCH_AARCH64, SCMP_ARCH_ARM, SCMP_ARCH_LOONGARCH64, SCMP_ARCH_MIPS,
    SCMP_ARCH_MIPS64, SCMP_ARCH_MIPS64N32, SCMP_ARCH_MIPSEL, SCMP_ARCH_MIPSEL64,
    SCMP_ARCH_MIPSEL64N32, SCMP_ARCH_NATIVE, SCMP_ARCH_PARISC, SCMP_ARCH_PARISC64, SCMP_ARCH_PPC,
    SCMP_ARCH_PPC64, SCMP_ARCH_PPC64LE, SCMP_ARCH_RISCV64, SCMP_ARCH_S390, SCMP_ARCH_S390X,
    SCMP_ARCH_X32, SCMP_ARCH_X86, SCMP_ARCH_X86_64, SECCOMP_ERROR_NUMBER_KILL,
    SECCOMP_LOCAL_ARCH_BLOCKED, SECCOMP_LOCAL_ARCH_END, SeccompParseFlags, SyscallFilterOperation,
    SyscallFilterSet, arch_has_sysctl, arch_supports_socket_filter, build_syscall_filter_map,
    errno_is_seccomp_fatal, expand_filter_set, filter_set_add_logic, foreach_local_arch,
    override_default_action, parse_syscall_and_errno, parse_syscall_archs, scmp_act_errno,
    seccomp_arch_from_string, seccomp_arch_to_string, seccomp_errno_or_action_is_valid,
    seccomp_errno_or_action_to_string, seccomp_parse_errno_or_action,
    seccomp_parse_syscall_filter_spec, sync_syscall_needs_fd_check, syscall_filter_set_find,
};

#[test]
fn test_arch_roundtrip_string() {
    let cases: &[(&str, u32)] = &[
        ("native", SCMP_ARCH_NATIVE),
        ("x86", SCMP_ARCH_X86),
        ("x86-64", SCMP_ARCH_X86_64),
        ("x32", SCMP_ARCH_X32),
        ("arm", SCMP_ARCH_ARM),
        ("arm64", SCMP_ARCH_AARCH64),
        ("loongarch64", SCMP_ARCH_LOONGARCH64),
        ("mips", SCMP_ARCH_MIPS),
        ("mips64", SCMP_ARCH_MIPS64),
        ("mips64-n32", SCMP_ARCH_MIPS64N32),
        ("mips-le", SCMP_ARCH_MIPSEL),
        ("mips64-le", SCMP_ARCH_MIPSEL64),
        ("mips64-le-n32", SCMP_ARCH_MIPSEL64N32),
        ("parisc", SCMP_ARCH_PARISC),
        ("parisc64", SCMP_ARCH_PARISC64),
        ("ppc", SCMP_ARCH_PPC),
        ("ppc64", SCMP_ARCH_PPC64),
        ("ppc64-le", SCMP_ARCH_PPC64LE),
        ("riscv64", SCMP_ARCH_RISCV64),
        ("s390", SCMP_ARCH_S390),
        ("s390x", SCMP_ARCH_S390X),
    ];

    for &(name, code) in cases {
        assert_eq!(
            seccomp_arch_to_string(code),
            Some(name),
            "arch code {:#010X} should map to {:?}",
            code,
            name
        );
        assert_eq!(
            seccomp_arch_from_string(name),
            Ok(code),
            "{:?} should map to arch code {:#010X}",
            name,
            code
        );
    }
}

#[test]
fn test_arch_from_string_invalid() {
    assert_eq!(seccomp_arch_from_string("bogus"), Err(Errno::EINVAL));
    assert_eq!(seccomp_arch_from_string(""), Err(Errno::EINVAL));
    assert_eq!(
        seccomp_arch_from_string("X86"), // case-sensitive
        Err(Errno::EINVAL)
    );
}

#[test]
fn test_arch_to_string_unknown() {
    assert_eq!(seccomp_arch_to_string(0xDEADBEEF), None);
    assert_eq!(seccomp_arch_to_string(u32::MAX), None);
    assert_eq!(seccomp_arch_to_string(1), None);
}

#[test]
fn test_syscall_filter_set_find() {
    assert_eq!(
        syscall_filter_set_find("@default"),
        Some(SyscallFilterSet::Default)
    );
    assert_eq!(syscall_filter_set_find("@aio"), Some(SyscallFilterSet::Aio));
    assert_eq!(
        syscall_filter_set_find("@sandbox"),
        Some(SyscallFilterSet::Sandbox)
    );
    assert_eq!(
        syscall_filter_set_find("@known"),
        Some(SyscallFilterSet::Known)
    );
    assert_eq!(syscall_filter_set_find("@nonexistent"), None);
    assert_eq!(syscall_filter_set_find("default"), None); // no @
    assert_eq!(syscall_filter_set_find(""), None);
}

#[test]
fn test_syscall_filter_set_names() {
    assert_eq!(SyscallFilterSet::Default.name(), "@default");
    assert_eq!(SyscallFilterSet::Aio.name(), "@aio");
    assert_eq!(SyscallFilterSet::Known.name(), "@known");
    assert_eq!(SyscallFilterSet::SystemService.name(), "@system-service");
}

#[test]
fn test_syscall_filter_set_help() {
    assert!(!SyscallFilterSet::Default.help().is_empty());
    assert!(!SyscallFilterSet::Known.help().is_empty());
    assert_eq!(SyscallFilterSet::Aio.help(), "Asynchronous IO");
}

#[test]
fn test_syscall_filter_set_syscalls_nonempty() {
    for set in SyscallFilterSet::all() {
        assert!(
            !set.syscalls().is_empty(),
            "set {:?} should have syscalls",
            set.name()
        );
    }
}

#[test]
fn test_syscall_filter_set_default_starts_with_sandbox() {
    let syscalls = SyscallFilterSet::Default.syscalls();
    assert_eq!(syscalls[0], "@sandbox");
}

#[test]
fn test_syscall_filter_set_known_starts_with_obsolete() {
    let syscalls = SyscallFilterSet::Known.syscalls();
    assert_eq!(syscalls[0], "@obsolete");
}

#[test]
fn test_syscall_filter_set_all_count() {
    let all: Vec<_> = SyscallFilterSet::all().collect();
    assert_eq!(all.len(), SyscallFilterSet::MAX);
    assert_eq!(all[0], SyscallFilterSet::Default);
    assert_eq!(all[all.len() - 1], SyscallFilterSet::Known);
}

#[test]
fn test_syscall_filter_set_privileged_contains_chown_ref() {
    let syscalls = SyscallFilterSet::Privileged.syscalls();
    assert!(syscalls.contains(&"@chown"));
    assert!(syscalls.contains(&"@module"));
    assert!(syscalls.contains(&"bpf"));
}

#[test]
fn test_seccomp_parse_errno_or_action() {
    assert_eq!(
        seccomp_parse_errno_or_action("kill"),
        Ok(SECCOMP_ERROR_NUMBER_KILL)
    );
    assert_eq!(seccomp_parse_errno_or_action("0"), Err(Errno::EINVAL));
    assert_eq!(seccomp_parse_errno_or_action("1"), Ok(1));
    assert_eq!(seccomp_parse_errno_or_action("EINVAL"), Ok(libc::EINVAL));
    assert_eq!(seccomp_parse_errno_or_action("22"), Ok(22));
    assert_eq!(seccomp_parse_errno_or_action("4095"), Ok(4095));
    assert_eq!(seccomp_parse_errno_or_action("4096"), Err(Errno::EINVAL));
    assert_eq!(seccomp_parse_errno_or_action("-1"), Err(Errno::EINVAL));
    assert_eq!(seccomp_parse_errno_or_action("abc"), Err(Errno::EINVAL));
}

#[test]
fn test_seccomp_errno_or_action_to_string() {
    assert_eq!(
        seccomp_errno_or_action_to_string(SECCOMP_ERROR_NUMBER_KILL),
        "kill"
    );
    assert_eq!(seccomp_errno_or_action_to_string(0), "errno");
    assert_eq!(seccomp_errno_or_action_to_string(22), "EINVAL");
    assert_eq!(seccomp_errno_or_action_to_string(EPERM), "EPERM");
}

#[test]
fn test_seccomp_errno_or_action_is_valid() {
    assert!(seccomp_errno_or_action_is_valid(SECCOMP_ERROR_NUMBER_KILL));
    assert!(!seccomp_errno_or_action_is_valid(0));
    assert!(seccomp_errno_or_action_is_valid(1));
    assert!(seccomp_errno_or_action_is_valid(4095));
    assert!(!seccomp_errno_or_action_is_valid(-1));
    assert!(!seccomp_errno_or_action_is_valid(4096));
    assert!(!seccomp_errno_or_action_is_valid(i32::MIN));
}

#[test]
fn test_override_default_action() {
    // ALLOW and LOG pass through
    assert_eq!(override_default_action(SCMP_ACT_ALLOW), SCMP_ACT_ALLOW);
    assert_eq!(override_default_action(SCMP_ACT_LOG), SCMP_ACT_LOG);
    // Everything else becomes ENOSYS
    let expected = scmp_act_errno(libc::ENOSYS as u32);
    assert_eq!(override_default_action(SCMP_ACT_KILL_PROCESS), expected);
    assert_eq!(override_default_action(SCMP_ACT_TRAP), expected);
    assert_eq!(
        override_default_action(scmp_act_errno(libc::EPERM as u32)),
        expected
    );
}

#[test]
fn test_errno_is_seccomp_fatal() {
    assert!(errno_is_seccomp_fatal(-libc::EPERM));
    assert!(errno_is_seccomp_fatal(-libc::EACCES));
    assert!(errno_is_seccomp_fatal(-libc::ENOMEM));
    assert!(errno_is_seccomp_fatal(-libc::EFAULT));
    assert!(!errno_is_seccomp_fatal(-libc::EINVAL));
    assert!(!errno_is_seccomp_fatal(-libc::EDOM));
    assert!(!errno_is_seccomp_fatal(0));
    assert!(!errno_is_seccomp_fatal(1));
}

#[test]
fn test_parse_syscall_and_errno() {
    // Simple name, no errno
    let (name, errno) = parse_syscall_and_errno("uname").unwrap();
    assert_eq!(name, "uname");
    assert_eq!(errno, -1);

    // Name with errno
    let (name, errno) = parse_syscall_and_errno("uname:22").unwrap();
    assert_eq!(name, "uname");
    assert_eq!(errno, 22);

    // Set reference with errno
    let (name, errno) = parse_syscall_and_errno("@sync:0").unwrap();
    assert_eq!(name, "@sync");
    assert_eq!(errno, 0);

    // Set reference with kill
    let (name, errno) = parse_syscall_and_errno("@sync:kill").unwrap();
    assert_eq!(name, "@sync");
    assert_eq!(errno, SECCOMP_ERROR_NUMBER_KILL);
}

#[test]
fn test_parse_syscall_and_errno_errors() {
    // Empty input
    assert!(parse_syscall_and_errno("").is_err());

    // Empty name before colon
    assert!(parse_syscall_and_errno(":22").is_err());

    // Invalid errno
    assert!(parse_syscall_and_errno("foo:-1").is_err());
    assert!(parse_syscall_and_errno("foo:abc").is_err());
    assert!(parse_syscall_and_errno("foo:4096").is_err());
}

#[test]
fn test_parse_syscall_archs() {
    let archs = parse_syscall_archs(&["x86-64", "arm", "x86"]).unwrap();
    assert_eq!(archs.len(), 3);
    assert!(archs.contains(&SCMP_ARCH_X86_64));
    assert!(archs.contains(&SCMP_ARCH_ARM));
    assert!(archs.contains(&SCMP_ARCH_X86));

    // Duplicate should still appear (HashSet deduplicates)
    let archs2 = parse_syscall_archs(&["x86-64", "x86-64"]).unwrap();
    assert_eq!(archs2.len(), 1);

    // Unknown arch
    assert!(parse_syscall_archs(&["bogus"]).is_err());
}

#[test]
fn test_scmp_act_errno() {
    assert_eq!(scmp_act_errno(0), SCMP_ACT_ERRNO_BASE);
    assert_eq!(scmp_act_errno(22), SCMP_ACT_ERRNO_BASE | 22);
    assert_eq!(scmp_act_errno(4095), SCMP_ACT_ERRNO_BASE | 4095);
    // High bits should be masked
    assert_eq!(scmp_act_errno(0x1FFFF), SCMP_ACT_ERRNO_BASE | 0xFFFF);
}

#[test]
fn test_seccomp_parse_flags() {
    let f = SeccompParseFlags::INVERT | SeccompParseFlags::LOG;
    assert!(SeccompParseFlags::is_set(
        f.bits(),
        SeccompParseFlags::INVERT
    ));
    assert!(SeccompParseFlags::is_set(f.bits(), SeccompParseFlags::LOG));
    assert!(!SeccompParseFlags::is_set(
        f.bits(),
        SeccompParseFlags::PERMISSIVE
    ));
}

#[test]
fn test_expand_filter_set_default() {
    let expanded = expand_filter_set(SyscallFilterSet::Default);
    // Should contain individual syscalls (not @sandbox reference)
    assert!(expanded.contains(&"execve"));
    assert!(expanded.contains(&"exit"));
    assert!(expanded.contains(&"mmap"));
    // Should contain syscalls from @sandbox expansion
    assert!(expanded.contains(&"seccomp"));
    assert!(expanded.contains(&"landlock_create_ruleset"));
    // Should not contain @-references
    assert!(!expanded.iter().any(|s| s.starts_with('@')));
}

#[test]
fn test_expand_filter_set_no_duplicates() {
    let expanded = expand_filter_set(SyscallFilterSet::Default);
    let unique: HashSet<_> = expanded.iter().collect();
    assert_eq!(unique.len(), expanded.len());
}

#[test]
fn test_sync_syscall_needs_fd_check() {
    assert!(sync_syscall_needs_fd_check("fdatasync"));
    assert!(sync_syscall_needs_fd_check("fsync"));
    assert!(sync_syscall_needs_fd_check("sync_file_range"));
    assert!(sync_syscall_needs_fd_check("sync_file_range2"));
    assert!(sync_syscall_needs_fd_check("syncfs"));
    assert!(!sync_syscall_needs_fd_check("sync"));
    assert!(!sync_syscall_needs_fd_check("msync"));
}

#[test]
fn test_arch_supports_socket_filter() {
    assert!(arch_supports_socket_filter(SCMP_ARCH_X86_64));
    assert!(arch_supports_socket_filter(SCMP_ARCH_AARCH64));
    assert!(arch_supports_socket_filter(SCMP_ARCH_LOONGARCH64));
    assert!(arch_supports_socket_filter(SCMP_ARCH_RISCV64));
    assert!(!arch_supports_socket_filter(SCMP_ARCH_X86));
    assert!(!arch_supports_socket_filter(SCMP_ARCH_S390));
    assert!(!arch_supports_socket_filter(SCMP_ARCH_PARISC));
}

#[test]
fn test_arch_has_sysctl() {
    assert!(arch_has_sysctl(SCMP_ARCH_X86));
    assert!(arch_has_sysctl(SCMP_ARCH_X86_64));
    assert!(!arch_has_sysctl(SCMP_ARCH_AARCH64));
    assert!(!arch_has_sysctl(SCMP_ARCH_LOONGARCH64));
    assert!(!arch_has_sysctl(SCMP_ARCH_X32));
    assert!(!arch_has_sysctl(SCMP_ARCH_RISCV64));
}

#[test]
fn test_foreach_local_arch() {
    let archs = foreach_local_arch();
    // Should have at least one arch (or be empty on unknown targets)
    // The important thing is no SECCOMP_LOCAL_ARCH_END or BLOCKED
    assert!(!archs.contains(&SECCOMP_LOCAL_ARCH_END));
    assert!(!archs.contains(&SECCOMP_LOCAL_ARCH_BLOCKED));
}

#[test]
fn test_seccomp_constants() {
    assert_eq!(SCMP_ACT_ALLOW, 0x7fff0000);
    assert_eq!(SCMP_ACT_KILL_PROCESS, 0x80000000);
    assert_eq!(SCMP_ACT_LOG, 0x7ffc0000);
    assert_eq!(SCMP_ARCH_NATIVE, 0);
    assert_eq!(SCMP_ARCH_X32, 0x4000003e);
    assert_eq!(SCMP_ARCH_LOONGARCH64, 0xc0000102);
    assert_eq!(SCMP_ARCH_PARISC, 0x0000000f);
    assert_eq!(SCMP_ARCH_PARISC64, 0x8000000f);
    assert_eq!(SCMP_ARCH_PPC, 0x00000014);
    assert_eq!(SCMP_ARCH_S390, 0x00000016);
    assert_eq!(super::SCMP_FLTATR_ACT_DEFAULT, 1);
    assert_eq!(super::SCMP_FLTATR_ACT_BADARCH, 2);
    assert_eq!(super::SCMP_FLTATR_CTL_NNP, 3);
    assert_eq!(super::SCMP_FLTATR_CTL_TSYNC, 4);
    assert_eq!(super::SCMP_FLTATR_CTL_LOG, 6);
    assert_eq!(super::SCMP_FLTATR_CTL_OPTIMIZE, 8);
    assert_eq!(super::SCMP_CMP_NE, 1);
    assert_eq!(super::SCMP_CMP_LT, 2);
    assert_eq!(super::SCMP_CMP_LE, 3);
    assert_eq!(super::SCMP_CMP_EQ, 4);
    assert_eq!(super::SCMP_CMP_GE, 5);
    assert_eq!(super::SCMP_CMP_GT, 6);
    assert_eq!(super::SCMP_CMP_MASKED_EQ, 7);
    assert_eq!(SECCOMP_LOCAL_ARCH_END, u32::MAX);
    assert_eq!(SECCOMP_LOCAL_ARCH_BLOCKED, 0);
    assert_eq!(SECCOMP_ERROR_NUMBER_KILL, i32::MAX - 1);
}

#[test]
fn test_seccomp_parse_syscall_filter_spec() {
    // Individual syscalls
    let entries =
        seccomp_parse_syscall_filter_spec(&["read", "write", "open"], SeccompParseFlags::empty())
            .unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].name, "read");

    // Set reference
    let entries =
        seccomp_parse_syscall_filter_spec(&["@swap"], SeccompParseFlags::empty()).unwrap();
    assert!(!entries.is_empty());
    assert!(entries.iter().any(|e| e.name == "swapoff"));
    assert!(entries.iter().any(|e| e.name == "swapon"));

    // Unknown set without permissive
    assert!(seccomp_parse_syscall_filter_spec(&["@bogus"], SeccompParseFlags::empty()).is_err());

    // Unknown set with permissive
    let entries =
        seccomp_parse_syscall_filter_spec(&["@bogus", "read"], SeccompParseFlags::PERMISSIVE)
            .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "read");
}

#[test]
fn test_build_syscall_filter_map() {
    let entries = vec![
        ParsedSyscallEntry {
            name: "read".to_owned(),
            errno: -1,
        },
        ParsedSyscallEntry {
            name: "write".to_owned(),
            errno: 22,
        },
    ];
    let map = build_syscall_filter_map(&entries, SeccompParseFlags::empty()).unwrap();
    assert_eq!(map.len(), 2);
    assert_eq!(map.get("read"), Some(&-1));
    assert_eq!(map.get("write"), Some(&22));
}

#[test]
fn test_filter_set_add_logic() {
    // Add mode
    let map = filter_set_add_logic(SyscallFilterSet::Swap, true);
    assert!(!map.is_empty());
    assert!(
        map.values()
            .all(|operation| *operation == SyscallFilterOperation::Insert(-1))
    );

    // Remove mode
    let map = filter_set_add_logic(SyscallFilterSet::Swap, false);
    assert!(!map.is_empty());
    assert!(
        map.values()
            .all(|operation| *operation == SyscallFilterOperation::Remove)
    );
}

// Use EPERM from libc for clarity
use libc::EPERM;
