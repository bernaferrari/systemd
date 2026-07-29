// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/seccomp-util.c, src/shared/seccomp-util.h

mod architecture;
mod filter_set;
mod model;
mod parsing;
mod syscall_lists;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub use architecture::reset_seccomp_available_cache;
pub use architecture::{
    arch_has_sysctl, arch_is_s390, arch_supports_socket_filter, foreach_local_arch,
    is_seccomp_available, seccomp_arch_from_string, seccomp_arch_to_string, seccomp_local_archs,
    sync_syscall_needs_fd_check,
};
pub use filter_set::{expand_filter_set, filter_set_add_logic, syscall_filter_set_find};
pub use model::{
    ParsedSyscallEntry, Result, SCMP_ACT_ALLOW, SCMP_ACT_ERRNO_BASE, SCMP_ACT_KILL_PROCESS,
    SCMP_ACT_KILL_THREAD, SCMP_ACT_LOG, SCMP_ACT_TRACE, SCMP_ACT_TRAP, SCMP_ARCH_AARCH64,
    SCMP_ARCH_ARM, SCMP_ARCH_LOONGARCH64, SCMP_ARCH_MIPS, SCMP_ARCH_MIPS64, SCMP_ARCH_MIPS64N32,
    SCMP_ARCH_MIPSEL, SCMP_ARCH_MIPSEL64, SCMP_ARCH_MIPSEL64N32, SCMP_ARCH_NATIVE,
    SCMP_ARCH_PARISC, SCMP_ARCH_PARISC64, SCMP_ARCH_PPC, SCMP_ARCH_PPC64, SCMP_ARCH_PPC64LE,
    SCMP_ARCH_RISCV64, SCMP_ARCH_S390, SCMP_ARCH_S390X, SCMP_ARCH_X32, SCMP_ARCH_X86,
    SCMP_ARCH_X86_64, SCMP_CMP_EQ, SCMP_CMP_GE, SCMP_CMP_GT, SCMP_CMP_LE, SCMP_CMP_LT,
    SCMP_CMP_MASKED_EQ, SCMP_CMP_NE, SCMP_FLTATR_ACT_BADARCH, SCMP_FLTATR_ACT_DEFAULT,
    SCMP_FLTATR_CTL_LOG, SCMP_FLTATR_CTL_NNP, SCMP_FLTATR_CTL_OPTIMIZE, SCMP_FLTATR_CTL_TSYNC,
    SECCOMP_ERROR_NUMBER_KILL, SECCOMP_LOCAL_ARCH_BLOCKED, SECCOMP_LOCAL_ARCH_END, SeccompError,
    SeccompParseFlags, SyscallFilterOperation, SyscallFilterSet, scmp_act_errno,
};
pub use parsing::{
    build_syscall_filter_map, errno_is_seccomp_fatal, override_default_action,
    parse_syscall_and_errno, parse_syscall_and_errno_owned, parse_syscall_archs,
    seccomp_errno_or_action_is_valid, seccomp_errno_or_action_to_string,
    seccomp_parse_errno_or_action, seccomp_parse_syscall_filter_spec,
};
