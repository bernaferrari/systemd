/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C header inline functions vs Rust */
/* RUST-CONTRACT: cgroup-weight-validation */
/* RUST-CONTRACT: bfq-weight-scaling */
/* RUST-CONTRACT: file-size-validation */
/* RUST-CONTRACT: scalar-validator-predicates */
/* RUST-CONTRACT: pidref-state-predicates */
/* RUST-CONTRACT: allocation-overflow-predicate */
/* RUST-CONTRACT: allocation-roundup */
/* RUST-CONTRACT: file-offset-size-boundary */
/* RUST-CONTRACT: string-fallback-rendering */
/* RUST-CONTRACT: boolean-string-rendering */
/* RUST-CONTRACT: empty-string-normalization */
/* RUST-CONTRACT: empty-or-dash-predicate */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include "tests.h"
#include "cgroup-util.h"
#include "io-util.h"
#include "audit-util.h"
#include "errno-list.h"
#include "alloc-util.h"
#include "string-util.h"
#include "socket-util.h"
#include "process-util.h"
#include "fileio.h"
#include "rust/basic_validators.h"

static void test_CGROUP_WEIGHT_IS_OK(void) {
        assert_se(CGROUP_WEIGHT_IS_OK(0) == rs_CGROUP_WEIGHT_IS_OK(0));
        assert_se(CGROUP_WEIGHT_IS_OK(1) == rs_CGROUP_WEIGHT_IS_OK(1));
        assert_se(CGROUP_WEIGHT_IS_OK(100) == rs_CGROUP_WEIGHT_IS_OK(100));
        assert_se(CGROUP_WEIGHT_IS_OK(5000) == rs_CGROUP_WEIGHT_IS_OK(5000));
        assert_se(CGROUP_WEIGHT_IS_OK(10000) == rs_CGROUP_WEIGHT_IS_OK(10000));
        assert_se(CGROUP_WEIGHT_IS_OK(10001) == rs_CGROUP_WEIGHT_IS_OK(10001));
        assert_se(CGROUP_WEIGHT_IS_OK(UINT64_MAX) == rs_CGROUP_WEIGHT_IS_OK(UINT64_MAX));
}

static void test_BFQ_WEIGHT(void) {
        /* Test key points of the linear interpolation */
        assert_se(BFQ_WEIGHT(1) == rs_BFQ_WEIGHT(1));
        assert_se(BFQ_WEIGHT(100) == rs_BFQ_WEIGHT(100));
        assert_se(BFQ_WEIGHT(10000) == rs_BFQ_WEIGHT(10000));
        assert_se(BFQ_WEIGHT(5000) == rs_BFQ_WEIGHT(5000));
        assert_se(BFQ_WEIGHT(50) == rs_BFQ_WEIGHT(50));
        assert_se(BFQ_WEIGHT(200) == rs_BFQ_WEIGHT(200));
        assert_se(BFQ_WEIGHT(UINT64_MAX) == rs_BFQ_WEIGHT(UINT64_MAX));
}

static void test_FILE_SIZE_VALID(void) {
        assert_se(FILE_SIZE_VALID(0) == rs_FILE_SIZE_VALID(0));
        assert_se(FILE_SIZE_VALID(1) == rs_FILE_SIZE_VALID(1));
        assert_se(FILE_SIZE_VALID(UINT64_MAX / 2) == rs_FILE_SIZE_VALID(UINT64_MAX / 2));
        assert_se(FILE_SIZE_VALID((UINT64_C(1) << 63) - 1) == rs_FILE_SIZE_VALID((UINT64_C(1) << 63) - 1));
        assert_se(FILE_SIZE_VALID(UINT64_C(1) << 63) == rs_FILE_SIZE_VALID(UINT64_C(1) << 63));
        assert_se(FILE_SIZE_VALID(UINT64_MAX) == rs_FILE_SIZE_VALID(UINT64_MAX));
}

static void test_FILE_SIZE_VALID_OR_INFINITY(void) {
        assert_se(FILE_SIZE_VALID_OR_INFINITY(0) == rs_FILE_SIZE_VALID_OR_INFINITY(0));
        assert_se(FILE_SIZE_VALID_OR_INFINITY(UINT64_MAX) == rs_FILE_SIZE_VALID_OR_INFINITY(UINT64_MAX));
        assert_se(FILE_SIZE_VALID_OR_INFINITY(UINT64_C(1) << 63) == rs_FILE_SIZE_VALID_OR_INFINITY(UINT64_C(1) << 63));
}

static void test_audit_session_is_valid(void) {
        assert_se(audit_session_is_valid(0) == rs_audit_session_is_valid(0));
        assert_se(audit_session_is_valid(1) == rs_audit_session_is_valid(1));
        assert_se(audit_session_is_valid(42) == rs_audit_session_is_valid(42));
        assert_se(audit_session_is_valid(UINT32_MAX) == rs_audit_session_is_valid(UINT32_MAX));
}

static void test_errno_is_valid(void) {
        assert_se(errno_is_valid(0) == rs_errno_is_valid(0));
        assert_se(errno_is_valid(1) == rs_errno_is_valid(1));
        assert_se(errno_is_valid(EPERM) == rs_errno_is_valid(EPERM));
        assert_se(errno_is_valid(4095) == rs_errno_is_valid(4095));
        assert_se(errno_is_valid(4096) == rs_errno_is_valid(4096));
        assert_se(errno_is_valid(-1) == rs_errno_is_valid(-1));
}

static void test_VSOCK_CID_IS_REGULAR(void) {
        assert_se(VSOCK_CID_IS_REGULAR(0) == rs_VSOCK_CID_IS_REGULAR(0));
        assert_se(VSOCK_CID_IS_REGULAR(1) == rs_VSOCK_CID_IS_REGULAR(1));
        assert_se(VSOCK_CID_IS_REGULAR(2) == rs_VSOCK_CID_IS_REGULAR(2));
        assert_se(VSOCK_CID_IS_REGULAR(3) == rs_VSOCK_CID_IS_REGULAR(3));
        assert_se(VSOCK_CID_IS_REGULAR(100) == rs_VSOCK_CID_IS_REGULAR(100));
        assert_se(VSOCK_CID_IS_REGULAR(UINT32_MAX) == rs_VSOCK_CID_IS_REGULAR(UINT32_MAX));
}

static void test_SIGINFO_CODE_IS_DEAD(void) {
        assert_se(SIGINFO_CODE_IS_DEAD(CLD_EXITED) == rs_SIGINFO_CODE_IS_DEAD(CLD_EXITED));
        assert_se(SIGINFO_CODE_IS_DEAD(CLD_KILLED) == rs_SIGINFO_CODE_IS_DEAD(CLD_KILLED));
        assert_se(SIGINFO_CODE_IS_DEAD(CLD_DUMPED) == rs_SIGINFO_CODE_IS_DEAD(CLD_DUMPED));
        assert_se(SIGINFO_CODE_IS_DEAD(CLD_STOPPED) == rs_SIGINFO_CODE_IS_DEAD(CLD_STOPPED));
        assert_se(SIGINFO_CODE_IS_DEAD(0) == rs_SIGINFO_CODE_IS_DEAD(0));
        assert_se(SIGINFO_CODE_IS_DEAD(-1) == rs_SIGINFO_CODE_IS_DEAD(-1));
}

static void test_pid_validity(void) {
        assert_se(pid_is_valid(0) == rs_pid_is_valid(0));
        assert_se(pid_is_valid(1) == rs_pid_is_valid(1));
        assert_se(pid_is_valid(-1) == rs_pid_is_valid(-1));
        assert_se(pid_is_valid(65535) == rs_pid_is_valid(65535));
        assert_se(pid_is_valid(INT_MAX) == rs_pid_is_valid(INT_MAX));
        assert_se(pid_is_valid(INT_MIN) == rs_pid_is_valid(INT_MIN));
        assert_se(pid_is_automatic(PID_AUTOMATIC) == rs_pid_is_automatic(PID_AUTOMATIC));
        assert_se(pid_is_automatic(0) == rs_pid_is_automatic(0));
        assert_se(pid_is_automatic(1) == rs_pid_is_automatic(1));
}

static void test_size_multiply_overflow(void) {
        assert_se(size_multiply_overflow(0, 0) == rs_size_multiply_overflow(0, 0));
        assert_se(size_multiply_overflow(100, 0) == rs_size_multiply_overflow(100, 0));
        assert_se(size_multiply_overflow(0, 100) == rs_size_multiply_overflow(0, 100));
        assert_se(size_multiply_overflow(SIZE_MAX, 2) == rs_size_multiply_overflow(SIZE_MAX, 2));
        assert_se(size_multiply_overflow(SIZE_MAX / 2, 2) == rs_size_multiply_overflow(SIZE_MAX / 2, 2));
        assert_se(size_multiply_overflow(SIZE_MAX / 2 + 1, 2) == rs_size_multiply_overflow(SIZE_MAX / 2 + 1, 2));
}

static void test_GREEDY_ALLOC_ROUND_UP(void) {
        assert_se(GREEDY_ALLOC_ROUND_UP(0) == rs_GREEDY_ALLOC_ROUND_UP(0));
        assert_se(GREEDY_ALLOC_ROUND_UP(1) == rs_GREEDY_ALLOC_ROUND_UP(1));
        assert_se(GREEDY_ALLOC_ROUND_UP(2) == rs_GREEDY_ALLOC_ROUND_UP(2));
        assert_se(GREEDY_ALLOC_ROUND_UP(3) == rs_GREEDY_ALLOC_ROUND_UP(3));
        assert_se(GREEDY_ALLOC_ROUND_UP(4) == rs_GREEDY_ALLOC_ROUND_UP(4));
        assert_se(GREEDY_ALLOC_ROUND_UP(5) == rs_GREEDY_ALLOC_ROUND_UP(5));
        assert_se(GREEDY_ALLOC_ROUND_UP(100) == rs_GREEDY_ALLOC_ROUND_UP(100));
        assert_se(GREEDY_ALLOC_ROUND_UP(1000) == rs_GREEDY_ALLOC_ROUND_UP(1000));
        assert_se(GREEDY_ALLOC_ROUND_UP(1024) == rs_GREEDY_ALLOC_ROUND_UP(1024));
        assert_se(GREEDY_ALLOC_ROUND_UP(SIZE_MAX / 2 + 1) == rs_GREEDY_ALLOC_ROUND_UP(SIZE_MAX / 2 + 1));
        assert_se(GREEDY_ALLOC_ROUND_UP(SIZE_MAX) == rs_GREEDY_ALLOC_ROUND_UP(SIZE_MAX));
}

static void test_file_offset_beyond_memory_size(void) {
        assert_se(file_offset_beyond_memory_size(-1) == rs_file_offset_beyond_memory_size(-1));
        assert_se(file_offset_beyond_memory_size(0) == rs_file_offset_beyond_memory_size(0));
        assert_se(file_offset_beyond_memory_size(100) == rs_file_offset_beyond_memory_size(100));
        assert_se(file_offset_beyond_memory_size(INT64_MAX) == rs_file_offset_beyond_memory_size(INT64_MAX));
}

static void test_strnull_strna(void) {
        assert_se(streq(rs_strnull(NULL), strnull(NULL)));
        assert_se(streq(rs_strnull("hello"), strnull("hello")));
        assert_se(streq(rs_strna(NULL), strna(NULL)));
        assert_se(streq(rs_strna("hello"), strna("hello")));
}

static void test_bool_to_string(void) {
        assert_se(streq(rs_true_false(true), true_false(true)));
        assert_se(streq(rs_true_false(false), true_false(false)));
        assert_se(streq(rs_plus_minus(true), plus_minus(true)));
        assert_se(streq(rs_plus_minus(false), plus_minus(false)));
        assert_se(streq(rs_one_zero(true), one_zero(true)));
        assert_se(streq(rs_one_zero(false), one_zero(false)));
        assert_se(streq(rs_enable_disable(true), enable_disable(true)));
        assert_se(streq(rs_enable_disable(false), enable_disable(false)));
        assert_se(streq(rs_enabled_disabled(true), enabled_disabled(true)));
        assert_se(streq(rs_enabled_disabled(false), enabled_disabled(false)));
}

static void test_empty_helpers(void) {
        assert_se(streq(rs_empty_to_na(NULL), empty_to_na(NULL)));
        assert_se(streq(rs_empty_to_na(""), empty_to_na("")));
        assert_se(streq(rs_empty_to_na("hello"), empty_to_na("hello")));

        assert_se(streq(rs_empty_to_dash(NULL), empty_to_dash(NULL)));
        assert_se(streq(rs_empty_to_dash(""), empty_to_dash("")));
        assert_se(streq(rs_empty_to_dash("hello"), empty_to_dash("hello")));

        assert_se(rs_empty_or_dash(NULL) == empty_or_dash(NULL));
        assert_se(rs_empty_or_dash("") == empty_or_dash(""));
        assert_se(rs_empty_or_dash("-") == empty_or_dash("-"));
        assert_se(rs_empty_or_dash("--") == empty_or_dash("--"));
        assert_se(rs_empty_or_dash("hello") == empty_or_dash("hello"));
}

static void test_pidref_helpers(void) {
        PidRef c_null = PIDREF_NULL;
        PidRef c_auto = PIDREF_AUTOMATIC;
        PidRef c_remote = { .pid = 42, .fd = -EREMOTE, .fd_id = 0 };
        PidRef c_set = { .pid = 1234, .fd = -EBADF, .fd_id = 0 };
        PidRef c_set_fd5 = { .pid = 5678, .fd = 5, .fd_id = 99 };

        PidRef r_null = { .pid = 0, .fd = -EBADF, .fd_id = 0 };
        PidRef r_auto = { .pid = INT_MIN, .fd = -EBADF, .fd_id = 0 };
        PidRef r_remote = { .pid = 42, .fd = -EREMOTE, .fd_id = 0 };
        PidRef r_set = { .pid = 1234, .fd = -EBADF, .fd_id = 0 };
        PidRef r_set_fd5 = { .pid = 5678, .fd = 5, .fd_id = 99 };

        /* pidref_is_set */
        assert_se(pidref_is_set(&c_null) == rs_pidref_is_set(&r_null));
        assert_se(pidref_is_set(&c_auto) == rs_pidref_is_set(&r_auto));
        assert_se(pidref_is_set(&c_remote) == rs_pidref_is_set(&r_remote));
        assert_se(pidref_is_set(&c_set) == rs_pidref_is_set(&r_set));
        assert_se(pidref_is_set(&c_set_fd5) == rs_pidref_is_set(&r_set_fd5));
        assert_se(pidref_is_set(NULL) == rs_pidref_is_set(NULL));

        /* pidref_is_automatic */
        assert_se(pidref_is_automatic(&c_null) == rs_pidref_is_automatic(&r_null));
        assert_se(pidref_is_automatic(&c_auto) == rs_pidref_is_automatic(&r_auto));
        assert_se(pidref_is_automatic(&c_set) == rs_pidref_is_automatic(&r_set));
        assert_se(pidref_is_automatic(NULL) == rs_pidref_is_automatic(NULL));

        /* pidref_is_set_or_automatic */
        assert_se(pidref_is_set_or_automatic(&c_null) == rs_pidref_is_set_or_automatic(&r_null));
        assert_se(pidref_is_set_or_automatic(&c_auto) == rs_pidref_is_set_or_automatic(&r_auto));
        assert_se(pidref_is_set_or_automatic(&c_set) == rs_pidref_is_set_or_automatic(&r_set));
        assert_se(pidref_is_set_or_automatic(&c_remote) == rs_pidref_is_set_or_automatic(&r_remote));
        assert_se(pidref_is_set_or_automatic(NULL) == rs_pidref_is_set_or_automatic(NULL));

        /* pidref_is_remote */
        assert_se(pidref_is_remote(&c_null) == rs_pidref_is_remote(&r_null));
        assert_se(pidref_is_remote(&c_auto) == rs_pidref_is_remote(&r_auto));
        assert_se(pidref_is_remote(&c_remote) == rs_pidref_is_remote(&r_remote));
        assert_se(pidref_is_remote(&c_set) == rs_pidref_is_remote(&r_set));
        assert_se(pidref_is_remote(&c_set_fd5) == rs_pidref_is_remote(&r_set_fd5));
        assert_se(pidref_is_remote(NULL) == rs_pidref_is_remote(NULL));
}

int main(int argc, char **argv) {
        test_CGROUP_WEIGHT_IS_OK();
        test_BFQ_WEIGHT();
        test_FILE_SIZE_VALID();
        test_FILE_SIZE_VALID_OR_INFINITY();
        test_audit_session_is_valid();
        test_errno_is_valid();
        test_VSOCK_CID_IS_REGULAR();
        test_SIGINFO_CODE_IS_DEAD();
        test_pid_validity();
        test_size_multiply_overflow();
        test_GREEDY_ALLOC_ROUND_UP();
        test_file_offset_beyond_memory_size();
        test_strnull_strna();
        test_bool_to_string();
        test_empty_helpers();
        test_pidref_helpers();
        return 0;
}
