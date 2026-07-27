/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include "tests.h"
#include "namespace-util.h"
#include "mountpoint-util.h"
#include "rust/namespace_util.h"
#include "rust/mountpoint_util.h"

#include <sys/mount.h>
#include <linux/sched.h>

/* ── mount_propagation_flag_to_string ──────────────────────────────────── */

static void test_mount_propagation_to_string_zero(void) {
        const char *r_c = mount_propagation_flag_to_string(0);
        const char *r_r = rs_mount_propagation_flag_to_string(0);
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
}

static void test_mount_propagation_to_string_shared(void) {
        const char *r_c = mount_propagation_flag_to_string(MS_SHARED);
        const char *r_r = rs_mount_propagation_flag_to_string(MS_SHARED);
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
}

static void test_mount_propagation_to_string_slave(void) {
        const char *r_c = mount_propagation_flag_to_string(MS_SLAVE);
        const char *r_r = rs_mount_propagation_flag_to_string(MS_SLAVE);
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
}

static void test_mount_propagation_to_string_private(void) {
        const char *r_c = mount_propagation_flag_to_string(MS_PRIVATE);
        const char *r_r = rs_mount_propagation_flag_to_string(MS_PRIVATE);
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
}

static void test_mount_propagation_to_string_combined(void) {
        /* Combined flags: C returns NULL for invalid combinations */
        unsigned long combined = MS_SHARED | MS_SLAVE;
        const char *r_c = mount_propagation_flag_to_string(combined);
        const char *r_r = rs_mount_propagation_flag_to_string(combined);
        assert_se(!r_c && !r_r);
}

static void test_mount_propagation_to_string_all_bits(void) {
        /* All bits set: C returns NULL for invalid combinations */
        unsigned long all = MS_SHARED | MS_SLAVE | MS_PRIVATE;
        const char *r_c = mount_propagation_flag_to_string(all);
        const char *r_r = rs_mount_propagation_flag_to_string(all);
        assert_se(!r_c && !r_r);
}

/* ── mount_propagation_flag_from_string ────────────────────────────────── */

static void test_mount_propagation_from_string_empty(void) {
        unsigned long c_ret = 999, r_ret = 999;
        int r_c = mount_propagation_flag_from_string("", &c_ret);
        int r_r = rs_mount_propagation_flag_from_string("", &r_ret);
        assert_se(r_c == r_r);
        assert_se(c_ret == r_ret);
}

static void test_mount_propagation_from_string_shared(void) {
        unsigned long c_ret = 0, r_ret = 0;
        int r_c = mount_propagation_flag_from_string("shared", &c_ret);
        int r_r = rs_mount_propagation_flag_from_string("shared", &r_ret);
        assert_se(r_c == r_r);
        assert_se(r_c == 0);
        assert_se(c_ret == r_ret);
}

static void test_mount_propagation_from_string_slave(void) {
        unsigned long c_ret = 0, r_ret = 0;
        int r_c = mount_propagation_flag_from_string("slave", &c_ret);
        int r_r = rs_mount_propagation_flag_from_string("slave", &r_ret);
        assert_se(r_c == r_r);
        assert_se(r_c == 0);
        assert_se(c_ret == r_ret);
}

static void test_mount_propagation_from_string_private(void) {
        unsigned long c_ret = 0, r_ret = 0;
        int r_c = mount_propagation_flag_from_string("private", &c_ret);
        int r_r = rs_mount_propagation_flag_from_string("private", &r_ret);
        assert_se(r_c == r_r);
        assert_se(r_c == 0);
        assert_se(c_ret == r_ret);
}

static void test_mount_propagation_from_string_invalid(void) {
        unsigned long c_ret = 0, r_ret = 0;
        int r_c = mount_propagation_flag_from_string("foobar", &c_ret);
        int r_r = rs_mount_propagation_flag_from_string("foobar", &r_ret);
        assert_se(r_c == r_r);
        assert_se(r_c < 0);
}

static void test_mount_propagation_from_string_case(void) {
        unsigned long c_ret = 0, r_ret = 0;
        int r_c = mount_propagation_flag_from_string("Shared", &c_ret);
        int r_r = rs_mount_propagation_flag_from_string("Shared", &r_ret);
        assert_se(r_c == r_r);
        assert_se(r_c < 0);
}

/* ── is_name_to_handle_at_fatal_error ────────────────────────────────────── */

/* C implementation asserts err < 0, so only test negative errno values */

static void test_is_name_to_handle_at_fatal_error_fatal(void) {
        int errs[] = { -ENOENT, -ENOTDIR, -ELOOP, -ENOMEM };
        for (int i = 0; i < (int)ELEMENTSOF(errs); i++) {
                assert_se(is_name_to_handle_at_fatal_error(errs[i]) ==
                          rs_is_name_to_handle_at_fatal_error(errs[i]));
                assert_se(is_name_to_handle_at_fatal_error(errs[i]));
        }
}

static void test_is_name_to_handle_at_fatal_error_not_supported(void) {
        int errs[] = { -EOPNOTSUPP, -ENOTTY, -ENOSYS, -EAFNOSUPPORT,
                       -EPFNOSUPPORT, -EPROTONOSUPPORT, -ESOCKTNOSUPPORT,
                       -ENOPROTOOPT };
        for (int i = 0; i < (int)ELEMENTSOF(errs); i++) {
                assert_se(is_name_to_handle_at_fatal_error(errs[i]) ==
                          rs_is_name_to_handle_at_fatal_error(errs[i]));
                assert_se(!is_name_to_handle_at_fatal_error(errs[i]));
        }
}

static void test_is_name_to_handle_at_fatal_error_privilege(void) {
        assert_se(is_name_to_handle_at_fatal_error(-EACCES) == rs_is_name_to_handle_at_fatal_error(-EACCES));
        assert_se(is_name_to_handle_at_fatal_error(-EPERM) == rs_is_name_to_handle_at_fatal_error(-EPERM));
        assert_se(!is_name_to_handle_at_fatal_error(-EACCES));
}

static void test_is_name_to_handle_at_fatal_error_overflow(void) {
        assert_se(is_name_to_handle_at_fatal_error(-EOVERFLOW) == rs_is_name_to_handle_at_fatal_error(-EOVERFLOW));
        assert_se(!is_name_to_handle_at_fatal_error(-EOVERFLOW));
}

static void test_is_name_to_handle_at_fatal_error_einval(void) {
        assert_se(is_name_to_handle_at_fatal_error(-EINVAL) == rs_is_name_to_handle_at_fatal_error(-EINVAL));
        assert_se(!is_name_to_handle_at_fatal_error(-EINVAL));
}

/* ── clone_flag_to_namespace_type ───────────────────────────────────────── */

static void test_clone_flag_to_namespace_type_all(void) {
        static const struct {
                unsigned long flag;
                int expected;
        } table[] = {
                { CLONE_NEWCGROUP, NAMESPACE_CGROUP },
                { CLONE_NEWIPC,    NAMESPACE_IPC },
                { CLONE_NEWNET,    NAMESPACE_NET },
                { CLONE_NEWNS,     NAMESPACE_MOUNT },
                { CLONE_NEWPID,    NAMESPACE_PID },
                { CLONE_NEWUSER,   NAMESPACE_USER },
                { CLONE_NEWUTS,    NAMESPACE_UTS },
                { CLONE_NEWTIME,   NAMESPACE_TIME },
        };

        for (int i = 0; i < (int)ELEMENTSOF(table); i++) {
                int r_c = clone_flag_to_namespace_type(table[i].flag);
                int r_r = rs_clone_flag_to_namespace_type(table[i].flag);
                assert_se(r_c == r_r);
                assert_se(r_c == table[i].expected);
        }
}

static void test_clone_flag_to_namespace_type_invalid(void) {
        int r_c = clone_flag_to_namespace_type(0);
        int r_r = rs_clone_flag_to_namespace_type(0);
        assert_se(r_c == r_r);
        assert_se(r_c < 0);

        r_c = clone_flag_to_namespace_type(0xDEADBEEF);
        r_r = rs_clone_flag_to_namespace_type(0xDEADBEEF);
        assert_se(r_c == r_r);
        assert_se(r_c < 0);

        r_c = clone_flag_to_namespace_type(CLONE_NEWPID | CLONE_NEWNS);
        r_r = rs_clone_flag_to_namespace_type(CLONE_NEWPID | CLONE_NEWNS);
        assert_se(r_c == r_r);
        assert_se(r_c < 0);
}

/* ── userns_shift_range_valid ───────────────────────────────────────────── */

static void test_userns_shift_range_valid_basic(void) {
        assert_se(rs_userns_shift_range_valid(0, 1));
        assert_se(rs_userns_shift_range_valid(100, 100));
        assert_se(rs_userns_shift_range_valid(0, UINT32_MAX));
        assert_se(rs_userns_shift_range_valid(1, 1));
}

static void test_userns_shift_range_valid_invalid(void) {
        assert_se(!rs_userns_shift_range_valid(0, 0));
        assert_se(!rs_userns_shift_range_valid(UINT32_MAX, 1));
        assert_se(!rs_userns_shift_range_valid(UINT32_MAX - 1, 2));
        assert_se(!rs_userns_shift_range_valid(UINT32_MAX, UINT32_MAX));
}

static void test_userns_shift_range_valid_edge(void) {
        assert_se(rs_userns_shift_range_valid(UINT32_MAX - 1, 1));
        assert_se(rs_userns_shift_range_valid(0, UINT32_MAX));
}

int main(int argc, char *argv[]) {
        test_mount_propagation_to_string_zero();
        test_mount_propagation_to_string_shared();
        test_mount_propagation_to_string_slave();
        test_mount_propagation_to_string_private();
        test_mount_propagation_to_string_combined();
        test_mount_propagation_to_string_all_bits();
        test_mount_propagation_from_string_empty();
        test_mount_propagation_from_string_shared();
        test_mount_propagation_from_string_slave();
        test_mount_propagation_from_string_private();
        test_mount_propagation_from_string_invalid();
        test_mount_propagation_from_string_case();
        test_is_name_to_handle_at_fatal_error_fatal();
        test_is_name_to_handle_at_fatal_error_not_supported();
        test_is_name_to_handle_at_fatal_error_privilege();
        test_is_name_to_handle_at_fatal_error_overflow();
        test_is_name_to_handle_at_fatal_error_einval();
        test_clone_flag_to_namespace_type_all();
        test_clone_flag_to_namespace_type_invalid();
        test_userns_shift_range_valid_basic();
        test_userns_shift_range_valid_invalid();
        test_userns_shift_range_valid_edge();

        return 0;
}
