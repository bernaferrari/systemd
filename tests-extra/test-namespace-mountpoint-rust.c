/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
#include <limits.h>
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
/* RUST-CONTRACT: mount-propagation-flag-strings */

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

static void test_mount_propagation_to_string_ignores_other_flags(void) {
        unsigned long flags = MS_SHARED | MS_RDONLY;
        const char *r_c = mount_propagation_flag_to_string(flags);
        const char *r_r = rs_mount_propagation_flag_to_string(flags);

        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
        assert_se(streq(r_r, "shared"));
}

static void test_mount_propagation_to_string_is_static(void) {
        const char *first = rs_mount_propagation_flag_to_string(MS_PRIVATE);
        const char *second = rs_mount_propagation_flag_to_string(MS_PRIVATE);

        assert_se(first && second);
        assert_se(first == second);
}

/* RUST-CONTRACT: mount-propagation-flag-validity */
static void test_mount_propagation_flag_validity(void) {
        static const unsigned long cases[] = {
                0,
                MS_SHARED,
                MS_SLAVE,
                MS_PRIVATE,
                MS_SHARED | MS_SLAVE,
                MS_SHARED | MS_RDONLY,
                ULONG_MAX,
        };

        for (size_t i = 0; i < ELEMENTSOF(cases); i++)
                assert_se(mount_propagation_flag_is_valid(cases[i]) ==
                          rs_mount_propagation_flag_is_valid(cases[i]));
}

/* ── mount_propagation_flag_from_string ────────────────────────────────── */
/* RUST-CONTRACT: mount-propagation-flag-parsing */

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
        unsigned long c_ret = ULONG_MAX, r_ret = ULONG_MAX;
        int r_c = mount_propagation_flag_from_string("foobar", &c_ret);
        int r_r = rs_mount_propagation_flag_from_string("foobar", &r_ret);
        assert_se(r_c == r_r);
        assert_se(r_c < 0);
        assert_se(c_ret == ULONG_MAX);
        assert_se(r_ret == ULONG_MAX);
}

static void test_mount_propagation_from_string_case(void) {
        unsigned long c_ret = 0, r_ret = 0;
        int r_c = mount_propagation_flag_from_string("Shared", &c_ret);
        int r_r = rs_mount_propagation_flag_from_string("Shared", &r_ret);
        assert_se(r_c == r_r);
        assert_se(r_c < 0);
}

static void test_mount_propagation_from_string_null(void) {
        unsigned long c_ret = ULONG_MAX, r_ret = ULONG_MAX;
        int r_c = mount_propagation_flag_from_string(NULL, &c_ret);
        int r_r = rs_mount_propagation_flag_from_string(NULL, &r_ret);

        assert_se(r_c == r_r);
        assert_se(r_c == 0);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
}

static void test_mount_propagation_from_string_non_utf8(void) {
        static const char name[] = { 's', 'h', 'a', 'r', 'e', 'd', '\xff', 0 };
        unsigned long c_ret = ULONG_MAX, r_ret = ULONG_MAX;
        int r_c = mount_propagation_flag_from_string(name, &c_ret);
        int r_r = rs_mount_propagation_flag_from_string(name, &r_ret);

        assert_se(r_c == r_r);
        assert_se(r_c < 0);
        assert_se(c_ret == ULONG_MAX);
        assert_se(r_ret == ULONG_MAX);
}

static void test_mount_propagation_from_string_stops_at_nul(void) {
        static const char name[] = { 's', 'h', 'a', 'r', 'e', 'd', 0, 'x', 0 };
        unsigned long c_ret = ULONG_MAX, r_ret = ULONG_MAX;
        int r_c = mount_propagation_flag_from_string(name, &c_ret);
        int r_r = rs_mount_propagation_flag_from_string(name, &r_ret);

        assert_se(r_c == r_r);
        assert_se(r_c == 0);
        assert_se(c_ret == MS_SHARED);
        assert_se(r_ret == MS_SHARED);
}

/* ── is_name_to_handle_at_fatal_error ────────────────────────────────────── */
/* RUST-CONTRACT: name-to-handle-fatal-error */

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

/* RUST-CONTRACT: namespace-clone-flag-to-type */
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

        /* C intentionally ignores non-namespace clone flags. */
        r_c = clone_flag_to_namespace_type(CLONE_NEWNET | 0x01);
        r_r = rs_clone_flag_to_namespace_type(CLONE_NEWNET | 0x01);
        assert_se(r_c == r_r);
        assert_se(r_c == NAMESPACE_NET);
}

/* ── userns_shift_range_valid ───────────────────────────────────────────── */

/* RUST-CONTRACT: namespace-userns-shift-range */
static void test_userns_shift_range_valid_basic(void) {
        static const struct {
                uid_t shift;
                uid_t range;
        } cases[] = {
                { 0, 1 },
                { 100, 100 },
                { 0, (uid_t) -1 },
                { 1, 1 },
        };

        for (size_t i = 0; i < ELEMENTSOF(cases); i++)
                assert_se(userns_shift_range_valid(cases[i].shift, cases[i].range) ==
                          rs_userns_shift_range_valid(cases[i].shift, cases[i].range));
}

static void test_userns_shift_range_valid_invalid(void) {
        static const struct {
                uid_t shift;
                uid_t range;
        } cases[] = {
                { 0, 0 },
                { (uid_t) -1, 1 },
                { (uid_t) -2, 2 },
                { (uid_t) -1, (uid_t) -1 },
        };

        for (size_t i = 0; i < ELEMENTSOF(cases); i++)
                assert_se(userns_shift_range_valid(cases[i].shift, cases[i].range) ==
                          rs_userns_shift_range_valid(cases[i].shift, cases[i].range));
}

static void test_userns_shift_range_valid_edge(void) {
        assert_se(userns_shift_range_valid((uid_t) -2, 1) ==
                  rs_userns_shift_range_valid((uid_t) -2, 1));
        assert_se(userns_shift_range_valid(0, (uid_t) -1) ==
                  rs_userns_shift_range_valid(0, (uid_t) -1));
}

int main(int argc, char *argv[]) {
        test_mount_propagation_to_string_zero();
        test_mount_propagation_to_string_shared();
        test_mount_propagation_to_string_slave();
        test_mount_propagation_to_string_private();
        test_mount_propagation_to_string_combined();
        test_mount_propagation_to_string_all_bits();
        test_mount_propagation_to_string_ignores_other_flags();
        test_mount_propagation_to_string_is_static();
        test_mount_propagation_flag_validity();
        test_mount_propagation_from_string_empty();
        test_mount_propagation_from_string_shared();
        test_mount_propagation_from_string_slave();
        test_mount_propagation_from_string_private();
        test_mount_propagation_from_string_invalid();
        test_mount_propagation_from_string_case();
        test_mount_propagation_from_string_null();
        test_mount_propagation_from_string_non_utf8();
        test_mount_propagation_from_string_stops_at_nul();
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
