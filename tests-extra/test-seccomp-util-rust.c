/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "tests.h"
#include "seccomp-util.h"
#include "rust/seccomp_util.h"

/* ── seccomp_errno_or_action_is_valid ──────────────────────────────────── */

static void test_seccomp_errno_or_action_is_valid_kill(void) {
        assert_se(seccomp_errno_or_action_is_valid(SECCOMP_ERROR_NUMBER_KILL) ==
                  rs_seccomp_errno_or_action_is_valid(SECCOMP_ERROR_NUMBER_KILL));
}

static void test_seccomp_errno_or_action_is_valid_range(void) {
        assert_se(seccomp_errno_or_action_is_valid(1) == rs_seccomp_errno_or_action_is_valid(1));
        assert_se(seccomp_errno_or_action_is_valid(ERRNO_MAX) == rs_seccomp_errno_or_action_is_valid(ERRNO_MAX));
        assert_se(!seccomp_errno_or_action_is_valid(0));
        assert_se(!rs_seccomp_errno_or_action_is_valid(0));
        assert_se(!seccomp_errno_or_action_is_valid(ERRNO_MAX + 1));
        assert_se(!rs_seccomp_errno_or_action_is_valid(ERRNO_MAX + 1));
        assert_se(!seccomp_errno_or_action_is_valid(-1));
        assert_se(!rs_seccomp_errno_or_action_is_valid(-1));
}

/* ── seccomp_parse_errno_or_action ─────────────────────────────────────── */

static void test_seccomp_parse_errno_or_action_kill(void) {
        int r_c = seccomp_parse_errno_or_action("kill");
        int r_r = rs_seccomp_parse_errno_or_action("kill");
        assert_se(r_c == r_r);
        assert_se(r_c == SECCOMP_ERROR_NUMBER_KILL);
}

static void test_seccomp_parse_errno_or_action_errno_name(void) {
        int r_c = seccomp_parse_errno_or_action("EPERM");
        int r_r = rs_seccomp_parse_errno_or_action("EPERM");
        assert_se(r_c == r_r);
        assert_se(r_c == EPERM);
}

static void test_seccomp_parse_errno_or_action_errno_number(void) {
        int r_c = seccomp_parse_errno_or_action("2");
        int r_r = rs_seccomp_parse_errno_or_action("2");
        assert_se(r_c == r_r);
        assert_se(r_c == ENOENT);
}

static void test_seccomp_parse_errno_or_action_matrix(void) {
        static const char *const valid[] = {
                "0", "  02", "0x2", "0b10", "0b 10", "0o2", "EHWPOISON",
        };
        static const char *const invalid[] = {
                "", "-1", "4096", "not-an-errno", "2 ", "\v0b10",
        };

        FOREACH_ELEMENT(p, valid)
                assert_se(seccomp_parse_errno_or_action(*p) == rs_seccomp_parse_errno_or_action(*p));
        FOREACH_ELEMENT(p, invalid)
                assert_se(seccomp_parse_errno_or_action(*p) == rs_seccomp_parse_errno_or_action(*p));

        /* C asserts on NULL. The Rust ABI fails closed instead of dereferencing it. */
        assert_se(rs_seccomp_parse_errno_or_action(NULL) == -EINVAL);
}

/* ── seccomp_errno_or_action_to_string ─────────────────────────────────── */

static void test_seccomp_errno_or_action_to_string_kill(void) {
        const char *r_c = seccomp_errno_or_action_to_string(SECCOMP_ERROR_NUMBER_KILL);
        const char *r_r = rs_seccomp_errno_or_action_to_string(SECCOMP_ERROR_NUMBER_KILL);
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
        assert_se(streq(r_c, "kill"));
}

static void test_seccomp_errno_or_action_to_string_errno(void) {
        const char *r_c = seccomp_errno_or_action_to_string(EPERM);
        const char *r_r = rs_seccomp_errno_or_action_to_string(EPERM);
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));

        assert_se(streq_ptr(seccomp_errno_or_action_to_string(-EPERM),
                           rs_seccomp_errno_or_action_to_string(-EPERM)));
        assert_se(!seccomp_errno_or_action_to_string(0));
        assert_se(!rs_seccomp_errno_or_action_to_string(0));
}

/* ── seccomp_arch_to_string / seccomp_arch_from_string ─────────────────── */

static void test_seccomp_arch_roundtrip(void) {
        /* Use C's from_string as source of truth for arch values,
         * since SCMP_ARCH_* constants may differ across libseccomp versions. */
        static const char *names[] = {
                "native", "x86", "x86-64", "x32", "arm", "arm64",
#ifdef SCMP_ARCH_LOONGARCH64
                "loongarch64",
#endif
                "mips", "mips64", "mips64-n32", "mips-le", "mips64-le",
                "mips64-le-n32", "parisc", "parisc64", "ppc", "ppc64",
                "ppc64-le",
#ifdef SCMP_ARCH_RISCV64
                "riscv64",
#endif
                "s390", "s390x",
        };

        for (int i = 0; i < (int)ELEMENTSOF(names); i++) {
                uint32_t c_val = 0, r_val = 0;
                int rc_c = seccomp_arch_from_string(names[i], &c_val);
                int rc_r = rs_seccomp_arch_from_string(names[i], &r_val);

                /* Both must agree on success/failure */
                assert_se(rc_c == rc_r);
                if (rc_c < 0)
                        continue;

                /* Both must return the same arch value */
                assert_se(c_val == r_val);

                /* Both to_string must agree */
                const char *r_c = seccomp_arch_to_string(c_val);
                const char *r_r = rs_seccomp_arch_to_string(r_val);
                assert_se(r_c && r_r);
                assert_se(streq(r_c, r_r));
        }
}

static void test_seccomp_arch_invalid(void) {
        const char *r_c = seccomp_arch_to_string(0xDEADBEEF);
        const char *r_r = rs_seccomp_arch_to_string(0xDEADBEEF);
        assert_se(!r_c && !r_r);

        uint32_t c_ret = 0, r_ret = 0;
        int rc_c = seccomp_arch_from_string("foobar", &c_ret);
        int rc_r = rs_seccomp_arch_from_string("foobar", &r_ret);
        assert_se(rc_c == rc_r);
        assert_se(rc_c < 0);
        assert_se(c_ret == 0 && r_ret == 0);

        assert_se(rs_seccomp_arch_from_string(NULL, &r_ret) == -EINVAL);
        assert_se(rs_seccomp_arch_from_string("native", NULL) == -EINVAL);
}

static void test_seccomp_arch_optional_header_tokens(void) {
        uint32_t r_ret = 0;

#ifndef SCMP_ARCH_LOONGARCH64
        assert_se(rs_seccomp_arch_from_string("loongarch64", &r_ret) == -EINVAL);
        assert_se(r_ret == 0);
#endif
#ifndef SCMP_ARCH_RISCV64
        assert_se(rs_seccomp_arch_from_string("riscv64", &r_ret) == -EINVAL);
        assert_se(r_ret == 0);
#endif
        (void) r_ret;
}

int main(int argc, char *argv[]) {
        test_seccomp_errno_or_action_is_valid_kill();
        test_seccomp_errno_or_action_is_valid_range();
        test_seccomp_parse_errno_or_action_kill();
        test_seccomp_parse_errno_or_action_errno_name();
        test_seccomp_parse_errno_or_action_errno_number();
        test_seccomp_parse_errno_or_action_matrix();
        test_seccomp_errno_or_action_to_string_kill();
        test_seccomp_errno_or_action_to_string_errno();
        test_seccomp_arch_roundtrip();
        test_seccomp_arch_invalid();
        test_seccomp_arch_optional_header_tokens();

        return 0;
}
