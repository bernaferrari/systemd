/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: process-sigchld-code-to-string */
/* RUST-CONTRACT: process-sigchld-code-from-string */
/* RUST-CONTRACT: process-sched-policy-to-string-alloc */
/* RUST-CONTRACT: process-sched-policy-from-string */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rust/process_util_str_tables.h"

/* C references */
#include "process-util.h"
#include "string-util.h"

/* ── sigchld_code ─────────────────────────────────────────────────────── */

static void test_sigchld_code_to_string(void) {
        const char *c_ret, *r_ret;

        /* CLD_EXITED=1 */
        c_ret = sigchld_code_to_string(CLD_EXITED);
        r_ret = rs_sigchld_code_to_string(CLD_EXITED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = sigchld_code_to_string(CLD_KILLED);
        r_ret = rs_sigchld_code_to_string(CLD_KILLED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = sigchld_code_to_string(CLD_CONTINUED);
        r_ret = rs_sigchld_code_to_string(CLD_CONTINUED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* Invalid code */
        c_ret = sigchld_code_to_string(0);
        r_ret = rs_sigchld_code_to_string(0);
        assert_se(streq_ptr(c_ret, r_ret));

        /* The Rust facade has the same borrowed-static ownership as C's
         * DEFINE_STRING_TABLE_LOOKUP result. */
        r_ret = rs_sigchld_code_to_string(CLD_EXITED);
        assert_se(r_ret == rs_sigchld_code_to_string(CLD_EXITED));
}

static void test_sigchld_code_from_string(void) {
        int c_ret, r_ret;

        c_ret = sigchld_code_from_string("exited");
        r_ret = rs_sigchld_code_from_string("exited");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == CLD_EXITED);

        c_ret = sigchld_code_from_string("stopped");
        r_ret = rs_sigchld_code_from_string("stopped");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == CLD_STOPPED);

        /* Invalid */
        c_ret = sigchld_code_from_string("bogus");
        r_ret = rs_sigchld_code_from_string("bogus");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == -EINVAL);

        c_ret = sigchld_code_from_string(NULL);
        r_ret = rs_sigchld_code_from_string(NULL);
        assert_se(c_ret == r_ret);

        {
                static const char non_utf8[] = { 'e', 'x', 'i', 't', 'e', 'd', (char) 0xff, 0 };

                c_ret = sigchld_code_from_string(non_utf8);
                r_ret = rs_sigchld_code_from_string(non_utf8);
                assert_se(c_ret == r_ret);
        }
}

/* ── sched_policy ─────────────────────────────────────────────────────── */

static void test_sched_policy_to_string_alloc(void) {
        static const int policies[] = { SCHED_OTHER, SCHED_FIFO, SCHED_RR, SCHED_BATCH, SCHED_IDLE, 4, 99, INT_MAX };

        for (size_t i = 0; i < sizeof(policies) / sizeof(policies[0]); i++) {
                _cleanup_free_ char *c = NULL, *r = NULL;

                assert_se(sched_policy_to_string_alloc(policies[i], &c) >= 0);
                assert_se(rs_sched_policy_to_string_alloc(policies[i], &r) >= 0);
                assert_se(c && r);
                assert_se(streq(c, r));
        }

        /* Errors do not publish or overwrite either caller output. */
        char *c = (char*) 1, *r = (char*) 1;
        assert_se(sched_policy_to_string_alloc(-1, &c) == -ERANGE);
        assert_se(rs_sched_policy_to_string_alloc(-1, &r) == -ERANGE);
        assert_se(c == (char*) 1);
        assert_se(r == (char*) 1);
}

static void test_sched_policy_from_string(void) {
        int c_ret, r_ret;

        c_ret = sched_policy_from_string("other");
        r_ret = rs_sched_policy_from_string("other");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == SCHED_OTHER);

        c_ret = sched_policy_from_string("fifo");
        r_ret = rs_sched_policy_from_string("fifo");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == SCHED_FIFO);

        c_ret = sched_policy_from_string("rr");
        r_ret = rs_sched_policy_from_string("rr");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == SCHED_RR);

        c_ret = sched_policy_from_string("batch");
        r_ret = rs_sched_policy_from_string("batch");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == SCHED_BATCH);

        c_ret = sched_policy_from_string("idle");
        r_ret = rs_sched_policy_from_string("idle");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == SCHED_IDLE);

        /* Numeric fallback (DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK) */
        c_ret = sched_policy_from_string("0");
        r_ret = rs_sched_policy_from_string("0");
        assert_se(c_ret == r_ret);

        c_ret = sched_policy_from_string("1");
        r_ret = rs_sched_policy_from_string("1");
        assert_se(c_ret == r_ret);

        /* Invalid */
        c_ret = sched_policy_from_string("bogus");
        r_ret = rs_sched_policy_from_string("bogus");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == -EINVAL);

        c_ret = sched_policy_from_string(NULL);
        r_ret = rs_sched_policy_from_string(NULL);
        assert_se(c_ret == r_ret);

        /* The C fallback is safe_atou()-based: exercise its non-decimal,
         * leading-space, sign, range, and trailing-byte behavior directly. */
        static const char * const numeric_cases[] = {
                "0b11",
                "0o7",
                " 1",
                "+1",
                "-1",
                "2147483647",
                "2147483648",
                "1 ",
        };
        for (size_t i = 0; i < sizeof(numeric_cases) / sizeof(numeric_cases[0]); i++) {
                c_ret = sched_policy_from_string(numeric_cases[i]);
                r_ret = rs_sched_policy_from_string(numeric_cases[i]);
                assert_se(c_ret == r_ret);
        }

        {
                static const char non_utf8[] = { '1', (char) 0xff, 0 };

                c_ret = sched_policy_from_string(non_utf8);
                r_ret = rs_sched_policy_from_string(non_utf8);
                assert_se(c_ret == r_ret);
        }
}

int main(int argc, char **argv) {
        test_sigchld_code_to_string();
        test_sigchld_code_from_string();
        test_sched_policy_to_string_alloc();
        test_sched_policy_from_string();
        return 0;
}
