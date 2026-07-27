/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
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
}

/* ── sched_policy ─────────────────────────────────────────────────────── */

static void test_sched_policy_to_string(void) {
        /* sched_policy uses DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK which
         * generates sched_policy_to_string_alloc(int, char**). The Rust
         * version provides a simple rs_sched_policy_to_string(int) that
         * returns const char*. We test it independently. */
        const char *r;

        r = rs_sched_policy_to_string(SCHED_OTHER);
        assert_se(r);
        assert_se(streq(r, "other"));

        r = rs_sched_policy_to_string(SCHED_FIFO);
        assert_se(r);
        assert_se(streq(r, "fifo"));

        r = rs_sched_policy_to_string(SCHED_RR);
        assert_se(r);
        assert_se(streq(r, "rr"));

        r = rs_sched_policy_to_string(SCHED_BATCH);
        assert_se(r);
        assert_se(streq(r, "batch"));

        r = rs_sched_policy_to_string(SCHED_IDLE);
        assert_se(r);
        assert_se(streq(r, "idle"));

        /* Invalid */
        r = rs_sched_policy_to_string(99);
        assert_se(r == NULL);

        r = rs_sched_policy_to_string(4); /* gap between BATCH=3 and IDLE=5 */
        assert_se(r == NULL);
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
}

int main(int argc, char **argv) {
        test_sigchld_code_to_string();
        test_sigchld_code_from_string();
        test_sched_policy_to_string();
        test_sched_policy_from_string();
        return 0;
}
