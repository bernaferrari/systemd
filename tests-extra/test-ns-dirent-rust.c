/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C clone_flag_to_namespace_type vs Rust */

#include "tests.h"
#include <sched.h>
#include "namespace-util.h"

/* Rust FFI */
#include "rust/namespace_util.h"

/* ── clone_flag_to_namespace_type ────────────────────────────────────────── */

static void test_clone_flag_to_namespace_type(void) {
        int cr, rr;

        cr = clone_flag_to_namespace_type(CLONE_NEWCGROUP);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWCGROUP);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_CGROUP);

        cr = clone_flag_to_namespace_type(CLONE_NEWIPC);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWIPC);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_IPC);

        cr = clone_flag_to_namespace_type(CLONE_NEWNET);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWNET);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_NET);

        cr = clone_flag_to_namespace_type(CLONE_NEWNS);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWNS);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_MOUNT);

        cr = clone_flag_to_namespace_type(CLONE_NEWPID);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWPID);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_PID);

        cr = clone_flag_to_namespace_type(CLONE_NEWUSER);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWUSER);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_USER);

        cr = clone_flag_to_namespace_type(CLONE_NEWUTS);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWUTS);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_UTS);

        cr = clone_flag_to_namespace_type(CLONE_NEWTIME);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWTIME);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_TIME);

        /* Invalid: no matching flag */
        cr = clone_flag_to_namespace_type(0);
        rr = rs_clone_flag_to_namespace_type(0);
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* 0xDEAD matches NAMESPACE_TIME (bit 7 = CLONE_NEWTIME) */
        cr = clone_flag_to_namespace_type(0xDEAD);
        rr = rs_clone_flag_to_namespace_type(0xDEAD);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_TIME);

        /* Combination: CLONE_NEWNS | extra bits matches NAMESPACE_MOUNT
           (extra bits not in CLONE_* mask are ignored) */
        cr = clone_flag_to_namespace_type(CLONE_NEWNS | 0x1);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWNS | 0x1);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_MOUNT);
}

int main(int argc, char **argv) {
        test_clone_flag_to_namespace_type();
        return 0;
}
