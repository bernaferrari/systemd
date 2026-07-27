/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>

#include "uid-classification.h"
#include "user-util.h"
#include "tests.h"

TEST(uid_for_system_journal_basic) {
        /* System UIDs should get system journal */
        assert_se(uid_for_system_journal(0));
        assert_se(uid_for_system_journal(100));

        /* Regular user UIDs should not */
        assert_se(!uid_for_system_journal(1000));
}

TEST(uid_is_transient_basic) {
        /* Transient = container or dynamic */
        assert_se(uid_is_transient(61184));    /* dynamic min */
        assert_se(uid_is_transient(65519));    /* dynamic max */
        assert_se(!uid_is_transient(1000));    /* regular user */
        assert_se(!uid_is_transient(0));       /* root */
}

TEST(gid_is_transient_basic) {
        assert_se(gid_is_transient(61184));
        assert_se(!gid_is_transient(1000));
}

TEST(uid_is_valid_edge_cases) {
        /* UID 0 is valid */
        assert_se(uid_is_valid(0));
        /* Very large but valid */
        assert_se(uid_is_valid(1000000));
        /* Invalid: -1 (0xFFFFFFFF) */
        assert_se(!uid_is_valid(UINT32_C(0xFFFFFFFF)));
        /* Invalid: 0xFFFF (16-bit -1) */
        assert_se(!uid_is_valid(UINT32_C(0xFFFF)));
}

TEST(valid_home_basic) {
        assert_se(valid_home("/home/user"));
        assert_se(valid_home("/"));
        assert_se(!valid_home(""));             /* empty */
        assert_se(!valid_home("relative"));      /* not absolute */
        assert_se(!valid_home("/has:colon"));    /* no colons */
}

TEST(valid_shell_basic) {
        assert_se(valid_shell("/bin/bash"));
        assert_se(valid_shell("/bin/sh"));
        assert_se(!valid_shell(""));             /* empty */
        assert_se(!valid_shell("bash"));         /* not absolute */
        assert_se(!valid_shell("/bin/bash/"));   /* trailing slash */
}

DEFINE_TEST_MAIN(LOG_DEBUG);
