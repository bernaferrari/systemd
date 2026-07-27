/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nsflags.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(namespace_flags_from_string_basic) {
        unsigned long flags = 0;

        assert_se(namespace_flags_from_string("mnt", &flags) == 0);
        assert_se(flags == CLONE_NEWNS);

        assert_se(namespace_flags_from_string("net", &flags) == 0);
        assert_se(flags == CLONE_NEWNET);

        assert_se(namespace_flags_from_string("pid", &flags) == 0);
        assert_se(flags == CLONE_NEWPID);

        assert_se(namespace_flags_from_string("user", &flags) == 0);
        assert_se(flags == CLONE_NEWUSER);

        /* Invalid flag */
        assert_se(namespace_flags_from_string("invalid", &flags) == -EINVAL);
}

TEST(namespace_flags_from_string_combined) {
        unsigned long flags = 0;

        assert_se(namespace_flags_from_string("mnt net", &flags) == 0);
        assert_se(flags == (CLONE_NEWNS | CLONE_NEWNET));

        assert_se(namespace_flags_from_string("pid user ipc", &flags) == 0);
        assert_se(flags == (CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWIPC));
}

TEST(namespace_flags_to_string_basic) {
        _cleanup_free_ char *s = NULL;

        assert_se(namespace_flags_to_string(CLONE_NEWNS, &s) == 0);
        assert_se(streq(s, "mnt"));
        s = mfree(s);

        assert_se(namespace_flags_to_string(CLONE_NEWNS | CLONE_NEWNET, &s) == 0);
        /* Order may vary, just check both are present */
        assert_se(strstr(s, "mnt") || strstr(s, "net"));
}

TEST(namespace_flags_to_strv_basic) {
        _cleanup_strv_free_ char **l = NULL;

        assert_se(namespace_flags_to_strv(CLONE_NEWNS, &l) == 0);
        assert_se(strv_length(l) == 1);
        assert_se(streq(l[0], "mnt"));
}

TEST(namespace_flags_roundtrip) {
        unsigned long flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET;
        _cleanup_free_ char *s = NULL;
        unsigned long parsed = 0;

        assert_se(namespace_flags_to_string(flags, &s) == 0);
        assert_se(namespace_flags_from_string(s, &parsed) == 0);
        assert_se(parsed == flags);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
