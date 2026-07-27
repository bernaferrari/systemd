/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nsflags.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(namespace_flags_from_string_basic) {
        unsigned long flags = 0;
        int r;

        /* Single namespace */
        r = namespace_flags_from_string("mnt", &flags);
        assert_se(r >= 0);
        assert_se(flags != 0);

        /* Multiple namespaces */
        flags = 0;
        r = namespace_flags_from_string("mnt net ipc", &flags);
        assert_se(r >= 0);
        assert_se(flags != 0);

        /* Invalid namespace */
        r = namespace_flags_from_string("invalid", &flags);
        assert_se(r == -EINVAL);

        /* Empty string */
        flags = 99;
        r = namespace_flags_from_string("", &flags);
        assert_se(r >= 0);
        assert_se(flags == 0);
}

TEST(namespace_flags_to_string_basic) {
        _cleanup_free_ char *s = NULL;
        unsigned long flags = 0;
        int r;

        /* Convert 0 flags */
        r = namespace_flags_to_string(0, &s);
        assert_se(r >= 0);

        /* Convert specific flag */
        r = namespace_flags_from_string("mnt", &flags);
        assert_se(r >= 0);
        s = mfree(s);
        r = namespace_flags_to_string(flags, &s);
        assert_se(r >= 0);
        assert_se(s != NULL);
        assert_se(strstr(s, "mnt") != NULL);
}

TEST(namespace_flags_roundtrip) {
        _cleanup_free_ char *s = NULL;
        unsigned long flags_orig = 0, flags_parsed = 0;
        int r;

        r = namespace_flags_from_string("mnt net ipc", &flags_orig);
        assert_se(r >= 0);

        r = namespace_flags_to_string(flags_orig, &s);
        assert_se(r >= 0);
        assert_se(s != NULL);

        r = namespace_flags_from_string(s, &flags_parsed);
        assert_se(r >= 0);
        assert_se(flags_orig == flags_parsed);
}

TEST(namespace_single_flag_to_string_basic) {
        unsigned long flags = 0;
        int r = namespace_flags_from_string("mnt", &flags);
        assert_se(r >= 0);
        const char *name = namespace_single_flag_to_string(flags);
        assert_se(name != NULL);
        assert_se(streq(name, "mnt"));

        /* Unknown flag */
        name = namespace_single_flag_to_string(0xDEADBEEF);
        assert_se(name == NULL);
}

TEST(namespace_flags_to_strv_basic) {
        _cleanup_strv_free_ char **l = NULL;
        unsigned long flags = 0;
        int r;

        r = namespace_flags_from_string("mnt net", &flags);
        assert_se(r >= 0);

        r = namespace_flags_to_strv(flags, &l);
        assert_se(r >= 0);
        assert_se(strv_length(l) == 2);
        assert_se(strv_contains(l, "mnt"));
        assert_se(strv_contains(l, "net"));
}

TEST(namespace_flags_all) {
        /* NAMESPACE_FLAGS_ALL should be a valid combination */
        unsigned long all = NAMESPACE_FLAGS_ALL;
        assert_se(all != 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
