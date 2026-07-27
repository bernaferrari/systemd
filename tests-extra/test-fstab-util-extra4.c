/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fstab-util.h"
#include "string-util.h"
#include "tests.h"

TEST(fstab_filter_options) {
        const char *name = NULL;
        _cleanup_free_ char *value = NULL, *filtered = NULL;
        int r;

        /* Found option with value */
        r = fstab_filter_options("ro,noexec,size=1630748k", "size\0", NULL, &value, NULL, NULL);
        assert_se(r > 0);
        assert_se(streq(value, "1630748k"));

        /* Not found */
        value = mfree(value);
        r = fstab_filter_options("ro,noexec", "size\0", NULL, &value, NULL, NULL);
        assert_se(r == 0);
        assert_se(value == NULL);

        /* NULL opts → not found */
        r = fstab_filter_options(NULL, "size\0", NULL, &value, NULL, NULL);
        assert_se(r == 0);

        /* Found option without value */
        r = fstab_filter_options("ro,noexec,size=100", "ro\0", &name, NULL, NULL, NULL);
        assert_se(r > 0);
        assert_se(streq(name, "ro"));

        /* Filtered output: returns remaining options */
        filtered = mfree(filtered);
        r = fstab_filter_options("ro,noexec,size=100", "size\0", NULL, NULL, NULL, &filtered);
        assert_se(r > 0);
        assert_se(string_contains_word(filtered, ",", "ro"));
        assert_se(string_contains_word(filtered, ",", "noexec"));
        assert_se(!string_contains_word(filtered, ",", "size=100"));

        /* Multiple names to match (空分隔) */
        value = mfree(value);
        r = fstab_filter_options("ro,nosuid,nodev", "ro\0nosuid\0", &name, NULL, NULL, NULL);
        assert_se(r > 0);
        /* Returns the last matching name */
        assert_se(streq(name, "nosuid"));

        /* Match with value from multiple options */
        value = mfree(value);
        r = fstab_filter_options("size=100,size=200", "size\0", NULL, &value, NULL, NULL);
        assert_se(r > 0);
        /* Returns the last value */
        assert_se(streq(value, "200"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
