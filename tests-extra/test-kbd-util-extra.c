/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "kbd-util.h"
#include "tests.h"

TEST(keymap_is_valid) {
        assert_se(keymap_is_valid("us"));
        assert_se(keymap_is_valid("dvorak"));
        assert_se(keymap_is_valid("de-latin1"));
        assert_se(keymap_is_valid("uk"));
        assert_se(keymap_is_valid("colemak"));

        /* Invalid: empty */
        assert_se(!keymap_is_valid(""));

        /* Invalid: too long */
        char long_name[200];
        memset(long_name, 'a', sizeof(long_name) - 1);
        long_name[sizeof(long_name) - 1] = '\0';
        assert_se(!keymap_is_valid(long_name));

        /* Invalid: contains slash */
        assert_se(!keymap_is_valid("foo/bar"));

        /* Invalid: contains dot */
        assert_se(!keymap_is_valid("."));
        assert_se(!keymap_is_valid(".."));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
