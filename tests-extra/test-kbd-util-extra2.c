/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "kbd-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(keymap_is_valid) {
        /* Valid keymap names */
        assert_se(keymap_is_valid("us"));
        assert_se(keymap_is_valid("dvorak"));
        assert_se(keymap_is_valid("de-latin1"));
        assert_se(keymap_is_valid("en.UTF-8"));

        /* Invalid: empty */
        assert_se(!keymap_is_valid(""));
        assert_se(!keymap_is_valid(NULL));

        /* Invalid: too long (>= 128 chars) */
        char too_long[130];
        memset(too_long, 'a', 129);
        too_long[129] = '\0';
        assert_se(!keymap_is_valid(too_long));
}

TEST(keymap_directories) {
        _cleanup_strv_free_ char **dirs = NULL;
        int r;

        /* Without env override, returns default dirs */
        assert_se(unsetenv("SYSTEMD_KEYMAP_DIRECTORIES") >= 0);
        r = keymap_directories(&dirs);
        assert_se(r >= 0);
        assert_se(!strv_isempty(dirs));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
