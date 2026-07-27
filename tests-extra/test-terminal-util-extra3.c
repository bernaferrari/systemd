/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "terminal-util.h"
#include "tests.h"

TEST(osc_char_is_valid_basic) {
        /* Valid: ASCII 32-126 (printable, non-DEL) */
        assert_se(osc_char_is_valid(' '));
        assert_se(osc_char_is_valid('A'));
        assert_se(osc_char_is_valid('z'));
        assert_se(osc_char_is_valid('0'));
        assert_se(osc_char_is_valid('~'));
        assert_se(osc_char_is_valid(126));  /* last valid */

        /* Invalid: control chars and DEL */
        assert_se(!osc_char_is_valid(0));
        assert_se(!osc_char_is_valid(31));
        assert_se(!osc_char_is_valid(127));
        assert_se(!osc_char_is_valid('\n'));
        assert_se(!osc_char_is_valid('\t'));
        assert_se(!osc_char_is_valid('\x1b'));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
