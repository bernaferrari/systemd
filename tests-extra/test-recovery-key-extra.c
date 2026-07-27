/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "recovery-key.h"
#include "tests.h"

TEST(decode_modhex_char_basic) {
        /* The modhex alphabet is: cbdefghijklnrtuv (index 0-15) */
        assert_se(decode_modhex_char('c') == 0);
        assert_se(decode_modhex_char('b') == 1);
        assert_se(decode_modhex_char('d') == 2);
        assert_se(decode_modhex_char('e') == 3);
        assert_se(decode_modhex_char('f') == 4);
        assert_se(decode_modhex_char('v') == 15);

        /* Uppercase should also work */
        assert_se(decode_modhex_char('C') == 0);
        assert_se(decode_modhex_char('V') == 15);

        /* Invalid characters */
        assert_se(decode_modhex_char('a') == -EINVAL);
        assert_se(decode_modhex_char('z') == -EINVAL);
        assert_se(decode_modhex_char('0') == -EINVAL);
        assert_se(decode_modhex_char('9') == -EINVAL);
}

TEST(normalize_recovery_key_basic) {
        _cleanup_free_ char *ret = NULL;

        /* Wrong length */
        assert_se(normalize_recovery_key("short", &ret) == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
