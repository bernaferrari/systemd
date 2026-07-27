/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "recovery-key.h"
#include "tests.h"

TEST(decode_modhex_char_basic) {
        /* Modhex alphabet: cbdefghijklnrtu */
        assert_se(decode_modhex_char('c') == 0);
        assert_se(decode_modhex_char('b') == 1);
        assert_se(decode_modhex_char('d') == 2);
        assert_se(decode_modhex_char('e') == 3);
        assert_se(decode_modhex_char('f') == 4);
        assert_se(decode_modhex_char('g') == 5);
        assert_se(decode_modhex_char('h') == 6);
        assert_se(decode_modhex_char('i') == 7);
        assert_se(decode_modhex_char('j') == 8);
        assert_se(decode_modhex_char('k') == 9);
        assert_se(decode_modhex_char('l') == 10);
        assert_se(decode_modhex_char('n') == 11);
        assert_se(decode_modhex_char('r') == 12);
        assert_se(decode_modhex_char('t') == 13);
        assert_se(decode_modhex_char('u') == 14);

        /* Uppercase should also work */
        assert_se(decode_modhex_char('C') == 0);
        assert_se(decode_modhex_char('B') == 1);
        assert_se(decode_modhex_char('U') == 14);

        /* Invalid character */
        assert_se(decode_modhex_char('a') == -EINVAL);
        assert_se(decode_modhex_char('z') == -EINVAL);
        assert_se(decode_modhex_char('0') == -EINVAL);
        assert_se(decode_modhex_char(' ') == -EINVAL);
}

TEST(normalize_recovery_key_basic) {
        _cleanup_free_ char *result = NULL;
        int r;

        /* Wrong length → -EINVAL */
        assert_se(normalize_recovery_key("abc", &result) == -EINVAL);
        assert_se(normalize_recovery_key("", &result) == -EINVAL);

        /* All valid modhex chars, RECOVERY_KEY_MODHEX_RAW_LENGTH*2 = 64 chars */
        /* We'll construct a valid key of the right length */
        char key[65];
        for (int i = 0; i < 64; i++)
                key[i] = "cbdefghijklnrtu"[i % 15];
        key[64] = '\0';

        r = normalize_recovery_key(key, &result);
        assert_se(r >= 0);
        assert_se(result != NULL);
        /* Result should contain dashes every 5 chars */
}

DEFINE_TEST_MAIN(LOG_DEBUG);
