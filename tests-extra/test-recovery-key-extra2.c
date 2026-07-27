/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "recovery-key.h"
#include "string-util.h"
#include "tests.h"

TEST(decode_modhex_char) {
        /* modhex alphabet: c b d e f g h i j k l n r s t u v */
        assert_se(decode_modhex_char('c') == 0);
        assert_se(decode_modhex_char('b') == 1);
        assert_se(decode_modhex_char('v') >= 0);

        /* Uppercase */
        assert_se(decode_modhex_char('C') == 0);
        assert_se(decode_modhex_char('V') >= 0);

        /* Invalid */
        assert_se(decode_modhex_char('a') == -EINVAL);
        assert_se(decode_modhex_char('z') == -EINVAL);
        assert_se(decode_modhex_char('0') == -EINVAL);
        assert_se(decode_modhex_char('9') == -EINVAL);
}

TEST(normalize_recovery_key) {
        _cleanup_(erase_and_freep) char *ret = NULL;
        int r;

        /* Wrong length → -EINVAL */
        r = normalize_recovery_key("short", &ret);
        assert_se(r == -EINVAL);

        /* Valid: 64 modhex chars (no dashes) - use 'c'..'v' charset */
        char key_buf[65];
        memset(key_buf, 'c', 64);
        key_buf[64] = '\0';
        r = normalize_recovery_key(key_buf, &ret);
        assert_se(r >= 0);
        assert_se(ret != NULL);
        /* Dashes inserted at positions 8, 17, 26, 35, ... */
        assert_se(ret[8] == '-');
        assert_se(ret[35] == '-');
        erase_and_free(ret);
        ret = NULL;

        /* Invalid chars in key */
        r = normalize_recovery_key("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &ret);
        assert_se(r == -EINVAL);

        /* Wrong length string */
        r = normalize_recovery_key("ccc", &ret);
        assert_se(r == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
