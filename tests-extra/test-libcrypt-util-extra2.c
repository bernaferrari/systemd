/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libcrypt-util.h"
#include "string-util.h"
#include "tests.h"

TEST(looks_like_hashed_password) {
        /* Standard hashed passwords */
        assert_se(looks_like_hashed_password("$6$salt$hash"));
        assert_se(looks_like_hashed_password("$1$salt$hash"));
        assert_se(looks_like_hashed_password("$5$salt$hash"));
        assert_se(looks_like_hashed_password("randomhashstring"));

        /* Locked passwords (with "!" prefix) are still considered hashed */
        assert_se(looks_like_hashed_password("!$6$salt$hash"));
        assert_se(looks_like_hashed_password("!!$6$salt$hash"));
        assert_se(looks_like_hashed_password("!"));

        /* NULL → false */
        assert_se(!looks_like_hashed_password(NULL));

        /* "x" means shadow password, not a hash */
        assert_se(!looks_like_hashed_password("x"));

        /* "*" means no password, not a hash */
        assert_se(!looks_like_hashed_password("*"));

        /* Locked "x" and "*" still return false (lock prefix stripped, then check) */
        assert_se(!looks_like_hashed_password("!x"));
        assert_se(!looks_like_hashed_password("!*"));
        assert_se(!looks_like_hashed_password("!!x"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
