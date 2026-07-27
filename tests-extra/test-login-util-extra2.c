/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "login-util.h"
#include "string-util.h"
#include "tests.h"

TEST(session_id_valid_basic) {
        assert_se(session_id_valid("1"));
        assert_se(session_id_valid("42"));
        assert_se(session_id_valid("c1"));
        assert_se(session_id_valid("c123456"));
        assert_se(!session_id_valid(""));
        assert_se(!session_id_valid(NULL));
}

TEST(logind_running_basic) {
        /* Just call it, result depends on environment */
        (void) logind_running();
}

DEFINE_TEST_MAIN(LOG_DEBUG);
