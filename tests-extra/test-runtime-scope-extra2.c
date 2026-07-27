/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "runtime-scope.h"
#include "tests.h"

TEST(runtime_scope_to_from_string) {
        ASSERT_STREQ(runtime_scope_to_string(RUNTIME_SCOPE_SYSTEM), "system");
        ASSERT_STREQ(runtime_scope_to_string(RUNTIME_SCOPE_USER), "user");
        ASSERT_STREQ(runtime_scope_to_string(RUNTIME_SCOPE_GLOBAL), "global");

        ASSERT_EQ(runtime_scope_from_string("system"), RUNTIME_SCOPE_SYSTEM);
        ASSERT_EQ(runtime_scope_from_string("user"), RUNTIME_SCOPE_USER);
        ASSERT_EQ(runtime_scope_from_string("global"), RUNTIME_SCOPE_GLOBAL);
        ASSERT_EQ(runtime_scope_from_string("invalid"), _RUNTIME_SCOPE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
