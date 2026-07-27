/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "runtime-scope.h"
#include "tests.h"

TEST(runtime_scope_to_string) {
        ASSERT_STREQ(runtime_scope_to_string(RUNTIME_SCOPE_SYSTEM), "system");
        ASSERT_STREQ(runtime_scope_to_string(RUNTIME_SCOPE_USER), "user");
        ASSERT_STREQ(runtime_scope_to_string(RUNTIME_SCOPE_GLOBAL), "global");
}

TEST(runtime_scope_from_string) {
        ASSERT_EQ(runtime_scope_from_string("system"), RUNTIME_SCOPE_SYSTEM);
        ASSERT_EQ(runtime_scope_from_string("user"), RUNTIME_SCOPE_USER);
        ASSERT_EQ(runtime_scope_from_string("global"), RUNTIME_SCOPE_GLOBAL);
        ASSERT_EQ(runtime_scope_from_string("invalid"), _RUNTIME_SCOPE_INVALID);
}

TEST(runtime_scope_cmdline_option_to_string) {
        ASSERT_STREQ(runtime_scope_cmdline_option_to_string(RUNTIME_SCOPE_SYSTEM), "--system");
        ASSERT_STREQ(runtime_scope_cmdline_option_to_string(RUNTIME_SCOPE_USER), "--user");
        ASSERT_STREQ(runtime_scope_cmdline_option_to_string(RUNTIME_SCOPE_GLOBAL), "--global");
}

TEST(runtime_scope_to_socket_mode) {
        ASSERT_EQ(runtime_scope_to_socket_mode(RUNTIME_SCOPE_SYSTEM), (mode_t)0666);
        ASSERT_EQ(runtime_scope_to_socket_mode(RUNTIME_SCOPE_USER), (mode_t)0600);
        ASSERT_EQ(runtime_scope_to_socket_mode(RUNTIME_SCOPE_GLOBAL), MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
