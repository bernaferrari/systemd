/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exec-util.h"
#include "tests.h"

TEST(exec_command_flags_from_string_basic) {
        assert_se(exec_command_flags_from_string("ignore-failure") == EXEC_COMMAND_IGNORE_FAILURE);
        assert_se(exec_command_flags_from_string("privileged") == EXEC_COMMAND_FULLY_PRIVILEGED);
        assert_se(exec_command_flags_from_string("no-setuid") == EXEC_COMMAND_NO_SETUID);
        assert_se(exec_command_flags_from_string("no-env-expand") == EXEC_COMMAND_NO_ENV_EXPAND);
        assert_se(exec_command_flags_from_string("via-shell") == EXEC_COMMAND_VIA_SHELL);
        /* "ambient" is backward compat alias that maps to 0 */
        assert_se(exec_command_flags_from_string("ambient") == 0);
        assert_se(exec_command_flags_from_string("invalid") < 0);
}

TEST(exec_command_flags_to_string_basic) {
        /* exec_command_flags_to_string only works for single flags, not combined */
        assert_se(streq(exec_command_flags_to_string(EXEC_COMMAND_IGNORE_FAILURE), "ignore-failure"));
        assert_se(streq(exec_command_flags_to_string(EXEC_COMMAND_FULLY_PRIVILEGED), "privileged"));
        assert_se(streq(exec_command_flags_to_string(EXEC_COMMAND_NO_SETUID), "no-setuid"));
        assert_se(streq(exec_command_flags_to_string(EXEC_COMMAND_NO_ENV_EXPAND), "no-env-expand"));
        assert_se(streq(exec_command_flags_to_string(EXEC_COMMAND_VIA_SHELL), "via-shell"));

        /* Combined flags return NULL */
        assert_se(!exec_command_flags_to_string(EXEC_COMMAND_IGNORE_FAILURE|EXEC_COMMAND_FULLY_PRIVILEGED));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
