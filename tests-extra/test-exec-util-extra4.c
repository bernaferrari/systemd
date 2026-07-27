/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exec-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(exec_command_flags_roundtrip) {
        assert_se(streq(exec_command_flags_to_string(EXEC_COMMAND_IGNORE_FAILURE), "ignore-failure"));
        assert_se(streq(exec_command_flags_to_string(EXEC_COMMAND_FULLY_PRIVILEGED), "privileged"));
        assert_se(streq(exec_command_flags_to_string(EXEC_COMMAND_NO_SETUID), "no-setuid"));
        assert_se(streq(exec_command_flags_to_string(EXEC_COMMAND_NO_ENV_EXPAND), "no-env-expand"));
        assert_se(streq(exec_command_flags_to_string(EXEC_COMMAND_VIA_SHELL), "via-shell"));

        assert_se(exec_command_flags_from_string("ignore-failure") == EXEC_COMMAND_IGNORE_FAILURE);
        assert_se(exec_command_flags_from_string("privileged") == EXEC_COMMAND_FULLY_PRIVILEGED);
        assert_se(exec_command_flags_from_string("no-setuid") == EXEC_COMMAND_NO_SETUID);
        assert_se(exec_command_flags_from_string("no-env-expand") == EXEC_COMMAND_NO_ENV_EXPAND);
        assert_se(exec_command_flags_from_string("via-shell") == EXEC_COMMAND_VIA_SHELL);

        /* "ambient" is a compat alias that maps to 0 */
        assert_se(exec_command_flags_from_string("ambient") == 0);

        /* Invalid */
        assert_se(exec_command_flags_from_string("invalid") == _EXEC_COMMAND_FLAGS_INVALID);
}

TEST(exec_command_flags_from_strv) {
        ExecCommandFlags flags = 0;
        int r;

        /* Single flag */
        r = exec_command_flags_from_strv(STRV_MAKE("ignore-failure"), &flags);
        assert_se(r >= 0);
        assert_se(flags == EXEC_COMMAND_IGNORE_FAILURE);

        /* Multiple flags */
        r = exec_command_flags_from_strv(
                        STRV_MAKE("ignore-failure", "no-env-expand", "via-shell"),
                        &flags);
        assert_se(r >= 0);
        assert_se(FLAGS_SET(flags, EXEC_COMMAND_IGNORE_FAILURE));
        assert_se(FLAGS_SET(flags, EXEC_COMMAND_NO_ENV_EXPAND));
        assert_se(FLAGS_SET(flags, EXEC_COMMAND_VIA_SHELL));

        /* Empty list */
        r = exec_command_flags_from_strv(STRV_MAKE(NULL), &flags);
        assert_se(r >= 0);
        assert_se(flags == 0);

        /* Invalid flag in list */
        r = exec_command_flags_from_strv(STRV_MAKE("invalid-flag"), &flags);
        assert_se(r < 0);
}

TEST(exec_command_flags_to_strv) {
        _cleanup_strv_free_ char **opts = NULL;
        int r;

        r = exec_command_flags_to_strv(EXEC_COMMAND_IGNORE_FAILURE, &opts);
        assert_se(r >= 0);
        assert_se(strv_length(opts) == 1);
        assert_se(streq(opts[0], "ignore-failure"));

        opts = strv_free(opts);
        r = exec_command_flags_to_strv(
                        EXEC_COMMAND_IGNORE_FAILURE | EXEC_COMMAND_VIA_SHELL,
                        &opts);
        assert_se(r >= 0);
        assert_se(strv_length(opts) == 2);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
