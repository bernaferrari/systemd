/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "exec-util.h"

TEST(exec_command_flags_to_from_string) {
        /* to_string */
        assert_se(streq(exec_command_flags_to_string(EXEC_COMMAND_NO_ENV_EXPAND), "no-env-expand"));
        assert_se(streq(exec_command_flags_to_string(EXEC_COMMAND_VIA_SHELL), "via-shell"));

        /* from_string */
        assert_se(exec_command_flags_from_string("no-env-expand") == EXEC_COMMAND_NO_ENV_EXPAND);
        assert_se(exec_command_flags_from_string("via-shell") == EXEC_COMMAND_VIA_SHELL);

        /* "ambient" compatibility alias → returns 0 (no bits) */
        assert_se(exec_command_flags_from_string("ambient") == 0);

        /* Invalid */
        assert_se(exec_command_flags_from_string("invalid") < 0);
}

TEST(exec_command_flags_from_strv) {
        ExecCommandFlags flags;
        char *opts[] = { (char*) "no-env-expand", (char*) "via-shell", NULL };

        assert_se(exec_command_flags_from_strv(opts, &flags) == 0);
        assert_se(FLAGS_SET(flags, EXEC_COMMAND_NO_ENV_EXPAND));
        assert_se(FLAGS_SET(flags, EXEC_COMMAND_VIA_SHELL));

        /* Empty strv → 0 flags */
        char *empty[] = { NULL };
        assert_se(exec_command_flags_from_strv(empty, &flags) == 0);
        assert_se(flags == 0);

        /* Invalid option */
        char *bad[] = { (char*) "nonexistent", NULL };
        assert_se(exec_command_flags_from_strv(bad, &flags) < 0);
}

TEST(exec_command_flags_to_strv) {
        _cleanup_strv_free_ char **opts = NULL;
        ExecCommandFlags flags = EXEC_COMMAND_NO_ENV_EXPAND | EXEC_COMMAND_VIA_SHELL;

        assert_se(exec_command_flags_to_strv(flags, &opts) == 0);
        assert_se(strv_length(opts) == 2);
        assert_se(strv_contains(opts, "no-env-expand"));
        assert_se(strv_contains(opts, "via-shell"));

        /* Zero flags → empty strv */
        opts = strv_free(opts);
        assert_se(exec_command_flags_to_strv(0, &opts) == 0);
        assert_se(strv_isempty(opts));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
