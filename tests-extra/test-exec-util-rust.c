/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C exec_command_flags_to/from_string vs Rust */

#include "tests.h"
#include "exec-util.h"
#include "strv.h"
#include "rust/exec_util.h"

static void test_exec_command_flags_to_string(void) {
        const char *cr, *rr;

        /* Valid single flags */
        cr = exec_command_flags_to_string(EXEC_COMMAND_IGNORE_FAILURE);
        rr = rs_exec_command_flags_to_string(EXEC_COMMAND_IGNORE_FAILURE);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "ignore-failure"));

        cr = exec_command_flags_to_string(EXEC_COMMAND_FULLY_PRIVILEGED);
        rr = rs_exec_command_flags_to_string(EXEC_COMMAND_FULLY_PRIVILEGED);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "privileged"));

        cr = exec_command_flags_to_string(EXEC_COMMAND_NO_SETUID);
        rr = rs_exec_command_flags_to_string(EXEC_COMMAND_NO_SETUID);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cr = exec_command_flags_to_string(EXEC_COMMAND_NO_ENV_EXPAND);
        rr = rs_exec_command_flags_to_string(EXEC_COMMAND_NO_ENV_EXPAND);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cr = exec_command_flags_to_string(EXEC_COMMAND_VIA_SHELL);
        rr = rs_exec_command_flags_to_string(EXEC_COMMAND_VIA_SHELL);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        /* Invalid: multiple bits set */
        cr = exec_command_flags_to_string(EXEC_COMMAND_IGNORE_FAILURE | EXEC_COMMAND_FULLY_PRIVILEGED);
        rr = rs_exec_command_flags_to_string(EXEC_COMMAND_IGNORE_FAILURE | EXEC_COMMAND_FULLY_PRIVILEGED);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Invalid: zero */
        cr = exec_command_flags_to_string(0);
        rr = rs_exec_command_flags_to_string(0);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Invalid: out of range */
        cr = exec_command_flags_to_string(1 << 5);
        rr = rs_exec_command_flags_to_string(1 << 5);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Invalid: negative (errno range) */
        cr = exec_command_flags_to_string(-EINVAL);
        rr = rs_exec_command_flags_to_string(-EINVAL);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Invalid: negative */
        cr = exec_command_flags_to_string(-1);
        rr = rs_exec_command_flags_to_string(-1);
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

static void test_exec_command_flags_from_string(void) {
        int cr, rr;

        /* Valid strings */
        cr = exec_command_flags_from_string("ignore-failure");
        rr = rs_exec_command_flags_from_string("ignore-failure");
        assert_se(cr == rr);
        assert_se(cr == EXEC_COMMAND_IGNORE_FAILURE);

        cr = exec_command_flags_from_string("privileged");
        rr = rs_exec_command_flags_from_string("privileged");
        assert_se(cr == rr);
        assert_se(cr == EXEC_COMMAND_FULLY_PRIVILEGED);

        cr = exec_command_flags_from_string("no-setuid");
        rr = rs_exec_command_flags_from_string("no-setuid");
        assert_se(cr == rr);
        assert_se(cr == EXEC_COMMAND_NO_SETUID);

        cr = exec_command_flags_from_string("no-env-expand");
        rr = rs_exec_command_flags_from_string("no-env-expand");
        assert_se(cr == rr);
        assert_se(cr == EXEC_COMMAND_NO_ENV_EXPAND);

        cr = exec_command_flags_from_string("via-shell");
        rr = rs_exec_command_flags_from_string("via-shell");
        assert_se(cr == rr);
        assert_se(cr == EXEC_COMMAND_VIA_SHELL);

        /* "ambient" compatibility — maps to 0 */
        cr = exec_command_flags_from_string("ambient");
        rr = rs_exec_command_flags_from_string("ambient");
        assert_se(cr == rr);
        assert_se(cr == 0);

        /* Invalid strings */
        cr = exec_command_flags_from_string("bogus");
        rr = rs_exec_command_flags_from_string("bogus");
        assert_se(cr == rr);
        assert_se(cr == _EXEC_COMMAND_FLAGS_INVALID);

        cr = exec_command_flags_from_string("");
        rr = rs_exec_command_flags_from_string("");
        assert_se(cr == rr);
        assert_se(cr == _EXEC_COMMAND_FLAGS_INVALID);

        cr = exec_command_flags_from_string("IGNORE-FAILURE");
        rr = rs_exec_command_flags_from_string("IGNORE-FAILURE");
        assert_se(cr == rr);
        assert_se(cr == _EXEC_COMMAND_FLAGS_INVALID);

        cr = exec_command_flags_from_string("ignore_failure");
        rr = rs_exec_command_flags_from_string("ignore_failure");
        assert_se(cr == rr);
        assert_se(cr == _EXEC_COMMAND_FLAGS_INVALID);
}

static void test_indent_embedded_newlines(void) {
        _cleanup_free_ char *result = NULL;
        int r;

        /* No newlines */
        r = rs_indent_embedded_newlines("hello world", &result);
        assert_se(r == 0);
        assert_se(streq(result, "hello world"));
        result = mfree(result);

        /* Single newline */
        r = rs_indent_embedded_newlines("line1\nline2", &result);
        assert_se(r == 0);
        assert_se(streq(result, "line1\n              line2"));
        result = mfree(result);

        /* Multiple newlines */
        r = rs_indent_embedded_newlines("a\nb\nc", &result);
        assert_se(r == 0);
        assert_se(streq(result, "a\n              b\n              c"));
        result = mfree(result);

        /* Empty string */
        r = rs_indent_embedded_newlines("", &result);
        assert_se(r == 0);
        assert_se(streq(result, ""));
        result = mfree(result);

        /* Trailing newline */
        r = rs_indent_embedded_newlines("line1\n", &result);
        assert_se(r == 0);
        assert_se(streq(result, "line1\n              "));
        result = mfree(result);

        /* Only newlines */
        r = rs_indent_embedded_newlines("\n\n", &result);
        assert_se(r == 0);
        assert_se(streq(result, "\n              \n              "));
        result = mfree(result);

        /* Realistic kernel cmdline with embedded newline */
        r = rs_indent_embedded_newlines("root=UUID=aaaa initrd=/initramfs\nquiet splash", &result);
        assert_se(r == 0);
        assert_se(streq(result,
                "root=UUID=aaaa initrd=/initramfs\n"
                "              quiet splash"));
        result = mfree(result);

        /* Indentation matches C's 14 spaces */
        r = rs_indent_embedded_newlines("x\ny", &result);
        assert_se(r == 0);
        /* After "x\n" there should be 14 spaces before "y" */
        assert_se(strlen(result) == 1 + 1 + 14 + 1); // "x" + "\n" + "              " + "y"
        assert_se(result[0] == 'x');
        assert_se(result[1] == '\n');
        assert_se(result[2] == ' ');
        assert_se(result[15] == ' ');
        assert_se(result[16] == 'y');
        result = mfree(result);
}

static void test_exec_command_flags_from_strv(void) {
        char * const opts1[] = { (char*)"ignore-failure", (char*)"privileged", NULL };
        char * const opts2[] = { (char*)"no-setuid", NULL };
        char * const opts3[] = { NULL };
        char * const opts4[] = { (char*)"bogus", NULL };
        char * const opts5[] = { (char*)"ambient", (char*)"no-env-expand", NULL };
        int c_flags, r_flags;
        int rc, rrs;

        /* Multiple flags */
        rc = exec_command_flags_from_strv(opts1, &c_flags);
        rrs = rs_exec_command_flags_from_strv(opts1, &r_flags);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_flags == r_flags);
        assert_se(c_flags == (EXEC_COMMAND_IGNORE_FAILURE | EXEC_COMMAND_FULLY_PRIVILEGED));

        /* Single flag */
        rc = exec_command_flags_from_strv(opts2, &c_flags);
        rrs = rs_exec_command_flags_from_strv(opts2, &r_flags);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_flags == r_flags);
        assert_se(c_flags == EXEC_COMMAND_NO_SETUID);

        /* Empty array */
        rc = exec_command_flags_from_strv(opts3, &c_flags);
        rrs = rs_exec_command_flags_from_strv(opts3, &r_flags);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_flags == r_flags);
        assert_se(c_flags == 0);

        /* Invalid flag */
        rc = exec_command_flags_from_strv(opts4, &c_flags);
        rrs = rs_exec_command_flags_from_strv(opts4, &r_flags);
        assert_se(rc == rrs);
        assert_se(rc < 0);

        /* "ambient" compatibility + valid flag */
        rc = exec_command_flags_from_strv(opts5, &c_flags);
        rrs = rs_exec_command_flags_from_strv(opts5, &r_flags);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_flags == r_flags);
        assert_se(c_flags == EXEC_COMMAND_NO_ENV_EXPAND);
}

static void test_exec_command_flags_to_strv(void) {
        _cleanup_strv_free_ char **c_opts = NULL, **r_opts = NULL;
        int rc, rrs;

        /* Single flag */
        rc = exec_command_flags_to_strv(EXEC_COMMAND_IGNORE_FAILURE, &c_opts);
        rrs = rs_exec_command_flags_to_strv(EXEC_COMMAND_IGNORE_FAILURE, &r_opts);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_opts && r_opts);
        assert_se(streq(c_opts[0], r_opts[0]));
        assert_se(streq(c_opts[0], "ignore-failure"));
        assert_se(c_opts[1] == NULL && r_opts[1] == NULL);
        c_opts = strv_free(c_opts);
        r_opts = strv_free(r_opts);

        /* Multiple flags */
        rc = exec_command_flags_to_strv(EXEC_COMMAND_FULLY_PRIVILEGED | EXEC_COMMAND_NO_SETUID, &c_opts);
        rrs = rs_exec_command_flags_to_strv(EXEC_COMMAND_FULLY_PRIVILEGED | EXEC_COMMAND_NO_SETUID, &r_opts);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        assert_se(c_opts && r_opts);
        assert_se(strv_length(c_opts) == strv_length(r_opts));
        assert_se(strv_length(c_opts) == 2);
        /* Order may vary, but both should have the same entries */
        assert_se(strv_contains(c_opts, "privileged"));
        assert_se(strv_contains(r_opts, "privileged"));
        assert_se(strv_contains(c_opts, "no-setuid"));
        assert_se(strv_contains(r_opts, "no-setuid"));
        c_opts = strv_free(c_opts);
        r_opts = strv_free(r_opts);

        /* Zero flags (empty) */
        rc = exec_command_flags_to_strv(0, &c_opts);
        rrs = rs_exec_command_flags_to_strv(0, &r_opts);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        /* Both return NULL for zero flags */
        assert_se(!c_opts && !r_opts);
}

int main(int argc, char **argv) {
        test_exec_command_flags_to_string();
        test_exec_command_flags_from_string();
        test_exec_command_flags_from_strv();
        test_exec_command_flags_to_strv();
        test_indent_embedded_newlines();
        return 0;
}
