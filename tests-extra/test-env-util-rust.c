/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C env-util validators vs Rust rs_env_util validators */

/* RUST-CONTRACT: env-util-validators */

#include <string.h>

#include "env-util.h"
#include "rust/env_util.h"

/* ── env_name_is_valid ────────────────────────────────────────────────── */

static void test_env_name_is_valid(void) {
        assert_se(env_name_is_valid("FOO") == rs_env_name_is_valid("FOO"));
        assert_se(env_name_is_valid("FOO_BAR") == rs_env_name_is_valid("FOO_BAR"));
        assert_se(env_name_is_valid("FOO123") == rs_env_name_is_valid("FOO123"));
        assert_se(env_name_is_valid("") == rs_env_name_is_valid(""));
        assert_se(env_name_is_valid("1FOO") == rs_env_name_is_valid("1FOO"));
        assert_se(env_name_is_valid("FOO-BAR") == rs_env_name_is_valid("FOO-BAR"));
        assert_se(env_name_is_valid("FOO.BAR") == rs_env_name_is_valid("FOO.BAR"));
        assert_se(env_name_is_valid(NULL) == rs_env_name_is_valid(NULL));
}

/* ── env_value_is_valid ───────────────────────────────────────────────── */

static void test_env_value_is_valid(void) {
        static const char invalid_utf8[] = { 'x', (char) 0xC0, (char) 0x80, 0 };

        assert_se(env_value_is_valid("hello") == rs_env_value_is_valid("hello"));
        assert_se(env_value_is_valid("") == rs_env_value_is_valid(""));
        assert_se(env_value_is_valid(invalid_utf8) == rs_env_value_is_valid(invalid_utf8));
        assert_se(env_value_is_valid(NULL) == rs_env_value_is_valid(NULL));
}

/* ── env_assignment_is_valid ──────────────────────────────────────────── */

static void test_env_assignment_is_valid(void) {
        static const char invalid_utf8[] = { 'F', 'O', 'O', '=', (char) 0xF5, 0 };

        assert_se(env_assignment_is_valid("FOO=bar") == rs_env_assignment_is_valid("FOO=bar"));
        assert_se(env_assignment_is_valid("FOO=") == rs_env_assignment_is_valid("FOO="));
        assert_se(env_assignment_is_valid("FOO") == rs_env_assignment_is_valid("FOO"));
        assert_se(env_assignment_is_valid("=bar") == rs_env_assignment_is_valid("=bar"));
        assert_se(env_assignment_is_valid("") == rs_env_assignment_is_valid(""));
        assert_se(env_assignment_is_valid("1FOO=bar") == rs_env_assignment_is_valid("1FOO=bar"));
        assert_se(env_assignment_is_valid("FOO_BAR=hello") == rs_env_assignment_is_valid("FOO_BAR=hello"));
        assert_se(env_assignment_is_valid(invalid_utf8) == rs_env_assignment_is_valid(invalid_utf8));
        assert_se(rs_env_assignment_is_valid(NULL) == false); /* C asserts for this invalid call. */
}

/* ── strv_env_is_valid ────────────────────────────────────────────────── */

static void test_strv_env_is_valid(void) {
        char *valid[] = { (char*)"A=1", (char*)"B=2", (char*)"C=3", NULL };
        char *dup[] = { (char*)"A=1", (char*)"A=2", NULL };
        char *invalid[] = { (char*)"A=1", (char*)"=bad", NULL };
        char *empty[] = { NULL };

        assert_se(strv_env_is_valid(valid) == rs_strv_env_is_valid(valid));
        assert_se(strv_env_is_valid(dup) == rs_strv_env_is_valid(dup));
        assert_se(strv_env_is_valid(invalid) == rs_strv_env_is_valid(invalid));
        assert_se(strv_env_is_valid(empty) == rs_strv_env_is_valid(empty));
        assert_se(strv_env_is_valid(NULL) == rs_strv_env_is_valid(NULL));
}

/* ── strv_env_name_is_valid ─────────────────────────────────────────────── */

static void test_strv_env_name_is_valid(void) {
        char *valid[] = { (char*)"FOO", (char*)"BAR", NULL };
        char *dup[] = { (char*)"FOO", (char*)"FOO", NULL };
        char *invalid[] = { (char*)"FOO", (char*)"1BAR", NULL };
        char *empty[] = { NULL };

        assert_se(strv_env_name_is_valid(valid) == rs_strv_env_name_is_valid(valid));
        assert_se(strv_env_name_is_valid(dup) == rs_strv_env_name_is_valid(dup));
        assert_se(strv_env_name_is_valid(invalid) == rs_strv_env_name_is_valid(invalid));
        assert_se(strv_env_name_is_valid(empty) == rs_strv_env_name_is_valid(empty));
        assert_se(strv_env_name_is_valid(NULL) == rs_strv_env_name_is_valid(NULL));
}

/* ── strv_env_name_or_assignment_is_valid ──────────────────────────────── */

static void test_strv_env_name_or_assignment_is_valid(void) {
        char *valid[] = { (char*)"FOO", (char*)"BAR=1", NULL };
        char *dup[] = { (char*)"FOO", (char*)"FOO", NULL };
        char *invalid[] = { (char*)"FOO", (char*)"=bad", NULL };
        char *empty[] = { NULL };

        assert_se(strv_env_name_or_assignment_is_valid(valid) == rs_strv_env_name_or_assignment_is_valid(valid));
        assert_se(strv_env_name_or_assignment_is_valid(dup) == rs_strv_env_name_or_assignment_is_valid(dup));
        assert_se(strv_env_name_or_assignment_is_valid(invalid) == rs_strv_env_name_or_assignment_is_valid(invalid));
        assert_se(strv_env_name_or_assignment_is_valid(empty) == rs_strv_env_name_or_assignment_is_valid(empty));
        assert_se(strv_env_name_or_assignment_is_valid(NULL) == rs_strv_env_name_or_assignment_is_valid(NULL));
}

/* ── Main ──────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_env_name_is_valid();
        test_env_value_is_valid();
        test_env_assignment_is_valid();
        test_strv_env_is_valid();
        test_strv_env_name_is_valid();
        test_strv_env_name_or_assignment_is_valid();

        return 0;
}
