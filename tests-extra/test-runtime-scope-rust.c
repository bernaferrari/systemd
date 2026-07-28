/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C runtime-scope vs Rust rs_runtime_scope */
/* RUST-CONTRACT: runtime-scope-name */
/* RUST-CONTRACT: runtime-scope-parse */
/* RUST-CONTRACT: runtime-scope-command-line-option */
/* RUST-CONTRACT: runtime-scope-socket-mode */

#include <string.h>
#include <sys/stat.h>

#include "runtime-scope.h"
#include "string-util.h"
#include "rust/runtime_scope.h"

/* ── runtime_scope_to_string / from_string ────────────────────────────── */

static void test_runtime_scope_lookup(void) {
        int c_ret, r_ret;
        const char *c_str, *r_str;

        /* All valid scopes */
        for (int i = 0; i < _RUNTIME_SCOPE_MAX; i++) {
                c_str = runtime_scope_to_string(i);
                r_str = rs_runtime_scope_to_string(i);
                assert_se(c_str != NULL);
                assert_se(r_str != NULL);
                assert_se(streq(c_str, r_str));
        }

        /* Invalid */
        assert_se(runtime_scope_to_string(-1) == NULL);
        assert_se(rs_runtime_scope_to_string(-1) == NULL);
        assert_se(runtime_scope_to_string(_RUNTIME_SCOPE_MAX) == NULL);
        assert_se(rs_runtime_scope_to_string(_RUNTIME_SCOPE_MAX) == NULL);

        /* from_string */
        assert_se(runtime_scope_from_string("system") == RUNTIME_SCOPE_SYSTEM);
        assert_se(rs_runtime_scope_from_string("system") == RUNTIME_SCOPE_SYSTEM);
        assert_se(runtime_scope_from_string("user") == RUNTIME_SCOPE_USER);
        assert_se(rs_runtime_scope_from_string("user") == RUNTIME_SCOPE_USER);
        assert_se(runtime_scope_from_string("global") == RUNTIME_SCOPE_GLOBAL);
        assert_se(rs_runtime_scope_from_string("global") == RUNTIME_SCOPE_GLOBAL);

        /* Case sensitive */
        assert_se(runtime_scope_from_string("System") < 0);
        assert_se(rs_runtime_scope_from_string("System") < 0);

        /* Invalid */
        assert_se(runtime_scope_from_string(NULL) < 0);
        assert_se(rs_runtime_scope_from_string(NULL) < 0);
        assert_se(runtime_scope_from_string("invalid") < 0);
        assert_se(rs_runtime_scope_from_string("invalid") < 0);

        /* Round-trip */
        for (int i = 0; i < _RUNTIME_SCOPE_MAX; i++) {
                c_ret = runtime_scope_from_string(runtime_scope_to_string(i));
                r_ret = rs_runtime_scope_from_string(rs_runtime_scope_to_string(i));
                assert_se(c_ret == i);
                assert_se(r_ret == i);
        }
}

/* ── runtime_scope_cmdline_option_to_string ───────────────────────────── */

static void test_runtime_scope_cmdline(void) {
        assert_se(streq(runtime_scope_cmdline_option_to_string(RUNTIME_SCOPE_SYSTEM), "--system"));
        assert_se(streq(rs_runtime_scope_cmdline_option_to_string(RUNTIME_SCOPE_SYSTEM), "--system"));
        assert_se(streq(runtime_scope_cmdline_option_to_string(RUNTIME_SCOPE_USER), "--user"));
        assert_se(streq(rs_runtime_scope_cmdline_option_to_string(RUNTIME_SCOPE_USER), "--user"));
        assert_se(streq(runtime_scope_cmdline_option_to_string(RUNTIME_SCOPE_GLOBAL), "--global"));
        assert_se(streq(rs_runtime_scope_cmdline_option_to_string(RUNTIME_SCOPE_GLOBAL), "--global"));

        assert_se(runtime_scope_cmdline_option_to_string(-1) == NULL);
        assert_se(rs_runtime_scope_cmdline_option_to_string(-1) == NULL);
        assert_se(runtime_scope_cmdline_option_to_string(_RUNTIME_SCOPE_MAX) == NULL);
        assert_se(rs_runtime_scope_cmdline_option_to_string(_RUNTIME_SCOPE_MAX) == NULL);
}

/* ── runtime_scope_to_socket_mode ──────────────────────────────────────── */

static void test_runtime_scope_socket_mode(void) {
        mode_t c_ret, r_ret;

        c_ret = runtime_scope_to_socket_mode(RUNTIME_SCOPE_SYSTEM);
        r_ret = (mode_t) rs_runtime_scope_to_socket_mode(RUNTIME_SCOPE_SYSTEM);
        assert_se(c_ret == 0666);
        assert_se(r_ret == 0666);

        c_ret = runtime_scope_to_socket_mode(RUNTIME_SCOPE_USER);
        r_ret = (mode_t) rs_runtime_scope_to_socket_mode(RUNTIME_SCOPE_USER);
        assert_se(c_ret == 0600);
        assert_se(r_ret == 0600);

        c_ret = runtime_scope_to_socket_mode(RUNTIME_SCOPE_GLOBAL);
        r_ret = (mode_t) rs_runtime_scope_to_socket_mode(RUNTIME_SCOPE_GLOBAL);
        assert_se(c_ret == MODE_INVALID);
        assert_se(r_ret == MODE_INVALID);

        c_ret = runtime_scope_to_socket_mode(42);
        r_ret = (mode_t) rs_runtime_scope_to_socket_mode(42);
        assert_se(c_ret == MODE_INVALID);
        assert_se(r_ret == MODE_INVALID);
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_runtime_scope_lookup();
        test_runtime_scope_cmdline();
        test_runtime_scope_socket_mode();

        return 0;
}
