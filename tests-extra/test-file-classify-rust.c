/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C login-util.c session_id_valid vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"

/* C headers */
#include "login-util.h"

/* Rust FFI */
#include "rust/file_classify.h"

/* RUST-CONTRACT: session-id-valid */
/* -- session_id_valid ------------------------------------------------------- */

static void test_session_id_valid(void) {
        /* Valid session IDs */
        assert_se(session_id_valid("c1") == rs_session_id_valid("c1"));
        assert_se(session_id_valid("c1") == true);

        assert_se(session_id_valid("1") == rs_session_id_valid("1"));
        assert_se(session_id_valid("1") == true);

        assert_se(session_id_valid("session123") == rs_session_id_valid("session123"));
        assert_se(session_id_valid("session123") == true);

        assert_se(session_id_valid("abcABC123") == rs_session_id_valid("abcABC123"));
        assert_se(session_id_valid("abcABC123") == true);

        assert_se(session_id_valid("C") == rs_session_id_valid("C"));
        assert_se(session_id_valid("C") == true);

        assert_se(session_id_valid("a") == rs_session_id_valid("a"));
        assert_se(session_id_valid("a") == true);

        assert_se(session_id_valid("9") == rs_session_id_valid("9"));
        assert_se(session_id_valid("9") == true);

        /* Invalid session IDs */
        assert_se(session_id_valid("") == rs_session_id_valid(""));
        assert_se(session_id_valid("") == false);

        assert_se(session_id_valid("c1-x11") == rs_session_id_valid("c1-x11"));
        assert_se(session_id_valid("c1-x11") == false);

        assert_se(session_id_valid("session 1") == rs_session_id_valid("session 1"));
        assert_se(session_id_valid("session 1") == false);

        assert_se(session_id_valid("seat1/tty2") == rs_session_id_valid("seat1/tty2"));
        assert_se(session_id_valid("seat1/tty2") == false);

        assert_se(session_id_valid("_") == rs_session_id_valid("_"));
        assert_se(session_id_valid("_") == false);

        assert_se(session_id_valid("-") == rs_session_id_valid("-"));
        assert_se(session_id_valid("-") == false);

        assert_se(session_id_valid("session\t") == rs_session_id_valid("session\t"));
        assert_se(session_id_valid("session\t") == false);

        assert_se(session_id_valid("session\n") == rs_session_id_valid("session\n"));
        assert_se(session_id_valid("session\n") == false);

        static const char non_ascii[] = { 's', (char) 0xff, 0 };
        assert_se(session_id_valid(non_ascii) == rs_session_id_valid(non_ascii));
        assert_se(!session_id_valid(non_ascii));

        /* NULL */
        assert_se(session_id_valid(NULL) == rs_session_id_valid(NULL));
        assert_se(!session_id_valid(NULL));
}

int main(int argc, char **argv) {
        test_session_id_valid();
        return 0;
}
