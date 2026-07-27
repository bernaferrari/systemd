/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C terminal-util vs Rust rs_terminal_util */

#include "terminal-util.h"
#include "rust/terminal_util.h"
#include "tests.h"

/* ── tty_is_vc ────────────────────────────────────────────────────────── */

static void test_tty_is_vc(void) {
        bool cr, rr;

        cr = tty_is_vc("tty0");
        rr = rs_tty_is_vc("tty0");
        assert_se(cr == rr);
        assert_se(cr == true);

        cr = tty_is_vc("tty7");
        rr = rs_tty_is_vc("tty7");
        assert_se(cr == rr);
        assert_se(cr == true);

        cr = tty_is_vc("/dev/tty0");
        rr = rs_tty_is_vc("/dev/tty0");
        assert_se(cr == rr);
        assert_se(cr == true);

        cr = tty_is_vc("/dev/tty63");
        rr = rs_tty_is_vc("/dev/tty63");
        assert_se(cr == rr);
        assert_se(cr == true);

        /* Not a VC */
        cr = tty_is_vc("console");
        rr = rs_tty_is_vc("console");
        assert_se(cr == rr);
        assert_se(cr == false);

        cr = tty_is_vc("pts/0");
        rr = rs_tty_is_vc("pts/0");
        assert_se(cr == rr);
        assert_se(cr == false);

        cr = tty_is_vc("ttyS0");
        rr = rs_tty_is_vc("ttyS0");
        assert_se(cr == rr);
        assert_se(cr == false);

        cr = tty_is_vc("/dev/ttyS0");
        rr = rs_tty_is_vc("/dev/ttyS0");
        assert_se(cr == rr);
        assert_se(cr == false);

        /* Empty */
        cr = tty_is_vc("");
        rr = rs_tty_is_vc("");
        assert_se(cr == rr);
        assert_se(cr == false);
}

/* ── tty_is_console ───────────────────────────────────────────────────── */

static void test_tty_is_console(void) {
        bool cr, rr;

        cr = tty_is_console("console");
        rr = rs_tty_is_console("console");
        assert_se(cr == rr);
        assert_se(cr == true);

        cr = tty_is_console("/dev/console");
        rr = rs_tty_is_console("/dev/console");
        assert_se(cr == rr);
        assert_se(cr == true);

        /* Not console */
        cr = tty_is_console("tty0");
        rr = rs_tty_is_console("tty0");
        assert_se(cr == rr);
        assert_se(cr == false);

        cr = tty_is_console("tty1");
        rr = rs_tty_is_console("tty1");
        assert_se(cr == rr);
        assert_se(cr == false);

        cr = tty_is_console("/dev/tty0");
        rr = rs_tty_is_console("/dev/tty0");
        assert_se(cr == rr);
        assert_se(cr == false);

        cr = tty_is_console("pts/0");
        rr = rs_tty_is_console("pts/0");
        assert_se(cr == rr);
        assert_se(cr == false);

        /* Empty */
        cr = tty_is_console("");
        rr = rs_tty_is_console("");
        assert_se(cr == rr);
        assert_se(cr == false);
}

/* ── vtnr_from_tty ────────────────────────────────────────────────────── */

static void test_vtnr_from_tty(void) {
        int cr, rr;

        /* Valid */
        cr = vtnr_from_tty("tty1");
        rr = rs_vtnr_from_tty("tty1");
        assert_se(cr == rr);
        assert_se(cr == 1);

        cr = vtnr_from_tty("tty7");
        rr = rs_vtnr_from_tty("tty7");
        assert_se(cr == rr);
        assert_se(cr == 7);

        cr = vtnr_from_tty("tty63");
        rr = rs_vtnr_from_tty("tty63");
        assert_se(cr == rr);
        assert_se(cr == 63);

        /* With /dev/ prefix */
        cr = vtnr_from_tty("/dev/tty1");
        rr = rs_vtnr_from_tty("/dev/tty1");
        assert_se(cr == rr);
        assert_se(cr == 1);

        /* Out of range: 0 */
        cr = vtnr_from_tty("tty0");
        rr = rs_vtnr_from_tty("tty0");
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* Out of range: 64 */
        cr = vtnr_from_tty("tty64");
        rr = rs_vtnr_from_tty("tty64");
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* Out of range: 999 */
        cr = vtnr_from_tty("tty999");
        rr = rs_vtnr_from_tty("tty999");
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* Not a tty name */
        cr = vtnr_from_tty("console");
        rr = rs_vtnr_from_tty("console");
        assert_se(cr == rr);
        assert_se(cr < 0);

        cr = vtnr_from_tty("ttyS0");
        rr = rs_vtnr_from_tty("ttyS0");
        assert_se(cr == rr);
        assert_se(cr < 0);

        cr = vtnr_from_tty("pts/0");
        rr = rs_vtnr_from_tty("pts/0");
        assert_se(cr == rr);
        assert_se(cr < 0);
}

int main(int argc, char **argv) {
        test_tty_is_vc();
        test_tty_is_console();
        test_vtnr_from_tty();
        return 0;
}
