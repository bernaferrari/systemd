/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C terminal-util vs Rust rs_terminal_util */

#include <errno.h>
#include <string.h>

#include "terminal-util.h"
#include "rust/terminal_util.h"
#include "tests.h"

/* ── tty_is_vc ────────────────────────────────────────────────────────── */
/* RUST-CONTRACT: terminal-tty-vc */

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

        /* safe_atou() accepts base-zero forms, leading whitespace, and '+' */
        cr = tty_is_vc("tty010");
        rr = rs_tty_is_vc("tty010");
        assert_se(cr == rr);
        assert_se(cr == true);

        cr = tty_is_vc("tty0x3f");
        rr = rs_tty_is_vc("tty0x3f");
        assert_se(cr == rr);
        assert_se(cr == true);

        cr = tty_is_vc("tty0b111");
        rr = rs_tty_is_vc("tty0b111");
        assert_se(cr == rr);
        assert_se(cr == true);

        cr = tty_is_vc("tty0o10");
        rr = rs_tty_is_vc("tty0o10");
        assert_se(cr == rr);
        assert_se(cr == true);

        cr = tty_is_vc("tty+7");
        rr = rs_tty_is_vc("tty+7");
        assert_se(cr == rr);
        assert_se(cr == true);

        cr = tty_is_vc("tty\t7");
        rr = rs_tty_is_vc("tty\t7");
        assert_se(cr == rr);
        assert_se(cr == true);

        cr = tty_is_vc("tty\v7");
        rr = rs_tty_is_vc("tty\v7");
        assert_se(cr == rr);
        assert_se(cr == false);

        /* path_startswith() makes the /dev prefix component-aware */
        cr = tty_is_vc("//dev//tty7");
        rr = rs_tty_is_vc("//dev//tty7");
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

        cr = tty_is_vc("tty7junk");
        rr = rs_tty_is_vc("tty7junk");
        assert_se(cr == rr);
        assert_se(cr == false);

        cr = tty_is_vc("tty09");
        rr = rs_tty_is_vc("tty09");
        assert_se(cr == rr);
        assert_se(cr == false);

        cr = tty_is_vc("tty4294967296");
        rr = rs_tty_is_vc("tty4294967296");
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
/* RUST-CONTRACT: terminal-tty-console */

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

        cr = tty_is_console("//dev//console");
        rr = rs_tty_is_console("//dev//console");
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
/* RUST-CONTRACT: terminal-vtnr-from-tty */

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

        cr = vtnr_from_tty("tty010");
        rr = rs_vtnr_from_tty("tty010");
        assert_se(cr == rr);
        assert_se(cr == 8);

        cr = vtnr_from_tty("tty0x3f");
        rr = rs_vtnr_from_tty("tty0x3f");
        assert_se(cr == rr);
        assert_se(cr == 63);

        cr = vtnr_from_tty("tty0b111");
        rr = rs_vtnr_from_tty("tty0b111");
        assert_se(cr == rr);
        assert_se(cr == 7);

        cr = vtnr_from_tty("tty0o10");
        rr = rs_vtnr_from_tty("tty0o10");
        assert_se(cr == rr);
        assert_se(cr == 8);

        cr = vtnr_from_tty("tty+7");
        rr = rs_vtnr_from_tty("tty+7");
        assert_se(cr == rr);
        assert_se(cr == 7);

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

        cr = vtnr_from_tty("tty-0");
        rr = rs_vtnr_from_tty("tty-0");
        assert_se(cr == rr);
        assert_se(cr == -ERANGE);

        cr = vtnr_from_tty("tty7junk");
        rr = rs_vtnr_from_tty("tty7junk");
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

        cr = vtnr_from_tty("tty09");
        rr = rs_vtnr_from_tty("tty09");
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

        cr = vtnr_from_tty("tty\v7");
        rr = rs_vtnr_from_tty("tty\v7");
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

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

/* `url_suitable_for_osc8()` is deliberately static upstream. Keep this local
 * reference byte-for-byte aligned with pretty-print.c so the Rust-facing ABI
 * still has a C policy comparator without changing production linkage. */
static bool url_suitable_for_osc8(const char *url) {
        if (strlen(url) > 2000)
                return false;

        for (const char *c = url; *c; c++)
                if (!osc_char_is_valid(*c))
                        return false;

        return true;
}

static void test_osc8_helpers(void) {
        /* RUST-CONTRACT: terminal-osc-char */
        assert_se(osc_char_is_valid(' ') == rs_osc_char_is_valid(' '));
        assert_se(osc_char_is_valid('~') == rs_osc_char_is_valid('~'));
        assert_se(osc_char_is_valid(0x1f) == rs_osc_char_is_valid(0x1f));
        assert_se(osc_char_is_valid(0x7f) == rs_osc_char_is_valid(0x7f));
        assert_se(osc_char_is_valid((char) 0x80) == rs_osc_char_is_valid((char) 0x80));

        /* RUST-CONTRACT: terminal-vtnr-valid */
        assert_se(vtnr_is_valid(1) == rs_vtnr_is_valid(1));
        assert_se(vtnr_is_valid(63) == rs_vtnr_is_valid(63));
        assert_se(vtnr_is_valid(0) == rs_vtnr_is_valid(0));
        assert_se(vtnr_is_valid(64) == rs_vtnr_is_valid(64));

        /* RUST-CONTRACT: terminal-osc8-url */
        assert_se(url_suitable_for_osc8("https://example.com/path?q=1&b=2") == rs_url_suitable_for_osc8("https://example.com/path?q=1&b=2"));
        assert_se(url_suitable_for_osc8("") == rs_url_suitable_for_osc8(""));
        assert_se(url_suitable_for_osc8("https://example.com/\n") == rs_url_suitable_for_osc8("https://example.com/\n"));
        assert_se(url_suitable_for_osc8("https://example.com/\x7f") == rs_url_suitable_for_osc8("https://example.com/\x7f"));
        assert_se(url_suitable_for_osc8("https://example.com/\x80") == rs_url_suitable_for_osc8("https://example.com/\x80"));
}

int main(int argc, char **argv) {
        test_tty_is_vc();
        test_tty_is_console();
        test_vtnr_from_tty();
        test_osc8_helpers();
        return 0;
}
