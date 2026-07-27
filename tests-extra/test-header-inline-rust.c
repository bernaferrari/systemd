/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: header inline functions (batch 3) — utf8, terminal-util, user-util, path-util */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "utf8.h"
#include "terminal-util.h"
#include "user-util.h"
#include "path-util.h"
#include "rust/path_util.h"
#include "rust/terminal_util.h"
#include "rust/utf8.h"
#include "rust/user_util.h"

/* ── utf8_is_valid ─────────────────────────────────────────────────────── */

static void test_utf8_is_valid(void) {
        /* Valid UTF-8 */
        assert_se(utf8_is_valid("hello") == rs_utf8_is_valid("hello"));
        assert_se(!utf8_is_valid("hello") == false);

        /* Valid multi-byte */
        assert_se(utf8_is_valid("\xc3\xa9") == rs_utf8_is_valid("\xc3\xa9"));

        /* Invalid UTF-8 (0xff byte) */
        assert_se(utf8_is_valid("\xff") == rs_utf8_is_valid("\xff"));

        /* Current C rejects overlong encodings and Unicode noncharacters. */
        assert_se(utf8_is_valid("\xc0\x80") == rs_utf8_is_valid("\xc0\x80"));
        assert_se(utf8_is_valid("\xef\xbf\xbe") == rs_utf8_is_valid("\xef\xbf\xbe"));

        /* Empty string */
        assert_se(utf8_is_valid("") == rs_utf8_is_valid(""));
}

/* ── ascii_is_valid ────────────────────────────────────────────────────── */

static void test_ascii_is_valid(void) {
        assert_se(ascii_is_valid("hello") == rs_ascii_is_valid("hello"));
        assert_se(ascii_is_valid("") == rs_ascii_is_valid(""));
        assert_se(ascii_is_valid("\x7f") == rs_ascii_is_valid("\x7f"));
        assert_se(ascii_is_valid("\xc3\xa9") == rs_ascii_is_valid("\xc3\xa9"));
}

/* ── utf8_escape_non_printable ─────────────────────────────────────────── */

static void test_utf8_escape_non_printable(void) {
        _cleanup_free_ char *c_out = NULL, *rs_out = NULL;

        /* Printable ASCII — no escaping */
        c_out = utf8_escape_non_printable("hello");
        rs_out = rs_utf8_escape_non_printable("hello");
        assert_se(c_out && rs_out && streq(c_out, rs_out));
        c_out = mfree(c_out);
        rs_out = mfree(rs_out);

        /* Tab character — gets escaped */
        c_out = utf8_escape_non_printable("\t");
        rs_out = rs_utf8_escape_non_printable("\t");
        assert_se(c_out && rs_out && streq(c_out, rs_out));
        c_out = mfree(c_out);
        rs_out = mfree(rs_out);

        /* Empty string */
        c_out = utf8_escape_non_printable("");
        rs_out = rs_utf8_escape_non_printable("");
        assert_se(c_out && rs_out && streq(c_out, rs_out));
}

/* ── utf16_is_surrogate ────────────────────────────────────────────────── */

static void test_utf16_is_surrogate(void) {
        assert_se(utf16_is_surrogate(0xD800) == rs_utf16_is_surrogate(0xD800));
        assert_se(utf16_is_surrogate(0xDFFF) == rs_utf16_is_surrogate(0xDFFF));
        assert_se(utf16_is_surrogate(0xDC00) == rs_utf16_is_surrogate(0xDC00));
        assert_se(utf16_is_surrogate(0xD7FF) == rs_utf16_is_surrogate(0xD7FF));
        assert_se(utf16_is_surrogate(0xE000) == rs_utf16_is_surrogate(0xE000));
        assert_se(utf16_is_surrogate(0x0000) == rs_utf16_is_surrogate(0x0000));
        assert_se(utf16_is_surrogate(0xFFFF) == rs_utf16_is_surrogate(0xFFFF));
}

/* ── utf16_is_trailing_surrogate ───────────────────────────────────────── */

static void test_utf16_is_trailing_surrogate(void) {
        assert_se(utf16_is_trailing_surrogate(0xDC00) == rs_utf16_is_trailing_surrogate(0xDC00));
        assert_se(utf16_is_trailing_surrogate(0xDFFF) == rs_utf16_is_trailing_surrogate(0xDFFF));
        assert_se(utf16_is_trailing_surrogate(0xD800) == rs_utf16_is_trailing_surrogate(0xD800));
        assert_se(utf16_is_trailing_surrogate(0xDBFF) == rs_utf16_is_trailing_surrogate(0xDBFF));
        assert_se(utf16_is_trailing_surrogate(0xD7FF) == rs_utf16_is_trailing_surrogate(0xD7FF));
        assert_se(utf16_is_trailing_surrogate(0xE000) == rs_utf16_is_trailing_surrogate(0xE000));
}

/* ── utf16_surrogate_pair_to_unichar ───────────────────────────────────── */

static void test_utf16_surrogate_pair_to_unichar(void) {
        /* U+10000 = first codepoint above BMP */
        assert_se(utf16_surrogate_pair_to_unichar(0xD800, 0xDC00) ==
                  rs_utf16_surrogate_pair_to_unichar(0xD800, 0xDC00));
        assert_se(utf16_surrogate_pair_to_unichar(0xD800, 0xDC00) == 0x10000);

        /* U+1F600 (emoji) */
        assert_se(utf16_surrogate_pair_to_unichar(0xD83D, 0xDE00) ==
                  rs_utf16_surrogate_pair_to_unichar(0xD83D, 0xDE00));

        /* The inline has no validity precondition; unsigned arithmetic wraps. */
        assert_se(utf16_surrogate_pair_to_unichar(0, 0) ==
                  rs_utf16_surrogate_pair_to_unichar(0, 0));
}

/* ── osc_char_is_valid ─────────────────────────────────────────────────── */

static void test_osc_char_is_valid(void) {
        assert_se(osc_char_is_valid('A') == rs_osc_char_is_valid('A'));
        assert_se(osc_char_is_valid('Z') == rs_osc_char_is_valid('Z'));
        assert_se(osc_char_is_valid(' ') == rs_osc_char_is_valid(' '));
        assert_se(osc_char_is_valid('~') == rs_osc_char_is_valid('~'));
        assert_se(osc_char_is_valid(31) == rs_osc_char_is_valid(31));
        assert_se(osc_char_is_valid(127) == rs_osc_char_is_valid(127));
        assert_se(osc_char_is_valid(0) == rs_osc_char_is_valid(0));
        assert_se(osc_char_is_valid(-1) == rs_osc_char_is_valid(-1));
}

/* ── vtnr_is_valid ─────────────────────────────────────────────────────── */

static void test_vtnr_is_valid(void) {
        assert_se(vtnr_is_valid(1) == rs_vtnr_is_valid(1));
        assert_se(vtnr_is_valid(63) == rs_vtnr_is_valid(63));
        assert_se(vtnr_is_valid(0) == rs_vtnr_is_valid(0));
        assert_se(vtnr_is_valid(64) == rs_vtnr_is_valid(64));
        assert_se(vtnr_is_valid(100) == rs_vtnr_is_valid(100));
}

/* ── skip_dev_prefix ───────────────────────────────────────────────────── */

static void test_skip_dev_prefix(void) {
        assert_se(streq(skip_dev_prefix("/dev/tty0"), rs_skip_dev_prefix("/dev/tty0")));
        assert_se(streq(skip_dev_prefix("/dev/console"), rs_skip_dev_prefix("/dev/console")));
        assert_se(streq(skip_dev_prefix("/dev/"), rs_skip_dev_prefix("/dev/")));
        assert_se(streq(skip_dev_prefix("/proc/self"), rs_skip_dev_prefix("/proc/self")));
        assert_se(streq(skip_dev_prefix("tty0"), rs_skip_dev_prefix("tty0")));
        assert_se(streq(skip_dev_prefix("/devfoo"), rs_skip_dev_prefix("/devfoo")));
        assert_se(streq(skip_dev_prefix("/dev"), rs_skip_dev_prefix("/dev")));
        assert_se(streq(skip_dev_prefix("/./dev///tty0"), rs_skip_dev_prefix("/./dev///tty0")));
        /* skip_dev_prefix(NULL) crashes in C (path_startswith asserts), skip */
}

/* ── hashed_password_is_locked_or_invalid ──────────────────────────────── */

static void test_hashed_password_is_locked_or_invalid(void) {
        /* Valid hashed passwords start with $ */
        assert_se(hashed_password_is_locked_or_invalid("$6$rounds=656000$salt$hash") ==
                  rs_hashed_password_is_locked_or_invalid("$6$rounds=656000$salt$hash"));
        assert_se(!hashed_password_is_locked_or_invalid("$6$salt$hash"));

        /* Locked/invalid passwords don't start with $ */
        assert_se(hashed_password_is_locked_or_invalid("!") ==
                  rs_hashed_password_is_locked_or_invalid("!"));
        assert_se(hashed_password_is_locked_or_invalid("*") ==
                  rs_hashed_password_is_locked_or_invalid("*"));
        assert_se(hashed_password_is_locked_or_invalid("locked") ==
                  rs_hashed_password_is_locked_or_invalid("locked"));

        /* NULL */
        assert_se(!hashed_password_is_locked_or_invalid(NULL));
        assert_se(!rs_hashed_password_is_locked_or_invalid(NULL));
}

int main(int argc, char **argv) {
        test_utf8_is_valid();
        test_ascii_is_valid();
        test_utf8_escape_non_printable();
        test_utf16_is_surrogate();
        test_utf16_is_trailing_surrogate();
        test_utf16_surrogate_pair_to_unichar();
        test_osc_char_is_valid();
        test_vtnr_is_valid();
        test_skip_dev_prefix();
        test_hashed_password_is_locked_or_invalid();
        return 0;
}
