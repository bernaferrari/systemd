/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C strverscmp_improved vs Rust rs_strverscmp_improved */

#include <string.h>
#include "tests.h"
#include "string-util.h"

/* Rust FFI */
#include "rust/strverscmp.h"

static void test_strverscmp_improved_one(const char *a, const char *b, int expected) {
        int cr = strverscmp_improved(a, b);
        int rr = rs_strverscmp_improved(a, b);
        assert_se(cr == expected);
        assert_se(rr == expected);
        assert_se(cr == rr);
}

static void test_strverscmp_improved_newer(const char *older, const char *newer) {
        test_strverscmp_improved_one(older, newer, -1);
        assert_se(strverscmp_improved(older, older) == 0);
        assert_se(rs_strverscmp_improved(older, older) == 0);
        assert_se(strverscmp_improved(older, newer) < 0);
        assert_se(rs_strverscmp_improved(older, newer) < 0);
        assert_se(strverscmp_improved(newer, older) > 0);
        assert_se(rs_strverscmp_improved(newer, older) > 0);
        assert_se(strverscmp_improved(newer, newer) == 0);
        assert_se(rs_strverscmp_improved(newer, newer) == 0);
}

TEST(strverscmp_improved_rust) {
        static const char * const versions[] = {
                "~1",
                "",
                "ab",
                "abb",
                "abc",
                "0001",
                "002",
                "12",
                "122",
                "122.9",
                "123~rc1",
                "123",
                "123-a",
                "123-a.1",
                "123-a1",
                "123-a1.1",
                "123-3",
                "123-3.1",
                "123^patch1",
                "123^1",
                "123.a-1",
                "123.1-1",
                "123a-1",
                "124",
                NULL,
        };

        for (const char * const *p = versions; *p; p++)
                for (const char * const *q = p + 1; *q; q++)
                        test_strverscmp_improved_newer(*p, *q);

        test_strverscmp_improved_newer("123.45-67.88", "123.45-67.89");
        test_strverscmp_improved_newer("123.45-67.89", "123.45-67.89a");
        test_strverscmp_improved_newer("123.45-67.ab", "123.45-67.89");
        test_strverscmp_improved_newer("123.45-67.9", "123.45-67.89");
        test_strverscmp_improved_newer("123.45-67", "123.45-67.89");
        test_strverscmp_improved_newer("123.45-66.89", "123.45-67.89");
        test_strverscmp_improved_newer("123.45-9.99", "123.45-67.89");
        test_strverscmp_improved_newer("123.42-99.99", "123.45-67.89");
        test_strverscmp_improved_newer("123-99.99", "123.45-67.89");

        /* '~' : pre-releases */
        test_strverscmp_improved_newer("123~rc1-99.99", "123.45-67.89");
        test_strverscmp_improved_newer("123~rc1-99.99", "123-45.67.89");
        test_strverscmp_improved_newer("123~rc1-99.99", "123~rc2-67.89");
        test_strverscmp_improved_newer("123~rc1-99.99", "123^aa2-67.89");
        test_strverscmp_improved_newer("123~rc1-99.99", "123aa2-67.89");

        /* '-' : separator between version and release */
        test_strverscmp_improved_newer("123-99.99", "123.45-67.89");
        test_strverscmp_improved_newer("123-99.99", "123^aa2-67.89");
        test_strverscmp_improved_newer("123-99.99", "123aa2-67.89");

        /* '^' : patch releases */
        test_strverscmp_improved_newer("123^45-67.89", "123.45-67.89");
        test_strverscmp_improved_newer("123^aa1-99.99", "123^aa2-67.89");
        test_strverscmp_improved_newer("123^aa2-67.89", "123aa2-67.89");

        /* '.' : point release */
        test_strverscmp_improved_newer("123.aa2-67.89", "123aa2-67.89");
        test_strverscmp_improved_newer("123.aa2-67.89", "123.ab2-67.89");

        /* invalid characters */
        assert_se(strverscmp_improved("123_aa2-67.89", "123aa+2-67.89") == 0);
        assert_se(rs_strverscmp_improved("123_aa2-67.89", "123aa+2-67.89") == 0);

        /* corner cases */
        assert_se(strverscmp_improved("123.", "123") > 0);
        assert_se(rs_strverscmp_improved("123.", "123") > 0);

        assert_se(strverscmp_improved("12_3", "123") < 0);
        assert_se(rs_strverscmp_improved("12_3", "123") < 0);

        assert_se(strverscmp_improved("12_3", "12") > 0);
        assert_se(rs_strverscmp_improved("12_3", "12") > 0);

        assert_se(strverscmp_improved("12_3", "12.3") > 0);
        assert_se(rs_strverscmp_improved("12_3", "12.3") > 0);

        assert_se(strverscmp_improved("123.0", "123") > 0);
        assert_se(rs_strverscmp_improved("123.0", "123") > 0);

        assert_se(strverscmp_improved("123_0", "123") > 0);
        assert_se(rs_strverscmp_improved("123_0", "123") > 0);

        assert_se(strverscmp_improved("123..0", "123.0") < 0);
        assert_se(rs_strverscmp_improved("123..0", "123.0") < 0);

        /* empty strings or strings with ignored characters only */
        assert_se(strverscmp_improved("", NULL) == 0);
        assert_se(rs_strverscmp_improved("", NULL) == 0);
        assert_se(strverscmp_improved(NULL, "") == 0);
        assert_se(rs_strverscmp_improved(NULL, "") == 0);
        assert_se(strverscmp_improved("0_", "0") == 0);
        assert_se(rs_strverscmp_improved("0_", "0") == 0);
        assert_se(strverscmp_improved("_0_", "0") == 0);
        assert_se(rs_strverscmp_improved("_0_", "0") == 0);
        assert_se(strverscmp_improved("_0", "0") == 0);
        assert_se(rs_strverscmp_improved("_0", "0") == 0);
        assert_se(strverscmp_improved("0", "0___") == 0);
        assert_se(rs_strverscmp_improved("0", "0___") == 0);
        assert_se(strverscmp_improved("", "_") == 0);
        assert_se(rs_strverscmp_improved("", "_") == 0);
        assert_se(strverscmp_improved("_", "") == 0);
        assert_se(rs_strverscmp_improved("_", "") == 0);
        assert_se(strverscmp_improved("_", "_") == 0);
        assert_se(rs_strverscmp_improved("_", "_") == 0);
        assert_se(strverscmp_improved("", "~") > 0);
        assert_se(rs_strverscmp_improved("", "~") > 0);
        assert_se(strverscmp_improved("~", "") < 0);
        assert_se(rs_strverscmp_improved("~", "") < 0);
        assert_se(strverscmp_improved("~", "~") == 0);
        assert_se(rs_strverscmp_improved("~", "~") == 0);

        /* RPM compatibility tests */
        test_strverscmp_improved_one("1.0", "1.0", 0);
        test_strverscmp_improved_one("1.0", "2.0", -1);
        test_strverscmp_improved_one("2.0", "1.0", 1);
        test_strverscmp_improved_one("2.0.1", "2.0.1", 0);
        test_strverscmp_improved_one("2.0", "2.0.1", -1);
        test_strverscmp_improved_one("2.0.1", "2.0", 1);
        test_strverscmp_improved_one("2.0.1a", "2.0.1a", 0);
        test_strverscmp_improved_one("2.0.1a", "2.0.1", 1);
        test_strverscmp_improved_one("2.0.1", "2.0.1a", -1);
        test_strverscmp_improved_one("5.5p1", "5.5p1", 0);
        test_strverscmp_improved_one("5.5p1", "5.5p2", -1);
        test_strverscmp_improved_one("5.5p2", "5.5p1", 1);
        test_strverscmp_improved_one("5.5p10", "5.5p10", 0);
        test_strverscmp_improved_one("5.5p1", "5.5p10", -1);
        test_strverscmp_improved_one("5.5p10", "5.5p1", 1);
        test_strverscmp_improved_one("10xyz", "10.1xyz", 1);
        test_strverscmp_improved_one("10.1xyz", "10xyz", -1);
        test_strverscmp_improved_one("xyz10", "xyz10", 0);
        test_strverscmp_improved_one("xyz10", "xyz10.1", -1);
        test_strverscmp_improved_one("xyz10.1", "xyz10", 1);
        test_strverscmp_improved_one("xyz.4", "xyz.4", 0);
        test_strverscmp_improved_one("xyz.4", "8", -1);
        test_strverscmp_improved_one("8", "xyz.4", 1);
        test_strverscmp_improved_one("xyz.4", "2", -1);
        test_strverscmp_improved_one("2", "xyz.4", 1);
        test_strverscmp_improved_one("5.5p2", "5.6p1", -1);
        test_strverscmp_improved_one("5.6p1", "5.5p2", 1);
        test_strverscmp_improved_one("5.6p1", "6.5p1", -1);
        test_strverscmp_improved_one("6.5p1", "5.6p1", 1);
        test_strverscmp_improved_one("6.0.rc1", "6.0", 1);
        test_strverscmp_improved_one("6.0", "6.0.rc1", -1);
        test_strverscmp_improved_one("10b2", "10a1", 1);
        test_strverscmp_improved_one("10a2", "10b2", -1);
        test_strverscmp_improved_one("1.0aa", "1.0aa", 0);
        test_strverscmp_improved_one("1.0a", "1.0aa", -1);
        test_strverscmp_improved_one("1.0aa", "1.0a", 1);
        test_strverscmp_improved_one("10.0001", "10.0001", 0);
        test_strverscmp_improved_one("10.0001", "10.1", 0);
        test_strverscmp_improved_one("10.1", "10.0001", 0);
        test_strverscmp_improved_one("10.0001", "10.0039", -1);
        test_strverscmp_improved_one("10.0039", "10.0001", 1);
        test_strverscmp_improved_one("4.999.9", "5.0", -1);
        test_strverscmp_improved_one("5.0", "4.999.9", 1);
        test_strverscmp_improved_one("20101121", "20101121", 0);
        test_strverscmp_improved_one("20101121", "20101122", -1);
        test_strverscmp_improved_one("20101122", "20101121", 1);
        test_strverscmp_improved_one("2_0", "2_0", 0);
        test_strverscmp_improved_one("2.0", "2_0", -1);
        test_strverscmp_improved_one("2_0", "2.0", 1);

        /* tilde sorting */
        test_strverscmp_improved_one("1.0~rc1", "1.0~rc1", 0);
        test_strverscmp_improved_one("1.0~rc1", "1.0", -1);
        test_strverscmp_improved_one("1.0", "1.0~rc1", 1);
        test_strverscmp_improved_one("1.0~rc1", "1.0~rc2", -1);
        test_strverscmp_improved_one("1.0~rc2", "1.0~rc1", 1);
        test_strverscmp_improved_one("1.0~rc1~git123", "1.0~rc1~git123", 0);
        test_strverscmp_improved_one("1.0~rc1~git123", "1.0~rc1", -1);
        test_strverscmp_improved_one("1.0~rc1", "1.0~rc1~git123", 1);

        /* caret sorting */
        test_strverscmp_improved_one("1.0^", "1.0^", 0);
        test_strverscmp_improved_one("1.0^", "1.0", 1);
        test_strverscmp_improved_one("1.0", "1.0^", -1);
        test_strverscmp_improved_one("1.0^git1", "1.0^git1", 0);
        test_strverscmp_improved_one("1.0^git1", "1.0", 1);
        test_strverscmp_improved_one("1.0", "1.0^git1", -1);
        test_strverscmp_improved_one("1.0^git1", "1.0^git2", -1);
        test_strverscmp_improved_one("1.0^git2", "1.0^git1", 1);
        test_strverscmp_improved_one("1.0^git1", "1.01", -1);
        test_strverscmp_improved_one("1.01", "1.0^git1", 1);
        test_strverscmp_improved_one("1.0^20160101", "1.0^20160101", 0);
        test_strverscmp_improved_one("1.0^20160101", "1.0.1", -1);
}

DEFINE_TEST_MAIN(LOG_INFO);
