/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C user-util.c / parse-util.c vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "user-util.h"
#include "parse-util.h"

/* Rust FFI */
#include "rust/user_shell_util.h"

/* -- is_nologin_shell ------------------------------------------------------ */

static void test_is_nologin_shell(void) {
        assert_se(is_nologin_shell("/bin/nologin") == rs_is_nologin_shell("/bin/nologin"));
        assert_se(is_nologin_shell("/bin/nologin") == true);

        assert_se(is_nologin_shell("/sbin/nologin") == rs_is_nologin_shell("/sbin/nologin"));
        assert_se(is_nologin_shell("/sbin/nologin") == true);

        assert_se(is_nologin_shell("/usr/bin/nologin") == rs_is_nologin_shell("/usr/bin/nologin"));
        assert_se(is_nologin_shell("/usr/bin/nologin") == true);

        assert_se(is_nologin_shell("/usr/sbin/nologin") == rs_is_nologin_shell("/usr/sbin/nologin"));
        assert_se(is_nologin_shell("/usr/sbin/nologin") == true);

        assert_se(is_nologin_shell("/bin/false") == rs_is_nologin_shell("/bin/false"));
        assert_se(is_nologin_shell("/bin/false") == true);

        assert_se(is_nologin_shell("/usr/bin/false") == rs_is_nologin_shell("/usr/bin/false"));
        assert_se(is_nologin_shell("/usr/bin/false") == true);

        assert_se(is_nologin_shell("/bin/true") == rs_is_nologin_shell("/bin/true"));
        assert_se(is_nologin_shell("/bin/true") == true);

        assert_se(is_nologin_shell("/usr/bin/true") == rs_is_nologin_shell("/usr/bin/true"));
        assert_se(is_nologin_shell("/usr/bin/true") == true);

        assert_se(is_nologin_shell("/bin/bash") == rs_is_nologin_shell("/bin/bash"));
        assert_se(is_nologin_shell("/bin/bash") == false);

        assert_se(is_nologin_shell("/bin/sh") == rs_is_nologin_shell("/bin/sh"));
        assert_se(is_nologin_shell("/bin/sh") == false);

        assert_se(is_nologin_shell("/usr/bin/zsh") == rs_is_nologin_shell("/usr/bin/zsh"));
        assert_se(is_nologin_shell("/usr/bin/zsh") == false);

        assert_se(is_nologin_shell("") == rs_is_nologin_shell(""));
        assert_se(is_nologin_shell("") == false);

        /* NULL: C would crash (PATH_IN_SET dereferences), Rust returns false */
        assert_se(rs_is_nologin_shell(NULL) == false);
}

/* -- shell_is_placeholder -------------------------------------------------- */

static void test_shell_is_placeholder(void) {
        assert_se(shell_is_placeholder("") == rs_shell_is_placeholder(""));
        assert_se(shell_is_placeholder("") == true);

        assert_se(shell_is_placeholder("/bin/nologin") == rs_shell_is_placeholder("/bin/nologin"));
        assert_se(shell_is_placeholder("/bin/nologin") == true);

        assert_se(shell_is_placeholder("/bin/false") == rs_shell_is_placeholder("/bin/false"));
        assert_se(shell_is_placeholder("/bin/false") == true);

        assert_se(shell_is_placeholder("/bin/bash") == rs_shell_is_placeholder("/bin/bash"));
        assert_se(shell_is_placeholder("/bin/bash") == false);

        assert_se(shell_is_placeholder("/bin/sh") == rs_shell_is_placeholder("/bin/sh"));
        assert_se(shell_is_placeholder("/bin/sh") == false);

        /* NULL */
        assert_se(rs_shell_is_placeholder(NULL) == true);
}

/* -- parse_fractional_part_u ----------------------------------------------- */

static void test_parse_fractional_part_u(void) {
        const char *cs;
        const char *rs;
        unsigned cr, rr;
        int cret, rret;

        /* Simple case: "5" with 1 digit */
        cs = "5abc"; rs = "5abc";
        cret = parse_fractional_part_u(&cs, 1, &cr);
        rret = rs_parse_fractional_part_u(&rs, 1, &rr);
        assert_se(cret == rret);
        assert_se(cret == 0);
        assert_se(cr == rr);
        assert_se(cr == 5);
        assert_se(streq(cs, rs));

        /* Two digits: "50" */
        cs = "50abc"; rs = "50abc";
        cret = parse_fractional_part_u(&cs, 2, &cr);
        rret = rs_parse_fractional_part_u(&rs, 2, &rr);
        assert_se(cret == rret);
        assert_se(cr == rr);
        assert_se(cr == 50);

        /* Rounding: "55" with 1 digit -> 6 */
        cs = "55"; rs = "55";
        cret = parse_fractional_part_u(&cs, 1, &cr);
        rret = rs_parse_fractional_part_u(&rs, 1, &rr);
        assert_se(cret == rret);
        assert_se(cr == rr);
        assert_se(cr == 6);

        /* No rounding: "54" with 1 digit -> 5 */
        cs = "54"; rs = "54";
        cret = parse_fractional_part_u(&cs, 1, &cr);
        rret = rs_parse_fractional_part_u(&rs, 1, &rr);
        assert_se(cret == rret);
        assert_se(cr == rr);
        assert_se(cr == 5);

        /* Pad with zeros: "1" with 3 digits -> 100 */
        cs = "1a"; rs = "1a";
        cret = parse_fractional_part_u(&cs, 3, &cr);
        rret = rs_parse_fractional_part_u(&rs, 3, &rr);
        assert_se(cret == rret);
        assert_se(cr == rr);
        assert_se(cr == 100);

        /* No digits: "abc" with 2 digits -> -EINVAL */
        cs = "abc"; rs = "abc";
        cret = parse_fractional_part_u(&cs, 2, &cr);
        rret = rs_parse_fractional_part_u(&rs, 2, &rr);
        assert_se(cret == rret);
        assert_se(cret == -EINVAL);

        /* End of string: "7" with 3 digits -> 700 */
        cs = "7"; rs = "7";
        cret = parse_fractional_part_u(&cs, 3, &cr);
        rret = rs_parse_fractional_part_u(&rs, 3, &rr);
        assert_se(cret == rret);
        assert_se(cr == rr);
        assert_se(cr == 700);

        /* Skip remaining digits: "12345x" with 2 digits -> 12, pointer at "x" */
        cs = "12345x"; rs = "12345x";
        cret = parse_fractional_part_u(&cs, 2, &cr);
        rret = rs_parse_fractional_part_u(&rs, 2, &rr);
        assert_se(cret == rret);
        assert_se(cr == rr);
        assert_se(cr == 12);
        assert_se(streq(cs, rs));
        assert_se(streq(cs, "x"));

        /* Zero digits: "0" with 1 digit */
        cs = "0abc"; rs = "0abc";
        cret = parse_fractional_part_u(&cs, 1, &cr);
        rret = rs_parse_fractional_part_u(&rs, 1, &rr);
        assert_se(cret == rret);
        assert_se(cr == rr);
        assert_se(cr == 0);
}

int main(int argc, char **argv) {
        test_is_nologin_shell();
        test_shell_is_placeholder();
        test_parse_fractional_part_u();
        return 0;
}
