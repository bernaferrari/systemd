/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C parse_range/parse_fractional_part_u vs Rust */

#include "tests.h"
#include "parse-util.h"

/* Rust FFI */
#include "rust/parse_util.h"

/* ── parse_range ──────────────────────────────────────────────────────── */

static void test_parse_range(void) {
        unsigned cl, cu, rl, ru;
        int cr, rr;

        /* Single number */
        cr = parse_range("42", &cl, &cu);
        rr = rs_parse_range("42", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cl == 42 && cu == 42);
        assert_se(rl == 42 && ru == 42);

        /* Range */
        cr = parse_range("5-10", &cl, &cu);
        rr = rs_parse_range("5-10", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cl == 5 && cu == 10);
        assert_se(rl == 5 && ru == 10);

        /* Range with spaces */
        cr = parse_range("5 - 10", &cl, &cu);
        rr = rs_parse_range("5 - 10", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cl == 5 && cu == 10);
        assert_se(rl == 5 && ru == 10);

        /* Large values */
        cr = parse_range("0-4294967295", &cl, &cu);
        rr = rs_parse_range("0-4294967295", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cl == 0 && cu == 4294967295);
        assert_se(rl == 0 && ru == 4294967295);

        /* Invalid: empty */
        cr = parse_range("", &cl, &cu);
        rr = rs_parse_range("", &rl, &ru);
        assert_se(cr < 0);
        assert_se(rr < 0);

        /* Invalid: not a number */
        cr = parse_range("abc", &cl, &cu);
        rr = rs_parse_range("abc", &rl, &ru);
        assert_se(cr < 0);
        assert_se(rr < 0);

        /* Invalid: trailing dash */
        cr = parse_range("5-", &cl, &cu);
        rr = rs_parse_range("5-", &rl, &ru);
        assert_se(cr < 0);
        assert_se(rr < 0);

        /* Invalid: dash only */
        cr = parse_range("-", &cl, &cu);
        rr = rs_parse_range("-", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

        /* Invalid: second part not a number */
        cr = parse_range("5-abc", &cl, &cu);
        rr = rs_parse_range("5-abc", &rl, &ru);
        assert_se(cr < 0);
        assert_se(rr < 0);

        /* Invalid: NULL */
        cr = parse_range(NULL, &cl, &cu);
        rr = rs_parse_range(NULL, &rl, &ru);
        assert_se(cr < 0);
        assert_se(rr < 0);

        /* Invalid: negative */
        cr = parse_range("-1", &cl, &cu);
        rr = rs_parse_range("-1", &rl, &ru);
        assert_se(cr < 0);
        assert_se(rr < 0);
}

/* ── parse_fractional_part_u ───────────────────────────────────────────── */

/* RUST-CONTRACT: parse-fractional-part */
static void test_parse_fractional_part_u(void) {
        const char *pc, *pr;
        unsigned cr, rr;
        int cr_ret, rr_ret;

        /* Exact digits */
        pc = "12345";
        cr_ret = parse_fractional_part_u(&pc, 3, &cr);
        pr = "12345";
        rr_ret = rs_parse_fractional_part_u(&pr, 3, &rr);
        assert_se(cr_ret == rr_ret);
        assert_se(cr_ret == 0);
        assert_se(cr == 123);
        assert_se(rr == 123);

        /* Fewer digits than requested: pad with 0 */
        pc = "50";
        cr_ret = parse_fractional_part_u(&pc, 4, &cr);
        pr = "50";
        rr_ret = rs_parse_fractional_part_u(&pr, 4, &rr);
        assert_se(cr_ret == rr_ret);
        assert_se(cr_ret == 0);
        assert_se(cr == 5000);
        assert_se(rr == 5000);

        /* Round up: next digit >= 5 */
        pc = "157";
        cr_ret = parse_fractional_part_u(&pc, 2, &cr);
        pr = "157";
        rr_ret = rs_parse_fractional_part_u(&pr, 2, &rr);
        assert_se(cr_ret == rr_ret);
        assert_se(cr_ret == 0);
        assert_se(cr == 16);  /* 15 + round up because next digit is 7 */
        assert_se(rr == 16);

        /* No round up needed: next digit < 5 */
        pc = "143";
        cr_ret = parse_fractional_part_u(&pc, 2, &cr);
        pr = "143";
        rr_ret = rs_parse_fractional_part_u(&pr, 2, &rr);
        assert_se(cr_ret == rr_ret);
        assert_se(cr == 14);
        assert_se(rr == 14);

        /* Zero digits */
        pc = "000";
        cr_ret = parse_fractional_part_u(&pc, 3, &cr);
        pr = "000";
        rr_ret = rs_parse_fractional_part_u(&pr, 3, &rr);
        assert_se(cr_ret == rr_ret);
        assert_se(cr == 0);
        assert_se(rr == 0);

        /* Single digit */
        pc = "7xyz";
        cr_ret = parse_fractional_part_u(&pc, 1, &cr);
        pr = "7xyz";
        rr_ret = rs_parse_fractional_part_u(&pr, 1, &rr);
        assert_se(cr_ret == rr_ret);
        assert_se(cr == 7);
        assert_se(rr == 7);

        /* Position pointer advanced past consumed digits, with rounding */
        pc = "789abc";
        cr_ret = parse_fractional_part_u(&pc, 2, &cr);
        pr = "789abc";
        rr_ret = rs_parse_fractional_part_u(&pr, 2, &rr);
        assert_se(cr_ret == rr_ret);
        assert_se(cr == 79); /* 78 rounded up because next digit '9' >= 5 */
        assert_se(rr == 79);
        assert_se(*pc == 'a'); /* C pointer past consumed+skipped digits */
        assert_se(*pr == 'a'); /* Rust pointer past consumed+skipped digits */

        /* Invalid: no digits at all */
        pc = "abc";
        cr_ret = parse_fractional_part_u(&pc, 3, &cr);
        pr = "abc";
        rr_ret = rs_parse_fractional_part_u(&pr, 3, &rr);
        assert_se(cr_ret < 0);
        assert_se(rr_ret < 0);

        /* Invalid: non-digit in first position */
        pc = ".5";
        cr_ret = parse_fractional_part_u(&pc, 3, &cr);
        pr = ".5";
        rr_ret = rs_parse_fractional_part_u(&pr, 3, &rr);
        assert_se(cr_ret < 0);
        assert_se(rr_ret < 0);

        /* Invalid: empty string */
        pc = "";
        cr_ret = parse_fractional_part_u(&pc, 3, &cr);
        pr = "";
        rr_ret = rs_parse_fractional_part_u(&pr, 3, &rr);
        assert_se(cr_ret < 0);
        assert_se(rr_ret < 0);
}

int main(int argc, char **argv) {
        test_parse_range();
        test_parse_fractional_part_u();
        return 0;
}
