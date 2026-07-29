/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C web-util/color-util/compare-operator vs Rust */

#include <assert.h>
#include <math.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "web-util.h"
#include "color-util.h"
#include "compare-operator.h"

/* Rust FFI */
#include "rust/shared_facades/validation.h"

/* ── http_etag_is_valid ────────────────────────────────────────────────── */

static void test_http_etag_is_valid(void) {
        /* Valid etags */
        assert_se(http_etag_is_valid("\"abc\"") == rs_http_etag_is_valid("\"abc\""));
        assert_se(http_etag_is_valid("\"abc\"") == true);
        assert_se(http_etag_is_valid("\"\"") == rs_http_etag_is_valid("\"\""));
        assert_se(http_etag_is_valid("\"\"") == true);
        assert_se(http_etag_is_valid("W/\"abc\"") == rs_http_etag_is_valid("W/\"abc\""));
        assert_se(http_etag_is_valid("W/\"abc\"") == true);
        assert_se(http_etag_is_valid("W/\"\"") == rs_http_etag_is_valid("W/\"\""));
        assert_se(http_etag_is_valid("W/\"\"") == true);

        /* Invalid: empty */
        assert_se(http_etag_is_valid("") == rs_http_etag_is_valid(""));
        assert_se(http_etag_is_valid("") == false);
        assert_se(http_etag_is_valid(NULL) == rs_http_etag_is_valid(NULL));
        assert_se(http_etag_is_valid(NULL) == false);

        /* Invalid: doesn't end with " */
        assert_se(http_etag_is_valid("abc") == rs_http_etag_is_valid("abc"));
        assert_se(http_etag_is_valid("abc") == false);
        assert_se(http_etag_is_valid("\"abc") == rs_http_etag_is_valid("\"abc"));
        assert_se(http_etag_is_valid("\"abc") == false);

        /* Invalid: doesn't start with " or W/" */
        assert_se(http_etag_is_valid("x\"abc\"") == rs_http_etag_is_valid("x\"abc\""));
        assert_se(http_etag_is_valid("x\"abc\"") == false);
        assert_se(http_etag_is_valid("w/\"abc\"") == rs_http_etag_is_valid("w/\"abc\""));
        assert_se(http_etag_is_valid("w/\"abc\"") == false);
}

/* ── http_url_is_valid ────────────────────────────────────────────────── */

static void test_http_url_is_valid(void) {
        /* Valid */
        assert_se(http_url_is_valid("http://example.com") == rs_http_url_is_valid("http://example.com"));
        assert_se(http_url_is_valid("http://example.com") == true);
        assert_se(http_url_is_valid("https://example.com/path") == rs_http_url_is_valid("https://example.com/path"));
        assert_se(http_url_is_valid("https://example.com/path") == true);
        assert_se(http_url_is_valid("http://a") == rs_http_url_is_valid("http://a"));
        assert_se(http_url_is_valid("http://a") == true);

        /* Invalid: empty */
        assert_se(http_url_is_valid("") == rs_http_url_is_valid(""));
        assert_se(http_url_is_valid("") == false);
        assert_se(http_url_is_valid(NULL) == rs_http_url_is_valid(NULL));
        assert_se(http_url_is_valid(NULL) == false);

        /* Invalid: no scheme */
        assert_se(http_url_is_valid("example.com") == rs_http_url_is_valid("example.com"));
        assert_se(http_url_is_valid("example.com") == false);

        /* Invalid: scheme only, empty path */
        assert_se(http_url_is_valid("http://") == rs_http_url_is_valid("http://"));
        assert_se(http_url_is_valid("http://") == false);

        /* Invalid: non-ASCII in path */
        assert_se(http_url_is_valid("http://example.com/\xc3\xa9") == rs_http_url_is_valid("http://example.com/\xc3\xa9"));
        assert_se(http_url_is_valid("http://example.com/\xc3\xa9") == false);

        /* file: is not http */
        assert_se(http_url_is_valid("file:///etc/passwd") == rs_http_url_is_valid("file:///etc/passwd"));
        assert_se(http_url_is_valid("file:///etc/passwd") == false);
}

/* ── file_url_is_valid ────────────────────────────────────────────────── */

static void test_file_url_is_valid(void) {
        /* Valid */
        assert_se(file_url_is_valid("file:///etc/passwd") == rs_file_url_is_valid("file:///etc/passwd"));
        assert_se(file_url_is_valid("file:///etc/passwd") == true);
        assert_se(file_url_is_valid("file:/etc/passwd") == rs_file_url_is_valid("file:/etc/passwd"));
        assert_se(file_url_is_valid("file:/etc/passwd") == true);

        /* Invalid: empty */
        assert_se(file_url_is_valid("") == rs_file_url_is_valid(""));
        assert_se(file_url_is_valid("") == false);
        assert_se(file_url_is_valid(NULL) == rs_file_url_is_valid(NULL));
        assert_se(file_url_is_valid(NULL) == false);

        /* Invalid: wrong scheme */
        assert_se(file_url_is_valid("http://example.com") == rs_file_url_is_valid("http://example.com"));
        assert_se(file_url_is_valid("http://example.com") == false);

        /* Invalid: file: with nothing after (no slash) */
        assert_se(file_url_is_valid("file:") == rs_file_url_is_valid("file:"));
        assert_se(file_url_is_valid("file:") == false);
}

/* ── documentation_url_is_valid ───────────────────────────────────────── */

static void test_documentation_url_is_valid(void) {
        /* Valid: http */
        assert_se(documentation_url_is_valid("http://example.com") == rs_documentation_url_is_valid("http://example.com"));
        assert_se(documentation_url_is_valid("http://example.com") == true);

        /* Valid: https */
        assert_se(documentation_url_is_valid("https://example.com") == rs_documentation_url_is_valid("https://example.com"));
        assert_se(documentation_url_is_valid("https://example.com") == true);

        /* Valid: file */
        assert_se(documentation_url_is_valid("file:///etc/passwd") == rs_documentation_url_is_valid("file:///etc/passwd"));
        assert_se(documentation_url_is_valid("file:///etc/passwd") == true);

        /* Valid: info */
        assert_se(documentation_url_is_valid("info:bar") == rs_documentation_url_is_valid("info:bar"));
        assert_se(documentation_url_is_valid("info:bar") == true);

        /* Valid: man */
        assert_se(documentation_url_is_valid("man:foo(1)") == rs_documentation_url_is_valid("man:foo(1)"));
        assert_se(documentation_url_is_valid("man:foo(1)") == true);

        /* Invalid: empty */
        assert_se(documentation_url_is_valid("") == rs_documentation_url_is_valid(""));
        assert_se(documentation_url_is_valid("") == false);
        assert_se(documentation_url_is_valid(NULL) == rs_documentation_url_is_valid(NULL));
        assert_se(documentation_url_is_valid(NULL) == false);

        /* Invalid: ftp (not a recognized scheme) */
        assert_se(documentation_url_is_valid("ftp://example.com") == rs_documentation_url_is_valid("ftp://example.com"));
        assert_se(documentation_url_is_valid("ftp://example.com") == false);

        /* info: with non-ASCII */
        assert_se(documentation_url_is_valid("info:\xc3\xa9") == rs_documentation_url_is_valid("info:\xc3\xa9"));
        assert_se(documentation_url_is_valid("info:\xc3\xa9") == false);
}

/* ── rgb_to_hsv ───────────────────────────────────────────────────────── */

/* The C/R shadow contract is exact output representation, including the sign
 * of zero. Avoid a floating-point == expression, which systemd rightly
 * rejects under -Werror=float-equal. */
static bool double_bits_equal(double left, double right) {
        return memcmp(&left, &right, sizeof left) == 0;
}

static void test_rgb_to_hsv(void) {
        double ch, cs, cv, rh, rs_r, rv;

        /* Black (0,0,0) → H=NaN, S=0, V=0 */
        rgb_to_hsv(0.0, 0.0, 0.0, &ch, &cs, &cv);
        rs_rgb_to_hsv(0.0, 0.0, 0.0, &rh, &rs_r, &rv);
        assert_se(double_bits_equal(cv, rv));
        assert_se(double_bits_equal(cs, rs_r));
        assert_se(isnan(ch) && isnan(rh));

        /* White (1,1,1) → H=NaN, S=0, V=100 */
        rgb_to_hsv(1.0, 1.0, 1.0, &ch, &cs, &cv);
        rs_rgb_to_hsv(1.0, 1.0, 1.0, &rh, &rs_r, &rv);
        assert_se(double_bits_equal(cv, rv));
        assert_se(double_bits_equal(cs, rs_r));
        assert_se(isnan(ch) && isnan(rh));

        /* Pure red (1,0,0) → H=0, S=100, V=100 */
        rgb_to_hsv(1.0, 0.0, 0.0, &ch, &cs, &cv);
        rs_rgb_to_hsv(1.0, 0.0, 0.0, &rh, &rs_r, &rv);
        assert_se(double_bits_equal(ch, rh));
        assert_se(double_bits_equal(cs, rs_r));
        assert_se(double_bits_equal(cv, rv));
        assert_se(double_bits_equal(ch, 0.0));
        assert_se(double_bits_equal(cs, 100.0));
        assert_se(double_bits_equal(cv, 100.0));

        /* Pure green (0,1,0) → H=120, S=100, V=100 */
        rgb_to_hsv(0.0, 1.0, 0.0, &ch, &cs, &cv);
        rs_rgb_to_hsv(0.0, 1.0, 0.0, &rh, &rs_r, &rv);
        assert_se(double_bits_equal(ch, rh));
        assert_se(double_bits_equal(cs, rs_r));
        assert_se(double_bits_equal(cv, rv));
        assert_se(double_bits_equal(ch, 120.0));

        /* Pure blue (0,0,1) → H=240, S=100, V=100 */
        rgb_to_hsv(0.0, 0.0, 1.0, &ch, &cs, &cv);
        rs_rgb_to_hsv(0.0, 0.0, 1.0, &rh, &rs_r, &rv);
        assert_se(double_bits_equal(ch, rh));
        assert_se(double_bits_equal(cs, rs_r));
        assert_se(double_bits_equal(cv, rv));
        assert_se(double_bits_equal(ch, 240.0));

        /* Gray (0.5, 0.5, 0.5) → H=NaN, S=0, V=50 */
        rgb_to_hsv(0.5, 0.5, 0.5, &ch, &cs, &cv);
        rs_rgb_to_hsv(0.5, 0.5, 0.5, &rh, &rs_r, &rv);
        assert_se(double_bits_equal(cv, rv));
        assert_se(double_bits_equal(cs, rs_r));
        assert_se(isnan(ch) && isnan(rh));

        /* Test with NULL outputs */
        rgb_to_hsv(0.5, 0.3, 0.1, NULL, NULL, &cv);
        rs_rgb_to_hsv(0.5, 0.3, 0.1, NULL, NULL, &rv);
        assert_se(double_bits_equal(cv, rv));
}

/* ── hsv_to_rgb ───────────────────────────────────────────────────────── */

static void test_hsv_to_rgb(void) {
        uint8_t cr, cg, cb, rr, rg, rb;

        /* Red: H=0, S=100, V=100 → (255, 0, 0) */
        hsv_to_rgb(0.0, 100.0, 100.0, &cr, &cg, &cb);
        rs_hsv_to_rgb(0.0, 100.0, 100.0, &rr, &rg, &rb);
        assert_se(cr == rr);
        assert_se(cg == rg);
        assert_se(cb == rb);
        assert_se(cr == 255);
        assert_se(cg == 0);
        assert_se(cb == 0);

        /* Green: H=120, S=100, V=100 → (0, 255, 0) */
        hsv_to_rgb(120.0, 100.0, 100.0, &cr, &cg, &cb);
        rs_hsv_to_rgb(120.0, 100.0, 100.0, &rr, &rg, &rb);
        assert_se(cr == rr);
        assert_se(cg == rg);
        assert_se(cb == rb);
        assert_se(cg == 255);

        /* Blue: H=240, S=100, V=100 → (0, 0, 255) */
        hsv_to_rgb(240.0, 100.0, 100.0, &cr, &cg, &cb);
        rs_hsv_to_rgb(240.0, 100.0, 100.0, &rr, &rg, &rb);
        assert_se(cr == rr);
        assert_se(cg == rg);
        assert_se(cb == rb);
        assert_se(cb == 255);

        /* Black: H=0, S=0, V=0 → (0, 0, 0) */
        hsv_to_rgb(0.0, 0.0, 0.0, &cr, &cg, &cb);
        rs_hsv_to_rgb(0.0, 0.0, 0.0, &rr, &rg, &rb);
        assert_se(cr == rr && cg == rg && cb == rb);
        assert_se(cr == 0 && cg == 0 && cb == 0);

        /* White: H=0, S=0, V=100 → (255, 255, 255) */
        hsv_to_rgb(0.0, 0.0, 100.0, &cr, &cg, &cb);
        rs_hsv_to_rgb(0.0, 0.0, 100.0, &rr, &rg, &rb);
        assert_se(cr == rr && cg == rg && cb == rb);
        assert_se(cr == 255 && cg == 255 && cb == 255);

        /* H=360 is the supported cyclic boundary and is equivalent to H=0. */
        hsv_to_rgb(360.0, 100.0, 100.0, &cr, &cg, &cb);
        rs_hsv_to_rgb(360.0, 100.0, 100.0, &rr, &rg, &rb);
        assert_se(cr == rr && cg == rg && cb == rb);

        /* Gray: H=0, S=0, V=50 → (128, 128, 128) */
        hsv_to_rgb(0.0, 0.0, 50.0, &cr, &cg, &cb);
        rs_hsv_to_rgb(0.0, 0.0, 50.0, &rr, &rg, &rb);
        assert_se(cr == rr && cg == rg && cb == rb);
}

/* ── parse_compare_operator ───────────────────────────────────────────── */

static void test_parse_compare_operator(void) {
        const char *cs = NULL;
        const char *rs = NULL;
        int cv, rv;

        /* Simple operators, no flags */
        cs = "==rest";
        rs = "==rest";
        cv = parse_compare_operator(&cs, 0);
        rv = rs_parse_compare_operator(&rs, 0);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_EQUAL);
        assert_se(streq(cs, rs));

        cs = "!=rest";
        rs = "!=rest";
        cv = parse_compare_operator(&cs, 0);
        rv = rs_parse_compare_operator(&rs, 0);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_UNEQUAL);

        cs = "<=rest";
        rs = "<=rest";
        cv = parse_compare_operator(&cs, 0);
        rv = rs_parse_compare_operator(&rs, 0);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_LOWER_OR_EQUAL);

        cs = ">=rest";
        rs = ">=rest";
        cv = parse_compare_operator(&cs, 0);
        rv = rs_parse_compare_operator(&rs, 0);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_GREATER_OR_EQUAL);

        cs = "<rest";
        rs = "<rest";
        cv = parse_compare_operator(&cs, 0);
        rv = rs_parse_compare_operator(&rs, 0);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_LOWER);

        cs = ">rest";
        rs = ">rest";
        cv = parse_compare_operator(&cs, 0);
        rv = rs_parse_compare_operator(&rs, 0);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_GREATER);

        cs = "<>rest";
        rs = "<>rest";
        cv = parse_compare_operator(&cs, 0);
        rv = rs_parse_compare_operator(&rs, 0);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_UNEQUAL);

        /* = alone (not ==) → COMPARE_EQUAL */
        cs = "=rest";
        rs = "=rest";
        cv = parse_compare_operator(&cs, 0);
        rv = rs_parse_compare_operator(&rs, 0);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_EQUAL);

        /* FNMATCH: only allowed with COMPARE_ALLOW_FNMATCH */
        cs = "$=foo";
        rs = "$=foo";
        cv = parse_compare_operator(&cs, COMPARE_ALLOW_FNMATCH);
        rv = rs_parse_compare_operator(&rs, COMPARE_ALLOW_FNMATCH);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_FNMATCH_EQUAL);

        cs = "$=foo";
        rs = "$=foo";
        cv = parse_compare_operator(&cs, 0);
        rv = rs_parse_compare_operator(&rs, 0);
        assert_se(cv == rv);
        assert_se(cv == _COMPARE_OPERATOR_INVALID);

        /* FNMATCH UNEQUAL */
        cs = "!$=foo";
        rs = "!$=foo";
        cv = parse_compare_operator(&cs, COMPARE_ALLOW_FNMATCH);
        rv = rs_parse_compare_operator(&rs, COMPARE_ALLOW_FNMATCH);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_FNMATCH_UNEQUAL);

        /* EQUAL_BY_STRING: = alone maps to COMPARE_STRING_EQUAL */
        cs = "=rest";
        rs = "=rest";
        cv = parse_compare_operator(&cs, COMPARE_EQUAL_BY_STRING);
        rv = rs_parse_compare_operator(&rs, COMPARE_EQUAL_BY_STRING);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_STRING_EQUAL);

        /* EQUAL_BY_STRING: != maps to COMPARE_STRING_UNEQUAL */
        cs = "!=rest";
        rs = "!=rest";
        cv = parse_compare_operator(&cs, COMPARE_EQUAL_BY_STRING);
        rv = rs_parse_compare_operator(&rs, COMPARE_EQUAL_BY_STRING);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_STRING_UNEQUAL);

        /* Textual operators */
        cs = "lt rest";
        rs = "lt rest";
        cv = parse_compare_operator(&cs, COMPARE_ALLOW_TEXTUAL);
        rv = rs_parse_compare_operator(&rs, COMPARE_ALLOW_TEXTUAL);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_LOWER);

        cs = "le rest";
        rs = "le rest";
        cv = parse_compare_operator(&cs, COMPARE_ALLOW_TEXTUAL);
        rv = rs_parse_compare_operator(&rs, COMPARE_ALLOW_TEXTUAL);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_LOWER_OR_EQUAL);

        cs = "eq rest";
        rs = "eq rest";
        cv = parse_compare_operator(&cs, COMPARE_ALLOW_TEXTUAL);
        rv = rs_parse_compare_operator(&rs, COMPARE_ALLOW_TEXTUAL);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_EQUAL);

        cs = "ne rest";
        rs = "ne rest";
        cv = parse_compare_operator(&cs, COMPARE_ALLOW_TEXTUAL);
        rv = rs_parse_compare_operator(&rs, COMPARE_ALLOW_TEXTUAL);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_UNEQUAL);

        cs = "ge rest";
        rs = "ge rest";
        cv = parse_compare_operator(&cs, COMPARE_ALLOW_TEXTUAL);
        rv = rs_parse_compare_operator(&rs, COMPARE_ALLOW_TEXTUAL);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_GREATER_OR_EQUAL);

        cs = "gt rest";
        rs = "gt rest";
        cv = parse_compare_operator(&cs, COMPARE_ALLOW_TEXTUAL);
        rv = rs_parse_compare_operator(&rs, COMPARE_ALLOW_TEXTUAL);
        assert_se(cv == rv);
        assert_se(cv == COMPARE_GREATER);

        /* Textual without flag → INVALID */
        cs = "lt rest";
        rs = "lt rest";
        cv = parse_compare_operator(&cs, 0);
        rv = rs_parse_compare_operator(&rs, 0);
        assert_se(cv == rv);
        assert_se(cv == _COMPARE_OPERATOR_INVALID);

        /* NULL input */
        cs = NULL;
        rs = NULL;
        cv = parse_compare_operator(&cs, 0);
        rv = rs_parse_compare_operator(&rs, 0);
        assert_se(cv == rv);
        assert_se(cv == _COMPARE_OPERATOR_INVALID);

        /* Unknown operator */
        cs = "xyz";
        rs = "xyz";
        cv = parse_compare_operator(&cs, 0);
        rv = rs_parse_compare_operator(&rs, 0);
        assert_se(cv == rv);
        assert_se(cv == _COMPARE_OPERATOR_INVALID);
}

/* ── test_order ───────────────────────────────────────────────────────── */

static void test_test_order(void) {
        int cv, rv;

        cv = test_order(-1, COMPARE_LOWER);
        rv = rs_test_order(-1, COMPARE_LOWER);
        assert_se(cv == rv);
        assert_se(cv == 1);

        cv = test_order(0, COMPARE_LOWER);
        rv = rs_test_order(0, COMPARE_LOWER);
        assert_se(cv == rv);
        assert_se(cv == 0);

        cv = test_order(1, COMPARE_LOWER);
        rv = rs_test_order(1, COMPARE_LOWER);
        assert_se(cv == rv);
        assert_se(cv == 0);

        cv = test_order(0, COMPARE_EQUAL);
        rv = rs_test_order(0, COMPARE_EQUAL);
        assert_se(cv == rv);
        assert_se(cv == 1);

        cv = test_order(1, COMPARE_EQUAL);
        rv = rs_test_order(1, COMPARE_EQUAL);
        assert_se(cv == rv);
        assert_se(cv == 0);

        cv = test_order(-1, COMPARE_UNEQUAL);
        rv = rs_test_order(-1, COMPARE_UNEQUAL);
        assert_se(cv == rv);
        assert_se(cv == 1);

        cv = test_order(0, COMPARE_UNEQUAL);
        rv = rs_test_order(0, COMPARE_UNEQUAL);
        assert_se(cv == rv);
        assert_se(cv == 0);

        cv = test_order(1, COMPARE_GREATER);
        rv = rs_test_order(1, COMPARE_GREATER);
        assert_se(cv == rv);
        assert_se(cv == 1);

        cv = test_order(0, COMPARE_GREATER_OR_EQUAL);
        rv = rs_test_order(0, COMPARE_GREATER_OR_EQUAL);
        assert_se(cv == rv);
        assert_se(cv == 1);

        cv = test_order(-1, COMPARE_LOWER_OR_EQUAL);
        rv = rs_test_order(-1, COMPARE_LOWER_OR_EQUAL);
        assert_se(cv == rv);
        assert_se(cv == 1);

        /* Invalid operator */
        cv = test_order(0, _COMPARE_OPERATOR_INVALID);
        rv = rs_test_order(0, _COMPARE_OPERATOR_INVALID);
        assert_se(cv == rv);
        assert_se(cv == -EINVAL);

        /* STRING_EQUAL is not an order operator */
        cv = test_order(0, COMPARE_STRING_EQUAL);
        rv = rs_test_order(0, COMPARE_STRING_EQUAL);
        assert_se(cv == rv);
        assert_se(cv == -EINVAL);
}

int main(int argc, char **argv) {
        test_http_etag_is_valid();
        test_http_url_is_valid();
        test_file_url_is_valid();
        test_documentation_url_is_valid();
        test_rgb_to_hsv();
        test_hsv_to_rgb();
        test_parse_compare_operator();
        test_test_order();
        return 0;
}
