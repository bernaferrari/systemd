/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "percent-util.h"
#include "tests.h"

/* Rust FFI */
#include "rust/percent_util.h"

/* RUST-CONTRACT: percent-parsers */

/* ── parse_percent ───────────────────────────────────────────────────────── */

TEST(parse_percent_normal) {
        assert_se(parse_percent("50%") == rs_parse_percent("50%"));
        assert_se(parse_percent("50%") == 50);
}

TEST(parse_percent_zero) {
        assert_se(parse_percent("0%") == rs_parse_percent("0%"));
        assert_se(parse_percent("0%") == 0);
}

TEST(parse_percent_hundred) {
        assert_se(parse_percent("100%") == rs_parse_percent("100%"));
        assert_se(parse_percent("100%") == 100);
}

TEST(parse_percent_over) {
        assert_se(parse_percent("101%") == rs_parse_percent("101%"));
        assert_se(parse_percent("101%") == -ERANGE);
}

TEST(parse_percent_negative) {
        assert_se(parse_percent("-5%") == rs_parse_percent("-5%"));
        assert_se(parse_percent("-5%") == -ERANGE);
}

TEST(parse_percent_no_symbol) {
        assert_se(parse_percent("50") == rs_parse_percent("50"));
        assert_se(parse_percent("50") == -EINVAL);
}

/* ── parse_percent_unbounded ────────────────────────────────────────────── */

TEST(parse_percent_unbounded) {
        assert_se(parse_percent_unbounded("200%") == rs_parse_percent_unbounded("200%"));
        assert_se(parse_percent_unbounded("200%") == 200);
}

/* ── parse_permille ──────────────────────────────────────────────────────── */

TEST(parse_permille_percent) {
        /* "12.5%" → 125 */
        assert_se(parse_permille("12.5%") == rs_parse_permille("12.5%"));
        assert_se(parse_permille("12.5%") == 125);
}

TEST(parse_permille_percent_whole) {
        /* "50%" → 500 */
        assert_se(parse_permille("50%") == rs_parse_permille("50%"));
        assert_se(parse_permille("50%") == 500);
}

TEST(parse_permille_per_mille) {
        /* "500‰" → 500 */
        assert_se(parse_permille("500‰") == rs_parse_permille("500‰"));
        assert_se(parse_permille("500‰") == 500);
}

TEST(parse_permille_zero) {
        assert_se(parse_permille("0%") == rs_parse_permille("0%"));
        assert_se(parse_permille("0%") == 0);
}

TEST(parse_permille_over) {
        assert_se(parse_permille("1001‰") == rs_parse_permille("1001‰"));
        assert_se(parse_permille("1001‰") == -ERANGE);
}

TEST(parse_permille_bad_decimal) {
        assert_se(parse_permille("12.%") == rs_parse_permille("12.%"));
        assert_se(parse_permille("12.%") == -EINVAL);
}

/* ── parse_permyriad ────────────────────────────────────────────────────── */

TEST(parse_permyriad_percent) {
        /* "12.34%" → 1234 */
        assert_se(parse_permyriad("12.34%") == rs_parse_permyriad("12.34%"));
        assert_se(parse_permyriad("12.34%") == 1234);
}

TEST(parse_permyriad_percent_one_decimal) {
        /* "12.3%" → 1230 */
        assert_se(parse_permyriad("12.3%") == rs_parse_permyriad("12.3%"));
        assert_se(parse_permyriad("12.3%") == 1230);
}

TEST(parse_permyriad_percent_whole) {
        /* "50%" → 5000 */
        assert_se(parse_permyriad("50%") == rs_parse_permyriad("50%"));
        assert_se(parse_permyriad("50%") == 5000);
}

TEST(parse_permyriad_per_mille) {
        /* "500‰" → 5000 */
        assert_se(parse_permyriad("500‰") == rs_parse_permyriad("500‰"));
        assert_se(parse_permyriad("500‰") == 5000);
}

TEST(parse_permyriad_per_mille_decimal) {
        /* "50.5‰" → 505 permille = 505 permyriad */
        assert_se(parse_permyriad("50.5‰") == rs_parse_permyriad("50.5‰"));
        assert_se(parse_permyriad("50.5‰") == 505);
}

TEST(parse_permyriad_per_myriad) {
        /* "5000‱" → 5000 */
        assert_se(parse_permyriad("5000‱") == rs_parse_permyriad("5000‱"));
        assert_se(parse_permyriad("5000‱") == 5000);
}

TEST(parse_permyriad_over) {
        assert_se(parse_permyriad("10001‱") == rs_parse_permyriad("10001‱"));
        assert_se(parse_permyriad("10001‱") == -ERANGE);
}

/* ── parse_permille_unbounded ────────────────────────────────────────────── */

TEST(parse_permille_unbounded_over) {
        /* Unbounded allows values > 1000 */
        assert_se(parse_permille_unbounded("1001‰") == rs_parse_permille_unbounded("1001‰"));
        assert_se(parse_permille_unbounded("1001‰") == 1001);
        assert_se(parse_permille_unbounded("2000‰") == rs_parse_permille_unbounded("2000‰"));
        assert_se(parse_permille_unbounded("2000‰") == 2000);
}

/* ── parse_permyriad_unbounded ───────────────────────────────────────────── */

TEST(parse_permyriad_unbounded_over) {
        /* Unbounded allows values > 10000 */
        assert_se(parse_permyriad_unbounded("10001‱") == rs_parse_permyriad_unbounded("10001‱"));
        assert_se(parse_permyriad_unbounded("10001‱") == 10001);
        assert_se(parse_permyriad_unbounded("20000‱") == rs_parse_permyriad_unbounded("20000‱"));
        assert_se(parse_permyriad_unbounded("20000‱") == 20000);
}

TEST(parse_permyriad_unbounded_percent) {
        /* "150.25%" → 15025 unbounded */
        assert_se(parse_permyriad_unbounded("150.25%") == rs_parse_permyriad_unbounded("150.25%"));
        assert_se(parse_permyriad_unbounded("150.25%") == 15025);
}

/* Exercise the branch and error-precedence boundaries in percent-util.c, in
 * addition to the representative cases above. */
typedef int (*percent_parser_t)(const char *p);

typedef struct PercentParserCase {
        const char *input;
        int expected;
} PercentParserCase;

static void assert_parser_parity(
                percent_parser_t c_parser,
                percent_parser_t rust_parser,
                const PercentParserCase *cases,
                size_t n_cases) {

        FOREACH_ARRAY(test, cases, n_cases) {
                int c_result = c_parser(test->input);
                int rust_result = rust_parser(test->input);

                log_debug("percent parser input %s: C=%d Rust=%d", test->input, c_result, rust_result);
                assert_se(c_result == test->expected);
                assert_se(rust_result == c_result);
        }
}

TEST(parse_percent_branch_parity) {
        static const PercentParserCase cases[] = {
                { "%",                  -EINVAL },
                { "%%",                 -EINVAL },
                { "10",                 -EINVAL },
                { "  +010%",                  8 },
                { "0x10%",                   16 },
                { "0b10%",                    2 },
                { "0B  +10%",                 2 },
                { "0o10%",                    8 },
                { "\v10%",                   10 },
                { "-0%",                       0 },
                { "-1%",                 -ERANGE },
                { "10 %",                -EINVAL },
                { "2147483647%",      INT32_MAX },
                { "2147483648%",        -ERANGE },
                { "999999999999999999999999x%", -ERANGE },
                { "\xff%",              -EINVAL },
        };

        assert_parser_parity(
                        parse_percent_unbounded,
                        rs_parse_percent_unbounded,
                        cases,
                        ELEMENTSOF(cases));
        assert_se(rs_parse_percent_unbounded(NULL) == -EINVAL);
        assert_se(rs_parse_percent(NULL) == -EINVAL);
}

TEST(parse_percent_target_libc_parity) {
        static const char *const cases[] = {
                "+0b10%",
                "-0o10%",
                "\v0b10%",
                "\f0o10%",
        };

        FOREACH_ELEMENT(input, cases)
                assert_se(parse_percent_unbounded(*input) == rs_parse_percent_unbounded(*input));
}

TEST(parse_permille_branch_parity) {
        static const PercentParserCase unbounded_cases[] = {
                { "‰",                  -EINVAL },
                { "1.0‰",               -EINVAL },
                { "1%",                       10 },
                { "1.2%",                     12 },
                { ".2%",                 -EINVAL },
                { "1.%",                 -EINVAL },
                { "1.23%",               -EINVAL },
                { "1.x%",                -EINVAL },
                { "-0.0%",                     0 },
                { "-1.0%",               -ERANGE },
                { "214748364.7%",      INT32_MAX },
                { "214748364.8%",        -ERANGE },
                { "214748364%",         2147483640 },
                { "214748365%",          -ERANGE },
                { "\xff‰",               -EINVAL },
        };
        static const PercentParserCase bounded_cases[] = {
                { "100.0%",                  1000 },
                { "100.1%",               -ERANGE },
                { "1000‰",                   1000 },
                { "1001‰",                 -ERANGE },
        };

        assert_parser_parity(
                        parse_permille_unbounded,
                        rs_parse_permille_unbounded,
                        unbounded_cases,
                        ELEMENTSOF(unbounded_cases));
        assert_parser_parity(
                        parse_permille,
                        rs_parse_permille,
                        bounded_cases,
                        ELEMENTSOF(bounded_cases));
        assert_se(rs_parse_permille_unbounded(NULL) == -EINVAL);
        assert_se(rs_parse_permille(NULL) == -EINVAL);
}

TEST(parse_permyriad_branch_parity) {
        static const PercentParserCase unbounded_cases[] = {
                { "‱",                  -EINVAL },
                { "1.0‱",               -EINVAL },
                { "1‰",                       10 },
                { "1.2‰",                     12 },
                { "1.23‰",               -EINVAL },
                { "1%",                      100 },
                { "1.2%",                    120 },
                { "1.23%",                   123 },
                { ".23%",                -EINVAL },
                { "1.%",                 -EINVAL },
                { "1.234%",              -EINVAL },
                { "1.x%",                -EINVAL },
                { "1.2x%",               -EINVAL },
                { "-0.00%",                    0 },
                { "-1.00%",              -ERANGE },
                { "21474836.47%",      INT32_MAX },
                { "21474836.48%",        -ERANGE },
                { "21474836%",          2147483600 },
                { "21474837%",            -ERANGE },
                { "\xff‱",               -EINVAL },
        };
        static const PercentParserCase bounded_cases[] = {
                { "100.00%",                10000 },
                { "100.01%",              -ERANGE },
                { "1000.0‰",                10000 },
                { "1000.1‰",              -ERANGE },
                { "10000‱",                 10000 },
                { "10001‱",               -ERANGE },
        };

        assert_parser_parity(
                        parse_permyriad_unbounded,
                        rs_parse_permyriad_unbounded,
                        unbounded_cases,
                        ELEMENTSOF(unbounded_cases));
        assert_parser_parity(
                        parse_permyriad,
                        rs_parse_permyriad,
                        bounded_cases,
                        ELEMENTSOF(bounded_cases));
        assert_se(rs_parse_permyriad_unbounded(NULL) == -EINVAL);
        assert_se(rs_parse_permyriad(NULL) == -EINVAL);
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
