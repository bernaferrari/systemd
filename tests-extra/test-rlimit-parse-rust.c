/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C vs Rust for safe_atou64 and rlimit_parse_nice */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "tests.h"
#include "parse-util.h"
#include "rlimit-util.h"
#include "string-util.h"
#include "rust/parse_util.h"
#include "rust/rlimit_util.h"

/* -- safe_atou64 ----------------------------------------------------------- */

static void test_safe_atou64(void) {
        uint64_t c_val = 0, rs_val = 0;
        int c_r, rs_r;

        /* Normal values */
        c_r = safe_atou64("42", &c_val);
        rs_r = rs_safe_atou64("42", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);
        assert_se(c_val == 42);

        c_val = 0; rs_val = 0;
        c_r = safe_atou64("18446744073709551615", &c_val); /* UINT64_MAX */
        rs_r = rs_safe_atou64("18446744073709551615", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);

        c_val = 0; rs_val = 0;
        c_r = safe_atou64("0", &c_val);
        rs_r = rs_safe_atou64("0", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);
        assert_se(c_val == 0);

        /* Leading zeros */
        c_val = 0; rs_val = 0;
        c_r = safe_atou64("007", &c_val);
        rs_r = rs_safe_atou64("007", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);

        /* Overflow */
        c_val = 0; rs_val = 0;
        c_r = safe_atou64("18446744073709551616", &c_val); /* UINT64_MAX + 1 */
        rs_r = rs_safe_atou64("18446744073709551616", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);

        /* Negative */
        c_val = 0; rs_val = 0;
        c_r = safe_atou64("-1", &c_val);
        rs_r = rs_safe_atou64("-1", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);

        /* Empty */
        c_val = 0; rs_val = 0;
        c_r = safe_atou64("", &c_val);
        rs_r = rs_safe_atou64("", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);

        /* Invalid */
        c_val = 0; rs_val = 0;
        c_r = safe_atou64("abc", &c_val);
        rs_r = rs_safe_atou64("abc", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);

        /* NULL — both C and Rust assert on NULL, skip this test */

        /* Hex */
        c_val = 0; rs_val = 0;
        c_r = safe_atou64("0xff", &c_val);
        rs_r = rs_safe_atou64("0xff", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == 0xff);
}

/* -- rlimit_parse_nice (via rlimit_parse_one with RLIMIT_NICE) ------------- */

static void test_rlimit_parse_nice(void) {
        rlim_t c_val = 0, rs_val = 0;
        int c_r, rs_r;

        /* Raw values: 0 is valid (kernel default) */
        c_r = rlimit_parse_one(RLIMIT_NICE, "0", &c_val);
        rs_r = rs_rlimit_parse_nice("0", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == rs_val);

        /* Raw value 1 (maps to nice level 19) */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NICE, "1", &c_val);
        rs_r = rs_rlimit_parse_nice("1", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);

        /* Raw value 20 (maps to nice level 0) */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NICE, "20", &c_val);
        rs_r = rs_rlimit_parse_nice("20", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);

        /* Raw value 40 (maps to nice level -20) */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NICE, "40", &c_val);
        rs_r = rs_rlimit_parse_nice("40", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);

        /* Raw value 41 — out of range */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NICE, "41", &c_val);
        rs_r = rs_rlimit_parse_nice("41", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);

        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NICE, "+0x13", &c_val);
        rs_r = rs_rlimit_parse_nice("+0x13", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);

        /* Positive nice: "+0" → 20 (nice level 0) */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NICE, "+0", &c_val);
        rs_r = rs_rlimit_parse_nice("+0", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == 20);
        assert_se(rs_val == 20);

        /* Positive nice: "+19" → 1 */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NICE, "+19", &c_val);
        rs_r = rs_rlimit_parse_nice("+19", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == rs_val);

        /* Positive nice: "+20" — out of range */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NICE, "+20", &c_val);
        rs_r = rs_rlimit_parse_nice("+20", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);

        /* Negative nice: "-0" → 20 (nice level 0) */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NICE, "-0", &c_val);
        rs_r = rs_rlimit_parse_nice("-0", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == 20);
        assert_se(rs_val == 20);

        /* Negative nice: "-20" → 40 (nice level -20) */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NICE, "-20", &c_val);
        rs_r = rs_rlimit_parse_nice("-20", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == 40);
        assert_se(rs_val == 40);

        /* Negative nice: "-21" — out of range */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NICE, "-21", &c_val);
        rs_r = rs_rlimit_parse_nice("-21", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);

        /* "infinity" is not a valid nice value */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NICE, "infinity", &c_val);
        rs_r = rs_rlimit_parse_nice("infinity", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);
}

/* -- safe_atoi64 ----------------------------------------------------------- */

static void test_safe_atoi64(void) {
        int64_t c_val = 0, rs_val = 0;
        int c_r, rs_r;

        c_r = safe_atoi64("42", &c_val);
        rs_r = rs_safe_atoi64("42", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);
        assert_se(c_val == 42);

        c_val = 0; rs_val = 0;
        c_r = safe_atoi64("-1", &c_val);
        rs_r = rs_safe_atoi64("-1", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);
        assert_se(c_val == -1);

        c_val = 0; rs_val = 0;
        c_r = safe_atoi64("9223372036854775807", &c_val); /* INT64_MAX */
        rs_r = rs_safe_atoi64("9223372036854775807", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);

        c_val = 0; rs_val = 0;
        c_r = safe_atoi64("0", &c_val);
        rs_r = rs_safe_atoi64("0", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);

        /* Overflow */
        c_val = 0; rs_val = 0;
        c_r = safe_atoi64("9223372036854775808", &c_val); /* INT64_MAX + 1 */
        rs_r = rs_safe_atoi64("9223372036854775808", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);

        /* Invalid */
        c_val = 0; rs_val = 0;
        c_r = safe_atoi64("abc", &c_val);
        rs_r = rs_safe_atoi64("abc", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);

        /* Empty */
        c_val = 0; rs_val = 0;
        c_r = safe_atoi64("", &c_val);
        rs_r = rs_safe_atoi64("", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);
}

/* -- safe_atoux64 ---------------------------------------------------------- */

static void test_safe_atoux64(void) {
        uint64_t c_val = 0, rs_val = 0;
        int c_r, rs_r;

        c_r = safe_atoux64("ff", &c_val);
        rs_r = rs_safe_atoux64("ff", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);
        assert_se(c_val == 0xff);

        c_val = 0; rs_val = 0;
        c_r = safe_atoux64("0xff", &c_val);
        rs_r = rs_safe_atoux64("0xff", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);
        assert_se(c_val == 0xff);

        c_val = 0; rs_val = 0;
        c_r = safe_atoux64("0", &c_val);
        rs_r = rs_safe_atoux64("0", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);

        c_val = 0; rs_val = 0;
        c_r = safe_atoux64("deadbeef", &c_val);
        rs_r = rs_safe_atoux64("deadbeef", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);

        c_val = 0; rs_val = 0;
        c_r = safe_atoux64("FFFFFFFFFFFFFFFF", &c_val); /* UINT64_MAX */
        rs_r = rs_safe_atoux64("FFFFFFFFFFFFFFFF", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);

        /* Invalid (decimal in hex mode) */
        c_val = 0; rs_val = 0;
        c_r = safe_atoux64("xyz", &c_val);
        rs_r = rs_safe_atoux64("xyz", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);

        /* Empty */
        c_val = 0; rs_val = 0;
        c_r = safe_atoux64("", &c_val);
        rs_r = rs_safe_atoux64("", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);
}

/* -- rlimit_parse_size (via rlimit_parse_one with RLIMIT_FSIZE) ------------ */

static void test_rlimit_parse_size(void) {
        rlim_t c_val = 0, rs_val = 0;
        int c_r, rs_r;

        /* Normal size */
        c_r = rlimit_parse_one(RLIMIT_FSIZE, "16M", &c_val);
        rs_r = rs_rlimit_parse_size("16M", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == rs_val);

        /* Bytes */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_FSIZE, "1024", &c_val);
        rs_r = rs_rlimit_parse_size("1024", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == 1024);
        assert_se(rs_val == 1024);

        /* Zero */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_FSIZE, "0", &c_val);
        rs_r = rs_rlimit_parse_size("0", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);

        /* "infinity" */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_FSIZE, "infinity", &c_val);
        rs_r = rs_rlimit_parse_size("infinity", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == RLIM_INFINITY);
        assert_se(rs_val == RLIM_INFINITY);

        /* K suffix */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_FSIZE, "4K", &c_val);
        rs_r = rs_rlimit_parse_size("4K", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == 4096);
        assert_se(rs_val == 4096);

        /* G suffix */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_FSIZE, "1G", &c_val);
        rs_r = rs_rlimit_parse_size("1G", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == 1073741824);
        assert_se(rs_val == 1073741824);

        /* Invalid */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_FSIZE, "abc", &c_val);
        rs_r = rs_rlimit_parse_size("abc", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);

        /* Empty */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_FSIZE, "", &c_val);
        rs_r = rs_rlimit_parse_size("", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);
}

/* -- rlimit_parse_u64 (via rlimit_parse_one with RLIMIT_NOFILE) ------------ */

static void test_rlimit_parse_u64(void) {
        rlim_t c_val = 0, rs_val = 0;
        int c_r, rs_r;

        /* Normal value */
        c_r = rlimit_parse_one(RLIMIT_NOFILE, "1024", &c_val);
        rs_r = rs_rlimit_parse_u64("1024", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == rs_val);

        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NOFILE, "0x400", &c_val);
        rs_r = rs_rlimit_parse_u64("0x400", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);
        assert_se(c_val == 1024);

        /* Zero */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NOFILE, "0", &c_val);
        rs_r = rs_rlimit_parse_u64("0", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == rs_val);

        /* "infinity" */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NOFILE, "infinity", &c_val);
        rs_r = rs_rlimit_parse_u64("infinity", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r == 0);
        assert_se(c_val == RLIM_INFINITY);
        assert_se(rs_val == RLIM_INFINITY);

        /* Large value */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NOFILE, "18446744073709551614", &c_val);
        rs_r = rs_rlimit_parse_u64("18446744073709551614", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_val == rs_val);

        /* Invalid */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NOFILE, "abc", &c_val);
        rs_r = rs_rlimit_parse_u64("abc", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);

        /* Empty */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NOFILE, "", &c_val);
        rs_r = rs_rlimit_parse_u64("", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);

        /* Negative */
        c_val = 0; rs_val = 0;
        c_r = rlimit_parse_one(RLIMIT_NOFILE, "-1", &c_val);
        rs_r = rs_rlimit_parse_u64("-1", &rs_val);
        assert_se(c_r == rs_r);
        assert_se(c_r < 0);
}

/* -- rlimit_format (Rust-only: C version has symbol versioning issues) ----- */

static void test_rlimit_format(void) {
        _cleanup_free_ char *rs_ret = NULL;
        int r;
        struct rlimit rl;

        /* Both infinity */
        rl.rlim_cur = RLIM_INFINITY;
        rl.rlim_max = RLIM_INFINITY;
        r = rs_rlimit_format(&rl, &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(rs_ret, "infinity"));

        rs_ret = mfree(rs_ret);

        /* Both same finite value */
        rl.rlim_cur = 1024;
        rl.rlim_max = 1024;
        r = rs_rlimit_format(&rl, &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(rs_ret, "1024"));

        rs_ret = mfree(rs_ret);

        /* Different values */
        rl.rlim_cur = 1024;
        rl.rlim_max = 4096;
        r = rs_rlimit_format(&rl, &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(rs_ret, "1024:4096"));

        rs_ret = mfree(rs_ret);

        /* cur infinity, max finite */
        rl.rlim_cur = RLIM_INFINITY;
        rl.rlim_max = 4096;
        r = rs_rlimit_format(&rl, &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(rs_ret, "infinity:4096"));

        rs_ret = mfree(rs_ret);

        /* cur finite, max infinity */
        rl.rlim_cur = 1024;
        rl.rlim_max = RLIM_INFINITY;
        r = rs_rlimit_format(&rl, &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(rs_ret, "1024:infinity"));

        assert_se(rs_rlimit_format(NULL, &rs_ret) == -EINVAL);
        assert_se(rs_rlimit_format(&rl, NULL) == -EINVAL);
}

static void test_rlimit_rust_null_boundaries(void) {
        rlim_t value = 4711;

        assert_se(rs_rlimit_from_string(NULL) == -EINVAL);
        assert_se(rs_rlimit_from_string_harder(NULL) == -EINVAL);
        assert_se(rs_rlimit_parse_nice(NULL, &value) == -EINVAL);
        assert_se(value == 4711);
        assert_se(rs_rlimit_parse_u64("1", NULL) == -EINVAL);
        assert_se(rs_rlimit_parse_size(NULL, &value) == -EINVAL);
        assert_se(value == 4711);
}

int main(int argc, char **argv) {
        test_safe_atou64();
        test_safe_atoi64();
        test_safe_atoux64();
        test_rlimit_parse_size();
        test_rlimit_parse_u64();
        test_rlimit_parse_nice();
        test_rlimit_format();
        test_rlimit_rust_null_boundaries();
        return 0;
}
