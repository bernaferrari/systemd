/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C timestamp_style vs Rust rs_timestamp_style */
/* RUST-CONTRACT: time-timestamp-style-to-string */
/* RUST-CONTRACT: time-timestamp-style-from-string */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "tests.h"
#include "time-util.h"
#include "rust/time_util.h"
#include "string-util.h"

/* ── timestamp_style_to_string ────────────────────────────────────────── */

TEST(timestamp_style_to_string_c_vs_rs) {
        const char *c_ret, *r_ret;

        c_ret = timestamp_style_to_string(TIMESTAMP_PRETTY);
        r_ret = rs_timestamp_style_to_string(TIMESTAMP_PRETTY);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = timestamp_style_to_string(TIMESTAMP_US);
        r_ret = rs_timestamp_style_to_string(TIMESTAMP_US);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = timestamp_style_to_string(TIMESTAMP_UTC);
        r_ret = rs_timestamp_style_to_string(TIMESTAMP_UTC);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = timestamp_style_to_string(TIMESTAMP_US_UTC);
        r_ret = rs_timestamp_style_to_string(TIMESTAMP_US_UTC);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = timestamp_style_to_string(TIMESTAMP_UNIX);
        r_ret = rs_timestamp_style_to_string(TIMESTAMP_UNIX);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* TIMESTAMP_DATE has no to_string representation in C (intentional gap) */
        c_ret = timestamp_style_to_string(TIMESTAMP_DATE);
        r_ret = rs_timestamp_style_to_string(TIMESTAMP_DATE);
        assert_se(streq_ptr(c_ret, r_ret));

        /* Out of range */
        c_ret = timestamp_style_to_string(-1);
        r_ret = rs_timestamp_style_to_string(-1);
        assert_se(streq_ptr(c_ret, r_ret));
        assert_se(!c_ret);

        c_ret = timestamp_style_to_string(99);
        r_ret = rs_timestamp_style_to_string(99);
        assert_se(streq_ptr(c_ret, r_ret));
        assert_se(!c_ret);
}

/* ── timestamp_style_from_string ──────────────────────────────────────── */

TEST(timestamp_style_from_string_c_vs_rs) {
        TimestampStyle cv;
        int rv;

        cv = timestamp_style_from_string("pretty");
        rv = rs_timestamp_style_from_string("pretty");
        assert_se((int)cv == rv);
        assert_se(cv == TIMESTAMP_PRETTY);

        cv = timestamp_style_from_string("us");
        rv = rs_timestamp_style_from_string("us");
        assert_se((int)cv == rv);
        assert_se(cv == TIMESTAMP_US);

        cv = timestamp_style_from_string("utc");
        rv = rs_timestamp_style_from_string("utc");
        assert_se((int)cv == rv);
        assert_se(cv == TIMESTAMP_UTC);

        cv = timestamp_style_from_string("us+utc");
        rv = rs_timestamp_style_from_string("us+utc");
        assert_se((int)cv == rv);
        assert_se(cv == TIMESTAMP_US_UTC);

        cv = timestamp_style_from_string("unix");
        rv = rs_timestamp_style_from_string("unix");
        assert_se((int)cv == rv);
        assert_se(cv == TIMESTAMP_UNIX);

        /* "date" has no from_string representation in C (intentional gap) */
        cv = timestamp_style_from_string("date");
        rv = rs_timestamp_style_from_string("date");
        assert_se((int)cv == rv);
        assert_se((int)cv < 0);

        /* Unicode µs aliases — C accepts both µ (U+00B5) and μ (U+03BC) */
        cv = timestamp_style_from_string("\xC2\xB5s"); /* µ = U+00B5 */
        rv = rs_timestamp_style_from_string("\xC2\xB5s");
        assert_se((int)cv == rv);
        assert_se(cv == TIMESTAMP_US);

        cv = timestamp_style_from_string("\xCE\xBCs"); /* μ = U+03BC */
        rv = rs_timestamp_style_from_string("\xCE\xBCs");
        assert_se((int)cv == rv);
        assert_se(cv == TIMESTAMP_US);

        cv = timestamp_style_from_string("\xC2\xB5s+utc");
        rv = rs_timestamp_style_from_string("\xC2\xB5s+utc");
        assert_se((int)cv == rv);
        assert_se(cv == TIMESTAMP_US_UTC);

        /* Invalid */
        cv = timestamp_style_from_string("bogus");
        rv = rs_timestamp_style_from_string("bogus");
        assert_se((int)cv == rv);
        assert_se((int)cv < 0);

        cv = timestamp_style_from_string(NULL);
        rv = rs_timestamp_style_from_string(NULL);
        assert_se((int)cv == rv);
        assert_se((int)cv < 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
