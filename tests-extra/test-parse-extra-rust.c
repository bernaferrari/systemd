/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C parse_tristate_full, parse_mtu, parse_sector_size,
 *             store_loadavg_fixed_point, parse_loadavg_fixed_point,
 *             parse_gmtoff, format_timespan vs Rust */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include "tests.h"
#include "string-util.h"
#include "parse-util.h"
#include "time-util.h"
#include "rust/parse_util.h"
#include "rust/time_util.h"

/* ── parse_tristate_full ──────────────────────────────────────────────────── */

static void test_parse_tristate_full(void) {
        int cr, rr;

        /* Empty string → -1 */
        assert_se(parse_tristate_full("", "auto", &cr) == 0);
        assert_se(cr == -1);
        assert_se(rs_parse_tristate_full("", "auto", &rr) == 0);
        assert_se(rr == -1);

        /* NULL v → -1 */
        assert_se(parse_tristate_full(NULL, "auto", &cr) == 0);
        assert_se(cr == -1);
        assert_se(rs_parse_tristate_full(NULL, "auto", &rr) == 0);
        assert_se(rr == -1);

        /* Match third string */
        assert_se(parse_tristate_full("auto", "auto", &cr) == 0);
        assert_se(cr == -1);
        assert_se(rs_parse_tristate_full("auto", "auto", &rr) == 0);
        assert_se(rr == -1);

        /* Boolean true */
        assert_se(parse_tristate_full("yes", "auto", &cr) == 0);
        assert_se(cr == 1);
        assert_se(rs_parse_tristate_full("yes", "auto", &rr) == 0);
        assert_se(rr == 1);

        /* Boolean false */
        assert_se(parse_tristate_full("no", "auto", &cr) == 0);
        assert_se(cr == 0);
        assert_se(rs_parse_tristate_full("no", "auto", &rr) == 0);
        assert_se(rr == 0);

        /* Invalid boolean */
        assert_se(parse_tristate_full("bogus", "auto", &cr) < 0);
        assert_se(rs_parse_tristate_full("bogus", "auto", &rr) < 0);

        /* NULL ret pointer */
        assert_se(parse_tristate_full("yes", "auto", NULL) == 0);
        assert_se(rs_parse_tristate_full("yes", "auto", NULL) == 0);
}

/* ── parse_mtu ───────────────────────────────────────────────────────────── */

static void test_parse_mtu(void) {
        uint32_t cr, rr;

        /* Valid MTU */
        assert_se(parse_mtu(AF_INET, "1500", &cr) == 0);
        assert_se(rs_parse_mtu(AF_INET, "1500", &rr) == 0);
        assert_se(cr == rr && cr == 1500);

        assert_se(parse_mtu(AF_INET6, "9000", &cr) == 0);
        assert_se(rs_parse_mtu(AF_INET6, "9000", &rr) == 0);
        assert_se(cr == rr && cr == 9000);

        /* Below IPv4 minimum */
        assert_se(parse_mtu(AF_INET, "50", &cr) == -ERANGE);
        assert_se(rs_parse_mtu(AF_INET, "50", &rr) == -ERANGE);

        /* Below IPv6 minimum */
        assert_se(parse_mtu(AF_INET6, "1000", &cr) == -ERANGE);
        assert_se(rs_parse_mtu(AF_INET6, "1000", &rr) == -ERANGE);

        /* No family restriction */
        assert_se(parse_mtu(0, "100", &cr) == 0);
        assert_se(rs_parse_mtu(0, "100", &rr) == 0);
        assert_se(cr == rr && cr == 100);

        /* Invalid */
        assert_se(parse_mtu(AF_INET, "bogus", &cr) < 0);
        assert_se(rs_parse_mtu(AF_INET, "bogus", &rr) < 0);
}

/* ── parse_sector_size ────────────────────────────────────────────────────── */

static void test_parse_sector_size(void) {
        uint64_t cr, rr;

        /* Valid sector sizes */
        assert_se(parse_sector_size("512", &cr) == 0);
        assert_se(rs_parse_sector_size("512", &rr) == 0);
        assert_se(cr == rr && cr == 512);

        assert_se(parse_sector_size("4096", &cr) == 0);
        assert_se(rs_parse_sector_size("4096", &rr) == 0);
        assert_se(cr == rr && cr == 4096);

        assert_se(parse_sector_size("1024", &cr) == 0);
        assert_se(rs_parse_sector_size("1024", &rr) == 0);
        assert_se(cr == rr && cr == 1024);

        /* Too small */
        assert_se(parse_sector_size("256", &cr) == -ERANGE);
        assert_se(rs_parse_sector_size("256", &rr) == -ERANGE);

        /* Too large */
        assert_se(parse_sector_size("8192", &cr) == -ERANGE);
        assert_se(rs_parse_sector_size("8192", &rr) == -ERANGE);

        /* Not power of 2 */
        assert_se(parse_sector_size("1000", &cr) == -EINVAL);
        assert_se(rs_parse_sector_size("1000", &rr) == -EINVAL);

        /* Invalid */
        assert_se(parse_sector_size("bogus", &cr) < 0);
        assert_se(rs_parse_sector_size("bogus", &rr) < 0);
}

/* ── store_loadavg_fixed_point / parse_loadavg_fixed_point ─────────────────── */

static void test_loadavg_fixed_point(void) {
        unsigned long cr, rr;

        /* store_loadavg_fixed_point: 0.0 → 0 */
        assert_se(store_loadavg_fixed_point(0, 0, &cr) == 0);
        assert_se(rs_store_loadavg_fixed_point(0, 0, &rr) == 0);
        assert_se(cr == rr && cr == 0);

        /* store_loadavg_fixed_point: 0.5 → 1024 (0.5 * 2^11) */
        assert_se(store_loadavg_fixed_point(0, 50, &cr) == 0);
        assert_se(rs_store_loadavg_fixed_point(0, 50, &rr) == 0);
        assert_se(cr == rr && cr == 1024);

        /* store_loadavg_fixed_point: 1.0 → 2048 (1.0 * 2^11) */
        assert_se(store_loadavg_fixed_point(1, 0, &cr) == 0);
        assert_se(rs_store_loadavg_fixed_point(1, 0, &rr) == 0);
        assert_se(cr == rr && cr == 2048);

        /* store_loadavg_fixed_point: 2.75 */
        assert_se(store_loadavg_fixed_point(2, 75, &cr) == 0);
        assert_se(rs_store_loadavg_fixed_point(2, 75, &rr) == 0);
        assert_se(cr == rr);

        /* parse_loadavg_fixed_point: "0.00" → 0 */
        assert_se(parse_loadavg_fixed_point("0.00", &cr) == 0);
        assert_se(rs_parse_loadavg_fixed_point("0.00", &rr) == 0);
        assert_se(cr == rr && cr == 0);

        /* parse_loadavg_fixed_point: "1.50" */
        assert_se(parse_loadavg_fixed_point("1.50", &cr) == 0);
        assert_se(rs_parse_loadavg_fixed_point("1.50", &rr) == 0);
        assert_se(cr == rr);

        /* parse_loadavg_fixed_point: "0.45" */
        assert_se(parse_loadavg_fixed_point("0.45", &cr) == 0);
        assert_se(rs_parse_loadavg_fixed_point("0.45", &rr) == 0);
        assert_se(cr == rr);

        /* No dot → error */
        assert_se(parse_loadavg_fixed_point("42", &cr) == -EINVAL);
        assert_se(rs_parse_loadavg_fixed_point("42", &rr) == -EINVAL);

        /* Invalid */
        assert_se(parse_loadavg_fixed_point("abc", &cr) == -EINVAL);
        assert_se(rs_parse_loadavg_fixed_point("abc", &rr) == -EINVAL);
}

/* ── parse_gmtoff ──────────────────────────────────────────────────────────── */

static void test_parse_gmtoff(void) {
        long cr, rr;

        /* "+0900" = 9 hours = 32400 seconds */
        assert_se(parse_gmtoff("+0900", &cr) == 0);
        assert_se(rs_parse_gmtoff("+0900", &rr) == 0);
        assert_se(cr == rr && cr == 32400);

        /* "-0500" = -5 hours = -18000 seconds */
        assert_se(parse_gmtoff("-0500", &cr) == 0);
        assert_se(rs_parse_gmtoff("-0500", &rr) == 0);
        assert_se(cr == rr && cr == -18000);

        /* "+00:00" = 0 */
        assert_se(parse_gmtoff("+00:00", &cr) == 0);
        assert_se(rs_parse_gmtoff("+00:00", &rr) == 0);
        assert_se(cr == rr && cr == 0);

        /* "-14:00" = -14 hours = -50400 seconds */
        assert_se(parse_gmtoff("-14:00", &cr) == 0);
        assert_se(rs_parse_gmtoff("-14:00", &rr) == 0);
        assert_se(cr == rr && cr == -50400);

        /* "+09" = +9 hours (2-digit shorthand) */
        assert_se(parse_gmtoff("+09", &cr) == 0);
        assert_se(rs_parse_gmtoff("+09", &rr) == 0);
        assert_se(cr == rr && cr == 32400);

        /* Invalid: no sign */
        assert_se(parse_gmtoff("0900", &cr) == -EINVAL);
        assert_se(rs_parse_gmtoff("0900", &rr) == -EINVAL);

        /* Invalid: non-digit */
        assert_se(parse_gmtoff("+ab", &cr) == -EINVAL);
        assert_se(rs_parse_gmtoff("+ab", &rr) == -EINVAL);

        /* Invalid: empty */
        assert_se(parse_gmtoff("", &cr) == -EINVAL);
        assert_se(rs_parse_gmtoff("", &rr) == -EINVAL);

        /* Invalid: too large (>24 hours) — glibc strptime may accept this */
        assert_se(rs_parse_gmtoff("+25:00", &rr) == -EINVAL);

        /* Invalid: minutes >= 60 — glibc strptime may accept this */
        assert_se(rs_parse_gmtoff("+00:60", &rr) == -EINVAL);

        /* NULL ret */
        assert_se(parse_gmtoff("+0900", NULL) == 0);
        assert_se(rs_parse_gmtoff("+0900", NULL) == 0);
}

/* ── format_timespan ──────────────────────────────────────────────────────── */

static void test_format_timespan(void) {
        char cbuf[256];
        char rbuf[256];
        const char *cr, *rr;

        /* Zero → "0" */
        cr = format_timespan(cbuf, sizeof(cbuf), 0, 0);
        rr = rs_format_timespan(rbuf, sizeof(rbuf), 0, 0);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "0"));

        /* 500ms */
        cr = format_timespan(cbuf, sizeof(cbuf), 500 * USEC_PER_MSEC, 0);
        rr = rs_format_timespan(rbuf, sizeof(rbuf), 500 * USEC_PER_MSEC, 0);
        assert_se(streq(cr, rr));

        /* 1.5s */
        cr = format_timespan(cbuf, sizeof(cbuf), 1500000, 0);
        rr = rs_format_timespan(rbuf, sizeof(rbuf), 1500000, 0);
        assert_se(streq(cr, rr));

        /* 5min 30s */
        cr = format_timespan(cbuf, sizeof(cbuf), 330 * USEC_PER_SEC, 0);
        rr = rs_format_timespan(rbuf, sizeof(rbuf), 330 * USEC_PER_SEC, 0);
        assert_se(streq(cr, rr));

        /* 1h 23min */
        cr = format_timespan(cbuf, sizeof(cbuf), 4980 * USEC_PER_SEC, 0);
        rr = rs_format_timespan(rbuf, sizeof(rbuf), 4980 * USEC_PER_SEC, 0);
        assert_se(streq(cr, rr));

        /* 2 days */
        cr = format_timespan(cbuf, sizeof(cbuf), 2 * USEC_PER_DAY, 0);
        rr = rs_format_timespan(rbuf, sizeof(rbuf), 2 * USEC_PER_DAY, 0);
        assert_se(streq(cr, rr));

        /* Negative value wraps to USEC_INFINITY → "infinity" */
        cr = format_timespan(cbuf, sizeof(cbuf), -1, 0);
        rr = rs_format_timespan(rbuf, sizeof(rbuf), -1, 0);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "infinity"));

        /* NULL buf → Rust returns NULL (C asserts, so skip C comparison) */
        rr = rs_format_timespan(NULL, 0, 1000000, 0);
        assert_se(rr == NULL);

        /* Zero-length buf → Rust returns NULL (C asserts, so skip C comparison) */
        rr = rs_format_timespan(rbuf, 0, 1000000, 0);
        assert_se(rr == NULL);
}

int main(int argc, char **argv) {
        test_parse_tristate_full();
        test_parse_mtu();
        test_parse_sector_size();
        test_loadavg_fixed_point();
        test_parse_gmtoff();
        test_format_timespan();
        return 0;
}
