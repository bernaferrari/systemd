/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "tests.h"
#include "time-util.h"

/* Rust FFI */
#include "rust/time_util.h"

/* ── map_clock_usec_raw ─────────────────────────────────────────────────── */
/* RUST-CONTRACT: time-map-clock-usec-raw */

TEST(map_clock_usec_raw_future) {
        /* from > from_base, simple addition */
        assert_se(map_clock_usec_raw(110, 100, 200) == rs_map_clock_usec_raw(110, 100, 200));
        assert_se(map_clock_usec_raw(110, 100, 200) == 210);
}

TEST(map_clock_usec_raw_past) {
        /* from < from_base, subtraction */
        assert_se(map_clock_usec_raw(90, 100, 200) == rs_map_clock_usec_raw(90, 100, 200));
        assert_se(map_clock_usec_raw(90, 100, 200) == 190);
}

TEST(map_clock_usec_raw_equal) {
        /* from == from_base */
        assert_se(map_clock_usec_raw(100, 100, 200) == rs_map_clock_usec_raw(100, 100, 200));
        assert_se(map_clock_usec_raw(100, 100, 200) == 200);
}

TEST(map_clock_usec_raw_zero_base) {
        assert_se(map_clock_usec_raw(50, 0, 100) == rs_map_clock_usec_raw(50, 0, 100));
        assert_se(map_clock_usec_raw(50, 0, 100) == 150);
}

TEST(map_clock_usec_raw_overflow) {
        /* delta would overflow USEC_INFINITY */
        usec_t from = USEC_INFINITY - 10;
        usec_t from_base = 0;
        usec_t to_base = USEC_INFINITY - 5;
        assert_se(map_clock_usec_raw(from, from_base, to_base) == rs_map_clock_usec_raw(from, from_base, to_base));
        assert_se(map_clock_usec_raw(from, from_base, to_base) == USEC_INFINITY);
}

TEST(map_clock_usec_raw_underflow) {
        /* to_base - delta would underflow */
        assert_se(map_clock_usec_raw(0, 100, 50) == rs_map_clock_usec_raw(0, 100, 50));
        assert_se(map_clock_usec_raw(0, 100, 50) == 0);
}

/* ── timespec_load ──────────────────────────────────────────────────────── */
/* RUST-CONTRACT: time-timespec-load */

TEST(timespec_load_normal) {
        struct timespec ts = { .tv_sec = 5, .tv_nsec = 500000 };
        assert_se(timespec_load(&ts) == rs_timespec_load(&ts));
        assert_se(timespec_load(&ts) == 5000500);
}

TEST(timespec_load_zero) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 0 };
        assert_se(timespec_load(&ts) == rs_timespec_load(&ts));
        assert_se(timespec_load(&ts) == 0);
}

TEST(timespec_load_negative_sec) {
        struct timespec ts = { .tv_sec = -1, .tv_nsec = 0 };
        assert_se(timespec_load(&ts) == rs_timespec_load(&ts));
        assert_se(timespec_load(&ts) == USEC_INFINITY);
}

TEST(timespec_load_negative_nsec) {
        struct timespec ts = { .tv_sec = 5, .tv_nsec = -1 };
        assert_se(timespec_load(&ts) == rs_timespec_load(&ts));
        assert_se(timespec_load(&ts) == USEC_INFINITY);
}

TEST(timespec_load_no_nsec) {
        struct timespec ts = { .tv_sec = 3, .tv_nsec = 0 };
        assert_se(timespec_load(&ts) == rs_timespec_load(&ts));
        assert_se(timespec_load(&ts) == 3000000);
}

/* ── timespec_load_nsec ─────────────────────────────────────────────────── */
/* RUST-CONTRACT: time-timespec-load-nsec */

TEST(timespec_load_nsec_normal) {
        struct timespec ts = { .tv_sec = 2, .tv_nsec = 500000000 };
        assert_se(timespec_load_nsec(&ts) == rs_timespec_load_nsec(&ts));
        assert_se(timespec_load_nsec(&ts) == 2500000000ULL);
}

TEST(timespec_load_nsec_negative) {
        struct timespec ts = { .tv_sec = -1, .tv_nsec = 0 };
        assert_se(timespec_load_nsec(&ts) == rs_timespec_load_nsec(&ts));
        assert_se(timespec_load_nsec(&ts) == NSEC_INFINITY);
}

/* ── timespec_store ─────────────────────────────────────────────────────── */
/* RUST-CONTRACT: time-timespec-store */

TEST(timespec_store_normal) {
        struct timespec c_ts, rs_ts;
        memset(&c_ts, 0, sizeof(c_ts));
        memset(&rs_ts, 0, sizeof(rs_ts));
        timespec_store(&c_ts, 5500000);
        rs_timespec_store(&rs_ts, 5500000);
        assert_se(c_ts.tv_sec == rs_ts.tv_sec);
        assert_se(c_ts.tv_nsec == rs_ts.tv_nsec);
        assert_se(c_ts.tv_sec == 5);
        assert_se(c_ts.tv_nsec == 500000000);
}

TEST(timespec_store_infinity) {
        struct timespec c_ts, rs_ts;
        timespec_store(&c_ts, USEC_INFINITY);
        rs_timespec_store(&rs_ts, USEC_INFINITY);
        assert_se(c_ts.tv_sec == rs_ts.tv_sec);
        assert_se(c_ts.tv_nsec == rs_ts.tv_nsec);
        assert_se(c_ts.tv_sec == -1);
}

TEST(timespec_store_zero) {
        struct timespec c_ts, rs_ts;
        timespec_store(&c_ts, 0);
        rs_timespec_store(&rs_ts, 0);
        assert_se(c_ts.tv_sec == rs_ts.tv_sec);
        assert_se(c_ts.tv_nsec == rs_ts.tv_nsec);
        assert_se(c_ts.tv_sec == 0 && c_ts.tv_nsec == 0);
}

/* ── timespec_store_nsec ────────────────────────────────────────────────── */
/* RUST-CONTRACT: time-timespec-store-nsec */

TEST(timespec_store_nsec_normal) {
        struct timespec c_ts, rs_ts;
        timespec_store_nsec(&c_ts, 2500000000ULL);
        rs_timespec_store_nsec(&rs_ts, 2500000000ULL);
        assert_se(c_ts.tv_sec == rs_ts.tv_sec);
        assert_se(c_ts.tv_nsec == rs_ts.tv_nsec);
        assert_se(c_ts.tv_sec == 2 && c_ts.tv_nsec == 500000000);
}

/* ── timeval_load ────────────────────────────────────────────────────────── */
/* RUST-CONTRACT: time-timeval-load */

TEST(timeval_load_normal) {
        struct timeval tv = { .tv_sec = 5, .tv_usec = 500000 };
        assert_se(timeval_load(&tv) == rs_timeval_load(&tv));
        assert_se(timeval_load(&tv) == 5500000);
}

TEST(timeval_load_negative_sec) {
        struct timeval tv = { .tv_sec = -1, .tv_usec = 0 };
        assert_se(timeval_load(&tv) == rs_timeval_load(&tv));
        assert_se(timeval_load(&tv) == USEC_INFINITY);
}

TEST(timeval_load_negative_usec) {
        struct timeval tv = { .tv_sec = 5, .tv_usec = -1 };
        assert_se(timeval_load(&tv) == rs_timeval_load(&tv));
        assert_se(timeval_load(&tv) == USEC_INFINITY);
}

TEST(timeval_load_zero) {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 0 };
        assert_se(timeval_load(&tv) == rs_timeval_load(&tv));
        assert_se(timeval_load(&tv) == 0);
}

/* ── timeval_store ──────────────────────────────────────────────────────── */
/* RUST-CONTRACT: time-timeval-store */

TEST(timeval_store_normal) {
        struct timeval c_tv, rs_tv;
        timeval_store(&c_tv, 5500000);
        rs_timeval_store(&rs_tv, 5500000);
        assert_se(c_tv.tv_sec == rs_tv.tv_sec);
        assert_se(c_tv.tv_usec == rs_tv.tv_usec);
        assert_se(c_tv.tv_sec == 5 && c_tv.tv_usec == 500000);
}

TEST(timeval_store_infinity) {
        struct timeval c_tv, rs_tv;
        timeval_store(&c_tv, USEC_INFINITY);
        rs_timeval_store(&rs_tv, USEC_INFINITY);
        assert_se(c_tv.tv_sec == rs_tv.tv_sec);
        assert_se(c_tv.tv_usec == rs_tv.tv_usec);
        assert_se(c_tv.tv_sec == -1);
}

TEST(timeval_store_zero) {
        struct timeval c_tv, rs_tv;
        timeval_store(&c_tv, 0);
        rs_timeval_store(&rs_tv, 0);
        assert_se(c_tv.tv_sec == rs_tv.tv_sec);
        assert_se(c_tv.tv_usec == rs_tv.tv_usec);
        assert_se(c_tv.tv_sec == 0 && c_tv.tv_usec == 0);
}

/* ── triple_timestamp_by_clock ──────────────────────────────────────────── */

TEST(triple_timestamp_by_clock_realtime) {
        triple_timestamp ts = { .realtime = 100, .monotonic = 200, .boottime = 300 };
        assert_se(triple_timestamp_by_clock(&ts, CLOCK_REALTIME) == rs_triple_timestamp_by_clock(&ts, CLOCK_REALTIME));
        assert_se(triple_timestamp_by_clock(&ts, CLOCK_REALTIME) == 100);
}

TEST(triple_timestamp_by_clock_monotonic) {
        triple_timestamp ts = { .realtime = 100, .monotonic = 200, .boottime = 300 };
        assert_se(triple_timestamp_by_clock(&ts, CLOCK_MONOTONIC) == rs_triple_timestamp_by_clock(&ts, CLOCK_MONOTONIC));
        assert_se(triple_timestamp_by_clock(&ts, CLOCK_MONOTONIC) == 200);
}

TEST(triple_timestamp_by_clock_boottime) {
        triple_timestamp ts = { .realtime = 100, .monotonic = 200, .boottime = 300 };
        assert_se(triple_timestamp_by_clock(&ts, CLOCK_BOOTTIME) == rs_triple_timestamp_by_clock(&ts, CLOCK_BOOTTIME));
        assert_se(triple_timestamp_by_clock(&ts, CLOCK_BOOTTIME) == 300);
}

TEST(triple_timestamp_by_clock_alarm) {
        triple_timestamp ts = { .realtime = 100, .monotonic = 200, .boottime = 300 };
        assert_se(triple_timestamp_by_clock(&ts, CLOCK_REALTIME_ALARM) == rs_triple_timestamp_by_clock(&ts, CLOCK_REALTIME_ALARM));
        assert_se(triple_timestamp_by_clock(&ts, CLOCK_REALTIME_ALARM) == 100);
}

TEST(triple_timestamp_by_clock_unknown) {
        triple_timestamp ts = { .realtime = 100, .monotonic = 200, .boottime = 300 };
        assert_se(triple_timestamp_by_clock(&ts, 99) == rs_triple_timestamp_by_clock(&ts, 99));
        assert_se(triple_timestamp_by_clock(&ts, 99) == USEC_INFINITY);
}

/* ── parse_time ───────────────────────────────────────────────────────────── */

TEST(parse_time_seconds) {
        usec_t c_val, r_val;
        assert_se(parse_time("5s", &c_val, USEC_PER_SEC) >= 0);
        assert_se(rs_parse_time("5s", &r_val, USEC_PER_SEC) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 5 * USEC_PER_SEC);
}

TEST(parse_time_minutes) {
        usec_t c_val, r_val;
        assert_se(parse_time("5min", &c_val, USEC_PER_SEC) >= 0);
        assert_se(rs_parse_time("5min", &r_val, USEC_PER_SEC) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 5 * USEC_PER_MINUTE);
}

TEST(parse_time_hours) {
        usec_t c_val, r_val;
        assert_se(parse_time("2h", &c_val, USEC_PER_SEC) >= 0);
        assert_se(rs_parse_time("2h", &r_val, USEC_PER_SEC) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 2 * USEC_PER_HOUR);
}

TEST(parse_time_days) {
        usec_t c_val, r_val;
        assert_se(parse_time("3d", &c_val, USEC_PER_SEC) >= 0);
        assert_se(rs_parse_time("3d", &r_val, USEC_PER_SEC) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 3 * USEC_PER_DAY);
}

TEST(parse_time_combined) {
        usec_t c_val, r_val;
        assert_se(parse_time("1h 30min", &c_val, USEC_PER_SEC) >= 0);
        assert_se(rs_parse_time("1h 30min", &r_val, USEC_PER_SEC) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == USEC_PER_HOUR + 30 * USEC_PER_MINUTE);
}

TEST(parse_time_msec) {
        usec_t c_val, r_val;
        assert_se(parse_time("500ms", &c_val, USEC_PER_SEC) >= 0);
        assert_se(rs_parse_time("500ms", &r_val, USEC_PER_SEC) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 500 * USEC_PER_MSEC);
}

TEST(parse_time_decimal) {
        usec_t c_val, r_val;
        assert_se(parse_time("1.5s", &c_val, USEC_PER_SEC) >= 0);
        assert_se(rs_parse_time("1.5s", &r_val, USEC_PER_SEC) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 1500000); /* 1.5 seconds */
}

TEST(parse_time_infinity) {
        usec_t c_val, r_val;
        assert_se(parse_time("infinity", &c_val, USEC_PER_SEC) >= 0);
        assert_se(rs_parse_time("infinity", &r_val, USEC_PER_SEC) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == USEC_INFINITY);
}

TEST(parse_time_default_unit) {
        usec_t c_val, r_val;
        /* No suffix, default to seconds */
        assert_se(parse_time("5", &c_val, USEC_PER_SEC) >= 0);
        assert_se(rs_parse_time("5", &r_val, USEC_PER_SEC) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 5 * USEC_PER_SEC);
}

TEST(parse_time_whitespace) {
        usec_t c_val, r_val;
        assert_se(parse_time("  5s  ", &c_val, USEC_PER_SEC) >= 0);
        assert_se(rs_parse_time("  5s  ", &r_val, USEC_PER_SEC) >= 0);
        assert_se(c_val == r_val);
}

TEST(parse_time_zero) {
        usec_t c_val, r_val;
        assert_se(parse_time("0", &c_val, USEC_PER_SEC) >= 0);
        assert_se(rs_parse_time("0", &r_val, USEC_PER_SEC) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 0);
}

TEST(parse_time_usecs) {
        usec_t c_val, r_val;
        assert_se(parse_time("100us", &c_val, USEC_PER_SEC) >= 0);
        assert_se(rs_parse_time("100us", &r_val, USEC_PER_SEC) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 100);
}

TEST(parse_time_weeks) {
        usec_t c_val, r_val;
        assert_se(parse_time("1w", &c_val, USEC_PER_SEC) >= 0);
        assert_se(rs_parse_time("1w", &r_val, USEC_PER_SEC) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == USEC_PER_WEEK);
}

/* ── parse_sec ─────────────────────────────────────────────────────────────── */

TEST(parse_sec_basic) {
        usec_t c_val, r_val;
        assert_se(parse_sec("5", &c_val) >= 0);
        assert_se(rs_parse_sec("5", &r_val) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 5 * USEC_PER_SEC);
}

TEST(parse_sec_with_suffix) {
        usec_t c_val, r_val;
        assert_se(parse_sec("5min", &c_val) >= 0);
        assert_se(rs_parse_sec("5min", &r_val) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 5 * USEC_PER_MINUTE);
}

TEST(parse_sec_infinity) {
        usec_t c_val, r_val;
        assert_se(parse_sec("infinity", &c_val) >= 0);
        assert_se(rs_parse_sec("infinity", &r_val) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == USEC_INFINITY);
}

/* ── parse_sec_fix_0 ──────────────────────────────────────────────────────── */

TEST(parse_sec_fix_0_nonzero) {
        usec_t c_val, r_val;
        assert_se(parse_sec_fix_0("5s", &c_val) >= 0);
        assert_se(rs_parse_sec_fix_0("5s", &r_val) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 5 * USEC_PER_SEC);
}

TEST(parse_sec_fix_0_zero) {
        usec_t c_val, r_val;
        assert_se(parse_sec_fix_0("0", &c_val) >= 0);
        assert_se(rs_parse_sec_fix_0("0", &r_val) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == USEC_INFINITY); /* 0 maps to infinity */
}

/* ── parse_sec_def_infinity ─────────────────────────────────────────────── */

TEST(parse_sec_def_infinity_empty) {
        usec_t c_val, r_val;
        assert_se(parse_sec_def_infinity("", &c_val) >= 0);
        assert_se(rs_parse_sec_def_infinity("", &r_val) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == USEC_INFINITY); /* empty → infinity */
}

TEST(parse_sec_def_infinity_value) {
        usec_t c_val, r_val;
        assert_se(parse_sec_def_infinity("5s", &c_val) >= 0);
        assert_se(rs_parse_sec_def_infinity("5s", &r_val) >= 0);
        assert_se(c_val == r_val);
        assert_se(c_val == 5 * USEC_PER_SEC);
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
