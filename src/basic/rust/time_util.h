/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "time-util.h"

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in time-util.h/c with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

/* PORT-SYNC: scope=basic.time-util; authority=src/basic/time-util.c,src/basic/time-util.h */

usec_t rs_map_clock_usec_raw(usec_t from, usec_t from_base, usec_t to_base);
usec_t rs_timespec_load(const struct timespec *ts);
nsec_t rs_timespec_load_nsec(const struct timespec *ts);
struct timespec *rs_timespec_store(struct timespec *ts, usec_t u);
struct timespec *rs_timespec_store_nsec(struct timespec *ts, nsec_t n);
usec_t rs_timeval_load(const struct timeval *tv);
struct timeval *rs_timeval_store(struct timeval *tv, usec_t u);
usec_t rs_triple_timestamp_by_clock(triple_timestamp *ts, clockid_t clock);
const char *rs_timestamp_style_to_string(int t);
int rs_timestamp_style_from_string(const char *s);
int rs_parse_time(const char *t, usec_t *ret, usec_t default_unit);
int rs_parse_sec(const char *t, usec_t *ret);
int rs_parse_sec_fix_0(const char *t, usec_t *ret);
int rs_parse_sec_def_infinity(const char *t, usec_t *ret);
bool rs_timestamp_is_set(usec_t timestamp);
bool rs_dual_timestamp_is_set(const dual_timestamp *ts);
bool rs_triple_timestamp_is_set(const triple_timestamp *ts);
usec_t rs_usec_add(usec_t a, usec_t b);
usec_t rs_usec_sub_unsigned(usec_t timestamp, usec_t delta);
usec_t rs_usec_sub_signed(usec_t timestamp, int64_t delta);
int rs_parse_gmtoff(const char *t, long *ret);
char *rs_format_timespan(char *buf, size_t l, usec_t t, usec_t accuracy);
