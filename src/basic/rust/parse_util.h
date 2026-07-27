/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in parse-util.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

int rs_parse_boolean(const char *v);
int rs_safe_atou(const char *s, unsigned *ret_u);
int rs_safe_atou_full(const char *s, unsigned base, unsigned *ret_u);
int rs_safe_atou_bounded(const char *s, unsigned min, unsigned max, unsigned *ret);
int rs_safe_atou8_full(const char *s, unsigned base, uint8_t *ret);
int rs_safe_atou16_full(const char *s, unsigned base, uint16_t *ret);
int rs_safe_atoi(const char *s, int *ret_i);
int rs_safe_atoi16(const char *s, int16_t *ret);
int rs_safe_atolli(const char *s, long long *ret_lli);
int rs_safe_atollu(const char *s, unsigned long long *ret_llu);
int rs_safe_atollu_full(const char *s, unsigned base, unsigned long long *ret_llu);
int rs_safe_atolu_full(const char *s, unsigned base, unsigned long *ret_u);
int rs_safe_atou64(const char *s, uint64_t *ret_u);
int rs_safe_atoi64(const char *s, int64_t *ret_i);
int rs_safe_atoux64(const char *s, uint64_t *ret);
int rs_parse_size(const char *t, uint64_t base, uint64_t *size);
int rs_parse_pid(const char *s, pid_t *ret);
int rs_parse_mode(const char *s, mode_t *ret);
int rs_parse_ifindex(const char *s);
int rs_parse_fd(const char *s);
int rs_parse_errno(const char *s);
int rs_parse_nice(const char *s, int *ret);
int rs_parse_ip_port(const char *s, uint16_t *ret);
int rs_parse_range(const char *t, unsigned *lower, unsigned *upper);
int rs_parse_ip_port_range(const char *s, uint16_t *low, uint16_t *high, bool allow_zero);
int rs_parse_oom_score_adjust(const char *s, int *ret);
int rs_parse_fractional_part_u(const char **p, size_t digits, unsigned *res);

/* Current parse-util.c and parse-util.h shadow facades. */
int rs_safe_atou8(const char *s, uint8_t *ret);
int rs_safe_atou16(const char *s, uint16_t *ret);
int rs_safe_atoux16(const char *s, uint16_t *ret);
int rs_safe_atou32(const char *s, uint32_t *ret);
int rs_safe_atoi32(const char *s, int32_t *ret);
int rs_safe_atolu(const char *s, unsigned long *ret);
int rs_safe_atoli(const char *s, long *ret);
int rs_safe_atozu(const char *s, size_t *ret);
int rs_parse_tristate(const char *v, int *ret);
int rs_parse_tristate_full(const char *v, const char *third, int *ret);
int rs_parse_mtu(int family, const char *s, uint32_t *ret);
int rs_parse_sector_size(const char *t, uint64_t *ret);
int rs_store_loadavg_fixed_point(unsigned long i, unsigned long f, unsigned long *ret);
int rs_parse_loadavg_fixed_point(const char *s, unsigned long *ret);
