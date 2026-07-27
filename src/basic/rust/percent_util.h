/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in percent-util.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

int rs_parse_percent_unbounded(const char *p);
int rs_parse_percent(const char *p);
int rs_parse_permille_unbounded(const char *p);
int rs_parse_permille(const char *p);
int rs_parse_permyriad_unbounded(const char *p);
int rs_parse_permyriad(const char *p);

/* Exact C ABI facades for the UINT32_SCALE_* static inline helpers in
 * percent-util.h. Their `int` / `uint32_t` domains, saturation, and
 * integer-rounding behavior match the C authority. */
uint32_t rs_UINT32_SCALE_FROM_PERCENT(int percent);
uint32_t rs_UINT32_SCALE_FROM_PERMILLE(int permille);
uint32_t rs_UINT32_SCALE_FROM_PERMYRIAD(int permyriad);
int rs_UINT32_SCALE_TO_PERCENT(uint32_t scale);
int rs_UINT32_SCALE_TO_PERMILLE(uint32_t scale);
int rs_UINT32_SCALE_TO_PERMYRIAD(uint32_t scale);
