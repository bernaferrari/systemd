/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: src/shared/output-mode.h,src/shared/sleep-config.h,src/basic/user-util.h */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Exact Rust C ABI facades for the inline predicates in output-mode.h,
 * sleep-config.h, and user-util.h. The two enum predicates take raw `int`
 * values intentionally: C callers can pass invalid enum discriminants and
 * the source helpers handle those as ordinary non-matching integers. */
bool rs_OUTPUT_MODE_IS_JSON(int mode);
bool rs_SLEEP_OPERATION_IS_HIBERNATION(int operation);
bool rs_ERRNO_IS_NEG_BAD_ACCOUNT(intmax_t r);
