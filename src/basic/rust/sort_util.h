/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in sort-util.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

#include "basic-forward.h"

void *rs_xbsearch_r(const void *key, const void *base, size_t nmemb, size_t size,
                    comparison_userdata_fn_t compar, void *arg);

void rs_qsort_safe(void *base, size_t nmemb, size_t size, comparison_fn_t compar);

void rs_qsort_r_safe(void *base, size_t nmemb, size_t size,
                     comparison_userdata_fn_t compar, void *userdata);

void* rs_bsearch_safe_internal(const void *key, const void *base, size_t nmemb,
                               size_t size, comparison_fn_t compar);

int rs_cmp_int(const int *a, const int *b);
int rs_cmp_uint16(const uint16_t *a, const uint16_t *b);
