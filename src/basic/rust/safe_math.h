/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t rs_u64_multiply_safe(uint64_t a, uint64_t b);
unsigned long rs_ALIGN_POWER2(unsigned long u);
size_t rs_size_add(size_t x, size_t y);

#ifdef __cplusplus
}
#endif
