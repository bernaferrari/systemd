/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

void *rs_memdup(const void *p, size_t l);
void *rs_memdup_suffix0(const void *p, size_t l);
void rs_free_many(void **p, size_t n);

void *rs_malloc_multiply(size_t need, size_t size);
void *rs_memdup_multiply(const void *p, size_t need, size_t size);
void *rs_memdup_suffix0_multiply(const void *p, size_t need, size_t size);
