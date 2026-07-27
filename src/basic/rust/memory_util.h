/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

size_t rs_page_size(void);
void *rs_memdup_reverse(const void *mem, size_t size);
void *rs_memcpy_safe(void *dst, const void *src, size_t n);
void *rs_mempcpy_safe(void *dst, const void *src, size_t n);
int rs_memcmp_safe(const void *s1, const void *s2, size_t n);
int rs_memcmp_nn(const void *s1, size_t n1, const void *s2, size_t n2);
void *rs_mempset(void *s, int c, size_t n);
void *rs_memmem_safe(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
void *rs_mempmem_safe(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
bool rs_memeqbyte(uint8_t byte, const void *data, size_t length);
