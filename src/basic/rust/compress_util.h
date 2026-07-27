/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

const char *rs_compression_to_string(int c);
int rs_compression_from_string(const char *s);
const char *rs_compression_to_string_lowercase(int c);
int rs_compression_from_string_lowercase(const char *s);
bool rs_compression_supported(int c);

/* C helper: returns bitmask of supported compression types (set in compress.c init) */
uint32_t rs_get_compression_supported_mask(void);
