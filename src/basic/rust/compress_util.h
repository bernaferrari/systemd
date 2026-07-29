/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* PORT-SYNC: scope=basic.compress; authority=src/basic/compress.c,src/basic/compress.h */

/* Mirrors compression_to_string()/compression_from_string(). */
const char *rs_compression_to_string(int c);
int rs_compression_from_string(const char *s);

/* Mirrors compression_uppercase_to_string()/compression_uppercase_from_string(). */
const char *rs_compression_uppercase_to_string(int c);
int rs_compression_uppercase_from_string(const char *s);

/* Mirrors compression_supported() for valid Compression enum values. */
bool rs_compression_supported(int c);
