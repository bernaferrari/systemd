/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

/* Rust FFI declarations for gunicode module.
 * PORT-SYNC: src/basic/gunicode.c */

char *rs_utf8_prev_char(const char *p);
extern const char rs_utf8_skip_data[256];
bool rs_unichar_iswide(uint32_t c);
