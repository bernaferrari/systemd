/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* PORT-SYNC: scope=basic.gunicode; authority=src/basic/gunicode.c,src/basic/gunicode.h
 * Rust FFI declarations for gunicode module. */

#ifdef __cplusplus
extern "C" {
#endif

char *rs_utf8_prev_char(const char *p);
extern const char rs_utf8_skip_data[256];
bool rs_unichar_iswide(uint32_t c);

#ifdef __cplusplus
}
#endif
