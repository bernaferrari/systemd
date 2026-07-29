/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.ansi-color; authority=src/basic/ansi-color.c,src/basic/ansi-color.h */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in ansi-color.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

int rs_color_mode_from_string(const char *s);
const char *rs_color_mode_to_string(int i);
int rs_parse_systemd_colors(void);
int rs_get_color_mode(void);
bool rs_underline_enabled(void);
void rs_reset_ansi_feature_caches(void);
bool rs_looks_like_ansi_color_code(const char *str);
