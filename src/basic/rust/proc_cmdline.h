/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in proc-cmdline.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

char* rs_proc_cmdline_key_startswith(const char *s, const char *prefix);
bool rs_proc_cmdline_key_streq(const char *x, const char *y);
