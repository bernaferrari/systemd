/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/*
 * Rust FFI declarations for shadow testing.
 * These mirror the C functions in glyph-util.h with rs_ prefix.
 * Only used by shadow tests — production code uses the C originals.
 */

const char* rs_glyph_full(int code, bool force_utf);
