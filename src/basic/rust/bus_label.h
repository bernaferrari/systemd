/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

/* Rust FFI declarations for bus_label module.
 * PORT-SYNC: src/basic/bus-label.c */

char *rs_bus_label_escape(const char *s);
char *rs_bus_label_unescape_n(const char *f, size_t l);
