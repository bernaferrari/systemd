/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

/* PORT-SYNC: scope=basic.bus-label; authority=src/basic/bus-label.c,src/basic/bus-label.h
 * Rust C ABI mirror of src/basic/bus-label.c and src/basic/bus-label.h.
 *
 * Returned pointers are allocated by the process C allocator; callers must
 * release them with free(). */

char *rs_bus_label_escape(const char *s);
char *rs_bus_label_unescape_n(const char *f, size_t l);
