/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

/* Exact Rust C ABI mirrors of src/shared/udev-util.c.
 *
 * rs_udev_replace_whitespace() reads at most len bytes from str and writes a
 * trailing NUL at to[result], so to must hold len + 1 bytes. str and to may
 * name the same buffer. rs_udev_replace_chars() mutates a NUL-terminated
 * writable string in place; allow is NULL or a NUL-terminated allow-list. */
size_t rs_udev_replace_whitespace(const char *str, char *to, size_t len);
size_t rs_udev_replace_chars(char *str, const char *allow);
