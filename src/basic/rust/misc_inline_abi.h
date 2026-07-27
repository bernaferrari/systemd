/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/*
 * Canonical Rust declarations for the small inline/helper shadow surface in
 * test-misc-inline-rust.c.  Keep this independent of the C implementation
 * headers: it documents the rs_ ABI and remains safe to include on its own.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

bool rs_devnum_is_zero(dev_t d);
bool rs_devnum_set_and_equal(dev_t a, dev_t b);

bool rs_xattr_is_acl(const char *name);
bool rs_xattr_is_selinux(const char *name);

char *rs_format_bytes(char *buf, size_t l, uint64_t t);

int rs_unhexmem(const char *p, void **ret_data, size_t *ret_size);
ssize_t rs_base64mem(const void *p, size_t l, char **ret);
int rs_unbase64mem(const char *p, void **ret_data, size_t *ret_size);
