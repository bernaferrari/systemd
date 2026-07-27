/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdbool.h>

size_t rs_strnpcpy_full(char **dest, size_t size, const char *src, size_t len, bool *ret_truncated);
size_t rs_strpcpy_full(char **dest, size_t size, const char *src, bool *ret_truncated);
size_t rs_strnscpy_full(char *dest, size_t size, const char *src, size_t len, bool *ret_truncated);
size_t rs_strscpy_full(char *dest, size_t size, const char *src, bool *ret_truncated);
