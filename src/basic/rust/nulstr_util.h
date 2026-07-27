/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdbool.h>

const char* rs_nulstr_get(const char *nulstr, const char *needle);
char** rs_strv_parse_nulstr_full(const char *s, size_t l, bool drop_trailing_nuls);
