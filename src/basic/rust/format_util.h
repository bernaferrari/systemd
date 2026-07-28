/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.format-util; authority=src/basic/format-util.c,src/basic/format-util.h */
#pragma once

#include <stdint.h>
#include <stddef.h>

char* rs_format_bytes_full(char *buf, size_t l, uint64_t t, int flag);
char* rs_format_bytes(char *buf, size_t l, uint64_t t);
