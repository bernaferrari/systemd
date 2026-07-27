/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <stddef.h>

char* rs_format_bytes_full(char *buf, size_t l, uint64_t t, unsigned int flag);
