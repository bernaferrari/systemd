/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

int rs_allow_listed_char_for_devnode(char c, const char *additional);
int rs_encode_devnode_name(const char *s, char *enc, size_t len);
