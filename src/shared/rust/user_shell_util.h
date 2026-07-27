/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

bool rs_is_nologin_shell(const char *shell);
bool rs_shell_is_placeholder(const char *shell);
int rs_parse_fractional_part_u(const char **p, size_t digits, unsigned *res);
