/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

bool rs_string_is_glob(const char *p);
int rs_glob_non_glob_prefix(const char *path, char **ret);
