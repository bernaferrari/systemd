/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

bool rs_argv_looks_like_help(int argc, const char **argv);
bool rs_invoked_as(const char **argv, const char *token);
