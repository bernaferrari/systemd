/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.argv-util; authority=src/basic/argv-util.c,src/basic/argv-util.h */
#pragma once

#include <stdbool.h>

bool rs_argv_looks_like_help(int argc, char **argv);
bool rs_invoked_as(char **argv, const char *token);
