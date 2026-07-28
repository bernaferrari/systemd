/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.locale-util; authority=src/basic/locale-util.c,src/basic/locale-util.h */

#include <stdbool.h>

const char *rs_locale_variable_to_string(int v);
int rs_locale_variable_from_string(const char *s);
bool rs_locale_is_valid(const char *name);
