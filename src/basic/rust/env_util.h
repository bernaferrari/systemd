/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

bool rs_env_name_is_valid(const char *e);
bool rs_env_value_is_valid(const char *e);
bool rs_env_assignment_is_valid(const char *e);
bool rs_strv_env_is_valid(char * const *e);
bool rs_strv_env_name_is_valid(char * const *l);
bool rs_strv_env_name_or_assignment_is_valid(char * const *l);
