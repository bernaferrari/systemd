/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

const char *rs_namespace_single_flag_to_string(unsigned long flag);
int rs_namespace_flags_to_strv(unsigned long flags, char ***ret);
int rs_namespace_flags_to_string(unsigned long flags, char **ret);
int rs_namespace_flags_from_string(const char *name, unsigned long *ret);
