/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

/* PORT-SYNC: scope=shared.nsflags; authority=src/shared/nsflags.c,src/shared/nsflags.h,src/basic/namespace-util.c,src/basic/namespace-util.h */

/* Borrowed static result; never free. */
const char *rs_namespace_single_flag_to_string(unsigned long flag);
/* Successful results use libc allocation: strv_free() for char **, free() for char *. */
int rs_namespace_flags_to_strv(unsigned long flags, char ***ret);
int rs_namespace_flags_to_string(unsigned long flags, char **ret);
int rs_namespace_flags_from_string(const char *name, unsigned long *ret);
