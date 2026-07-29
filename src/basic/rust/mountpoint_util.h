/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.mountpoint-util; authority=src/basic/mountpoint-util.c,src/basic/mountpoint-util.h */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Returns a static string or NULL; the result must not be freed. */
const char *rs_mount_propagation_flag_to_string(unsigned long flags);
/* NULL name is treated as empty. ret must be non-NULL and is written only on success. */
int rs_mount_propagation_flag_from_string(const char *name, unsigned long *ret);
bool rs_mount_propagation_flag_is_valid(unsigned long flag);
/* err must be a negative errno. */
bool rs_is_name_to_handle_at_fatal_error(int err);
