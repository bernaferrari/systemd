/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

const char *rs_mount_propagation_flag_to_string(unsigned long flags);
int rs_mount_propagation_flag_from_string(const char *name, unsigned long *ret);
bool rs_mount_propagation_flag_is_valid(unsigned long flag);
bool rs_is_name_to_handle_at_fatal_error(int err);
