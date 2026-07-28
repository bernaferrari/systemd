/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

/* PORT-SYNC: scope=basic.namespace-util; authority=src/basic/namespace-util.c,src/basic/namespace-util.h,src/include/override/sched.h */

int rs_clone_flag_to_namespace_type(unsigned long clone_flag);
bool rs_userns_shift_range_valid(uid_t shift, uid_t range);
