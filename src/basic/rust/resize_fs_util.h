/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.resize-fs-util; authority=src/shared/resize-fs.c,src/shared/resize-fs.h */

#include <stdbool.h>
#include <stdint.h>

#include "stat-util.h"

uint64_t rs_minimal_size_by_fs_name(const char *name);
uint64_t rs_minimal_size_by_fs_magic(statfs_f_type_t magic);
bool rs_fs_can_online_shrink_and_grow(statfs_f_type_t magic);
