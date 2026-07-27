/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

uint64_t rs_minimal_size_by_fs_name(const char *name);
uint64_t rs_minimal_size_by_fs_magic(uint64_t magic);
bool rs_fs_can_online_shrink_and_grow(uint64_t magic);
