/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

struct file_handle;

bool rs_fstype_is_ro(const char *fstype);
bool rs_fstype_needs_quota(const char *fstype);
bool rs_fstype_can_uid_gid(const char *fstype);
bool rs_path_below_api_vfs(const char *p);
bool rs_file_handle_equal(const struct file_handle *a, const struct file_handle *b);
