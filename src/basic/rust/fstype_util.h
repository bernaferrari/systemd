/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <fcntl.h>

bool rs_fstype_is_ro(const char *fstype);
bool rs_fstype_needs_quota(const char *fstype);
bool rs_fstype_can_uid_gid(const char *fstype);
bool rs_path_below_api_vfs(const char *p);
bool rs_fstype_is_network(const char *fstype);
bool rs_fstype_is_api_vfs(const char *fstype);
bool rs_fstype_is_blockdev_backed(const char *fstype);

/* Uses same ABI layout as struct file_handle from <fcntl.h> */
bool rs_file_handle_equal(const struct file_handle *a, const struct file_handle *b);
