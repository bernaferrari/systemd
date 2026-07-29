/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.mount-setup; authority=src/shared/mount-setup.c,src/shared/mount-setup.h */

#include <stdbool.h>

/* NULL returns false as a Rust ABI extension. Non-NULL inputs must be live NUL-terminated C strings. */
bool rs_mount_point_is_api(const char *path);
bool rs_mount_point_ignore(const char *path);
