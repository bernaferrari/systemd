/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

bool rs_xattr_is_acl(const char *name);
bool rs_xattr_is_selinux(const char *name);
