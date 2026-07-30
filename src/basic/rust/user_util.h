/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.user-util-abi; authority=src/basic/user-util.c,src/basic/user-util.h,src/basic/capsule-util.c,src/basic/capsule-util.h,src/libsystemd/sd-id128/id128-util.c,src/libsystemd/sd-id128/id128-util.h */

#include <stdbool.h>
#include <sys/types.h>

bool rs_valid_user_group_name(const char *u, unsigned int flags);
int rs_capsule_name_is_valid(const char *name);
bool rs_uid_is_valid(uid_t uid);
int rs_parse_uid(const char *s, uid_t *ret);
int rs_parse_uid_range(const char *s, uid_t *ret_lower, uid_t *ret_upper);
bool rs_id128_is_valid(const char *s);
bool rs_hashed_password_is_locked_or_invalid(const char *password);
