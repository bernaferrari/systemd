/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

bool rs_valid_user_group_name(const char *u, unsigned int flags);
int rs_capsule_name_is_valid(const char *name);
bool rs_uid_is_valid(uid_t uid);
int rs_parse_uid(const char *s, uid_t *ret);
int rs_parse_uid_range(const char *s, uid_t *ret_lower, uid_t *ret_upper);
bool rs_id128_is_valid(const char *s);
bool rs_hashed_password_is_locked_or_invalid(const char *password);
