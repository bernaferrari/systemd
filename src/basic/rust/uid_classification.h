/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

bool rs_uid_is_greeter(uid_t uid);
bool rs_uid_is_dynamic(uid_t uid);
bool rs_uid_is_container(uid_t uid);
bool rs_uid_is_foreign(uid_t uid);
bool rs_uid_is_transient(uid_t uid);

bool rs_gid_is_dynamic(gid_t gid);
bool rs_gid_is_container(gid_t gid);
bool rs_gid_is_foreign(gid_t gid);
bool rs_gid_is_transient(gid_t gid);
