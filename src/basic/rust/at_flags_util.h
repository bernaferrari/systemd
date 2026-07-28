/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.at-flags-util; authority=src/basic/fs-util.h */

#ifdef __cplusplus
extern "C" {
#endif

int rs_at_flags_normalize_nofollow(int flags);
int rs_at_flags_normalize_follow(int flags);

#ifdef __cplusplus
}
#endif
