/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.log-target; authority=src/basic/log.c,src/basic/log.h,src/basic/string-table.h */

const char *rs_log_target_to_string(int t);
int rs_log_target_from_string(const char *s);
