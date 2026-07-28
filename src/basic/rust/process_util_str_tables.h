/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.process-util-str-tables; authority=src/basic/process-util.c,src/basic/process-util.h,src/basic/string-table.c,src/basic/string-table.h,src/basic/parse-util.c,src/basic/parse-util.h */
#pragma once

#include <stdbool.h>
#include <stddef.h>

const char *rs_sigchld_code_to_string(int code);
int rs_sigchld_code_from_string(const char *s);
int rs_sched_policy_to_string_alloc(int i, char **ret);
int rs_sched_policy_from_string(const char *s);
