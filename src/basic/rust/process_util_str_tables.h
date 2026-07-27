/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

const char *rs_sigchld_code_to_string(int code);
int rs_sigchld_code_from_string(const char *s);
const char *rs_sched_policy_to_string(int i);
int rs_sched_policy_from_string(const char *s);
